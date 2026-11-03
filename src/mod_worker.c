/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
 * Copyright (c) 2026-present iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "mem.h"
#include "private.h"
#include "tjs.h"

#include <stdatomic.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#include <winsock2.h>
#endif

enum {
    MSGPIPE_EVENT_MESSAGE = 0,
    MSGPIPE_EVENT_MESSAGE_ERROR,
    MSGPIPE_EVENT_CLOSE,
    MSGPIPE_EVENT_MAX,
};

static thread_local JSClassID tjs_msgpipe_class_id;

/* Messages received before an onmessage listener is installed remain pending
 * until the listener is attached. Do not cap this queue: a MessagePipe has
 * message-delivery semantics, so silently discarding a burst here is worse
 * than retaining it (the JS Worker layer has its own startup queue too). */

/* A Worker wrapper can be finalized before its thread returns, so qrt->workers
 * is not a complete fork-safety guard. Keep a process-wide count until the
 * worker thread has finished tearing down its native runtime. The mutex is
 * initialized once and intentionally lives for the process lifetime. */
static uv_once_t tjs_worker_count_once = UV_ONCE_INIT;
static uv_mutex_t tjs_worker_count_lock;
static size_t tjs_worker_count;

/* The transfer table is out of band.  A token is deliberately used instead of
 * putting a process-local pointer on the wire: a complete frame must claim the
 * token while holding the registry lock before it can touch QuickJS objects. */
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t blob_len;
    uint64_t transfer_count;
    uint64_t transfer_token;
} TJSMessagePipeFrameHeader;

typedef struct TJSMessagePipeFrame TJSMessagePipeFrame;
typedef struct TJSMessagePipeTransferOwner TJSMessagePipeTransferOwner;

static void tjs_worker_count_init(void) {
    CHECK_EQ(uv_mutex_init(&tjs_worker_count_lock), 0);
}

static void tjs_worker_count_add(void) {
    uv_once(&tjs_worker_count_once, tjs_worker_count_init);
    uv_mutex_lock(&tjs_worker_count_lock);
    tjs_worker_count++;
    uv_mutex_unlock(&tjs_worker_count_lock);
}

static void tjs_worker_count_remove(void) {
    uv_once(&tjs_worker_count_once, tjs_worker_count_init);
    uv_mutex_lock(&tjs_worker_count_lock);
    CHECK_GT(tjs_worker_count, 0);
    tjs_worker_count--;
    uv_mutex_unlock(&tjs_worker_count_lock);
}

size_t tjs__active_worker_count(void) {
    size_t count;
    uv_once(&tjs_worker_count_once, tjs_worker_count_init);
    uv_mutex_lock(&tjs_worker_count_lock);
    count = tjs_worker_count;
    uv_mutex_unlock(&tjs_worker_count_lock);
    return count;
}

typedef struct {
    JSContext *ctx;
    TJSRuntime *trt;
    int closed;
    int finalized;
    int closing_for_runtime;
    bool peer_eof;
    bool peer_closed_cleanly;
    bool close_dispatched;
    struct list_head link;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_pipe_t pipe;
        uv_tcp_t tcp;
    } h;
    struct {
        TJSMessagePipeFrameHeader header;
        uint8_t *data;
        uint64_t nread;
        uint64_t header_nread;
    } reading;
    /* Borrowed from the JS wrapper. A queued drain job owns its own duplicate. */
    JSValue self;
    JSValue events[MSGPIPE_EVENT_MAX];
    JSValue *pending;
    size_t pending_count;
    size_t pending_cap;
    size_t pending_bytes;
    bool pending_drain_queued;
    TJSMessagePipeFrame *frame;
} TJSMessagePipe;

struct TJSMessagePipeFrame {
    TJSMessagePipeFrameHeader header;
    uint8_t *blob;
    TJSMessagePipeTransferOwner *transfers;
    int committed;
};

/* The wrapper is allocated in neutral memory, rather than on the sender's JS
 * stack. One reference is held by the write request and one by the frame
 * header delivered to the peer. */
struct TJSMessagePipeTransferOwner {
    _Atomic unsigned refs;
    JSAutoTransferTab tab;
};

enum {
    MSGPIPE_FRAME_MAGIC = 0x54534a4d, /* "MJST", in host byte order */
    MSGPIPE_FRAME_VERSION = 1,
};

/* One registry reference is reserved by every published entry.  Claim moves
 * that reference to the reader; cancel drops it.  The other owner reference
 * belongs to the write request until its callback runs. */
typedef struct TJSMessagePipeTransferRegistryEntry {
    uint64_t token;
    TJSMessagePipeTransferOwner *owner;
    struct list_head link;
} TJSMessagePipeTransferRegistryEntry;

static uv_once_t tjs_msgpipe_registry_once = UV_ONCE_INIT;
static uv_mutex_t tjs_msgpipe_registry_lock;
static struct list_head tjs_msgpipe_registry;
static uint64_t tjs_msgpipe_registry_next_token;

static void msgpipe_transfer_registry_init(void) {
    CHECK_EQ(uv_mutex_init(&tjs_msgpipe_registry_lock), 0);
    init_list_head(&tjs_msgpipe_registry);
    tjs_msgpipe_registry_next_token = 1;
}

typedef struct {
    uv_write_t req;
    uint8_t *data;
    // Track SABs that were dup'd for this write, so we can free them on close
    void **sab_list;
    size_t sab_count;
    TJSMessagePipeFrame frame;
    TJSMessagePipeTransferOwner *transfer_owner;
    uint64_t transfer_token;
} TJSMessagePipeWriteReq;

static void msgpipe_transfer_owner_release(TJSMessagePipeTransferOwner *owner) {
    if (!owner) return;
    if (atomic_fetch_sub_explicit(&owner->refs, 1, memory_order_acq_rel) == 1) {
        JS_ReleaseAutoTransferTab(&owner->tab);
        tjs__free(owner);
    }
}

static void msgpipe_transfer_owner_release_unsent(TJSMessagePipeTransferOwner *owner) {
    /* The receiver reference was reserved before uv_write. It is not
     * published when uv_write fails, so both sides can be released here. */
    if (!owner) return;
    msgpipe_transfer_owner_release(owner);
    msgpipe_transfer_owner_release(owner);
}

static bool msgpipe_transfer_registry_reserve(
    TJSMessagePipeTransferOwner *owner,
    TJSMessagePipeTransferRegistryEntry **entry_out) {
    TJSMessagePipeTransferRegistryEntry *entry;
    uint64_t token;

    entry = tjs__mallocz(sizeof(*entry));
    if (!entry) return false;

    uv_once(&tjs_msgpipe_registry_once, msgpipe_transfer_registry_init);
    uv_mutex_lock(&tjs_msgpipe_registry_lock);
    token = tjs_msgpipe_registry_next_token++;
    if (token == 0) {
        /* Do not ever put zero in a frame: it is reserved as an invalid token. */
        token = tjs_msgpipe_registry_next_token++;
    }
    entry->token = token;
    entry->owner = owner;
    init_list_head(&entry->link);
    uv_mutex_unlock(&tjs_msgpipe_registry_lock);
    *entry_out = entry;
    return true;
}

static void msgpipe_transfer_registry_publish(
    TJSMessagePipeTransferRegistryEntry *entry) {
    uv_once(&tjs_msgpipe_registry_once, msgpipe_transfer_registry_init);
    uv_mutex_lock(&tjs_msgpipe_registry_lock);
    list_add_tail(&entry->link, &tjs_msgpipe_registry);
    uv_mutex_unlock(&tjs_msgpipe_registry_lock);
}

static void msgpipe_transfer_registry_discard_reserved(
    TJSMessagePipeTransferRegistryEntry *entry) {
    tjs__free(entry);
}

/* Remove an entry and return its reserved receiver reference.  The registry
 * lock makes removal and ownership transfer one operation. */
static TJSMessagePipeTransferOwner *msgpipe_transfer_registry_claim(
    uint64_t token, uint64_t transfer_count) {
    struct list_head *el;
    TJSMessagePipeTransferOwner *owner = NULL;

    if (!token) return NULL;
    uv_once(&tjs_msgpipe_registry_once, msgpipe_transfer_registry_init);
    uv_mutex_lock(&tjs_msgpipe_registry_lock);
    list_for_each(el, &tjs_msgpipe_registry) {
        TJSMessagePipeTransferRegistryEntry *entry =
            list_entry(el, TJSMessagePipeTransferRegistryEntry, link);
        if (entry->token == token) {
            if (entry->owner->tab.len == (size_t)transfer_count) {
                owner = entry->owner;
                list_del(&entry->link);
                tjs__free(entry);
            }
            break;
        }
    }
    uv_mutex_unlock(&tjs_msgpipe_registry_lock);
    return owner;
}

/* Cancel is used for a failed write and for a truncated frame.  It drops the
 * receiver reference; the write callback still drops its separate reference. */
static bool msgpipe_transfer_registry_cancel(uint64_t token) {
    struct list_head *el, *tmp;
    TJSMessagePipeTransferOwner *owner = NULL;

    if (!token) return false;
    uv_once(&tjs_msgpipe_registry_once, msgpipe_transfer_registry_init);
    uv_mutex_lock(&tjs_msgpipe_registry_lock);
    list_for_each_safe(el, tmp, &tjs_msgpipe_registry) {
        TJSMessagePipeTransferRegistryEntry *entry =
            list_entry(el, TJSMessagePipeTransferRegistryEntry, link);
        if (entry->token == token) {
            owner = entry->owner;
            list_del(&entry->link);
            tjs__free(entry);
            break;
        }
    }
    uv_mutex_unlock(&tjs_msgpipe_registry_lock);
    if (owner) msgpipe_transfer_owner_release(owner);
    return owner != NULL;
}

static TJSMessagePipeTransferOwner *msgpipe_parse_transfers(
    JSContext *ctx, JSValueConst value) {
    TJSMessagePipeTransferOwner *owner;
    JSValue length_value;
    uint64_t len64;
    size_t size;

    if (JS_IsUndefined(value) || JS_IsNull(value)) {
        owner = tjs__mallocz(sizeof(*owner));
        if (!owner) {
            JS_ThrowOutOfMemory(ctx);
            return NULL;
        }
        atomic_init(&owner->refs, 2);
        return owner;
    }
    if (!JS_IsArray(value)) {
        JS_ThrowTypeError(ctx, "transfer list must be an array");
        return NULL;
    }
    length_value = JS_GetPropertyStr(ctx, value, "length");
    if (JS_IsException(length_value))
        return NULL;
    if (JS_ToIndex(ctx, &len64, length_value)) {
        JS_FreeValue(ctx, length_value);
        return NULL;
    }
    JS_FreeValue(ctx, length_value);
    if (len64 > UINT32_MAX ||
        len64 > (SIZE_MAX - sizeof(*owner)) / sizeof(owner->tab.tab[0])) {
        JS_ThrowRangeError(ctx, "transfer list is too large");
        return NULL;
    }
    size = sizeof(*owner) + (size_t)len64 * sizeof(owner->tab.tab[0]);
    owner = tjs__mallocz(size);
    if (!owner) {
        JS_ThrowOutOfMemory(ctx);
        return NULL;
    }
    atomic_init(&owner->refs, 2);
    owner->tab.tab = (JSAutoTransferEntry *)(owner + 1);
    owner->tab.len = (size_t)len64;
    for (size_t i = 0; i < owner->tab.len; i++) {
        owner->tab.tab[i].value = JS_GetPropertyUint32(ctx, value, (uint32_t)i);
        if (JS_IsException(owner->tab.tab[i].value)) {
            for (size_t j = 0; j < i; j++)
                JS_FreeValue(ctx, owner->tab.tab[j].value);
            tjs__free(owner);
            return NULL;
        }
    }
    return owner;
}

static void msgpipe_free_transfer_values(
    JSContext *ctx, TJSMessagePipeTransferOwner *owner) {
    if (!owner) return;
    for (size_t i = 0; i < owner->tab.len; i++) {
        JS_FreeValue(ctx, owner->tab.tab[i].value);
        owner->tab.tab[i].value = JS_UNDEFINED;
    }
}

static void uv__close_cb(uv_handle_t *handle);
static void msgpipe_frame_clear(TJSMessagePipe *p);

static void msgpipe_frame_destroy(TJSMessagePipe *p) {
    msgpipe_frame_clear(p);
    tjs__free(p->frame);
    p->frame = NULL;
}

static void msgpipe_cancel_reading_token(TJSMessagePipe *p) {
    TJSMessagePipeFrameHeader *header = &p->reading.header;
    if (p->reading.header_nread == sizeof(*header) &&
        header->magic == MSGPIPE_FRAME_MAGIC &&
        header->version == MSGPIPE_FRAME_VERSION && header->reserved == 0) {
        msgpipe_transfer_registry_cancel(header->transfer_token);
    }
}

static void msgpipe_unlink(TJSMessagePipe *p) {
    if (p && p->link.next) {
        list_del(&p->link);
        p->link.next = NULL;
        p->link.prev = NULL;
    }
}

static void msgpipe_frame_clear(TJSMessagePipe *p) {
    if (!p->frame) return;
    /* The read buffer is owned by p->reading and is released by the caller;
     * frame->blob is only a view used while the frame is active. */
    p->frame->blob = NULL;
    if (p->frame->transfers) {
        msgpipe_transfer_owner_release(p->frame->transfers);
    }
    memset(p->frame, 0, sizeof(*p->frame));
}

static void msgpipe_clear_js_rt(JSRuntime *rt, TJSMessagePipe *p) {
    for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
        JSValue event = p->events[i];
        p->events[i] = JS_UNDEFINED;
        JS_FreeValueRT(rt, event);
    }
    uint8_t *data = p->reading.data;
    msgpipe_cancel_reading_token(p);
    memset(&p->reading, 0, sizeof(p->reading));
    js_free_rt(rt, data);
    msgpipe_frame_clear(p);
    for (size_t i = 0; i < p->pending_count; i++) {
        JS_FreeValueRT(rt, p->pending[i]);
    }
    p->pending_count = 0;
    js_free_rt(rt, p->pending);
    p->pending = NULL;
    p->pending_cap = 0;
    p->pending_bytes = 0;
}

static void msgpipe_clear_js(TJSMessagePipe *p) {
    for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
        JSValue event = p->events[i];
        p->events[i] = JS_UNDEFINED;
        JS_FreeValue(p->ctx, event);
    }
    uint8_t *data = p->reading.data;
    msgpipe_cancel_reading_token(p);
    memset(&p->reading, 0, sizeof(p->reading));
    js_free(p->ctx, data);
    msgpipe_frame_clear(p);
    for (size_t i = 0; i < p->pending_count; i++) {
        JS_FreeValue(p->ctx, p->pending[i]);
    }
    p->pending_count = 0;
    js_free(p->ctx, p->pending);
    p->pending = NULL;
    p->pending_cap = 0;
    p->pending_bytes = 0;
}

static void msgpipe_close_handle(TJSMessagePipe *p) {
    if (!uv_is_closing(&p->h.handle)) {
        uv_read_stop(&p->h.stream);
        uv_close(&p->h.handle, uv__close_cb);
    }
}


static void uv__close_cb(uv_handle_t *handle) {
    TJSMessagePipe *p = handle->data;
    CHECK_NOT_NULL(p);
    p->closed = 1;
    if (p->finalized) {
        msgpipe_frame_destroy(p);
        tjs__free(p);
    }
}

static void tjs_msgpipe_finalizer(JSRuntime *rt, JSValue val) {
    TJSMessagePipe *p = JS_GetOpaque(val, tjs_msgpipe_class_id);
    if (p) {
        msgpipe_unlink(p);
        /* Free JS resources now while rt is still alive. */
        msgpipe_clear_js_rt(rt, p);

        p->finalized = 1;
        if (!uv_is_closing(&p->h.handle)) {
            msgpipe_close_handle(p);
            return;
        }
        if (!p->closed) {
            /* uv_close already in flight, close_cb will free p */
            return;
        }
        msgpipe_frame_destroy(p);
        tjs__free(p);
    }
}

static void tjs_msgpipe_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSMessagePipe *p = JS_GetOpaque(val, tjs_msgpipe_class_id);
    if (p) {
        for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
            JS_MarkValue(rt, p->events[i], mark_func);
        }
        for (size_t i = 0; i < p->pending_count; i++) {
            JS_MarkValue(rt, p->pending[i], mark_func);
        }
    }
}

static JSClassDef tjs_msgpipe_class = {
    "MessagePipe",
    .finalizer = tjs_msgpipe_finalizer,
    .gc_mark = tjs_msgpipe_mark,
};

static TJSMessagePipe *tjs_msgpipe_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_msgpipe_class_id);
}

/* Message delivery runs from a libuv callback, not from a JS call frame. An
 * exception left on the context there would have no caller to observe it, so
 * make an allocation failure follow the runtime's existing uncatchable-error
 * path rather than silently losing the message. */
static void msgpipe_oom(TJSMessagePipe *p) {
    JSContext *ctx = p->ctx;
    JS_ThrowOutOfMemory(ctx);
    JSValue error = JS_GetException(ctx);
    tjs__stop_uncatchable_error(ctx, error);
    JS_FreeValue(ctx, error);
}

static JSValue emit_event(JSContext *ctx, int argc, JSValue *argv) {
    CHECK_EQ(argc, 2);

    TJSRuntime *trt = TJS_GetRuntime(ctx);
    if (trt && trt->freeing) {
        return JS_UNDEFINED;
    }

    JSValue arg = JS_DupValue(ctx, argv[1]);
    tjs_call_handler(ctx, argv[0], 1, &arg);
    JS_FreeValue(ctx, arg);

    return JS_UNDEFINED;
}

static JSValue drain_msgpipe_messages(JSContext *ctx, int argc, JSValue *argv) {
    CHECK_EQ(argc, 1);

    TJSMessagePipe *p = JS_GetOpaque(argv[0], tjs_msgpipe_class_id);
    if (!p || p->finalized || p->closing_for_runtime) return JS_UNDEFINED;

    JSValue event_func = p->events[MSGPIPE_EVENT_MESSAGE];
    if (!JS_IsFunction(ctx, event_func) || p->pending_count == 0) {
        p->pending_drain_queued = false;
        return JS_UNDEFINED;
    }

    JSValue *messages = p->pending;
    size_t count = p->pending_count;
    p->pending = NULL;
    p->pending_count = 0;
    p->pending_cap = 0;
    p->pending_bytes = 0;
    event_func = JS_DupValue(ctx, event_func);

    for (size_t i = 0; i < count; i++) {
        JSValue arg = JS_DupValue(ctx, messages[i]);
        tjs_call_handler(ctx, event_func, 1, &arg);
        JS_FreeValue(ctx, arg);
        JS_FreeValue(ctx, messages[i]);
    }
    js_free(ctx, messages);
    JS_FreeValue(ctx, event_func);

    p->pending_drain_queued = false;
    if (p->pending_count > 0 &&
        JS_IsFunction(ctx, p->events[MSGPIPE_EVENT_MESSAGE])) {
        JSValueConst pipe_obj = p->self;
        if (JS_EnqueueJob(ctx, drain_msgpipe_messages, 1, &pipe_obj))
            msgpipe_oom(p);
        else
            p->pending_drain_queued = true;
    }
    return JS_UNDEFINED;
}

static void schedule_msgpipe_drain(TJSMessagePipe *p) {
    if (p->pending_drain_queued || p->pending_count == 0 ||
        !JS_IsFunction(p->ctx, p->events[MSGPIPE_EVENT_MESSAGE]))
        return;

    JSValueConst pipe_obj = p->self;
    if (JS_EnqueueJob(p->ctx, drain_msgpipe_messages, 1, &pipe_obj)) {
        msgpipe_oom(p);
        return;
    }
    p->pending_drain_queued = true;
}

static void emit_msgpipe_event(TJSMessagePipe *p, int event, JSValue arg, size_t message_bytes) {
    JSContext *ctx = p->ctx;
    JSValue event_func = p->events[event];
    if (event == MSGPIPE_EVENT_MESSAGE) {
            if (p->pending_count >= p->pending_cap) {
                size_t new_cap;
                if (p->pending_cap == 0) {
                    new_cap = 8;
                } else if (p->pending_cap > SIZE_MAX / 2) {
                    new_cap = SIZE_MAX;
                } else {
                    new_cap = p->pending_cap * 2;
                }
                if (new_cap > SIZE_MAX / sizeof(*p->pending)) {
                    new_cap = SIZE_MAX / sizeof(*p->pending);
                }
                if (new_cap <= p->pending_cap) {
                    /* This is only reachable after exhausting addressable
                     * memory; report OOM instead of silently losing a value. */
                    msgpipe_oom(p);
                    return;
                }
                JSValue *grown = js_realloc(ctx, p->pending, new_cap * sizeof(JSValue));
                if (!grown) {
                    /* Allocation failure is exceptional, unlike a queue cap.
                     * Keep the existing queue intact and surface the failure
                     * through the runtime's normal OOM path. */
                    msgpipe_oom(p);
                    return;
                }
                p->pending = grown;
                p->pending_cap = new_cap;
            }
            p->pending[p->pending_count++] = JS_DupValue(ctx, arg);
            if (message_bytes > SIZE_MAX - p->pending_bytes) {
                p->pending_bytes = SIZE_MAX;
            } else {
                p->pending_bytes += message_bytes;
            }
            schedule_msgpipe_drain(p);
        return;
    }

    if (!JS_IsFunction(ctx, event_func)) return;

    JSValueConst args[2] = { event_func, arg };
    CHECK_EQ(JS_EnqueueJob(ctx, emit_event, 2, args), 0);
}

static void uv__alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    TJSMessagePipe *p = handle->data;
    CHECK_NOT_NULL(p);

    if (p->reading.data) {
        buf->base = (char *) p->reading.data + p->reading.nread;
        uint64_t remaining = p->reading.header.blob_len - p->reading.nread;
        buf->len = remaining > suggested_size ? suggested_size : remaining;
    } else {
        buf->base = (char *) &p->reading.header + p->reading.header_nread;
        size_t remaining = sizeof(p->reading.header) - p->reading.header_nread;
        buf->len = remaining > suggested_size ? suggested_size : remaining;
    }
}

static void uv__read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    TJSMessagePipe *p = handle->data;
    CHECK_NOT_NULL(p);
    if (p->finalized) return;
    if (p->closing_for_runtime) return;

    JSContext *ctx = p->ctx;
    uint64_t total_size = 0;

    if (nread < 0) {
        bool peer_eof = nread == UV_EOF;
        bool at_message_boundary = p->reading.data == NULL && p->reading.header_nread == 0;
        if (peer_eof) p->peer_eof = true;
        if (peer_eof && at_message_boundary) p->peer_closed_cleanly = true;
        uv_read_stop(&p->h.stream);
        if (p->reading.data) {
            js_free(ctx, p->reading.data);
        }
        msgpipe_cancel_reading_token(p);
        memset(&p->reading, 0, sizeof(p->reading));
        msgpipe_frame_clear(p);
        if (!p->closing_for_runtime && p->peer_closed_cleanly && !p->close_dispatched
            && JS_IsFunction(ctx, p->events[MSGPIPE_EVENT_CLOSE])) {
            p->close_dispatched = true;
            emit_msgpipe_event(p, MSGPIPE_EVENT_CLOSE, JS_UNDEFINED, 0);
        } else if (!p->closing_for_runtime && (!peer_eof || !at_message_boundary)) {
            /* EOF is clean only after a complete frame; a partial frame is corrupt. */
            JSValue error = tjs_new_error(ctx, nread);
            emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, error, 0);
            JS_FreeValue(ctx, error);
        }
        msgpipe_close_handle(p);
        return;
    }

    if (!p->reading.data) {
        p->reading.header_nread += (uint64_t) nread;
        if (p->reading.header_nread < sizeof(p->reading.header)) {
            return;
        }

        TJSMessagePipeFrameHeader header = p->reading.header;
        if (header.magic != MSGPIPE_FRAME_MAGIC ||
            header.version != MSGPIPE_FRAME_VERSION || header.reserved != 0 ||
            header.transfer_token == 0 || header.transfer_count > SIZE_MAX ||
            header.blob_len > SIZE_MAX) {
            msgpipe_cancel_reading_token(p);
            memset(&p->reading, 0, sizeof(p->reading));
            JSValue err = tjs_new_error(ctx, UV_EPROTO);
            emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, err, 0);
            JS_FreeValue(ctx, err);
            msgpipe_close_handle(p);
            return;
        }

        p->frame->header = header;
        total_size = header.blob_len;
        p->reading.nread = 0;

        if (total_size != 0) {
            p->reading.data = js_malloc(ctx, (size_t)total_size);
            if (!p->reading.data) {
                msgpipe_cancel_reading_token(p);
                memset(&p->reading, 0, sizeof(p->reading));
                msgpipe_frame_clear(p);
                JSValue err = tjs_new_error(ctx, UV_ENOMEM);
                emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, err, 0);
                JS_FreeValue(ctx, err);
                msgpipe_close_handle(p);
            } else {
                p->frame->blob = p->reading.data;
            }
            return;
        }

        /* Zero-length blobs still carry a valid structured-clone value. */
        goto deserialize_frame;
    }

    /* We are continuing a partial read. */
    total_size = p->reading.header.blob_len;
    p->reading.nread += nread;

    if (p->reading.nread < total_size) {
        /* We still need to read more. */

        return;
    }

    CHECK_EQ(p->reading.nread, total_size);

deserialize_frame:
    /* We have a complete frame now. The structured reader consumes the
     * out-of-band transfer table; it never expects descriptor bytes in blob.
     * Claim only now, after the complete header and blob have arrived. */
    p->frame->transfers = msgpipe_transfer_registry_claim(
        p->frame->header.transfer_token, p->frame->header.transfer_count);
    if (!p->frame->transfers) {
        msgpipe_transfer_registry_cancel(p->frame->header.transfer_token);
        JSValue err = tjs_new_error(ctx, UV_EPROTO);
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, err, 0);
        JS_FreeValue(ctx, err);
        js_free(ctx, p->reading.data);
        memset(&p->reading, 0, sizeof(p->reading));
        msgpipe_frame_clear(p);
        msgpipe_close_handle(p);
        return;
    }
    JSSABTab sab_tab = { .tab = NULL, .len = 0 };
    int flags = JS_READ_OBJ_SAB | JS_READ_OBJ_REFERENCE | JS_READ_OBJ_STRUCTURED_CLONE;
    const uint8_t *blob = p->reading.data ? p->reading.data : (const uint8_t *)"";
    JSValue obj = JS_ReadObject3(ctx, blob,
        total_size, flags, &sab_tab, &p->frame->transfers->tab);
    if (JS_IsException(obj)) {
        JSValue exc = JS_GetException(ctx);
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, exc, 0);
        JS_FreeValue(ctx, exc);
    } else {
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE, obj, total_size);
    }
    JS_FreeValue(ctx, obj);

    /* The sender transfers its SAB references with the serialized message.
     * JS_ReadObject3() consumes ordinary ArrayBuffer wire refs as well. */
    for (size_t i = 0; i < sab_tab.len; i++) {
        tjs__sab_free(NULL, sab_tab.tab[i]);
    }
    js_free(ctx, sab_tab.tab);

    js_free(ctx, p->reading.data);
    memset(&p->reading, 0, sizeof(p->reading));
    msgpipe_frame_clear(p);
}

static JSValue tjs_new_msgpipe(JSContext *ctx, uv_os_sock_t fd) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_msgpipe_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    TJSMessagePipe *p = tjs__mallocz(sizeof(*p));
    if (!p) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    p->frame = tjs__mallocz(sizeof(*p->frame));
    if (!p->frame) {
        tjs__free(p);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    p->ctx = ctx;
    p->trt = TJS_GetRuntime(ctx);
    p->self = obj;
    for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
        p->events[i] = JS_UNDEFINED;
    }
    init_list_head(&p->link);
    list_add_tail(&p->link, &p->trt->msgpipes);

#ifndef _WIN32
    CHECK_EQ(uv_pipe_init(tjs_get_loop(ctx), &p->h.pipe, 0), 0);
    CHECK_EQ(uv_pipe_open(&p->h.pipe, fd), 0);
#else
    CHECK_EQ(uv_tcp_init(tjs_get_loop(ctx), &p->h.tcp), 0);
    CHECK_EQ(uv_tcp_open(&p->h.tcp, fd), 0);
    uv_tcp_nodelay(&p->h.tcp, 1);  // Disable Nagle — small events must flush immediately.
#endif
    p->h.handle.data = p;
    CHECK_EQ(uv_read_start(&p->h.stream, uv__alloc_cb, uv__read_cb), 0);

    JS_SetOpaque(obj, p);
    return obj;
}

void tjs__close_all_msgpipes(TJSRuntime *qrt) {
    struct list_head *el, *tmp;
    list_for_each_safe(el, tmp, &qrt->msgpipes) {
        TJSMessagePipe *p = list_entry(el, TJSMessagePipe, link);
        p->closing_for_runtime = 1;
        msgpipe_clear_js(p);
        msgpipe_close_handle(p);
    }
}

static void uv__write_cb(uv_write_t *req, int status) {
    TJSMessagePipeWriteReq *wr = req->data;
    CHECK_NOT_NULL(wr);

    TJSMessagePipe *p = req->handle->data;
    CHECK_NOT_NULL(p);

    if (status < 0 && !p->finalized && !p->closing_for_runtime) {
        JSContext *ctx = p->ctx;
        JSValue error = tjs_new_error(ctx, status);
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, error, 0);
        JS_FreeValue(ctx, error);
    }

    /* js_malloc/js_free use the same allocator as tjs__malloc/tjs__free,
     * so tjs__free is safe here even after ctx/rt have been freed. */
    tjs__free(wr->data);

    /* A successful write transfers these references to the read side. A
     * failed write has no receiver to consume them. */
    if (status < 0) {
        for (size_t i = 0; i < wr->sab_count; i++) {
            tjs__sab_free(NULL, wr->sab_list[i]);
        }
    }
    tjs__free(wr->sab_list);
    if (status < 0) {
        /* The token was published before uv_write, but no complete frame was
         * delivered. Cancel drops the receiver reference. */
        msgpipe_transfer_registry_cancel(wr->transfer_token);
        msgpipe_transfer_owner_release(wr->transfer_owner);
    } else {
        msgpipe_transfer_owner_release(wr->transfer_owner);
    }
    tjs__free(wr);
}

static JSValue tjs_msgpipe_postmessage(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }
    if (p->peer_eof || uv_is_closing(&p->h.handle)) {
        return tjs_throw_errno(ctx, UV_EPIPE);
    }

    TJSMessagePipeWriteReq *wr = tjs__mallocz(sizeof(*wr));
    if (!wr) {
        return JS_ThrowOutOfMemory(ctx);
    }

    JSValueConst transfer_list = argc >= 2 ? argv[1] : JS_UNDEFINED;
    TJSMessagePipeTransferOwner *owner = msgpipe_parse_transfers(ctx, transfer_list);
    if (!owner) {
        tjs__free(wr);
        return JS_EXCEPTION;
    }

    size_t len;
    int flags = JS_WRITE_OBJ_SAB | JS_WRITE_OBJ_REFERENCE |
                JS_WRITE_OBJ_STRUCTURED_CLONE;
    JSSABTab sab_tab = { .tab = NULL, .len = 0 };
    JSAutoTransferTab *transfer_tab = &owner->tab;
    uint8_t *buf = JS_WriteObject3(ctx, &len, argv[0], flags, &sab_tab,
                                   transfer_tab);
    if (!buf) {
        msgpipe_free_transfer_values(ctx, owner);
        msgpipe_transfer_owner_release_unsent(owner);
        tjs__free(wr);
        return JS_EXCEPTION;
    }

    wr->req.data = wr;
    wr->transfer_owner = owner;
    wr->frame.header.magic = MSGPIPE_FRAME_MAGIC;
    wr->frame.header.version = MSGPIPE_FRAME_VERSION;
    wr->frame.header.reserved = 0;
    wr->frame.header.blob_len = len;
    wr->frame.header.transfer_count = owner->tab.len;

    /* JS_WriteObject2() returns QuickJS-owned memory.  The uv_write callback can
     * run during runtime shutdown, so copy the payload into neutral memory now
     * and release the QuickJS allocation while ctx is still valid. */
    wr->data = tjs__malloc(len ? len : 1);
    if (!wr->data) {
        js_free(ctx, buf);
        js_free(ctx, sab_tab.tab);
        msgpipe_free_transfer_values(ctx, owner);
        msgpipe_transfer_owner_release_unsent(owner);
        tjs__free(wr);
        return JS_ThrowOutOfMemory(ctx);
    }
    if (len) memcpy(wr->data, buf, len);
    js_free(ctx, buf);

    /* Keep SABs alive until the peer deserializes the message. The read side
     * consumes these transferred references after cloning the objects. */
    if (sab_tab.len > 0) {
        wr->sab_list = tjs__malloc(sizeof(void*) * sab_tab.len);
        if (!wr->sab_list) {
            tjs__free(wr->data);
            js_free(ctx, sab_tab.tab);
            msgpipe_free_transfer_values(ctx, owner);
            msgpipe_transfer_owner_release_unsent(owner);
            tjs__free(wr);
            return JS_ThrowOutOfMemory(ctx);
        }
        wr->sab_count = sab_tab.len;
        for (size_t i = 0; i < sab_tab.len; i++) {
            tjs__sab_dup(NULL, sab_tab.tab[i]);
            wr->sab_list[i] = sab_tab.tab[i];
        }
    }
    js_free(ctx, sab_tab.tab);

    /* Reserve neutral registry storage before commit.  Reservation is not
     * visible to readers; it makes the post-commit publish infallible. */
    TJSMessagePipeTransferRegistryEntry *registry_entry;
    if (!msgpipe_transfer_registry_reserve(owner, &registry_entry)) {
        tjs__free(wr->data);
        for (size_t i = 0; i < wr->sab_count; i++) {
            tjs__sab_free(NULL, wr->sab_list[i]);
        }
        tjs__free(wr->sab_list);
        msgpipe_free_transfer_values(ctx, owner);
        msgpipe_transfer_owner_release_unsent(owner);
        tjs__free(wr);
        return JS_ThrowOutOfMemory(ctx);
    }
    wr->transfer_token = registry_entry->token;

    /* Detach sources before exposing the token to the peer.  If commit fails,
     * no registry entry or frame is published. */
    if (JS_CommitArrayBufferTransfers(ctx, transfer_tab)) {
        tjs__free(wr->data);
        for (size_t i = 0; i < wr->sab_count; i++) {
            tjs__sab_free(NULL, wr->sab_list[i]);
        }
        tjs__free(wr->sab_list);
        msgpipe_transfer_registry_discard_reserved(registry_entry);
        msgpipe_free_transfer_values(ctx, owner);
        msgpipe_transfer_owner_release_unsent(owner);
        tjs__free(wr);
        return JS_EXCEPTION;
    }
    msgpipe_free_transfer_values(ctx, owner);

    msgpipe_transfer_registry_publish(registry_entry);
    wr->frame.header.transfer_token = wr->transfer_token;

    uv_buf_t bufs[2] = { uv_buf_init((char *) &wr->frame.header, sizeof(wr->frame.header)),
                         uv_buf_init((char *) wr->data, len) };
    int r = uv_write(&wr->req, &p->h.stream, bufs, 2, uv__write_cb);
    if (r != 0) {
        tjs__free(wr->data);
        for (size_t i = 0; i < wr->sab_count; i++) {
            tjs__sab_free(NULL, wr->sab_list[i]);
        }
        tjs__free(wr->sab_list);
        msgpipe_transfer_registry_cancel(wr->transfer_token);
        msgpipe_transfer_owner_release(owner);
        tjs__free(wr);

        return tjs_throw_errno(ctx, r);
    }

    return JS_UNDEFINED;
}

static JSValue tjs_msgpipe_ref(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }
    if (!uv_is_closing(&p->h.handle)) {
        uv_ref(&p->h.handle);
    }
    return JS_UNDEFINED;
}

static JSValue tjs_msgpipe_unref(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }
    if (!uv_is_closing(&p->h.handle)) {
        uv_unref(&p->h.handle);
        if (p->trt->is_worker && (JS_IsJobPending(p->trt->rt) || p->trt->jobs.ticks_pending)) {
            uv_stop(tjs_get_loop(ctx));
        }
    }
    return JS_UNDEFINED;
}

static JSValue tjs_msgpipe_event_get(JSContext *ctx, JSValue this_val, int magic) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }
    return JS_DupValue(ctx, p->events[magic]);
}

static JSValue tjs_msgpipe_event_set(JSContext *ctx, JSValue this_val, JSValue value, int magic) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }
    if (JS_IsFunction(ctx, value) || JS_IsUndefined(value) || JS_IsNull(value)) {
        JSValue prev = p->events[magic];
        p->events[magic] = JS_DupValue(ctx, value);
        JS_FreeValue(ctx, prev);

        if (magic == MSGPIPE_EVENT_MESSAGE && JS_IsFunction(ctx, value) && p->pending_count > 0) {
            schedule_msgpipe_drain(p);
        }
        if (magic == MSGPIPE_EVENT_CLOSE && p->peer_closed_cleanly && !p->close_dispatched
            && JS_IsFunction(ctx, value)) {
            p->close_dispatched = true;
            emit_msgpipe_event(p, MSGPIPE_EVENT_CLOSE, JS_UNDEFINED, 0);
        }
    }
    return JS_UNDEFINED;
}

static JSValue tjs_msgpipe_pending_stats(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }

    JSValue stats = JS_NewObject(ctx);
    if (JS_IsException(stats)) {
        return stats;
    }
    JS_SetPropertyStr(ctx, stats, "messages", JS_NewInt64(ctx, (int64_t) p->pending_count));
    JS_SetPropertyStr(ctx, stats, "bytes", JS_NewInt64(ctx, (int64_t) p->pending_bytes));
    /* A zero limit denotes unlimited buffering. Keep these fields for callers
     * of the diagnostic API written against the old bounded implementation. */
    JS_SetPropertyStr(ctx, stats, "dropped", JS_NewInt64(ctx, 0));
    JS_SetPropertyStr(ctx, stats, "maxMessages", JS_NewInt64(ctx, 0));
    JS_SetPropertyStr(ctx, stats, "maxBytes", JS_NewInt64(ctx, 0));
    return stats;
}

static const JSCFunctionListEntry tjs_msgpipe_proto_funcs[] = {
    TJS_CFUNC_DEF("postMessage", 2, tjs_msgpipe_postmessage),
    TJS_CFUNC_DEF("pendingStats", 0, tjs_msgpipe_pending_stats),
    TJS_CFUNC_DEF("ref", 0, tjs_msgpipe_ref),
    TJS_CFUNC_DEF("unref", 0, tjs_msgpipe_unref),
    JS_CGETSET_MAGIC_DEF("onmessage", tjs_msgpipe_event_get, tjs_msgpipe_event_set, MSGPIPE_EVENT_MESSAGE),
    JS_CGETSET_MAGIC_DEF("onmessageerror", tjs_msgpipe_event_get, tjs_msgpipe_event_set, MSGPIPE_EVENT_MESSAGE_ERROR),
    JS_CGETSET_MAGIC_DEF("onclose", tjs_msgpipe_event_get, tjs_msgpipe_event_set, MSGPIPE_EVENT_CLOSE),
};

static void reg_msgpipe(JSContext* ctx) {
	JSRuntime *rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, &tjs_msgpipe_class_id);
    JS_NewClass(rt, tjs_msgpipe_class_id, &tjs_msgpipe_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_msgpipe_proto_funcs, countof(tjs_msgpipe_proto_funcs));
    JS_SetClassProto(ctx, tjs_msgpipe_class_id, proto);
}

static JSValue tjs_new_worker(JSContext *ctx, uv_os_sock_t channel_fd);

static thread_local JSClassID tjs_worker_class_id;

/* Worker thread data passed to worker_entry */
typedef struct {
    uv_os_sock_t channel_fd;
    uv_sem_t *start_sem;
    uv_sem_t *ready_sem;
    TJSWorker *worker;
    TJSRuntime *wrt;
    _Atomic int commit_error;

	// something pass to worker
	uint8_t* udata;
	size_t udata_size;
    TJSMessagePipeTransferOwner *transfer_owner;
} worker_data_t;

static void worker_release_self(JSContext *ctx, TJSWorker *w) {
    if (!JS_IsUndefined(w->self_obj)) {
        JSValue self = w->self_obj;
        w->self_obj = JS_UNDEFINED;
        JS_FreeValue(ctx, self);
    }
}

static void worker_detach_self(TJSWorker *w) {
    w->self_obj = JS_UNDEFINED;
}

/* The runtime is stopping, but the worker thread still owns `w` until it
 * finishes TJS_FreeRuntime() and the final ownership check below. */
static void worker_mark_runtime_stopped(TJSWorker *w) {
    uv_mutex_lock(&w->lock);
    w->terminated = true;
    w->wrt = NULL;
    uv_mutex_unlock(&w->lock);
}

static void worker_mark_started(TJSWorker *w, TJSRuntime *wrt) {
    uv_mutex_lock(&w->lock);
    w->exited = false;
    w->wrt = wrt;
    uv_mutex_unlock(&w->lock);
}

static TJSRuntime *worker_get_runtime(TJSWorker *w) {
    TJSRuntime *wrt;
    uv_mutex_lock(&w->lock);
    wrt = w->wrt;
    uv_mutex_unlock(&w->lock);
    return wrt;
}

/* Request a stop AND deliver it while still holding the lock.
 * TJS_Stop() must not be called on a runtime pointer that escaped the lock:
 * worker_mark_exited() clears w->wrt under the same lock and the worker thread
 * then runs TJS_FreeRuntime(), which uv_close()s wrt->stop and frees wrt. A
 * stop delivered after that window is a use-after-free / send on a closed
 * handle. Serializing against worker_mark_exited() closes it. */
static void worker_stop_locked(TJSWorker *w) {
    uv_mutex_lock(&w->lock);
    if (!w->terminated) {
        w->terminated = true;
        if (w->wrt) TJS_Stop(w->wrt);
    }
    uv_mutex_unlock(&w->lock);
}

static bool worker_should_join(TJSWorker *w) {
    bool should_join;
    uv_mutex_lock(&w->lock);
    should_join = !w->joined;
    uv_mutex_unlock(&w->lock);
    return should_join;
}

static void worker_mark_joined(TJSWorker *w) {
    uv_mutex_lock(&w->lock);
    w->joined = true;
    w->wrt = NULL;
    uv_mutex_unlock(&w->lock);
}

/* Atomically mark that the GC finalizer has run and decide, under the lock,
 * whether the finalizer is the party responsible for freeing the struct.
 * The finalizer frees only if the worker thread has already returned; else it
 * defers to the thread (which will observe finalized_by_gc under the lock). */
static bool worker_gc_claim_free(TJSWorker *w) {
    bool free_now;
    uv_mutex_lock(&w->lock);
    w->finalized_by_gc = true;
    free_now = w->joined || w->exited;
    uv_mutex_unlock(&w->lock);
    return free_now;
}

/* Atomically mark the worker thread as returned and decide, under the lock,
 * whether the thread is responsible for freeing the struct (i.e. the GC
 * finalizer already ran and deferred to us). */
static bool worker_thread_claim_free(TJSWorker *w) {
    bool free_now;
    uv_mutex_lock(&w->lock);
    w->exited = true;
    free_now = w->finalized_by_gc;
    uv_mutex_unlock(&w->lock);
    return free_now;
}

void tjs__worker_stop_and_join(JSContext *ctx, TJSWorker *w) {
    worker_stop_locked(w);

    if (worker_should_join(w)) {
        CHECK_EQ(uv_thread_join(&w->tid), 0);
        worker_mark_joined(w);
        uv_update_time(tjs_get_loop(ctx));
        worker_release_self(ctx, w);
    }
}

/* This is what the worker runs */
static void worker_entry(void *arg) {
    worker_data_t *wd = arg;

    /* The parent owns the transfer table until it has committed the
     * serialization.  Do not create a runtime or touch workerData before the
     * parent has published that result. */
    uv_sem_wait(wd->start_sem);
    if (atomic_load_explicit(&wd->commit_error, memory_order_acquire)) {
        TJSWorker *owner = wd->worker;

        msgpipe_transfer_owner_release(wd->transfer_owner);
        wd->transfer_owner = NULL;
        tjs__free(wd->udata);
        wd->udata = NULL;
#ifndef _WIN32
        close(wd->channel_fd);
#else
        closesocket(wd->channel_fd);
#endif
        if (owner) worker_mark_runtime_stopped(owner);
        /* Wake the constructor so it can join and dispose of the owner. */
        uv_sem_post(wd->ready_sem);
        tjs__free(wd);
        if (owner && worker_thread_claim_free(owner)) {
            uv_mutex_destroy(&owner->lock);
            tjs__free(owner);
        }
        tjs_worker_count_remove();
        return;
    }

    TJSRuntime *wrt = TJS_NewRuntimeWorker();
    CHECK_NOT_NULL(wrt);
    JSContext *ctx = wrt->main_ctx;

    /* Bootstrap the worker scope. */
	reg_msgpipe(ctx);	// we should register class MessagePipe before creating
    JSValue message_pipe = tjs_new_msgpipe(ctx, wd->channel_fd);
    wrt->builtins.message_pipe = message_pipe;
	if (wd->udata){
		wrt->builtins.worker_udata = JS_ReadObject3(ctx, wd->udata,
            wd->udata_size,
            JS_READ_OBJ_REFERENCE | JS_READ_OBJ_SAB |
                JS_READ_OBJ_STRUCTURED_CLONE,
            NULL, wd->transfer_owner ? &wd->transfer_owner->tab : NULL);
		if (JS_IsException(wrt->builtins.worker_udata)) {
			JS_FreeValue(ctx, JS_GetException(ctx));
			wrt->builtins.worker_udata = JS_UNDEFINED;
		}
	} else {
		wrt->builtins.worker_udata = JS_UNDEFINED;
	}
    msgpipe_transfer_owner_release(wd->transfer_owner);
    tjs__free(wd->udata);
    wd->udata = NULL;

	/* run core bootstrap code */
	tjs__run_main(wrt);

    /* Notify the caller we are setup. */
    TJSWorker *owner = wd->worker;
    if (owner) worker_mark_started(owner, wrt);
    uv_sem_post(wd->ready_sem);
    tjs__free(wd);
    wd = NULL;

    TJS_Run(wrt);

    if (owner) worker_mark_runtime_stopped(owner);

    TJS_FreeRuntime(wrt);

    /* If the parent GC already ran tjs_worker_finalizer while we were still
     * alive, the finalizer deferred freeing the TJSWorker struct to us. The
     * parent-side message_pipe is owned by its own JS wrapper on the parent's
     * loop and is released independently of this thread.
     * The exited flag is set only here, after every worker-thread access to the
     * owner is complete. The flag and finalized_by_gc read are one atomic
     * decision under the lock, so the finalizer cannot free the owner while the
     * thread is still using it. */
    if (owner && worker_thread_claim_free(owner)) {
        uv_mutex_destroy(&owner->lock);
        tjs__free(owner);
    }
    /* Keep the fork guard active until every access to the parent-side worker
     * record has completed, not merely until the worker JS runtime is gone. */
    tjs_worker_count_remove();
}

static void tjs_worker_finalizer(JSRuntime *rt, JSValue val) {
    TJSWorker *w = JS_GetOpaque(val, tjs_worker_class_id);
    if (!w) return;

    /* self_obj is always a dup of this Worker wrapper.  Once QuickJS is
     * finalizing the wrapper, dropping that self-reference must not recurse
     * into JS_FreeValueRT() on the same JSObject. */
    worker_detach_self(w);

    /* Signal the worker thread to stop, but don't block in finalizer.
     * Blocking here can cause hangs if the worker thread is stuck in a
     * synchronous operation (deadloop, blocking syscall).
     * The thread will clean up when it exits.
     * Don't call uv_thread_join here - it can block indefinitely if the
     * worker thread is stuck. */
    worker_stop_locked(w);

    /* Drop our reference to the msgpipe wrapper. Its finalizer closes the
     * handle (setting p->finalized so uv__close_cb frees the C struct once the
     * close cb fires), which is correct whether or not the worker thread has
     * exited — the parent and child hold different handles on different loops
     * over the two ends of the socketpair. */
    JSValue message_pipe = w->message_pipe;
    w->message_pipe = JS_UNDEFINED;
    JS_FreeValueRT(rt, message_pipe);

    if (w->link.next) list_del(&w->link);

    /* Decide ownership of the struct free atomically under the lock. If the
     * worker thread has already returned we free now; otherwise the thread
     * frees it when it exits (observing finalized_by_gc under the same lock). */
    if (worker_gc_claim_free(w)) {
        uv_mutex_destroy(&w->lock);
        tjs__free(w);
    }
    // Otherwise, the thread cleanup will free w when it exits
}

static void tjs_worker_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSWorker *w = JS_GetOpaque(val, tjs_worker_class_id);
    if (w) {
        JS_MarkValue(rt, w->message_pipe, mark_func);
    }
}

static JSClassDef tjs_worker_class = {
    "Worker",
    .finalizer = tjs_worker_finalizer,
    .gc_mark = tjs_worker_mark,
};

static TJSWorker *tjs_worker_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_worker_class_id);
}

static JSValue tjs_new_worker(JSContext *ctx, uv_os_sock_t channel_fd) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_worker_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    TJSWorker *w = tjs__mallocz(sizeof(*w));
    if (!w) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    w->ctx = ctx;
    w->terminated = false;
    w->exited = false;
    w->joined = false;
    CHECK_EQ(uv_mutex_init(&w->lock), 0);
    w->self_obj = JS_UNDEFINED;
    w->message_pipe = tjs_new_msgpipe(ctx, channel_fd);

    if (JS_IsException(w->message_pipe)) {
        JS_FreeValue(ctx, obj);
        uv_mutex_destroy(&w->lock);
        tjs__free(w);
        return JS_EXCEPTION;
    }

    JS_SetOpaque(obj, w);
    return obj;
}

/* No thread owns this worker yet. Clear the opaque pointer before releasing
 * the JS values so a finalizer cannot race this synchronous error cleanup. */
static void worker_dispose_unstarted(JSContext *ctx, JSValue obj, TJSWorker *w) {
    JSValue message_pipe;

    JS_SetOpaque(obj, NULL);
    message_pipe = w->message_pipe;
    w->message_pipe = JS_UNDEFINED;
    JS_FreeValue(ctx, message_pipe);
    worker_release_self(ctx, w);
    JS_FreeValue(ctx, obj);
    uv_mutex_destroy(&w->lock);
    tjs__free(w);
}

static JSValue tjs_worker_constructor(JSContext *ctx, JSValue new_target, int argc, JSValue *argv) {
	TJSRuntime *qrt = TJS_GetRuntime(ctx);

	/* serialize user_data */
    JSValue user_data = argc >= 1 ? argv[0] : JS_UNDEFINED;
	JSValueConst transfer_list = argc >= 2 ? argv[1] : JS_UNDEFINED;
	TJSMessagePipeTransferOwner *transfer_owner =
        msgpipe_parse_transfers(ctx, transfer_list);
	if (!transfer_owner)
        return JS_EXCEPTION;
	size_t udata_size = 0;
	uint8_t* udata = NULL;
	{
		udata = JS_WriteObject3(ctx, &udata_size, user_data,
            JS_WRITE_OBJ_REFERENCE | JS_WRITE_OBJ_SAB |
                JS_WRITE_OBJ_STRUCTURED_CLONE,
            NULL, &transfer_owner->tab);
		if (!udata) {
			msgpipe_free_transfer_values(ctx, transfer_owner);
			msgpipe_transfer_owner_release_unsent(transfer_owner);
			return JS_EXCEPTION;
		}
	}
	{
		uint8_t *neutral_udata = tjs__malloc(udata_size ? udata_size : 1);
		if (!neutral_udata) {
			js_free(ctx, udata);
			msgpipe_free_transfer_values(ctx, transfer_owner);
			msgpipe_transfer_owner_release_unsent(transfer_owner);
			return JS_ThrowOutOfMemory(ctx);
		}
		if (udata_size) memcpy(neutral_udata, udata, udata_size);
		js_free(ctx, udata);
		udata = neutral_udata;
	}

    uv_os_sock_t fds[2];
    int r = uv_socketpair(SOCK_STREAM, 0, fds, UV_NONBLOCK_PIPE, UV_NONBLOCK_PIPE);
    if (r != 0) {
		tjs__free(udata);
        msgpipe_free_transfer_values(ctx, transfer_owner);
        msgpipe_transfer_owner_release_unsent(transfer_owner);
        return tjs_throw_errno(ctx, r);
    }

    JSValue obj = tjs_new_worker(ctx, fds[0]);
    if (JS_IsException(obj)) {
#ifndef _WIN32
        close(fds[0]);
        close(fds[1]);
#else
        closesocket(fds[0]);
        closesocket(fds[1]);
#endif
		tjs__free(udata);
        msgpipe_free_transfer_values(ctx, transfer_owner);
        msgpipe_transfer_owner_release_unsent(transfer_owner);
        return JS_EXCEPTION;
    }

    TJSWorker *w = tjs_worker_get(ctx, obj);
    w->self_obj = JS_DupValue(ctx, obj);

    /* We will wait for the worker to complete the creation of the VM. */
    uv_sem_t start_sem;
    uv_sem_t ready_sem;
    CHECK_EQ(uv_sem_init(&start_sem, 0), 0);
    CHECK_EQ(uv_sem_init(&ready_sem, 0), 0);

    worker_data_t *worker_data = tjs__mallocz(sizeof(*worker_data));
    if (!worker_data) {
        uv_sem_destroy(&ready_sem);
        uv_sem_destroy(&start_sem);
#ifndef _WIN32
        close(fds[1]);
#else
        closesocket(fds[1]);
#endif
        worker_dispose_unstarted(ctx, obj, w);
        tjs__free(udata);
        msgpipe_free_transfer_values(ctx, transfer_owner);
        msgpipe_transfer_owner_release_unsent(transfer_owner);
        return JS_ThrowOutOfMemory(ctx);
    }
    worker_data->channel_fd = fds[1];
    worker_data->start_sem = &start_sem;
    worker_data->ready_sem = &ready_sem;
    worker_data->worker = w;
    worker_data->udata = udata;
    worker_data->udata_size = udata_size;
    worker_data->transfer_owner = transfer_owner;
    atomic_init(&worker_data->commit_error, 1);

    tjs_worker_count_add();
    r = uv_thread_create(&w->tid, worker_entry, (void *) worker_data);
    if (r != 0) {
        tjs_worker_count_remove();
        uv_sem_destroy(&ready_sem);
        uv_sem_destroy(&start_sem);
#ifndef _WIN32
        close(fds[1]);
#else
        closesocket(fds[1]);
#endif
        tjs__free(worker_data);
        worker_dispose_unstarted(ctx, obj, w);
        tjs__free(udata);
        msgpipe_free_transfer_values(ctx, transfer_owner);
        msgpipe_transfer_owner_release_unsent(transfer_owner);
        return tjs_throw_errno(ctx, r);
    }
	/* The child is blocked on this semaphore until the transfer commit has
	 * completed. This keeps a failed commit from exposing a half-detached
	 * workerData table to JS_ReadObject3(). */
	int commit_error = JS_CommitArrayBufferTransfers(ctx, &transfer_owner->tab);
	atomic_store_explicit(&worker_data->commit_error, commit_error,
        memory_order_release);
	msgpipe_free_transfer_values(ctx, transfer_owner);
	msgpipe_transfer_owner_release(transfer_owner);
	uv_sem_post(&start_sem);

	if (commit_error) {
		/* The child releases its transfer-owner reference and signals this
		 * semaphore before returning. Join it before disposing of the owner. */
		uv_sem_wait(&ready_sem);
		CHECK_EQ(uv_thread_join(&w->tid), 0);
		worker_mark_joined(w);
		uv_sem_destroy(&ready_sem);
		uv_sem_destroy(&start_sem);
		worker_dispose_unstarted(ctx, obj, w);
		return JS_EXCEPTION;
	}
	list_add(&w->link, &qrt->workers);

    /* Wait for the worker to initialize. */
    uv_sem_wait(&ready_sem);
    uv_sem_destroy(&ready_sem);
    uv_sem_destroy(&start_sem);
	udata = NULL;

    uv_update_time(tjs_get_loop(ctx));

    CHECK_NOT_NULL(worker_get_runtime(w));

    return obj;
}

static JSValue tjs_worker_terminate(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWorker *w = tjs_worker_get(ctx, this_val);
    if (!w) {
        return JS_EXCEPTION;
    }
    tjs__worker_stop_and_join(ctx, w);
    return JS_UNDEFINED;
}

static JSValue tjs_worker_stop(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWorker *w = tjs_worker_get(ctx, this_val);
    if (!w) {
        return JS_EXCEPTION;
    }
    worker_stop_locked(w);
    return JS_UNDEFINED;
}

static JSValue tjs_worker_close_current(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    if (!trt->is_worker) {
        return JS_ThrowTypeError(ctx, "worker.close() is only available inside a worker");
    }
    TJS_Stop(trt);
    return JS_UNDEFINED;
}

static JSValue tjs_worker_get_msgpipe(JSContext *ctx, JSValue this_val) {
    TJSWorker *w = tjs_worker_get(ctx, this_val);
    if (!w) {
        return JS_EXCEPTION;
    }
    return JS_DupValue(ctx, w->message_pipe);
}

static const JSCFunctionListEntry tjs_worker_proto_funcs[] = {
    TJS_CFUNC_DEF("stop", 0, tjs_worker_stop),
    TJS_CFUNC_DEF("terminate", 0, tjs_worker_terminate),
    TJS_CGETSET_DEF("messagePipe", tjs_worker_get_msgpipe, NULL),
};

void tjs__mod_worker_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSValue proto, obj;
	TJSRuntime* trt = TJS_GetRuntime(ctx);

    /* Worker class */
    JS_NewClassID(rt, &tjs_worker_class_id);
    JS_NewClass(rt, tjs_worker_class_id, &tjs_worker_class);
    proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_worker_proto_funcs, countof(tjs_worker_proto_funcs));
    JS_SetClassProto(ctx, tjs_worker_class_id, proto);

    /* Worker object */
    obj = JS_NewCFunction2(ctx, tjs_worker_constructor, "Worker", 2, JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, obj, proto);
    JS_DefinePropertyValueStr(ctx, ns, "Worker", obj, JS_PROP_C_W_E);

    /* MessagePipe class */
	if (!trt->is_worker) reg_msgpipe(ctx);

	/* If we are in a worker, we need to initialize the pipe. */
	JS_SetPropertyStr(ctx, ns, "isWorker", JS_NewBool(ctx, trt->is_worker));
	if (trt->is_worker){
		JS_SetPropertyStr(ctx, ns, "pipe", trt->builtins.message_pipe);
		trt->builtins.message_pipe = JS_UNDEFINED;	// avoid double free
		JS_SetPropertyStr(ctx, ns, "workerData", trt->builtins.worker_udata);
		trt->builtins.worker_udata = JS_UNDEFINED;
        JS_SetPropertyStr(ctx, ns, "close", JS_NewCFunction(ctx, tjs_worker_close_current, "close", 0));
	}
}
