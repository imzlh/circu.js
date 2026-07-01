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
    MSGPIPE_EVENT_MAX,
};

static thread_local JSClassID tjs_msgpipe_class_id;

typedef struct {
    JSContext *ctx;
    TJSRuntime *trt;
    int closed;
    int finalized;
    int closing_for_runtime;
    struct list_head link;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
    } h;
    struct {
        union {
            uint64_t u64;
            uint8_t u8[8];
        } total_size;
        uint8_t *data;
        uint64_t nread;
    } reading;
    JSValue events[MSGPIPE_EVENT_MAX];
    JSValue *pending;
    size_t pending_count;
    size_t pending_cap;
} TJSMessagePipe;

typedef struct {
    uv_write_t req;
    uint8_t *data;
    union {
        uint64_t u64;
        uint8_t u8[8];
    } data_size;
    // Track SABs that were dup'd for this write, so we can free them on close
    void **sab_list;
    size_t sab_count;
} TJSMessagePipeWriteReq;

static void uv__close_cb(uv_handle_t *handle);

static void msgpipe_unlink(TJSMessagePipe *p) {
    if (p && p->link.next) {
        list_del(&p->link);
        p->link.next = NULL;
        p->link.prev = NULL;
    }
}

static void msgpipe_clear_js_rt(JSRuntime *rt, TJSMessagePipe *p) {
    for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
        JSValue event = p->events[i];
        p->events[i] = JS_UNDEFINED;
        JS_FreeValueRT(rt, event);
    }
    uint8_t *data = p->reading.data;
    memset(&p->reading, 0, sizeof(p->reading));
    js_free_rt(rt, data);
    for (size_t i = 0; i < p->pending_count; i++) {
        JS_FreeValueRT(rt, p->pending[i]);
    }
    p->pending_count = 0;
    js_free_rt(rt, p->pending);
    p->pending = NULL;
    p->pending_cap = 0;
}

static void msgpipe_clear_js(TJSMessagePipe *p) {
    for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
        JSValue event = p->events[i];
        p->events[i] = JS_UNDEFINED;
        JS_FreeValue(p->ctx, event);
    }
    uint8_t *data = p->reading.data;
    memset(&p->reading, 0, sizeof(p->reading));
    js_free(p->ctx, data);
    for (size_t i = 0; i < p->pending_count; i++) {
        JS_FreeValue(p->ctx, p->pending[i]);
    }
    p->pending_count = 0;
    js_free(p->ctx, p->pending);
    p->pending = NULL;
    p->pending_cap = 0;
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
        tjs__free(p);
    }
}

static void tjs_msgpipe_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSMessagePipe *p = JS_GetOpaque(val, tjs_msgpipe_class_id);
    if (p) {
        for (int i = 0; i < MSGPIPE_EVENT_MAX; i++) {
            JS_MarkValue(rt, p->events[i], mark_func);
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

static void emit_msgpipe_event(TJSMessagePipe *p, int event, JSValue arg) {
    JSContext *ctx = p->ctx;
    JSValue event_func = p->events[event];
    if (!JS_IsFunction(ctx, event_func)) {
        if (event == MSGPIPE_EVENT_MESSAGE) {
            if (p->pending_count >= p->pending_cap) {
                p->pending_cap = p->pending_cap ? p->pending_cap * 2 : 8;
                p->pending = js_realloc(ctx, p->pending, p->pending_cap * sizeof(JSValue));
            }
            if (p->pending) p->pending[p->pending_count++] = JS_DupValue(ctx, arg);
        }
        return;
    }

    JSValue args[2];
    args[0] = JS_DupValue(ctx, event_func);
    args[1] = JS_DupValue(ctx, arg);
    CHECK_EQ(JS_EnqueueJob(ctx, emit_event, 2, (JSValue *) args), 0);
    JS_FreeValue(ctx, args[0]);
    JS_FreeValue(ctx, args[1]);
}

static void uv__alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    TJSMessagePipe *p = handle->data;
    CHECK_NOT_NULL(p);

    if (p->reading.data) {
        buf->base = (char *) p->reading.data + p->reading.nread;
        uint64_t remaining = p->reading.total_size.u64 - p->reading.nread;
        buf->len = remaining > suggested_size ? suggested_size : remaining;
    } else {
        buf->base = (char *) p->reading.total_size.u8 + p->reading.nread;
        buf->len = sizeof(p->reading.total_size.u8) - p->reading.nread;
    }
}

static void uv__read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    TJSMessagePipe *p = handle->data;
    CHECK_NOT_NULL(p);
    if (p->finalized) return;
    if (p->closing_for_runtime) return;

    JSContext *ctx = p->ctx;

    if (nread < 0) {
        uv_read_stop(&p->h.stream);
        if (p->reading.data) {
            js_free(ctx, p->reading.data);
        }
        memset(&p->reading, 0, sizeof(p->reading));
        if (!p->closing_for_runtime) {
            /* Treat peer shutdown as a transport error too. Otherwise the
             * owner only notices a vanished worker after its own task timeout. */
            JSValue error = tjs_new_error(ctx, nread);
            emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, error);
            JS_FreeValue(ctx, error);
        }
        return;
    }

    if (!p->reading.data) {
        size_t len_size = sizeof(p->reading.total_size.u8);

        p->reading.nread += (uint64_t) nread;
        if (p->reading.nread < len_size) {
            return;
        }

        uint64_t total_size = p->reading.total_size.u64;
        p->reading.nread = 0;
        CHECK_GE(total_size, 0);

        if (total_size == 0) {
            JSSABTab sab_tab = { .tab = NULL, .len = 0 };
            JSValue obj = JS_ReadObject2(ctx, (const uint8_t *) "", 0,
                JS_READ_OBJ_SAB | JS_READ_OBJ_REFERENCE | JS_READ_OBJ_BYTECODE, &sab_tab);
            if (JS_IsException(obj)) {
                JSValue exc = JS_GetException(ctx);
                emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, exc);
                JS_FreeValue(ctx, exc);
            } else {
                emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE, obj);
            }
            JS_FreeValue(ctx, obj);
            js_free(ctx, sab_tab.tab);
            memset(&p->reading, 0, sizeof(p->reading));
            return;
        }

        p->reading.data = js_malloc(ctx, total_size);
        if (!p->reading.data) {
            memset(&p->reading, 0, sizeof(p->reading));
            JSValue err = tjs_new_error(ctx, UV_ENOMEM);
            emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, err);
            JS_FreeValue(ctx, err);
        }

        return;
    }

    /* We are continuing a partial read. */
    uint64_t total_size = p->reading.total_size.u64;
    p->reading.nread += nread;

    if (p->reading.nread < total_size) {
        /* We still need to read more. */

        return;
    }

    CHECK_EQ(p->reading.nread, total_size);

    /* We have a complete buffer now. */
    JSSABTab sab_tab = { .tab = NULL, .len = 0 };
    int flags = JS_READ_OBJ_SAB | JS_READ_OBJ_REFERENCE | JS_READ_OBJ_BYTECODE;
    JSValue obj = JS_ReadObject2(ctx, (const uint8_t *) p->reading.data, total_size, flags, &sab_tab);
    if (JS_IsException(obj)) {
        JSValue exc = JS_GetException(ctx);
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, exc);
        JS_FreeValue(ctx, exc);
    } else {
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE, obj);
    }
    JS_FreeValue(ctx, obj);

    /* Decrement the SAB reference counts and free the SAB table. */
    for (int i = 0; i < sab_tab.len; i++) {
        tjs__sab_free(NULL, sab_tab.tab[i]);
    }
    js_free(ctx, sab_tab.tab);

    js_free(ctx, p->reading.data);
    memset(&p->reading, 0, sizeof(p->reading));
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

    p->ctx = ctx;
    p->trt = TJS_GetRuntime(ctx);
    p->h.handle.data = p;
    p->events[0] = JS_UNDEFINED;
    p->events[1] = JS_UNDEFINED;
    init_list_head(&p->link);
    list_add_tail(&p->link, &p->trt->msgpipes);

    CHECK_EQ(uv_tcp_init(tjs_get_loop(ctx), &p->h.tcp), 0);
    CHECK_EQ(uv_tcp_open(&p->h.tcp, fd), 0);
    uv_tcp_nodelay(&p->h.tcp, 1);  // Disable Nagle — small events must flush immediately.
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
        emit_msgpipe_event(p, MSGPIPE_EVENT_MESSAGE_ERROR, error);
        JS_FreeValue(ctx, error);
    }

    /* js_malloc/js_free use the same allocator as tjs__malloc/tjs__free,
     * so tjs__free is safe here even after ctx/rt have been freed. */
    tjs__free(wr->data);

    // Free the SAB references that were dup'd for this write
    for (size_t i = 0; i < wr->sab_count; i++) {
        tjs__sab_free(NULL, wr->sab_list[i]);
    }
    tjs__free(wr->sab_list);
    tjs__free(wr);
}

static JSValue tjs_msgpipe_postmessage(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSMessagePipe *p = tjs_msgpipe_get(ctx, this_val);
    if (!p) {
        return JS_EXCEPTION;
    }

    TJSMessagePipeWriteReq *wr = tjs__mallocz(sizeof(*wr));
    if (!wr) {
        return JS_ThrowOutOfMemory(ctx);
    }

    size_t len;
    int flags = JS_WRITE_OBJ_SAB | JS_WRITE_OBJ_REFERENCE | JS_WRITE_OBJ_BYTECODE;
    JSSABTab sab_tab = { .tab = NULL, .len = 0 };
    uint8_t *buf = JS_WriteObject2(ctx, &len, argv[0], flags, &sab_tab);
    if (!buf) {
        tjs__free(wr);
        return JS_EXCEPTION;
    }

    wr->req.data = wr;
    wr->data_size.u64 = len;

    /* JS_WriteObject2() returns QuickJS-owned memory.  The uv_write callback can
     * run during runtime shutdown, so copy the payload into neutral memory now
     * and release the QuickJS allocation while ctx is still valid. */
    wr->data = tjs__malloc(len ? len : 1);
    if (!wr->data) {
        js_free(ctx, buf);
        js_free(ctx, sab_tab.tab);
        tjs__free(wr);
        return JS_ThrowOutOfMemory(ctx);
    }
    if (len) memcpy(wr->data, buf, len);
    js_free(ctx, buf);

    /* Increment SAB reference counts before scheduling the async write. */
    if (sab_tab.len > 0) {
        wr->sab_list = tjs__malloc(sizeof(void*) * sab_tab.len);
        if (!wr->sab_list) {
            tjs__free(wr->data);
            js_free(ctx, sab_tab.tab);
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

    uv_buf_t bufs[2] = { uv_buf_init((char *) wr->data_size.u8, sizeof(wr->data_size.u8)),
                         uv_buf_init((char *) wr->data, len) };
    int r = uv_write(&wr->req, &p->h.stream, bufs, 2, uv__write_cb);
    if (r != 0) {
        tjs__free(wr->data);
        for (size_t i = 0; i < wr->sab_count; i++) {
            tjs__sab_free(NULL, wr->sab_list[i]);
        }
        tjs__free(wr->sab_list);
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
            for (size_t i = 0; i < p->pending_count; i++) {
                JSValue args[2];
                args[0] = JS_DupValue(ctx, value);
                args[1] = p->pending[i];
                CHECK_EQ(JS_EnqueueJob(ctx, emit_event, 2, (JSValue *) args), 0);
                JS_FreeValue(ctx, args[0]);
                JS_FreeValue(ctx, p->pending[i]);
            }
            p->pending_count = 0;
        }
    }
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_msgpipe_proto_funcs[] = {
    TJS_CFUNC_DEF("postMessage", 1, tjs_msgpipe_postmessage),
    TJS_CFUNC_DEF("ref", 0, tjs_msgpipe_ref),
    TJS_CFUNC_DEF("unref", 0, tjs_msgpipe_unref),
    JS_CGETSET_MAGIC_DEF("onmessage", tjs_msgpipe_event_get, tjs_msgpipe_event_set, MSGPIPE_EVENT_MESSAGE),
    JS_CGETSET_MAGIC_DEF("onmessageerror", tjs_msgpipe_event_get, tjs_msgpipe_event_set, MSGPIPE_EVENT_MESSAGE_ERROR),
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
    uv_sem_t *sem;
    TJSWorker *worker;
    TJSRuntime *wrt;
    int init_error;

	// something pass to worker
	uint8_t* udata;
	size_t udata_size;
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

static void worker_mark_exited(TJSWorker *w) {
    uv_mutex_lock(&w->lock);
    w->terminated = true;
    w->wrt = NULL;
    uv_mutex_unlock(&w->lock);
}

static void worker_mark_started(TJSWorker *w, TJSRuntime *wrt) {
    uv_mutex_lock(&w->lock);
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

static TJSRuntime *worker_request_stop(TJSWorker *w) {
    TJSRuntime *wrt = NULL;
    uv_mutex_lock(&w->lock);
    if (!w->terminated) {
        w->terminated = true;
        wrt = w->wrt;
    }
    uv_mutex_unlock(&w->lock);
    return wrt;
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

static bool worker_is_done(TJSWorker *w) {
    bool done;
    uv_mutex_lock(&w->lock);
    done = w->joined || w->wrt == NULL;
    uv_mutex_unlock(&w->lock);
    return done;
}

void tjs__worker_stop_and_join(JSContext *ctx, TJSWorker *w) {
    TJSRuntime *wrt = worker_request_stop(w);
    if (wrt != NULL) TJS_Stop(wrt);

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

    TJSRuntime *wrt = TJS_NewRuntimeWorker();
    CHECK_NOT_NULL(wrt);
    JSContext *ctx = wrt->main_ctx;

    /* Bootstrap the worker scope. */
	reg_msgpipe(ctx);	// we should register class MessagePipe before creating
    JSValue message_pipe = tjs_new_msgpipe(ctx, wd->channel_fd);
    wrt->builtins.message_pipe = message_pipe;
	if (wd->udata){
		wrt->builtins.worker_udata = JS_ReadObject(ctx, wd->udata, wd->udata_size, JS_READ_OBJ_REFERENCE | JS_READ_OBJ_BYTECODE | JS_READ_OBJ_SAB);
		if (JS_IsException(wrt->builtins.worker_udata)) {
			JS_FreeValue(ctx, JS_GetException(ctx));
			wrt->builtins.worker_udata = JS_UNDEFINED;
		}
	} else {
		wrt->builtins.worker_udata = JS_UNDEFINED;
	}

	/* run core bootstrap code */
	tjs__run_main(wrt);

    /* Notify the caller we are setup. */
    TJSWorker *owner = wd->worker;
    if (owner) worker_mark_started(owner, wrt);
    uv_sem_post(wd->sem);
    tjs__free(wd);
    wd = NULL;

    TJS_Run(wrt);

    if (owner) worker_mark_exited(owner);

    TJS_FreeRuntime(wrt);

    /* If the parent GC already ran tjs_worker_finalizer while we were
     * still alive, the finalizer deferred freeing the TJSWorker struct
     * to us.  The finalizer already closed the parent-side message_pipe
     * TCP handle; TJS_FreeRuntime pumped the loop so the close callback
     * has fired and freed the TJSMessagePipe C struct.  Now free w. */
    if (owner && owner->finalized_by_gc) {
        uv_mutex_destroy(&owner->lock);
        tjs__free(owner);
    }
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
     * The thread will clean up when it exits. */
    TJSRuntime *wrt = worker_request_stop(w);
    if (wrt != NULL) {
        TJS_Stop(wrt);
        // Don't call uv_thread_join here - it can block indefinitely
        // if the worker thread is stuck. The thread will clean up on exit.
    }

    if (worker_is_done(w)) {
        JSValue message_pipe = w->message_pipe;
        w->message_pipe = JS_UNDEFINED;
        JS_FreeValueRT(rt, message_pipe);
    } else {
        /* Thread still alive — we cannot block here (may deadlock).
         * Close the parent-side TCP handle now so the socket does not
         * leak.  TJS_FreeRuntime will pump the loop and fire the close
         * callback, freeing the TJSMessagePipe C struct.
         * The thread will free w itself when it exits. */
        TJSMessagePipe *mp = JS_GetOpaque(w->message_pipe, tjs_msgpipe_class_id);
        if (mp && !uv_is_closing(&mp->h.handle)) {
            uv_read_stop(&mp->h.stream);
            uv_close(&mp->h.handle, uv__close_cb);
        }
        w->message_pipe = JS_UNDEFINED;
        w->finalized_by_gc = true;
    }

    if (w->link.next) list_del(&w->link);
    // Don't free w here if thread is still running - let thread cleanup handle it
    if (worker_is_done(w)) {
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

static JSValue tjs_worker_constructor(JSContext *ctx, JSValue new_target, int argc, JSValue *argv) {
	TJSRuntime *qrt = TJS_GetRuntime(ctx);

	/* serialize user_data */
    JSValue user_data = argc >= 1 ? argv[0] : JS_UNDEFINED;
	size_t udata_size = 0;
	uint8_t* udata = NULL;
	if (!JS_IsUndefined(user_data) && !JS_IsNull(user_data)){
		udata = JS_WriteObject(ctx, &udata_size, user_data, JS_WRITE_OBJ_REFERENCE | JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_SAB);
		if (!udata) {
			return JS_EXCEPTION;
		}
	}

    uv_os_sock_t fds[2];
    int r = uv_socketpair(SOCK_STREAM, 0, fds, UV_NONBLOCK_PIPE, UV_NONBLOCK_PIPE);
    if (r != 0) {
		js_free(ctx, udata);
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
		js_free(ctx, udata);
        return JS_EXCEPTION;
    }

    TJSWorker *w = tjs_worker_get(ctx, obj);
    w->self_obj = JS_DupValue(ctx, obj);

    /* We will wait for the worker to complete the creation of the VM. */
    uv_sem_t sem;
    CHECK_EQ(uv_sem_init(&sem, 0), 0);

    worker_data_t *worker_data = tjs__mallocz(sizeof(*worker_data));
    if (!worker_data) {
        uv_sem_destroy(&sem);
#ifndef _WIN32
        close(fds[1]);
#else
        closesocket(fds[1]);
#endif
        JS_FreeValue(ctx, obj);
        js_free(ctx, udata);
        return JS_ThrowOutOfMemory(ctx);
    }
    worker_data->channel_fd = fds[1];
    worker_data->sem = &sem;
    worker_data->worker = w;
    worker_data->udata = udata;
    worker_data->udata_size = udata_size;

    CHECK_EQ(uv_thread_create(&w->tid, worker_entry, (void *) worker_data), 0);
	list_add(&w->link, &qrt->workers);

    /* Wait for the worker to initialize. */
    uv_sem_wait(&sem);
    uv_sem_destroy(&sem);
	if (udata) {
		js_free(ctx, udata);
		udata = NULL;
	}

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

static JSValue tjs_worker_get_msgpipe(JSContext *ctx, JSValue this_val) {
    TJSWorker *w = tjs_worker_get(ctx, this_val);
    if (!w) {
        return JS_EXCEPTION;
    }
    return JS_DupValue(ctx, w->message_pipe);
}

static const JSCFunctionListEntry tjs_worker_proto_funcs[] = {
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
	}
}
