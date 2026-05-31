/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
 * Copyright (c) 2025-2026 iz <himzlh@163.com>
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
#include "utils.h"

#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#else
#include <io.h>
#include <winsock2.h>
#include <mswsock.h>
#endif


/* ---- Forward declarations ---- */
static JSValue tjs_new_tcp(JSContext *ctx, int af);
JSValue tjs_new_pipe(JSContext *ctx);  /* exported: used by other modules */


/* ---- Data structures ---- */
enum {
    STREAM_CB_READ = 0,    /* onread(data, error) */
    STREAM_CB_CONNECTION,  /* onconnection(error, client) */
    STREAM_CB_CLOSE,       /* onclose() */
    STREAM_CB_MAX
};

typedef struct TJSReadReq TJSReadReq;

typedef struct {
    JSContext *ctx;
    int closed;
    int finalized;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t    tcp;
        uv_tty_t    tty;
        uv_pipe_t   pipe;
    } h;
    JSValue obj;                     /* GC pin — not in gc_mark to prevent false cycle detection */
    JSValue callbacks[STREAM_CB_MAX];
    uint8_t *read_buf;               /* dynamically allocated for the streaming onread path */
    TJSReadReq *read_req;            /* non-NULL while a one-shot read(buf) is in flight */
    TJSPromise connect_promise;
    TJSPromise shutdown_promise;

    // for tty only
    int tty_mode;
} TJSStream;

typedef struct {
    uv_write_t req;
    JSValue buf;        /* pinned to prevent GC during async write */
    TJSPromise result;
    uint8_t *data;      /* native write buffer owned by the request */
    int total;          /* original byte count, reported on resolve */
} TJSWriteReq;

struct TJSReadReq {
    JSValue buf;        /* user-provided buffer, pinned */
    TJSPromise result;
    uint8_t *data;      /* native read buffer owned by the request */
    size_t data_len;
    int settled;        /* promise already resolved/rejected */
    int canceled;       /* close() requested while read was in flight */
};

static void tjs_read_req_free(JSContext *ctx, TJSReadReq *rr) {
    if (!rr) return;
    js_free(ctx, rr->data);
    JS_FreeValue(ctx, rr->buf);
    js_free(ctx, rr);
}

static void tjs_read_req_free_rt(JSRuntime *rt, TJSReadReq *rr) {
    if (!rr) return;
    js_free_rt(rt, rr->data);
    TJS_FreePromiseRT(rt, &rr->result);
    JS_FreeValueRT(rt, rr->buf);
    js_free_rt(rt, rr);
}

static void tjs_write_req_free(JSContext *ctx, TJSWriteReq *wr) {
    if (!wr) return;
    js_free(ctx, wr->data);
    JS_FreeValue(ctx, wr->buf);
    js_free(ctx, wr);
}


/* ---- Class IDs (assigned at init time, used by finalizers and gc_mark) ---- */
static JSClassID tjs_tcp_class_id;
static JSClassID tjs_tty_class_id;
static JSClassID tjs_pipe_class_id;

#pragma region Inline helpers
/* Get the TJSStream from any stream-derived JS object (TCP/TTY/Pipe). */
static inline TJSStream *stream_get_any(JSContext *ctx, JSValue obj) {
    JSClassID cid;
    (void)ctx;
    return JS_GetAnyOpaque(obj, &cid);
}

/* Throw and return false if the handle is already closing. */
static inline bool stream_check_open(JSContext *ctx, TJSStream *s) {
    if (uv_is_closing(&s->h.handle)) {
        tjs_throw_errno(ctx, UV_ECONNRESET);
        return false;
    }
    return true;
}

/* Pin the JS object to prevent GC while async work is in flight. Idempotent. */
static inline void stream_pin(JSContext *ctx, TJSStream *s, JSValue obj) {
    if (JS_IsUndefined(s->obj))
        s->obj = JS_DupValue(ctx, obj);
}

/* Release the GC pin. */
static inline void stream_unpin(TJSStream *s) {
    if (!JS_IsUndefined(s->obj)) {
        JS_FreeValue(s->ctx, s->obj);
        s->obj = JS_UNDEFINED;
    }
}

/* Get the OS file descriptor, -1 on error. */
static inline int stream_get_fd(TJSStream *s) {
    uv_os_fd_t fd;
    if (uv_fileno(&s->h.handle, &fd) != 0) return -1;
#ifdef _WIN32
    return (int)(intptr_t)fd;
#else
    return (int)fd;
#endif
}

#pragma endregion
#pragma callbacks
static void uv__close_cb(uv_handle_t *handle) {
    TJSStream *s = handle->data;
    CHECK_NOT_NULL(s);
    s->closed = 1;

    if (s->read_req && (s->read_req->canceled || s->read_req->settled)) {
        tjs_read_req_free(s->ctx, s->read_req);
        s->read_req = NULL;
    }

    /* Fire onclose callback if set. */
    JSValue fn = s->callbacks[STREAM_CB_CLOSE];
    if (JS_IsFunction(s->ctx, fn)) {
        tjs_call_handler(s->ctx, fn, 0, NULL);
    }

    /* Keep the JS wrapper pinned until libuv has fully finished closing.
     * Close can still trigger read cancellation callbacks before this point. */
    stream_unpin(s);

    if (s->finalized)
        tjs__free(s);
}

static void maybe_close(TJSStream *s) {
    if (!uv_is_closing(&s->h.handle))
        uv_close(&s->h.handle, uv__close_cb);
}

static JSValue tjs_stream_callback_get(JSContext *ctx, JSValue this_val, int magic) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    return JS_DupValue(ctx, s->callbacks[magic]);
}

static JSValue tjs_stream_callback_set(JSContext *ctx, JSValue this_val, JSValue value, int magic) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (JS_IsFunction(ctx, value) || JS_IsUndefined(value) || JS_IsNull(value)) {
        JS_FreeValue(ctx, s->callbacks[magic]);
        s->callbacks[magic] = JS_DupValue(ctx, value);
    }
    return JS_UNDEFINED;
}

/* Invoke a stream callback if set, always frees argv values. */
static void invoke_cb(TJSStream *s, int cb, int argc, JSValue *argv) {
    JSContext *ctx = s->ctx;
    JSValue fn = s->callbacks[cb];
    if (JS_IsFunction(ctx, fn))
        tjs_call_handler(ctx, fn, argc, argv);
    for (int i = 0; i < argc; i++)
        JS_FreeValue(ctx, argv[i]);
}


static JSValue tjs_stream_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;

    if (s->read_req) {
        TJSReadReq *rr = s->read_req;
        rr->canceled = 1;
        uv_read_stop(&s->h.stream);

        if (!rr->settled) {
            JSValue arg = tjs_new_error(ctx, UV_ECANCELED);
            rr->settled = 1;
            TJS_RejectPromise(ctx, &rr->result, 1, &arg);
        }
    }

    maybe_close(s);
    return JS_UNDEFINED;
}


static void uv__stream_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    TJSStream *s = handle->data;
    CHECK_NOT_NULL(s);
    s->read_buf = js_malloc(s->ctx, suggested_size);
    if (s->read_buf) {
        buf->base = (char *)s->read_buf;
        buf->len  = suggested_size;
    } else {
        buf->base = NULL;
        buf->len  = 0;
    }
}

static void uv__stream_read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    TJSStream *s = handle->data;
    CHECK_NOT_NULL(s);
    JSContext *ctx = s->ctx;

    if (nread == 0) { /* EAGAIN — nothing to read, discard buffer */
        js_free(ctx, s->read_buf);
        s->read_buf = NULL;
        return;
    }

    JSValue args[2];
    if (nread < 0) {
        js_free(ctx, s->read_buf);
        s->read_buf = NULL;
        if (nread == UV_EOF) {
            args[0] = JS_NULL;       /* EOF: onread(null, undefined) */
            args[1] = JS_UNDEFINED;
        } else {
            args[0] = JS_UNDEFINED;
            args[1] = tjs_new_error(ctx, nread);
        }
    } else {
        /* Hand off ownership of read_buf to the new Uint8Array. */
        args[0] = TJS_NewUint8Array(ctx, s->read_buf, nread);
        args[1] = JS_UNDEFINED;
        s->read_buf = NULL;
    }

    invoke_cb(s, STREAM_CB_READ, 2, args);
}

static JSValue tjs_stream_start_read(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!stream_check_open(ctx, s)) return JS_EXCEPTION;

    int r = uv_read_start(&s->h.stream, uv__stream_alloc_cb, uv__stream_read_cb);
    if (r != 0) return tjs_throw_errno(ctx, r);
    stream_pin(ctx, s, this_val);
    return JS_UNDEFINED;
}

static JSValue tjs_stream_stop_read(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (uv_is_closing(&s->h.handle)) return JS_UNDEFINED;
    uv_read_stop(&s->h.stream);
    js_free(ctx, s->read_buf);
    s->read_buf = NULL;
    stream_unpin(s);
    return JS_UNDEFINED;
}

static void uv__write_cb(uv_write_t *req, int status) {
    TJSWriteReq *wr = req->data;
    TJSStream *s    = req->handle->data;
    CHECK_NOT_NULL(s);
    JSContext *ctx = s->ctx;

    if (status < 0) {
        JSValue arg = tjs_new_error(ctx, status);
        TJS_RejectPromise(ctx, &wr->result, 1, &arg);
    } else {
        JSValue arg = JS_NewInt32(ctx, wr->total);
        TJS_ResolvePromise(ctx, &wr->result, 1, &arg);
    }

    tjs_write_req_free(ctx, wr);
}

static JSValue tjs_stream_write(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!stream_check_open(ctx, s)) return JS_EXCEPTION;

    size_t sz;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &sz, argv[0]);
    if (!buf) return JS_EXCEPTION;

    /* Fast path: everything written inline. */
    uv_buf_t b = uv_buf_init((char *)buf, sz);
    int r = uv_try_write(&s->h.stream, &b, 1);
    if (r == (int)sz) {
        JSValue arg = JS_NewInt32(ctx, (int32_t)sz);
        return TJS_NewResolvedPromise(ctx, 1, &arg);
    }

    /* Partial or EAGAIN: async write for the remainder. */
    int sync = (r >= 0) ? r : 0;
    buf += sync;
    sz  -= sync;

    TJSWriteReq *wr = js_malloc(ctx, sizeof(*wr));
    if (!wr) return JS_EXCEPTION;
    memset(wr, 0, sizeof(*wr));
    wr->req.data = wr;
    wr->buf      = JS_DupValue(ctx, argv[0]); /* pin: buf pointer must stay valid */
    wr->total    = (int)(sync + sz);          /* == original sz */
    wr->data     = js_malloc(ctx, sz);
    if (!wr->data) {
        JS_FreeValue(ctx, wr->buf);
        js_free(ctx, wr);
        return JS_ThrowOutOfMemory(ctx);
    }
    memcpy(wr->data, buf, sz);

    b = uv_buf_init((char *)wr->data, sz);
    r = uv_write(&wr->req, &s->h.stream, &b, 1, uv__write_cb);
    if (r != 0) {
        tjs_write_req_free(ctx, wr);
        return tjs_throw_errno(ctx, r);
    }

    return TJS_InitPromise(ctx, &wr->result);
}

static void uv__read_once_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    TJSStream *s = handle->data;
    CHECK_NOT_NULL(s);
    (void)suggested_size;
    TJSReadReq *rr = s->read_req;
    if (rr && rr->data && rr->data_len > 0) {
        buf->base = (char *)rr->data;
        buf->len  = rr->data_len;
        return;
    }
    buf->base = NULL;
    buf->len  = 0;
}

static void uv__read_once_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    TJSStream *s = handle->data;
    CHECK_NOT_NULL(s);
    uv_read_stop(&s->h.stream);

    JSContext *ctx = s->ctx;
    TJSReadReq *rr = s->read_req;
    s->read_req    = NULL;
    stream_unpin(s);

    /* close() can race with a pending one-shot read. If the request was
     * already cleaned up while the handle was shutting down, ignore the
     * cancellation callback instead of dereferencing freed state. */
    if (!rr)
        return;

    if (rr->canceled || rr->settled) {
        tjs_read_req_free(ctx, rr);
        return;
    }

    JSValue arg;
    if (nread > 0) {
        size_t sz;
        uint8_t *data = JS_GetAnyBuffer(ctx, &sz, rr->buf);
        if (!data || sz < (size_t)nread) {
            arg = JS_NewInternalError(ctx, "read buffer became invalid");
            rr->settled = 1;
            TJS_RejectPromise(ctx, &rr->result, 1, &arg);
            tjs_read_req_free(ctx, rr);
            return;
        }
        memcpy(data, rr->data, (size_t)nread);
        arg = JS_NewInt32(ctx, (int32_t)nread);
        rr->settled = 1;
        TJS_ResolvePromise(ctx, &rr->result, 1, &arg);
    } else if (nread == 0 || nread == UV_EOF) {
        /* EAGAIN or EOF: resolve with 0 */
        arg = JS_NewInt32(ctx, 0);
        rr->settled = 1;
        TJS_ResolvePromise(ctx, &rr->result, 1, &arg);
    } else {
        arg = tjs_new_error(ctx, nread);
        rr->settled = 1;
        TJS_RejectPromise(ctx, &rr->result, 1, &arg);
    }

    tjs_read_req_free(ctx, rr);
}

static JSValue tjs_stream_read(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!stream_check_open(ctx, s)) return JS_EXCEPTION;
    if (s->read_req)
        return JS_ThrowInternalError(ctx, "read already in progress");

    size_t sz;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &sz, argv[0]);
    if (!buf) return JS_EXCEPTION;
    if (sz == 0) return JS_ThrowTypeError(ctx, "read buffer must not be empty");

    TJSReadReq *rr = js_malloc(ctx, sizeof(*rr));
    if (!rr) return JS_EXCEPTION;
    memset(rr, 0, sizeof(*rr));
    rr->buf     = JS_DupValue(ctx, argv[0]);
    rr->data    = js_malloc(ctx, sz);
    rr->data_len = sz;
    if (!rr->data) {
        JS_FreeValue(ctx, rr->buf);
        js_free(ctx, rr);
        return JS_ThrowOutOfMemory(ctx);
    }
    s->read_req = rr;
    stream_pin(ctx, s, this_val);

    int r = uv_read_start(&s->h.stream, uv__read_once_alloc_cb, uv__read_once_cb);
    if (r != 0) {
        s->read_req = NULL;
        tjs_read_req_free(ctx, rr);
        stream_unpin(s);
        return tjs_throw_errno(ctx, r);
    }

    return TJS_InitPromise(ctx, &rr->result);
}

static void uv__shutdown_cb(uv_shutdown_t *req, int status) {
    TJSStream *s = req->handle->data;
    CHECK_NOT_NULL(s);
    JSContext *ctx = s->ctx;

    if (status == 0) {
        TJS_ResolvePromise(ctx, &s->shutdown_promise, 0, NULL);
    } else {
        JSValue arg = tjs_new_error(ctx, status);
        TJS_RejectPromise(ctx, &s->shutdown_promise, 1, &arg);
    }

    js_free(ctx, req);
}

static JSValue tjs_stream_shutdown(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!stream_check_open(ctx, s)) return JS_EXCEPTION;
    if (!JS_IsUndefined(s->shutdown_promise.p))
        return JS_ThrowInternalError(ctx, "shutdown already in progress");

    uv_shutdown_t *req = js_malloc(ctx, sizeof(*req));
    if (!req) return JS_EXCEPTION;
    req->data = s;

    int r = uv_shutdown(req, &s->h.stream, uv__shutdown_cb);
    if (r != 0) {
        js_free(ctx, req);
        return tjs_throw_errno(ctx, r);
    }

    return TJS_InitPromise(ctx, &s->shutdown_promise);
}

static void uv__connect_cb(uv_connect_t *req, int status) {
    TJSStream *s = req->handle->data;
    CHECK_NOT_NULL(s);
    JSContext *ctx = s->ctx;

    if (status == 0) {
        TJS_ResolvePromise(ctx, &s->connect_promise, 0, NULL);
    } else {
        JSValue arg = tjs_new_error(ctx, status);
        TJS_RejectPromise(ctx, &s->connect_promise, 1, &arg);
    }

    /* Unpin unless startRead() re-pinned inside the connect handler. */
    if (!uv_is_active(&s->h.handle))
        stream_unpin(s);

    js_free(ctx, req);
}

static void uv__connection_cb(uv_stream_t *handle, int status) {
    TJSStream *s = handle->data;
    CHECK_NOT_NULL(s);
    if (!JS_IsFunction(s->ctx, s->callbacks[STREAM_CB_CONNECTION]))
        return;

    JSContext *ctx = s->ctx;
    JSValue args[2];

    if (status != 0) {
        args[0] = tjs_new_error(ctx, status);
        args[1] = JS_UNDEFINED;
        invoke_cb(s, STREAM_CB_CONNECTION, 2, args);
        return;
    }

    /* Create a new client stream of the same handle type. */
    JSValue client_obj;
    switch (handle->type) {
        case UV_TCP:         client_obj = tjs_new_tcp(ctx, AF_UNSPEC); break;
        case UV_NAMED_PIPE:  client_obj = tjs_new_pipe(ctx);           break;
        default:             abort();
    }

    if (JS_IsException(client_obj)) {
        args[0] = JS_GetException(ctx);
        args[1] = JS_UNDEFINED;
        invoke_cb(s, STREAM_CB_CONNECTION, 2, args);
        return;
    }

    JSClassID cid;
    TJSStream *client = JS_GetAnyOpaque(client_obj, &cid);
    int r = uv_accept(handle, &client->h.stream);
    if (r != 0) {
        JS_FreeValue(ctx, client_obj);
        args[0] = tjs_new_error(ctx, r);
        args[1] = JS_UNDEFINED;
    } else {
        args[0] = JS_UNDEFINED;
        args[1] = client_obj;
    }

    invoke_cb(s, STREAM_CB_CONNECTION, 2, args);
}

static JSValue tjs_stream_listen(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;

    uint32_t backlog = 511;
    if (!JS_IsUndefined(argv[0]) && JS_ToUint32(ctx, &backlog, argv[0]))
        return JS_EXCEPTION;

    int r = uv_listen(&s->h.stream, (int)backlog, uv__connection_cb);
    if (r != 0) return tjs_throw_errno(ctx, r);
    stream_pin(ctx, s, this_val);
    return JS_UNDEFINED;
}

#pragma endregion
#pragma region misc funcs
static JSValue tjs_stream_set_blocking(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    int blocking = JS_ToBool(ctx, argv[0]);
    if (blocking == -1) return JS_EXCEPTION;
    int r = uv_stream_set_blocking(&s->h.stream, blocking);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

static JSValue tjs_stream_get_fileno(JSContext *ctx, JSValue this_val) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    uv_os_fd_t fd;
    int r = uv_fileno(&s->h.handle, &fd);
    if (r != 0) return tjs_throw_errno(ctx, r);
#ifdef _WIN32
    return JS_NewInt32(ctx, (int32_t)(intptr_t)fd);
#else
    return JS_NewInt32(ctx, (int32_t)fd);
#endif
}

static JSValue tjs_stream_ref(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!uv_is_closing(&s->h.handle)) uv_ref(&s->h.handle);
    return JS_UNDEFINED;
}

static JSValue tjs_stream_unref(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!uv_is_closing(&s->h.handle)) uv_unref(&s->h.handle);
    return JS_UNDEFINED;
}


#pragma endregion
#pragma region sync funcs

/* readSync(buf) → number of bytes read, or null on EOF */
static JSValue tjs_stream_read_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
#ifdef _WIN32
    return JS_ThrowTypeError(ctx, "readSync() is not supported on Windows. use waitPromise() instead");
#else
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!stream_check_open(ctx, s)) return JS_EXCEPTION;
    int fd = stream_get_fd(s);
    if (fd < 0) return tjs_throw_errno(ctx, UV_EBADF);

    size_t sz;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &sz, argv[0]);
    if (!buf) return JS_EXCEPTION;

    ssize_t n;
    n = read(fd, buf, sz);
    if (n < 0) return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
    return n == 0 ? JS_NULL : JS_NewInt32(ctx, (int32_t)n);
#endif
}

/* writeSync(buf) → number of bytes written */
static JSValue tjs_stream_write_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
#ifdef _WIN32
    return JS_ThrowTypeError(ctx, "writeSync() is not supported on Windows. use waitPromise() instead");
#else
    TJSStream *s = stream_get_any(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!stream_check_open(ctx, s)) return JS_EXCEPTION;
    int fd = stream_get_fd(s);
    if (fd < 0) return tjs_throw_errno(ctx, UV_EBADF);

    size_t sz;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &sz, argv[0]);
    if (!buf) return JS_EXCEPTION;

    ssize_t n;
    n = write(fd, buf, sz);
    if (n < 0) return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
    return JS_NewInt64(ctx, n);
#endif
}


#pragma endregion
#pragma region C apis

static JSValue tjs_init_stream(JSContext *ctx, JSValue obj, TJSStream *s) {
    s->ctx           = ctx;
    s->h.handle.data = s;
    s->obj           = JS_UNDEFINED;
    s->read_buf      = NULL;
    s->read_req      = NULL;

    for (int i = 0; i < STREAM_CB_MAX; i++)
        s->callbacks[i] = JS_UNDEFINED;

    /*
     * Set promise .p to JS_UNDEFINED so that the "already in progress" guards
     * (`!JS_IsUndefined(s->xxx_promise.p)`) start in the correct state.
     * The remaining fields of TJSPromise (resolve/reject) are left zeroed
     * by tjs__mallocz; JS_FreeValueRT treats zero JSValues as no-ops.
     */
    s->connect_promise.p  = JS_UNDEFINED;
    s->shutdown_promise.p = JS_UNDEFINED;

    JS_SetOpaque(obj, s);
    return obj;
}

static void tjs_stream_finalizer(JSRuntime *rt, TJSStream *s) {
    if (!s) return;

    JS_FreeValueRT(rt, s->obj);
    for (int i = 0; i < STREAM_CB_MAX; i++)
        JS_FreeValueRT(rt, s->callbacks[i]);

    /* read_buf must be NULL'd: uv_close below will trigger one final
     * uv__stream_read_cb with UV_ECANCELED, which would double-free it. */
    js_free_rt(rt, s->read_buf);
    s->read_buf = NULL;

    if (s->read_req) {
        tjs_read_req_free_rt(rt, s->read_req);
        s->read_req = NULL;
    }

    if (!JS_IsUndefined(s->shutdown_promise.p))
        TJS_FreePromiseRT(rt, &s->shutdown_promise);

    if (!JS_IsUndefined(s->connect_promise.p))
        TJS_FreePromiseRT(rt, &s->connect_promise);

    s->finalized = 1;
    if (s->closed)
        tjs__free(s);
    else
        maybe_close(s);
}

static void tjs_stream_mark(JSRuntime *rt, TJSStream *s, JS_MarkFunc *mark_func) {
    if (!s) return;

    for (int i = 0; i < STREAM_CB_MAX; i++)
        JS_MarkValue(rt, s->callbacks[i], mark_func);

    if (s->read_req) {
        TJS_MarkPromise(rt, &s->read_req->result, mark_func);
        JS_MarkValue(rt, s->read_req->buf, mark_func);
    }

    TJS_MarkPromise(rt, &s->connect_promise, mark_func);
    TJS_MarkPromise(rt, &s->shutdown_promise, mark_func);
}


#pragma endregion
#pragma region class tcp

static void tjs_tcp_finalizer(JSRuntime *rt, JSValue val) {
    tjs_stream_finalizer(rt, JS_GetOpaque(val, tjs_tcp_class_id));
}
static void tjs_tcp_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    tjs_stream_mark(rt, JS_GetOpaque(val, tjs_tcp_class_id), mark_func);
}
static JSClassDef tjs_tcp_class = {
    "TCP",
    .finalizer = tjs_tcp_finalizer,
    .gc_mark   = tjs_tcp_mark,
};

static JSValue tjs_new_tcp(JSContext *ctx, int af) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_tcp_class_id);
    if (JS_IsException(obj)) return obj;

    TJSStream *s = tjs__mallocz(sizeof(*s));
    if (!s) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    int r = uv_tcp_init_ex(tjs_get_loop(ctx), &s->h.tcp, af);
    if (r != 0) {
        JS_FreeValue(ctx, obj);
        tjs__free(s);
        return tjs_throw_errno(ctx, r);
    }

    return tjs_init_stream(ctx, obj, s);
}

static JSValue tjs_tcp_constructor(JSContext *ctx, JSValue new_target, int argc, JSValue *argv) {
    int af = AF_UNSPEC;
    if (!JS_IsUndefined(argv[0]) && JS_ToInt32(ctx, &af, argv[0]))
        return JS_EXCEPTION;
    return tjs_new_tcp(ctx, af);
}

static TJSStream *tjs_tcp_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_tcp_class_id);
}

static JSValue tjs_tcp_get_sockpeername(JSContext *ctx, JSValue this_val, int magic) {
    TJSStream *t = tjs_tcp_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    struct sockaddr_storage addr;
    int namelen = sizeof(addr);
    int r = magic == 0
        ? uv_tcp_getsockname(&t->h.tcp, (struct sockaddr *)&addr, &namelen)
        : uv_tcp_getpeername(&t->h.tcp, (struct sockaddr *)&addr, &namelen);
    if (r != 0) return tjs_throw_errno(ctx, r);
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    tjs_addr2obj(ctx, obj, (struct sockaddr *)&addr, false);
    return obj;
}

static JSValue tjs_tcp_connect(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_tcp_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    if (!JS_IsUndefined(t->connect_promise.p))
        return JS_ThrowInternalError(ctx, "connect already in progress");

    struct sockaddr_storage ss;
    if (tjs_obj2addr(ctx, argv[0], &ss) != 0) return JS_EXCEPTION;

    uv_connect_t *req = js_malloc(ctx, sizeof(*req));
    if (!req) return JS_EXCEPTION;

    int r = uv_tcp_connect(req, &t->h.tcp, (struct sockaddr *)&ss, uv__connect_cb);
    if (r != 0) {
        js_free(ctx, req);
        return tjs_throw_errno(ctx, r);
    }

    stream_pin(ctx, t, this_val);
    return TJS_InitPromise(ctx, &t->connect_promise);
}

/* connectSync: blocking OS connect with timeout, hands the fd to libuv. */
static JSValue tjs_tcp_connect_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_tcp_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    if (!stream_check_open(ctx, t)) return JS_EXCEPTION;

    // uv_tcp_open requires the handle to not have a fd yet
    if (stream_get_fd(t) >= 0)
        return JS_ThrowInternalError(ctx, "socket already open");

    struct sockaddr_storage ss;
    if (tjs_obj2addr(ctx, argv[0], &ss) != 0) return JS_EXCEPTION;

    // Optional timeout in ms (default 30000)
    int timeout_ms = 30000;
    if (argc > 1 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &timeout_ms, argv[1])) return JS_EXCEPTION;
        if (timeout_ms < 0) timeout_ms = 30000;
    }

#ifndef _WIN32
    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return tjs_throw_errno(ctx, uv_translate_sys_error(errno));

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        int e = errno; close(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }

    // Start connect (returns EINPROGRESS immediately)
    int conn_ret = connect(fd, (struct sockaddr *)&ss, sizeof(ss));
    if (conn_ret == 0) {
        // Connected immediately (rare, e.g. localhost)
        fcntl(fd, F_SETFL, flags); // Restore blocking
        int r = uv_tcp_open(&t->h.tcp, (uv_os_sock_t)fd);
        if (r != 0) { close(fd); return tjs_throw_errno(ctx, r); }
        return JS_UNDEFINED;
    }

    if (errno != EINPROGRESS) {
        int e = errno; close(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }

    // Wait for connect with timeout
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (sel == 0) {
        close(fd);
        return JS_ThrowInternalError(ctx, "Connection timeout");
    }
    if (sel < 0) {
        int e = errno; close(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }

    // Check if connect succeeded
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0) {
        int e = errno; close(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }
    if (so_error != 0) {
        close(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(so_error));
    }

    // Restore blocking mode
    fcntl(fd, F_SETFL, flags);
    int r = uv_tcp_open(&t->h.tcp, (uv_os_sock_t)fd);
    if (r != 0) { close(fd); return tjs_throw_errno(ctx, r); }
#else  // Windows
    SOCKET fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return tjs_throw_errno(ctx, uv_translate_sys_error(WSAGetLastError()));

    // Set non-blocking
    u_long mode = 1;
    if (ioctlsocket(fd, FIONBIO, &mode) != 0) {
        int e = WSAGetLastError(); closesocket(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }

    // Start connect (returns WSAEWOULDBLOCK immediately)
    int conn_ret = connect(fd, (struct sockaddr *)&ss, sizeof(ss));
    if (conn_ret == 0) {
        // Connected immediately
        mode = 0;
        ioctlsocket(fd, FIONBIO, &mode);
        int r = uv_tcp_open(&t->h.tcp, (uv_os_sock_t)fd);
        if (r != 0) { closesocket(fd); return tjs_throw_errno(ctx, r); }
        return JS_UNDEFINED;
    }

    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK) {
        closesocket(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(err));
    }

    // Wait for connect with timeout
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(0, NULL, &wfds, NULL, &tv);
    if (sel == 0) {
        closesocket(fd);
        return JS_ThrowInternalError(ctx, "Connection timeout");
    }
    if (sel == SOCKET_ERROR) {
        int e = WSAGetLastError(); closesocket(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }

    // Check if connect succeeded
    int so_error = 0;
    int len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) != 0) {
        int e = WSAGetLastError(); closesocket(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }
    if (so_error != 0) {
        closesocket(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(so_error));
    }

    // Restore blocking mode
    mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
    int r = uv_tcp_open(&t->h.tcp, (uv_os_sock_t)fd);
    if (r != 0) { closesocket(fd); return tjs_throw_errno(ctx, r); }
#endif
    return JS_UNDEFINED;
}

static JSValue tjs_tcp_bind(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_tcp_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    struct sockaddr_storage ss;
    if (tjs_obj2addr(ctx, argv[0], &ss) != 0) return JS_EXCEPTION;
    int flags = 0;
    if (!JS_IsUndefined(argv[1]) && JS_ToInt32(ctx, &flags, argv[1])) return JS_EXCEPTION;
    int r = uv_tcp_bind(&t->h.tcp, (struct sockaddr *)&ss, flags);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

static JSValue tjs_tcp_keepalive(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_tcp_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    int enable = JS_ToBool(ctx, argv[0]);
    if (enable == -1) return JS_EXCEPTION;
    int delay;
    if (JS_ToInt32(ctx, &delay, argv[1])) return JS_EXCEPTION;
    int r = uv_tcp_keepalive(&t->h.tcp, enable, delay);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

static JSValue tjs_tcp_nodelay(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_tcp_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    int enable = JS_ToBool(ctx, argv[0]);
    if (enable == -1) return JS_EXCEPTION;
    int r = uv_tcp_nodelay(&t->h.tcp, enable);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}


#pragma endregion
#pragma region class tty
static void tjs_tty_finalizer(JSRuntime *rt, JSValue val) {
    tjs_stream_finalizer(rt, JS_GetOpaque(val, tjs_tty_class_id));
}
static void tjs_tty_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    tjs_stream_mark(rt, JS_GetOpaque(val, tjs_tty_class_id), mark_func);
}
static JSClassDef tjs_tty_class = {
    "TTY",
    .finalizer = tjs_tty_finalizer,
    .gc_mark   = tjs_tty_mark,
};

static JSValue tjs_tty_constructor(JSContext *ctx, JSValue new_target, int argc, JSValue *argv) {
    int fd, readable;
    if (JS_ToInt32(ctx, &fd, argv[0])) return JS_EXCEPTION;
    if ((readable = JS_ToBool(ctx, argv[1])) == -1) return JS_EXCEPTION;

    JSValue obj = JS_NewObjectClass(ctx, tjs_tty_class_id);
    if (JS_IsException(obj)) return obj;

    TJSStream *s = tjs__mallocz(sizeof(*s));
    if (!s) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    int r = uv_tty_init(tjs_get_loop(ctx), &s->h.tty, fd, readable);
    if (r != 0) {
        JS_FreeValue(ctx, obj);
        tjs__free(s);
        return tjs_throw_errno(ctx, r);
    }

    s->tty_mode = UV_TTY_MODE_NORMAL;
    return tjs_init_stream(ctx, obj, s);
}

static TJSStream *tjs_tty_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_tty_class_id);
}

static JSValue tjs_tty_set_mode(JSContext *ctx, JSValue this_val, JSValue value) {
    TJSStream *s = tjs_tty_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    int mode;
    if (JS_ToInt32(ctx, &mode, value)) return JS_EXCEPTION;
    int r = uv_tty_set_mode(&s->h.tty, mode);
    if (r != 0) return tjs_throw_errno(ctx, r);
    s->tty_mode = mode;
    return JS_UNDEFINED;
}

static JSValue tjs_tty_get_mode(JSContext *ctx, JSValue this_val) {
    TJSStream *s = tjs_tty_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    return JS_NewInt32(ctx, s->tty_mode);
}

static JSValue tjs_tty_get_win_size(JSContext *ctx, JSValue this_val) {
    TJSStream *s = tjs_tty_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    int w, h;
    int r = uv_tty_get_winsize(&s->h.tty, &w, &h);
    if (r != 0) return tjs_throw_errno(ctx, r);
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    JS_DefinePropertyValueStr(ctx, obj, "width",  JS_NewInt32(ctx, w), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "height", JS_NewInt32(ctx, h), JS_PROP_C_W_E);
    return obj;
}


#pragma endregion
#pragma region class pipe
static void tjs_pipe_finalizer(JSRuntime *rt, JSValue val) {
    tjs_stream_finalizer(rt, JS_GetOpaque(val, tjs_pipe_class_id));
}
static void tjs_pipe_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    tjs_stream_mark(rt, JS_GetOpaque(val, tjs_pipe_class_id), mark_func);
}
static JSClassDef tjs_pipe_class = {
    "Pipe",
    .finalizer = tjs_pipe_finalizer,
    .gc_mark   = tjs_pipe_mark,
};

JSValue tjs_new_pipe(JSContext *ctx) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_pipe_class_id);
    if (JS_IsException(obj)) return obj;

    TJSStream *s = tjs__mallocz(sizeof(*s));
    if (!s) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    int r = uv_pipe_init(tjs_get_loop(ctx), &s->h.pipe, 0);
    if (r != 0) {
        JS_FreeValue(ctx, obj);
        tjs__free(s);
        return tjs_throw_errno(ctx, r);
    }

    return tjs_init_stream(ctx, obj, s);
}

static JSValue tjs_pipe_constructor(JSContext *ctx, JSValue new_target, int argc, JSValue *argv) {
    return tjs_new_pipe(ctx);
}

static TJSStream *tjs_pipe_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_pipe_class_id);
}

uv_stream_t *tjs_pipe_get_stream(JSContext *ctx, JSValue obj) {
    TJSStream *s = JS_GetOpaque(obj, tjs_pipe_class_id);
    return s ? &s->h.stream : NULL;
}

uv_pipe_t *tjs_pipe_get_pipe(JSContext *ctx, JSValue obj) {
    TJSStream *s = JS_GetOpaque(obj, tjs_pipe_class_id);
    return s ? &s->h.pipe : NULL;
}

static JSValue tjs_pipe_getsockpeername(JSContext *ctx, JSValue this_val, int argc, JSValue *argv, int magic) {
    TJSStream *t = tjs_pipe_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    char buf[1024];
    size_t len = sizeof(buf);
    int r = magic == 0
        ? uv_pipe_getsockname(&t->h.pipe, buf, &len)
        : uv_pipe_getpeername(&t->h.pipe, buf, &len);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_NewStringLen(ctx, buf, len);
}

static JSValue tjs_pipe_connect(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_pipe_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    if (!JS_IsUndefined(t->connect_promise.p))
        return JS_ThrowInternalError(ctx, "connect already in progress");
    if (!JS_IsString(argv[0])) return JS_ThrowTypeError(ctx, "pipe name must be a string");

    size_t len;
    const char *name = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!name) return JS_EXCEPTION;

    uv_connect_t *req = js_malloc(ctx, sizeof(*req));
    if (!req) { JS_FreeCString(ctx, name); return JS_EXCEPTION; }

    int r = uv_pipe_connect2(req, &t->h.pipe, name, len, 0, uv__connect_cb);
    JS_FreeCString(ctx, name);
    if (r != 0) {
        js_free(ctx, req);
        return tjs_throw_errno(ctx, r);
    }

    stream_pin(ctx, t, this_val);
    return TJS_InitPromise(ctx, &t->connect_promise);
}

/* connectSync: blocking Unix domain socket connect, hands fd to libuv. */
static JSValue tjs_pipe_connect_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
#ifdef _WIN32
    return JS_ThrowTypeError(ctx, "named-pipe sync connect not supported on Windows");
#else
    TJSStream *t = tjs_pipe_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    if (!stream_check_open(ctx, t)) return JS_EXCEPTION;
    if (!JS_IsString(argv[0])) return JS_ThrowTypeError(ctx, "pipe name must be a string");

    size_t len;
    const char *name = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!name) return JS_EXCEPTION;

    if (len >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        JS_FreeCString(ctx, name);
        return JS_ThrowTypeError(ctx, "pipe name too long");
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name, len + 1);
    JS_FreeCString(ctx, name);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int e = errno; close(fd);
        return tjs_throw_errno(ctx, uv_translate_sys_error(e));
    }
    int r = uv_pipe_open(&t->h.pipe, fd);
    if (r != 0) { close(fd); return tjs_throw_errno(ctx, r); }
    return JS_UNDEFINED;
#endif
}

static JSValue tjs_pipe_bind(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_pipe_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    if (!JS_IsString(argv[0])) return JS_ThrowTypeError(ctx, "pipe name must be a string");
    size_t len;
    const char *name = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!name) return JS_EXCEPTION;
    int r = uv_pipe_bind2(&t->h.pipe, name, len, 0);
    JS_FreeCString(ctx, name);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

static JSValue tjs_pipe_open(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSStream *t = tjs_pipe_get(ctx, this_val);
    if (!t) return JS_EXCEPTION;
    int fd;
    if (JS_ToInt32(ctx, &fd, argv[0])) return JS_EXCEPTION;
    int r = uv_pipe_open(&t->h.pipe, fd);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}


#pragma endregion
#pragma region define class
/* clang-format off */
static const JSCFunctionListEntry tjs_stream_proto_funcs[] = {
    JS_CGETSET_MAGIC_DEF("onread",       tjs_stream_callback_get, tjs_stream_callback_set, STREAM_CB_READ),
    JS_CGETSET_MAGIC_DEF("onconnection", tjs_stream_callback_get, tjs_stream_callback_set, STREAM_CB_CONNECTION),
    JS_CGETSET_MAGIC_DEF("onclose",      tjs_stream_callback_get, tjs_stream_callback_set, STREAM_CB_CLOSE),
    TJS_CFUNC_DEF("listen",      1, tjs_stream_listen),
    TJS_CFUNC_DEF("startRead",   0, tjs_stream_start_read),
    TJS_CFUNC_DEF("stopRead",    0, tjs_stream_stop_read),
    TJS_CFUNC_DEF("read",        1, tjs_stream_read),
    TJS_CFUNC_DEF("readSync",    1, tjs_stream_read_sync),
    TJS_CFUNC_DEF("write",       1, tjs_stream_write),
    TJS_CFUNC_DEF("writeSync",   1, tjs_stream_write_sync),
    TJS_CFUNC_DEF("shutdown",    0, tjs_stream_shutdown),
    TJS_CFUNC_DEF("setBlocking", 1, tjs_stream_set_blocking),
    TJS_CFUNC_DEF("close",       0, tjs_stream_close),
    JS_CGETSET_DEF("fileno",        tjs_stream_get_fileno, NULL),
    TJS_CFUNC_DEF("ref",         0, tjs_stream_ref),
    TJS_CFUNC_DEF("unref",       0, tjs_stream_unref),
};

static const JSCFunctionListEntry tjs_tcp_proto_funcs[] = {
    JS_CGETSET_MAGIC_DEF("sockname", tjs_tcp_get_sockpeername, NULL, 0),
    JS_CGETSET_MAGIC_DEF("peername", tjs_tcp_get_sockpeername, NULL, 1),
    TJS_CFUNC_DEF("connect",      1, tjs_tcp_connect),
    TJS_CFUNC_DEF("connectSync",  1, tjs_tcp_connect_sync),
    TJS_CFUNC_DEF("bind",         2, tjs_tcp_bind),
    TJS_CFUNC_DEF("setKeepAlive", 2, tjs_tcp_keepalive),
    TJS_CFUNC_DEF("setNoDelay",   1, tjs_tcp_nodelay),
};

static const JSCFunctionListEntry tjs_tty_proto_funcs[] = {
    JS_CGETSET_DEF("mode",         tjs_tty_get_mode, tjs_tty_set_mode),
    JS_CGETSET_DEF("size",         tjs_tty_get_win_size, NULL)
};

static const JSCFunctionListEntry tjs_pipe_proto_funcs[] = {
    JS_CFUNC_MAGIC_DEF("getsockname", 0, tjs_pipe_getsockpeername, 0),
    JS_CFUNC_MAGIC_DEF("getpeername", 0, tjs_pipe_getsockpeername, 1),
    TJS_CFUNC_DEF("open",        1, tjs_pipe_open),
    TJS_CFUNC_DEF("connect",     1, tjs_pipe_connect),
    TJS_CFUNC_DEF("connectSync", 1, tjs_pipe_connect_sync),
    TJS_CFUNC_DEF("bind",        1, tjs_pipe_bind),
};

static const JSCFunctionListEntry tjs_streams_funcs[] = {
    TJS_UVCONST(TCP_IPV6ONLY),
    TJS_UVCONST(TTY_MODE_NORMAL),
    TJS_UVCONST(TTY_MODE_RAW),
    TJS_UVCONST(TTY_MODE_RAW_VT),
};
/* clang-format on */


/* Register one class with its own prototype that inherits from stream_proto. */
#define STREAM_CLASS_INIT(id, def, extra, ctor_name, ctor_fn) do { \
    JS_NewClassID(rt, &(id));                                        \
    JS_NewClass(rt, id, &(def));                                     \
    proto = JS_NewObjectProto(ctx, stream_proto);                    \
    JS_SetPropertyFunctionList(ctx, proto, extra, countof(extra));   \
    JS_SetClassProto(ctx, id, proto);                                \
    obj = JS_NewCFunction2(ctx, ctor_fn, ctor_name, 1,              \
                           JS_CFUNC_constructor, 0);                 \
    JS_DefinePropertyValueStr(ctx, ns, ctor_name, obj, JS_PROP_C_W_E); \
} while (0)

void tjs__mod_streams_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSValue proto, obj;

    /* Shared base prototype for all stream types. */
    JSValue stream_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, stream_proto, tjs_stream_proto_funcs,
                               countof(tjs_stream_proto_funcs));

    STREAM_CLASS_INIT(tjs_tcp_class_id,  tjs_tcp_class,  tjs_tcp_proto_funcs,  "TCP",  tjs_tcp_constructor);
    STREAM_CLASS_INIT(tjs_tty_class_id,  tjs_tty_class,  tjs_tty_proto_funcs,  "TTY",  tjs_tty_constructor);
    STREAM_CLASS_INIT(tjs_pipe_class_id, tjs_pipe_class, tjs_pipe_proto_funcs, "Pipe", tjs_pipe_constructor);

    JS_SetPropertyFunctionList(ctx, ns, tjs_streams_funcs, countof(tjs_streams_funcs));
    JS_FreeValue(ctx, stream_proto);
}

#undef STREAM_CLASS_INIT
