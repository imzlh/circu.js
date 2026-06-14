/*
 * txiki.js curl wrapper
 *
 * Copyright (c) 2025 iz
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

#include "private.h"
#include "tjs.h"
#include "utils.h"
#include "mem.h"

#include <curl/curl.h>
#include <curl/options.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

/*
 * Design notes
 * ------------
 * Async transfers run on libuv's event loop through curl_multi + uv_poll +
 * uv_timer (the socket_callback / timer_callback machinery). That is genuine
 * non-blocking IO: no worker thread is parked for the lifetime of a request,
 * which is exactly why we do NOT add a uv_queue_work(curl_easy_perform)
 * fallback -- that would tie up a threadpool slot per in-flight request and
 * scale far worse than the multi interface we already drive.
 *
 * performSync() stays honestly blocking (curl_easy_perform on a private easy
 * handle that never touches the pool) for callers that *want* to block, e.g.
 * CLI scripts and startup paths.
 *
 * Memory: every struct that owns a libuv handle (pool, socket polls) is
 * allocated/freed with tjs__malloc/tjs__free so it can be torn down during
 * runtime shutdown when the JSContext may already be gone. The TJSCURL object
 * is a regular GC object and uses js_malloc/js_free_rt.
 *
 * Bodies are bytes at the core: the buffered response `body` is an ArrayBuffer
 * with a lazily-decoding `text` getter, setBody() accepts ArrayBuffer /
 * TypedArray / string, and onData() streams ArrayBuffer chunks.
 */

#pragma region Type Definitions

typedef struct TJSConnPool {
    CURLM *multi_handle;
    uv_timer_t timer;
    uv_prepare_t prep;     /* one-shot "kick" so sync completions still drain */
    bool prep_active;

    JSContext *ctx;
    JSValue err_cb;

    struct list_head curls; /* live TJSCURL handles (TJSCURL.link) */

    int open_handles;       /* outstanding uv handles (timer, prep, socket polls) */
    bool freeing;           /* finalizer ran; free the struct once open_handles == 0 */
} TJSConnPool;

typedef struct {
    CURL *handle;
    JSValue self_obj;       /* keeps the JS wrapper alive while in-flight */
    JSValue pool_obj;
    TJSConnPool *pool;      /* NULL once detached by the pool teardown */
    struct list_head link;  /* node in pool->curls */
    JSContext *ctx;

    TJSPromise promise;
    bool in_flight;         /* added to multi and not yet settled */

    JSValue on_data;
    bool stream_mode;

    /* Response data (raw bytes) */
    DynBuf response_body;
    DynBuf response_headers;

    /* Request-owned resources freed on reset()/finalize */
    struct curl_slist *request_headers;   /* CURLOPT_HTTPHEADER (setHeaders) */
    struct curl_slist **gen_slists;       /* slists created via setOpt() */
    size_t gen_slists_len;
    curl_mime *mime;                      /* setMimePost() */
    FILE *upload_fp;                      /* setUploadFile() */
    uint8_t *upload_data;                 /* setUploadData() copy */
    size_t upload_size;
    size_t upload_offset;

    JSValue share_obj;                    /* keeps a referenced Share alive */

    /* Callbacks */
    JSValue on_progress;
    JSValue on_header;
    JSValue on_headers_complete;  /* fired once with (status, headersString) when headers end */

    /* Status / scratch */
    long response_code;
    char *effective_url;
    char error_buffer[CURL_ERROR_SIZE];
    bool completed;
    bool in_callback;  /* true while inside a libcurl callback - prevent reentry */
    bool headers_complete_fired;  /* true after onHeadersComplete has been called */
} TJSCURL;

typedef struct {
    uv_poll_t poll;
    curl_socket_t sockfd;
    TJSConnPool *pool;
} TJSSocketPoll;

typedef struct {
    CURLSH *share;
} TJSShare;

#pragma endregion

#pragma region Forward Declarations

static thread_local JSClassID tjs_curl_class_id;
static thread_local JSClassID tjs_connpool_class_id;
static thread_local JSClassID tjs_share_class_id;

static void tjs_curl_finalizer(JSRuntime *rt, JSValue val);
static void tjs_curl_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func);
static JSClassDef tjs_curl_class = {
    "CURL",
    .finalizer = tjs_curl_finalizer,
    .gc_mark = tjs_curl_gc_mark
};

static void tjs_connpool_finalizer(JSRuntime *rt, JSValue val);
static void tjs_connpool_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func);
static JSClassDef tjs_connpool_class = {
    "ConnPool",
    .finalizer = tjs_connpool_finalizer,
    .gc_mark = tjs_connpool_gc_mark
};

static void tjs_share_finalizer(JSRuntime *rt, JSValue val);
static JSClassDef tjs_share_class = {
    "Share",
    .finalizer = tjs_share_finalizer,
};

static void kick_prep_once(TJSConnPool *pool);
static void check_multi_info(TJSConnPool *pool);
static void timer_cb(uv_timer_t *handle);
static void curl_clear_request_resources(JSRuntime *rt, TJSCURL *curl);

static void curl_release_self(JSContext *ctx, TJSCURL *curl) {
    if (!JS_IsUndefined(curl->self_obj)) {
        JSValue self = curl->self_obj;
        curl->self_obj = JS_UNDEFINED;
        JS_FreeValue(ctx, self);
    }
}

static void curl_release_self_rt(JSRuntime *rt, TJSCURL *curl) {
    if (!JS_IsUndefined(curl->self_obj)) {
        JSValue self = curl->self_obj;
        curl->self_obj = JS_UNDEFINED;
        JS_FreeValueRT(rt, self);
    }
}

static int connpool_require_open(JSContext *ctx, TJSConnPool *pool) {
    if (!pool->multi_handle) {
        JS_ThrowTypeError(ctx, "ConnPool is closed");
        return -1;
    }
    return 0;
}

static void call_err_cb(TJSConnPool *pool, CURLMcode err) {
    if (!pool->ctx) return;
    JSValue cb = pool->err_cb;
    if (JS_IsUndefined(cb)) return;
    JS_ThrowPlainError(pool->ctx, "CURL failed: %s", curl_multi_strerror(err));
    JSValue error = JS_GetException(pool->ctx);
    JS_FreeValue(pool->ctx, JS_Call(pool->ctx, cb, JS_UNDEFINED, 1, (JSValueConst[]) { error }));
    JS_FreeValue(pool->ctx, error);
}

#define MSACT(pool, ...) do { \
    __maybe_unused CURLMcode _ret = curl_multi_socket_action(__VA_ARGS__); \
    if (_ret != CURLM_OK) call_err_cb(pool, _ret); \
} while (0)

/* free an ArrayBuffer backing store that was js_malloc'd */
static void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr) {
    js_free_rt(rt, ptr);
}

#pragma endregion

#pragma region LibCURL Callbacks

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    TJSCURL *curl = (TJSCURL *) userdata;
    size_t realsize = size * nmemb;

    if (curl->stream_mode && !JS_IsUndefined(curl->on_data)) {
        JSValue args[1];
        args[0] = JS_NewArrayBufferCopy(curl->ctx, (const uint8_t *) ptr, realsize);

        // Mark that we're inside a callback to prevent reentry destruction
        curl->in_callback = true;
        JSValue ret = JS_Call(curl->ctx, curl->on_data, JS_UNDEFINED, 1, args);
        curl->in_callback = false;
        JS_FreeValue(curl->ctx, args[0]);

        if (JS_IsException(ret)) {
            JS_FreeValue(curl->ctx, ret);
            return 0; /* abort transfer; perform() will reject */
        }

        bool should_abort = JS_ToBool(curl->ctx, ret);
        JS_FreeValue(curl->ctx, ret);
        return should_abort ? 0 : realsize;
    }

    if (dbuf_put(&curl->response_body, (const uint8_t *) ptr, realsize) < 0) {
        return 0;
    }
    return realsize;
}

static size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    TJSCURL *curl = (TJSCURL *) userdata;
    size_t realsize = size * nmemb;

    if (dbuf_put(&curl->response_headers, (const uint8_t *) ptr, realsize) < 0) {
        return 0;
    }

    if (!JS_IsUndefined(curl->on_header)) {
        JSValue args[1];
        args[0] = JS_NewStringLen(curl->ctx, ptr, realsize);
        curl->in_callback = true;
        JSValue ret = JS_Call(curl->ctx, curl->on_header, JS_UNDEFINED, 1, args);
        curl->in_callback = false;
        JS_FreeValue(curl->ctx, args[0]);
        if (JS_IsException(ret)) {
            JS_FreeValue(curl->ctx, ret);
            return 0;
        }
        int32_t processed = 0;
        if (JS_IsNumber(ret) && JS_ToInt32(curl->ctx, &processed, ret) == 0 && processed <= 0) {
            JS_FreeValue(curl->ctx, ret);
            return 0;
        }
        JS_FreeValue(curl->ctx, ret);
    }

    /* Blank line signals end of headers (also handles HTTP/2 where status line
     * may repeat on redirects — fire only when we have a final 2xx/3xx/4xx/5xx). */
    if (!JS_IsUndefined(curl->on_headers_complete) &&
            (realsize == 2 && ptr[0] == '\r' && ptr[1] == '\n')) {
        long status = 0;
        curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE, &status);
        /* Skip informational 1xx responses — headers aren't final yet.
         * Also skip if already fired (e.g., on redirect chain). */
        if (status >= 200 && !curl->headers_complete_fired) {
            curl->headers_complete_fired = true;
            JSValue args[2] = {
                JS_NewInt32(curl->ctx, (int32_t) status),
                curl->response_headers.size > 0
                    ? JS_NewStringLen(curl->ctx, (char *) curl->response_headers.buf,
                                      curl->response_headers.size)
                    : JS_NewString(curl->ctx, ""),
            };
            JSValue ret = JS_Call(curl->ctx, curl->on_headers_complete, JS_UNDEFINED, 2, args);
            JS_FreeValue(curl->ctx, args[0]);
            JS_FreeValue(curl->ctx, args[1]);
            JS_FreeValue(curl->ctx, ret);
        }
    }
    return realsize;
}

static int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                             curl_off_t ultotal, curl_off_t ulnow) {
    TJSCURL *curl = (TJSCURL *) clientp;

    if (!JS_IsUndefined(curl->on_progress)) {
        JSValue args[4] = {
            JS_NewInt64(curl->ctx, dltotal),
            JS_NewInt64(curl->ctx, dlnow),
            JS_NewInt64(curl->ctx, ultotal),
            JS_NewInt64(curl->ctx, ulnow),
        };
        curl->in_callback = true;
        JSValue ret = JS_Call(curl->ctx, curl->on_progress, JS_UNDEFINED, 4, args);
        curl->in_callback = false;
        for (int i = 0; i < 4; i++) JS_FreeValue(curl->ctx, args[i]);

        if (JS_IsException(ret)) {
            JS_FreeValue(curl->ctx, ret);
            return 1; /* abort */
        }
        /* returning false from JS aborts the transfer */
        bool keep_going = JS_ToBool(curl->ctx, ret);
        JS_FreeValue(curl->ctx, ret);
        return keep_going ? 0 : 1;
    }
    return 0;
}

/* default CURLOPT_READFUNCTION replacement for in-memory uploads */
static size_t read_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    TJSCURL *curl = (TJSCURL *) userdata;
    size_t want = size * nitems;
    size_t left = curl->upload_size - curl->upload_offset;
    size_t n = want < left ? want : left;
    if (n) {
        memcpy(buffer, curl->upload_data + curl->upload_offset, n);
        curl->upload_offset += n;
    }
    return n;
}

#pragma endregion

#pragma region Pool teardown helpers

static void pool_maybe_free(TJSConnPool *pool) {
    if (pool->freeing && pool->open_handles == 0) {
        tjs__free(pool);
    }
}

static void uv_handle_closed_cb(uv_handle_t *handle) {
    TJSConnPool *pool = handle->data;
    pool->open_handles--;
    pool_maybe_free(pool);
}

/* Detach every live easy handle from the multi handle and tear it down.
 * Never calls into JS, so it is safe from the GC finalizer. Pending promises
 * are freed (not rejected) here; explicit abort()/close() reject beforehand. */
static void connpool_teardown_multi(JSRuntime *rt, TJSConnPool *pool) {
    if (!pool->multi_handle) return;

    struct list_head *el, *el1;
    list_for_each_safe(el, el1, &pool->curls) {
        TJSCURL *c = list_entry(el, TJSCURL, link);
        if (c->in_flight) {
            curl_multi_remove_handle(pool->multi_handle, c->handle);
            c->in_flight = false;
        }
        if (TJS_IsPromisePending(pool->ctx, &c->promise)) {
            TJS_FreePromiseRT(rt, &c->promise);
            TJS_ClearPromise(NULL, &c->promise);
        }
        curl_release_self_rt(rt, c);
        c->pool = NULL; /* detach: c's finalizer must not touch the multi handle */
        list_del(&c->link);
        init_list_head(&c->link);
    }

    /* cleanup fires the socket callback with CURL_POLL_REMOVE for every active
     * socket, which uv_close()es the matching poll handle. */
    curl_multi_cleanup(pool->multi_handle);
    pool->multi_handle = NULL;
}

#pragma endregion

#pragma region Socket Poll Management

static void poll_close_cb(uv_handle_t *handle) {
    TJSSocketPoll *socket_poll = (TJSSocketPoll *) handle->data;
    TJSConnPool *pool = socket_poll->pool;
    tjs__free(socket_poll);
    pool->open_handles--;
    pool_maybe_free(pool);
}

static void poll_cb(uv_poll_t *handle, int status, int events) {
    TJSSocketPoll *socket_poll = (TJSSocketPoll *) handle->data;
    TJSConnPool *pool = socket_poll->pool;

    int ev_bitmask = 0;
    if (status < 0) {
        ev_bitmask = CURL_CSELECT_ERR;
    } else {
        if (events & UV_READABLE) ev_bitmask |= CURL_CSELECT_IN;
        if (events & UV_WRITABLE) ev_bitmask |= CURL_CSELECT_OUT;
    }

    int running_handles;
    MSACT(pool, pool->multi_handle, socket_poll->sockfd, ev_bitmask, &running_handles);
    check_multi_info(pool);
}

static int socket_callback(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp) {
    TJSConnPool *pool = (TJSConnPool *) userp;
    TJSSocketPoll *socket_poll = (TJSSocketPoll *) socketp;

    if (what == CURL_POLL_REMOVE) {
        if (socket_poll) {
            uv_poll_stop(&socket_poll->poll);
            uv_close((uv_handle_t *) &socket_poll->poll, poll_close_cb);
            curl_multi_assign(pool->multi_handle, s, NULL);
        }
    } else {
        int events = 0;
        if (what & CURL_POLL_IN) events |= UV_READABLE;
        if (what & CURL_POLL_OUT) events |= UV_WRITABLE;

        if (!socket_poll) {
            socket_poll = tjs__malloc(sizeof(TJSSocketPoll));
            if (!socket_poll) return -1;

            socket_poll->sockfd = s;
            socket_poll->pool = pool;
            socket_poll->poll.data = socket_poll;

            uv_poll_init_socket(tjs_get_loop(pool->ctx), &socket_poll->poll, s);
            pool->open_handles++;
            curl_multi_assign(pool->multi_handle, s, socket_poll);
        }

        uv_poll_start(&socket_poll->poll, events, poll_cb);
    }

    return 0;
}

#pragma endregion

#pragma region Prep / Timer Management

static void once_prepare_cb(uv_prepare_t *handle) {
    TJSConnPool *pool = (TJSConnPool *) handle->data;
    int running;

    pool->prep_active = false;
    uv_prepare_stop(handle);

    if (!pool->ctx || !pool->multi_handle) return;

    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info(pool);
}

static void kick_prep_once(TJSConnPool *pool) {
    if (pool->prep_active) return;
    pool->prep_active = true;
    uv_prepare_start(&pool->prep, once_prepare_cb);
}

static int timer_callback(CURLM *multi, long timeout_ms, void *userp) {
    TJSConnPool *pool = (TJSConnPool *) userp;

    if (timeout_ms < 0) {
        uv_timer_stop(&pool->timer);
    } else {
        if (timeout_ms == 0) timeout_ms = 1; /* avoid a 0ms busy spin */
        uv_timer_start(&pool->timer, timer_cb, timeout_ms, 0);
    }
    return 0;
}

static void timer_cb(uv_timer_t *handle) {
    TJSConnPool *pool = (TJSConnPool *) handle->data;
    if (!pool->multi_handle) return;

    int running;
    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info(pool);
}

#pragma endregion

#pragma region Response building

/* Hand the accumulated body bytes to an ArrayBuffer, transferring ownership of
 * the DynBuf storage (which is js_malloc'd via tjs_dbuf_init). */
static JSValue body_to_arraybuffer(JSContext *ctx, DynBuf *b) {
    if (b->size == 0) {
        return JS_NewArrayBufferCopy(ctx, NULL, 0);
    }
    JSValue ab = JS_NewArrayBuffer(ctx, b->buf, b->size, free_js_malloc, NULL, false);
    if (JS_IsException(ab)) return ab;
    /* ownership transferred; detach so dbuf_free()/reuse won't double free */
    b->buf = NULL;
    b->size = 0;
    b->allocated_size = 0;
    return ab;
}

static JSValue get_response_text(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue body = JS_GetPropertyStr(ctx, this_val, "body");
    size_t len = 0;
    uint8_t *p = JS_IsUndefined(body) ? NULL : JS_GetArrayBuffer(ctx, &len, body);
    JSValue s = p ? JS_NewStringLen(ctx, (const char *) p, len) : JS_NewString(ctx, "");
    JS_FreeValue(ctx, body);
    return s;
}

static JSValue build_response(JSContext *ctx, TJSCURL *curl) {
    JSValue response = JS_NewObject(ctx);

    if (!curl->stream_mode) {
        JS_DefinePropertyValueStr(ctx, response, "body",
            body_to_arraybuffer(ctx, &curl->response_body), JS_PROP_C_W_E);
    }

    JS_DefinePropertyValueStr(ctx, response, "headers",
        curl->response_headers.size > 0
            ? JS_NewStringLen(ctx, (char *) curl->response_headers.buf, curl->response_headers.size)
            : JS_NewString(ctx, ""),
        JS_PROP_C_W_E);

    JS_DefinePropertyValueStr(ctx, response, "status",
        JS_NewInt32(ctx, curl->response_code), JS_PROP_C_W_E);

    if (curl->effective_url) {
        JS_DefinePropertyValueStr(ctx, response, "url",
            JS_NewString(ctx, curl->effective_url), JS_PROP_C_W_E);
    }

    JS_DefinePropertyValueStr(ctx, response, "streamed",
        JS_NewBool(ctx, curl->stream_mode), JS_PROP_C_W_E);

    /* lazy UTF-8 decode of body */
    JSAtom text_atom = JS_NewAtom(ctx, "text");
    JSValue getter = JS_NewCFunction(ctx, get_response_text, "text", 0);
    JS_DefinePropertyGetSet(ctx, response, text_atom, getter, JS_UNDEFINED,
                            JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);
    JS_FreeAtom(ctx, text_atom);

    return response;
}

static JSValue tjs__curl_new_os_string(JSContext *ctx, const char *s) {
    if (!s)
        return JS_NewString(ctx, "");
#ifdef _WIN32
    int wlen = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (wlen <= 0)
        return JS_NewString(ctx, s);
    WCHAR *w = js_malloc(ctx, (size_t) wlen * sizeof(WCHAR));
    if (!w)
        return JS_NewString(ctx, s);
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, wlen);
    int ulen = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (ulen <= 0) {
        js_free(ctx, w);
        return JS_NewString(ctx, s);
    }
    char *u = js_malloc(ctx, (size_t) ulen);
    if (!u) {
        js_free(ctx, w);
        return JS_NewString(ctx, s);
    }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, u, ulen, NULL, NULL);
    js_free(ctx, w);
    JSValue v = JS_NewString(ctx, u);
    js_free(ctx, u);
    return v;
#else
    return JS_NewString(ctx, s);
#endif
}

static JSValue build_error(JSContext *ctx, const char *error_buffer, CURLcode code) {
    JSValue error = JS_NewError(ctx);
    const char *msg = (error_buffer && error_buffer[0]) ? error_buffer : curl_easy_strerror(code);
    JS_DefinePropertyValueStr(ctx, error, "message",
        tjs__curl_new_os_string(ctx, msg), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, error, "code",
        JS_NewInt32(ctx, code), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    return error;
}

#pragma endregion

#pragma region Request Completion Handling

static void check_multi_info(TJSConnPool *pool) {
    CURLMsg *msg;
    int msgs_left;

    while ((msg = curl_multi_info_read(pool->multi_handle, &msgs_left))) {
        if (msg->msg != CURLMSG_DONE) continue;

        CURL *easy = msg->easy_handle;
        TJSCURL *curl = NULL;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &curl);
        if (!curl || curl->completed) continue;

        curl->completed = true;
        curl->in_flight = false;

        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &curl->response_code);

        char *url = NULL;
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
        if (url) {
            if (curl->effective_url) js_free(curl->ctx, curl->effective_url);
            curl->effective_url = js_strdup(curl->ctx, url);
        }

        curl_multi_remove_handle(pool->multi_handle, easy);

        JSValue arg;
        bool is_reject = (msg->data.result != CURLE_OK);
        if (is_reject) {
            arg = build_error(curl->ctx, curl->error_buffer, msg->data.result);
        } else {
            arg = build_response(curl->ctx, curl);
        }

        if (TJS_IsPromisePending(curl->ctx, &curl->promise)) {
            TJS_SettlePromise(curl->ctx, &curl->promise, is_reject, 1, &arg);
        } else {
            JS_FreeValue(curl->ctx, arg);
        }
        curl_release_self(curl->ctx, curl);
    }
}

#pragma endregion

#pragma region Finalizers

static void curl_clear_request_resources(JSRuntime *rt, TJSCURL *curl) {
    if (curl->request_headers) {
        curl_slist_free_all(curl->request_headers);
        curl->request_headers = NULL;
    }
    if (curl->gen_slists) {
        for (size_t i = 0; i < curl->gen_slists_len; i++) {
            curl_slist_free_all(curl->gen_slists[i]);
        }
        js_free_rt(rt, curl->gen_slists);
        curl->gen_slists = NULL;
        curl->gen_slists_len = 0;
    }
    if (curl->mime) {
        curl_mime_free(curl->mime);
        curl->mime = NULL;
    }
    if (curl->upload_fp) {
        fclose(curl->upload_fp);
        curl->upload_fp = NULL;
    }
    if (curl->upload_data) {
        js_free_rt(rt, curl->upload_data);
        curl->upload_data = NULL;
        curl->upload_size = curl->upload_offset = 0;
    }
}

static void curl_clear_body_resources(JSRuntime *rt, TJSCURL *curl) {
    if (curl->mime) {
        curl_easy_setopt(curl->handle, CURLOPT_MIMEPOST, NULL);
        curl_mime_free(curl->mime);
        curl->mime = NULL;
    }
    if (curl->upload_fp) {
        fclose(curl->upload_fp);
        curl->upload_fp = NULL;
    }
    if (curl->upload_data) {
        js_free_rt(rt, curl->upload_data);
        curl->upload_data = NULL;
        curl->upload_size = curl->upload_offset = 0;
    }

    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(curl->handle, CURLOPT_READFUNCTION, NULL);
    curl_easy_setopt(curl->handle, CURLOPT_READDATA, NULL);
    curl_easy_setopt(curl->handle, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(curl->handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) 0);
}

static void tjs_curl_finalizer(JSRuntime *rt, JSValue val) {
    TJSCURL *curl = JS_GetOpaque(val, tjs_curl_class_id);
    if (!curl) return;

    /* unlink from the pool's live list if still attached */
    if (curl->pool && !list_empty(&curl->link)) {
        if (curl->pool->multi_handle && curl->in_flight) {
            curl_multi_remove_handle(curl->pool->multi_handle, curl->handle);
        }
        list_del(&curl->link);
    }

    if (curl->handle) {
        curl_easy_cleanup(curl->handle);
    }

    curl_clear_request_resources(rt, curl);

    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);

    TJS_FreePromiseRT(rt, &curl->promise);
    curl_release_self_rt(rt, curl);
    JS_FreeValueRT(rt, curl->on_headers_complete);
    JS_FreeValueRT(rt, curl->on_progress);
    JS_FreeValueRT(rt, curl->on_header);
    JS_FreeValueRT(rt, curl->on_data);
    JS_FreeValueRT(rt, curl->pool_obj);
    JS_FreeValueRT(rt, curl->share_obj);

    if (curl->effective_url) js_free_rt(rt, curl->effective_url);

    js_free_rt(rt, curl);
}

static void tjs_connpool_finalizer(JSRuntime *rt, JSValue val) {
    TJSConnPool *pool = JS_GetOpaque(val, tjs_connpool_class_id);
    if (!pool) return;

    connpool_teardown_multi(rt, pool);

    JS_FreeValueRT(rt, pool->err_cb);
    pool->err_cb = JS_UNDEFINED;
    pool->ctx = NULL;
    pool->freeing = true;

    if (!uv_is_closing((uv_handle_t *) &pool->timer))
        uv_close((uv_handle_t *) &pool->timer, uv_handle_closed_cb);
    if (!uv_is_closing((uv_handle_t *) &pool->prep))
        uv_close((uv_handle_t *) &pool->prep, uv_handle_closed_cb);

    pool_maybe_free(pool);
}

static void tjs_share_finalizer(JSRuntime *rt, JSValue val) {
    TJSShare *sh = JS_GetOpaque(val, tjs_share_class_id);
    if (!sh) return;
    if (sh->share) curl_share_cleanup(sh->share);
    js_free_rt(rt, sh);
}

#pragma endregion

#pragma region GC Mark Functions

static void tjs_curl_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    TJSCURL *curl = JS_GetOpaque(val, tjs_curl_class_id);
    if (!curl) return;
    TJS_MarkPromise(rt, &curl->promise, mark_func);
    JS_MarkValue(rt, curl->on_progress, mark_func);
    JS_MarkValue(rt, curl->on_header, mark_func);
    JS_MarkValue(rt, curl->on_headers_complete, mark_func);
    JS_MarkValue(rt, curl->on_data, mark_func);
    JS_MarkValue(rt, curl->pool_obj, mark_func);
    JS_MarkValue(rt, curl->share_obj, mark_func);
}

static void tjs_connpool_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    TJSConnPool *pool = JS_GetOpaque(val, tjs_connpool_class_id);
    if (pool) JS_MarkValue(rt, pool->err_cb, mark_func);
}

#pragma endregion

#pragma region ConnPool Constructor / Methods

static JSValue tjs_connpool_constructor(JSContext *ctx, JSValueConst new_target,
                                        int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_connpool_class_id);
    if (JS_IsException(obj)) return obj;

    TJSConnPool *pool = tjs__mallocz(sizeof(TJSConnPool));
    if (!pool) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    pool->ctx = ctx;
    pool->err_cb = JS_UNDEFINED;
    init_list_head(&pool->curls);

    pool->multi_handle = curl_multi_init();
    if (!pool->multi_handle) {
        tjs__free(pool);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    curl_multi_setopt(pool->multi_handle, CURLMOPT_SOCKETFUNCTION, socket_callback);
    curl_multi_setopt(pool->multi_handle, CURLMOPT_SOCKETDATA, pool);
    curl_multi_setopt(pool->multi_handle, CURLMOPT_TIMERFUNCTION, timer_callback);
    curl_multi_setopt(pool->multi_handle, CURLMOPT_TIMERDATA, pool);

    uv_timer_init(tjs_get_loop(ctx), &pool->timer);
    pool->timer.data = pool;
    pool->open_handles++;

    uv_prepare_init(tjs_get_loop(ctx), &pool->prep);
    pool->prep.data = pool;
    pool->prep_active = false;
    pool->open_handles++;

    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue v;

        v = JS_GetPropertyStr(ctx, argv[0], "maxConnections");
        if (JS_IsNumber(v)) {
            int32_t n; JS_ToInt32(ctx, &n, v);
            curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long) n);
        }
        JS_FreeValue(ctx, v);

        v = JS_GetPropertyStr(ctx, argv[0], "maxConnectionsPerHost");
        if (JS_IsNumber(v)) {
            int32_t n; JS_ToInt32(ctx, &n, v);
            curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, (long) n);
        }
        JS_FreeValue(ctx, v);

        v = JS_GetPropertyStr(ctx, argv[0], "pipelining");
        if (JS_ToBool(ctx, v))
            curl_multi_setopt(pool->multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
        JS_FreeValue(ctx, v);
    }

    JS_SetOpaque(obj, pool);
    return obj;
}

static JSValue tjs_connpool_get_active_count(JSContext *ctx, JSValueConst this_val,
                                             int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    if (!pool->multi_handle) return JS_NewInt32(ctx, 0);

    /* read the running-transfer count without driving IO as a side effect */
    int running = 0;
    curl_multi_socket_action(pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    return JS_NewInt32(ctx, running);
}

static JSValue tjs_connpool_close(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;

    /* reject any in-flight promises before we drop the transfers */
    struct list_head *el;
    list_for_each(el, &pool->curls) {
        TJSCURL *c = list_entry(el, TJSCURL, link);
        if (c->in_flight && TJS_IsPromisePending(ctx, &c->promise)) {
            JSValue err = build_error(ctx, NULL, CURLE_ABORTED_BY_CALLBACK);
            TJS_SettlePromise(ctx, &c->promise, true, 1, &err);
        }
    }

    connpool_teardown_multi(JS_GetRuntime(ctx), pool);
    uv_timer_stop(&pool->timer);
    if (pool->prep_active) {
        uv_prepare_stop(&pool->prep);
        pool->prep_active = false;
    }
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_process(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    if (connpool_require_open(ctx, pool) < 0) return JS_EXCEPTION;

    int running;
    CURLMcode ret = curl_multi_socket_action(pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info(pool);
    if (ret != CURLM_OK) {
        return JS_ThrowPlainError(ctx, "perform failed: %s", curl_multi_strerror(ret));
    }
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_set_max_pipeline_length(JSContext *ctx, JSValueConst this_val,
                                                    int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    if (connpool_require_open(ctx, pool) < 0) return JS_EXCEPTION;
    int32_t length;
    if (JS_ToInt32(ctx, &length, argv[0]) < 0) return JS_EXCEPTION;
    curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_PIPELINE_LENGTH, (long) length);
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_set_max_concurrent_streams(JSContext *ctx, JSValueConst this_val,
                                                       int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    if (connpool_require_open(ctx, pool) < 0) return JS_EXCEPTION;
    int32_t streams;
    if (JS_ToInt32(ctx, &streams, argv[0]) < 0) return JS_EXCEPTION;
#ifdef CURLMOPT_MAX_CONCURRENT_STREAMS
    curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_CONCURRENT_STREAMS, (long) streams);
#endif
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_get_onerror(JSContext *ctx, JSValueConst this_val) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    return JS_DupValue(ctx, pool->err_cb);
}

static JSValue tjs_connpool_set_onerror(JSContext *ctx, JSValueConst this_val, JSValueConst value) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    JS_FreeValue(ctx, pool->err_cb);
    pool->err_cb = JS_DupValue(ctx, value);
    return JS_UNDEFINED;
}

#pragma endregion

#pragma region CURL Constructor

static void curl_apply_default_opts(TJSCURL *curl) {
    curl_easy_setopt(curl->handle, CURLOPT_PRIVATE, curl);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl->handle, CURLOPT_HEADERDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl->handle, CURLOPT_XFERINFODATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl->handle, CURLOPT_ERRORBUFFER, curl->error_buffer);
    curl_easy_setopt(curl->handle, CURLOPT_FOLLOWLOCATION, 1L);
}

static JSValue tjs_curl_constructor(JSContext *ctx, JSValueConst new_target,
                                    int argc, JSValueConst *argv) {
    if (argc == 0 || !JS_GetOpaque(argv[0], tjs_connpool_class_id)) {
        return JS_ThrowTypeError(ctx, "Expect first argument to be a ConnPool");
    }
    TJSConnPool *pool = JS_GetOpaque(argv[0], tjs_connpool_class_id);
    if (!pool->multi_handle) {
        return JS_ThrowTypeError(ctx, "ConnPool is closed");
    }

    JSValue obj = JS_NewObjectClass(ctx, tjs_curl_class_id);
    if (JS_IsException(obj)) return obj;

    TJSCURL *curl = js_mallocz(ctx, sizeof(TJSCURL));
    if (!curl) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    curl->ctx = ctx;
    curl->handle = curl_easy_init();
    if (!curl->handle) {
        js_free(ctx, curl);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    /* JS-runtime allocator so the body buffer can be handed to an ArrayBuffer
     * freed via js_free_rt (see body_to_arraybuffer / free_js_malloc). */
    tjs_dbuf_init(ctx, &curl->response_body);
    tjs_dbuf_init(ctx, &curl->response_headers);

    curl_apply_default_opts(curl);

    curl->on_progress = JS_UNDEFINED;
    curl->on_header = JS_UNDEFINED;
    curl->on_headers_complete = JS_UNDEFINED;
    curl->on_data = JS_UNDEFINED;
    curl->self_obj = JS_UNDEFINED;
    curl->share_obj = JS_UNDEFINED;
    TJS_ClearPromise(ctx, &curl->promise);

    curl->pool_obj = JS_DupValue(ctx, argv[0]);
    curl->pool = pool;
    init_list_head(&curl->link);
    list_add_tail(&curl->link, &pool->curls);

    JS_SetOpaque(obj, curl);
    return obj;
}

#pragma endregion

#pragma region CURL Configuration Methods

#define CURL_THIS(ctx, this_val) \
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id); \
    if (!curl) return JS_EXCEPTION

static JSValue tjs_curl_set_url(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *url = JS_ToCString(ctx, argv[0]);
    if (!url) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_URL, url);
    JS_FreeCString(ctx, url);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_method(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *method = JS_ToCString(ctx, argv[0]);
    if (!method) return JS_EXCEPTION;

    curl_easy_setopt(curl->handle, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(curl->handle, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl->handle, CURLOPT_POST, 0L);

    if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTPGET, 1L);
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_POST, 1L);
    } else if (strcmp(method, "HEAD") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_NOBODY, 1L);
    } else {
        /* PUT/DELETE/PATCH/... via CUSTOMREQUEST so an in-memory body set with
         * setBody() (CURLOPT_POSTFIELDS) is still sent. Streaming uploads use
         * setUploadData()/setUploadFile() which enable CURLOPT_UPLOAD. */
        curl_easy_setopt(curl->handle, CURLOPT_CUSTOMREQUEST, method);
    }
    JS_FreeCString(ctx, method);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_headers(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);

    if (curl->request_headers) {
        curl_slist_free_all(curl->request_headers);
        curl->request_headers = NULL;
    }

    if (JS_IsObject(argv[0])) {
        JSPropertyEnum *props;
        uint32_t prop_count;
        if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, argv[0],
                                   JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
            for (uint32_t i = 0; i < prop_count; i++) {
                JSValue key = JS_AtomToString(ctx, props[i].atom);
                JSValue val = JS_GetProperty(ctx, argv[0], props[i].atom);
                const char *key_str = JS_ToCString(ctx, key);
                const char *val_str = JS_ToCString(ctx, val);
                if (key_str && val_str) {
                    size_t hlen = strlen(key_str) + strlen(val_str) + 3;
                    char *header = js_malloc(ctx, hlen);
                    if (header) {
                        snprintf(header, hlen, "%s: %s", key_str, val_str);
                        /* Use temp var to preserve old list if append fails */
                        struct curl_slist *new_headers = curl_slist_append(curl->request_headers, header);
                        if (new_headers) {
                            curl->request_headers = new_headers;
                        } else {
                            /* OOM: keep existing headers, free temp, report error */
                            js_free(ctx, header);
                            return JS_ThrowOutOfMemory(ctx);
                        }
                        js_free(ctx, header);
                    }
                }
                JS_FreeCString(ctx, key_str);
                JS_FreeCString(ctx, val_str);
                JS_FreeValue(ctx, key);
                JS_FreeValue(ctx, val);
            }
            js_free(ctx, props);
            curl_easy_setopt(curl->handle, CURLOPT_HTTPHEADER, curl->request_headers);
        }
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_body(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);

    size_t len = 0;
    const uint8_t *data = NULL;
    const char *cstr = NULL;

    if (JS_IsString(argv[0])) {
        cstr = JS_ToCStringLen(ctx, &len, argv[0]);
        if (!cstr) return JS_EXCEPTION;
        data = (const uint8_t *) cstr;
    } else {
        data = JS_GetAnyBuffer(ctx, &len, argv[0]);
        if (!data) {
            return JS_ThrowTypeError(ctx, "body must be a string, ArrayBuffer or TypedArray");
        }
    }

    curl_clear_body_resources(JS_GetRuntime(ctx), curl);

    /* COPYPOSTFIELDS makes libcurl strdup the buffer; size must be set first so
     * binary payloads with embedded NULs are sent verbatim. */
    curl_easy_setopt(curl->handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) len);
    curl_easy_setopt(curl->handle, CURLOPT_COPYPOSTFIELDS, data);

    if (cstr) JS_FreeCString(ctx, cstr);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_timeout(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    int32_t timeout;
    if (JS_ToInt32(ctx, &timeout, argv[0]) < 0) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_TIMEOUT_MS, (long) timeout);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_follow_redirects(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    curl_easy_setopt(curl->handle, CURLOPT_FOLLOWLOCATION, JS_ToBool(ctx, argv[0]) ? 1L : 0L);
    return JS_DupValue(ctx, this_val);
}

#pragma endregion

#pragma region CURL Callback Setters

static JSValue tjs_curl_on_progress(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    JS_FreeValue(ctx, curl->on_progress);
    curl->on_progress = JS_IsFunction(ctx, argv[0]) ? JS_DupValue(ctx, argv[0]) : JS_UNDEFINED;
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_on_header(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    JS_FreeValue(ctx, curl->on_header);
    curl->on_header = JS_IsFunction(ctx, argv[0]) ? JS_DupValue(ctx, argv[0]) : JS_UNDEFINED;
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_stream_mode(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    curl->stream_mode = JS_ToBool(ctx, argv[0]);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_on_data(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    JS_FreeValue(ctx, curl->on_data);
    if (JS_IsFunction(ctx, argv[0])) {
        curl->on_data = JS_DupValue(ctx, argv[0]);
        curl->stream_mode = true;
    } else {
        curl->on_data = JS_UNDEFINED;
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_on_headers_complete(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    JS_FreeValue(ctx, curl->on_headers_complete);
    curl->on_headers_complete = JS_IsFunction(ctx, argv[0]) ? JS_DupValue(ctx, argv[0]) : JS_UNDEFINED;
    return JS_DupValue(ctx, this_val);
}

#pragma endregion

#pragma region Generic setOpt / getInfo

/* Resolve a JS value to a long for CURLOT_LONG / CURLOT_VALUES options. */
static int js_to_curl_long(JSContext *ctx, JSValueConst v, long *out) {
    if (JS_IsBool(v)) { *out = JS_ToBool(ctx, v) ? 1 : 0; return 0; }
    int64_t n;
    if (JS_ToInt64(ctx, &n, v) < 0) return -1;
    *out = (long) n;
    return 0;
}

static bool curl_option_is_reserved(CURLoption id) {
    switch (id) {
        case CURLOPT_PRIVATE:
        case CURLOPT_ERRORBUFFER:
        case CURLOPT_WRITEFUNCTION:
        case CURLOPT_WRITEDATA:
        case CURLOPT_HEADERFUNCTION:
        case CURLOPT_HEADERDATA:
        case CURLOPT_XFERINFOFUNCTION:
        case CURLOPT_XFERINFODATA:
        case CURLOPT_READFUNCTION:
        case CURLOPT_READDATA:
            return true;
        default:
            return false;
    }
}

static int curl_set_slist_opt(JSContext *ctx, TJSCURL *curl, CURLoption id, JSValueConst arr) {
    struct curl_slist *slist = NULL;
    uint32_t len = 0;
    JSValue lenv = JS_GetPropertyStr(ctx, arr, "length");
    JS_ToUint32(ctx, &len, lenv);
    JS_FreeValue(ctx, lenv);

    for (uint32_t i = 0; i < len; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, arr, i);
        const char *s = JS_ToCString(ctx, item);
        if (s) {
            struct curl_slist *new_slist = curl_slist_append(slist, s);
            if (new_slist) {
                slist = new_slist;
            } else {
                /* OOM on append: free what we have and fail */
                curl_slist_free_all(slist);
                JS_FreeCString(ctx, s);
                JS_FreeValue(ctx, item);
                return -1;
            }
            JS_FreeCString(ctx, s);
        }
        JS_FreeValue(ctx, item);
    }

    /* track for cleanup */
    struct curl_slist **grown = js_realloc(ctx, curl->gen_slists,
                                           (curl->gen_slists_len + 1) * sizeof(*grown));
    if (!grown) {
        curl_slist_free_all(slist);
        return -1;
    }
    curl->gen_slists = grown;
    curl->gen_slists[curl->gen_slists_len++] = slist;

    curl_easy_setopt(curl->handle, id, slist);
    return 0;
}

/* setOpt(optId, value) typed by the option id via curl_easy_option_by_id. */
static JSValue tjs_curl_set_opt(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    if (argc < 2) return JS_ThrowTypeError(ctx, "setOpt(optId, value) requires 2 arguments");

    int32_t id32;
    if (JS_ToInt32(ctx, &id32, argv[0]) < 0) return JS_EXCEPTION;
    CURLoption id = (CURLoption) id32;
    JSValueConst value = argv[1];

    if (curl_option_is_reserved(id)) {
        return JS_ThrowTypeError(ctx, "setOpt(%d) is reserved by the CURL binding", id32);
    }

    const struct curl_easyoption *opt = curl_easy_option_by_id(id);
    if (!opt && id32 >= CURLOPTTYPE_OBJECTPOINT && id32 < CURLOPTTYPE_OFF_T) {
        return JS_ThrowTypeError(ctx, "unknown object pointer option %d is unsafe for setOpt()", id32);
    }
    curl_easytype type = opt ? opt->type
                             : (curl_easytype) /* fallback by numeric range */
                               (id32 >= CURLOPTTYPE_BLOB ? CURLOT_BLOB :
                                id32 >= CURLOPTTYPE_OFF_T ? CURLOT_OFF_T : CURLOT_LONG);

    CURLcode rc = CURLE_OK;
    switch (type) {
        case CURLOT_LONG:
        case CURLOT_VALUES: {
            long n;
            if (js_to_curl_long(ctx, value, &n) < 0) return JS_EXCEPTION;
            rc = curl_easy_setopt(curl->handle, id, n);
            break;
        }
        case CURLOT_OFF_T: {
            int64_t n;
            if (JS_ToInt64(ctx, &n, value) < 0) return JS_EXCEPTION;
            rc = curl_easy_setopt(curl->handle, id, (curl_off_t) n);
            break;
        }
        case CURLOT_STRING: {
            if (JS_IsNull(value) || JS_IsUndefined(value)) {
                rc = curl_easy_setopt(curl->handle, id, NULL);
            } else {
                const char *s = JS_ToCString(ctx, value);
                if (!s) return JS_EXCEPTION;
                rc = curl_easy_setopt(curl->handle, id, s);
                JS_FreeCString(ctx, s);
            }
            break;
        }
        case CURLOT_SLIST: {
            if (!JS_IsObject(value)) return JS_ThrowTypeError(ctx, "slist option expects an array of strings");
            if (curl_set_slist_opt(ctx, curl, id, value) < 0) return JS_ThrowOutOfMemory(ctx);
            return JS_DupValue(ctx, this_val);
        }
        case CURLOT_BLOB: {
            size_t len;
            uint8_t *data = JS_GetAnyBuffer(ctx, &len, value);
            if (!data) return JS_ThrowTypeError(ctx, "blob option expects an ArrayBuffer");
            struct curl_blob blob = { .data = data, .len = len, .flags = CURL_BLOB_COPY };
            rc = curl_easy_setopt(curl->handle, id, &blob);
            break;
        }
        default:
            return JS_ThrowTypeError(ctx, "option %d has an unsupported type for setOpt()", id32);
    }

    if (rc != CURLE_OK) {
        return JS_ThrowPlainError(ctx, "setOpt(%d) failed: %s", id32, curl_easy_strerror(rc));
    }
    return JS_DupValue(ctx, this_val);
}

/* setOptByName("URL", value) same dispatch keyed by curl option name. */
static JSValue tjs_curl_set_opt_by_name(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    if (argc < 2) return JS_ThrowTypeError(ctx, "setOptByName(name, value) requires 2 arguments");
    const char *name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_EXCEPTION;
    const struct curl_easyoption *opt = curl_easy_option_by_name(name);
    JS_FreeCString(ctx, name);
    if (!opt) return JS_ThrowTypeError(ctx, "unknown curl option name");

    JSValueConst forwarded[2] = { JS_NewInt32(ctx, opt->id), argv[1] };
    JSValue r = tjs_curl_set_opt(ctx, this_val, 2, forwarded);
    JS_FreeValue(ctx, forwarded[0]);
    return r;
}

static JSValue curl_info_value(JSContext *ctx, CURL *handle, CURLINFO info) {
    switch (info & CURLINFO_TYPEMASK) {
        case CURLINFO_STRING: {
            char *s = NULL;
            if (curl_easy_getinfo(handle, info, &s) != CURLE_OK || !s) return JS_NULL;
            return JS_NewString(ctx, s);
        }
        case CURLINFO_LONG: {
            long v = 0;
            if (curl_easy_getinfo(handle, info, &v) != CURLE_OK) return JS_NULL;
            return JS_NewInt64(ctx, v);
        }
        case CURLINFO_DOUBLE: {
            double v = 0;
            if (curl_easy_getinfo(handle, info, &v) != CURLE_OK) return JS_NULL;
            return JS_NewFloat64(ctx, v);
        }
        case CURLINFO_OFF_T: {
            curl_off_t v = 0;
            if (curl_easy_getinfo(handle, info, &v) != CURLE_OK) return JS_NULL;
            return JS_NewInt64(ctx, (int64_t) v);
        }
        case CURLINFO_SLIST: {
            struct curl_slist *list = NULL;
            if (curl_easy_getinfo(handle, info, &list) != CURLE_OK) return JS_NULL;
            JSValue arr = JS_NewArray(ctx);
            uint32_t i = 0;
            for (struct curl_slist *p = list; p; p = p->next)
                JS_SetPropertyUint32(ctx, arr, i++, JS_NewString(ctx, p->data));
            if (list) curl_slist_free_all(list);
            return arr;
        }
        default:
            return JS_NULL;
    }
}

static JSValue tjs_curl_get_info(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);

    if (argc >= 1 && JS_IsNumber(argv[0])) {
        int32_t id;
        if (JS_ToInt32(ctx, &id, argv[0]) < 0) return JS_EXCEPTION;
        return curl_info_value(ctx, curl->handle, (CURLINFO) id);
    }

    /* no-arg: friendly summary */
    JSValue info = JS_NewObject(ctx);
    long response_code = 0;
    curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE, &response_code);
    JS_DefinePropertyValueStr(ctx, info, "status", JS_NewInt32(ctx, response_code), JS_PROP_C_W_E);

    char *url = NULL;
    curl_easy_getinfo(curl->handle, CURLINFO_EFFECTIVE_URL, &url);
    if (url) JS_DefinePropertyValueStr(ctx, info, "url", JS_NewString(ctx, url), JS_PROP_C_W_E);

    double total_time = 0;
    curl_easy_getinfo(curl->handle, CURLINFO_TOTAL_TIME, &total_time);
    JS_DefinePropertyValueStr(ctx, info, "totalTime", JS_NewFloat64(ctx, total_time), JS_PROP_C_W_E);

    curl_off_t dl = 0, ul = 0;
    curl_easy_getinfo(curl->handle, CURLINFO_SIZE_DOWNLOAD_T, &dl);
    curl_easy_getinfo(curl->handle, CURLINFO_SIZE_UPLOAD_T, &ul);
    JS_DefinePropertyValueStr(ctx, info, "downloadSize", JS_NewInt64(ctx, dl), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, info, "uploadSize", JS_NewInt64(ctx, ul), JS_PROP_C_W_E);

    curl_off_t speed = 0;
    curl_easy_getinfo(curl->handle, CURLINFO_SPEED_DOWNLOAD_T, &speed);
    JS_DefinePropertyValueStr(ctx, info, "downloadSpeed", JS_NewInt64(ctx, speed), JS_PROP_C_W_E);

    long http_version = 0;
    curl_easy_getinfo(curl->handle, CURLINFO_HTTP_VERSION, &http_version);
    JS_DefinePropertyValueStr(ctx, info, "httpVersion", JS_NewInt32(ctx, http_version), JS_PROP_C_W_E);

    return info;
}

#pragma endregion

#pragma region Typed sugar helpers

static JSValue tjs_curl_set_ssl_verify(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    bool verify_peer = JS_ToBool(ctx, argv[0]);
    bool verify_host = argc > 1 ? JS_ToBool(ctx, argv[1]) : verify_peer;
    curl_easy_setopt(curl->handle, CURLOPT_SSL_VERIFYPEER, verify_peer ? 1L : 0L);
    curl_easy_setopt(curl->handle, CURLOPT_SSL_VERIFYHOST, verify_host ? 2L : 0L);
    return JS_DupValue(ctx, this_val);
}

static JSValue curl_set_string_opt(JSContext *ctx, JSValueConst this_val, JSValueConst v, CURLoption opt) {
    CURL_THIS(ctx, this_val);
    const char *s = JS_ToCString(ctx, v);
    if (!s) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, opt, s);
    JS_FreeCString(ctx, s);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_ca_bundle(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_CAINFO);
}
static JSValue tjs_curl_set_user_agent(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_USERAGENT);
}
static JSValue tjs_curl_set_cookie(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_COOKIE);
}
static JSValue tjs_curl_set_cookie_file(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_COOKIEFILE);
}
static JSValue tjs_curl_set_cookie_jar(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_COOKIEJAR);
}
static JSValue tjs_curl_set_referer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_REFERER);
}
static JSValue tjs_curl_set_dns_servers(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_DNS_SERVERS);
}
static JSValue tjs_curl_set_interface(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return curl_set_string_opt(ctx, this_val, argv[0], CURLOPT_INTERFACE);
}

static JSValue tjs_curl_set_accept_encoding(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    /* empty string => all encodings libcurl was built with */
    const char *enc = argc > 0 && JS_IsString(argv[0]) ? JS_ToCString(ctx, argv[0]) : NULL;
    curl_easy_setopt(curl->handle, CURLOPT_ACCEPT_ENCODING, enc ? enc : "");
    if (enc) JS_FreeCString(ctx, enc);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_basic_auth(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *user = JS_ToCString(ctx, argv[0]);
    const char *pass = argc > 1 ? JS_ToCString(ctx, argv[1]) : NULL;
    if (user) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTPAUTH, (long) CURLAUTH_BASIC);
        curl_easy_setopt(curl->handle, CURLOPT_USERNAME, user);
        if (pass) curl_easy_setopt(curl->handle, CURLOPT_PASSWORD, pass);
    }
    if (user) JS_FreeCString(ctx, user);
    if (pass) JS_FreeCString(ctx, pass);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_bearer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *token = JS_ToCString(ctx, argv[0]);
    if (!token) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_HTTPAUTH, (long) CURLAUTH_BEARER);
    curl_easy_setopt(curl->handle, CURLOPT_XOAUTH2_BEARER, token);
    JS_FreeCString(ctx, token);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_proxy(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *proxy = JS_ToCString(ctx, argv[0]);
    if (!proxy) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_PROXY, proxy);
    JS_FreeCString(ctx, proxy);

    if (argc > 1 && JS_IsString(argv[1])) {
        const char *type = JS_ToCString(ctx, argv[1]);
        if (type) {
            long t = -1;
            if (strcmp(type, "http") == 0) t = CURLPROXY_HTTP;
            else if (strcmp(type, "https") == 0) t = CURLPROXY_HTTPS;
            else if (strcmp(type, "socks4") == 0) t = CURLPROXY_SOCKS4;
            else if (strcmp(type, "socks4a") == 0) t = CURLPROXY_SOCKS4A;
            else if (strcmp(type, "socks5") == 0) t = CURLPROXY_SOCKS5;
            else if (strcmp(type, "socks5h") == 0) t = CURLPROXY_SOCKS5_HOSTNAME;
            if (t >= 0) curl_easy_setopt(curl->handle, CURLOPT_PROXYTYPE, t);
            JS_FreeCString(ctx, type);
        }
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_max_redirects(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    int32_t max;
    if (JS_ToInt32(ctx, &max, argv[0]) < 0) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_MAXREDIRS, (long) max);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_connect_timeout(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    int32_t timeout;
    if (JS_ToInt32(ctx, &timeout, argv[0]) < 0) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_CONNECTTIMEOUT_MS, (long) timeout);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_low_speed(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    int32_t limit = 0, time_s = 0;
    if (JS_ToInt32(ctx, &limit, argv[0]) < 0) return JS_EXCEPTION;
    if (argc > 1 && JS_ToInt32(ctx, &time_s, argv[1]) < 0) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_LOW_SPEED_LIMIT, (long) limit);
    curl_easy_setopt(curl->handle, CURLOPT_LOW_SPEED_TIME, (long) time_s);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_keepalive(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    bool on = JS_ToBool(ctx, argv[0]);
    curl_easy_setopt(curl->handle, CURLOPT_TCP_KEEPALIVE, on ? 1L : 0L);
    if (argc > 1) {
        int32_t idle; if (JS_ToInt32(ctx, &idle, argv[1]) == 0)
            curl_easy_setopt(curl->handle, CURLOPT_TCP_KEEPIDLE, (long) idle);
    }
    if (argc > 2) {
        int32_t intvl; if (JS_ToInt32(ctx, &intvl, argv[2]) == 0)
            curl_easy_setopt(curl->handle, CURLOPT_TCP_KEEPINTVL, (long) intvl);
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_verbose(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    curl_easy_setopt(curl->handle, CURLOPT_VERBOSE, JS_ToBool(ctx, argv[0]) ? 1L : 0L);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_http_version(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *version = JS_ToCString(ctx, argv[0]);
    if (!version) return JS_EXCEPTION;
    long v = CURL_HTTP_VERSION_NONE;
    if (strcmp(version, "1.0") == 0) v = CURL_HTTP_VERSION_1_0;
    else if (strcmp(version, "1.1") == 0) v = CURL_HTTP_VERSION_1_1;
    else if (strcmp(version, "2") == 0 || strcmp(version, "2.0") == 0) v = CURL_HTTP_VERSION_2_0;
    else if (strcmp(version, "2TLS") == 0) v = CURL_HTTP_VERSION_2TLS;
#ifdef CURL_HTTP_VERSION_3
    else if (strcmp(version, "3") == 0) v = CURL_HTTP_VERSION_3;
#endif
    curl_easy_setopt(curl->handle, CURLOPT_HTTP_VERSION, v);
    JS_FreeCString(ctx, version);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_range(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    int64_t start, end = -1;
    if (JS_ToInt64(ctx, &start, argv[0]) < 0) return JS_EXCEPTION;
    if (argc > 1 && !JS_IsUndefined(argv[1])) JS_ToInt64(ctx, &end, argv[1]);

    char range[64];
    if (end >= 0) snprintf(range, sizeof(range), "%lld-%lld", (long long) start, (long long) end);
    else snprintf(range, sizeof(range), "%lld-", (long long) start);
    curl_easy_setopt(curl->handle, CURLOPT_RANGE, range);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_share(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    TJSShare *sh = JS_GetOpaque2(ctx, argv[0], tjs_share_class_id);
    if (!sh) return JS_EXCEPTION;
    curl_easy_setopt(curl->handle, CURLOPT_SHARE, sh->share);
    JS_FreeValue(ctx, curl->share_obj);
    curl->share_obj = JS_DupValue(ctx, argv[0]); /* keep the Share alive */
    return JS_DupValue(ctx, this_val);
}

#pragma endregion

#pragma region Upload / mime

static JSValue tjs_curl_set_upload_data(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);

    size_t len = 0;
    const uint8_t *data;
    const char *cstr = NULL;
    if (JS_IsString(argv[0])) {
        cstr = JS_ToCStringLen(ctx, &len, argv[0]);
        if (!cstr) return JS_EXCEPTION;
        data = (const uint8_t *) cstr;
    } else {
        data = JS_GetAnyBuffer(ctx, &len, argv[0]);
        if (!data) return JS_ThrowTypeError(ctx, "upload data must be a string, ArrayBuffer or TypedArray");
    }

    curl_clear_body_resources(JS_GetRuntime(ctx), curl);

    curl->upload_data = js_malloc(ctx, len ? len : 1);
    if (!curl->upload_data) { if (cstr) JS_FreeCString(ctx, cstr); return JS_EXCEPTION; }
    memcpy(curl->upload_data, data, len);
    curl->upload_size = len;
    curl->upload_offset = 0;
    if (cstr) JS_FreeCString(ctx, cstr);

    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl->handle, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl->handle, CURLOPT_READDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t) len);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_upload_file(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    const char *path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        JS_FreeCString(ctx, path);
        return JS_ThrowPlainError(ctx, "cannot open upload file");
    }
    JS_FreeCString(ctx, path);

    curl_clear_body_resources(JS_GetRuntime(ctx), curl);
    curl->upload_fp = fp;

    /* default READFUNCTION uses fread() on READDATA as a FILE* */
    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl->handle, CURLOPT_READFUNCTION, NULL);
    curl_easy_setopt(curl->handle, CURLOPT_READDATA, fp);

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz >= 0) curl_easy_setopt(curl->handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t) sz);
    return JS_DupValue(ctx, this_val);
}

/* setMimePost([{ name, data?|file?, filename?, type? }, ...]) */
static JSValue tjs_curl_set_mime_post(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    if (!JS_IsObject(argv[0])) return JS_ThrowTypeError(ctx, "setMimePost expects an array of parts");

    curl_clear_body_resources(JS_GetRuntime(ctx), curl);
    curl_mime *mime = curl_mime_init(curl->handle);
    if (!mime) return JS_ThrowOutOfMemory(ctx);

    uint32_t len = 0;
    JSValue lenv = JS_GetPropertyStr(ctx, argv[0], "length");
    JS_ToUint32(ctx, &len, lenv);
    JS_FreeValue(ctx, lenv);

    for (uint32_t i = 0; i < len; i++) {
        JSValue part = JS_GetPropertyUint32(ctx, argv[0], i);
        curl_mimepart *mp = curl_mime_addpart(mime);

        JSValue jn = JS_GetPropertyStr(ctx, part, "name");
        const char *name = JS_IsString(jn) ? JS_ToCString(ctx, jn) : NULL;
        if (name) curl_mime_name(mp, name);

        JSValue jfile = JS_GetPropertyStr(ctx, part, "file");
        JSValue jdata = JS_GetPropertyStr(ctx, part, "data");
        if (JS_IsString(jfile)) {
            const char *f = JS_ToCString(ctx, jfile);
            if (f) { curl_mime_filedata(mp, f); JS_FreeCString(ctx, f); }
        } else if (!JS_IsUndefined(jdata)) {
            size_t dlen = 0;
            const char *cstr = NULL;
            const uint8_t *data;
            if (JS_IsString(jdata)) { cstr = JS_ToCStringLen(ctx, &dlen, jdata); data = (const uint8_t *) cstr; }
            else data = JS_GetAnyBuffer(ctx, &dlen, jdata);
            if (data) curl_mime_data(mp, (const char *) data, dlen);
            if (cstr) JS_FreeCString(ctx, cstr);
        }

        JSValue jfn = JS_GetPropertyStr(ctx, part, "filename");
        if (JS_IsString(jfn)) { const char *fn = JS_ToCString(ctx, jfn); if (fn) { curl_mime_filename(mp, fn); JS_FreeCString(ctx, fn); } }
        JSValue jtype = JS_GetPropertyStr(ctx, part, "type");
        if (JS_IsString(jtype)) { const char *t = JS_ToCString(ctx, jtype); if (t) { curl_mime_type(mp, t); JS_FreeCString(ctx, t); } }

        if (name) JS_FreeCString(ctx, name);
        JS_FreeValue(ctx, jn);
        JS_FreeValue(ctx, jfile);
        JS_FreeValue(ctx, jdata);
        JS_FreeValue(ctx, jfn);
        JS_FreeValue(ctx, jtype);
        JS_FreeValue(ctx, part);
    }

    curl->mime = mime;
    curl_easy_setopt(curl->handle, CURLOPT_MIMEPOST, mime);
    return JS_DupValue(ctx, this_val);
}

#pragma endregion

#pragma region Execution

static void curl_reset_buffers(TJSCURL *curl) {
    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);
    tjs_dbuf_init(curl->ctx, &curl->response_body);
    tjs_dbuf_init(curl->ctx, &curl->response_headers);
    curl->completed = false;
    curl->headers_complete_fired = false;
    curl->upload_offset = 0;
    if (curl->upload_fp) fseek(curl->upload_fp, 0, SEEK_SET);
}

static JSValue tjs_curl_perform(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);

    TJSConnPool *pool = curl->pool;
    if (!pool || connpool_require_open(ctx, pool) < 0)
        return JS_EXCEPTION;
    if (curl->in_flight || TJS_IsPromisePending(ctx, &curl->promise))
        return JS_ThrowTypeError(ctx, "Request already in progress");

    curl_reset_buffers(curl);

    JSValue promise = TJS_InitPromise(ctx, &curl->promise);
    if (JS_IsException(promise)) return JS_EXCEPTION;

    curl->self_obj = JS_DupValue(ctx, this_val);

    CURLMcode mc = curl_multi_add_handle(pool->multi_handle, curl->handle);
    if (mc != CURLM_OK) {
        JSValue err = build_error(ctx, NULL, CURLE_FAILED_INIT);
        JS_FreeValue(ctx, err);
        TJS_FreePromise(ctx, &curl->promise);
        TJS_ClearPromise(ctx, &curl->promise);
        curl_release_self(ctx, curl);
        JS_FreeValue(ctx, promise);
        return JS_ThrowPlainError(ctx, "curl_multi_add_handle failed: %s", curl_multi_strerror(mc));
    }
    curl->in_flight = true;

    int running;
    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    if (pool->multi_handle) {
        kick_prep_once(pool);
    }

    return promise;
}

static JSValue tjs_curl_abort(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    if (!curl->in_flight) return JS_UNDEFINED;

    // Prevent abort while inside a callback - would cause UAF
    if (curl->in_callback) {
        return JS_ThrowTypeError(ctx, "Cannot abort() from within a callback");
    }

    if (curl->pool && curl->pool->multi_handle)
        curl_multi_remove_handle(curl->pool->multi_handle, curl->handle);
    curl->in_flight = false;
    curl->completed = true;

    if (TJS_IsPromisePending(ctx, &curl->promise)) {
        JSValue err = build_error(ctx, NULL, CURLE_ABORTED_BY_CALLBACK);
        TJS_SettlePromise(ctx, &curl->promise, true, 1, &err);
    }
    curl_release_self(ctx, curl);
    return JS_UNDEFINED;
}

static JSValue tjs_curl_perform_sync(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);
    if (curl->in_flight)
        return JS_ThrowTypeError(ctx, "Request already in progress");

    curl_reset_buffers(curl);

    /* curl_easy_perform on the handle directly; never touches the multi pool. */
    CURLcode res = curl_easy_perform(curl->handle);

    if (res != CURLE_OK) {
        return JS_Throw(ctx, build_error(ctx, curl->error_buffer, res));
    }

    curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE, &curl->response_code);
    char *url = NULL;
    curl_easy_getinfo(curl->handle, CURLINFO_EFFECTIVE_URL, &url);
    if (url) {
        if (curl->effective_url) js_free(ctx, curl->effective_url);
        curl->effective_url = js_strdup(ctx, url);
    }
    return build_response(ctx, curl);
}

static JSValue tjs_curl_reset(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    CURL_THIS(ctx, this_val);

    // Prevent reset while inside a callback - would cause UAF
    if (curl->in_callback) {
        return JS_ThrowTypeError(ctx, "Cannot reset() from within a callback");
    }

    if (curl->in_flight && curl->pool && curl->pool->multi_handle) {
        curl_multi_remove_handle(curl->pool->multi_handle, curl->handle);
        curl->in_flight = false;
        curl->completed = true;
    }

    curl_easy_reset(curl->handle);
    curl_apply_default_opts(curl);
    curl_clear_request_resources(JS_GetRuntime(ctx), curl);

    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);
    tjs_dbuf_init(ctx, &curl->response_body);
    tjs_dbuf_init(ctx, &curl->response_headers);
    curl->completed = false;
    curl->headers_complete_fired = false;
    curl->stream_mode = false;

    if (TJS_IsPromisePending(ctx, &curl->promise)) {
        JSValue err = build_error(ctx, NULL, CURLE_ABORTED_BY_CALLBACK);
        TJS_SettlePromise(ctx, &curl->promise, true, 1, &err);
    }
    curl_release_self(ctx, curl);

    JS_FreeValue(ctx, curl->on_data); curl->on_data = JS_UNDEFINED;
    JS_FreeValue(ctx, curl->on_progress); curl->on_progress = JS_UNDEFINED;
    JS_FreeValue(ctx, curl->on_header); curl->on_header = JS_UNDEFINED;
    JS_FreeValue(ctx, curl->on_headers_complete); curl->on_headers_complete = JS_UNDEFINED;
    JS_FreeValue(ctx, curl->share_obj); curl->share_obj = JS_UNDEFINED;

    return JS_UNDEFINED;
}

#pragma endregion

#pragma region Share class

static JSValue tjs_share_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_share_class_id);
    if (JS_IsException(obj)) return obj;

    TJSShare *sh = js_mallocz(ctx, sizeof(TJSShare));
    if (!sh) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }

    sh->share = curl_share_init();
    if (!sh->share) { js_free(ctx, sh); JS_FreeValue(ctx, obj); return JS_ThrowOutOfMemory(ctx); }

    /* single-threaded module: no lock callbacks needed */
    curl_share_setopt(sh->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
    curl_share_setopt(sh->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    curl_share_setopt(sh->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    curl_share_setopt(sh->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);

    JS_SetOpaque(obj, sh);
    return obj;
}

#pragma endregion

#pragma region Module static functions

static JSValue tjs_curl_static_strerror(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    int32_t code;
    if (argc == 0 || JS_ToInt32(ctx, &code, argv[0]) < 0)
        return JS_ThrowTypeError(ctx, "strerror expects an integer code");
    return JS_NewString(ctx, curl_easy_strerror((CURLcode) code));
}

static JSValue tjs_curl_static_escape(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    size_t len;
    const char *s = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!s) return JS_EXCEPTION;
    char *out = curl_easy_escape(NULL, s, (int) len);
    JS_FreeCString(ctx, s);
    JSValue r = out ? JS_NewString(ctx, out) : JS_NULL;
    if (out) curl_free(out);
    return r;
}

static JSValue tjs_curl_static_unescape(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    size_t len;
    const char *s = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!s) return JS_EXCEPTION;
    int outlen = 0;
    char *out = curl_easy_unescape(NULL, s, (int) len, &outlen);
    JS_FreeCString(ctx, s);
    JSValue r = out ? JS_NewStringLen(ctx, out, outlen) : JS_NULL;
    if (out) curl_free(out);
    return r;
}

#pragma endregion

#pragma region Proto Tables

static const JSCFunctionListEntry tjs_curl_proto_funcs[] = {
    TJS_CFUNC_DEF("setUrl", 1, tjs_curl_set_url),
    TJS_CFUNC_DEF("setMethod", 1, tjs_curl_set_method),
    TJS_CFUNC_DEF("setHeaders", 1, tjs_curl_set_headers),
    TJS_CFUNC_DEF("setBody", 1, tjs_curl_set_body),
    TJS_CFUNC_DEF("setTimeout", 1, tjs_curl_set_timeout),
    TJS_CFUNC_DEF("setFollowRedirects", 1, tjs_curl_set_follow_redirects),

    /* generic escape hatch: near-complete libcurl access */
    TJS_CFUNC_DEF("setOpt", 2, tjs_curl_set_opt),
    TJS_CFUNC_DEF("setOptByName", 2, tjs_curl_set_opt_by_name),
    TJS_CFUNC_DEF("getInfo", 0, tjs_curl_get_info),

    /* callbacks */
    TJS_CFUNC_DEF("onProgress", 1, tjs_curl_on_progress),
    TJS_CFUNC_DEF("onHeader", 1, tjs_curl_on_header),
    TJS_CFUNC_DEF("onHeadersComplete", 1, tjs_curl_on_headers_complete),
    TJS_CFUNC_DEF("setStreamMode", 1, tjs_curl_set_stream_mode),
    TJS_CFUNC_DEF("onData", 1, tjs_curl_on_data),

    /* execution */
    TJS_CFUNC_DEF("perform", 0, tjs_curl_perform),
    TJS_CFUNC_DEF("performSync", 0, tjs_curl_perform_sync),
    TJS_CFUNC_DEF("abort", 0, tjs_curl_abort),
    TJS_CFUNC_DEF("reset", 0, tjs_curl_reset),

    /* SSL/TLS */
    TJS_CFUNC_DEF("setSSLVerify", 1, tjs_curl_set_ssl_verify),
    TJS_CFUNC_DEF("setCABundle", 1, tjs_curl_set_ca_bundle),

    /* network */
    TJS_CFUNC_DEF("setProxy", 1, tjs_curl_set_proxy),
    TJS_CFUNC_DEF("setInterface", 1, tjs_curl_set_interface),
    TJS_CFUNC_DEF("setDNSServers", 1, tjs_curl_set_dns_servers),
    TJS_CFUNC_DEF("setKeepAlive", 1, tjs_curl_set_keepalive),
    TJS_CFUNC_DEF("setLowSpeedLimit", 1, tjs_curl_set_low_speed),

    /* HTTP */
    TJS_CFUNC_DEF("setUserAgent", 1, tjs_curl_set_user_agent),
    TJS_CFUNC_DEF("setCookie", 1, tjs_curl_set_cookie),
    TJS_CFUNC_DEF("setCookieFile", 1, tjs_curl_set_cookie_file),
    TJS_CFUNC_DEF("setCookieJar", 1, tjs_curl_set_cookie_jar),
    TJS_CFUNC_DEF("setReferer", 1, tjs_curl_set_referer),
    TJS_CFUNC_DEF("setMaxRedirects", 1, tjs_curl_set_max_redirects),
    TJS_CFUNC_DEF("setHTTPVersion", 1, tjs_curl_set_http_version),
    TJS_CFUNC_DEF("setRange", 1, tjs_curl_set_range),
    TJS_CFUNC_DEF("setAcceptEncoding", 1, tjs_curl_set_accept_encoding),
    TJS_CFUNC_DEF("setBasicAuth", 1, tjs_curl_set_basic_auth),
    TJS_CFUNC_DEF("setBearerToken", 1, tjs_curl_set_bearer),

    /* upload / multipart */
    TJS_CFUNC_DEF("setUploadData", 1, tjs_curl_set_upload_data),
    TJS_CFUNC_DEF("setUploadFile", 1, tjs_curl_set_upload_file),
    TJS_CFUNC_DEF("setMimePost", 1, tjs_curl_set_mime_post),

    /* sharing */
    TJS_CFUNC_DEF("setShare", 1, tjs_curl_set_share),

    /* timeouts / debug */
    TJS_CFUNC_DEF("setConnectTimeout", 1, tjs_curl_set_connect_timeout),
    TJS_CFUNC_DEF("setVerbose", 1, tjs_curl_set_verbose),
};

static const JSCFunctionListEntry tjs_connpool_proto_funcs[] = {
    TJS_CFUNC_DEF("getActiveCount", 0, tjs_connpool_get_active_count),
    TJS_CFUNC_DEF("close", 0, tjs_connpool_close),
    TJS_CFUNC_DEF("process", 0, tjs_connpool_process),
    TJS_CFUNC_DEF("setMaxPipelineLength", 1, tjs_connpool_set_max_pipeline_length),
    TJS_CFUNC_DEF("setMaxConcurrentStreams", 1, tjs_connpool_set_max_concurrent_streams),
    TJS_CGETSET_DEF("onerror", tjs_connpool_get_onerror, tjs_connpool_set_onerror),
};

#pragma endregion

#pragma region Module Initialization

/* Populate ns.CURLOPT with every value option libcurl exposes at runtime. */
static void export_curlopt_table(JSContext *ctx, JSValue ns) {
    JSValue tbl = JS_NewObject(ctx);
    const struct curl_easyoption *o = NULL;
    while ((o = curl_easy_option_next(o)) != NULL) {
        JS_DefinePropertyValueStr(ctx, tbl, o->name, JS_NewInt32(ctx, o->id), JS_PROP_C_W_E);
    }
    JS_DefinePropertyValueStr(ctx, ns, "CURLOPT", tbl, JS_PROP_C_W_E);
}

#define EXPORT_CONST(obj, name) \
    JS_DefinePropertyValueStr(ctx, obj, #name, JS_NewInt64(ctx, (int64_t) name), JS_PROP_C_W_E)

static void export_constants(JSContext *ctx, JSValue ns) {
    /* common CURLINFO ids (no runtime enumeration API exists for these) */
    JSValue info = JS_NewObject(ctx);
    EXPORT_CONST(info, CURLINFO_EFFECTIVE_URL);
    EXPORT_CONST(info, CURLINFO_RESPONSE_CODE);
    EXPORT_CONST(info, CURLINFO_HTTP_VERSION);
    EXPORT_CONST(info, CURLINFO_TOTAL_TIME);
    EXPORT_CONST(info, CURLINFO_NAMELOOKUP_TIME);
    EXPORT_CONST(info, CURLINFO_CONNECT_TIME);
    EXPORT_CONST(info, CURLINFO_APPCONNECT_TIME);
    EXPORT_CONST(info, CURLINFO_PRETRANSFER_TIME);
    EXPORT_CONST(info, CURLINFO_STARTTRANSFER_TIME);
    EXPORT_CONST(info, CURLINFO_REDIRECT_TIME);
    EXPORT_CONST(info, CURLINFO_REDIRECT_COUNT);
    EXPORT_CONST(info, CURLINFO_REDIRECT_URL);
    EXPORT_CONST(info, CURLINFO_SIZE_UPLOAD_T);
    EXPORT_CONST(info, CURLINFO_SIZE_DOWNLOAD_T);
    EXPORT_CONST(info, CURLINFO_SPEED_DOWNLOAD_T);
    EXPORT_CONST(info, CURLINFO_SPEED_UPLOAD_T);
    EXPORT_CONST(info, CURLINFO_CONTENT_TYPE);
    EXPORT_CONST(info, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T);
    EXPORT_CONST(info, CURLINFO_PRIMARY_IP);
    EXPORT_CONST(info, CURLINFO_PRIMARY_PORT);
    EXPORT_CONST(info, CURLINFO_LOCAL_IP);
    EXPORT_CONST(info, CURLINFO_LOCAL_PORT);
    EXPORT_CONST(info, CURLINFO_NUM_CONNECTS);
    EXPORT_CONST(info, CURLINFO_COOKIELIST);
    EXPORT_CONST(info, CURLINFO_SSL_VERIFYRESULT);
    EXPORT_CONST(info, CURLINFO_OS_ERRNO);
    EXPORT_CONST(info, CURLINFO_SCHEME);
    JS_DefinePropertyValueStr(ctx, ns, "CURLINFO", info, JS_PROP_C_W_E);

    /* misc constants for use with setOpt */
    JSValue c = JS_NewObject(ctx);
    EXPORT_CONST(c, CURLAUTH_BASIC);
    EXPORT_CONST(c, CURLAUTH_DIGEST);
    EXPORT_CONST(c, CURLAUTH_NTLM);
    EXPORT_CONST(c, CURLAUTH_BEARER);
    EXPORT_CONST(c, CURLAUTH_NEGOTIATE);
    EXPORT_CONST(c, CURLAUTH_ANY);
    EXPORT_CONST(c, CURLAUTH_ANYSAFE);
    EXPORT_CONST(c, CURLPROXY_HTTP);
    EXPORT_CONST(c, CURLPROXY_HTTPS);
    EXPORT_CONST(c, CURLPROXY_SOCKS4);
    EXPORT_CONST(c, CURLPROXY_SOCKS4A);
    EXPORT_CONST(c, CURLPROXY_SOCKS5);
    EXPORT_CONST(c, CURLPROXY_SOCKS5_HOSTNAME);
    EXPORT_CONST(c, CURL_HTTP_VERSION_1_0);
    EXPORT_CONST(c, CURL_HTTP_VERSION_1_1);
    EXPORT_CONST(c, CURL_HTTP_VERSION_2_0);
    EXPORT_CONST(c, CURL_HTTP_VERSION_2TLS);
#ifdef CURL_HTTP_VERSION_3
    EXPORT_CONST(c, CURL_HTTP_VERSION_3);
#endif
    EXPORT_CONST(c, CURLUSESSL_NONE);
    EXPORT_CONST(c, CURLUSESSL_TRY);
    EXPORT_CONST(c, CURLUSESSL_CONTROL);
    EXPORT_CONST(c, CURLUSESSL_ALL);
    EXPORT_CONST(c, CURLSSLOPT_ALLOW_BEAST);
    EXPORT_CONST(c, CURLSSLOPT_NO_REVOKE);
    EXPORT_CONST(c, CURL_IPRESOLVE_WHATEVER);
    EXPORT_CONST(c, CURL_IPRESOLVE_V4);
    EXPORT_CONST(c, CURL_IPRESOLVE_V6);
    JS_DefinePropertyValueStr(ctx, ns, "constants", c, JS_PROP_C_W_E);
}

void tjs__mod_curl_init(JSContext *ctx, JSValue ns) {
    curl_global_init(CURL_GLOBAL_ALL);
    JSRuntime *rt = JS_GetRuntime(ctx);

    /* ConnPool */
    JS_NewClassID(rt, &tjs_connpool_class_id);
    JS_NewClass(rt, tjs_connpool_class_id, &tjs_connpool_class);
    JSValue connpool_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, connpool_proto, tjs_connpool_proto_funcs, countof(tjs_connpool_proto_funcs));
    JS_SetClassProto(ctx, tjs_connpool_class_id, connpool_proto);
    JSValue connpool_ctor = JS_NewCFunction2(ctx, tjs_connpool_constructor, "ConnPool", 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "ConnPool", connpool_ctor, JS_PROP_C_W_E);

    /* CURL */
    JS_NewClassID(rt, &tjs_curl_class_id);
    JS_NewClass(rt, tjs_curl_class_id, &tjs_curl_class);
    JSValue curl_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, curl_proto, tjs_curl_proto_funcs, countof(tjs_curl_proto_funcs));
    JS_SetClassProto(ctx, tjs_curl_class_id, curl_proto);
    JSValue curl_ctor = JS_NewCFunction2(ctx, tjs_curl_constructor, "CURL", 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "CURL", curl_ctor, JS_PROP_C_W_E);

    /* Share */
    JS_NewClassID(rt, &tjs_share_class_id);
    JS_NewClass(rt, tjs_share_class_id, &tjs_share_class);
    JSValue share_proto = JS_NewObject(ctx);
    JS_SetClassProto(ctx, tjs_share_class_id, share_proto);
    JSValue share_ctor = JS_NewCFunction2(ctx, tjs_share_constructor, "Share", 0, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "Share", share_ctor, JS_PROP_C_W_E);

    /* module static functions */
    JS_DefinePropertyValueStr(ctx, ns, "strerror",
        JS_NewCFunction(ctx, tjs_curl_static_strerror, "strerror", 1), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, ns, "escape",
        JS_NewCFunction(ctx, tjs_curl_static_escape, "escape", 1), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, ns, "unescape",
        JS_NewCFunction(ctx, tjs_curl_static_unescape, "unescape", 1), JS_PROP_C_W_E);

    /* constant tables */
    export_curlopt_table(ctx, ns);
    export_constants(ctx, ns);

    /* version info */
    JSValue version_info = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, version_info, "curl", JS_NewString(ctx, curl_version()), JS_PROP_C_W_E);
    curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
    if (ver) {
        DynBuf protocols;
        tjs_dbuf_init(ctx, &protocols);
        if (ver->protocols) {
            for (int i = 0; ver->protocols[i]; i++) {
                if (i > 0) dbuf_putc(&protocols, ',');
                dbuf_putstr(&protocols, ver->protocols[i]);
            }
        }
        dbuf_putc(&protocols, '\0');
        JS_DefinePropertyValueStr(ctx, version_info, "protocols",
            JS_NewString(ctx, protocols.buf ? (char *) protocols.buf : ""), JS_PROP_C_W_E);
        dbuf_free(&protocols);
        JS_DefinePropertyValueStr(ctx, version_info, "features",
            JS_NewInt64(ctx, ver->features), JS_PROP_C_W_E);
    }
    JS_DefinePropertyValueStr(ctx, ns, "version", version_info, JS_PROP_C_W_E);
}

void tjs_mod_curl_cleanup(JSContext *ctx) {
    curl_global_cleanup();
}

#pragma endregion
