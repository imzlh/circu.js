/*
 * txiki.js CURL Module
 * LibCURL integration with libuv event loop
 */

#include "private.h"
#include "tjs.h"
#include "mem.h"
#include <curl/curl.h>

#pragma region Type Definitions

typedef struct {
    uv_prepare_t prep;   // one-shot prepare handle
    void* pool;
} TJSConnPoolPrep;

typedef struct {
    CURLM *multi_handle;
    uv_timer_t timer;
    uv_poll_t *poll_handles;
    size_t poll_count;
    size_t poll_capacity;
    JSContext *ctx;
	JSValue err_cb;

	TJSConnPoolPrep* prep;
} TJSConnPool;

typedef struct {
    CURL *handle;
	JSValue pool_obj;
    TJSConnPool *pool;
    JSContext *ctx;
    JSValue promise;
    JSValue resolve;
    JSValue reject;
	
	JSValue on_data;
    bool stream_mode;
	
    // Response data
    DynBuf response_body;
    DynBuf response_headers;
    struct curl_slist *request_headers;
    
    // Options
    bool sync_mode;
    bool follow_redirects;
    long timeout_ms;
    
    // Callback data
    JSValue on_progress;
    JSValue on_header;
    
    // Status
    long response_code;
    char *effective_url;
    char error_buffer[CURL_ERROR_SIZE];
    bool completed;
} TJSCURL;

typedef struct {
    uv_poll_t poll;
    curl_socket_t sockfd;
    TJSConnPool *pool;
} TJSSocketPoll;

// Define magic values for common CURL operations
#define TJS_CURL_MAGIC_GET    0x4745544D  // "GETM"
#define TJS_CURL_MAGIC_POST   0x504F5354  // "POST"
#define TJS_CURL_MAGIC_SYNC   0x53594E43  // "SYNC"

#pragma endregion

#pragma region Forward Declarations

static JSClassID tjs_curl_class_id;
static JSClassID tjs_connpool_class_id;

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

static void kick_prep_once(TJSConnPool *pool);
static void check_multi_info(TJSConnPool *pool);
static void timer_cb(uv_timer_t *handle);

static void call_err_cb(TJSConnPool* pool, CURLMcode err) {
	JSValue cb = pool->err_cb;
	if (JS_IsUndefined(cb)) return;
	JS_ThrowPlainError(pool->ctx, "CURL failed: %s", curl_multi_strerror(err));
	JSValue error = JS_GetException(pool->ctx);
	JS_FreeValue(
		pool->ctx,
		JS_Call(pool->ctx, cb, JS_UNDEFINED, 1, (JSValueConst[]) { error })
	);
	JS_FreeValue(pool->ctx, error);
}

#define MSACT(pool, ...) { \
 	__maybe_unused CURLMcode ret = curl_multi_socket_action(__VA_ARGS__); \
	if (ret != CURLM_OK) call_err_cb(pool, ret); \
}

#pragma endregion

#pragma region LibCURL Callbacks

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    TJSCURL *curl = (TJSCURL *)userdata;
    size_t realsize = size * nmemb;

	if (curl->stream_mode && !JS_IsUndefined(curl->on_data)) {
        JSValue args[1];
        args[0] = JS_NewArrayBufferCopy(curl->ctx, (const uint8_t *)ptr, realsize);
        
        JSValue ret = JS_Call(curl->ctx, curl->on_data, JS_UNDEFINED, 1, args);
        JS_FreeValue(curl->ctx, args[0]);
        
        if (JS_IsException(ret)) {
            JS_FreeValue(curl->ctx, ret);
            return 0;
        }
        
        bool should_abort = false;
        if (JS_IsBool(ret)) {
            should_abort = JS_ToBool(curl->ctx, ret);
        }
        JS_FreeValue(curl->ctx, ret);
        
        return should_abort ? 0 : realsize;
    }
    
    if (dbuf_put(&curl->response_body, (const uint8_t *)ptr, realsize) < 0) {
        return 0;
    }
    
    return realsize;
}

static size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    TJSCURL *curl = (TJSCURL *)userdata;
    size_t realsize = size * nmemb;
    
    if (dbuf_put(&curl->response_headers, (const uint8_t *)ptr, realsize) < 0) {
        return 0;
    }
    
    // Call JS header callback if set
    if (!JS_IsUndefined(curl->on_header)) {
        JSValue args[1];
        args[0] = JS_NewStringLen(curl->ctx, ptr, realsize);
        JSValue ret = JS_Call(curl->ctx, curl->on_header, JS_UNDEFINED, 1, args);
        JS_FreeValue(curl->ctx, args[0]);
        if (JS_IsException(ret)) {
            JS_FreeValue(curl->ctx, ret);
            return 0;
        }
        JS_FreeValue(curl->ctx, ret);
    }
    
    return realsize;
}

static int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, 
                             curl_off_t ultotal, curl_off_t ulnow) {
    TJSCURL *curl = (TJSCURL *)clientp;
    
    if (!JS_IsUndefined(curl->on_progress)) {
        JSValue args[4];
        args[0] = JS_NewInt64(curl->ctx, dltotal);
        args[1] = JS_NewInt64(curl->ctx, dlnow);
        args[2] = JS_NewInt64(curl->ctx, ultotal);
        args[3] = JS_NewInt64(curl->ctx, ulnow);
        
        JSValue ret = JS_Call(curl->ctx, curl->on_progress, JS_UNDEFINED, 4, args);
        
        for (int i = 0; i < 4; i++) {
            JS_FreeValue(curl->ctx, args[i]);
        }
        
        if (JS_IsException(ret)) {
            JS_FreeValue(curl->ctx, ret);
            return 1; // Abort transfer
        }
        
        bool should_abort = false;
        if (JS_IsBool(ret)) {
            should_abort = !JS_ToBool(curl->ctx, ret);
        }
        JS_FreeValue(curl->ctx, ret);
        
        return should_abort ? 1 : 0;
    }
    
    return 0;
}

#pragma endregion

#pragma region Socket Poll Management

static void poll_close_cb(uv_handle_t *handle) {
    TJSSocketPoll *socket_poll = (TJSSocketPoll *)handle->data;
    tjs__free(socket_poll);
}

static void poll_cb(uv_poll_t *handle, int status, int events) {
    TJSSocketPoll *socket_poll = (TJSSocketPoll *)handle->data;
    TJSConnPool *pool = socket_poll->pool;
    
    int ev_bitmask = 0;
    if (events & UV_READABLE) ev_bitmask |= CURL_CSELECT_IN;
    if (events & UV_WRITABLE) ev_bitmask |= CURL_CSELECT_OUT;
    
    int running_handles;
    MSACT(pool, pool->multi_handle, socket_poll->sockfd, ev_bitmask, &running_handles);
}

static int socket_callback(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp) {
    TJSConnPool *pool = (TJSConnPool *)userp;
    TJSSocketPoll *socket_poll = (TJSSocketPoll *)socketp;
    
    if (what == CURL_POLL_REMOVE) {
        if (socket_poll) {
            uv_poll_stop(&socket_poll->poll);
            uv_close((uv_handle_t *)&socket_poll->poll, poll_close_cb);
            curl_multi_assign(pool->multi_handle, s, NULL);
        }
    } else {
        int events = 0;
        if (what & CURL_POLL_IN) events |= UV_READABLE;
        if (what & CURL_POLL_OUT) events |= UV_WRITABLE;
        
        if (!socket_poll) {
            socket_poll = js_malloc(pool->ctx, sizeof(TJSSocketPoll));
            if (!socket_poll) return -1;
            
            socket_poll->sockfd = s;
            socket_poll->pool = pool;
            socket_poll->poll.data = socket_poll;
            
            uv_poll_init_socket(tjs_get_loop(pool->ctx), &socket_poll->poll, s);
            curl_multi_assign(pool->multi_handle, s, socket_poll);
        }
        
        uv_poll_start(&socket_poll->poll, events, poll_cb);
    }
    
    int running = 0;
    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    if (running == 0) {
        kick_prep_once(pool);
    }
    
    return 0;
}

#pragma endregion

#pragma region Prep Management

#define PREP_GET_POOL(p) ((TJSConnPool*)p->pool)

static void once_prepare_cb(uv_prepare_t *handle) {
    TJSConnPoolPrep *prep = (TJSConnPoolPrep *)handle->data;
    TJSConnPool *pool = prep->pool;
    int running;

	if (!pool->ctx) return; // Context was destroyed, stop preparing
    
    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info(pool);
    
    uv_prepare_stop(handle);
}

static void prep_close_cb(uv_handle_t *handle) {
    TJSConnPoolPrep *prep = (TJSConnPoolPrep *)handle->data;
    tjs__free(prep);
}

static void kick_prep_once(TJSConnPool *pool) {
    if (!pool->prep) {
        pool->prep = js_mallocz(pool->ctx, sizeof(TJSConnPoolPrep));
        pool->prep->pool = pool;
        uv_prepare_init(tjs_get_loop(pool->ctx), &pool->prep->prep);
        pool->prep->prep.data = pool->prep;
    }
    uv_prepare_stop(&pool->prep->prep);
    uv_prepare_start(&pool->prep->prep, once_prepare_cb);
}

#pragma endregion

#pragma region Timer Management

static int timer_callback(CURLM *multi, long timeout_ms, void *userp) {
    TJSConnPool *pool = (TJSConnPool *)userp;
    
    if (timeout_ms < 0) {
        uv_timer_stop(&pool->timer);
    } else {
        if (timeout_ms == 0) timeout_ms = 1; // 0 会立即触发，避免忙等
        uv_timer_start(&pool->timer, timer_cb, timeout_ms, 0);
    }
    
    return 0;
}

static void timer_cb(uv_timer_t *handle) {
    TJSConnPool *pool = (TJSConnPool *)handle->data;
    int running;
    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info(pool);
    
    if (running == 0) {
        kick_prep_once(pool);
    }
}

#pragma endregion

#pragma region Request Completion Handling

static void check_multi_info(TJSConnPool *pool) {
    CURLMsg *msg;
    int msgs_left;
    
    // Process all completed transfers from the multi handle
    while ((msg = curl_multi_info_read(pool->multi_handle, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE) {
            CURL *easy = msg->easy_handle;
            TJSCURL *curl;
            
            // Retrieve our custom CURL object from the easy handle
            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &curl);
            
            // Ensure we only process completion once per request
            if (!curl->completed) {
                curl->completed = true;
                
                // Get final response information
                curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &curl->response_code);
                
                // Get the effective URL (after any redirects)
                char *url = NULL;
                curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
                if (url) {
                    curl->effective_url = js_strdup(curl->ctx, url);
                }
                
                // Remove the easy handle from the multi handle
                curl_multi_remove_handle(pool->multi_handle, easy);
                
                // Resolve or reject the JavaScript promise based on result
                if (msg->data.result == CURLE_OK) {
                    JSValue response = JS_NewObject(curl->ctx);
                    
                    // In streaming mode, response body has already been delivered
                    // via onData callbacks during the transfer
                    if (!curl->stream_mode) {
                        // Non-streaming mode: add accumulated response body
                        if (curl->response_body.size > 0) {
                            JS_DefinePropertyValueStr(curl->ctx, response, "body",
                                JS_NewStringLen(curl->ctx, (char *)curl->response_body.buf, 
                                              curl->response_body.size),
                                JS_PROP_C_W_E);
                        } else {
                            JS_DefinePropertyValueStr(curl->ctx, response, "body",
                                JS_NewString(curl->ctx, ""), JS_PROP_C_W_E);
                        }
                    }
                    
                    // Add response headers (accumulated in both modes)
                    if (curl->response_headers.size > 0) {
                        JS_DefinePropertyValueStr(curl->ctx, response, "headers",
                            JS_NewStringLen(curl->ctx, (char *)curl->response_headers.buf,
                                          curl->response_headers.size),
                            JS_PROP_C_W_E);
                    } else {
                        JS_DefinePropertyValueStr(curl->ctx, response, "headers",
                            JS_NewString(curl->ctx, ""), JS_PROP_C_W_E);
                    }
                    
                    // Add HTTP status code
                    JS_DefinePropertyValueStr(curl->ctx, response, "status",
                        JS_NewInt32(curl->ctx, curl->response_code), JS_PROP_C_W_E);
                    
                    // Add effective URL
                    if (curl->effective_url) {
                        JS_DefinePropertyValueStr(curl->ctx, response, "url",
                            JS_NewString(curl->ctx, curl->effective_url), JS_PROP_C_W_E);
                    }
                    
                    // Mark as streamed response if streaming mode was enabled
                    if (curl->stream_mode) {
                        JS_DefinePropertyValueStr(curl->ctx, response, "streamed",
                            JS_NewBool(curl->ctx, true), JS_PROP_C_W_E);
                    }
                    
                    // Resolve the promise with the response object
                    JSValue args[1] = { response };
                    JSValue ret = JS_Call(curl->ctx, curl->resolve, JS_UNDEFINED, 1, args);
                    JS_FreeValue(curl->ctx, ret);
                    JS_FreeValue(curl->ctx, response);
                } else {
                    // Request failed: create and throw error
                    JSValue error = JS_NewError(curl->ctx);
                    
                    // Use detailed error message from buffer if available
                    const char *error_msg = curl->error_buffer[0] ? 
                        curl->error_buffer : curl_easy_strerror(msg->data.result);
                    
                    JS_DefinePropertyValueStr(curl->ctx, error, "message",
                        JS_NewString(curl->ctx, error_msg), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
                    
                    JS_DefinePropertyValueStr(curl->ctx, error, "code",
                        JS_NewInt32(curl->ctx, msg->data.result), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
                    
                    // Reject the promise with the error
                    JSValue args[1] = { error };
                    JSValue ret = JS_Call(curl->ctx, curl->reject, JS_UNDEFINED, 1, args);
                    JS_FreeValue(curl->ctx, ret);
                    JS_FreeValue(curl->ctx, error);
                }
            }
        }
    }
}

#pragma endregion

#pragma region Finalizers

static void tjs_curl_finalizer(JSRuntime *rt, JSValue val) {
    TJSCURL *curl = JS_GetOpaque(val, tjs_curl_class_id);
    if (!curl) return;
    
    if (curl->handle) {
        curl_multi_remove_handle(curl->pool->multi_handle, curl->handle);
        curl_easy_cleanup(curl->handle);
    }
    
    if (curl->request_headers) {
        curl_slist_free_all(curl->request_headers);
    }
    
    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);
    
    JS_FreeValueRT(rt, curl->promise);
    JS_FreeValueRT(rt, curl->resolve);
    JS_FreeValueRT(rt, curl->reject);
    JS_FreeValueRT(rt, curl->on_progress);
    JS_FreeValueRT(rt, curl->on_header);
	JS_FreeValueRT(rt, curl->on_data);
	JS_FreeValueRT(rt, curl->pool_obj);
    
    if (curl->effective_url) {
        js_free_rt(rt, curl->effective_url);
    }
    
    js_free_rt(rt, curl);
}

void timer_close_cb(uv_handle_t* handle) {
	TJSConnPool* pool = handle->data;

	if (pool->prep) {
		uv_prepare_stop(&pool->prep->prep);
		uv_close((uv_handle_t *)&pool->prep->prep, prep_close_cb);
		pool->prep = NULL;
	} else {
		tjs__free(pool);	// note: ctx manbe NULL
	}
}

static void tjs_connpool_finalizer(JSRuntime *rt, JSValue val) {
    TJSConnPool *pool = JS_GetOpaque(val, tjs_connpool_class_id);
    if (!pool) return;
    
    if (pool->multi_handle) {
        curl_multi_cleanup(pool->multi_handle);
		pool->multi_handle = NULL;
	}

	JS_FreeValueRT(rt, pool->err_cb);
	pool->err_cb = JS_UNDEFINED;

	if (uv_is_closing((uv_handle_t *)&pool->timer)) {
		timer_close_cb((uv_handle_t*)&pool->timer);
	} else {
        uv_timer_stop(&pool->timer);
        uv_close((uv_handle_t *)&pool->timer, timer_close_cb);
    }

	pool->ctx = NULL;	// maybe in TJS_FreeRuntime?
}

#pragma endregion

#pragma region GC Mark Functions

static void tjs_curl_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    TJSCURL *curl = JS_GetOpaque(val, tjs_curl_class_id);
    if (curl) {
        // Mark all JSValues held by the CURL object to prevent GC collection
        JS_MarkValue(rt, curl->promise, mark_func);
        JS_MarkValue(rt, curl->resolve, mark_func);
        JS_MarkValue(rt, curl->reject, mark_func);
        JS_MarkValue(rt, curl->on_progress, mark_func);
        JS_MarkValue(rt, curl->on_header, mark_func);
		JS_MarkValue(rt, curl->pool_obj, mark_func);
        JS_MarkValue(rt, curl->on_data, mark_func);           // For streaming mode
    }
}

static void tjs_connpool_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    TJSConnPool *pool = JS_GetOpaque(val, tjs_connpool_class_id);
    if (pool) {
		JS_MarkValue(rt, pool->err_cb, mark_func);
    }
}

#pragma endregion

#pragma region ConnPool Constructor

static JSValue tjs_connpool_constructor(JSContext *ctx, JSValueConst new_target,
                                       int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_connpool_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }
    
    TJSConnPool *pool = js_mallocz(ctx, sizeof(TJSConnPool));
    if (!pool) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    pool->ctx = ctx;
    pool->multi_handle = curl_multi_init();
	pool->err_cb = JS_UNDEFINED;
    if (!pool->multi_handle) {
        js_free(ctx, pool);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    // Set callbacks
    curl_multi_setopt(pool->multi_handle, CURLMOPT_SOCKETFUNCTION, socket_callback);
    curl_multi_setopt(pool->multi_handle, CURLMOPT_SOCKETDATA, pool);
    curl_multi_setopt(pool->multi_handle, CURLMOPT_TIMERFUNCTION, timer_callback);
    curl_multi_setopt(pool->multi_handle, CURLMOPT_TIMERDATA, pool);
    
    // Initialize timer
    pool->timer.data = pool;
    uv_timer_init(tjs_get_loop(ctx), &pool->timer);

	// initialize prep
	pool->prep = NULL;
    
    // Parse options
    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue max_conn = JS_GetPropertyStr(ctx, argv[0], "maxConnections");
        if (JS_IsNumber(max_conn)) {
            int32_t max;
            JS_ToInt32(ctx, &max, max_conn);
            curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long)max);
        }
        JS_FreeValue(ctx, max_conn);
        
        JSValue max_host = JS_GetPropertyStr(ctx, argv[0], "maxConnectionsPerHost");
        if (JS_IsNumber(max_host)) {
            int32_t max;
            JS_ToInt32(ctx, &max, max_host);
            curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, (long)max);
        }
        JS_FreeValue(ctx, max_host);
        
        JSValue pipelining = JS_GetPropertyStr(ctx, argv[0], "pipelining");
        if (JS_IsBool(pipelining) && JS_ToBool(ctx, pipelining)) {
            curl_multi_setopt(pool->multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
        }
        JS_FreeValue(ctx, pipelining);
    }
    
    JS_SetOpaque(obj, pool);
    return obj;
}

#pragma endregion

#pragma region ConnPool Methods

static JSValue tjs_connpool_get_active_count(JSContext *ctx, JSValueConst this_val,
                                            int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) {
        return JS_EXCEPTION;
    }
    
    int running_handles;
    MSACT(pool, pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    
    return JS_NewInt32(ctx, running_handles);
}

static JSValue tjs_connpool_close(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) {
        return JS_EXCEPTION;
    }
    
    if (pool->multi_handle) {
        curl_multi_cleanup(pool->multi_handle);
        pool->multi_handle = NULL;
    }
    
    uv_timer_stop(&pool->timer);
    
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_process(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) {
        return JS_EXCEPTION;
    }
    
    int running_handles;
    CURLMcode ret = curl_multi_socket_action(pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    check_multi_info(pool);

	if (ret != CURLM_OK) {
		const char* err = curl_multi_strerror(ret);
		return JS_ThrowPlainError(ctx, "perform failed: %s", err);
	}
    
    return JS_UNDEFINED;
}

#pragma endregion

#pragma region CURL Constructor

static JSValue tjs_curl_constructor(JSContext *ctx, JSValueConst new_target,
                                    int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_curl_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

	if (argc == 0 || !JS_GetOpaque(argv[0], tjs_connpool_class_id)) {
		return JS_ThrowTypeError(ctx, "Expect first object as ConnPool");
	}
    
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
    
    // Initialize buffers
    dbuf_init(&curl->response_body);
    dbuf_init(&curl->response_headers);
    
    // Set default options
    curl_easy_setopt(curl->handle, CURLOPT_PRIVATE, curl);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl->handle, CURLOPT_HEADERDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl->handle, CURLOPT_XFERINFODATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl->handle, CURLOPT_ERRORBUFFER, curl->error_buffer);
    
    // Default settings
    curl->follow_redirects = true;
    curl->timeout_ms = 0;
    curl->sync_mode = false;
    curl->on_progress = JS_UNDEFINED;
    curl->on_header = JS_UNDEFINED;
    curl->promise = JS_UNDEFINED;
    curl->resolve = JS_UNDEFINED;
    curl->reject = JS_UNDEFINED;
	curl->on_data = JS_UNDEFINED;
	curl->stream_mode = false;
    
    // Get pool
	curl->pool_obj = JS_DupValue(ctx, argv[0]);
    curl->pool = JS_GetOpaque2(ctx, argv[0], tjs_connpool_class_id);
    
    JS_SetOpaque(obj, curl);
    return obj;
}

#pragma endregion

#pragma region CURL Configuration Methods

static JSValue tjs_curl_set_url(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *url = JS_ToCString(ctx, argv[0]);
    if (!url) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_URL, url);
    JS_FreeCString(ctx, url);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_method(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *method = JS_ToCString(ctx, argv[0]);
    if (!method) return JS_EXCEPTION;
    
    if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTPGET, 1L);
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_POST, 1L);
    } else if (strcmp(method, "PUT") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 1L);
    } else if (strcmp(method, "HEAD") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_NOBODY, 1L);
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else {
        curl_easy_setopt(curl->handle, CURLOPT_CUSTOMREQUEST, method);
    }
    
    JS_FreeCString(ctx, method);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_headers(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
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
                    char *header = js_malloc(ctx, strlen(key_str) + strlen(val_str) + 3);
                    sprintf(header, "%s: %s", key_str, val_str);
                    curl->request_headers = curl_slist_append(curl->request_headers, header);
                    js_free(ctx, header);
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

static JSValue tjs_curl_set_body(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    if (JS_IsString(argv[0])) {
        size_t len;
        const char *data = JS_ToCStringLen(ctx, &len, argv[0]);
        if (!data) return JS_EXCEPTION;
        
        char *copy = js_malloc(ctx, len);
        memcpy(copy, data, len);
        
        curl_easy_setopt(curl->handle, CURLOPT_POSTFIELDS, copy);
        curl_easy_setopt(curl->handle, CURLOPT_POSTFIELDSIZE, (long)len);
        
        JS_FreeCString(ctx, data);
    }
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_timeout(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    int32_t timeout;
    if (JS_ToInt32(ctx, &timeout, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    curl->timeout_ms = timeout;
    curl_easy_setopt(curl->handle, CURLOPT_TIMEOUT_MS, (long)timeout);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_follow_redirects(JSContext *ctx, JSValueConst this_val,
                                             int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    curl->follow_redirects = JS_ToBool(ctx, argv[0]);
    curl_easy_setopt(curl->handle, CURLOPT_FOLLOWLOCATION, curl->follow_redirects ? 1L : 0L);
    
    return JS_DupValue(ctx, this_val);
}

#pragma endregion

#pragma region CURL Callback Setters

static JSValue tjs_curl_on_progress(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    if (JS_IsFunction(ctx, argv[0])) {
        JS_FreeValue(ctx, curl->on_progress);
        curl->on_progress = JS_DupValue(ctx, argv[0]);
    }
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_on_header(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    if (JS_IsFunction(ctx, argv[0])) {
        JS_FreeValue(ctx, curl->on_header);
        curl->on_header = JS_DupValue(ctx, argv[0]);
    }
    
    return JS_DupValue(ctx, this_val);
}

#pragma endregion

#pragma region CURL Execution - Async Mode

static JSValue tjs_curl_perform(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    // Check if already executing
    if (!JS_IsUndefined(curl->promise)) {
        return JS_ThrowTypeError(ctx, "Request already in progress");
    }
    
    // Create promise
    JSValue promise, callbacks[2];
    promise = JS_NewPromiseCapability(ctx, callbacks);
    if (JS_IsException(promise)) {
        return JS_EXCEPTION;
    }
    
    curl->promise = JS_DupValue(ctx, promise);
    curl->resolve = callbacks[0];
    curl->reject = callbacks[1];
    curl->completed = false;
    
    // Clear previous response data
    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);
    dbuf_init(&curl->response_body);
    dbuf_init(&curl->response_headers);
    
    // Add to pool
    curl_multi_add_handle(curl->pool->multi_handle, curl->handle);
    int running;
    MSACT(curl->pool, curl->pool->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info(curl->pool);

	// Handle sync error
    kick_prep_once(curl->pool);
    
    return promise;
}

#pragma endregion

#pragma region CURL Execution - Sync Mode

static JSValue tjs_curl_perform_sync(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    // Clear previous response data
    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);
    dbuf_init(&curl->response_body);
    dbuf_init(&curl->response_headers);
    
    curl->sync_mode = true;
    
    // Perform synchronous request
    CURLcode res = curl_easy_perform(curl->handle);
    
    if (res == CURLE_OK) {
        // Get response info
        curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE, &curl->response_code);
        
        char *url = NULL;
        curl_easy_getinfo(curl->handle, CURLINFO_EFFECTIVE_URL, &url);
        if (url && !curl->effective_url) {
            curl->effective_url = js_strdup(ctx, url);
        }
        
        // Build response object
        JSValue response = JS_NewObject(ctx);
        
        if (curl->response_body.size > 0) {
            JS_DefinePropertyValueStr(ctx, response, "body",
                JS_NewStringLen(ctx, (char *)curl->response_body.buf, curl->response_body.size),
                JS_PROP_C_W_E);
        } else {
            JS_DefinePropertyValueStr(ctx, response, "body",
                JS_NewString(ctx, ""), JS_PROP_C_W_E);
        }
        
        if (curl->response_headers.size > 0) {
            JS_DefinePropertyValueStr(ctx, response, "headers",
                JS_NewStringLen(ctx, (char *)curl->response_headers.buf, curl->response_headers.size),
                JS_PROP_C_W_E);
        } else {
            JS_DefinePropertyValueStr(ctx, response, "headers",
                JS_NewString(ctx, ""), JS_PROP_C_W_E);
        }
        
        JS_DefinePropertyValueStr(ctx, response, "status",
            JS_NewInt32(ctx, curl->response_code), JS_PROP_C_W_E);
        
        if (curl->effective_url) {
            JS_DefinePropertyValueStr(ctx, response, "url",
                JS_NewString(ctx, curl->effective_url), JS_PROP_C_W_E);
        }
        
        return response;
    } else {
        JSValue error = JS_NewError(ctx);
        
        const char *error_msg = curl->error_buffer[0] ? 
            curl->error_buffer : curl_easy_strerror(res);
        
        JS_DefinePropertyValueStr(ctx, error, "message",
            JS_NewString(ctx, error_msg), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
        
        JS_DefinePropertyValueStr(ctx, error, "code",
            JS_NewInt32(ctx, res), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
        
        return JS_Throw(ctx, error);
    }
}

#pragma endregion

#pragma region CURL Utility Methods

static JSValue tjs_curl_reset(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    curl_easy_reset(curl->handle);
    
    // Reset callbacks
    curl_easy_setopt(curl->handle, CURLOPT_PRIVATE, curl);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl->handle, CURLOPT_HEADERDATA, curl);
    curl_easy_setopt(curl->handle, CURLOPT_ERRORBUFFER, curl->error_buffer);
    
    // Clear buffers
    dbuf_free(&curl->response_body);
    dbuf_free(&curl->response_headers);
    dbuf_init(&curl->response_body);
    dbuf_init(&curl->response_headers);
    
    if (curl->request_headers) {
        curl_slist_free_all(curl->request_headers);
        curl->request_headers = NULL;
    }

	// Clear promises
	if (!JS_IsUndefined(curl->promise)){
		JS_FreeValue(ctx, curl->promise);
		JS_FreeValue(ctx, curl->resolve);
		JS_FreeValue(ctx, curl->reject);
		curl->promise = curl->resolve = curl->reject
			= JS_UNDEFINED;
	}
    
    return JS_UNDEFINED;
}

static JSValue tjs_curl_get_info(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    JSValue info = JS_NewObject(ctx);
    
    long response_code;
    curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE, &response_code);
    JS_DefinePropertyValueStr(ctx, info, "status",
        JS_NewInt32(ctx, response_code), JS_PROP_C_W_E);
    
    char *url;
    curl_easy_getinfo(curl->handle, CURLINFO_EFFECTIVE_URL, &url);
    if (url) {
        JS_DefinePropertyValueStr(ctx, info, "url",
            JS_NewString(ctx, url), JS_PROP_C_W_E);
    }
    
    double total_time;
    curl_easy_getinfo(curl->handle, CURLINFO_TOTAL_TIME, &total_time);
    JS_DefinePropertyValueStr(ctx, info, "totalTime",
        JS_NewFloat64(ctx, total_time), JS_PROP_C_W_E);
    
    curl_off_t download_size;
    curl_easy_getinfo(curl->handle, CURLINFO_SIZE_DOWNLOAD_T, &download_size);
    JS_DefinePropertyValueStr(ctx, info, "downloadSize",
        JS_NewInt64(ctx, download_size), JS_PROP_C_W_E);
    
    curl_off_t upload_size;
    curl_easy_getinfo(curl->handle, CURLINFO_SIZE_UPLOAD_T, &upload_size);
    JS_DefinePropertyValueStr(ctx, info, "uploadSize",
        JS_NewInt64(ctx, upload_size), JS_PROP_C_W_E);
    
    return info;
}

#pragma endregion

#pragma region Advanced CURL Options

static JSValue tjs_curl_set_ssl_verify(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    bool verify_peer = JS_ToBool(ctx, argv[0]);
    bool verify_host = argc > 1 ? JS_ToBool(ctx, argv[1]) : verify_peer;
    
    curl_easy_setopt(curl->handle, CURLOPT_SSL_VERIFYPEER, verify_peer ? 1L : 0L);
    curl_easy_setopt(curl->handle, CURLOPT_SSL_VERIFYHOST, verify_host ? 2L : 0L);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_ca_bundle(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_CAINFO, path);
    JS_FreeCString(ctx, path);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_proxy(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *proxy = JS_ToCString(ctx, argv[0]);
    if (!proxy) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_PROXY, proxy);
    JS_FreeCString(ctx, proxy);
    
    // Optional proxy type
    if (argc > 1 && JS_IsString(argv[1])) {
        const char *type = JS_ToCString(ctx, argv[1]);
        if (type) {
            if (strcmp(type, "http") == 0) {
                curl_easy_setopt(curl->handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            } else if (strcmp(type, "https") == 0) {
                curl_easy_setopt(curl->handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTPS);
            } else if (strcmp(type, "socks4") == 0) {
                curl_easy_setopt(curl->handle, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4);
            } else if (strcmp(type, "socks5") == 0) {
                curl_easy_setopt(curl->handle, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
            }
            JS_FreeCString(ctx, type);
        }
    }
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_user_agent(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *ua = JS_ToCString(ctx, argv[0]);
    if (!ua) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_USERAGENT, ua);
    JS_FreeCString(ctx, ua);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_cookie(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *cookie = JS_ToCString(ctx, argv[0]);
    if (!cookie) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_COOKIE, cookie);
    JS_FreeCString(ctx, cookie);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_cookie_file(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_COOKIEFILE, path);
    JS_FreeCString(ctx, path);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_referer(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *referer = JS_ToCString(ctx, argv[0]);
    if (!referer) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_REFERER, referer);
    JS_FreeCString(ctx, referer);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_max_redirects(JSContext *ctx, JSValueConst this_val,
                                          int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    int32_t max;
    if (JS_ToInt32(ctx, &max, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    curl_easy_setopt(curl->handle, CURLOPT_MAXREDIRS, (long)max);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_connect_timeout(JSContext *ctx, JSValueConst this_val,
                                            int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    int32_t timeout;
    if (JS_ToInt32(ctx, &timeout, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    curl_easy_setopt(curl->handle, CURLOPT_CONNECTTIMEOUT_MS, (long)timeout);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_verbose(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    bool verbose = JS_ToBool(ctx, argv[0]);
    curl_easy_setopt(curl->handle, CURLOPT_VERBOSE, verbose ? 1L : 0L);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_http_version(JSContext *ctx, JSValueConst this_val,
                                         int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *version = JS_ToCString(ctx, argv[0]);
    if (!version) return JS_EXCEPTION;
    
    if (strcmp(version, "1.0") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    } else if (strcmp(version, "1.1") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    } else if (strcmp(version, "2") == 0 || strcmp(version, "2.0") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    } else if (strcmp(version, "2TLS") == 0) {
        curl_easy_setopt(curl->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    } else if (strcmp(version, "3") == 0) {
#ifdef CURL_HTTP_VERSION_3
        curl_easy_setopt(curl->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
#endif
    }
    
    JS_FreeCString(ctx, version);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_range(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    int64_t start, end = -1;
    if (JS_ToInt64(ctx, &start, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (argc > 1 && !JS_IsUndefined(argv[1])) {
        JS_ToInt64(ctx, &end, argv[1]);
    }
    
    char range[64];
    if (end >= 0) {
        snprintf(range, sizeof(range), "%lld-%lld", (long long)start, (long long)end);
    } else {
        snprintf(range, sizeof(range), "%lld-", (long long)start);
    }
    
    curl_easy_setopt(curl->handle, CURLOPT_RANGE, range);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_dns_servers(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *servers = JS_ToCString(ctx, argv[0]);
    if (!servers) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_DNS_SERVERS, servers);
    JS_FreeCString(ctx, servers);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_interface(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    const char *interface = JS_ToCString(ctx, argv[0]);
    if (!interface) return JS_EXCEPTION;
    
    curl_easy_setopt(curl->handle, CURLOPT_INTERFACE, interface);
    JS_FreeCString(ctx, interface);
    
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_set_stream_mode(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    curl->stream_mode = JS_ToBool(ctx, argv[0]);
    return JS_DupValue(ctx, this_val);
}

static JSValue tjs_curl_on_data(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    TJSCURL *curl = JS_GetOpaque2(ctx, this_val, tjs_curl_class_id);
    if (!curl) return JS_EXCEPTION;
    
    if (JS_IsFunction(ctx, argv[0])) {
        JS_FreeValue(ctx, curl->on_data);
        curl->on_data = JS_DupValue(ctx, argv[0]);
        curl->stream_mode = true;
    }
    
    return JS_DupValue(ctx, this_val);
}
#pragma endregion

#pragma region Advanced ConnPool Options

static JSValue tjs_connpool_set_max_pipeline_length(JSContext *ctx, JSValueConst this_val,
                                                    int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    
    int32_t length;
    if (JS_ToInt32(ctx, &length, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_PIPELINE_LENGTH, (long)length);
    
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_set_max_concurrent_streams(JSContext *ctx, JSValueConst this_val,
                                                       int argc, JSValueConst *argv) {
    TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;
    
    int32_t streams;
    if (JS_ToInt32(ctx, &streams, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef CURLMOPT_MAX_CONCURRENT_STREAMS
    curl_multi_setopt(pool->multi_handle, CURLMOPT_MAX_CONCURRENT_STREAMS, (long)streams);
#endif
    
    return JS_UNDEFINED;
}

static JSValue tjs_connpool_get_onerror(JSContext* ctx, JSValue this_val) {
	TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;

	return JS_DupValue(ctx, pool->err_cb);
}

static JSValue tjs_connpool_set_onerror(JSContext* ctx, JSValue this_val, JSValueConst value) {
	TJSConnPool *pool = JS_GetOpaque2(ctx, this_val, tjs_connpool_class_id);
    if (!pool) return JS_EXCEPTION;

	JS_FreeValue(ctx, pool->err_cb);
	pool->err_cb = JS_DupValue(ctx, value);
	return JS_UNDEFINED;
} 

#pragma endregion

#pragma region Proto Functions

static const JSCFunctionListEntry tjs_curl_proto_funcs[] = {
	TJS_CFUNC_DEF("setUrl", 1, tjs_curl_set_url),
    TJS_CFUNC_DEF("setMethod", 1, tjs_curl_set_method),
    TJS_CFUNC_DEF("setHeaders", 1, tjs_curl_set_headers),
    TJS_CFUNC_DEF("setBody", 1, tjs_curl_set_body),
    TJS_CFUNC_DEF("setTimeout", 1, tjs_curl_set_timeout),
    TJS_CFUNC_DEF("setFollowRedirects", 1, tjs_curl_set_follow_redirects),
    
    // Callback setters
    TJS_CFUNC_DEF("onProgress", 1, tjs_curl_on_progress),
    TJS_CFUNC_DEF("onHeader", 1, tjs_curl_on_header),
    
    // Execution methods
    TJS_CFUNC_DEF("perform", 0, tjs_curl_perform),
    TJS_CFUNC_DEF("performSync", 0, tjs_curl_perform_sync),
    
    // Utility methods
    TJS_CFUNC_DEF("reset", 0, tjs_curl_reset),
    TJS_CFUNC_DEF("getInfo", 0, tjs_curl_get_info),

    // SSL/TLS options
    TJS_CFUNC_DEF("setSSLVerify", 1, tjs_curl_set_ssl_verify),
    TJS_CFUNC_DEF("setCABundle", 1, tjs_curl_set_ca_bundle),
    
    // Network options
    TJS_CFUNC_DEF("setProxy", 1, tjs_curl_set_proxy),
    TJS_CFUNC_DEF("setInterface", 1, tjs_curl_set_interface),
    TJS_CFUNC_DEF("setDNSServers", 1, tjs_curl_set_dns_servers),
    
    // HTTP options
    TJS_CFUNC_DEF("setUserAgent", 1, tjs_curl_set_user_agent),
    TJS_CFUNC_DEF("setCookie", 1, tjs_curl_set_cookie),
    TJS_CFUNC_DEF("setCookieFile", 1, tjs_curl_set_cookie_file),
    TJS_CFUNC_DEF("setReferer", 1, tjs_curl_set_referer),
    TJS_CFUNC_DEF("setMaxRedirects", 1, tjs_curl_set_max_redirects),
    TJS_CFUNC_DEF("setHTTPVersion", 1, tjs_curl_set_http_version),
    TJS_CFUNC_DEF("setRange", 1, tjs_curl_set_range),
    
    // Timeout options
    TJS_CFUNC_DEF("setConnectTimeout", 1, tjs_curl_set_connect_timeout),
    
    // Debug options
    TJS_CFUNC_DEF("setVerbose", 1, tjs_curl_set_verbose),

	// streaming support
	TJS_CFUNC_DEF("setStreamMode", 1, tjs_curl_set_stream_mode),
    TJS_CFUNC_DEF("onData", 1, tjs_curl_on_data),
};

static const JSCFunctionListEntry tjs_connpool_proto_funcs[] = {
	TJS_CFUNC_DEF("getActiveCount", 0, tjs_connpool_get_active_count),
    TJS_CFUNC_DEF("close", 0, tjs_connpool_close),
    TJS_CFUNC_DEF("process", 0, tjs_connpool_process),

    TJS_CFUNC_DEF("setMaxPipelineLength", 1, tjs_connpool_set_max_pipeline_length),
    TJS_CFUNC_DEF("setMaxConcurrentStreams", 1, tjs_connpool_set_max_concurrent_streams),
	TJS_CGETSET_DEF("onerror", tjs_connpool_get_onerror, tjs_connpool_set_onerror)
};

#pragma endregion

#pragma region Module Initialization

void tjs__mod_curl_init(JSContext *ctx, JSValue ns) {
    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Register ConnPool class
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_connpool_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_connpool_class_id, &tjs_connpool_class);
    JSValue connpool_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, connpool_proto, tjs_connpool_proto_funcs,
                              countof(tjs_connpool_proto_funcs));
    JS_SetClassProto(ctx, tjs_connpool_class_id, connpool_proto);
    
    JSValue connpool_ctor = JS_NewCFunction2(ctx, tjs_connpool_constructor, "ConnPool", 1,
                                            JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "ConnPool", connpool_ctor, JS_PROP_C_W_E);
    
    // Register CURL class
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_curl_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_curl_class_id, &tjs_curl_class);
    JSValue curl_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, curl_proto, tjs_curl_proto_funcs,
                              countof(tjs_curl_proto_funcs));
    JS_SetClassProto(ctx, tjs_curl_class_id, curl_proto);
    
    JSValue curl_ctor = JS_NewCFunction2(ctx, tjs_curl_constructor, "CURL", 1,
                                        JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "CURL", curl_ctor, JS_PROP_C_W_E);
    
    // Add version info
    JSValue version_info = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, version_info, "curl",
        JS_NewString(ctx, curl_version()), JS_PROP_C_W_E);
    
    curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
    if (ver) {
        JS_DefinePropertyValueStr(ctx, version_info, "protocols",
            JS_NewString(ctx, ver->protocols ? ver->protocols[0] : ""), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, version_info, "features",
            JS_NewInt64(ctx, ver->features), JS_PROP_C_W_E);
    }
    
    JS_DefinePropertyValueStr(ctx, ns, "version", version_info, JS_PROP_C_W_E);
}

void tjs_mod_curl_cleanup(JSContext *ctx) {
    curl_global_cleanup();
}

#pragma endregion