/*
 * circu.js HTTP Parser Module
 * Based on llhttp and integrated with libuv
 */

#include "private.h"
#include "tjs.h"
#include <llhttp.h>

#define TJS_HTTP_PARSER_FLAG_NONE           0
#define TJS_HTTP_PARSER_FLAG_UPGRADE        (1 << 0)
#define TJS_HTTP_PARSER_FLAG_COMPLETE       (1 << 1)
#define TJS_HTTP_PARSER_FLAG_HEADERS_DONE   (1 << 2)

typedef struct {
    JSContext *ctx;
    JSValue obj;
    JSValue on_message_begin;
    JSValue on_url;
    JSValue on_status;
    JSValue on_header_field;
    JSValue on_header_value;
    JSValue on_headers_complete;
    JSValue on_body;
    JSValue on_message_complete;
    JSValue on_chunk_header;
    JSValue on_chunk_complete;
    
    llhttp_t parser;
    llhttp_settings_t settings;
    
    uv_pipe_t *pipe;
    uint32_t flags;
    
    // Header parsing state
    JSValue current_headers;
    DynBuf header_field;
    DynBuf header_value;
    bool in_header_field;
    
    // URL components (parsed by llhttp)
    DynBuf url_buf;
    
    // Body data pipe (留空给你实现)
    JSValue body_pipe;
} TJSHttpParser;

typedef struct {
    JSContext *ctx;
    JSValue method;
    JSValue url;
    JSValue version_major;
    JSValue version_minor;
    JSValue headers;
    JSValue body_pipe;
    bool upgrade;
    bool should_keep_alive;
} TJSHttpRequest;

static JSClassID tjs_http_parser_class_id;
static JSClassID tjs_http_request_class_id;

static void tjs_http_parser_finalizer(JSRuntime *rt, JSValue val) {
    TJSHttpParser *parser = JS_GetOpaque(val, tjs_http_parser_class_id);
    if (parser) {
        JS_FreeValueRT(rt, parser->on_message_begin);
        JS_FreeValueRT(rt, parser->on_url);
        JS_FreeValueRT(rt, parser->on_status);
        JS_FreeValueRT(rt, parser->on_header_field);
        JS_FreeValueRT(rt, parser->on_header_value);
        JS_FreeValueRT(rt, parser->on_headers_complete);
        JS_FreeValueRT(rt, parser->on_body);
        JS_FreeValueRT(rt, parser->on_message_complete);
        JS_FreeValueRT(rt, parser->on_chunk_header);
        JS_FreeValueRT(rt, parser->on_chunk_complete);
        JS_FreeValueRT(rt, parser->current_headers);
        JS_FreeValueRT(rt, parser->body_pipe);
        
        dbuf_free(&parser->header_field);
        dbuf_free(&parser->header_value);
        dbuf_free(&parser->url_buf);
        
        js_free_rt(rt, parser);
    }
}

static JSClassDef tjs_http_parser_class = {
    "HttpParser",
    .finalizer = tjs_http_parser_finalizer,
};

static void tjs_http_request_finalizer(JSRuntime *rt, JSValue val) {
    TJSHttpRequest *req = JS_GetOpaque(val, tjs_http_request_class_id);
    if (req) {
        JS_FreeValueRT(rt, req->method);
        JS_FreeValueRT(rt, req->url);
        JS_FreeValueRT(rt, req->version_major);
        JS_FreeValueRT(rt, req->version_minor);
        JS_FreeValueRT(rt, req->headers);
        JS_FreeValueRT(rt, req->body_pipe);
        js_free_rt(rt, req);
    }
}

static JSClassDef tjs_http_request_class = {
    "HttpRequest",
    .finalizer = tjs_http_request_finalizer,
};

// llhttp callbacks
static int on_message_begin_cb(llhttp_t *parser) {
    TJSHttpParser *p = parser->data;
    if (!JS_IsUndefined(p->on_message_begin)) {
        JSValue ret = JS_Call(p->ctx, p->on_message_begin, p->obj, 0, NULL);
        JS_FreeValue(p->ctx, ret);
    }
    
    // Reset state
    p->flags = TJS_HTTP_PARSER_FLAG_NONE;
    p->current_headers = JS_NewObject(p->ctx);
    dbuf_init(&p->header_field);
    dbuf_init(&p->header_value);
    dbuf_init(&p->url_buf);
    p->in_header_field = false;
    
    return HPE_OK;
}

static int on_url_cb(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpParser *p = parser->data;
    
    // Accumulate URL data
    dbuf_put(&p->url_buf, (const uint8_t *)at, length);
    
    if (!JS_IsUndefined(p->on_url)) {
        JSValue url = JS_NewStringLen(p->ctx, at, length);
        JSValue argv[] = { url };
        JSValue ret = JS_Call(p->ctx, p->on_url, p->obj, 1, argv);
        JS_FreeValue(p->ctx, url);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static int on_status_cb(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpParser *p = parser->data;
    
    if (!JS_IsUndefined(p->on_status)) {
        JSValue status = JS_NewStringLen(p->ctx, at, length);
        JSValue argv[] = { status };
        JSValue ret = JS_Call(p->ctx, p->on_status, p->obj, 1, argv);
        JS_FreeValue(p->ctx, status);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static void flush_header(TJSHttpParser *p) {
    if (p->header_field.size > 0 && p->header_value.size > 0) {
        JSValue field = JS_NewStringLen(p->ctx, (char *)p->header_field.buf, p->header_field.size);
        JSValue value = JS_NewStringLen(p->ctx, (char *)p->header_value.buf, p->header_value.size);
        
        // Check if header already exists (for multi-value headers)
        JSValue existing = JS_GetProperty(p->ctx, p->current_headers, JS_ValueToAtom(p->ctx, field));
        if (!JS_IsUndefined(existing)) {
            // Append with comma separator (HTTP spec)
            const char *old_val = JS_ToCString(p->ctx, existing);
            const char *new_val = JS_ToCString(p->ctx, value);
            char *combined = js_malloc(p->ctx, strlen(old_val) + strlen(new_val) + 3);
            sprintf(combined, "%s, %s", old_val, new_val);
            JS_FreeValue(p->ctx, value);
            value = JS_NewString(p->ctx, combined);
            js_free(p->ctx, combined);
            JS_FreeCString(p->ctx, old_val);
            JS_FreeCString(p->ctx, new_val);
        }
        JS_FreeValue(p->ctx, existing);
        
        JS_SetProperty(p->ctx, p->current_headers, JS_ValueToAtom(p->ctx, field), value);
        JS_FreeValue(p->ctx, field);
        
        p->header_field.size = 0;
        p->header_value.size = 0;
    }
}

static int on_header_field_cb(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpParser *p = parser->data;
    
    // If we were in value, flush the previous header
    if (!p->in_header_field && p->header_field.size > 0) {
        flush_header(p);
    }
    
    p->in_header_field = true;
    dbuf_put(&p->header_field, (const uint8_t *)at, length);
    
    if (!JS_IsUndefined(p->on_header_field)) {
        JSValue field = JS_NewStringLen(p->ctx, at, length);
        JSValue argv[] = { field };
        JSValue ret = JS_Call(p->ctx, p->on_header_field, p->obj, 1, argv);
        JS_FreeValue(p->ctx, field);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static int on_header_value_cb(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpParser *p = parser->data;
    
    p->in_header_field = false;
    dbuf_put(&p->header_value, (const uint8_t *)at, length);
    
    if (!JS_IsUndefined(p->on_header_value)) {
        JSValue value = JS_NewStringLen(p->ctx, at, length);
        JSValue argv[] = { value };
        JSValue ret = JS_Call(p->ctx, p->on_header_value, p->obj, 1, argv);
        JS_FreeValue(p->ctx, value);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static int on_headers_complete_cb(llhttp_t *parser) {
    TJSHttpParser *p = parser->data;
    
    // Flush last header
    flush_header(p);
    
    p->flags |= TJS_HTTP_PARSER_FLAG_HEADERS_DONE;
    
    // Create Request object
    TJSHttpRequest *req = js_mallocz(p->ctx, sizeof(*req));
    req->ctx = p->ctx;
    
    // Get method
    const char *method_str = llhttp_method_name(llhttp_get_method(parser));
    req->method = JS_NewString(p->ctx, method_str);
    
    // Get URL (with full parsing)
    req->url = JS_NewStringLen(p->ctx, (char *)p->url_buf.buf, p->url_buf.size);
    
    // Get version
    req->version_major = JS_NewInt32(p->ctx, parser->http_major);
    req->version_minor = JS_NewInt32(p->ctx, parser->http_minor);
    
    // Transfer headers
    req->headers = p->current_headers;
    p->current_headers = JS_UNDEFINED;
    
    // Get connection info
    req->upgrade = llhttp_get_upgrade(parser);
    req->should_keep_alive = llhttp_should_keep_alive(parser);
    
    // Body pipe (留空 - 你来实现)
    // 这里应该创建一个 tjs pipe 对象
    // req->body_pipe = tjs_new_pipe(p->ctx);
    req->body_pipe = JS_UNDEFINED;  // Placeholder
    p->body_pipe = req->body_pipe;
    
    if (!JS_IsUndefined(p->on_headers_complete)) {
        JSValue req_obj = JS_NewObjectClass(p->ctx, tjs_http_request_class_id);
        JS_opaque(req_obj, req);
        
        // Set properties
        JS_DefinePropertyValueStr(p->ctx, req_obj, "method", JS_DupValue(p->ctx, req->method), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "url", JS_DupValue(p->ctx, req->url), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "versionMajor", JS_DupValue(p->ctx, req->version_major), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "versionMinor", JS_DupValue(p->ctx, req->version_minor), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "headers", JS_DupValue(p->ctx, req->headers), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "upgrade", JS_NewBool(p->ctx, req->upgrade), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "shouldKeepAlive", JS_NewBool(p->ctx, req->should_keep_alive), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(p->ctx, req_obj, "bodyPipe", JS_DupValue(p->ctx, req->body_pipe), JS_PROP_C_W_E);
        
        JSValue argv[] = { req_obj };
        JSValue ret = JS_Call(p->ctx, p->on_headers_complete, p->obj, 1, argv);
        JS_FreeValue(p->ctx, ret);
        JS_FreeValue(p->ctx, req_obj);
    }
    
    if (req->upgrade) {
        p->flags |= TJS_HTTP_PARSER_FLAG_UPGRADE;
        return HPE_PAUSED_UPGRADE;
    }
    
    return HPE_OK;
}

static int on_body_cb(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpParser *p = parser->data;
    
    // Write body data to pipe (留空 - 你来实现)
    // if (!JS_IsUndefined(p->body_pipe)) {
    //     tjs_pipe_write(p->ctx, p->body_pipe, at, length);
    // }
    
    if (!JS_IsUndefined(p->on_body)) {
        JSValue data = JS_NewArrayBufferCopy(p->ctx, (const uint8_t *)at, length);
        JSValue argv[] = { data };
        JSValue ret = JS_Call(p->ctx, p->on_body, p->obj, 1, argv);
        JS_FreeValue(p->ctx, data);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static int on_message_complete_cb(llhttp_t *parser) {
    TJSHttpParser *p = parser->data;
    
    p->flags |= TJS_HTTP_PARSER_FLAG_COMPLETE;
    
    // Close body pipe (留空 - 你来实现)
    // if (!JS_IsUndefined(p->body_pipe)) {
    //     tjs_pipe_close(p->ctx, p->body_pipe);
    // }
    
    if (!JS_IsUndefined(p->on_message_complete)) {
        JSValue ret = JS_Call(p->ctx, p->on_message_complete, p->obj, 0, NULL);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static int on_chunk_header_cb(llhttp_t *parser) {
    TJSHttpParser *p = parser->data;
    
    if (!JS_IsUndefined(p->on_chunk_header)) {
        JSValue ret = JS_Call(p->ctx, p->on_chunk_header, p->obj, 0, NULL);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

static int on_chunk_complete_cb(llhttp_t *parser) {
    TJSHttpParser *p = parser->data;
    
    if (!JS_IsUndefined(p->on_chunk_complete)) {
        JSValue ret = JS_Call(p->ctx, p->on_chunk_complete, p->obj, 0, NULL);
        JS_FreeValue(p->ctx, ret);
    }
    
    return HPE_OK;
}

// Constructor
static JSValue tjs_http_parser_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_http_parser_class_id);
    if (JS_IsException(obj))
        return obj;
    
    TJSHttpParser *parser = js_mallocz(ctx, sizeof(*parser));
    if (!parser) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    parser->ctx = ctx;
    parser->obj = JS_DupValue(ctx, obj);
    
    // Parse type argument (REQUEST or RESPONSE)
    llhttp_type_t type = HTTP_REQUEST;
    if (argc > 0) {
        int32_t t;
        if (JS_ToInt32(ctx, &t, argv[0]) == 0) {
            type = (t == 0) ? HTTP_REQUEST : HTTP_RESPONSE;
        }
    }
    
    // Initialize llhttp
    llhttp_settings_init(&parser->settings);
    parser->settings.on_message_begin = on_message_begin_cb;
    parser->settings.on_url = on_url_cb;
    parser->settings.on_status = on_status_cb;
    parser->settings.on_header_field = on_header_field_cb;
    parser->settings.on_header_value = on_header_value_cb;
    parser->settings.on_headers_complete = on_headers_complete_cb;
    parser->settings.on_body = on_body_cb;
    parser->settings.on_message_complete = on_message_complete_cb;
    parser->settings.on_chunk_header = on_chunk_header_cb;
    parser->settings.on_chunk_complete = on_chunk_complete_cb;
    
    llhttp_init(&parser->parser, type, &parser->settings);
    parser->parser.data = parser;
    
    // Initialize callbacks as undefined
    parser->on_message_begin = JS_UNDEFINED;
    parser->on_url = JS_UNDEFINED;
    parser->on_status = JS_UNDEFINED;
    parser->on_header_field = JS_UNDEFINED;
    parser->on_header_value = JS_UNDEFINED;
    parser->on_headers_complete = JS_UNDEFINED;
    parser->on_body = JS_UNDEFINED;
    parser->on_message_complete = JS_UNDEFINED;
    parser->on_chunk_header = JS_UNDEFINED;
    parser->on_chunk_complete = JS_UNDEFINED;
    parser->current_headers = JS_UNDEFINED;
    parser->body_pipe = JS_UNDEFINED;
    
    JS_opaque(obj, parser);
    return obj;
}

// execute(data: ArrayBuffer | Uint8Array): number
static JSValue tjs_http_parser_execute(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id);
    if (!parser)
        return JS_EXCEPTION;
    
    size_t size;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &size, argv[0]);
    if (!buf) {
        // Try Uint8Array
        JSValue buffer = JS_GetPropertyStr(ctx, argv[0], "buffer");
        if (JS_IsException(buffer))
            return JS_EXCEPTION;
        buf = JS_GetArrayBuffer(ctx, &size, buffer);
        JS_FreeValue(ctx, buffer);
        if (!buf)
            return JS_ThrowTypeError(ctx, "expected ArrayBuffer or Uint8Array");
    }
    
    enum llhttp_errno err = llhttp_execute(&parser->parser, (const char *)buf, size);
    
    if (err != HPE_OK && err != HPE_PAUSED_UPGRADE) {
        return JS_ThrowInternalError(ctx, "HTTP parser error: %s (%s)", 
                                     llhttp_errno_name(err),
                                     llhttp_get_error_reason(&parser->parser));
    }
    
    return JS_NewInt32(ctx, llhttp_get_errno(&parser->parser));
}

// finish(): void
static JSValue tjs_http_parser_finish(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id);
    if (!parser)
        return JS_EXCEPTION;
    
    enum llhttp_errno err = llhttp_finish(&parser->parser);
    
    if (err != HPE_OK) {
        return JS_ThrowInternalError(ctx, "HTTP parser finish error: %s", llhttp_errno_name(err));
    }
    
    return JS_UNDEFINED;
}

// reset(): void
static JSValue tjs_http_parser_reset(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id);
    if (!parser)
        return JS_EXCEPTION;
    
    llhttp_reset(&parser->parser);
    parser->flags = TJS_HTTP_PARSER_FLAG_NONE;
    
    return JS_UNDEFINED;
}

// pause(): void
static JSValue tjs_http_parser_pause(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id);
    if (!parser)
        return JS_EXCEPTION;
    
    llhttp_pause(&parser->parser);
    return JS_UNDEFINED;
}

// resume(): void
static JSValue tjs_http_parser_resume(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id);
    if (!parser)
        return JS_EXCEPTION;
    
    llhttp_resume(&parser->parser);
    return JS_UNDEFINED;
}

// Getters
#define TJS_HTTP_PARSER_GETTER(name, func) \
    static JSValue tjs_http_parser_get_##name(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) { \
        TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id); \
        if (!parser) return JS_EXCEPTION; \
        return func(ctx, &parser->parser); \
    }

static JSValue get_http_major(JSContext *ctx, llhttp_t *p) { return JS_NewInt32(ctx, p->http_major); }
static JSValue get_http_minor(JSContext *ctx, llhttp_t *p) { return JS_NewInt32(ctx, p->http_minor); }
static JSValue get_status_code(JSContext *ctx, llhttp_t *p) { return JS_NewInt32(ctx, p->status_code); }
static JSValue get_method(JSContext *ctx, llhttp_t *p) { return JS_NewString(ctx, llhttp_method_name(llhttp_get_method(p))); }
static JSValue get_upgrade(JSContext *ctx, llhttp_t *p) { return JS_NewBool(ctx, llhttp_get_upgrade(p)); }
static JSValue get_should_keep_alive(JSContext *ctx, llhttp_t *p) { return JS_NewBool(ctx, llhttp_should_keep_alive(p)); }
static JSValue get_content_length(JSContext *ctx, llhttp_t *p) { return JS_NewInt64(ctx, p->content_length); }

TJS_HTTP_PARSER_GETTER(http_major, get_http_major)
TJS_HTTP_PARSER_GETTER(http_minor, get_http_minor)
TJS_HTTP_PARSER_GETTER(status_code, get_status_code)
TJS_HTTP_PARSER_GETTER(method, get_method)
TJS_HTTP_PARSER_GETTER(upgrade, get_upgrade)
TJS_HTTP_PARSER_GETTER(should_keep_alive, get_should_keep_alive)
TJS_HTTP_PARSER_GETTER(content_length, get_content_length)

// Callback setters
#define TJS_HTTP_PARSER_CALLBACK(name) \
    static JSValue tjs_http_parser_set_##name(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) { \
        TJSHttpParser *parser = JS_GetOpaque2(ctx, this_val, tjs_http_parser_class_id); \
        if (!parser) return JS_EXCEPTION; \
        if (!JS_IsFunction(ctx, argv[0]) && !JS_IsUndefined(argv[0])) \
            return JS_ThrowTypeError(ctx, "callback must be a function"); \
        JS_FreeValue(ctx, parser->name); \
        parser->name = JS_DupValue(ctx, argv[0]); \
        return JS_UNDEFINED; \
    }

TJS_HTTP_PARSER_CALLBACK(on_message_begin)
TJS_HTTP_PARSER_CALLBACK(on_url)
TJS_HTTP_PARSER_CALLBACK(on_status)
TJS_HTTP_PARSER_CALLBACK(on_header_field)
TJS_HTTP_PARSER_CALLBACK(on_header_value)
TJS_HTTP_PARSER_CALLBACK(on_headers_complete)
TJS_HTTP_PARSER_CALLBACK(on_body)
TJS_HTTP_PARSER_CALLBACK(on_message_complete)
TJS_HTTP_PARSER_CALLBACK(on_chunk_header)
TJS_HTTP_PARSER_CALLBACK(on_chunk_complete)

static const JSCFunctionListEntry tjs_http_parser_proto_funcs[] = {
    TJS_CFUNC_DEF("execute", 1, tjs_http_parser_execute),
    TJS_CFUNC_DEF("finish", 0, tjs_http_parser_finish),
    TJS_CFUNC_DEF("reset", 0, tjs_http_parser_reset),
    TJS_CFUNC_DEF("pause", 0, tjs_http_parser_pause),
    TJS_CFUNC_DEF("resume", 0, tjs_http_parser_resume),
    TJS_CFUNC_DEF("onMessageBegin", 1, tjs_http_parser_set_on_message_begin),
    TJS_CFUNC_DEF("onUrl", 1, tjs_http_parser_set_on_url),
    TJS_CFUNC_DEF("onStatus", 1, tjs_http_parser_set_on_status),
    TJS_CFUNC_DEF("onHeaderField", 1, tjs_http_parser_set_on_header_field),
    TJS_CFUNC_DEF("onHeaderValue", 1, tjs_http_parser_set_on_header_value),
    TJS_CFUNC_DEF("onHeadersComplete", 1, tjs_http_parser_set_on_headers_complete),
    TJS_CFUNC_DEF("onBody", 1, tjs_http_parser_set_on_body),
    TJS_CFUNC_DEF("onMessageComplete", 1, tjs_http_parser_set_on_message_complete),
    TJS_CFUNC_DEF("onChunkHeader", 1, tjs_http_parser_set_on_chunk_header),
    TJS_CFUNC_DEF("onChunkComplete", 1, tjs_http_parser_set_on_chunk_complete),
    TJS_CGETSET_DEF("httpMajor", tjs_http_parser_get_http_major, NULL),
    TJS_CGETSET_DEF("httpMinor", tjs_http_parser_get_http_minor, NULL),
    TJS_CGETSET_DEF("statusCode", tjs_http_parser_get_status_code, NULL),
    TJS_CGETSET_DEF("method", tjs_http_parser_get_method, NULL),
    TJS_CGETSET_DEF("upgrade", tjs_http_parser_get_upgrade, NULL),
    TJS_CGETSET_DEF("shouldKeepAlive", tjs_http_parser_get_should_keep_alive, NULL),
    TJS_CGETSET_DEF("contentLength", tjs_http_parser_get_content_length, NULL),
};

static const JSCFunctionListEntry tjs_http_parser_class_funcs[] = {
    JS_PROP_INT32_DEF("REQUEST", HTTP_REQUEST, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RESPONSE", HTTP_RESPONSE, JS_PROP_ENUMERABLE),
};

void tjs_mod_http_parser_init(JSContext *ctx, JSValue ns) {
    // HttpParser class
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_http_parser_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_http_parser_class_id, &tjs_http_parser_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_http_parser_proto_funcs, countof(tjs_http_parser_proto_funcs));
    JS_SetClassProto(ctx, tjs_http_parser_class_id, proto);
    
    JSValue ctor = JS_NewCFunction2(ctx, tjs_http_parser_constructor, "HttpParser", 1, JS_CFUNC_constructor, 0);
    JS_SetPropertyFunctionList(ctx, ctor, tjs_http_parser_class_funcs, countof(tjs_http_parser_class_funcs));
    JS_DefinePropertyValueStr(ctx, ns, "HttpParser", ctor, JS_PROP_C_W_E);
    
    // HttpRequest class
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_http_request_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_http_request_class_id, &tjs_http_request_class);
}