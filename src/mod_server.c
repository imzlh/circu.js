/*
 * txiki.ts
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
#include "utils.h"
/* tjs_http.c - HTTP Server with llhttp + libuv for TJS */
#include "private.h"
#include "tjs.h"

#include <llhttp.h>
#include <stdlib.h>
#include <string.h>

/* Forward declarations */
typedef struct TJSHttpServer TJSHttpServer;
typedef struct TJSHttpConnection TJSHttpConnection;

/* HTTP Connection */
struct TJSHttpConnection {
    TJSHttpServer *server;
    uv_tcp_t tcp;
    llhttp_t parser;
    llhttp_settings_t parser_settings;
    
    /* Request data */
    JSValue request_obj;
    JSValue headers_obj;
    JSValue url_obj;
    char *current_header_field;
    size_t current_header_field_len;
    char *current_header_value;
    size_t current_header_value_len;
    char *body;
    size_t body_len;
    char *url;
    
    /* Response state */
    int response_sent;
    int keep_alive;
    int should_close;
    
    /* Write queue */
    uv_write_t write_req;
    uv_buf_t *write_bufs;
    int write_buf_count;
};

/* HTTP Server */
struct TJSHttpServer {
    JSContext *ctx;
    uv_tcp_t tcp;
    JSValue on_request;
    JSValue on_upgrade;
	JSValue on_error;
    int port;
};

static JSClassID tjs_http_server_class_id;
static JSClassID tjs_http_connection_class_id;

/* Parser callbacks */
static int on_message_begin(llhttp_t *parser) {
    TJSHttpConnection *conn = parser->data;
    
    conn->request_obj = JS_NewObject(conn->server->ctx);
    conn->headers_obj = JS_NewObject(conn->server->ctx);
    conn->url_obj = JS_NewObject(conn->server->ctx);
    conn->body = NULL;
    conn->body_len = 0;
    conn->url = NULL;
    conn->response_sent = 0;
    
    return 0;
}

static int on_url(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpConnection *conn = parser->data;
    
    if (!conn->url) {
        conn->url = js_malloc(conn->server->ctx, length + 1);
        memcpy(conn->url, at, length);
        conn->url[length] = '\0';
    } else {
        size_t old_len = strlen(conn->url);
        char *new_url = js_realloc(conn->server->ctx, conn->url, old_len + length + 1);
        if (new_url) {
            memcpy(new_url + old_len, at, length);
            new_url[old_len + length] = '\0';
            conn->url = new_url;
        }
    }
    
    return 0;
}

static int on_header_field(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpConnection *conn = parser->data;
    
    /* Save previous header if exists */
    if (conn->current_header_field && conn->current_header_value) {
        JS_SetPropertyStr(conn->server->ctx, conn->headers_obj,
                         conn->current_header_field,
                         JS_NewStringLen(conn->server->ctx, 
                                       conn->current_header_value,
                                       conn->current_header_value_len));
        js_free(conn->server->ctx, conn->current_header_field);
        js_free(conn->server->ctx, conn->current_header_value);
        conn->current_header_field = NULL;
        conn->current_header_value = NULL;
    }
    
    /* Accumulate field name */
    if (!conn->current_header_field) {
        conn->current_header_field = js_malloc(conn->server->ctx, length + 1);
        memcpy(conn->current_header_field, at, length);
        conn->current_header_field[length] = '\0';
        conn->current_header_field_len = length;
    } else {
        char *new_field = js_realloc(conn->server->ctx, conn->current_header_field,
                                     conn->current_header_field_len + length + 1);
        if (new_field) {
            memcpy(new_field + conn->current_header_field_len, at, length);
            conn->current_header_field_len += length;
            new_field[conn->current_header_field_len] = '\0';
            conn->current_header_field = new_field;
        }
    }
    
    return 0;
}

static int on_header_value(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpConnection *conn = parser->data;
    
    if (!conn->current_header_value) {
        conn->current_header_value = js_malloc(conn->server->ctx, length + 1);
        memcpy(conn->current_header_value, at, length);
        conn->current_header_value[length] = '\0';
        conn->current_header_value_len = length;
    } else {
        char *new_value = js_realloc(conn->server->ctx, conn->current_header_value,
                                     conn->current_header_value_len + length + 1);
        if (new_value) {
            memcpy(new_value + conn->current_header_value_len, at, length);
            conn->current_header_value_len += length;
            new_value[conn->current_header_value_len] = '\0';
            conn->current_header_value = new_value;
        }
    }
    
    return 0;
}

static int on_headers_complete(llhttp_t *parser) {
    TJSHttpConnection *conn = parser->data;
    
    /* Save last header */
    if (conn->current_header_field && conn->current_header_value) {
        JS_SetPropertyStr(conn->server->ctx, conn->headers_obj,
                         conn->current_header_field,
                         JS_NewStringLen(conn->server->ctx,
                                       conn->current_header_value,
                                       conn->current_header_value_len));
        js_free(conn->server->ctx, conn->current_header_field);
        js_free(conn->server->ctx, conn->current_header_value);
        conn->current_header_field = NULL;
        conn->current_header_value = NULL;
    }
    
    /* Parse URL */
    if (conn->url) {
        char *query_start = strchr(conn->url, '?');
        if (query_start) {
            *query_start = '\0';
            JS_SetPropertyStr(conn->server->ctx, conn->url_obj, "pathname",
                            JS_NewString(conn->server->ctx, conn->url));
            
            /* Parse query parameters */
            JSValue query_obj = JS_NewObject(conn->server->ctx);
            char *query = query_start + 1;
            char *pair;
            while ((pair = strsep(&query, "&")) != NULL) {
                char *eq = strchr(pair, '=');
                if (eq) {
                    *eq = '\0';
                    JS_SetPropertyStr(conn->server->ctx, query_obj, pair,
                                    JS_NewString(conn->server->ctx, eq + 1));
                } else {
                    JS_SetPropertyStr(conn->server->ctx, query_obj, pair,
                                    JS_NewString(conn->server->ctx, ""));
                }
            }
            JS_SetPropertyStr(conn->server->ctx, conn->url_obj, "query", query_obj);
        } else {
            JS_SetPropertyStr(conn->server->ctx, conn->url_obj, "pathname",
                            JS_NewString(conn->server->ctx, conn->url));
            JS_SetPropertyStr(conn->server->ctx, conn->url_obj, "query",
                            JS_NewObject(conn->server->ctx));
        }
    }
    
    /* Set request properties */
    const char *method = llhttp_method_name(parser->method);
    JS_SetPropertyStr(conn->server->ctx, conn->request_obj, "method",
                     JS_NewString(conn->server->ctx, method));
    JS_SetPropertyStr(conn->server->ctx, conn->request_obj, "url", conn->url_obj);
    JS_SetPropertyStr(conn->server->ctx, conn->request_obj, "headers", conn->headers_obj);
    JS_SetPropertyStr(conn->server->ctx, conn->request_obj, "httpVersion",
                     JS_NewString(conn->server->ctx,
                                parser->http_major == 1 && parser->http_minor == 1 ? "1.1" : "1.0"));
    
    /* Check keep-alive */
    conn->keep_alive = llhttp_should_keep_alive(parser);
    
    return 0;
}

static int on_body(llhttp_t *parser, const char *at, size_t length) {
    TJSHttpConnection *conn = parser->data;
    
    if (!conn->body) {
        conn->body = js_malloc(conn->server->ctx, length);
        if (conn->body) {
            memcpy(conn->body, at, length);
            conn->body_len = length;
        }
    } else {
        char *new_body = js_realloc(conn->server->ctx, conn->body, conn->body_len + length);
        if (new_body) {
            memcpy(new_body + conn->body_len, at, length);
            conn->body_len += length;
            conn->body = new_body;
        }
    }
    
    return 0;
}

static int on_message_complete(llhttp_t *parser) {
    TJSHttpConnection *conn = parser->data;
    
    /* Set body if exists */
    if (conn->body && conn->body_len > 0) {
        JS_SetPropertyStr(conn->server->ctx, conn->request_obj, "body",
                         JS_NewArrayBufferCopy(conn->server->ctx,
                                             (uint8_t *)conn->body,
                                             conn->body_len));
    }
    
    /* Create response object */
    JSValue res_obj = JS_NewObjectClass(conn->server->ctx, tjs_http_connection_class_id);
    JS_SetOpaque(res_obj, conn);
    
    /* Call JavaScript handler */
    JSValue args[2] = { conn->request_obj, res_obj };
    JSValue ret = JS_Call(conn->server->ctx, conn->server->on_request,
                         JS_UNDEFINED, 2, args);
    
    if (JS_IsException(ret)) {
        JSValue cb = conn->server->on_error;
		JSValue err = JS_GetException(conn->server->ctx);
		JS_Call(conn->server->ctx, cb, JS_UNDEFINED, 1, (JSValueConst[]) { err });
        conn->should_close = 1;
    }
    
    JS_FreeValue(conn->server->ctx, ret);
    JS_FreeValue(conn->server->ctx, res_obj);
    
    return 0;
}

/* Connection management */
static void on_connection_close(uv_handle_t *handle) {
    TJSHttpConnection *conn = handle->data;
    if (conn) {
        if (conn->url) js_free(conn->server->ctx, conn->url);
        if (conn->body) js_free(conn->server->ctx, conn->body);
        if (conn->current_header_field) js_free(conn->server->ctx, conn->current_header_field);
        if (conn->current_header_value) js_free(conn->server->ctx, conn->current_header_value);
        JS_FreeValue(conn->server->ctx, conn->request_obj);
        js_free(conn->server->ctx, conn);
    }
}

static void after_write(uv_write_t *req, int status) {
    TJSHttpConnection *conn = req->data;
    
    if (conn->write_bufs) {
        for (int i = 0; i < conn->write_buf_count; i++) {
            if (conn->write_bufs[i].base) {
                js_free(conn->server->ctx, conn->write_bufs[i].base);
            }
        }
        js_free(conn->server->ctx, conn->write_bufs);
        conn->write_bufs = NULL;
        conn->write_buf_count = 0;
    }
    
    if (status < 0 || conn->should_close || !conn->keep_alive) {
        uv_close((uv_handle_t *)&conn->tcp, on_connection_close);
    }
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    TJSHttpConnection *conn = stream->data;
	JSContext *ctx = conn->server->ctx;
    
    if (nread > 0) {
        enum llhttp_errno err = llhttp_execute(&conn->parser, buf->base, nread);
        
        if (err != HPE_OK) {
			JS_ThrowPlainError(ctx, "HTTP parse error: %s %s\n",
                   llhttp_errno_name(err), llhttp_get_error_reason(&conn->parser));
			JSValue err = JS_GetException(ctx);
			JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 1, (JSValueConst[]){ err });
			JS_FreeValue(ctx, err);
            conn->should_close = 1;
            uv_close((uv_handle_t *)stream, on_connection_close);
        }
    } else if (nread < 0) {
        if (nread != UV_EOF) {
			JS_ThrowPlainError(ctx, "Read error: %s\n", uv_strerror(nread));
			JSValue err = JS_GetException(ctx);
			JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 1, (JSValueConst[]){ err });
			JS_FreeValue(ctx, err);
        }
        uv_close((uv_handle_t *)stream, on_connection_close);
    }
    
    if (buf->base) {
        free(buf->base);
    }
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_new_connection(uv_stream_t *server, int status) {
    TJSHttpServer *http_server = server->data;

	if (status < 0) {
		JSContext* ctx = http_server->ctx;
		JS_ThrowPlainError(ctx, "Failed to accept incoming connection: %s\n", uv_strerror(status));
		JSValue err = JS_GetException(ctx);
		JS_Call(ctx, http_server->on_error, JS_UNDEFINED, 1, (JSValueConst[]){ err });
		JS_FreeValue(ctx, err);
        return;
    }

    TJSHttpConnection *conn = js_mallocz(http_server->ctx, sizeof(TJSHttpConnection));
    if (!conn) return;
    
    conn->server = http_server;
    conn->tcp.data = conn;
    
    uv_tcp_init(server->loop, &conn->tcp);
    
    if (uv_accept(server, (uv_stream_t *)&conn->tcp) == 0) {
        /* Initialize parser */
        llhttp_settings_init(&conn->parser_settings);
        conn->parser_settings.on_message_begin = on_message_begin;
        conn->parser_settings.on_url = on_url;
        conn->parser_settings.on_header_field = on_header_field;
        conn->parser_settings.on_header_value = on_header_value;
        conn->parser_settings.on_headers_complete = on_headers_complete;
        conn->parser_settings.on_body = on_body;
        conn->parser_settings.on_message_complete = on_message_complete;
        
        llhttp_init(&conn->parser, HTTP_REQUEST, &conn->parser_settings);
        conn->parser.data = conn;
        
        conn->write_req.data = conn;
        
        uv_read_start((uv_stream_t *)&conn->tcp, alloc_buffer, on_read);
    } else {
        uv_close((uv_handle_t *)&conn->tcp, on_connection_close);
    }
}

/* Response methods */
static JSValue tjs_http_response_write_head(JSContext *ctx, JSValueConst this_val,
                                            int argc, JSValueConst *argv) {
    TJSHttpConnection *conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
    if (!conn) {
        return JS_ThrowTypeError(ctx, "Invalid response object");
    }
    
    if (conn->response_sent) {
        return JS_ThrowTypeError(ctx, "Headers already sent");
    }
    
    int32_t status_code = 200;
    const char *status_text = "OK";
    
    if (argc > 0) {
        JS_ToInt32(ctx, &status_code, argv[0]);
    }
    
    /* Build status line */
    char status_line[256];
    snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
             status_code, status_text);
    
    /* Build headers */
    JSValue headers = JS_UNDEFINED;
    if (argc > 1 && JS_IsObject(argv[1])) {
        headers = argv[1];
    }
    
    size_t total_len = strlen(status_line);
    char *response_header = js_malloc(ctx, 4096);
    strcpy(response_header, status_line);
    
    if (JS_IsObject(headers)) {
        JSPropertyEnum *props;
        uint32_t prop_count;
        if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, headers,
                                   JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
            for (uint32_t i = 0; i < prop_count; i++) {
                JSValue key = JS_AtomToString(ctx, props[i].atom);
                JSValue val = JS_GetProperty(ctx, headers, props[i].atom);
                
                const char *key_str = JS_ToCString(ctx, key);
                const char *val_str = JS_ToCString(ctx, val);
                
                if (key_str && val_str) {
                    size_t header_len = strlen(key_str) + strlen(val_str) + 4;
                    if (total_len + header_len < 4096) {
                        strcat(response_header, key_str);
                        strcat(response_header, ": ");
                        strcat(response_header, val_str);
                        strcat(response_header, "\r\n");
                        total_len += header_len;
                    }
                }
                
                JS_FreeCString(ctx, key_str);
                JS_FreeCString(ctx, val_str);
                JS_FreeValue(ctx, key);
                JS_FreeValue(ctx, val);
            }
            js_free(ctx, props);
        }
    }
    
    strcat(response_header, "\r\n");
    
    /* Send headers */
    uv_buf_t buf = uv_buf_init(response_header, strlen(response_header));
    conn->write_bufs = js_malloc(ctx, sizeof(uv_buf_t));
    conn->write_bufs[0] = buf;
    conn->write_buf_count = 1;
    
    uv_write(&conn->write_req, (uv_stream_t *)&conn->tcp, &buf, 1, NULL);
    
    conn->response_sent = 1;
    
    return JS_UNDEFINED;
}

static JSValue tjs_http_response_write(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    TJSHttpConnection *conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
    if (!conn) {
        return JS_ThrowTypeError(ctx, "Invalid response object");
    }
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "write requires data");
    }
    
    size_t len;
    const char *data = NULL;
    int is_string = 0;
    
    if (JS_IsString(argv[0])) {
        data = JS_ToCStringLen(ctx, &len, argv[0]);
        is_string = 1;
    } else {
        uint8_t *buf = JS_GetArrayBuffer(ctx, &len, argv[0]);
        if (buf) {
            data = (const char *)buf;
        }
    }
    
    if (!data) {
        return JS_ThrowTypeError(ctx, "Invalid data type");
    }
    
    char *buf_data = js_malloc(ctx, len);
    memcpy(buf_data, data, len);
    
    if (is_string) {
        JS_FreeCString(ctx, data);
    }
    
    uv_buf_t buf = uv_buf_init(buf_data, len);
    conn->write_bufs = js_malloc(ctx, sizeof(uv_buf_t));
    conn->write_bufs[0] = buf;
    conn->write_buf_count = 1;
    
    uv_write(&conn->write_req, (uv_stream_t *)&conn->tcp, &buf, 1, after_write);
    
    return JS_UNDEFINED;
}

static JSValue tjs_http_response_end(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    TJSHttpConnection *conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
    if (!conn) {
        return JS_ThrowTypeError(ctx, "Invalid response object");
    }
    
    if (argc > 0) {
        tjs_http_response_write(ctx, this_val, argc, argv);
    }
    
    conn->should_close = !conn->keep_alive;
    
    return JS_UNDEFINED;
}

static JSValue tjs_http_response_send(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    TJSHttpConnection *conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
    if (!conn) {
        return JS_ThrowTypeError(ctx, "Invalid response object");
    }
    
    int32_t status_code = 200;
    const char *body = "";
    size_t body_len = 0;
    int is_string = 0;
    
    if (argc > 0 && JS_IsNumber(argv[0])) {
        JS_ToInt32(ctx, &status_code, argv[0]);
    }
    
    if (argc > 1) {
        if (JS_IsString(argv[1])) {
            body = JS_ToCStringLen(ctx, &body_len, argv[1]);
            is_string = 1;
        } else {
            uint8_t *buf = JS_GetArrayBuffer(ctx, &body_len, argv[1]);
            if (buf) {
                body = (const char *)buf;
            }
        }
    }
    
    /* Build response */
    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d OK\r\n"
             "Content-Length: %zu\r\n"
             "Connection: %s\r\n"
             "\r\n",
             status_code, body_len,
             conn->keep_alive ? "keep-alive" : "close");
    
    size_t header_len = strlen(header);
    char *response_data = js_malloc(ctx, header_len + body_len);
    memcpy(response_data, header, header_len);
    if (body_len > 0) {
        memcpy(response_data + header_len, body, body_len);
    }
    
    if (is_string) {
        JS_FreeCString(ctx, body);
    }
    
    uv_buf_t buf = uv_buf_init(response_data, header_len + body_len);
    conn->write_bufs = js_malloc(ctx, sizeof(uv_buf_t));
    conn->write_bufs[0] = buf;
    conn->write_buf_count = 1;
    
    uv_write(&conn->write_req, (uv_stream_t *)&conn->tcp, &buf, 1, after_write);
    
    conn->response_sent = 1;
    
    return JS_UNDEFINED;
}

/* Server methods */
static void tjs_http_server_finalizer(JSRuntime *rt, JSValue val) {
    TJSHttpServer *server = JS_GetOpaque(val, tjs_http_server_class_id);
    if (server) {
        JS_FreeValueRT(rt, server->on_request);
        JS_FreeValueRT(rt, server->on_upgrade);
		JS_FreeValueRT(rt, server->on_error);
        js_free_rt(rt, server);
    }
}

static JSClassDef tjs_http_server_class = {
    "HttpServer",
    .finalizer = tjs_http_server_finalizer,
};

static JSClassDef tjs_http_connection_class = {
    "HttpResponse",
};

static JSValue tjs_http_create_server(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "createServer requires options object");
    }
    
    JSValue opts = argv[0];
    int32_t port = 8080;
    
    JSValue js_port = JS_GetPropertyStr(ctx, opts, "port");
    if (JS_IsNumber(js_port)) {
        JS_ToInt32(ctx, &port, js_port);
    }
    JS_FreeValue(ctx, js_port);
    
    JSValue on_request = JS_GetPropertyStr(ctx, opts, "onRequest");
    if (!JS_IsFunction(ctx, on_request)) {
        JS_FreeValue(ctx, on_request);
        return JS_ThrowTypeError(ctx, "onRequest must be a function");
    }
	JSValue on_error = JS_GetPropertyStr(ctx, opts, "onError");
	if (!JS_IsFunction(ctx, on_error)) {
		JS_FreeValue(ctx, on_error);
		return JS_ThrowTypeError(ctx, "onError must be a function");
	}
	const char* addr_str = "0.0.0.0";
	JSValue addr_obj = JS_GetPropertyStr(ctx, opts, "address");
	struct sockaddr addr;
	if (JS_IsString(addr_obj)){
		addr_str = JS_ToCString(ctx, addr_obj);
		if(strstr(JS_ToCString(ctx, addr_obj), ":")){
			if(-1 == uv_ip6_addr(addr_str, port, (struct sockaddr_in6*)&addr)){
addrerr:;
				return JS_ThrowTypeError(ctx, "address must be a vaild ipv4/6 string");
			}
		}else{
			if(-1 == uv_ip4_addr(addr_str, port, (struct sockaddr_in*)&addr)){
				goto addrerr;
			}
		}
		JS_FreeCString(ctx, addr_str);
	}
	JS_FreeValue(ctx, addr_obj);
    
    TJSHttpServer *server = js_mallocz(ctx, sizeof(TJSHttpServer));
    if (!server) {
        JS_FreeValue(ctx, on_request);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    server->ctx = ctx;
    server->port = port;
    server->on_request = JS_DupValue(ctx, on_request);
    server->on_upgrade = JS_UNDEFINED;
	server->on_error = on_error;
    
    JS_FreeValue(ctx, on_request);
    
    /* Initialize TCP server */
	TJSRuntime* trt = TJS_GetRuntime(ctx);
    uv_loop_t *loop = TJS_GetLoop(trt);
    uv_tcp_init(loop, &server->tcp);
    server->tcp.data = server;
    
    
    int r = uv_tcp_bind(&server->tcp, (const struct sockaddr *)&addr, 0);
    if (r != 0) {
bindfailed:;
        JS_FreeValue(ctx, server->on_request);
        js_free(ctx, server);
        return tjs_throw_errno(ctx, r);
    }
    
    r = uv_listen((uv_stream_t *)&server->tcp, 128, on_new_connection);
    if (r != 0) {
		goto bindfailed;
    }
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_http_server_class_id);
    JS_SetOpaque(obj, server);
    
    return obj;
}

static JSValue tjs_http_server_close(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    TJSHttpServer *server = JS_GetOpaque2(ctx, this_val, tjs_http_server_class_id);
    if (!server) {
        return JS_ThrowTypeError(ctx, "Invalid server object");
    }
    
    uv_close((uv_handle_t *)&server->tcp, NULL);
    
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_http_server_proto_funcs[] = {
    TJS_CFUNC_DEF("close", 0, tjs_http_server_close),
};

static const JSCFunctionListEntry tjs_http_response_proto_funcs[] = {
    TJS_CFUNC_DEF("writeHead", 2, tjs_http_response_write_head),
    TJS_CFUNC_DEF("write", 1, tjs_http_response_write),
    TJS_CFUNC_DEF("end", 1, tjs_http_response_end),
    TJS_CFUNC_DEF("send", 2, tjs_http_response_send),
};

static const JSCFunctionListEntry tjs_http_funcs[] = {
    TJS_CFUNC_DEF("createServer", 1, tjs_http_create_server),
};

void tjs__mod_server_init(JSContext *ctx, JSValue ns) {
	JSRuntime* rt = JS_GetRuntime(ctx);

    /* Register server class */
    JS_NewClassID(rt, &tjs_http_server_class_id);
    JS_NewClass(rt, tjs_http_server_class_id, &tjs_http_server_class);
    
    JSValue server_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, server_proto, tjs_http_server_proto_funcs,
                              countof(tjs_http_server_proto_funcs));
    JS_SetClassProto(ctx, tjs_http_server_class_id, server_proto);
    
    /* Register connection class */
    JS_NewClassID(rt, &tjs_http_connection_class_id);
    JS_NewClass(rt, tjs_http_connection_class_id, &tjs_http_connection_class);
    
    JSValue response_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, response_proto, tjs_http_response_proto_funcs,
                              countof(tjs_http_response_proto_funcs));
    JS_SetClassProto(ctx, tjs_http_connection_class_id, response_proto);
    
    /* Set module functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_http_funcs, countof(tjs_http_funcs));
}