/*
 * circu.js http server module
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

#include <llhttp.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

 /* ========================================================================== */
 /* Macros & Constants                                                         */
 /* ========================================================================== */

#define TJS_HTTP_DEFAULT_PORT 8080
#define TJS_HTTP_DEFAULT_BACKLOG 128
#define TJS_HTTP_BUFFER_SIZE 8192
#define TJS_HTTP_HEADER_BUFFER_SIZE 4096

/* Safe reference management */
#define TJS_INIT_REF(ctx, val) ((val) = JS_UNDEFINED)
#define TJS_SETPROP(ctx, target, val) do { \
    JS_FreeValue((ctx), (target)); \
    (target) = (val); \
} while(0)
#define TJS_FREE_REF(ctx, val) do { \
    JS_FreeValue((ctx), (val)); \
    (val) = JS_UNDEFINED; \
} while(0)

/* Check connection state */
#define CHECK_CONN(conn) do { \
    if (!(conn) || (conn)->closed) { \
        return JS_ThrowTypeError(ctx, "Connection closed"); \
    } \
} while(0)

#define CHECK_HEADERS_SENT(conn) do { \
    if ((conn)->headers_sent) { \
        return JS_ThrowTypeError(ctx, "Headers already sent"); \
    } \
} while(0)

/* ========================================================================== */
/* Type Definitions                                                           */
/* ========================================================================== */

typedef struct TJSHttpServer TJSHttpServer;
typedef struct TJSHttpConnection TJSHttpConnection;

typedef enum {
	RESPONSE_MODE_UNKNOWN = 0,
	RESPONSE_MODE_CONTENT_LENGTH,
	RESPONSE_MODE_CHUNKED,
	RESPONSE_MODE_CONNECTION_CLOSE
} TJSResponseMode;

struct TJSHttpConnection {
	/* Reference management */
	int ref_count;

	/* Server reference */
	TJSHttpServer* server;

	/* UV handles */
	uv_tcp_t tcp;
	bool tcp_initialized;

	/* HTTP parser */
	llhttp_t parser;
	llhttp_settings_t parser_settings;

	/* Request objects */
	JSValue request_obj;
	JSValue response_obj;
	JSValue headers_obj;
	JSValue addrinfo_obj;

	/* Request parsing state */
	char* url;
	char* current_header_field;
	size_t current_header_field_len;
	char* current_header_value;
	size_t current_header_value_len;
	char* body;
	size_t body_len;

	/* Response state */
	bool headers_sent;
	bool closed;
	TJSResponseMode response_mode;
	ssize_t content_length_remaining;
	bool keep_alive;

	/* SSL context */
	SSL* ssl;
	BIO* rbio;
	BIO* wbio;
	bool ssl_handshake_done;
};

struct TJSHttpServer {
	JSContext* ctx;
	uv_tcp_t tcp;
	bool tcp_initialized;

	/* JavaScript callbacks */
	JSValue on_request;
	JSValue on_error;
	JSValue on_body;
	JSValue on_accept;
	JSValue on_complete;

	/* Self reference for GC */
	JSValue self;

	int port;
	bool closed;
};

static JSClassID tjs_http_server_class_id;
static JSClassID tjs_http_connection_class_id;

/* ========================================================================== */
/* Forward Declarations                                                       */
/* ========================================================================== */

static void connection_close(TJSHttpConnection* conn);
static void connection_free(TJSHttpConnection* conn);
static int write_data(TJSHttpConnection* conn, const void* data, size_t len, bool copy);

/* ========================================================================== */
/* Memory Management Helpers                                                  */
/* ========================================================================== */

static inline void* safe_malloc(JSContext* ctx, size_t size) {
	void* ptr = js_malloc(ctx, size);
	if (ptr) memset(ptr, 0, size);
	return ptr;
}

static inline void safe_free(JSContext* ctx, void** ptr) {
	if (*ptr) {
		js_free(ctx, *ptr);
		*ptr = NULL;
	}
}

#define UNREF(obj) do { \
	obj->ref_count--; \
	if (obj->ref_count == 0) { \
		connection_free(obj); \
	} \
} while(0)

/* ========================================================================== */
/* Connection Management                                                      */
/* ========================================================================== */

static void connection_reset_request(TJSHttpConnection* conn) {
	JSContext* ctx = conn->server->ctx;

	safe_free(ctx, (void**) &conn->url);
	safe_free(ctx, (void**) &conn->body);
	safe_free(ctx, (void**) &conn->current_header_field);
	safe_free(ctx, (void**) &conn->current_header_value);

	conn->body_len = 0;
	conn->current_header_field_len = 0;
	conn->current_header_value_len = 0;

	TJS_FREE_REF(ctx, conn->request_obj);
	TJS_FREE_REF(ctx, conn->headers_obj);
	TJS_FREE_REF(ctx, conn->addrinfo_obj);
}

static void connection_free(TJSHttpConnection* conn) {
	if (!conn) return;
	assert(conn->ref_count == 0);

	JSContext* ctx = conn->server->ctx;

	/* reset/free the transient request state (this frees request_obj/headers_obj) */
	connection_reset_request(conn);

	/* free persistent response object if any */
	if (!JS_IsUndefined(conn->response_obj)) {
		/* clear opaque on the JS object first to avoid callbacks into freed native object */
		JS_SetOpaque(conn->response_obj, NULL);
		TJS_FREE_REF(ctx, conn->response_obj);
	}

	if (conn->ssl) {
		SSL_free(conn->ssl);
		conn->ssl = NULL;
	}

	js_free(ctx, conn);
}

static void conn_close_cb(uv_handle_t* handle) {
	TJSHttpConnection* conn = (TJSHttpConnection*) handle->data;
	UNREF(conn);	// uv: free ref
	TJS_FREE_REF(conn->server->ctx, conn->response_obj);
}

static void connection_close(TJSHttpConnection* conn) {
	if (conn->closed) return;

	conn->closed = true;

	if (conn->tcp_initialized && !uv_is_closing((uv_handle_t*) &conn->tcp)) {
		uv_close((uv_handle_t*) &conn->tcp, conn_close_cb);
	}
}

/* ========================================================================== */
/* Write Helpers                                                              */
/* ========================================================================== */

typedef struct {
	uv_write_t req;
	TJSHttpConnection* conn;
	uv_buf_t buf;
} TJSWriteReq;

static void after_write(uv_write_t* req, int status) {
	TJSWriteReq* write_req = (TJSWriteReq*) req;
	TJSHttpConnection* conn = write_req->conn;

	if (write_req->buf.base) {
		js_free(conn->server->ctx, write_req->buf.base);
	}
	js_free(conn->server->ctx, write_req);

	if (status < 0 || (!conn->keep_alive && conn->headers_sent)) {
		connection_close(conn);
	}
}

static int write_data(TJSHttpConnection* conn, const void* data, size_t len, bool copy) {
	if (len == 0 || !data) return 0;
	if (conn->closed) return UV_EBADF;

	TJSWriteReq* req = safe_malloc(conn->server->ctx, sizeof(TJSWriteReq));
	if (!req) return UV_ENOMEM;

	req->conn = conn;

	if (copy) {
		req->buf.base = js_malloc(conn->server->ctx, len);
		if (!req->buf.base) {
			js_free(conn->server->ctx, req);
			return UV_ENOMEM;
		}
		memcpy(req->buf.base, data, len);
	}
	else {
		req->buf.base = (char*) data;
	}
	req->buf.len = len;

	int r = uv_write(&req->req, (uv_stream_t*) &conn->tcp, &req->buf, 1, after_write);
	if (r != 0) {
		if (copy && req->buf.base) {
			js_free(conn->server->ctx, req->buf.base);
		}
		js_free(conn->server->ctx, req);
	}

	return r;
}

static int write_http_data(TJSHttpConnection* conn, const void* data, size_t len) {
	if (!conn->ssl) {
		/* No SSL: send directly */
		if (conn->response_mode == RESPONSE_MODE_CHUNKED && len > 0) {
			/* Send chunk header */
			char chunk_header[32];
			int header_len = snprintf(chunk_header, sizeof(chunk_header), "%zx\r\n", len);
			write_data(conn, chunk_header, header_len, true);

			/* Send data */
			int r = write_data(conn, data, len, true);

			/* Send chunk trailer */
			write_data(conn, "\r\n", 2, true);

			return r;
		}
		return write_data(conn, data, len, true);
	}

	/* SSL: encrypt then send */
	if (conn->response_mode == RESPONSE_MODE_CHUNKED && len > 0) {
		char chunk_header[32];
		int header_len = snprintf(chunk_header, sizeof(chunk_header), "%zx\r\n", len);
		SSL_write(conn->ssl, chunk_header, header_len);
	}

	if (len > 0) {
		int written = SSL_write(conn->ssl, data, len);
		if (written <= 0) return UV_EIO;
	}

	if (conn->response_mode == RESPONSE_MODE_CHUNKED && len > 0) {
		SSL_write(conn->ssl, "\r\n", 2);
	}

	/* Read encrypted data and send */
	size_t pending = BIO_pending(conn->wbio);
	if (pending > 0) {
		char* encrypted = js_malloc(conn->server->ctx, pending);
		BIO_read(conn->wbio, encrypted, pending);
		return write_data(conn, encrypted, pending, false);
	}

	return 0;
}

/* ========================================================================== */
/* HTTP Parser Callbacks                                                      */
/* ========================================================================== */

static int on_message_begin(llhttp_t* parser) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	connection_reset_request(conn);

	TJS_INIT_REF(ctx, conn->request_obj);
	TJS_INIT_REF(ctx, conn->headers_obj);

	conn->request_obj = JS_NewObject(ctx);
	conn->headers_obj = JS_NewObject(ctx);

	conn->headers_sent = false;
	conn->response_mode = RESPONSE_MODE_UNKNOWN;

	return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	if (!conn->url) {
		conn->url = js_malloc(ctx, length + 1);
		if (!conn->url) return -1;
		memcpy(conn->url, at, length);
		conn->url[length] = '\0';
	}
	else {
		size_t old_len = strlen(conn->url);
		char* new_url = js_realloc(ctx, conn->url, old_len + length + 1);
		if (!new_url) return -1;
		memcpy(new_url + old_len, at, length);
		new_url[old_len + length] = '\0';
		conn->url = new_url;
	}

	return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	/* Save previous header if complete */
	if (conn->current_header_field && conn->current_header_value) {
		JS_SetPropertyStr(ctx, conn->headers_obj,
			conn->current_header_field,
			JS_NewStringLen(ctx, conn->current_header_value,
				conn->current_header_value_len));
		safe_free(ctx, (void**) &conn->current_header_field);
		safe_free(ctx, (void**) &conn->current_header_value);
	}

	/* Accumulate field name */
	if (!conn->current_header_field) {
		conn->current_header_field = js_malloc(ctx, length + 1);
		if (!conn->current_header_field) return -1;
		memcpy(conn->current_header_field, at, length);
		conn->current_header_field[length] = '\0';
		conn->current_header_field_len = length;
	}
	else {
		char* new_field = js_realloc(ctx, conn->current_header_field,
			conn->current_header_field_len + length + 1);
		if (!new_field) return -1;
		memcpy(new_field + conn->current_header_field_len, at, length);
		conn->current_header_field_len += length;
		new_field[conn->current_header_field_len] = '\0';
		conn->current_header_field = new_field;
	}

	return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	if (!conn->current_header_value) {
		conn->current_header_value = js_malloc(ctx, length + 1);
		if (!conn->current_header_value) return -1;
		memcpy(conn->current_header_value, at, length);
		conn->current_header_value[length] = '\0';
		conn->current_header_value_len = length;
	}
	else {
		char* new_value = js_realloc(ctx, conn->current_header_value,
			conn->current_header_value_len + length + 1);
		if (!new_value) return -1;
		memcpy(new_value + conn->current_header_value_len, at, length);
		conn->current_header_value_len += length;
		new_value[conn->current_header_value_len] = '\0';
		conn->current_header_value = new_value;
	}

	return 0;
}

static int on_headers_complete(llhttp_t* parser) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	/* Save last header */
	if (conn->current_header_field && conn->current_header_value) {
		JS_SetPropertyStr(ctx, conn->headers_obj,
			conn->current_header_field,
			JS_NewStringLen(ctx, conn->current_header_value,
				conn->current_header_value_len));
		safe_free(ctx, (void**) &conn->current_header_field);
		safe_free(ctx, (void**) &conn->current_header_value);
	}

	/* Build request object */
	if (conn->url) {
		JS_SetPropertyStr(ctx, conn->request_obj, "url",
			JS_NewString(ctx, conn->url));
	}

	const char* method = llhttp_method_name(parser->method);
	JS_SetPropertyStr(ctx, conn->request_obj, "method",
		JS_NewString(ctx, method));
	JS_SetPropertyStr(ctx, conn->request_obj, "headers",
		JS_DupValue(ctx, conn->headers_obj));

	char version[8];
	snprintf(version, sizeof(version), "%d.%d",
		parser->http_major, parser->http_minor);
	JS_SetPropertyStr(ctx, conn->request_obj, "httpVersion",
		JS_NewString(ctx, version));

	/* Check keep-alive */
	conn->keep_alive = llhttp_should_keep_alive(parser);

	/* Create response object */
	JSValue res_obj;
	if (JS_IsUndefined(conn->response_obj)) {
		res_obj = JS_NewObjectClass(ctx, tjs_http_connection_class_id);
		JS_SetOpaque(res_obj, conn);
		conn->ref_count++;	// js
		conn->response_obj = JS_DupValue(ctx, res_obj);
	}
	else {
		res_obj = JS_DupValue(ctx, conn->response_obj);
	}

	/* Call JavaScript handler */
	JSValue args[3] = { conn->request_obj, res_obj, conn->addrinfo_obj };
	JSValue ret = JS_Call(ctx, conn->server->on_request, JS_UNDEFINED, 3, args);

	if (JS_IsException(ret)) {
		JSValue err = JS_GetException(ctx);
		if (!JS_IsUndefined(conn->server->on_error)) {
			JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 3,
				(JSValueConst[]) { err, conn->request_obj, conn->response_obj });
		}
		JS_FreeValue(ctx, err);
		connection_close(conn);
	}

	JS_FreeValue(ctx, ret);
	JS_FreeValue(ctx, res_obj);

	return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	if (!conn->body) {
		conn->body = js_malloc(ctx, length);
		if (!conn->body) return -1;
		memcpy(conn->body, at, length);
		conn->body_len = length;
	}
	else {
		char* new_body = js_realloc(ctx, conn->body, conn->body_len + length);
		if (!new_body) return -1;
		memcpy(new_body + conn->body_len, at, length);
		conn->body_len += length;
		conn->body = new_body;
	}

	return 0;
}

static int on_message_complete(llhttp_t* parser) {
	TJSHttpConnection* conn = parser->data;
	JSContext* ctx = conn->server->ctx;

	/* Set body if exists */
	if (conn->body && conn->body_len > 0) {
		JS_SetPropertyStr(ctx, conn->request_obj, "body",
			JS_NewArrayBufferCopy(ctx, (uint8_t*) conn->body,
				conn->body_len));

		if (!JS_IsUndefined(conn->server->on_body)) {
			JSValue ret = JS_Call(ctx, conn->server->on_body, JS_UNDEFINED, 3,
				(JSValueConst[]) { conn->request_obj, conn->response_obj, conn->addrinfo_obj });

			if (JS_IsException(ret)) {
				JSValue err = JS_GetException(ctx);
				if (!JS_IsUndefined(conn->server->on_error)) {
					JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 3,
						(JSValueConst[]) { err, conn->request_obj, conn->response_obj });
				}
				JS_FreeValue(ctx, err);
			}
			JS_FreeValue(ctx, ret);
		}
	}

	/* Call onCompleted callback */
	if (!JS_IsUndefined(conn->server->on_complete)) {
		JSValue ret = JS_Call(ctx, conn->server->on_complete, JS_UNDEFINED, 3,
			(JSValueConst[]) { conn->request_obj, conn->response_obj, conn->addrinfo_obj });

		if (JS_IsException(ret)) {
			JSValue err = JS_GetException(ctx);
			if (!JS_IsUndefined(conn->server->on_error)) {
				JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 3,
					(JSValueConst[]) { err, conn->request_obj, conn->response_obj });
			}
			JS_FreeValue(ctx, err);
		}
		JS_FreeValue(ctx, ret);
	}

	return 0;
}

/* ========================================================================== */
/* SSL Helpers                                                                */
/* ========================================================================== */

static int send_pending_ssl_data(TJSHttpConnection* conn) {
	size_t pending = BIO_pending(conn->wbio);
	if (pending > 0) {
		char* buf = js_malloc(conn->server->ctx, pending);
		BIO_read(conn->wbio, buf, pending);
		return write_data(conn, buf, pending, false);
	}
	return 0;
}

static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

static void on_ssl_handshake(TJSHttpConnection* conn) {
	int ret = SSL_do_handshake(conn->ssl);

	if (ret == 1) {
		send_pending_ssl_data(conn);
		conn->ssl_handshake_done = true;
		uv_read_start((uv_stream_t*) &conn->tcp, alloc_buffer, on_read);
		return;
	}

	int err = SSL_get_error(conn->ssl, ret);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		send_pending_ssl_data(conn);
		return;
	}

	/* Handshake failed */
	connection_close(conn);
}

/* ========================================================================== */
/* Connection I/O                                                             */
/* ========================================================================== */

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
	TJSHttpConnection* conn = stream->data;
	JSContext* ctx = conn->server->ctx;
	conn->ref_count++;	// llhttp

	if (nread > 0) {
		if (conn->ssl) {
			BIO_write(conn->rbio, buf->base, nread);

			if (!conn->ssl_handshake_done) {
				on_ssl_handshake(conn);
				goto cleanup;
			}

			/* Decrypt and parse */
			char decrypt_buf[TJS_HTTP_BUFFER_SIZE];
			int decrypted;

			while ((decrypted = SSL_read(conn->ssl, decrypt_buf, sizeof(decrypt_buf))) > 0) {
				enum llhttp_errno err = llhttp_execute(&conn->parser, decrypt_buf, decrypted);
				if (err != HPE_OK) {
					if (!JS_IsUndefined(conn->server->on_error)) {
						JSValue js_err = JS_NewError(ctx);
						JS_SetPropertyStr(ctx, js_err, "message",
							JS_NewString(ctx, llhttp_get_error_reason(&conn->parser)));
						JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 3,
							(JSValueConst[]) { js_err, conn->request_obj, conn->response_obj });
						JS_FreeValue(ctx, js_err);
					}
					connection_close(conn);
					goto cleanup;
				}
			}

			int ssl_err = SSL_get_error(conn->ssl, decrypted);
			if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE && decrypted < 0) {
				connection_close(conn);
			}
		}
		else {
			/* No SSL: parse directly */
			enum llhttp_errno err = llhttp_execute(&conn->parser, buf->base, nread);
			if (err != HPE_OK) {
				if (!JS_IsUndefined(conn->server->on_error)) {
					JSValue js_err = JS_NewError(ctx);
					JS_SetPropertyStr(ctx, js_err, "message",
						JS_NewString(ctx, llhttp_get_error_reason(&conn->parser)));
					JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 3,
						(JSValueConst[]) { js_err, conn->request_obj, conn->response_obj });
					JS_FreeValue(ctx, js_err);
				}
				connection_close(conn);
			}
		}
	}
	else if (nread < 0) {
		if (nread != UV_EOF && !JS_IsUndefined(conn->server->on_error)) {
			JSValue js_err = JS_NewError(ctx);
			JS_SetPropertyStr(ctx, js_err, "message",
				JS_NewString(ctx, uv_strerror(nread)));
			JS_Call(ctx, conn->server->on_error, JS_UNDEFINED, 3,
				(JSValueConst[]) { js_err, conn->request_obj, conn->response_obj });
			JS_FreeValue(ctx, js_err);
		}
		connection_close(conn);
	}

cleanup:
	UNREF(conn); // llhttp
	if (buf->base) {
		free(buf->base);
	}
}

/* ========================================================================== */
/* Connection Accept                                                          */
/* ========================================================================== */

static void on_new_connection(uv_stream_t* server, int status) {
	TJSHttpServer* http_server = server->data;
	JSContext* ctx = http_server->ctx;

	if (status < 0) return;

	TJSHttpConnection* conn = safe_malloc(ctx, sizeof(TJSHttpConnection));
	if (!conn) return;

	conn->ref_count = 1; // uv
	conn->server = http_server;
	conn->tcp.data = conn;
	conn->tcp_initialized = false;
	conn->keep_alive = true;

	TJS_INIT_REF(ctx, conn->request_obj);
	TJS_INIT_REF(ctx, conn->response_obj);
	TJS_INIT_REF(ctx, conn->headers_obj);
	TJS_INIT_REF(ctx, conn->addrinfo_obj);

	uv_tcp_init(server->loop, &conn->tcp);
	conn->tcp_initialized = true;

	if (uv_accept(server, (uv_stream_t*) &conn->tcp) != 0) {
		connection_free(conn);
		return;
	}

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

	/* Check SSL via onAccept callback */
	SSL_CTX* ssl_ctx = NULL;
	if (!JS_IsUndefined(http_server->on_accept)) {
		struct sockaddr_storage addr;
		int addr_len = sizeof(addr);
		char remote_ip[INET6_ADDRSTRLEN] = "unknown";
		int remote_port = 0;

		if (uv_tcp_getpeername((uv_tcp_t*) &conn->tcp,
			(struct sockaddr*) &addr, &addr_len) == 0) {
			if (addr.ss_family == AF_INET) {
				struct sockaddr_in* addr_in = (struct sockaddr_in*) &addr;
				uv_ip4_name(addr_in, remote_ip, sizeof(remote_ip));
				remote_port = ntohs(addr_in->sin_port);
			}
			else if (addr.ss_family == AF_INET6) {
				struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*) &addr;
				uv_ip6_name(addr_in6, remote_ip, sizeof(remote_ip));
				remote_port = ntohs(addr_in6->sin6_port);
			}
		}

		JSValue info = JS_NewObject(ctx);
		JS_SetPropertyStr(ctx, info, "remoteAddress", JS_NewString(ctx, remote_ip));
		JS_SetPropertyStr(ctx, info, "remotePort", JS_NewInt32(ctx, remote_port));

		JSValue ret = JS_Call(ctx, http_server->on_accept, JS_UNDEFINED, 1,
			(JSValueConst[]) { info });
		conn->addrinfo_obj = info;

		/* Check if connection refused */
		if (JS_IsBool(ret) && !JS_ToBool(ctx, ret)) {
			JS_FreeValue(ctx, ret);
			JS_FreeValue(ctx, info);
			connection_free(conn);
			return;
		}

		ssl_ctx = tjs__sslctx_get(ctx, ret);
		JS_FreeValue(ctx, ret);
	}

	if (ssl_ctx) {
		conn->ssl = SSL_new(ssl_ctx);
		conn->rbio = BIO_new(BIO_s_mem());
		conn->wbio = BIO_new(BIO_s_mem());
		SSL_set_bio(conn->ssl, conn->rbio, conn->wbio);
		SSL_set_accept_state(conn->ssl);

		conn->ssl_handshake_done = false;
		uv_read_start((uv_stream_t*) &conn->tcp, alloc_buffer, on_read);
		on_ssl_handshake(conn);
	}
	else {
		uv_read_start((uv_stream_t*) &conn->tcp, alloc_buffer, on_read);
	}
}

/* ========================================================================== */
/* Response Methods                                                           */
/* ========================================================================== */

static JSValue tjs_http_response_write_head(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpConnection* conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
	CHECK_CONN(conn);
	CHECK_HEADERS_SENT(conn);

	int32_t status_code = 200;
	if (argc > 0) {
		JS_ToInt32(ctx, &status_code, argv[0]);
	}

	/* Build status line */
	char* response_header = js_malloc(ctx, TJS_HTTP_HEADER_BUFFER_SIZE);
	if (!response_header) return JS_ThrowOutOfMemory(ctx);

	int header_len = snprintf(response_header, TJS_HTTP_HEADER_BUFFER_SIZE,
		"HTTP/1.1 %d OK\r\n", status_code);

	/* Process headers */
	bool has_content_length = false;
	bool has_transfer_encoding = false;
	bool has_connection = false;

	if (argc > 1 && JS_IsObject(argv[1])) {
		JSPropertyEnum* props;
		uint32_t prop_count;

		if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, argv[1],
			JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
			for (uint32_t i = 0; i < prop_count; i++) {
				JSValue key = JS_AtomToString(ctx, props[i].atom);
				JSValue val = JS_GetProperty(ctx, argv[1], props[i].atom);

				const char* key_str = JS_ToCString(ctx, key);
				const char* val_str = JS_ToCString(ctx, val);

				if (key_str && val_str) {
					int needed = header_len + strlen(key_str) + strlen(val_str) + 4;
					if (needed >= TJS_HTTP_HEADER_BUFFER_SIZE) {
						/* Header too large */
						JS_FreeCString(ctx, key_str);
						JS_FreeCString(ctx, val_str);
						JS_FreeValue(ctx, key);
						JS_FreeValue(ctx, val);
						continue;
					}

					header_len += snprintf(response_header + header_len,
						TJS_HTTP_HEADER_BUFFER_SIZE - header_len,
						"%s: %s\r\n", key_str, val_str);

					/* Track special headers */
					if (strcasecmp(key_str, "Content-Length") == 0) {
						has_content_length = true;
						conn->content_length_remaining = atoll(val_str);
						conn->response_mode = RESPONSE_MODE_CONTENT_LENGTH;
					}
					else if (strcasecmp(key_str, "Transfer-Encoding") == 0 &&
						strcasecmp(val_str, "chunked") == 0) {
						has_transfer_encoding = true;
						conn->response_mode = RESPONSE_MODE_CHUNKED;
					}
					else if (strcasecmp(key_str, "Connection") == 0) {
						has_connection = true;
						if (strcasecmp(val_str, "close") == 0) {
							conn->keep_alive = false;
						}
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

	/* Add default headers if not present */
	if (!has_connection) {
		header_len += snprintf(response_header + header_len,
			TJS_HTTP_HEADER_BUFFER_SIZE - header_len,
			"Connection: %s\r\n",
			conn->keep_alive ? "keep-alive" : "close");
	}

	if (!has_content_length && !has_transfer_encoding) {
		/* No content-length or chunked: must close connection */
		conn->response_mode = RESPONSE_MODE_CONNECTION_CLOSE;
		conn->keep_alive = false;
	}

	/* End headers */
	snprintf(response_header + header_len, TJS_HTTP_HEADER_BUFFER_SIZE - header_len,
		"\r\n");

	conn->headers_sent = true;
	write_http_data(conn, response_header, strlen(response_header));
	js_free(ctx, response_header);

	return JS_DupValue(ctx, this_val);
}

static JSValue tjs_http_response_write(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpConnection* conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
	CHECK_CONN(conn);

	if (argc < 1) {
		return JS_ThrowTypeError(ctx, "write requires data");
	}

	if (!conn->headers_sent) {
		return JS_ThrowTypeError(ctx, "Headers not sent. Call writeHead() first");
	}

	size_t len;
	const char* data = NULL;
	bool is_string = false;

	if (JS_IsString(argv[0])) {
		data = JS_ToCStringLen(ctx, &len, argv[0]);
		is_string = true;
	}
	else {
		uint8_t* buf = JS_GetArrayBuffer(ctx, &len, argv[0]);
		if (buf) {
			data = (const char*) buf;
		}
	}

	if (!data) {
		return JS_ThrowTypeError(ctx, "Invalid data type");
	}

	write_http_data(conn, data, len);

	if (is_string) {
		JS_FreeCString(ctx, data);
	}

	return JS_DupValue(ctx, this_val);
}

static JSValue tjs_http_response_end(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpConnection* conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
	CHECK_CONN(conn);

	/* Write final data if provided */
	if (argc > 0 && conn->headers_sent) {
		tjs_http_response_write(ctx, this_val, argc, argv);
	}

	/* Send chunk trailer for chunked encoding */
	if (conn->response_mode == RESPONSE_MODE_CHUNKED) {
		write_http_data(conn, "0\r\n\r\n", 5);
	}

	/* Close if not keep-alive */
	if (!conn->keep_alive) {
		connection_close(conn);
	}

	return JS_UNDEFINED;
}

static JSValue tjs_http_response_send(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpConnection* conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
	CHECK_CONN(conn);
	CHECK_HEADERS_SENT(conn);

	int32_t status_code = 200;
	const char* body = "";
	size_t body_len = 0;
	bool is_string = false;

	if (argc > 0) {
		if (JS_IsNumber(argv[0])) {
			JS_ToInt32(ctx, &status_code, argv[0]);
			if (argc > 1) {
				if (JS_IsString(argv[1])) {
					body = JS_ToCStringLen(ctx, &body_len, argv[1]);
					is_string = true;
				}
				else {
					uint8_t* buf = JS_GetArrayBuffer(ctx, &body_len, argv[1]);
					if (buf) body = (const char*) buf;
				}
			}
		}
		else {
			if (JS_IsString(argv[0])) {
				body = JS_ToCStringLen(ctx, &body_len, argv[0]);
				is_string = true;
			}
			else {
				uint8_t* buf = JS_GetArrayBuffer(ctx, &body_len, argv[0]);
				if (buf) body = (const char*) buf;
			}
		}
	}

	/* Build complete response */
	char header[512];
	int header_len = snprintf(header, sizeof(header),
		"HTTP/1.1 %d OK\r\n"
		"Content-Length: %zu\r\n"
		"Connection: %s\r\n"
		"\r\n",
		status_code, body_len,
		conn->keep_alive ? "keep-alive" : "close");

	/* Send header */
	write_data(conn, header, header_len, true);

	/* Send body */
	if (body_len > 0) {
		write_data(conn, body, body_len, true);
	}

	if (is_string) {
		JS_FreeCString(ctx, body);
	}

	conn->headers_sent = true;
	conn->response_mode = RESPONSE_MODE_CONTENT_LENGTH;

	if (!conn->keep_alive) {
		connection_close(conn);
	}

	return JS_UNDEFINED;
}

static JSValue tjs_http_response_upgrade(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpConnection* conn = JS_GetOpaque2(ctx, this_val, tjs_http_connection_class_id);
	CHECK_CONN(conn);

	/* Stop reading */
	uv_read_stop((uv_stream_t*) &conn->tcp);

	/* Get file descriptor */
	uv_os_fd_t fd;
	int r = uv_fileno((uv_handle_t*) &conn->tcp, &fd);
	if (r != 0) {
		return tjs_throw_errno(ctx, r);
	}

	conn->headers_sent = true;
	conn->keep_alive = false;
	conn->tcp_initialized = false; // avoid close

	connection_close(conn);
	JS_SetOpaque(this_val, NULL);
	return JS_NewInt32(ctx, (int) fd);
}

/* ========================================================================== */
/* Server Management                                                          */
/* ========================================================================== */

static void server_onclose(uv_handle_t* handle) {
	TJSHttpServer* server = handle->data;
	js_free(server->ctx, server);
}

static void tjs_http_server_finalizer(JSRuntime* rt, JSValue val) {
	TJSHttpServer* server = JS_GetOpaque(val, tjs_http_server_class_id);
	if (server) {
		JSContext* ctx = server->ctx;

		if (server->tcp_initialized && !server->closed) {
			uv_close((uv_handle_t*) &server->tcp, server_onclose);
		}

		TJS_FREE_REF(ctx, server->on_request);
		TJS_FREE_REF(ctx, server->on_error);
		TJS_FREE_REF(ctx, server->on_body);
		TJS_FREE_REF(ctx, server->on_accept);
		TJS_FREE_REF(ctx, server->on_complete);
		TJS_FREE_REF(ctx, server->self);
	}
}

static void tjs_http_server_gc_mark(JSRuntime* rt, JSValueConst val, JS_MarkFunc* mark_func) {
	TJSHttpServer* server = JS_GetOpaque(val, tjs_http_server_class_id);
	if (server) {
		JS_MarkValue(rt, server->on_request, mark_func);
		JS_MarkValue(rt, server->on_error, mark_func);
		JS_MarkValue(rt, server->on_body, mark_func);
		JS_MarkValue(rt, server->on_accept, mark_func);
		JS_MarkValue(rt, server->on_complete, mark_func);
	}
}

static void tjs_http_connection_finalizer(JSRuntime* rt, JSValue val) {
	TJSHttpConnection* conn = JS_GetOpaque(val, tjs_http_connection_class_id);
	if (conn) {
		TJS_FREE_REF(conn->server->ctx, conn->request_obj);
		connection_close(conn);
		UNREF(conn);	// js side
	}
}

static void tjs_http_connection_gc_mark(JSRuntime* rt, JSValueConst val, JS_MarkFunc* mark_func) {
	TJSHttpConnection* conn = JS_GetOpaque(val, tjs_http_connection_class_id);
	if (conn) {
		JS_MarkValue(rt, conn->request_obj, mark_func);
		JS_MarkValue(rt, conn->headers_obj, mark_func);
		JS_MarkValue(rt, conn->addrinfo_obj, mark_func);
	}
}

static JSClassDef tjs_http_server_class = {
	"Server",
	.finalizer = tjs_http_server_finalizer,
	.gc_mark = tjs_http_server_gc_mark,
};

static JSClassDef tjs_http_connection_class = {
	"Response",
	.finalizer = tjs_http_connection_finalizer,
	.gc_mark = tjs_http_connection_gc_mark,
};

/* ========================================================================== */
/* Server API                                                                 */
/* ========================================================================== */

static JSValue tjs_http_create_server(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	if (argc < 1 || !JS_IsObject(argv[0])) {
		return JS_ThrowTypeError(ctx, "createServer requires options object");
	}

	JSValue opts = argv[0];

	/* Parse port */
	int32_t port = TJS_HTTP_DEFAULT_PORT;
	JSValue js_port = JS_GetPropertyStr(ctx, opts, "port");
	if (JS_IsNumber(js_port)) {
		JS_ToInt32(ctx, &port, js_port);
	}
	JS_FreeValue(ctx, js_port);

	/* Parse address */
	const char* addr_str = "0.0.0.0";
	JSValue addr_val = JS_GetPropertyStr(ctx, opts, "address");
	if (JS_IsString(addr_val)) {
		addr_str = JS_ToCString(ctx, addr_val);
	}

	struct sockaddr_storage addr;
	int r;
	if (strchr(addr_str, ':')) {
		r = uv_ip6_addr(addr_str, port, (struct sockaddr_in6*) &addr);
	}
	else if (strchr(addr_str, '/')) {
		r = 0;
	}
	else {
		r = uv_ip4_addr(addr_str, port, (struct sockaddr_in*) &addr);
	}

	if (JS_IsString(addr_val)) {
		JS_FreeCString(ctx, addr_str);
	}
	JS_FreeValue(ctx, addr_val);

	if (r != 0) {
		return JS_ThrowTypeError(ctx, "Invalid address");
	}

	/* Parse callbacks */
	JSValue on_request = JS_GetPropertyStr(ctx, opts, "onRequest");
	if (!JS_IsFunction(ctx, on_request)) {
		JS_FreeValue(ctx, on_request);
		return JS_ThrowTypeError(ctx, "onRequest must be a function");
	}

	JSValue on_error = JS_GetPropertyStr(ctx, opts, "onError");
	if (!JS_IsFunction(ctx, on_error)) {
		JS_FreeValue(ctx, on_error);
		on_error = JS_UNDEFINED;
	}

	JSValue on_body = JS_GetPropertyStr(ctx, opts, "onBody");
	if (!JS_IsFunction(ctx, on_body)) {
		JS_FreeValue(ctx, on_body);
		on_body = JS_UNDEFINED;
	}

	JSValue on_accept = JS_GetPropertyStr(ctx, opts, "onAccept");
	if (!JS_IsFunction(ctx, on_accept)) {
		JS_FreeValue(ctx, on_accept);
		on_accept = JS_UNDEFINED;
	}

	JSValue on_complete = JS_GetPropertyStr(ctx, opts, "onComplete");
	if (!JS_IsFunction(ctx, on_complete)) {
		JS_FreeValue(ctx, on_complete);
		on_complete = JS_UNDEFINED;
	}

	/* Create server */
	TJSHttpServer* server = safe_malloc(ctx, sizeof(TJSHttpServer));
	if (!server) {
		TJS_FREE_REF(ctx, on_request);
		TJS_FREE_REF(ctx, on_error);
		TJS_FREE_REF(ctx, on_body);
		TJS_FREE_REF(ctx, on_accept);
		return JS_ThrowOutOfMemory(ctx);
	}

	server->ctx = ctx;
	server->port = port;
	server->closed = false;
	server->tcp_initialized = false;

	TJS_SETPROP(ctx, server->on_request, on_request);
	TJS_SETPROP(ctx, server->on_error, on_error);
	TJS_SETPROP(ctx, server->on_body, on_body);
	TJS_SETPROP(ctx, server->on_accept, on_accept);
	TJS_SETPROP(ctx, server->on_complete, on_complete);

	/* Initialize TCP */
	TJSRuntime* trt = TJS_GetRuntime(ctx);
	uv_loop_t* loop = TJS_GetLoop(trt);

	r = uv_tcp_init(loop, &server->tcp);
	if (r != 0) goto fail;

	server->tcp_initialized = true;
	server->tcp.data = server;

	r = uv_tcp_bind(&server->tcp, (const struct sockaddr*) &addr, 0);
	if (r != 0) goto fail;

	r = uv_listen((uv_stream_t*) &server->tcp, TJS_HTTP_DEFAULT_BACKLOG,
		on_new_connection);
	if (r != 0) goto fail;

	/* Create JS object */
	JSValue obj = JS_NewObjectClass(ctx, tjs_http_server_class_id);
	JS_SetOpaque(obj, server);
	TJS_SETPROP(ctx, server->self, obj);

	return obj;

fail:
	if (server->tcp_initialized) {
		uv_close((uv_handle_t*) &server->tcp, NULL);
	}
	TJS_FREE_REF(ctx, server->on_request);
	TJS_FREE_REF(ctx, server->on_error);
	TJS_FREE_REF(ctx, server->on_body);
	TJS_FREE_REF(ctx, server->on_accept);
	TJS_FREE_REF(ctx, server->on_complete);
	js_free(ctx, server);
	return tjs_throw_errno(ctx, r);
}

static JSValue tjs_http_server_close(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpServer* server = JS_GetOpaque2(ctx, this_val, tjs_http_server_class_id);
	if (!server) return JS_EXCEPTION;

	if (!server->closed && server->tcp_initialized) {
		server->closed = true;
		uv_close((uv_handle_t*) &server->tcp, NULL);
	}

	return JS_UNDEFINED;
}

static JSValue tjs_http_server_address(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSHttpServer* server = JS_GetOpaque2(ctx, this_val, tjs_http_server_class_id);
	if (!server) return JS_EXCEPTION;

	struct sockaddr_storage addr;
	int addr_len = sizeof(addr);

	if (uv_tcp_getsockname(&server->tcp, (struct sockaddr*) &addr, &addr_len) != 0) {
		return JS_NULL;
	}

	JSValue obj = JS_NewObject(ctx);

	if (addr.ss_family == AF_INET) {
		struct sockaddr_in* addr_in = (struct sockaddr_in*) &addr;
		char ip[INET_ADDRSTRLEN];
		uv_ip4_name(addr_in, ip, sizeof(ip));
		JS_SetPropertyStr(ctx, obj, "address", JS_NewString(ctx, ip));
		JS_SetPropertyStr(ctx, obj, "port", JS_NewInt32(ctx, ntohs(addr_in->sin_port)));
		JS_SetPropertyStr(ctx, obj, "family", JS_NewString(ctx, "IPv4"));
	}
	else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*) &addr;
		char ip[INET6_ADDRSTRLEN];
		uv_ip6_name(addr_in6, ip, sizeof(ip));
		JS_SetPropertyStr(ctx, obj, "address", JS_NewString(ctx, ip));
		JS_SetPropertyStr(ctx, obj, "port", JS_NewInt32(ctx, ntohs(addr_in6->sin6_port)));
		JS_SetPropertyStr(ctx, obj, "family", JS_NewString(ctx, "IPv6"));
	}

	return obj;
}

/* ========================================================================== */
/* Module Initialization                                                      */
/* ========================================================================== */

static const JSCFunctionListEntry tjs_http_server_proto_funcs[] = {
	TJS_CFUNC_DEF("close", 0, tjs_http_server_close),
	TJS_CFUNC_DEF("address", 0, tjs_http_server_address),
};

static const JSCFunctionListEntry tjs_http_response_proto_funcs[] = {
	TJS_CFUNC_DEF("writeHead", 2, tjs_http_response_write_head),
	TJS_CFUNC_DEF("write", 1, tjs_http_response_write),
	TJS_CFUNC_DEF("end", 1, tjs_http_response_end),
	TJS_CFUNC_DEF("send", 2, tjs_http_response_send),
	TJS_CFUNC_DEF("upgrade", 0, tjs_http_response_upgrade),
};

static const JSCFunctionListEntry tjs_http_funcs[] = {
	TJS_CFUNC_DEF("createServer", 1, tjs_http_create_server),
};

void tjs__mod_server_init(JSContext* ctx, JSValue ns) {
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
