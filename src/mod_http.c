/*
 * txiki.js llhttp thin wrapper module
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

 /* ----------------------------- event ids ----------------------------- */

typedef enum {
	EV_MESSAGE_BEGIN = 0,
	EV_URL,
	EV_STATUS,
	EV_HEADER_FIELD,
	EV_HEADER_VALUE,
	EV_HEADERS_COMPLETE,
	EV_BODY,
	EV_MESSAGE_COMPLETE,
	EV_CHUNK_HEADER,
	EV_CHUNK_COMPLETE,

	EV_MAX
} TJSLlhttpEvent;

/* ----------------------------- class data ---------------------------- */

typedef struct {
	JSContext* ctx;

	llhttp_t parser;
	llhttp_settings_t settings;

	int type; /* REQUEST / RESPONSE */

	/* JS callback */
	JSValue events[EV_MAX];

	/* During execute(): current buffer kept alive */
	JSValue current_buf;      /* dup of execute() argument */
	const uint8_t* cur_base;  /* raw bytes for offset computation */
	size_t cur_len;

	/* If callback throws, we store the exception and stop parsing */
	JSValue pending_exc;

	bool initialized;
	bool running;
	bool pause_requested;
} TJSLlhttpParser;

static thread_local JSClassID tjs_llhttp_parser_class_id;

/* ----------------------------- helpers ------------------------------ */

static inline void tjs_llhttp_set_ref(JSContext* ctx, JSValue* slot, JSValue v) {
	JS_FreeValue(ctx, *slot);
	*slot = v;
}

static inline void tjs_llhttp_init_ref(JSValue* slot) {
	*slot = JS_UNDEFINED;
}

static inline const char* tjs_llhttp_event_name(TJSLlhttpEvent ev) {
	switch (ev){
		case EV_MESSAGE_BEGIN: return "messageBegin";
		case EV_URL: return "url";
		case EV_STATUS: return "status";
		case EV_HEADER_FIELD: return "headerField";
		case EV_HEADER_VALUE: return "headerValue";
		case EV_HEADERS_COMPLETE: return "headersComplete";
		case EV_BODY: return "body";
		case EV_MESSAGE_COMPLETE: return "messageComplete";
		case EV_CHUNK_HEADER: return "chunkHeader";
		case EV_CHUNK_COMPLETE: return "chunkComplete";
		default: return "unknown";
	}
}

/* Whether the event is critical and should stop parsing if it throws */
/* Mostly for data field that data cannot be ignored */
static inline bool tjs_llhttp_critical_event(TJSLlhttpEvent ev) {
	switch (ev) {
		case EV_URL:
		case EV_STATUS:
		case EV_HEADER_FIELD:
		case EV_HEADER_VALUE:
		case EV_BODY:
			return true;
		default:
			return false;
	}
}

static int tjs_llhttp_emit(TJSLlhttpParser* p, TJSLlhttpEvent ev, const char* at, size_t length) {
	JSContext* ctx = p->ctx;
	JSValue on_event = p->events[ev];
	bool critical = tjs_llhttp_critical_event(ev);

	if (JS_IsUndefined(on_event)) {
		if (critical) {
			/* Throw TypeError if no event handler and capture & store exception */
			JS_ThrowTypeError(ctx, "no event handler for %s", tjs_llhttp_event_name(ev));
			JSValue exc = JS_GetException(ctx);
			tjs_llhttp_set_ref(ctx, &p->pending_exc, exc);
			return HPE_USER;
		}
		return 0;
	}

	/* Compute offset inside current buffer (must be the same chunk passed to execute) */
	size_t off = 0;
	if (at != NULL && p->cur_base != NULL) {
		const uint8_t* uat = (const uint8_t*) at;
		if (uat >= p->cur_base && uat <= (p->cur_base + p->cur_len)) {
			off = (size_t) (uat - p->cur_base);
		}
		else {
			/* Not expected with llhttp: slices should point into provided buffer.
			   If not, fall back to 0 (JS may ignore) */
			off = 0;
		}
	}

	JSValue argv[] = {
		JS_DupValue(ctx, p->current_buf),
		JS_NewUint32(ctx, (uint32_t) off),
		JS_NewUint32(ctx, (uint32_t) length)
	};

	JSValue ret = JS_Call(ctx, on_event, JS_UNDEFINED, countof(argv), argv);

	for (int i = 0; i < countof(argv); i++)
		JS_FreeValue(ctx, argv[i]);

	if (JS_IsException(ret)) {
		JS_FreeValue(ctx, ret);

		if (critical) {
			/* capture & store exception, and stop parsing */
			JSValue exc = JS_GetException(ctx);
			tjs_llhttp_set_ref(ctx, &p->pending_exc, exc);
			return HPE_USER;
		}
		/* Non-critical event: swallow the error, but clear the pending
		 * exception so it cannot leak into later parsing or unrelated JS. */
		JS_FreeValue(ctx, JS_GetException(ctx));
		return 0;
	}

	JS_FreeValue(ctx, ret);
	if (p->pause_requested) {
		p->pause_requested = false;
		return HPE_PAUSED;
	}
	return 0;
}

/* ------------------------- llhttp callbacks -------------------------- */

static int cb_message_begin(llhttp_t* parser) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_MESSAGE_BEGIN, NULL, 0);
}

static int cb_url(llhttp_t* parser, const char* at, size_t length) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_URL, at, length);
}

static int cb_status(llhttp_t* parser, const char* at, size_t length) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_STATUS, at, length);
}

static int cb_header_field(llhttp_t* parser, const char* at, size_t length) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_HEADER_FIELD, at, length);
}

static int cb_header_value(llhttp_t* parser, const char* at, size_t length) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_HEADER_VALUE, at, length);
}

static int cb_headers_complete(llhttp_t* parser) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_HEADERS_COMPLETE, NULL, 0);
}

static int cb_body(llhttp_t* parser, const char* at, size_t length) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_BODY, at, length);
}

static int cb_message_complete(llhttp_t* parser) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_MESSAGE_COMPLETE, NULL, 0);
}

static int cb_chunk_header(llhttp_t* parser) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_CHUNK_HEADER, NULL, 0);
}

static int cb_chunk_complete(llhttp_t* parser) {
	TJSLlhttpParser* p = (TJSLlhttpParser*) parser->data;
	return tjs_llhttp_emit(p, EV_CHUNK_COMPLETE, NULL, 0);
}

/* --------------------------- lifecycle ------------------------------ */

static void tjs_llhttp_parser_init_llhttp(TJSLlhttpParser* p, int type) {
	memset(&p->settings, 0, sizeof(p->settings));

	p->settings.on_message_begin = cb_message_begin;
	p->settings.on_url = cb_url;
	p->settings.on_status = cb_status;
	p->settings.on_header_field = cb_header_field;
	p->settings.on_header_value = cb_header_value;
	p->settings.on_headers_complete = cb_headers_complete;
	p->settings.on_body = cb_body;
	p->settings.on_message_complete = cb_message_complete;
	p->settings.on_chunk_header = cb_chunk_header;
	p->settings.on_chunk_complete = cb_chunk_complete;

	llhttp_init(&p->parser, (llhttp_type_t) type, &p->settings);
	p->parser.data = p;

	p->type = type;
	p->initialized = true;
}

static void tjs_llhttp_parser_finalizer(JSRuntime* rt, JSValue val) {
	TJSLlhttpParser* p = JS_GetOpaque(val, tjs_llhttp_parser_class_id);
	if (!p) return;

	for (int i = 0; i < EV_MAX; i++)
		JS_FreeValueRT(rt, p->events[i]);
	JS_FreeValueRT(rt, p->current_buf);
	JS_FreeValueRT(rt, p->pending_exc);

	js_free_rt(rt, p);
}

static void tjs_llhttp_parser_mark(JSRuntime* rt, JSValueConst val, JS_MarkFunc* mark_func) {
	TJSLlhttpParser* p = JS_GetOpaque(val, tjs_llhttp_parser_class_id);
	if (!p) return;

	for (int i = 0; i < EV_MAX; i++)
		JS_MarkValue(rt, p->events[i], mark_func);
	JS_MarkValue(rt, p->current_buf, mark_func);
	JS_MarkValue(rt, p->pending_exc, mark_func);
}

static JSClassDef tjs_llhttp_parser_class = {
  "HTTPParser",
  .finalizer = tjs_llhttp_parser_finalizer,
  .gc_mark = tjs_llhttp_parser_mark,
};

/* ----------------------------- ctor --------------------------------- */

static JSValue tjs_llhttp_parser_ctor(JSContext* ctx, JSValueConst new_target,
	int argc, JSValueConst* argv) {
	int32_t type32 = 2;		// HTTP_BOTH = 2
	if (argc > 0) {
		if (JS_ToInt32(ctx, &type32, argv[0]) == -1) return JS_EXCEPTION;
		// 0 = HTTP_REQUEST, 1 = HTTP_RESPONSE, 2 = HTTP_BOTH
		if (type32 < 0 || type32 > 2) {
			return JS_ThrowRangeError(ctx, "invalid parser type");
		}
	}

	JSValue obj = JS_NewObjectClass(ctx, tjs_llhttp_parser_class_id);
	if (JS_IsException(obj)) return obj;

	TJSLlhttpParser* p = js_mallocz(ctx, sizeof(*p));
	if (!p) {
		JS_FreeValue(ctx, obj);
		return JS_ThrowOutOfMemory(ctx);
	}

	p->ctx = ctx;
	for (int i = 0; i < EV_MAX; i++)
		tjs_llhttp_init_ref(&p->events[i]);
	tjs_llhttp_init_ref(&p->current_buf);
	tjs_llhttp_init_ref(&p->pending_exc);
	p->cur_base = NULL;
	p->cur_len = 0;
	p->running = false;
	p->pause_requested = false;

	tjs_llhttp_parser_init_llhttp(p, type32);

	JS_SetOpaque(obj, p);
	(void) new_target;
	return obj;
}

/* ---------------------------- methods -------------------------------- */

static TJSLlhttpParser* tjs_llhttp_parser_get(JSContext* ctx, JSValueConst this_val) {
	return JS_GetOpaque2(ctx, this_val, tjs_llhttp_parser_class_id);
}

static JSValue tjs_llhttp_set_on_event(JSContext* ctx, JSValueConst this_val, JSValue set_value, int magic) {
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;

	assert(magic >= 0 && magic < EV_MAX);

	if (!JS_IsFunction(ctx, set_value) && !JS_IsUndefined(set_value)) {
		return JS_ThrowTypeError(ctx, "callback must be a function");
	}

	tjs_llhttp_set_ref(ctx, &p->events[magic], JS_DupValue(ctx, set_value));
	return JS_UNDEFINED;
}

static JSValue tjs_llhttp_get_on_event(JSContext* ctx, JSValueConst this_val, int magic) {
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;

	assert(magic >= 0 && magic < EV_MAX);

	return JS_DupValue(ctx, p->events[magic]);
}

static JSValue tjs_llhttp_execute(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;
	if (p->running) {
		return JS_ThrowInternalError(ctx, "parser is already executing");
	}
	if (argc == 0) {
		return JS_ThrowTypeError(ctx, "execute expects a buffer");
	}

	size_t len = 0;
	uint8_t* data = JS_GetAnyBuffer(ctx, &len, argv[0]);
	if (!data) return JS_EXCEPTION;
	uint8_t* parse_data = js_malloc(ctx, len ? len : 1);
	if (!parse_data) return JS_ThrowOutOfMemory(ctx);
	memcpy(parse_data, data, len);

	/* clear pending exception before running */
	if (!JS_IsUndefined(p->pending_exc)) {
		JS_FreeValue(ctx, p->pending_exc);
		p->pending_exc = JS_UNDEFINED;
	}

	tjs_llhttp_set_ref(ctx, &p->current_buf, JS_DupValue(ctx, argv[0]));

	p->cur_base = (const uint8_t*) parse_data;
	p->cur_len = len;
	p->running = true;
	p->pause_requested = false;

	llhttp_errno_t err = llhttp_execute(&p->parser, (const char*) parse_data, len);

	/* release current buffer ref */
	p->running = false;
	tjs_llhttp_set_ref(ctx, &p->current_buf, JS_UNDEFINED);
	p->cur_base = NULL;
	p->cur_len = 0;

	/* If callback threw, rethrow that exception */
	if (!JS_IsUndefined(p->pending_exc)) {
		JSValue exc = p->pending_exc;
		p->pending_exc = JS_UNDEFINED;
		js_free(ctx, parse_data);
		return JS_Throw(ctx, exc);
	}

	/* Return result object (even on error) so JS can decide */
	JSValue res = JS_NewObject(ctx);

	JS_SetPropertyStr(ctx, res, "errno", JS_NewInt32(ctx, (int32_t) err));
	JS_SetPropertyStr(ctx, res, "name", JS_NewString(ctx, llhttp_errno_name(err)));

	const char* reason = llhttp_get_error_reason(&p->parser);
	if (reason) {
		JS_SetPropertyStr(ctx, res, "reason", JS_NewString(ctx, reason));
	} else {
		JS_SetPropertyStr(ctx, res, "reason", JS_NULL);
	}

	/* bytes consumed: error_pos points to where error occurred; if OK, it's end */
	const char* err_pos = llhttp_get_error_pos(&p->parser);
	if (err_pos) {
		JS_SetPropertyStr(ctx, res, "bytesConsumed",
			JS_NewUint32(ctx, (uint32_t) ((const uint8_t*) err_pos - (const uint8_t*) parse_data)));
	} else {
		JS_SetPropertyStr(ctx, res, "bytesConsumed", JS_NewUint32(ctx, (uint32_t) len));
	}

	js_free(ctx, parse_data);
	return res;
}

static JSValue tjs_llhttp_pause(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	(void) argc; (void) argv;
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;
	if (p->running) {
		p->pause_requested = true;
		return JS_UNDEFINED;
	}
	llhttp_pause(&p->parser);
	return JS_UNDEFINED;
}

static JSValue tjs_llhttp_resume(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	(void) argc; (void) argv;
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;
	if (p->running) return JS_ThrowInternalError(ctx, "parser is executing");
	llhttp_resume(&p->parser);
	return JS_UNDEFINED;
}

static JSValue tjs_llhttp_reset(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;
	if (p->running) return JS_ThrowInternalError(ctx, "parser is executing");

	int32_t type32 = p->type;
	if (argc > 0 && !JS_IsUndefined(argv[0])) {
		if (JS_ToInt32(ctx, &type32, argv[0]) < 0) return JS_EXCEPTION;
		if (type32 < 0 || type32 > 2) {
			return JS_ThrowRangeError(ctx, "invalid parser type");
		}
	}

	llhttp_reset(&p->parser);
	tjs_llhttp_parser_init_llhttp(p, type32);

	return JS_UNDEFINED;
}

static JSValue tjs_llhttp_finish(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	(void) argc; (void) argv;
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;
	if (p->running) return JS_ThrowInternalError(ctx, "parser is executing");

	llhttp_errno_t err = llhttp_finish(&p->parser);

	JSValue res = JS_NewObject(ctx);
	JS_SetPropertyStr(ctx, res, "errno", JS_NewInt32(ctx, (int32_t) err));
	JS_SetPropertyStr(ctx, res, "name", JS_NewString(ctx, llhttp_errno_name(err)));

	const char* reason = llhttp_get_error_reason(&p->parser);
	JS_SetPropertyStr(ctx, res, "reason", reason ? JS_NewString(ctx, reason) : JS_NULL);
	return res;
}

static JSValue tjs_llhttp_get_state(JSContext* ctx, JSValueConst this_val) {
	TJSLlhttpParser* p = tjs_llhttp_parser_get(ctx, this_val);
	if (!p) return JS_EXCEPTION;

	JSValue st = JS_NewObject(ctx);
	JS_SetPropertyStr(ctx, st, "type", JS_NewInt32(ctx, p->type));
	JS_SetPropertyStr(ctx, st, "httpMajor", JS_NewInt32(ctx, p->parser.http_major));
	JS_SetPropertyStr(ctx, st, "httpMinor", JS_NewInt32(ctx, p->parser.http_minor));
	JS_SetPropertyStr(ctx, st, "status", JS_NewInt32(ctx, p->parser.status_code));
	JS_SetPropertyStr(ctx, st, "method", JS_NewInt32(ctx, p->parser.method));
	JS_SetPropertyStr(ctx, st, "upgrade", JS_NewBool(ctx, p->parser.upgrade));
	JS_SetPropertyStr(ctx, st, "keepAlive", JS_NewBool(ctx, llhttp_should_keep_alive(&p->parser)));

	JS_SetPropertyStr(ctx, st, "errno", JS_NewInt32(ctx, (int32_t) llhttp_get_errno(&p->parser)));
	JS_SetPropertyStr(ctx, st, "eof", JS_NewBool(ctx, llhttp_message_needs_eof(&p->parser)));
	return st;
}

static const JSCFunctionListEntry tjs_llhttp_parser_proto_funcs[] = {
	TJS_CFUNC_DEF("execute", 1, tjs_llhttp_execute),
	TJS_CFUNC_DEF("pause", 0, tjs_llhttp_pause),
	TJS_CFUNC_DEF("resume", 0, tjs_llhttp_resume),
	TJS_CFUNC_DEF("reset", 0, tjs_llhttp_reset),
	TJS_CFUNC_DEF("finish", 0, tjs_llhttp_finish),
	JS_CGETSET_DEF("state", tjs_llhttp_get_state, NULL),

	// callbacks
#define TJS_LLHTTP_CB(name, magic) JS_CGETSET_MAGIC_DEF(name, tjs_llhttp_get_on_event, tjs_llhttp_set_on_event, magic),
	TJS_LLHTTP_CB("onMessageBegin", EV_MESSAGE_BEGIN)
	TJS_LLHTTP_CB("onUrl", EV_URL)
	TJS_LLHTTP_CB("onStatus", EV_STATUS)
	TJS_LLHTTP_CB("onHeaderField", EV_HEADER_FIELD)
	TJS_LLHTTP_CB("onHeaderValue", EV_HEADER_VALUE)
	TJS_LLHTTP_CB("onHeadersComplete", EV_HEADERS_COMPLETE)
	TJS_LLHTTP_CB("onBody", EV_BODY)
	TJS_LLHTTP_CB("onMessageComplete", EV_MESSAGE_COMPLETE)
	TJS_LLHTTP_CB("onChunkHeader", EV_CHUNK_HEADER)
	TJS_LLHTTP_CB("onChunkComplete", EV_CHUNK_COMPLETE)
#undef TJS_LLHTTP_CB
};

static JSValue tjs_llhttp_static_strerr(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
	if (argc == 0 || !JS_IsNumber(argv[0])) {
		return JS_ThrowTypeError(ctx, "strerr expects an integer error code");
	}

	int32_t err = 0;
	JS_ToInt32(ctx, &err, argv[0]);
	const char* name = llhttp_errno_name((llhttp_errno_t) err);
	return name ? JS_NewString(ctx, name) : JS_NULL;
}

static JSValue tjs_llhttp_static_status_text(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
	if (argc == 0 || !JS_IsNumber(argv[0])) {
		return JS_ThrowTypeError(ctx, "statusText expects an integer status code");
	}

	int32_t status;
	if (-1 == JS_ToInt32(ctx, &status, argv[0]) || status < 100 || status >= 600) {
		return JS_ThrowTypeError(ctx, "status code invalid. expects an integer between 100 and 599");
	}
	
	const char* name = llhttp_status_name((llhttp_status_t ) status);
	return name ? JS_NewString(ctx, name) : JS_NULL;
}

static const JSCFunctionListEntry tjs_module_consts[] = {
	TJS_CONST2("REQUEST", HTTP_REQUEST),
	TJS_CONST2("RESPONSE", HTTP_RESPONSE),

	TJS_CFUNC_DEF("strerr", 1, tjs_llhttp_static_strerr),
	TJS_CFUNC_DEF("strstatus", 1, tjs_llhttp_static_status_text),
};

/* ------------------------ module init -------------------------------- */

void tjs__mod_http_init(JSContext* ctx, JSValue ns) {
	JSRuntime* rt = JS_GetRuntime(ctx);

	JS_NewClassID(rt, &tjs_llhttp_parser_class_id);
	JS_NewClass(rt, tjs_llhttp_parser_class_id, &tjs_llhttp_parser_class);

	/* prototype */
	JSValue proto = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, proto, tjs_llhttp_parser_proto_funcs,
		countof(tjs_llhttp_parser_proto_funcs));
	JS_SetClassProto(ctx, tjs_llhttp_parser_class_id, proto);

	/* constructor */
	JSValue ctor = JS_NewCFunction2(ctx, tjs_llhttp_parser_ctor, "Parser", 2,
		JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, ctor, proto);

	/* export constants */
	JS_SetPropertyFunctionList(ctx, ns, tjs_module_consts, countof(tjs_module_consts));

	JS_SetPropertyStr(ctx, ns, "Parser", ctor);
}
