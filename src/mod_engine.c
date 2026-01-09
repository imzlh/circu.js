/*
 * circu.js
 *
 * Copyright (c) 2024-present Saúl Ibarra Corretgé <s@saghul.net>
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
#include "version.h"

#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <uv.h>
#include <curl/curl.h>
#include <openssl/opensslv.h>
#include <expat.h>
#include <zlib.h>

#ifdef CJS__HAS_MIMALLOC
#include <mimalloc.h>
#endif

#include <llhttp.h>
#define LLHTTP_VERSION STRINGIFY(LLHTTP_VERSION_MAJOR) "." STRINGIFY(LLHTTP_VERSION_MINOR) "." STRINGIFY(LLHTTP_VERSION_PATCH)

static JSValue tjs_gc_run(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    JS_RunGC(JS_GetRuntime(ctx));
    return JS_UNDEFINED;
}

static JSValue tjs_gc_setThreshold(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    int64_t value;

    if (JS_ToInt64(ctx, &value, argv[0])) {
        return JS_EXCEPTION;
    }

    JS_SetGCThreshold(JS_GetRuntime(ctx), value);

    return JS_UNDEFINED;
}

static JSValue tjs_gc_getThreshold(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return JS_NewNumber(ctx, JS_GetGCThreshold(JS_GetRuntime(ctx)));
}


// fixme: thread_local?
static JSClassID js_module_class_id;

static inline JSValue module_new(JSContext* ctx, JSModuleDef* def){
    JSValue obj = JS_NewObjectClass(ctx, js_module_class_id);
    JS_SetOpaque(obj, def);
    return obj;
}

static JSValue js_module_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    if(argc < 2 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "loadModule() requires 2 argument");
    }

    size_t len;
    const char *source = JS_ToCStringLen(ctx, &len, argv[0]);
    if(!source) return JS_EXCEPTION;
	const char *_mname = JS_ToCString(ctx, argv[1]);
	const char *module_name = _mname;
	if(!_mname) module_name = "<module>";

    JSValue compiled = JS_Eval(ctx, source, len, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_FLAG_BACKTRACE_BARRIER);
    if(JS_IsException(compiled)) goto fail;

    JS_FreeCString(ctx, source);
    if(_mname) JS_FreeCString(ctx, _mname);
    return module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(compiled));
fail:
    JS_FreeCString(ctx, source);
    if(_mname) JS_FreeCString(ctx, _mname);
    return JS_EXCEPTION;
}

static JSValue js_module_eval(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
	if(!def) return JS_EXCEPTION;
	return JS_EvalFunction(ctx, JS_MKPTR(JS_TAG_MODULE, def));
}

static JSValue js_module_get_ptr(JSContext *ctx, JSValueConst this_val){
    return 
#if __SIZEOF_POINTER__ == 8
    JS_NewInt64
#else
    JS_NewInt32
#endif
    (ctx, (uintptr_t)JS_GetOpaque(this_val, js_module_class_id));
}

static void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr){
	js_free_rt(rt, ptr);
}

static JSValue js_module_dump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!def) return JS_EXCEPTION;

	int flags = JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE;
	if (argc != 0 && -1 == JS_ToInt32(ctx, &flags, argv[0])) {
		return JS_ThrowTypeError(ctx, "invalid flags. expect number mask or undefined");
	}

    size_t len = 0;
    uint8_t *data = JS_WriteObject(ctx, &len, JS_MKPTR(JS_TAG_MODULE, def), flags);
    if(!data) return JS_EXCEPTION;

    return JS_NewArrayBuffer(ctx, data, len, free_js_malloc, NULL, false);
}

static JSValue js_module_get_meta(JSContext* ctx, JSValueConst this_val){
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!def) return JS_EXCEPTION;
    return JS_GetImportMeta(ctx, def);
}

JSModuleDef* tjs__module_getdef(JSContext* ctx, JSValueConst this_val){
    JSModuleDef* def = (JSModuleDef*)JS_GetOpaque(this_val, js_module_class_id);
    return def;
}

JSValue tjs__new_module(JSContext* ctx, JSModuleDef* def){
	return module_new(ctx, def);
}

static const JSClassDef js_module_class = {
    "Module",
	// module do not require finalize
    // .finalizer = js_module_finalizer,
};

static const JSCFunctionListEntry js_module_proto_funcs[] = {
    JS_CGETSET_DEF("ptr", js_module_get_ptr, NULL),
    JS_CFUNC_DEF("dump", 0, js_module_dump),
    JS_CGETSET_DEF("meta", js_module_get_meta, NULL),
	JS_CFUNC_DEF("eval", 0, js_module_eval),
};

static JSValue tjs_setMemoryLimit(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    uint32_t v;
    if (JS_ToUint32(ctx, &v, argv[0])) {
        return JS_EXCEPTION;
    }
    JS_SetMemoryLimit(JS_GetRuntime(ctx), v);
    return JS_UNDEFINED;
}

static JSValue tjs_setMaxStackSize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    uint32_t v;
    if (JS_ToUint32(ctx, &v, argv[0])) {
        return JS_EXCEPTION;
    }
    JS_SetMaxStackSize(JS_GetRuntime(ctx), v);
    return JS_UNDEFINED;
}

static JSValue tjs_compile(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    size_t len = 0;
    const uint8_t *tmp = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!tmp) {
        return JS_EXCEPTION;
    }
    // We need to copy the buffer in order to null-terminate it, which JS_Eval needs.
    uint8_t *buf = js_malloc(ctx, len + 1);
    if (!buf) {
        return JS_EXCEPTION;
    }
    memcpy(buf, tmp, len);
    buf[len] = '\0';
    const char *module_name = JS_ToCString(ctx, argv[1]);
    if (!module_name) {
        js_free(ctx, buf);
        return JS_EXCEPTION;
    }
    int eval_flags = JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_TYPE_MODULE;
    JSValue obj = JS_Eval(ctx, (const char *) buf, len, module_name, eval_flags);
    JS_FreeCString(ctx, module_name);
    js_free(ctx, buf);
    return obj;
}

static JSValue tjs_serialize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    size_t len = 0;
    int flags = JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE;

	if (argc == 0) return JS_ThrowTypeError(ctx, "missing argument");

	if (argc >= 2 && -1 == JS_ToInt32(ctx, &flags, argv[1])) {
		return JS_ThrowTypeError(ctx, "invalid flags. expect number mask or undefined");
	}

    uint8_t *buf = JS_WriteObject(ctx, &len, argv[0], flags);
    if (!buf) {
        return JS_EXCEPTION;
    }
    JSValue ret = TJS_NewUint8Array(ctx, buf, len);
    if (JS_IsException(ret)) {
        js_free(ctx, buf);
    }
    return ret;
}

static JSValue tjs_deserialize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    size_t len = 0;
    int flags = JS_READ_OBJ_BYTECODE | JS_READ_OBJ_REFERENCE | JS_READ_OBJ_SAB;
    const uint8_t *buf = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!buf) {
        return JS_EXCEPTION;
    }
    JSValue ret = JS_ReadObject(ctx, buf, len, flags);
	switch (JS_VALUE_GET_NORM_TAG(ret)){
		case JS_TAG_MODULE:
			return module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(ret));

		case JS_TAG_FUNCTION_BYTECODE:
			// to do...

		default:
			return ret;
	}
}

static JSValue tjs_evalBytecode(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    JSValue obj = argv[0];

    if (JS_IsException(obj)) {
        return JS_EXCEPTION;
    }

    if (JS_VALUE_GET_TAG(obj) == JS_TAG_MODULE) {
        if (JS_ResolveModule(ctx, obj) < 0) {
            return JS_EXCEPTION;
        }

        js_module_set_import_meta(ctx, obj, false, false);
    }

    return JS_EvalFunction(ctx, obj);
}

#define IFOPT(optname, optcheckfunc, then) \
	valtmp = JS_GetPropertyStr(ctx, argv[0], optname); \
	if (optcheckfunc(valtmp)) then \
	else JS_FreeValue(ctx, valtmp)
#define IFOPT2(optname, optcheckfunc, then) \
	valtmp = JS_GetPropertyStr(ctx, argv[0], optname); \
	if (optcheckfunc(ctx, valtmp)) then \
	else JS_FreeValue(ctx, valtmp)
static JSValue tjs__override_module_options(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if(argc == 0 || !JS_IsObject(argv[0])){
		return JS_ThrowTypeError(ctx, "options must be an object");
	}

	TJSRuntime* trt = JS_GetContextOpaque(ctx);
	assert(trt != NULL);
	JSValue valtmp = JS_UNDEFINED;
	IFOPT2("load", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.loader);
		trt->module.loader = valtmp;
	});
	IFOPT2("resolve", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.resolver);
		trt->module.resolver = valtmp;
	});
	IFOPT2("init", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.metaloader);
		trt->module.metaloader = valtmp;
	});
	IFOPT2("attrchk", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.attrchecker);
		trt->module.attrchecker = valtmp;
	});

	return JS_UNDEFINED;
}
#undef IFOPT
#undef IFOPT2

static JSValue tjs__set_event_receiver(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if (argc == 0 || !JS_IsFunction(ctx, argv[0])){
		return JS_ThrowTypeError(ctx, "argument must be a function");
	}

	TJSRuntime* trt = TJS_GetRuntime(ctx);
	trt->builtins.dispatch_event_func = JS_DupValue(ctx, argv[0]);
	return JS_UNDEFINED;
}

static JSValue tjs_encodeString(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "argument must be a string");
	}

	size_t strlen;
	const char* str = JS_ToCStringLen(ctx, &strlen, argv[0]);
	JSValue buffer = JS_NewUint8ArrayCopy(ctx, (uint8_t*)str, strlen);
	JS_FreeCString(ctx, str);
	return buffer;
}

static JSValue tjs_decodeString(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0){
typerr:
		return JS_ThrowTypeError(ctx, "argument must be an ArrayBuffer or Uint8Array");
	}

	uint8_t* buf = NULL;
	size_t buflen;
	if (JS_GetTypedArrayType(argv[0]) != -1){
		buf = JS_GetUint8Array(ctx, &buflen, argv[0]);
	} else if (JS_IsArrayBuffer(argv[0])) {
		buf = JS_GetArrayBuffer(ctx, &buflen, argv[0]);
	}

	if (!buf){
		goto typerr;
	}

	JSValue str = JS_NewStringLen(ctx, (char*)buf, buflen);
	return str;
}

static JSValue tjs_encodeU16String(JSContext* ctx, JSValue this_val, int argc, JSValue* argv){
	if(argc == 0 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "argument must be a string");
	}

	size_t strlen;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &strlen, argv[0]);
	JSValue buffer = JS_NewArrayBufferCopy(ctx, (const uint8_t*)str, strlen *2);
	JS_FreeCStringUTF16(ctx, str);

	// to Uint16Array
	JSValue global = JS_GetGlobalObject(ctx);
	JSValue u16arrctor = JS_GetPropertyStr(ctx, global, "Uint16Array");	
	if (!JS_IsFunction(ctx, u16arrctor)) {
		JS_FreeValue(ctx, u16arrctor);
		JS_FreeValue(ctx, global);
		JS_FreeValue(ctx, buffer);
		return JS_ThrowTypeError(ctx, "Uint16Array constructor not found");
	}
	JSValue u16arr = JS_Call(ctx, u16arrctor, u16arrctor, 1, (JSValueConst[]) { buffer });
	JS_FreeValue(ctx, buffer);
	JS_FreeValue(ctx, u16arrctor);
	JS_FreeValue(ctx, global);

	return u16arr;
}

static JSValue tjs_decodeU16String(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0){
typerr:
		return JS_ThrowTypeError(ctx, "argument must be an ArrayBuffer or Uint16Array");
	}

	size_t buflen;
	uint8_t* u8 = JS_GetAnyBuffer(ctx, &buflen, argv[0]);
	if (!u8){
		goto typerr;
	}

	size_t u16len = buflen /2;
	JSValue str = JS_NewStringUTF16(ctx, (uint16_t*)u8, u16len);
	return str;
}


static JSValue tjs_proimise_result(JSContext* ctx, JSValueConst promise, int argc, JSValueConst* argv) {
	if (argc == 0 || !JS_IsPromise(promise)) {
		return JS_ThrowTypeError(ctx, "argument must be a Promise");
	}

	JSPromiseStateEnum state = JS_PromiseState(ctx, promise);
	JSValue err;
	switch (state) {
		case JS_PROMISE_PENDING:
		return JS_NULL;

		case JS_PROMISE_FULFILLED:
		return JS_PromiseResult(ctx, promise);

		case JS_PROMISE_REJECTED:
			err = JS_PromiseResult(ctx, promise);
		return JS_Throw(ctx, err);

		default: abort();
	}
}

static const JSCFunctionListEntry tjs_engine_funcs[] = {
    TJS_CFUNC_DEF("setMemoryLimit", 1, tjs_setMemoryLimit),
    TJS_CFUNC_DEF("setMaxStackSize", 1, tjs_setMaxStackSize),
    TJS_CFUNC_DEF("compile", 2, tjs_compile),
    TJS_CFUNC_DEF("serialize", 1, tjs_serialize),
    TJS_CFUNC_DEF("deserialize", 1, tjs_deserialize),
    TJS_CFUNC_DEF("evalBytecode", 1, tjs_evalBytecode),
	TJS_CFUNC_DEF("onModule", 1, tjs__override_module_options),
	TJS_CFUNC_DEF("onEvent", 1, tjs__set_event_receiver),
	TJS_CFUNC_DEF("encodeString", 1, tjs_encodeString),
	TJS_CFUNC_DEF("encodeU16String", 1, tjs_encodeU16String),
	TJS_CFUNC_DEF("decodeString", 1, tjs_decodeString),
	TJS_CFUNC_DEF("decodeU16String", 1, tjs_decodeU16String),
	TJS_CFUNC_DEF("promiseResult", 1, tjs_proimise_result),

	TJS_CONST2("DUMP_BYTECODE", JS_WRITE_OBJ_BYTECODE),
	TJS_CONST2("DUMP_NODEBUG", JS_WRITE_OBJ_STRIP_DEBUG),
	TJS_CONST2("DUMP_NOSOURCE", JS_WRITE_OBJ_STRIP_SOURCE),
	TJS_CONST2("DUMP_DEEP", JS_WRITE_OBJ_REFERENCE),
	TJS_CONST2("DUMP_LOCAL", JS_WRITE_OBJ_SAB),
	TJS_CONST2("DUMP_DEFAULT", JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE),
};

/* clang-format off */
static const JSCFunctionListEntry tjs_gc_funcs[] = {
    TJS_CFUNC_DEF("run", 0, tjs_gc_run),
    TJS_CFUNC_DEF("setThreshold", 1, tjs_gc_setThreshold),
    TJS_CFUNC_DEF("getThreshold", 0, tjs_gc_getThreshold)
};
/* clang-format on */

static const JSCFunctionListEntry tjs_promise_enum[] = {
	TJS_CONST2("CONSTRUCT", JS_PROMISE_HOOK_INIT),
	TJS_CONST2("FULFILLED", JS_PROMISE_HOOK_RESOLVE),
	TJS_CONST2("BEFORE_THEN", JS_PROMISE_HOOK_BEFORE),
	TJS_CONST2("AFTER_THEN", JS_PROMISE_HOOK_AFTER)
};

void tjs__mod_engine_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_engine_funcs, countof(tjs_engine_funcs));

    JSValue versions = JS_NewObjectProto(ctx, JS_NULL);
    JS_DefinePropertyValueStr(ctx, versions, "quickjs", JS_NewString(ctx, JS_GetVersion()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, versions, "tjs", JS_NewString(ctx, tjs_version()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, versions, "uv", JS_NewString(ctx, uv_version_string()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, versions, "sqlite3", JS_NewString(ctx, sqlite3_libversion()), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, versions, "zlib", JS_NewString(ctx, zlibVersion()), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, versions, "openssl", JS_NewString(ctx, OpenSSL_version(OPENSSL_VERSION)), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, versions, "expat", JS_NewString(ctx, XML_ExpatVersion()), JS_PROP_C_W_E);

	JS_DefinePropertyValueStr(ctx, versions, "llhttp", JS_NewString(ctx, LLHTTP_VERSION), JS_PROP_C_W_E);
#ifdef CJS__HAS_WASM
    JS_DefinePropertyValueStr(ctx, versions, "wasm3", JS_NewString(ctx, M3_VERSION), JS_PROP_C_W_E);
#endif
#ifdef CJS__HAS_MIMALLOC
    JS_DefinePropertyValueStr(ctx, versions, "mimalloc", JS_NewInt32(ctx, mi_version()), JS_PROP_C_W_E);
#endif

    JSValue gc = JS_NewObjectProto(ctx, JS_NULL);
    JS_SetPropertyFunctionList(ctx, gc, tjs_gc_funcs, countof(tjs_gc_funcs));
    JS_DefinePropertyValueStr(ctx, ns, "gc", gc, JS_PROP_C_W_E);

    JS_DefinePropertyValueStr(ctx, ns, "versions", versions, JS_PROP_C_W_E);

	// enum PromiseState
	JSValue promise_enum = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, promise_enum, tjs_promise_enum, countof(tjs_promise_enum));
	JS_DefinePropertyValueStr(ctx, ns, "PromiseState", promise_enum, JS_PROP_C_W_E);
	
	// class Module
	JS_NewClassID(JS_GetRuntime(ctx), &js_module_class_id);
	JS_NewClass(JS_GetRuntime(ctx), js_module_class_id, &js_module_class);
	JSValue proto = JS_NewObjectProto(ctx, JS_NULL);
	JS_SetPropertyFunctionList(ctx, proto, js_module_proto_funcs, countof(js_module_proto_funcs));
	JS_SetClassProto(ctx, js_module_class_id, proto);
	JSValue ctor = JS_NewCFunction2(ctx, js_module_constructor, "Module", 2, JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, ctor, proto);
	JS_DefinePropertyValue(ctx, ns, JS_ATOM_Module, ctor, JS_PROP_C_W_E);
}
