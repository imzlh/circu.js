/*
 * txiki.js
 *
 * Copyright (c) 2022-present Saúl Ibarra Corretgé <s@saghul.net>
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

static JSValue tjs_evalFile(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    const char *filename;
    size_t len;
    JSValue ret;
    filename = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!filename) {
        return JS_EXCEPTION;
    }
    ret = TJS_EvalModule(ctx, filename, true);
    JS_FreeCString(ctx, filename);
    return ret;
}

static JSValue tjs_loadScript(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    const char *filename;
    size_t len;
    JSValue ret;
    filename = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!filename) {
        return JS_EXCEPTION;
    }
    ret = TJS_EvalScript(ctx, filename);
    JS_FreeCString(ctx, filename);
    return ret;
}

static JSValue tjs_evalScript(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    const char *str;
    size_t len;
    JSValue ret;
    str = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!str) {
        return JS_EXCEPTION;
    }
    ret = JS_Eval(ctx, str, len, "<evalScript>", JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_ASYNC);
    JS_FreeCString(ctx, str);
    return ret;
}

static JSValue tjs_encodeString(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "argument must be a string");
	}

	size_t strlen;
	const char* str = JS_ToCStringLen(ctx, &strlen, argv[0]);
	JSValue buffer = JS_NewArrayBufferCopy(ctx, (uint8_t*)str, strlen);
	JS_FreeCString(ctx, str);
	return buffer;
}

static JSValue tjs_decodeString(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0){
typerr:
		return JS_ThrowTypeError(ctx, "argument must be an ArrayBuffer");
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

static JSValue tjs_isArrayBuffer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return JS_NewBool(ctx, JS_IsArrayBuffer(argv[0]));
}

static JSValue tjs_detachArrayBuffer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if(!JS_IsArrayBuffer(argv[0])) return JS_ThrowTypeError(ctx, "not an ArrayBuffer");
    JS_DetachArrayBuffer(ctx, argv[0]);

    return JS_UNDEFINED;
}

static JSValue tjs_exepath(JSContext *ctx, JSValue this_val) {
    char buf[1024];
    size_t size = sizeof(buf);
    char *dbuf = buf;
    int r;

    r = uv_exepath(dbuf, &size);
    if (r != 0) {
        if (r != UV_ENOBUFS) {
            return tjs_throw_errno(ctx, r);
        }
        dbuf = js_malloc(ctx, size);
        if (!dbuf) {
            return JS_EXCEPTION;
        }
        r = uv_exepath(dbuf, &size);
        if (r != 0) {
            js_free(ctx, dbuf);
            return tjs_throw_errno(ctx, r);
        }
    }

    JSValue ret = JS_NewStringLen(ctx, dbuf, size);

    if (dbuf != buf) {
        js_free(ctx, dbuf);
    }

    return ret;
}

static JSValue tjs_randomUUID(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    char v[37];
    unsigned char u[16];

    int r = uv_random(NULL, NULL, u, sizeof(u), 0, NULL);
    if (r != 0) {
        return tjs_throw_errno(ctx, r);
    }

    u[6] &= 15;
    u[6] |= 64;  // '4x'

    u[8] &= 63;
    u[8] |= 128;  // 0b10xxxxxx

    snprintf(v,
             sizeof(v),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0],
             u[1],
             u[2],
             u[3],
             u[4],
             u[5],
             u[6],
             u[7],
             u[8],
             u[9],
             u[10],
             u[11],
             u[12],
             u[13],
             u[14],
             u[15]);

    return JS_NewString(ctx, v);
}

#define IFOPT(optname, optcheckfunc, then) \
	valtmp = JS_GetPropertyStr(ctx, argv[0], optname); \
	if (optcheckfunc(valtmp)) then
#define IFOPT2(optname, optcheckfunc, then) \
	valtmp = JS_GetPropertyStr(ctx, argv[0], optname); \
	if (optcheckfunc(ctx, valtmp)) then
static JSValue tjs__setVmOptions(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if(argc == 0 || !JS_IsObject(argv[0])){
		return JS_ThrowTypeError(ctx, "options must be an object");
	}

	TJSRuntime* trt = JS_GetContextOpaque(ctx);
	assert(trt != NULL);
	JSValue valtmp = JS_UNDEFINED;
	IFOPT("maxMemory", JS_IsNumber, {
		int64_t maxMemory;
		if (JS_ToInt64(ctx, &maxMemory, valtmp) == -1 || maxMemory < 0) {
			return JS_ThrowRangeError(ctx, "maxMemory must be a non-negative integer");
		}
		JS_SetMemoryLimit(JS_GetRuntime(ctx), maxMemory);
	})
	IFOPT("maxStackSize", JS_IsNumber, {
		uint32_t max_stack;
		if (JS_ToUint32(ctx, &max_stack, valtmp) == -1 || max_stack < 16) {
			return JS_ThrowRangeError(ctx, "maxStackSize must be a positive integer greater than or equal to 16");
		}
		JS_SetMaxStackSize(JS_GetRuntime(ctx), max_stack);
	});
	IFOPT2("moduleLoader", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.loader);
		trt->module.loader = JS_DupValue(ctx, valtmp);
	});
	IFOPT2("moduleResolver", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.resolver);
		trt->module.resolver = JS_DupValue(ctx, valtmp);
	});
	IFOPT2("moduleInit", JS_IsFunction, {
		JS_FreeValue(ctx, trt->module.metaloader);
		trt->module.metaloader = JS_DupValue(ctx, valtmp);
	})
	IFOPT2("eventReceiver", JS_IsFunction, {
		JS_FreeValue(ctx, trt->builtins.dispatch_event_func);
		trt->builtins.dispatch_event_func = JS_DupValue(ctx, valtmp);
	});
	JS_FreeValue(ctx, valtmp);

	return JS_UNDEFINED;
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
        // return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "loadModule() requires 2 argument",
        //     "loadModule(source: string, module_name: string): Module"
        // );
		return JS_ThrowTypeError(ctx, "loadModule() requires 2 argument");
    }

    size_t len;
    const char *source = JS_ToCStringLen(ctx, &len, argv[0]);
    if(!source) return JS_EXCEPTION;
	const char *module_name = JS_ToCString(ctx, argv[1]);
	if(!module_name) module_name = "<module>";

    JSValue compiled = JS_Eval(ctx, source, len, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if(JS_IsException(compiled)) goto fail;

    JS_FreeCString(ctx, source);
    JS_FreeCString(ctx, module_name);
    return module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(compiled));
fail:
    JS_FreeCString(ctx, source);
    JS_FreeCString(ctx, module_name);
    return JS_EXCEPTION;
}

static void js_module_finalizer(JSRuntime *rt, JSValue val) {
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque(val, js_module_class_id);
    if(def) {
        JS_FreeValueRT(rt, JS_MKPTR(JS_TAG_MODULE, def));
    }
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

    size_t len = 0;
    uint8_t *data = JS_WriteObject(ctx, &len, JS_MKPTR(JS_TAG_MODULE, def), JS_WRITE_OBJ_BYTECODE);
    if(!data) return JS_EXCEPTION;

    return JS_NewArrayBuffer(ctx, data, len, free_js_malloc, NULL, false);
}

static JSValue js_module_get_meta(JSContext* ctx, JSValueConst this_val){
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!def) return JS_EXCEPTION;

    JSValue meta = JS_MKPTR(JS_TAG_MODULE, def);
	// fixme: more efficient way to get meta?
    return JS_DupValue(ctx, meta);
}

JSModuleDef* tjs__module_getdef(JSContext* ctx, JSValueConst this_val){
    JSModuleDef* def = (JSModuleDef*)JS_GetOpaque(this_val, js_module_class_id);
    return def;
}

static const JSClassDef js_module_class = {
    "Module",
    .finalizer = js_module_finalizer,
};

static const JSCFunctionListEntry js_module_proto_funcs[] = {
    JS_CGETSET_DEF("ptr", js_module_get_ptr, NULL),
    JS_CFUNC_DEF("dump", 0, js_module_dump),
    JS_CGETSET_DEF("meta", js_module_get_meta, NULL)
};

/* clang-format off */
static const JSCFunctionListEntry tjs_sys_funcs[] = {
    TJS_CFUNC_DEF("evalFile", 1, tjs_evalFile),
    TJS_CFUNC_DEF("evalScript", 1, tjs_evalScript),
    TJS_CFUNC_DEF("loadScript", 1, tjs_loadScript),
    TJS_CFUNC_DEF("randomUUID", 0, tjs_randomUUID),
    TJS_CFUNC_DEF("isArrayBuffer", 1, tjs_isArrayBuffer),
    TJS_CFUNC_DEF("detachArrayBuffer", 1, tjs_detachArrayBuffer),
	TJS_CFUNC_DEF("setOptions", 1, tjs__setVmOptions),
	TJS_CFUNC_DEF("encodeString", 1, tjs_encodeString),
	TJS_CFUNC_DEF("decodeString", 1, tjs_decodeString),
    TJS_CGETSET_DEF("exePath", tjs_exepath, NULL)
};
/* clang-format on */

void tjs__mod_sys_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_sys_funcs, countof(tjs_sys_funcs));
    JS_DefinePropertyValueStr(ctx, ns, "args", tjs__get_args(ctx), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, ns, "version", JS_NewString(ctx, tjs_version()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, ns, "platform", JS_NewString(ctx, TJS__PLATFORM), JS_PROP_C_W_E);

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
