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

#ifndef _WIN32
#include <unistd.h>
#endif
#include <assert.h>

#include <uv.h>
#include <curl/curl.h>
#include <openssl/opensslv.h>
#include <expat.h>
#include <zlib.h>

#include "../deps/quickjs/list.h"

#ifdef CJS__HAS_MIMALLOC
#include <mimalloc.h>
#endif

#ifdef CJS__HAS_WASM
#include <wasm_export.h>
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
static thread_local JSClassID js_module_class_id;
typedef struct {
	struct list_head local_def;
	JSModuleDef* def;
} tjs_module_t;

typedef struct {
	void* var;
	JSAtom atom;
	struct list_head list;
} tjs_module_export_t;

static inline JSValue module_new(JSContext* ctx, JSModuleDef* def){
    JSValue obj = JS_NewObjectClass(ctx, js_module_class_id);
    if (JS_IsException(obj)) return obj;
	tjs_module_t* mt = js_malloc(ctx, sizeof(tjs_module_t));
	if (!mt) {
		JS_FreeValue(ctx, obj);
		return JS_ThrowOutOfMemory(ctx);
	}
	init_list_head(&mt->local_def);
    mt->def = def;
    JS_SetOpaque(obj, mt);
    return obj;
}

static void js_module_finalizer(JSRuntime *rt, JSValueConst obj){
	tjs_module_t* mt = JS_GetOpaque(obj, js_module_class_id);
	if(!mt) return;

	// Free all exported var_refs
	if(mt->local_def.next) {
		struct list_head *pos, *tmp;
		list_for_each_safe(pos, tmp, &mt->local_def){
			tjs_module_export_t* me = list_entry(pos, tjs_module_export_t, list);
			JS_FreeModuleExport(rt, me->var);
			JS_FreeAtomRT(rt, me->atom);
			js_free_rt(rt, me);
		}
	}

	js_free_rt(rt, mt);
}

static JSValue js_module_static_create(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
	if (argc == 0 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "createModule() requires 1 argument");
    }

	const char* name = JS_ToCString(ctx, argv[0]);
    if(!name) return JS_EXCEPTION;
    JSModuleDef* m = JS_NewCModule2(ctx, name);
    JS_FreeCString(ctx, name);
    if(!m) return JS_EXCEPTION;
    return module_new(ctx, m);
}

// callback to export all private value
static int js_module_init_fn(JSContext *ctx, JSModuleDef *m) {
	JSPropertyEnum* ep;
	JSValueConst raw_object = JS_GetModulePrivateValue(ctx, m);
	int len = JS_GetOwnPropertyNames(ctx, &ep, NULL, raw_object, JS_GPN_STRING_MASK);
	if (len == -1) {
		JS_FreeValue(ctx, raw_object);
		return -1;
	}
	for (int i = 0; i < len; i++) {
		const char* name = JS_AtomToCString(ctx, ep[i].atom);
		JSValueConst val = JS_GetProperty(ctx, raw_object, ep[i].atom);
		if (JS_IsException(val)){
			JS_FreeCString(ctx, name);
			continue;
		}
		JS_SetModuleExport(ctx, m, name, val);
		JS_FreeCString(ctx, name);
	}
	JS_FreePropertyEnum(ctx, ep, len);
	JS_FreeValue(ctx, raw_object);
	return 0;
}

static JSValue js_module_static_from(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
	if (argc < 2){
		return JS_ThrowTypeError(ctx, "Module.from() requires 2 arguements");
    }

	if (!JS_IsString(argv[0]) || !JS_IsObject(argv[1])) {
		return JS_ThrowTypeError(ctx, "invalid arguments to Module.from()");
	}

	const char* name = JS_ToCString(ctx, argv[0]);
	if (!name) return JS_EXCEPTION;
	JSValue raw_object = JS_DupValue(ctx, argv[1]);
	JSModuleDef* m = JS_NewCModule(ctx, name, js_module_init_fn);
	JS_FreeCString(ctx, name);
	if (!m) {
		JS_FreeValue(ctx, raw_object);
		return JS_EXCEPTION;
	}

	// export all keys
	JSPropertyEnum* ep;
	int len = JS_GetOwnPropertyNames(ctx, &ep, NULL, raw_object, JS_GPN_STRING_MASK);
	if (len == -1) {
		JS_FreeValue(ctx, raw_object);
		return JS_EXCEPTION;
	}
	for (int i = 0; i < len; i++) {
		const char* ename = JS_AtomToCString(ctx, ep[i].atom);
		JS_AddModuleExport(ctx, m, ename);
		JS_FreeCString(ctx, ename);
	}
	JS_FreePropertyEnum(ctx, ep, len);

	JS_SetModulePrivateValue(ctx, m, raw_object);
	return module_new(ctx, m);
}

static JSValue js_module_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    if(argc < 2 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "new Module() requires 2 argument");
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
    JSModuleDef* def = (JSModuleDef*)JS_VALUE_GET_PTR(compiled);
    JSValue result = module_new(ctx, def);
    JS_FreeValue(ctx, compiled);  // Release the compiled JSValue; module_new now owns the def
    return result;
fail:
    JS_FreeCString(ctx, source);
    if(_mname) JS_FreeCString(ctx, _mname);
    return JS_EXCEPTION;
}

static JSValue js_module_eval(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
	if(!mt) return JS_EXCEPTION;
	JSValue mod_val = JS_MKPTR(JS_TAG_MODULE, mt->def);
	/* JS_EvalFunction expects the module value to have ref_count >= 2,
	 * as it will JS_FreeValue it internally */
	return JS_EvalFunction(ctx, JS_DupValue(ctx, mod_val));
}

static JSValue js_module_resolve(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
	if(!mt) return JS_EXCEPTION;
	int res = JS_ResolveModule(ctx, JS_MKPTR(JS_TAG_MODULE, mt->def));
	if (res != 0) {
		return JS_EXCEPTION;
	}

	return JS_UNDEFINED;
}

static JSValue js_module_export(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!mt) return JS_EXCEPTION;
    if(argc < 2 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "export() requires 2 argument: export_name: string, value: any");
    }

    const char *export_name = JS_ToCString(ctx, argv[0]);
    if(!export_name) return JS_EXCEPTION;
	JSAtom name = JS_NewAtom(ctx, export_name);
    JS_FreeCString(ctx, export_name);

	// find whether export exists
	struct list_head* pos;
	list_for_each(pos, &mt->local_def){
		tjs_module_export_t* me = list_entry(pos, tjs_module_export_t, list);
		if(name == me->atom){
			/* Don't free the var_ref here! JS_DefineModuleExport will reuse
			 * the same var_ref and just update its value. The var_ref is owned
			 * by the module and will be freed when the module is destroyed. */
			JS_DefineModuleExport(ctx, mt->def, name, JS_DupValue(ctx, argv[1]));
			JS_FreeAtom(ctx, name);
			goto end;
		}
	}

	// add to list
    void* def = JS_DefineModuleExport(ctx, mt->def, name, JS_DupValue(ctx, argv[1]));
    if(!def){
		JS_FreeAtom(ctx, name);
		return JS_EXCEPTION;
	}

	tjs_module_export_t* me = js_malloc(ctx, sizeof(tjs_module_export_t));
	me->atom = name;
	me->var = def;
	list_add_tail(&me->list, &mt->local_def);

end:
    return JS_UNDEFINED;
}

static JSValue js_module_unref(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
	tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
	if(!mt) return JS_EXCEPTION;
	if (argc == 0 || !JS_IsString(argv[0]))
		return JS_ThrowTypeError(ctx, "unref() requires 1 argument: name");

	const char* name = JS_ToCString(ctx, argv[0]);
    if(!name) return JS_EXCEPTION;
	JSAtom name_atom = JS_NewAtom(ctx, name);
	JS_FreeCString(ctx, name);

	// find in exports
	struct list_head* pos;
	list_for_each(pos, &mt->local_def){
		tjs_module_export_t* me = list_entry(pos, tjs_module_export_t, list);
		if(name_atom == me->atom){
			// Free the specific export's var_ref, not the whole module def
			JS_FreeModuleExport(JS_GetRuntime(ctx), me->var);
			JS_FreeAtom(ctx, me->atom);
			list_del(&me->list);
			js_free(ctx, me);
			JS_FreeAtom(ctx, name_atom);
			return JS_UNDEFINED;
		}
	}

	JSValue err = JS_ThrowTypeError(ctx, "export not found");
	JS_FreeAtom(ctx, name_atom);
    return err;
}

static JSValue js_module_get_ptr(JSContext *ctx, JSValueConst this_val){
	tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
	if(!mt) return JS_EXCEPTION;
    return 
#if __SIZEOF_POINTER__ == 8
    JS_NewInt64
#else
    JS_NewInt32
#endif
    (ctx, (uintptr_t)mt->def);
}

static JSValue js_module_get_namespace(JSContext *ctx, JSValueConst this_val){
	tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
	if(!mt) return JS_EXCEPTION;

	return JS_GetModuleNamespace(ctx, mt->def);
}

static void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr){
	js_free_rt(rt, ptr);
}

static JSValue js_module_dump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!mt) return JS_EXCEPTION;

	int flags = JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE;
	if (argc != 0 && -1 == JS_ToInt32(ctx, &flags, argv[0])) {
		return JS_ThrowTypeError(ctx, "invalid flags. expect number mask or undefined");
	}

    size_t len = 0;
    uint8_t *data = JS_WriteObject(ctx, &len, JS_MKPTR(JS_TAG_MODULE, mt->def), flags);
    if(!data) return JS_EXCEPTION;

    return JS_NewArrayBuffer(ctx, data, len, free_js_malloc, NULL, false);
}

static JSValue js_module_get_meta(JSContext* ctx, JSValueConst this_val){
    tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!mt) return JS_EXCEPTION;
    return JS_GetImportMeta(ctx, mt->def);
}

JSModuleDef* tjs__module_getdef(JSContext* ctx, JSValueConst this_val){
    tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
    return mt->def;
}

JSValue tjs__new_module(JSContext* ctx, JSModuleDef* mt){
	return module_new(ctx, mt);
}

static const JSClassDef js_module_class = {
    "Module",
    .finalizer = js_module_finalizer,
};

static const JSCFunctionListEntry js_module_proto_funcs[] = {
    JS_CGETSET_DEF("ptr", js_module_get_ptr, NULL),
    JS_CFUNC_DEF("dump", 0, js_module_dump),
    JS_CGETSET_DEF("meta", js_module_get_meta, NULL),
	JS_CGETSET_DEF("namespace", js_module_get_namespace, NULL),
	JS_CFUNC_DEF("eval", 0, js_module_eval),
	JS_CFUNC_DEF("resolve", 0, js_module_resolve),
	JS_CFUNC_DEF("export", 0, js_module_export),
	JS_CFUNC_DEF("unref", 0, js_module_unref),
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

static JSValue tjs_eval(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    size_t len = 0;
    const char *buf = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!buf) {
        return JS_EXCEPTION;
    }

	// use custom eval flag
	int eval_flags = JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_BACKTRACE_BARRIER;
	if (argc >= 3 && JS_IsNumber(argv[2]))
		JS_ToInt32(ctx, &eval_flags, argv[2]);

    const char *module_name = JS_ToCString(ctx, argv[1]);
    if (!module_name) {
		JS_FreeCString(ctx, buf);
        return JS_EXCEPTION;
    }
    
    JSValue obj = JS_Eval(ctx, buf, len, module_name, eval_flags);
    JS_FreeCString(ctx, module_name);
    JS_FreeCString(ctx, buf);
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
    if (JS_IsException(ret)) {
        return ret;
    }
	switch (JS_VALUE_GET_NORM_TAG(ret)){
		case JS_TAG_MODULE: {
			JSValue result = module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(ret));
			JS_FreeValue(ctx, ret);  // Release the module JSValue wrapper
			return result;
		}
		case JS_TAG_FUNCTION_BYTECODE:
			// Explicit handling (was fallthrough to default)
			return ret;
		default:
			return ret;
	}
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
	JS_FreeValue(ctx, trt->builtins.dispatch_event_func);
	trt->builtins.dispatch_event_func = JS_DupValue(ctx, argv[0]);
	return JS_UNDEFINED;
}

static JSValue tjs_encodeString(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "argument must be a string");
	}

	size_t slen;
	const char* str = JS_ToCStringLen(ctx, &slen, argv[0]);
	if (!str) {
		return JS_EXCEPTION;
	}
	JSValue buffer = JS_NewUint8ArrayCopy(ctx, (uint8_t*)str, slen);
	JS_FreeCString(ctx, str);
	return buffer;
}

static JSValue tjs_decodeString(JSContext *ctx, JSValue this_val, int argc, JSValue *argv){
	if(argc == 0){
typerr:
		return JS_ThrowTypeError(ctx, "argument must be an ArrayBuffer or Uint8Array");
	}

	uint8_t* buf = NULL;
	size_t buflen = 0;
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

	size_t slen;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &slen, argv[0]);
	if (!str) {
		return JS_EXCEPTION;
	}
	JSValue buffer = JS_NewArrayBufferCopy(ctx, (const uint8_t*)str, slen *2);
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
	JSValue u16arr = JS_CallConstructor(ctx, u16arrctor, 1, (JSValueConst[]) { buffer });
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


static JSValue tjs_proimise_result(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
	if (argc == 0 || !JS_IsPromise(argv[0])) {
		return JS_ThrowTypeError(ctx, "argument must be a Promise");
	}

	JSPromiseStateEnum state = JS_PromiseState(ctx, argv[0]);
	JSValue err;
	switch (state) {
		case JS_PROMISE_PENDING:
		return JS_NULL;

		case JS_PROMISE_FULFILLED:
		return JS_PromiseResult(ctx, argv[0]);

		case JS_PROMISE_REJECTED:
			err = JS_PromiseResult(ctx, argv[0]);
		return JS_Throw(ctx, err);

		default: abort();
	}
}


static JSValue tjs_isArrayBuffer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return JS_NewBool(ctx, argc >= 1 && JS_IsArrayBuffer(argv[0]));
}

static JSValue tjs_detachArrayBuffer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if(argc == 0 || !JS_IsArrayBuffer(argv[0]))
		return JS_ThrowTypeError(ctx, "first argument is not an ArrayBuffer");
    JS_DetachArrayBuffer(ctx, argv[0]);

    return JS_UNDEFINED;
}


static JSValue tjs_immutArrayBuffer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if(argc == 0 || !JS_IsArrayBuffer(argv[0]))
		return JS_ThrowTypeError(ctx, "first argument is not an ArrayBuffer");
	bool immut = argc >= 2 ? JS_ToBool(ctx, argv[1]) : true;
    int ret = JS_SetImmutableArrayBuffer(argv[0], immut);

    return ret == 0 ? JS_UNDEFINED : JS_EXCEPTION;
}

static JSValue tjs_waitIO(JSContext* ctx, JSValue this_val, int argc, JSValue *argv) {
	if (argc == 0 || !JS_IsPromise(argv[0]))
		return JS_ThrowTypeError(ctx, "not a Promise.");

	JSValue abort_check = argc >= 2 && JS_IsFunction(ctx, argv[1]) ? JS_DupValue(ctx, argv[1]) : JS_UNDEFINED;

	TJSRuntime* trt = TJS_GetRuntime(ctx);
	uv_loop_t* loop = TJS_GetLoop(trt);

	// Track nested waitIO depth
	int prev_depth = trt->jobs.waitio_depth++;

	bool aborted = false;
	JSValue abort_exception = JS_UNDEFINED;
	int loop_iterations = 0;
	const int MAX_ITERATIONS = 100000;

	while (JS_PromiseState(ctx, argv[0]) == JS_PROMISE_PENDING) {
		// Safety: prevent infinite loops
		if (++loop_iterations > MAX_ITERATIONS) {
			abort_exception = JS_ThrowInternalError(ctx, "waitPromise: too many iterations");
			aborted = true;
			break;
		}

		// Execute pending jobs BEFORE uv_run
		// This is critical: jobs may create/start uv handles needed for I/O
		JSContext *ctx1;
		int err;
		while (1) {
			err = JS_ExecutePendingJob(JS_GetRuntime(ctx), &ctx1);
			if (err <= 0) {
				if (err < 0) {
					// Job threw an exception
					JSValue js_err = JS_GetException(ctx1);
					JSValue retv = tjs__dispatch_event(ctx1, EV_JOB_EXCEPTION, js_err);
					bool should_stop = (JS_IsEqual(ctx1, retv, JS_FALSE) == 1);
					JS_FreeValue(ctx1, js_err);
					JS_FreeValue(ctx1, retv);

					if (should_stop) {
						abort_exception = JS_ThrowInternalError(ctx, "Job exception caused runtime stop");
						aborted = true;
						break;
					}
				}
				break;  // No more jobs
			}
		}

		if (aborted) break;

		// Run event loop to process I/O
		int uv_result = uv_run(loop, UV_RUN_ONCE);

		// Check if loop is dead and no pending jobs
		if (uv_result == 0 && uv_loop_alive(loop) == 0 && !JS_IsJobPending(JS_GetRuntime(ctx))) {
			break;
		}

		// Check abort condition if provided
		if (!JS_IsUndefined(abort_check)) {
			JSValue ret = JS_Call(ctx, abort_check, this_val, 0, NULL);
			if (JS_IsException(ret)) {
				abort_exception = JS_GetException(ctx);
				aborted = true;
				break;
			}

			int is_true = JS_IsEqual(ctx, ret, JS_TRUE);
			JS_FreeValue(ctx, ret);

			if (is_true == -1) {
				abort_exception = JS_GetException(ctx);
				aborted = true;
				break;
			}

			if (is_true == 1) {
				aborted = true;
				break;
			}
		}
	}

	// Restore state
	trt->jobs.waitio_depth = prev_depth;

	JS_FreeValue(ctx, abort_check);

	// Handle abort exception
	if (!JS_IsUndefined(abort_exception)) {
		return abort_exception;
	}

	// Get final promise state
	JSPromiseStateEnum state = JS_PromiseState(ctx, argv[0]);

	switch (state) {
		case JS_PROMISE_FULFILLED: {
			JSValue result = JS_PromiseResult(ctx, argv[0]);
			return result;  // Already owned reference, don't dup
		}
		case JS_PROMISE_REJECTED: {
			JSValue error = JS_PromiseResult(ctx, argv[0]);
			return JS_Throw(ctx, error);  // Throw consumes the error, don't dup
		}
		case JS_PROMISE_PENDING:
			if (aborted) {
				return JS_ThrowInternalError(ctx, "waitPromise aborted");
			}
			return JS_ThrowInternalError(ctx, "waitPromise: promise did not settle");
		default:
			abort();
	}
}

static const JSCFunctionListEntry tjs_engine_funcs[] = {
    TJS_CFUNC_DEF("setMemoryLimit", 1, tjs_setMemoryLimit),
    TJS_CFUNC_DEF("setMaxStackSize", 1, tjs_setMaxStackSize),
    TJS_CFUNC_DEF("eval", 3, tjs_eval),
    TJS_CFUNC_DEF("serialize", 2, tjs_serialize),
    TJS_CFUNC_DEF("deserialize", 1, tjs_deserialize),
	TJS_CFUNC_DEF("onModule", 1, tjs__override_module_options),
	TJS_CFUNC_DEF("onEvent", 1, tjs__set_event_receiver),
	TJS_CFUNC_DEF("encodeString", 1, tjs_encodeString),
	TJS_CFUNC_DEF("encodeU16String", 1, tjs_encodeU16String),
	TJS_CFUNC_DEF("decodeString", 1, tjs_decodeString),
	TJS_CFUNC_DEF("decodeU16String", 1, tjs_decodeU16String),
	TJS_CFUNC_DEF("promiseResult", 1, tjs_proimise_result),
    TJS_CFUNC_DEF("isArrayBuffer", 1, tjs_isArrayBuffer),
    TJS_CFUNC_DEF("detachArrayBuffer", 1, tjs_detachArrayBuffer),
	TJS_CFUNC_DEF("setImmutableArrayBuffer", 2, tjs_immutArrayBuffer),
	TJS_CFUNC_DEF("waitIO", 2, tjs_waitIO),

	TJS_CONST2("DUMP_BYTECODE", JS_WRITE_OBJ_BYTECODE),
	TJS_CONST2("DUMP_NODEBUG", JS_WRITE_OBJ_STRIP_DEBUG),
	TJS_CONST2("DUMP_NOSOURCE", JS_WRITE_OBJ_STRIP_SOURCE),
	TJS_CONST2("DUMP_DEEP", JS_WRITE_OBJ_REFERENCE),
	TJS_CONST2("DUMP_LOCAL", JS_WRITE_OBJ_SAB),
	TJS_CONST2("DUMP_DEFAULT", JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE),

	TJS_CONST2("EVAL_MODULE", JS_EVAL_TYPE_MODULE),
	TJS_CONST2("EVAL_ASYNC", JS_EVAL_FLAG_ASYNC),
	TJS_CONST2("EVAL_STRICT", JS_EVAL_FLAG_STRICT),
	TJS_CONST2("EVAL_NEW_BACKTRACE", JS_EVAL_FLAG_BACKTRACE_BARRIER),
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

static const JSCFunctionListEntry tjs_event_enum[] = {
	TJS_CONST2("LOAD", EV_LOAD),
	TJS_CONST2("EXIT", EV_EXIT),
	TJS_CONST2("UNHANDLED_REJECTION", EV_UNHANDLED_REJECTION),
	TJS_CONST2("JOB_EXCEPTION", EV_JOB_EXCEPTION),
	TJS_CONST2("PROMISE", EV_PROMISE),
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
	JS_DefinePropertyValueStr(ctx, versions, "core", JS_NewString(ctx, tjs_version()), JS_PROP_C_W_E);

	JS_DefinePropertyValueStr(ctx, versions, "llhttp", JS_NewString(ctx, LLHTTP_VERSION), JS_PROP_C_W_E);
#ifdef CJS__HAS_WASM
	char wasm_version[128] = {0};
	wasm_runtime_get_file_package_version((uint8_t*)wasm_version, sizeof(wasm_version));
    JS_DefinePropertyValueStr(ctx, versions, "wasm3", JS_NewString(ctx, wasm_version), JS_PROP_C_W_E);
#endif
#ifdef CJS__HAS_MIMALLOC
    JS_DefinePropertyValueStr(ctx, versions, "mimalloc", JS_NewInt32(ctx, mi_version()), JS_PROP_C_W_E);
#endif

	
    /* Export version info */
	JS_SetPropertyStr(ctx, ns, "EXPAT_VERSION", JS_NewString(ctx,
#ifdef HAVE_XML_EXPAT_VERSION
    XML_ExpatVersion()
#else
	STRINGIFY(XML_MAJOR_VERSION) "." STRINGIFY(XML_MINOR_VERSION) "." STRINGIFY(XML_MICRO_VERSION)
#endif
	));

    JSValue gc = JS_NewObjectProto(ctx, JS_NULL);
    JS_SetPropertyFunctionList(ctx, gc, tjs_gc_funcs, countof(tjs_gc_funcs));
    JS_DefinePropertyValueStr(ctx, ns, "gc", gc, JS_PROP_C_W_E);

    JS_DefinePropertyValueStr(ctx, ns, "versions", versions, JS_PROP_C_W_E);

	// enum PromiseState
	JSValue promise_enum = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, promise_enum, tjs_promise_enum, countof(tjs_promise_enum));
	JS_DefinePropertyValueStr(ctx, ns, "PromiseState", promise_enum, JS_PROP_C_W_E);
	
	// enum EventType
	JSValue event_enum = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, event_enum, tjs_event_enum, countof(tjs_event_enum));
	JS_DefinePropertyValueStr(ctx, ns, "EventType", event_enum, JS_PROP_C_W_E);

	// class Module
	JS_NewClassID(JS_GetRuntime(ctx), &js_module_class_id);
	JS_NewClass(JS_GetRuntime(ctx), js_module_class_id, &js_module_class);
	JSValue proto = JS_NewObjectProto(ctx, JS_NULL);
	JS_SetPropertyFunctionList(ctx, proto, js_module_proto_funcs, countof(js_module_proto_funcs));
	JS_SetClassProto(ctx, js_module_class_id, proto);
	JSValue ctor = JS_NewCFunction2(ctx, js_module_constructor, "Module", 2, JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, ctor, proto);
	JS_DefinePropertyValue(ctx, ns, JS_ATOM_Module, ctor, JS_PROP_C_W_E);

	// Module.create
	JSValue mcreate = JS_NewCFunction(ctx, js_module_static_create, "create", 1);
	JS_DefinePropertyValueStr(ctx, ctor, "create", mcreate, JS_PROP_C_W_E);

	// Module.from
	JSValue mfrom = JS_NewCFunction(ctx, js_module_static_from, "from", 1);
	JS_DefinePropertyValueStr(ctx, ctor, "from", mfrom, JS_PROP_C_W_E);
}
