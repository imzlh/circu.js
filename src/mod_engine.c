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
#include "mem.h"

#include <string.h>
#include <stdlib.h>

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
#define CHECK_IF_IN_SANDBOX() do {\
    App* app = TJS_GetApp(ctx); \
    if (app->is_sandbox) { \
        return JS_ThrowTypeError(ctx, "cannot call in sandbox mode"); \
    } \
} while(0)

/* Implemented in utils.c. Declared locally rather than in utils.h because that
 * header is shared with concurrent work; the definition and both call sites
 * (here and vm.c) are the whole surface. */
size_t tjs__clamp_stack_size(size_t requested, bool *was_clamped);
size_t tjs__native_stack_total_size(void);

/* PromiseHook 
 * Called SYNCHRONOUSLY, matching V8: PromiseHook events describe a moment, so
 * dispatching them later reports the wrong moment.
 */
static thread_local bool tjs__in_promise_hook = false;

static void tjs__promise_hook(JSContext* ctx, JSPromiseHookType type,
    JSValueConst promise, JSValueConst parent_promise, void* opaque) {
    (void) opaque;

    TJSRuntime* trt = TJS_GetRuntime(ctx);
    if (!trt || trt->freeing || tjs__in_promise_hook) {
        return;
    }
    if (!JS_IsFunction(ctx, trt->builtins.promise_hook_fn)) {
        return;
    }

    /* Preserve any exception the engine is already carrying. */
    JSValue pending = JS_UNDEFINED;
    bool had_pending = JS_HasException(ctx);
    if (had_pending) {
        pending = JS_GetException(ctx);
    }

    JSValue argv[3] = {
        JS_NewUint32(ctx, type),
        JS_DupValue(ctx, promise),
        JS_DupValue(ctx, parent_promise),
    };

    tjs__in_promise_hook = true;
    JSValue ret = JS_Call(ctx, trt->builtins.promise_hook_fn, JS_UNDEFINED, 3, (JSValueConst*) argv);
    tjs__in_promise_hook = false;

    for (int i = 0; i < 3; i++) {
        JS_FreeValue(ctx, argv[i]);
    }

    if (JS_IsException(ret)) {
        /* The hook threw. Report it here -- there is no caller that could. */
        TJS_DumpException(ctx);
    }
    JS_FreeValue(ctx, ret);

    if (had_pending) {
        JS_Throw(ctx, pending);
    }
}

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

    // QuickJS owns the module export var_refs and frees them with JSModuleDef.
    // The wrapper only owns this bookkeeping list and its atom references.
    if(mt->local_def.next) {
        struct list_head *pos, *tmp;
        list_for_each_safe(pos, tmp, &mt->local_def){
            tjs_module_export_t* me = list_entry(pos, tjs_module_export_t, list);
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
	if(argc < 2){
		return JS_ThrowTypeError(ctx, "new Module() requires 2 argument");
	}

	/* Convert the module name BEFORE acquiring argv[0]'s backing store: if
	 * argv[1] is an object, JS_ToCString runs a user toString() that can detach
	 * argv[0]. On the zero-copy "guarded" path below, `source` points straight
	 * into that backing store and JS_Eval would then compile freed heap. */
	const char *_mname = JS_ToCString(ctx, argv[1]);
	/* Propagate instead of falling back to "<module>". This is NOT an OOM-only
	 * path: argv[1] may be any object, so the JS_ToCString above runs a user
	 * toString() (the very reason it was hoisted here), and that throw landed in
	 * ctx as a pending exception while the old code carried on to compile and
	 * return a module. OBSERVED before this change:
	 *   new Module('export const x = 1;', { toString(){ throw new Error('x') } })
	 * returned a usable module object, resolve() and eval() both succeeded and
	 * the process exited 0 -- the user's exception vanished. Node/V8 propagate a
	 * throwing toString() from an argument conversion, so returning JS_EXCEPTION
	 * is both the correct protocol and the matching behaviour. Nothing is
	 * allocated yet at this point, so a bare return needs no cleanup. */
	if (!_mname) return JS_EXCEPTION;
	const char *module_name = _mname;

	size_t len = 0;
	const char *source = NULL;
	char *source_copy = NULL;
	bool source_is_string = JS_IsString(argv[0]);
	if (source_is_string) {
		source = JS_ToCStringLen(ctx, &len, argv[0]);
		if (!source) { if(_mname) JS_FreeCString(ctx, _mname); return JS_EXCEPTION; }
	} else {
		source = (const char *)JS_GetAnyBuffer(ctx, &len, argv[0]);
		if (!source) {
			if(_mname) JS_FreeCString(ctx, _mname);
			return JS_ThrowTypeError(ctx, "new Module() source must be a string or UTF-8 bytes");
		}

		/* JS_Eval requires source[len] == '\0' (see quickjs.c). engine.toSharedBytes()
		 * and oxc's transpileSharedBytes() supply this NUL guard past the exposed
		 * view; anything else (e.g. a raw fs.readFile() buffer) is not guaranteed
		 * to have it, so copy+terminate rather than risk a 1-byte heap overread. */
		bool guarded = false;
		if (JS_GetTypedArrayType(argv[0]) == JS_TYPED_ARRAY_UINT8) {
			size_t offset = 0, view_len = 0, bytes_per_element = 0, buffer_len = 0;
			JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[0], &offset, &view_len, &bytes_per_element);
			if (!JS_IsException(buffer)) {
				uint8_t *base = JS_GetArrayBuffer(ctx, &buffer_len, buffer);
				guarded = base && view_len == len && offset <= buffer_len && len < buffer_len - offset
					&& base[offset + len] == 0;
				JS_FreeValue(ctx, buffer);
			}
		}
		if (!guarded) {
			if (len == SIZE_MAX) {
				if(_mname) JS_FreeCString(ctx, _mname);
				return JS_ThrowRangeError(ctx, "source too large");
			}
			source_copy = malloc(len + 1);
			if (!source_copy) {
				if(_mname) JS_FreeCString(ctx, _mname);
				return JS_ThrowOutOfMemory(ctx);
			}
			if (len) memcpy(source_copy, source, len);
			source_copy[len] = 0;
			source = source_copy;
		}
	}
    JSValue compiled = JS_Eval(ctx, source, len, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_FLAG_BACKTRACE_BARRIER);
    if(JS_IsException(compiled)) goto fail;

	if (source_is_string) JS_FreeCString(ctx, source);
	free(source_copy);
	if(_mname) JS_FreeCString(ctx, _mname);
    JSModuleDef* def = (JSModuleDef*)JS_VALUE_GET_PTR(compiled);
    JSValue result = module_new(ctx, def);
    JS_FreeValue(ctx, compiled);  // Release the compiled JSValue; module_new now owns the def
    return result;
fail:
	if (source_is_string) JS_FreeCString(ctx, source);
	free(source_copy);
	if(_mname) JS_FreeCString(ctx, _mname);
	return JS_EXCEPTION;
}

static JSValue js_module_eval(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_module_t* mt = JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!mt) return JS_EXCEPTION;
    JSValue mod_val = JS_MKPTR(JS_TAG_MODULE, mt->def);
    /* Resolve dependencies and initialize import.meta (including metaloader
     * / init hook) before evaluating. The standard QuickJS eval path in
     * quickjs-libc.c does JS_ResolveModule → js_module_set_import_meta →
     * JS_EvalFunction, but js_module_eval was only calling the last step,
     * so the entry module's import.meta was never set up and the init hook
     * (which fires Debugger.scriptParsed) never triggered. */
    if (JS_ResolveModule(ctx, mod_val) < 0)
        return JS_EXCEPTION;
    if (js_module_set_import_meta(ctx, mod_val, false, false) < 0)
        return JS_EXCEPTION;
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
        return JS_ThrowTypeError(ctx, "export() requires 2 arguments: export_name string and value");
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
    if (!me) {
        /* def's var_ref is owned by the module; only the atom is ours. */
        JS_FreeAtom(ctx, name);
        return JS_ThrowOutOfMemory(ctx);
    }
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
            // QuickJS keeps owning the export var_ref through JSModuleDef.
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
    if (!mt) return NULL;
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

/* ── Sandbox class ─────────────────────────────────────────────────────── */

static thread_local JSClassID js_sandbox_class_id;

static JSValue js_sandbox_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);

    App *app = TJS_NewAppInternal(trt, true);
    if (!app)
        return JS_ThrowOutOfMemory(ctx);
    JS_AddIntrinsicBaseObjects(app->ctx);    // should before any intrinsic
    JS_AddIntrinsicEval(app->ctx);

    /* Create the Sandbox JS object */
    JSValue obj = JS_NewObjectClass(ctx, js_sandbox_class_id);
    if (JS_IsException(obj)) {
        JS_FreeContext(app->ctx);
        list_del(&app->link);
        tjs__free(app);
        return obj;
    }

    TJSSandbox *sb = tjs__mallocz(sizeof(*sb));
    if (!sb) {
        JS_FreeValue(ctx, obj);
        JS_FreeContext(app->ctx);
        list_del(&app->link);
        tjs__free(app);
        return JS_ThrowOutOfMemory(ctx);
    }
    sb->app = app;
    sb->global = JS_GetGlobalObject(app->ctx);
    sb->trt = trt;

    JS_SetOpaque(obj, sb);
    return obj;
}

static void js_sandbox_finalizer(JSRuntime *rt, JSValueConst val) {
    TJSSandbox *sb = JS_GetOpaque(val, js_sandbox_class_id);
    if (!sb) return;

    JS_FreeValueRT(rt, sb->global);
    sb->global = JS_UNDEFINED;

    if (!sb->trt->freeing){
        /* Only when JS_FreeRuntime not running, we free it manually */
        App *app = sb->app;
        if (app) {
            TJSRuntime *trt = app->trt;
            if (!trt->freeing) {
                JS_FreeContext(app->ctx);
                list_del(&app->link);
                tjs__free(app);
            }
            sb->app = NULL;
        }
    }

    tjs__free(sb);
}

static void js_sandbox_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    TJSSandbox *sb = JS_GetOpaque(val, js_sandbox_class_id);
    if (sb)
        JS_MarkValue(rt, sb->global, mark_func);
}

static JSClassDef js_sandbox_class = {
    "Sandbox",
    .finalizer = js_sandbox_finalizer,
    .gc_mark = js_sandbox_mark,
};

int add_intrinsic(JSContext *ctx, const char *name, size_t len) {
#pragma warning(push)
#pragma warning(disable: 4232)
    static const struct {
        const char *name;
        int (*add_func)(JSContext *);
    } intrinsics[] = {
        {"date",         JS_AddIntrinsicDate},
        {"regexp",       JS_AddIntrinsicRegExp},
        {"json",         JS_AddIntrinsicJSON},
        {"proxy",        JS_AddIntrinsicProxy},
        {"map",          JS_AddIntrinsicMapSet},
        {"typedarrays",  JS_AddIntrinsicTypedArrays},
        {"promise",      JS_AddIntrinsicPromise},
        {"bigint",       JS_AddIntrinsicBigInt},
        {"weakref",      JS_AddIntrinsicWeakRef},
        {"atob",         JS_AddIntrinsicAToB},
        {"domexception", JS_AddIntrinsicDOMException},
        {"performance",  JS_AddPerformance},
    };
#pragma warning(pop)

        for (size_t i = 0; i < sizeof(intrinsics) / sizeof(intrinsics[0]); i++) {
            if (strlen(intrinsics[i].name) == len && 
                strncmp(name, intrinsics[i].name, len) == 0) {
                return intrinsics[i].add_func(ctx);
            }
        }
        return 0;
    }

static JSValue js_sandbox_init_global(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSSandbox *sb = JS_GetOpaque2(ctx, this_val, js_sandbox_class_id);
    if (!sb) return JS_EXCEPTION;
    if (sb->g_inited) return JS_ThrowTypeError(ctx, "global already initialized");

    if (argc != 0 && JS_IsArray(argv[0])) {
        int64_t arrlen;
        if (JS_GetLength(ctx, argv[0], &arrlen) != -1){
            for (int64_t i = 0; i < arrlen; i++) {
                JSValue obj = JS_GetPropertyUint32(ctx, argv[0], i);
                const char* name = JS_ToCString(ctx, obj);
                JS_FreeValue(ctx, obj);
                if (!name)
                    return JS_EXCEPTION;
                int ret = add_intrinsic(ctx, name, strlen(name));
                JS_FreeCString(ctx, name);
                if (ret != 0)
                    return JS_EXCEPTION;
            }
            return JS_UNDEFINED;
        }
    }

    if (
        JS_AddIntrinsicDate(ctx) ||
        JS_AddIntrinsicEval(ctx) ||
        JS_AddIntrinsicRegExp(ctx) ||
        JS_AddIntrinsicJSON(ctx) ||
        JS_AddIntrinsicProxy(ctx) ||
        JS_AddIntrinsicMapSet(ctx) ||
        JS_AddIntrinsicTypedArrays(ctx) ||
        JS_AddIntrinsicPromise(ctx) ||
        JS_AddIntrinsicWeakRef(ctx) ||
        JS_AddIntrinsicAToB(ctx) ||
        JS_AddPerformance(ctx)
    ) {
            return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

static JSValue js_sandbox_call(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSSandbox *sb = JS_GetOpaque2(ctx, this_val, js_sandbox_class_id);
    if (!sb) return JS_EXCEPTION;

    if (argc < 1 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "call(code: string, name?: string)");

    size_t len;
    const char *code = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!code) return JS_EXCEPTION;

    const char *name = "<sandbox>";
    if (argc >= 2 && JS_IsString(argv[1])) {
        name = JS_ToCString(ctx, argv[1]);
        if (!name) {
            JS_FreeCString(ctx, code);
            return JS_EXCEPTION;
        }
    }

    JSValue ret = JS_Eval(sb->app->ctx, code, len, name,
        JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_BACKTRACE_BARRIER);

    if (argc >= 2 && JS_IsString(argv[1]))
        JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, code);

    return ret;
}

static JSValue js_sandbox_get_global(JSContext *ctx, JSValueConst this_val) {
    TJSSandbox *sb = JS_GetOpaque2(ctx, this_val, js_sandbox_class_id);
    if (!sb) return JS_EXCEPTION;
    return JS_DupValue(ctx, sb->global);
}

static JSValue js_sandbox_loadModule(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSSandbox *sb = JS_GetOpaque2(ctx, this_val, js_sandbox_class_id);
    if (!sb) return JS_EXCEPTION;

    if (argc < 1 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "loadModule(code: string, name: string)");

    size_t len;
    const char *code = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!code) return JS_EXCEPTION;

    const char *name = "<sandbox-module>";
    if (argc >= 2 && JS_IsString(argv[1])) {
        name = JS_ToCString(ctx, argv[1]);
        if (!name) {
            JS_FreeCString(ctx, code);
            return JS_EXCEPTION;
        }
    }

    JSValue ret = JS_Eval(sb->app->ctx, code, len, name,
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_FLAG_BACKTRACE_BARRIER);

    if (argc >= 2 && JS_IsString(argv[1]))
        JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, code);

    if (JS_IsException(ret))
        return ret;

    /* Resolve and eval the module */
    if (JS_ResolveModule(sb->app->ctx, ret) < 0) {
        JS_FreeValue(sb->app->ctx, ret);
        return JS_EXCEPTION;
    }

    JSValue eval_ret = JS_EvalFunction(sb->app->ctx, JS_DupValue(sb->app->ctx, ret));
    JSModuleDef *m = (JSModuleDef *)JS_VALUE_GET_PTR(ret);
    JS_FreeValue(sb->app->ctx, ret);

    if (JS_IsException(eval_ret)) {
        JS_FreeValue(sb->app->ctx, eval_ret);
        return JS_EXCEPTION;
    }
    JS_FreeValue(sb->app->ctx, eval_ret);

    return JS_GetModuleNamespace(sb->app->ctx, m);
}

static const JSCFunctionListEntry js_sandbox_proto_funcs[] = {
    JS_CFUNC_DEF("call", 2, js_sandbox_call),
    JS_CFUNC_DEF("loadModule", 2, js_sandbox_loadModule),
    JS_CFUNC_DEF("initGlobal", 1, js_sandbox_init_global),
    JS_CGETSET_DEF("global", js_sandbox_get_global, NULL),
};

static JSValue tjs_setCanBlock(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    CHECK_IF_IN_SANDBOX();
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_SetCanBlock(rt, argc > 0 && JS_ToBool(ctx, argv[0]) ? true : false);
    return JS_UNDEFINED;
}

static JSValue tjs_setMemoryLimit(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    uint32_t v;
    CHECK_IF_IN_SANDBOX();

    if (JS_ToUint32(ctx, &v, argv[0])) {
        return JS_EXCEPTION;
    }
    JS_SetMemoryLimit(JS_GetRuntime(ctx), v);
    return JS_UNDEFINED;
}

static JSValue tjs_setMaxStackSize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    uint32_t v;
    CHECK_IF_IN_SANDBOX();

    if (JS_ToUint32(ctx, &v, argv[0])) {
        return JS_EXCEPTION;
    }
    /* This is the ONLY live path for --max-stack-size: the CLI parses it in
     * src/commands/run.ts:123 and cts/src/config.ts:356 calls straight through
     * to here. Passing the request to QuickJS unchecked put its soft limit at
     * or below the guard page for any value >= the thread's real stack, and an
     * ordinary recursion then died on the guard page with rc 0xC00000FD and
     * NOTHING on stdout or stderr — see the OBSERVED table above
     * tjs__clamp_stack_size in utils.c. A clamped value still throws a
     * catchable RangeError; an unclamped one cannot.
     *
     * The clamp reads the OS stack bounds, not the stack pointer, which is
     * required here: this runs many JS frames deep, so an sp-relative
     * measurement would under-report the available stack badly. */
    bool clamped = false;
    size_t limit = tjs__clamp_stack_size((size_t) v, &clamped);
    if (clamped) {
        /* Report it. A silently ignored resource flag is the failure mode that
         * let --memory-limit=16MB allow 4GB (src/commands/run.ts:115-121), and
         * the requirement for this flag is that no value may produce an empty
         * diagnostic. Only fires when the caller asked for more than the
         * thread can address, so the default tiers (2/4/6MB, cts/src/config.ts:37-41)
         * never print.
         *
         * Prints the thread's TOTAL stack rather than the usable ceiling: the
         * ceiling is by construction equal to `limit` whenever clamped is true,
         * so naming it would print the same number twice and read like a bug.
         * The total is also the actionable figure, since it is what /STACK (or
         * the thread's dwStackSize / RLIMIT_STACK) controls. */
        fprintf(stderr,
                "cno: --max-stack-size=%zu does not fit in this thread's %zu-byte stack; "
                "using %zu instead\n",
                (size_t) v,
                tjs__native_stack_total_size(),
                limit);
        fflush(stderr);
    }
    JS_SetMaxStackSize(JS_GetRuntime(ctx), limit);
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
    /* TJS_NewUint8Array takes ownership of buf and frees it (via tjs__buf_free)
     * on every path, including failure. No manual js_free here. */
    return TJS_NewUint8Array(ctx, buf, len);
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

/* Run a value previously produced by JS_Eval(..., JS_EVAL_FLAG_COMPILE_ONLY)
 * (either global/script or module code) — generic counterpart to
 * js_module_eval, but not tied to the Module class wrapper. Needed to
 * actually execute a plain compiled-script value round-tripped through
 * tjs_serialize()/tjs_deserialize() (the JS_TAG_FUNCTION_BYTECODE case). */
static JSValue tjs_eval_compiled(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "evalCompiled(compiledValue) requires 1 argument");
    return JS_EvalFunction(ctx, JS_DupValue(ctx, argv[0]));
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

    CHECK_IF_IN_SANDBOX();

    TJSRuntime* trt = TJS_GetRuntime(ctx);
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
    CHECK_IF_IN_SANDBOX();
    
    if (argc == 0 || !JS_IsFunction(ctx, argv[0])){
        return JS_ThrowTypeError(ctx, "argument must be a function");
    }

    TJSRuntime* trt = TJS_GetRuntime(ctx);
    JS_FreeValue(ctx, trt->builtins.dispatch_event_fn);
    trt->builtins.dispatch_event_fn = JS_DupValue(ctx, argv[0]);
    return JS_UNDEFINED;
}

static JSValue tjs__getset_promise_hook(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    CHECK_IF_IN_SANDBOX();
    TJSRuntime* trt = TJS_GetRuntime(ctx);

    if (argc == 0) return JS_DupValue(ctx, trt->builtins.promise_hook_fn);

    if (JS_IsUndefined(trt->builtins.promise_hook_fn)) {
        JS_SetPromiseHook(JS_GetRuntime(ctx), tjs__promise_hook, trt);
    } else {
        JS_FreeValue(ctx, trt->builtins.promise_hook_fn);
    }

    if (JS_IsFunction(ctx, argv[0])) {
        trt->builtins.promise_hook_fn = JS_DupValue(ctx, argv[0]);
    } else {
        JS_SetPromiseHook(JS_GetRuntime(ctx), NULL, NULL);
        trt->builtins.promise_hook_fn = JS_UNDEFINED;
    }
    return JS_UNDEFINED;
}

/* process.nextTick checkpoint */
static JSValue tjs__set_nexttick_drain(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    CHECK_IF_IN_SANDBOX();
    TJSRuntime* trt = TJS_GetRuntime(ctx);

    JS_FreeValue(ctx, trt->builtins.nexttick_drain_fn);
    if (argc > 0 && JS_IsFunction(ctx, argv[0])) {
        trt->builtins.nexttick_drain_fn = JS_DupValue(ctx, argv[0]);
    } else {
        /* Unregistering: drop any pending flag too, or the checkpoint would
         * keep looping on a drain that no longer exists. */
        trt->builtins.nexttick_drain_fn = JS_UNDEFINED;
        trt->jobs.ticks_pending = false;
    }
    return JS_UNDEFINED;
}

static JSValue tjs__notify_nexttick(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    trt->jobs.ticks_pending = true;
    return JS_UNDEFINED;
}

void tjs__run_next_ticks(TJSRuntime* trt) {
    if (!trt->jobs.ticks_pending || trt->jobs.ticks_draining || trt->jobs.paused) {
        return;
    }
    if (JS_IsUndefined(trt->builtins.nexttick_drain_fn)) {
        /* No drain registered: DROP the flag rather than leave it set. */
        trt->jobs.ticks_pending = false;
        return;
    }

    JSContext* ctx = trt->main_ctx;

    /* Cleared BEFORE the call so a tick callback that queues another tick can
     * re-raise it. The JS drain loops until its queue is empty, so the common
     * case costs one crossing per checkpoint, not one per callback. */
    trt->jobs.ticks_pending = false;
    trt->jobs.ticks_draining = true;
    JSValue ret = JS_Call(ctx, trt->builtins.nexttick_drain_fn, JS_UNDEFINED, 0, NULL);
    trt->jobs.ticks_draining = false;

    if (JS_IsException(ret)) {
        /* The JS drain catches each callback and only rethrows when there is no
         * 'uncaughtException' listener. Route that exactly like a failed promise
         * job: today the drain runs AS a promise job, so this is the same path
         * the error already takes, diagnostic and exit code included. */
        JSValue js_err = JS_GetException(ctx);
        if (JS_IsUncatchableError(js_err)) {
            TJS_Stop(trt);
        } else {
            JSValue retv = tjs__dispatch_event(ctx, EV_JOB_EXCEPTION, js_err);
            if (JS_IsEqual(ctx, retv, JS_FALSE)) {
                TJS_Stop(trt);
            }
            JS_FreeValue(ctx, retv);
        }
        JS_FreeValue(ctx, js_err);
    } else {
        JS_FreeValue(ctx, ret);
    }
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

static JSValue tjs_new_shared_bytes_copy(JSContext *ctx, const uint8_t *src, size_t len) {
	if (len >= INT32_MAX)
		return JS_ThrowRangeError(ctx, "buffer too large");

	uint8_t *data = tjs__sab_alloc(NULL, len + 1);
	if (!data)
		return JS_ThrowOutOfMemory(ctx);
	if (len)
		memcpy(data, src, len);
	data[len] = 0;

	JSValue buffer = JS_NewArrayBuffer(ctx, data, len + 1, NULL, NULL, true);
	tjs__sab_free(NULL, data);
	if (JS_IsException(buffer))
		return buffer;

	JSValue args[] = { buffer, JS_NewInt64(ctx, 0), JS_NewInt64(ctx, len) };
	JSValue bytes = JS_NewTypedArray(ctx, 3, args, JS_TYPED_ARRAY_UINT8);
	JS_FreeValue(ctx, buffer);
	return bytes;
}

static JSValue tjs_toSharedBytes(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
	if (argc == 0)
		return JS_ThrowTypeError(ctx, "argument must be a string or byte buffer");

	if (JS_IsString(argv[0])) {
		size_t len = 0;
		const char *str = JS_ToCStringLen(ctx, &len, argv[0]);
		if (!str)
			return JS_EXCEPTION;
		JSValue bytes = tjs_new_shared_bytes_copy(ctx, (const uint8_t *)str, len);
		JS_FreeCString(ctx, str);
		return bytes;
	}

	size_t len = 0;
	uint8_t *data = JS_GetAnyBuffer(ctx, &len, argv[0]);
	if (!data)
		return JS_ThrowTypeError(ctx, "argument must be a string or byte buffer");
	return tjs_new_shared_bytes_copy(ctx, data, len);
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

static JSValue tjs_isProxy(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return JS_NewBool(ctx, argc >= 1 && JS_IsProxy(argv[0]));
}

#define TJS_ENGINE_PREDICATE(name, predicate) \
    static JSValue tjs_##name(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) { \
        return JS_NewBool(ctx, argc >= 1 && predicate(argv[0])); \
    }

TJS_ENGINE_PREDICATE(isDataView, JS_IsDataView)
TJS_ENGINE_PREDICATE(isAsyncFunction, JS_IsAsyncFunction)
TJS_ENGINE_PREDICATE(isArgumentsObject, JS_IsArgumentsObject)
TJS_ENGINE_PREDICATE(isGeneratorFunction, JS_IsGeneratorFunction)
TJS_ENGINE_PREDICATE(isGeneratorObject, JS_IsGeneratorObject)
TJS_ENGINE_PREDICATE(isMapIterator, JS_IsMapIterator)
TJS_ENGINE_PREDICATE(isSetIterator, JS_IsSetIterator)
TJS_ENGINE_PREDICATE(isModuleNamespaceObject, JS_IsModuleNamespaceObject)
TJS_ENGINE_PREDICATE(isDate, JS_IsDate)
TJS_ENGINE_PREDICATE(isError, JS_IsError)
TJS_ENGINE_PREDICATE(isMap, JS_IsMap)
TJS_ENGINE_PREDICATE(isPromise, JS_IsPromise)
TJS_ENGINE_PREDICATE(isRegExp, JS_IsRegExp)
TJS_ENGINE_PREDICATE(isSet, JS_IsSet)
TJS_ENGINE_PREDICATE(isWeakMap, JS_IsWeakMap)
TJS_ENGINE_PREDICATE(isWeakRef, JS_IsWeakRef)
TJS_ENGINE_PREDICATE(isWeakSet, JS_IsWeakSet)

#undef TJS_ENGINE_PREDICATE

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
    const int MAX_ITERATIONS = 1000;

    while (JS_PromiseState(ctx, argv[0]) == JS_PROMISE_PENDING) {
        // Safety: prevent infinite loops
        if (++loop_iterations > MAX_ITERATIONS) {
            abort_exception = JS_ThrowInternalError(ctx, "waitIO: too many iterations");
            aborted = true;
            break;
        }

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
                return JS_ThrowInternalError(ctx, "waitIO aborted");
            }
            return JS_ThrowInternalError(ctx, "waitIO: promise did not settle");
        default:
            abort();
    }
}

static JSValue tjs_get_global_lexvar(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
#ifdef CJS_DISABLE_DEBUG
    return JS_ThrowTypeError(ctx, "Debug features are disabled. Please rebuild cjs");
#else
    return JS_GetGlobalLexicalVariables(ctx);
#endif
}

static const JSCFunctionListEntry tjs_engine_funcs[] = {
    TJS_CFUNC_DEF("setCanBlock", 1, tjs_setCanBlock),
    TJS_CFUNC_DEF("setMemoryLimit", 1, tjs_setMemoryLimit),
    TJS_CFUNC_DEF("setMaxStackSize", 1, tjs_setMaxStackSize),
    TJS_CFUNC_DEF("eval", 3, tjs_eval),
    TJS_CFUNC_DEF("serialize", 2, tjs_serialize),
    TJS_CFUNC_DEF("deserialize", 1, tjs_deserialize),
    TJS_CFUNC_DEF("evalCompiled", 1, tjs_eval_compiled),
    TJS_CFUNC_DEF("onModule", 1, tjs__override_module_options),
    TJS_CFUNC_DEF("onEvent", 1, tjs__set_event_receiver),
	TJS_CFUNC_DEF("promiseHook", 2, tjs__getset_promise_hook),
    TJS_CFUNC_DEF("setNextTickDrain", 1, tjs__set_nexttick_drain),
    TJS_CFUNC_DEF("notifyNextTick", 0, tjs__notify_nexttick),
	TJS_CFUNC_DEF("encodeString", 1, tjs_encodeString),
	TJS_CFUNC_DEF("toSharedBytes", 1, tjs_toSharedBytes),
	TJS_CFUNC_DEF("encodeU16String", 1, tjs_encodeU16String),
    TJS_CFUNC_DEF("decodeString", 1, tjs_decodeString),
    TJS_CFUNC_DEF("decodeU16String", 1, tjs_decodeU16String),
    TJS_CFUNC_DEF("promiseResult", 1, tjs_proimise_result),
    TJS_CFUNC_DEF("isArrayBuffer", 1, tjs_isArrayBuffer),
    TJS_CFUNC_DEF("isProxy", 1, tjs_isProxy),
    TJS_CFUNC_DEF("isDataView", 1, tjs_isDataView),
    TJS_CFUNC_DEF("isAsyncFunction", 1, tjs_isAsyncFunction),
    TJS_CFUNC_DEF("isArgumentsObject", 1, tjs_isArgumentsObject),
    TJS_CFUNC_DEF("isGeneratorFunction", 1, tjs_isGeneratorFunction),
    TJS_CFUNC_DEF("isGeneratorObject", 1, tjs_isGeneratorObject),
    TJS_CFUNC_DEF("isMapIterator", 1, tjs_isMapIterator),
    TJS_CFUNC_DEF("isSetIterator", 1, tjs_isSetIterator),
    TJS_CFUNC_DEF("isModuleNamespaceObject", 1, tjs_isModuleNamespaceObject),
    TJS_CFUNC_DEF("isDate", 1, tjs_isDate),
    TJS_CFUNC_DEF("isError", 1, tjs_isError),
    TJS_CFUNC_DEF("isMap", 1, tjs_isMap),
    TJS_CFUNC_DEF("isPromise", 1, tjs_isPromise),
    TJS_CFUNC_DEF("isRegExp", 1, tjs_isRegExp),
    TJS_CFUNC_DEF("isSet", 1, tjs_isSet),
    TJS_CFUNC_DEF("isWeakMap", 1, tjs_isWeakMap),
    TJS_CFUNC_DEF("isWeakRef", 1, tjs_isWeakRef),
    TJS_CFUNC_DEF("isWeakSet", 1, tjs_isWeakSet),
    TJS_CFUNC_DEF("detachArrayBuffer", 1, tjs_detachArrayBuffer),
    TJS_CFUNC_DEF("setImmutableArrayBuffer", 2, tjs_immutArrayBuffer),
    TJS_CFUNC_DEF("getGlobalLexVar", 0, tjs_get_global_lexvar),
    TJS_CFUNC_DEF("waitIO", 2, tjs_waitIO),

    TJS_CONST2("DUMP_BYTECODE", JS_WRITE_OBJ_BYTECODE),
    TJS_CONST2("DUMP_NODEBUG", JS_WRITE_OBJ_STRIP_DEBUG),
    TJS_CONST2("DUMP_NOSOURCE", JS_WRITE_OBJ_STRIP_SOURCE),
    TJS_CONST2("DUMP_DEEP", JS_WRITE_OBJ_REFERENCE),
    TJS_CONST2("DUMP_LOCAL", JS_WRITE_OBJ_SAB),
    TJS_CONST2("DUMP_DEFAULT", JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE),

    TJS_CONST2("EVAL_MODULE", JS_EVAL_TYPE_MODULE),
    TJS_CONST2("EVAL_GLOBAL", JS_EVAL_TYPE_GLOBAL),
    TJS_CONST2("EVAL_ASYNC", JS_EVAL_FLAG_ASYNC),
    TJS_CONST2("EVAL_STRICT", JS_EVAL_FLAG_STRICT),
    TJS_CONST2("EVAL_NEW_BACKTRACE", JS_EVAL_FLAG_BACKTRACE_BARRIER),
    TJS_CONST2("EVAL_COMPILE_ONLY", JS_EVAL_FLAG_COMPILE_ONLY),
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
    TJS_CONST2("BEFORE_UNLOAD", EV_BEFORE_UNLOAD),
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
    JS_DefinePropertyValueStr(ctx, versions, "curl", JS_NewString(ctx, curl_version()), JS_PROP_C_W_E);
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

    const char* expat_version =
#ifdef HAVE_XML_EXPAT_VERSION
        XML_ExpatVersion()
#else
        STRINGIFY(XML_MAJOR_VERSION) "." STRINGIFY(XML_MINOR_VERSION) "." STRINGIFY(XML_MICRO_VERSION)
#endif
    ;
    JS_DefinePropertyValueStr(ctx, versions, "expat", JS_NewString(ctx, expat_version), JS_PROP_C_W_E);
#ifdef CJS_HAVE_BROTLI
    /* Runtime version string, e.g. "1.1.0" */
    uint32_t v = BrotliEncoderVersion();
    char ver[32];
    snprintf(ver, sizeof(ver), "%u.%u.%u", (v >> 24) & 0xFFF, (v >> 12) & 0xFFF, v & 0xFFF);
    JS_DefinePropertyValueStr(ctx, versions, "brotli", JS_NewString(ctx, ver), JS_PROP_C_W_E);
#endif

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

    // class Sandbox
    JS_NewClassID(JS_GetRuntime(ctx), &js_sandbox_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_sandbox_class_id, &js_sandbox_class);
    JSValue sb_proto = JS_NewObjectProto(ctx, JS_NULL);
    JS_SetPropertyFunctionList(ctx, sb_proto, js_sandbox_proto_funcs, countof(js_sandbox_proto_funcs));
    JS_SetClassProto(ctx, js_sandbox_class_id, sb_proto);
    JSValue sb_ctor = JS_NewCFunction2(ctx, js_sandbox_ctor, "Sandbox", 0, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, sb_ctor, sb_proto);
    JS_DefinePropertyValueStr(ctx, ns, "Sandbox", sb_ctor, JS_PROP_C_W_E);
}
