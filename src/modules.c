/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
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

#include <string.h>

#ifndef PATH_MAX // windows
#define PATH_MAX 2048
#endif

// # internal modules
struct TJSModule {
	const char *name;
	void (*init)(JSContext *ctx, JSValue ns);
	bool worker;
};

static const struct TJSModule tjs_modules[] = {
	// name init_fn allow_in_worker
	{ "algorithm", tjs__mod_algorithm_init, true },
	{ "asyncfs", tjs__mod_asyncfs_init, true },
#ifdef CJS__HAS_CURL
	{ "curl", tjs__mod_curl_init, false }, // not thread-safe currently
#endif
	{ "crypto", tjs__mod_crypto_init, true },
	{ "console", tjs__mod_console_init, true },
	{ "dns", tjs__mod_dns_init, true },
	{ "engine", tjs__mod_engine_init, true },
	{ "error", tjs__mod_error_init, true },
	{ "ffi", tjs__mod_ffi_init, true },
	{ "fs", tjs__mod_fs_init, true },
	{ "fswatch", tjs__mod_fswatch_init, true },
	{ "http", tjs__mod_http_init, true },
	{ "os", tjs__mod_os_init, true },
	{ "process", tjs__mod_process_init, true },
	/* pty merged into process module */
	{ "signals", tjs__mod_signals_init, false }, // worker is not allowed to control process behavior
	{ "sourcemap", tjs__mod_sourcemap_init, true },
	{ "sqlite3", tjs__mod_sqlite3_init, true },
	{ "ssl", tjs__mod_ssl_init, true },
	{ "streams", tjs__mod_streams_init, true },
	{ "sys", tjs__mod_sys_init, true },
#ifdef CJS__HAS_ICONV
	{ "text", tjs__mod_text_init, true },
#endif
	{ "timers", tjs__mod_timers_init, true },
	{ "udp", tjs__mod_udp_init, true },
#ifdef CJS__HAS_WASM
	{ "wasm", tjs__mod_wasm_init, false },
#endif
	{ "worker", tjs__mod_worker_init, true },
	{ "xml", tjs__mod_xml_init, true },
	{ "zlib", tjs__mod_zlib_init, true },
	{ "socket", tjs__mod_socket_init, true },
#ifdef _WIN32
    { "win32", tjs__mod_win32_init, true },
#endif
};

JSValue tjs__module_use(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic, JSValueConst* value) {
	JSValue ns = value[0];
	TJSRuntime* qrt = TJS_GetRuntime(ctx);

	// find name
	if(argc == 0){
		return JS_NULL;
	}

	const char* name = JS_ToCString(ctx, argv[0]);
	if(!name) return JS_NULL;

	const struct TJSModule *mod = NULL;
	for (int i = 0; i < countof(tjs_modules); i ++){
		const struct TJSModule *m = &tjs_modules[i];
		if (strcmp(m->name, name) == 0){
			mod = m;
			break;
		}
	}
	if(!mod || (!mod->worker && qrt->is_worker)) {
		JS_FreeCString(ctx, name);
		return JS_NULL;
	}

	JSValue module_obj = JS_GetPropertyStr(ctx, ns, mod->name);
	if(!JS_IsUndefined(module_obj)){
		JS_FreeCString(ctx, name);  /* fix: name was leaked on cache hit */
		return module_obj;
	}

	// init
	module_obj = JS_NewObjectProto(ctx, JS_NULL);
	mod->init(ctx, module_obj);
	JS_SetPropertyStr(ctx, ns, mod->name, JS_DupValue(ctx, module_obj));
	JS_FreeCString(ctx, name);
	return module_obj;
}

JSValue tjs__mod_list_init(JSContext* ctx){
	JSValue obj = JS_NewArray(ctx);
	for (int i = 0; i < countof(tjs_modules); i ++){
		const struct TJSModule *m = &tjs_modules[i];
		JS_SetPropertyUint32(ctx, obj, i, JS_NewString(ctx, m->name));
	}
	JS_SetLength(ctx, obj, countof(tjs_modules));
	return obj;
}

// # module loader
int tjs__module_checkattr(JSContext *ctx, void *opaque, JSValueConst attributes){
	// by default, we will not check attributes for better capability
	TJSRuntime *trt = TJS_GetRuntime(ctx);
	if(!JS_IsUndefined(trt->module.attrchecker)){
		JSValueConst args[] = { attributes };
		JSValue ret = JS_Call(ctx, trt->module.attrchecker, JS_UNDEFINED, 1, args);
		if(JS_IsException(ret)){
			JS_FreeValue(ctx, ret);
			return -1;	// pass-through exception
		}
		JS_FreeValue(ctx, ret);
	}
	return 0;
}

JSModuleDef *tjs__module_loader(JSContext *ctx, const char *module_name, void *opaque, JSValueConst attributes) {
    static const char json_tpl_start[] = "export default JSON.parse(`";
    static const char json_tpl_end[] = "`);";

	JSModuleDef *m;
    JSValue func_val;
    int r, is_json;
    DynBuf dbuf;
	TJSRuntime *trt = TJS_GetRuntime(ctx);

	// try JS loader
	if(!JS_IsUndefined(trt->module.loader)){
		JSValueConst args[] = { JS_NewString(ctx, module_name), attributes };
		JSValue ret = JS_Call(ctx, trt->module.loader, JS_UNDEFINED, 2, args);
		JS_FreeValue(ctx, args[0]);	// args[1] owned by qjs
		if (JS_IsString(ret)) {
			size_t strlen;
			const char *str = JS_ToCStringLen(ctx, &strlen, ret);
			dbuf_init(&dbuf);
			dbuf_put(&dbuf, (const uint8_t *) str, strlen +1); // \0 terminator
			JS_FreeCString(ctx, str);
			JS_FreeValue(ctx, ret);
			goto compile;
		} else if(JS_IsObject(ret)){
			// try class Module
			JSModuleDef* m = tjs__module_getdef(ctx, ret);
			JS_FreeValue(ctx, ret);
			return m;
		} else if(JS_IsException(ret)){
			// failed
			JS_FreeValue(ctx, ret);
			return NULL;
		} else {
			JS_FreeValue(ctx, ret);
			JS_ThrowTypeError(ctx, "module loader did not return a string or a module");
			return NULL;
		}
	}

    tjs_dbuf_init(ctx, &dbuf);

    is_json = js__has_suffix(module_name, ".json");

    /* Support importing JSON files because... why not? */
    if (is_json) {
        dbuf_put(&dbuf, (const uint8_t *) json_tpl_start, strlen(json_tpl_start));
    }

    r = tjs__load_file(ctx, &dbuf, module_name);
    if (r != 0) {
        dbuf_free(&dbuf);
        JS_ThrowReferenceError(ctx, "could not load '%s'", module_name);
        return NULL;
    }

    if (is_json) {
        dbuf_put(&dbuf, (const uint8_t *) json_tpl_end, strlen(json_tpl_end));
    }

    /* Add null termination, required by JS_Eval. */
    dbuf_putc(&dbuf, '\0');

compile:
    /* compile JS the module */
    func_val =
        JS_Eval(ctx, (char *) dbuf.buf, dbuf.size - 1, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    dbuf_free(&dbuf);
    if (JS_IsException(func_val)) {
        JS_FreeValue(ctx, func_val);
        return NULL;
    }

    /* XXX: could propagate the exception */
    js_module_set_import_meta(ctx, func_val, true, false);
    /* the module is already referenced, so we must free it */
    m = JS_VALUE_GET_PTR(func_val);
    JS_FreeValue(ctx, func_val);

    return m;
}

#define TJS__PATHSEP_POSIX '/'
#if defined(_WIN32)
#define TJS__PATHSEP     '\\'
#define TJS__PATHSEP_STR "\\"
#else
#define TJS__PATHSEP     '/'
#define TJS__PATHSEP_STR "/"
#endif

int js_module_set_import_meta(JSContext *ctx, JSValue func_val, bool use_realpath, bool is_main) {
    JSModuleDef *m;
    char buf[PATH_MAX + 16] = { 0 };
    int r;
    JSValue meta_obj;
    JSAtom module_name_atom;
    const char *module_name;
    char module_dirname[PATH_MAX] = { 0 };
    char module_basename[PATH_MAX] = { 0 };
	TJSRuntime* trt = TJS_GetRuntime(ctx);

    CHECK_EQ(JS_VALUE_GET_TAG(func_val), JS_TAG_MODULE);
    m = JS_VALUE_GET_PTR(func_val);

    module_name_atom = JS_GetModuleName(ctx, m);
    module_name = JS_AtomToCString(ctx, module_name_atom);
    JS_FreeAtom(ctx, module_name_atom);
    if (!module_name) {
        return -1;
    }

	meta_obj = JS_GetImportMeta(ctx, m);
    if (JS_IsException(meta_obj)) {
        JS_FreeCString(ctx, module_name);
        return -1;
    }

	// try js resolver
	if(!JS_IsUndefined(trt->module.metaloader)){
		JSValueConst args[] = { JS_NewString(ctx, module_name), meta_obj };
		JSValue ret = JS_Call(ctx, trt->module.metaloader, JS_UNDEFINED, 2, args);
		JS_FreeValue(ctx, args[0]);
		JS_FreeValue(ctx, meta_obj);
		JS_FreeCString(ctx, module_name);  /* fix: was leaked on this path */
		if (JS_IsException(ret)) {         /* fix: propagate exception instead of swallowing */
			JS_FreeValue(ctx, ret);
			return -1;
		}
		JS_FreeValue(ctx, ret);
		return 0;
	}

    /* realpath() cannot be used with builtin modules
        because the corresponding module source code is not
        necessarily present */
    if (use_realpath) {
        uv_fs_t req;
        r = uv_fs_realpath(NULL, &req, module_name, NULL);
        if (r != 0) {
            uv_fs_req_cleanup(&req);
            JS_ThrowTypeError(ctx, "realpath failure");
            JS_FreeCString(ctx, module_name);
			JS_FreeValue(ctx, meta_obj);
            return -1;
        }
        js__pstrcpy(buf, sizeof(buf), "file://");
        js__pstrcat(buf, sizeof(buf), req.ptr);
        uv_fs_req_cleanup(&req);

        // When using realpath we have the opportunity to extract the dirname
        // and basename and add them to the meta. Since the path is now absolute
        // all we need to do is split on the last path separator.
        const char *start = buf + 7; /* skip file:// */
        char *p = strrchr(start, TJS__PATHSEP);
        strncpy(module_dirname, start, p - start);
        strcpy(module_basename, p + 1);
    } else {
        js__pstrcat(buf, sizeof(buf), module_name);
    }

    JS_FreeCString(ctx, module_name);

    JS_DefinePropertyValueStr(ctx, meta_obj, "url", JS_NewString(ctx, buf), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, meta_obj, "main", JS_NewBool(ctx, is_main), JS_PROP_C_W_E);
    if (use_realpath) {
        JS_DefinePropertyValueStr(ctx, meta_obj, "dirname", JS_NewString(ctx, module_dirname), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, meta_obj, "basename", JS_NewString(ctx, module_basename), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, meta_obj, "path", JS_NewString(ctx, buf + 7), JS_PROP_C_W_E);
    }
    JS_FreeValue(ctx, meta_obj);
    return 0;
}

static inline void tjs__normalize_pathsep(const char *name) {
#if defined(_WIN32)
    char *p;

    for (p = name; *p; p++) {
        if (p[0] == TJS__PATHSEP_POSIX) {
            p[0] = TJS__PATHSEP;
        }
    }
#else
    (void) name;
#endif
}

char *tjs__module_normalizer(JSContext *ctx, const char *base_name, const char *name, void *opaque) {
#if 0
    printf("normalize: %s %s\n", base_name, name);
#endif

	TJSRuntime* trt = TJS_GetRuntime(ctx);
	if (!JS_IsUndefined(trt->module.resolver)){
		JSValueConst args[] = { JS_NewString(ctx, name), JS_NewString(ctx, base_name) };
		JSValue ret = JS_Call(ctx, trt->module.resolver, JS_NULL, 2, args);
		for(int i = 0; i < 2; i++) JS_FreeValue(ctx, args[i]);

		if(JS_IsString(ret)){
			const char* str = JS_ToCString(ctx, ret);
			char* retstr = js_strdup(ctx, str);
			JS_FreeCString(ctx, str);
			JS_FreeValue(ctx, ret);
			return retstr;
		} else if(JS_IsException(ret)){
			return NULL;
		} else {
			JS_ThrowTypeError(ctx, "module resolver must return a string");
			JS_FreeValue(ctx, ret);
			return NULL;
		}
	}

    char *filename, *p;
    const char *r;
    int len;

    if (name[0] != '.') {
        /* if no initial dot, the module name is not modified */
        return js_strdup(ctx, name);
    }

    /* Normalize base_name. This is the path to the importing module, and
     * it should have the platform native path separator.
     */
    tjs__normalize_pathsep(name);

    p = strrchr(base_name, TJS__PATHSEP);
    if (p) {
        len = p - base_name;
    } else {
        len = 0;
    }

    filename = js_malloc(ctx, len + strlen(name) + 1 + 1);
    if (!filename) {
        return NULL;
    }
    memcpy(filename, base_name, len);
    filename[len] = '\0';

    /* we only normalize the leading '..' or '.' */
    r = name;
    for (;;) {
        if (r[0] == '.' && r[1] == TJS__PATHSEP_POSIX) {
            r += 2;
        } else if (r[0] == '.' && r[1] == '.' && r[2] == TJS__PATHSEP_POSIX) {
            /* remove the last path element of filename, except if "."
               or ".." */
            if (filename[0] == '\0') {
                break;
            }
            p = strrchr(filename, TJS__PATHSEP);
            if (!p) {
                p = filename;
            } else {
                p++;
            }
            if (!strcmp(p, ".") || !strcmp(p, "..")) {
                break;
            }
            if (p > filename) {
                p--;
            }
            *p = '\0';
            r += 3;
        } else {
            break;
        }
    }
    if (filename[0] != '\0') {
        strcat(filename, TJS__PATHSEP_STR);
    }
    strcat(filename, r);

    /* Re-normalize the path. The name part will have posix style paths, so
     * normalize it to the platform native separator.
     */
    tjs__normalize_pathsep(filename);

    return filename;
}

#undef TJS__PATHSEP
#undef TJS__PATHSEP_STR
#undef TJS__PATHSEP_POSIX
