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
#include "utils.h"

static JSCFunctionListEntry tjs__uv_errno[] = {
#define MAP_FN(name, __) TJS_CONST2(#name, UV_ ## name),
	UV_ERRNO_MAP(MAP_FN)
};

JSValue tjs_new_error(JSContext *ctx, int err) {
    char buf[256];

    snprintf(buf, sizeof(buf), "%s: %s", uv_err_name(err), uv_strerror(err));

    JSValue obj;
    obj = JS_NewError(ctx);
	JS_DefinePropertyValue(ctx, obj, JS_ATOM_name, JS_NewString(ctx, "IOError"), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValue(ctx, obj, JS_ATOM_message, JS_NewString(ctx, buf), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx,
                              obj,
                              "code",
                              JS_NewInt32(ctx, err),
                              JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    return obj;
}

JSValue tjs_new_error_path(JSContext *ctx, int err, const char *path) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s, path '%s'", uv_err_name(err), uv_strerror(err), path ? path : "(null)");

    JSValue obj = JS_NewError(ctx);
    JS_DefinePropertyValue(ctx, obj, JS_ATOM_name, JS_NewString(ctx, "IOError"), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValue(ctx, obj, JS_ATOM_message, JS_NewString(ctx, buf), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, obj, "code", JS_NewInt32(ctx, err), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    if (JS_IsException(obj)) {
        obj = JS_NULL;
    }
    return obj;
}

static JSValue tjs_error_constructor(JSContext *ctx, JSValue new_target, int argc, JSValue *argv) {
    int err;
    if (JS_ToInt32(ctx, &err, argv[0])) {
        return JS_EXCEPTION;
    }
    return tjs_new_error(ctx, err);
}

JSValue tjs_throw_errno(JSContext *ctx, int err) {
    JSValue obj;
    obj = tjs_new_error(ctx, err);
    if (JS_IsException(obj)) {
        obj = JS_NULL;
    }
    return JS_Throw(ctx, obj);
}

JSValue tjs_throw_errno_path(JSContext *ctx, int err, const char *path) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s, path '%s'", uv_err_name(err), uv_strerror(err), path ? path : "(null)");

    JSValue obj;
    obj = JS_NewError(ctx);
    JS_DefinePropertyValue(ctx, obj, JS_ATOM_name, JS_NewString(ctx, "IOError"), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValue(ctx, obj, JS_ATOM_message, JS_NewString(ctx, buf), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx,
                              obj,
                              "code",
                              JS_NewInt32(ctx, err),
                              JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    if (JS_IsException(obj)) {
        obj = JS_NULL;
    }
    return JS_Throw(ctx, obj);
}

JSValue tjs__error_strerr(JSContext *ctx, JSValueConst this_val, int argc, JSValue *argv){
	uint32_t err;
	if (argc == 0 || -1 == JS_ToUint32(ctx, &err, argv[0])) {
		err = errno;
	}

	const char *msg = uv_strerror(err);
	const char *name = uv_err_name(err);
	if (msg == NULL || name == NULL) {
		return JS_ThrowTypeError(ctx, "strerror: invalid error code");
	}

	char buf[256];
	int len = snprintf(buf, sizeof(buf), "%s: %s", name, msg);
	return JS_NewStringLen(ctx, buf, len);
}

JSCFunctionListEntry tjs__error_funcs[] = {
	JS_CFUNC_DEF2("Error", 1, tjs_error_constructor, JS_CFUNC_constructor),
	JS_CFUNC_DEF("strerror", 0, tjs__error_strerr)
};

void tjs__mod_error_init(JSContext *ctx, JSValue ns) {
	JS_SetPropertyFunctionList(ctx, ns, tjs__error_funcs, countof(tjs__error_funcs));

	JSValue uv_errno_obj = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, uv_errno_obj, tjs__uv_errno, countof(tjs__uv_errno));
	JS_DefinePropertyValueStr(ctx, ns, "errno", uv_errno_obj, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
}
