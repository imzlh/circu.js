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

#ifndef TJS_UTILS_H
#define TJS_UTILS_H

#include "../deps/quickjs/cutils.h"

#ifdef FOREIGN_QJS
#include <quickjs.h>
#else
#include "../deps/quickjs/quickjs.h"
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <uv.h>


#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct AssertionInfo {
    const char *file_line;  // filename:line
    const char *message;
    const char *function;
};

#define ERROR_AND_ABORT(expr)                                                                                          \
    do {                                                                                                               \
        static const struct AssertionInfo args = { __FILE__ ":" STRINGIFY(__LINE__), #expr, PRETTY_FUNCTION_NAME };    \
        tjs_assert(args);                                                                                              \
    } while (0)

#ifdef __GNUC__
#define TJS__LIKELY(expr)    __builtin_expect(!!(expr), 1)
#define TJS__UNLIKELY(expr)  __builtin_expect(!!(expr), 0)
#define PRETTY_FUNCTION_NAME __PRETTY_FUNCTION__
#else
#define TJS__LIKELY(expr)    expr
#define TJS__UNLIKELY(expr)  expr
#define PRETTY_FUNCTION_NAME ""
#endif

#define STRINGIFY_(x) #x
#define STRINGIFY(x)  STRINGIFY_(x)

#define CHECK(expr)                                                                                                    \
    do {                                                                                                               \
        if (TJS__UNLIKELY(!(expr))) {                                                                                  \
            ERROR_AND_ABORT(expr);                                                                                     \
        }                                                                                                              \
    } while (0)

#define CHECK_EQ(a, b)      CHECK((a) == (b))
#define CHECK_GE(a, b)      CHECK((a) >= (b))
#define CHECK_GT(a, b)      CHECK((a) > (b))
#define CHECK_LE(a, b)      CHECK((a) <= (b))
#define CHECK_LT(a, b)      CHECK((a) < (b))
#define CHECK_NE(a, b)      CHECK((a) != (b))
#define CHECK_NULL(val)     CHECK((val) == NULL)
#define CHECK_NOT_NULL(val) CHECK((val) != NULL)

void tjs_assert(const struct AssertionInfo info);

#define TJS_UVCONST(x)        JS_PROP_INT32_DEF(#x, UV_##x, JS_PROP_ENUMERABLE)
#define TJS_CONST(x)          JS_PROP_INT32_DEF(#x, x, JS_PROP_ENUMERABLE)
#define TJS_CONST2(name, val) JS_PROP_INT32_DEF(name, val, JS_PROP_ENUMERABLE)
#define TJS_CFUNC_DEF(name, length, func1)                                                                             \
    {                                                                                                                  \
        name, JS_PROP_C_W_E, JS_DEF_CFUNC, 0, {                                                                        \
            .func = { length, JS_CFUNC_generic, { .generic = func1 } }                                                 \
        }                                                                                                              \
    }
#define TJS_CFUNC_MAGIC_DEF(name, length, func1, magic)                                                                \
    {                                                                                                                  \
        name, JS_PROP_C_W_E, JS_DEF_CFUNC, magic, {                                                                    \
            .func = { length, JS_CFUNC_generic_magic, { .generic_magic = func1 } }                                     \
        }                                                                                                              \
    }
#define TJS_CGETSET_DEF(name, fgetter, fsetter)                                                                        \
    {                                                                                                                  \
        name, JS_PROP_C_W_E, JS_DEF_CGETSET, 0, {                                                                      \
            .getset = {.get = { .getter = fgetter }, .set = { .setter = fsetter } }                                    \
        }                                                                                                              \
    }

uv_loop_t *tjs_get_loop(JSContext *ctx);
int tjs_obj2addr(JSContext *ctx, JSValue obj, struct sockaddr_storage *ss);
void tjs_addr2obj(JSContext *ctx, JSValue obj, const struct sockaddr *sa, bool skip_port);
void tjs_call_handler(JSContext *ctx, JSValue func, int argc, JSValue *argv);
void tjs_dump_error(JSContext *ctx, JSValue exception_val);

typedef struct {
    JSValue p;
    JSValue rfuncs[2];
} TJSPromise;

JSValue TJS_InitPromise(JSContext *ctx, TJSPromise *p);
bool TJS_IsPromisePending(JSContext *ctx, TJSPromise *p);
void TJS_FreePromise(JSContext *ctx, TJSPromise *p);
void TJS_FreePromiseRT(JSRuntime *rt, TJSPromise *p);
void TJS_ClearPromise(JSContext *ctx, TJSPromise *p);
void TJS_MarkPromise(JSRuntime *rt, TJSPromise *p, JS_MarkFunc *mark_func);
void TJS_SettlePromise(JSContext *ctx, TJSPromise *p, bool is_reject, int argc, JSValue *argv);
void TJS_ResolvePromise(JSContext *ctx, TJSPromise *p, int argc, JSValue *argv);
void TJS_RejectPromise(JSContext *ctx, TJSPromise *p, int argc, JSValue *argv);
JSValue TJS_NewResolvedPromise(JSContext *ctx, int argc, JSValue *argv);
JSValue TJS_NewRejectedPromise(JSContext *ctx, int argc, JSValue *argv);

JSValue TJS_NewUint8Array(JSContext *ctx, uint8_t *data, size_t size);

extern const char *tjs_signal_map[];
extern size_t tjs_signal_map_count;
const char *tjs_getsig(int sig);
int tjs_getsignum(const char *sig_str);

#define TJS_THROW_ARG_ERR(ctx, argno, expected)                                                                        \
    JS_ThrowTypeError(ctx, "expected argument %d to be %s", argno + 1, expected)
#define TJS_CHECK_ARG_RET(ctx, check, argno, expected)                                                                 \
    if (!(check)) {                                                                                                    \
        return TJS_THROW_ARG_ERR(ctx, argno, expected);                                                                \
    }

void tjs_dbuf_init(JSContext *ctx, DynBuf *s);

static inline uint8_t* JS_GetAnyBuffer(JSContext* ctx, size_t* psize, JSValueConst obj){
	*psize = 0;
	if (JS_GetTypedArrayType(obj) == JS_TYPED_ARRAY_UINT8)
		return JS_GetUint8Array(ctx, psize, obj);
	else if (JS_IsArrayBuffer(obj))
		return JS_GetArrayBuffer(ctx, psize, obj);

	size_t poffset = 0, plen = 0, pbytes_per_element = 0;
	JSValue arrbuf;
	if (JS_IsDataView(obj)) {
		JSValue off_val, len_val;
		/* buffer/byteOffset/byteLength are prototype accessors, but an own
		 * property on the instance shadows them and would run user JS during
		 * the JS_GetPropertyStr calls below. Callers routinely hold a raw
		 * pointer into another argument's backing store by then, so that JS
		 * could detach it (ArrayBuffer.prototype.transfer) and turn this into
		 * a use-after-free. A genuine DataView never has these as own
		 * properties, so fail closed. JS_GetOwnProperty with a NULL descriptor
		 * is a shape lookup only and runs no JS. */
		static const char *const dv_props[3] = { "buffer", "byteOffset", "byteLength" };
		for (int i = 0; i < 3; i++) {
			JSAtom a = JS_NewAtom(ctx, dv_props[i]);
			if (a == JS_ATOM_NULL)
				return NULL;
			int has_own = JS_GetOwnProperty(ctx, NULL, obj, a);
			JS_FreeAtom(ctx, a);
			if (has_own != 0) {
				if (has_own > 0)
					JS_ThrowTypeError(ctx, "DataView with an own '%s' property is not accepted", dv_props[i]);
				return NULL;
			}
		}
		arrbuf = JS_GetPropertyStr(ctx, obj, "buffer");
		if (JS_IsException(arrbuf))
			return NULL;
		off_val = JS_GetPropertyStr(ctx, obj, "byteOffset");
		if (JS_IsException(off_val)) {
			JS_FreeValue(ctx, arrbuf);
			return NULL;
		}
		len_val = JS_GetPropertyStr(ctx, obj, "byteLength");
		if (JS_IsException(len_val)) {
			JS_FreeValue(ctx, off_val);
			JS_FreeValue(ctx, arrbuf);
			return NULL;
		}
		uint64_t off64 = 0, len64 = 0;
		if (JS_ToIndex(ctx, &off64, off_val) || JS_ToIndex(ctx, &len64, len_val)) {
			JS_FreeValue(ctx, len_val);
			JS_FreeValue(ctx, off_val);
			JS_FreeValue(ctx, arrbuf);
			return NULL;
		}
		JS_FreeValue(ctx, len_val);
		JS_FreeValue(ctx, off_val);
		if (off64 > SIZE_MAX || len64 > SIZE_MAX) {
			JS_FreeValue(ctx, arrbuf);
			return NULL;
		}
		poffset = (size_t)off64;
		plen = (size_t)len64;
	} else {
		arrbuf = JS_GetTypedArrayBuffer(ctx, obj, &poffset, &plen, &pbytes_per_element);
		if (JS_IsException(arrbuf)){
			return NULL;
		}
	}
	size_t bufsz = 0;
	uint8_t* ret = JS_GetArrayBuffer(ctx, &bufsz, arrbuf);
	JS_FreeValue(ctx, arrbuf);
	if (!ret){
		/* backing buffer detached or unavailable */
		return NULL;
	}
	/* plen is the view byte length; guard against an out-of-range view */
	if (poffset > bufsz || plen > bufsz - poffset){
		return NULL;
	}
	*psize = plen;
	return ret + poffset;
}

static inline int TJS_ParseOpenFlags(const char *strflags, int len) {
    int flags = 0, read = 0, write = 0;

    for (int i = 0; i < len; i++) {
        switch (strflags[i]) {
            case 'r':
                read = 1;
                break;
            case 'w':
                write = 1;
                flags |= O_TRUNC | O_CREAT;
                break;
            case 'a':
                write = 1;
                flags |= O_APPEND | O_CREAT;
                break;
            case '+':
                read = 1;
                write = 1;
                break;
            case 'x':
                flags |= O_EXCL;
                break;
            default:
                break;
        }
    }

    flags |= read ? (write ? O_RDWR : O_RDONLY) : (write ? O_WRONLY : 0);

    return flags;
}

#endif
