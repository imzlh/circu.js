/*
 * circu.js
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

#include "mem.h"
#include "private.h"
#include "utils.h"

#include <openssl/sha.h>
#include <string.h>

static inline bool JS_IsUint8Array(JSValueConst val){
	return JS_GetTypedArrayType(val) == JS_TYPED_ARRAY_UINT8;
}

void tjs__free_ab(JSRuntime *rt, void *opaque, void *ptr){
	js_free_rt(rt, ptr);
}

static JSValue tjs_ws_unpack(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !JS_IsUint8Array(argv[0]) || !JS_IsUint8Array(argv[1])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array)");
	}

	size_t inbuflen, keybuflen;
	uint8_t* inbuf = JS_GetUint8Array(ctx, &inbuflen, argv[0]);
	uint8_t* keybuf = JS_GetUint8Array(ctx, &keybuflen, argv[1]);
	if(keybuflen != 8){
		return JS_ThrowTypeError(ctx, "Invalid ws mask key. expected: 32 bits");
	}

	uint8_t* outbuf = js_malloc(ctx, inbuflen);
	if(!outbuf){
		return JS_ThrowOutOfMemory(ctx);
	}

	// unpack
	for (int i = 0; i < inbuflen; i++){
		outbuf[i] = inbuf[i] ^ keybuf[i % 4];
	}

	return JS_NewArrayBuffer(ctx, outbuf, inbuflen, tjs__free_ab, NULL, false);
}

static const JSCFunctionListEntry tjs_algorithm_funcs[] = {
	TJS_CFUNC_DEF("ws_unpack", 2, tjs_ws_unpack),
};

void tjs__mod_algorithm_init(JSContext* ctx, JSValue ns){
	JS_SetPropertyFunctionList(ctx, ns, tjs_algorithm_funcs, countof(tjs_algorithm_funcs));
}
