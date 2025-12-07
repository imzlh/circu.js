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

typedef struct {
    uint32_t s[4];
} xoshiro128_state;

// xoshiro128++ 1.0
static inline uint32_t rotl32(uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

static uint32_t xoshiro128_next(xoshiro128_state *state) {
    const uint32_t result = rotl32(state->s[0] + state->s[3], 7) + state->s[0];
    const uint32_t t = state->s[1] << 9;
    
    state->s[2] ^= state->s[0];
    state->s[3] ^= state->s[1];
    state->s[1] ^= state->s[2];
    state->s[0] ^= state->s[3];
    
    state->s[2] ^= t;
    state->s[3] = rotl32(state->s[3], 11);
    
    return result;
}

static void xoshiro128_jump(xoshiro128_state *state) {
    static const uint32_t JUMP[] = { 0x8764000b, 0xf542d2d3, 0x6fa035c3, 0x77f2db5b };
    
    uint32_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    
    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 32; b++) {
            if (JUMP[i] & (1U << b)) {
                s0 ^= state->s[0];
                s1 ^= state->s[1];
                s2 ^= state->s[2];
                s3 ^= state->s[3];
            }
            xoshiro128_next(state);
        }
    }
    
    state->s[0] = s0;
    state->s[1] = s1;
    state->s[2] = s2;
    state->s[3] = s3;
}

static void xoshiro128_long_jump(xoshiro128_state *state) {
    static const uint32_t LONG_JUMP[] = { 0xb523952e, 0x0b6f099f, 0xccf5a0ef, 0x1c580662 };
    
    uint32_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    
    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 32; b++) {
            if (LONG_JUMP[i] & (1U << b)) {
                s0 ^= state->s[0];
                s1 ^= state->s[1];
                s2 ^= state->s[2];
                s3 ^= state->s[3];
            }
            xoshiro128_next(state);
        }
    }
    
    state->s[0] = s0;
    state->s[1] = s1;
    state->s[2] = s2;
    state->s[3] = s3;
}

typedef struct {
    uint64_t s[4];
} xoshiro256_state;

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

// xoshiro256++ 1.0
static uint64_t xoshiro256_next(xoshiro256_state *state) {
    const uint64_t result = rotl64(state->s[0] + state->s[3], 23) + state->s[0];
    const uint64_t t = state->s[1] << 17;
    
    state->s[2] ^= state->s[0];
    state->s[3] ^= state->s[1];
    state->s[1] ^= state->s[2];
    state->s[0] ^= state->s[3];
    
    state->s[2] ^= t;
    state->s[3] = rotl64(state->s[3], 45);
    
    return result;
}

static void xoshiro256_jump(xoshiro256_state *state) {
    static const uint64_t JUMP[] = {
        0x180ec6d33cfd0aba, 0xd5a61266f0c9392c,
        0xa9582618e03fc9aa, 0x39abdc4529b1661c
    };
    
    uint64_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    
    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 64; b++) {
            if (JUMP[i] & (1ULL << b)) {
                s0 ^= state->s[0];
                s1 ^= state->s[1];
                s2 ^= state->s[2];
                s3 ^= state->s[3];
            }
            xoshiro256_next(state);
        }
    }
    
    state->s[0] = s0;
    state->s[1] = s1;
    state->s[2] = s2;
    state->s[3] = s3;
}

static void xoshiro256_long_jump(xoshiro256_state *state) {
    static const uint64_t LONG_JUMP[] = {
        0x76e15d3efefdcbbf, 0xc5004e441c522fb3,
        0x77710069854ee241, 0x39109bb02acbe635
    };
    
    uint64_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    
    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 64; b++) {
            if (LONG_JUMP[i] & (1ULL << b)) {
                s0 ^= state->s[0];
                s1 ^= state->s[1];
                s2 ^= state->s[2];
                s3 ^= state->s[3];
            }
            xoshiro256_next(state);
        }
    }
    
    state->s[0] = s0;
    state->s[1] = s1;
    state->s[2] = s2;
    state->s[3] = s3;
}

typedef struct {
    union {
        xoshiro128_state s128;
        xoshiro256_state s256;
    };
    int is_256; // 0 for 128-bit, 1 for 256-bit
} XoshiroRNG;

static JSClassID xoshiro_class_id;

static void xoshiro_finalizer(JSRuntime *rt, JSValue val) {
    XoshiroRNG *rng = JS_GetOpaque(val, xoshiro_class_id);
    if (rng) {
        js_free_rt(rt, rng);
    }
}

static JSValue xoshiro_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    XoshiroRNG *rng;
    JSValue obj;
    
    rng = js_mallocz(ctx, sizeof(*rng));
    if (!rng) return JS_EXCEPTION;
    rng->is_256 = 1;
    
    if (argc > 0) {
        if (JS_IsNumber(argv[0])) {
            uint64_t seed;
            if (JS_ToIndex(ctx, &seed, argv[0])) {
                js_free(ctx, rng);
                return JS_EXCEPTION;
            }
            
            if (rng->is_256) {
                rng->s256.s[0] = seed * 0x9e3779b97f4a7c15;
                rng->s256.s[1] = rotl64(seed, 21) * 0x9e3779b97f4a7c15;
                rng->s256.s[2] = rotl64(seed, 42) * 0x9e3779b97f4a7c15;
                rng->s256.s[3] = rotl64(seed, 63) * 0x9e3779b97f4a7c15;
            } else {
                rng->s128.s[0] = (uint32_t)(seed * 0x9e3779b9);
                rng->s128.s[1] = (uint32_t)(rotl32(seed, 11) * 0x9e3779b9);
                rng->s128.s[2] = (uint32_t)(rotl32(seed, 22) * 0x9e3779b9);
                rng->s128.s[3] = (uint32_t)(rotl32(seed, 33) * 0x9e3779b9);
            }
        } else if (JS_IsArray(argv[0])) {
			int64_t length;
			if (-1 == JS_GetLength(ctx, argv[0], &length)) {
				js_free(ctx, rng);
				return JS_ThrowTypeError(ctx, "Invalid seed array. expected: Array<number>");
			}
            
            if (rng->is_256) {
                if (length >= 4) {
                    for (int i = 0; i < 4; i++) {
                        JSValue elem = JS_GetPropertyUint32(ctx, argv[0], i);
                        uint64_t val;
                        if (JS_ToIndex(ctx, &val, elem)) {
                            JS_FreeValue(ctx, elem);
                            js_free(ctx, rng);
                            return JS_EXCEPTION;
                        }
                        rng->s256.s[i] = val;
                        JS_FreeValue(ctx, elem);
                    }
                }
            } else {
                if (length >= 4) {
                    for (int i = 0; i < 4; i++) {
                        JSValue elem = JS_GetPropertyUint32(ctx, argv[0], i);
                        uint32_t val;
                        if (JS_ToUint32(ctx, &val, elem)) {
                            JS_FreeValue(ctx, elem);
                            js_free(ctx, rng);
                            return JS_EXCEPTION;
                        }
                        rng->s128.s[i] = val;
                        JS_FreeValue(ctx, elem);
                    }
                }
            }
        }
    } else {
		// no seed provided, use current time as seed
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        uint64_t seed = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        
        if (rng->is_256) {
            rng->s256.s[0] = seed * 0x9e3779b97f4a7c15;
            rng->s256.s[1] = rotl64(seed, 21) * 0x9e3779b97f4a7c15;
            rng->s256.s[2] = rotl64(seed, 42) * 0x9e3779b97f4a7c15;
            rng->s256.s[3] = rotl64(seed, 63) * 0x9e3779b97f4a7c15;
        } else {
            rng->s128.s[0] = (uint32_t)(seed * 0x9e3779b9);
            rng->s128.s[1] = (uint32_t)(rotl32(seed, 11) * 0x9e3779b9);
            rng->s128.s[2] = (uint32_t)(rotl32(seed, 22) * 0x9e3779b9);
            rng->s128.s[3] = (uint32_t)(rotl32(seed, 33) * 0x9e3779b9);
        }
    }
    
    obj = JS_NewObjectClass(ctx, xoshiro_class_id);
    if (JS_IsException(obj)) {
        js_free(ctx, rng);
        return obj;
    }
    
    JS_SetOpaque(obj, rng);
    return obj;
}

static JSValue xoshiro_next(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque(this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    if (rng->is_256) {
        uint64_t result = xoshiro256_next(&rng->s256);
        return JS_NewBigUint64(ctx, result);
    } else {
        uint32_t result = xoshiro128_next(&rng->s128);
        return JS_NewUint32(ctx, result);
    }
}

static JSValue xoshiro_next_double(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque(this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    if (rng->is_256) {
        uint64_t result = xoshiro256_next(&rng->s256);
        double d = (result >> 11) * 0x1.0p-53;
        return JS_NewFloat64(ctx, d);
    } else {
        uint32_t result = xoshiro128_next(&rng->s128);
        double d = (result >> 8) * 0x1.0p-24;
        return JS_NewFloat64(ctx, d);
    }
}

static JSValue xoshiro_jump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque(this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    if (rng->is_256) {
        xoshiro256_jump(&rng->s256);
    } else {
        xoshiro128_jump(&rng->s128);
    }
    
    return JS_UNDEFINED;
}

static JSValue xoshiro_long_jump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque(this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    if (rng->is_256) {
        xoshiro256_long_jump(&rng->s256);
    } else {
        xoshiro128_long_jump(&rng->s128);
    }
    
    return JS_UNDEFINED;
}

static JSValue xoshiro_clone(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque(this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    XoshiroRNG *new_rng = js_mallocz(ctx, sizeof(*new_rng));
    if (!new_rng) return JS_EXCEPTION;
    
    memcpy(new_rng, rng, sizeof(*new_rng));
    
    JSValue obj = JS_NewObjectClass(ctx, xoshiro_class_id);
    if (JS_IsException(obj)) {
        js_free(ctx, new_rng);
        return obj;
    }
    
    JS_SetOpaque(obj, new_rng);
    return obj;
}

static const JSCFunctionListEntry xoshiro_proto_funcs[] = {
    JS_CFUNC_DEF("next", 0, xoshiro_next),
    JS_CFUNC_DEF("nextDouble", 0, xoshiro_next_double),
    JS_CFUNC_DEF("jump", 0, xoshiro_jump),
    JS_CFUNC_DEF("longJump", 0, xoshiro_long_jump),
    JS_CFUNC_DEF("clone", 0, xoshiro_clone),
};

static JSValue xoshiro_init(JSContext *ctx) {
    JS_NewClassID(JS_GetRuntime(ctx), &xoshiro_class_id);
    JS_NewClass(JS_GetRuntime(ctx), xoshiro_class_id, &(JSClassDef){
        .class_name = "XoshiroRNG",
        .finalizer = xoshiro_finalizer,
    });
    
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, xoshiro_proto_funcs, countof(xoshiro_proto_funcs));
    
    JSValue constructor = JS_NewCFunction2(ctx, xoshiro_constructor, "XoshiroRNG", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, constructor, proto);
    JS_SetClassProto(ctx, xoshiro_class_id, proto);
	
	return constructor;
}

static const JSCFunctionListEntry tjs_algorithm_funcs[] = {
	TJS_CFUNC_DEF("ws_unpack", 2, tjs_ws_unpack),
};

void tjs__mod_algorithm_init(JSContext* ctx, JSValue ns){
	JS_SetPropertyFunctionList(ctx, ns, tjs_algorithm_funcs, countof(tjs_algorithm_funcs));

	JSValue xoshiro_obj = xoshiro_init(ctx);
	JS_SetPropertyStr(ctx, ns, "XoshiroRNG", xoshiro_obj);
}
