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

#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

static inline bool JS_IsUint8Array(JSValueConst val){
	return JS_GetTypedArrayType(val) == JS_TYPED_ARRAY_UINT8;
}

static inline uint32_t read_u32_le(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static JSValue tjs_ws_mask(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !JS_IsUint8Array(argv[0]) || !JS_IsUint8Array(argv[1])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array)");
	}

	size_t inbuflen, keybuflen;
	uint8_t* inbuf = JS_GetUint8Array(ctx, &inbuflen, argv[0]);
	uint8_t* keybuf = JS_GetUint8Array(ctx, &keybuflen, argv[1]);
    if (!inbuf || !keybuf) {
        return JS_EXCEPTION;
    }
	if(keybuflen != 4){
		return JS_ThrowTypeError(ctx, "Invalid ws mask key. expected: 4 bytes");
	}
    if (inbuflen == 0) {
        return JS_NewUint8ArrayCopy(ctx, NULL, 0);
    }

	uint8_t* outbuf = js_malloc(ctx, inbuflen);
	if(!outbuf){
		return JS_ThrowOutOfMemory(ctx);
	}

	// apply/remove mask (XOR is symmetric)
	for (size_t i = 0; i < inbuflen; i++){
		outbuf[i] = inbuf[i] ^ keybuf[i % 4];
	}

	return TJS_NewUint8Array(ctx, outbuf, inbuflen);
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

static thread_local JSClassID xoshiro_class_id;

static void xoshiro_finalizer(JSRuntime *rt, JSValue val) {
    XoshiroRNG *rng = JS_GetOpaque(val, xoshiro_class_id);
    if (rng) {
        js_free_rt(rt, rng);
    }
}

static void xoshiro_seed256(XoshiroRNG *rng, uint64_t seed) {
    if (seed == 0) {
        seed = 0x9e3779b97f4a7c15ULL;
    }
    rng->s256.s[0] = seed * 0x9e3779b97f4a7c15ULL;
    rng->s256.s[1] = rotl64(seed, 21) * 0x9e3779b97f4a7c15ULL;
    rng->s256.s[2] = rotl64(seed, 42) * 0x9e3779b97f4a7c15ULL;
    rng->s256.s[3] = rotl64(seed, 63) * 0x9e3779b97f4a7c15ULL;
}

static bool xoshiro256_is_zero(const XoshiroRNG *rng) {
    return rng->s256.s[0] == 0 && rng->s256.s[1] == 0 && rng->s256.s[2] == 0 && rng->s256.s[3] == 0;
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
            
            xoshiro_seed256(rng, seed);
        } else if (JS_IsArray(argv[0])) {
			int64_t length;
			if (-1 == JS_GetLength(ctx, argv[0], &length)) {
				js_free(ctx, rng);
				return JS_ThrowTypeError(ctx, "Invalid seed array. expected: Array<number>");
			}

            if (length < 4) {
                js_free(ctx, rng);
                return JS_ThrowRangeError(ctx, "Seed array must contain at least 4 values");
            }

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
        } else {
            js_free(ctx, rng);
            return JS_ThrowTypeError(ctx, "Invalid seed. expected: number or Array<number>");
        }
    } else {
		// no seed provided, use current time as seed
        uint64_t seed;
#ifdef _WIN32
        // Windows: use GetSystemTimeAsFileTime for high-resolution timestamp
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        seed = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
#else
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        seed = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
        
        xoshiro_seed256(rng, seed);
    }

    if (xoshiro256_is_zero(rng)) {
        xoshiro_seed256(rng, 0x9e3779b97f4a7c15ULL);
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

// FNV-1a 32-bit hash
static uint32_t fnv1a_32(const uint8_t *data, size_t len) {
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

// FNV-1a 64-bit hash
static uint64_t fnv1a_64(const uint8_t *data, size_t len) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

// MurmurHash3 32-bit
static uint32_t murmur3_32(const uint8_t *key, size_t len, uint32_t seed) {
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t r1 = 15;
    const uint32_t r2 = 13;
    const uint32_t m = 5;
    const uint32_t n = 0xe6546b64;

    uint32_t hash = seed;

    const size_t nblocks = len / 4;

    for (size_t i = 0; i < nblocks; i++) {
        uint32_t k = read_u32_le(key + i * 4);
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        hash ^= k;
        hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    const uint8_t *tail = (const uint8_t *)(key + nblocks * 4);
    uint32_t k1 = 0;

    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = (k1 << r1) | (k1 >> (32 - r1));
                k1 *= c2;
                hash ^= k1;
    }

    hash ^= len;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
}

static JSValue tjs_hash_fnv1a32(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsUint8Array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    uint32_t result = fnv1a_32(data, len);
    return JS_NewUint32(ctx, result);
}

static JSValue tjs_hash_fnv1a64(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsUint8Array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    uint64_t result = fnv1a_64(data, len);
    return JS_NewBigUint64(ctx, result);
}

static JSValue tjs_hash_murmur3(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsUint8Array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    uint32_t seed = 0;
    if (argc >= 2 && JS_IsNumber(argv[1])) {
        if (JS_ToUint32(ctx, &seed, argv[1])) {
            return JS_EXCEPTION;
        }
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    uint32_t result = murmur3_32(data, len, seed);
    return JS_NewUint32(ctx, result);
}

/* xxHash - simple implementation */

static const uint32_t XXH_PRIME32_1 = 2654435761U;
static const uint32_t XXH_PRIME32_2 = 2246822519U;
static const uint32_t XXH_PRIME32_3 = 3266489917U;
static const uint32_t XXH_PRIME32_4 = 668265263U;
static const uint32_t XXH_PRIME32_5 = 374761393U;

static uint32_t xxh32_rotl(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

static uint32_t xxhash32(const uint8_t *input, size_t len, uint32_t seed) {
    uint32_t h32;
    const uint8_t *p = input;
    const uint8_t *const bEnd = input + len;

    if (len >= 16) {
        const uint8_t *const limit = bEnd - 16;
        uint32_t v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        uint32_t v2 = seed + XXH_PRIME32_2;
        uint32_t v3 = seed + 0;
        uint32_t v4 = seed - XXH_PRIME32_1;

        do {
            v1 += read_u32_le(p) * XXH_PRIME32_2;
            v1 = xxh32_rotl(v1, 13) * XXH_PRIME32_1;
            p += 4;
            v2 += read_u32_le(p) * XXH_PRIME32_2;
            v2 = xxh32_rotl(v2, 13) * XXH_PRIME32_1;
            p += 4;
            v3 += read_u32_le(p) * XXH_PRIME32_2;
            v3 = xxh32_rotl(v3, 13) * XXH_PRIME32_1;
            p += 4;
            v4 += read_u32_le(p) * XXH_PRIME32_2;
            v4 = xxh32_rotl(v4, 13) * XXH_PRIME32_1;
            p += 4;
        } while (p <= limit);

        h32 = xxh32_rotl(v1, 1) + xxh32_rotl(v2, 7) + xxh32_rotl(v3, 12) + xxh32_rotl(v4, 18);
    } else {
        h32 = seed + XXH_PRIME32_5;
    }

    h32 += (uint32_t)len;

    while (p + 4 <= bEnd) {
        h32 += read_u32_le(p) * XXH_PRIME32_3;
        h32 = xxh32_rotl(h32, 17) * XXH_PRIME32_4;
        p += 4;
    }

    while (p < bEnd) {
        h32 += (*p) * XXH_PRIME32_5;
        h32 = xxh32_rotl(h32, 11) * XXH_PRIME32_1;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= XXH_PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= XXH_PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

static JSValue tjs_hash_xxhash32(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsUint8Array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    uint32_t seed = 0;
    if (argc >= 2 && JS_IsNumber(argv[1])) {
        if (JS_ToUint32(ctx, &seed, argv[1])) {
            return JS_EXCEPTION;
        }
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    uint32_t result = xxhash32(data, len, seed);
    return JS_NewUint32(ctx, result);
}

static const JSCFunctionListEntry tjs_algorithm_funcs[] = {
	TJS_CFUNC_DEF("ws_mask", 2, tjs_ws_mask),
    TJS_CFUNC_DEF("fnv1a32", 1, tjs_hash_fnv1a32),
    TJS_CFUNC_DEF("fnv1a64", 1, tjs_hash_fnv1a64),
    TJS_CFUNC_DEF("murmur3", 2, tjs_hash_murmur3),
    TJS_CFUNC_DEF("xxhash32", 2, tjs_hash_xxhash32),
};

void tjs__mod_algorithm_init(JSContext* ctx, JSValue ns){
	JS_SetPropertyFunctionList(ctx, ns, tjs_algorithm_funcs, countof(tjs_algorithm_funcs));

	JSValue xoshiro_obj = xoshiro_init(ctx);
	JS_SetPropertyStr(ctx, ns, "XoshiroRNG", xoshiro_obj);
}
