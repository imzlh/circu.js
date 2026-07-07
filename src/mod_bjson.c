/*
 * circu.js bjson (not quickjs opcode)
 *
 * Copyright (c) 2026-present iz
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

#include <stdint.h>
#include <string.h>

#define BJSON_MAX_DEPTH 512
#define BJSON_MAX_ARRAYBUFFER_LEN ((uint64_t)INT32_MAX)

static const uint8_t bjson_magic[] = { 'C', 'N', 'O', 'C', 1 };

enum {
    BJSON_NULL = 0,
    BJSON_UNDEFINED = 1,
    BJSON_BOOL = 2,
    BJSON_NUMBER = 3,
    BJSON_STRING = 4,
    BJSON_BIGINT = 5,
    BJSON_BINARY = 6,
    BJSON_ARRAY = 7,
    BJSON_OBJECT = 8,
    BJSON_DATE = 9,
};

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t off;
} BJSONReader;

static int bjson_put_len(DynBuf *buf, uint8_t type, uint64_t len) {
    uint8_t tmp[8];
    int lenlen = 1;
    uint64_t n = len;

    while (n > 0xff) {
        lenlen++;
        n >>= 8;
    }
    for (int i = 0; i < lenlen; i++) {
        tmp[lenlen - 1 - i] = (uint8_t)(len >> (i * 8));
    }
    return dbuf_putc(buf, (uint8_t)((type << 4) | lenlen)) || dbuf_put(buf, tmp, lenlen);
}

static int bjson_put_u64be(DynBuf *buf, uint64_t value) {
    uint8_t out[8];
    for (int i = 0; i < 8; i++) {
        out[7 - i] = (uint8_t)(value >> (i * 8));
    }
    return dbuf_put(buf, out, sizeof(out));
}

static int bjson_put_double(DynBuf *buf, uint8_t type, double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return dbuf_putc(buf, (uint8_t)((type << 4) | 8)) || bjson_put_u64be(buf, bits);
}

static int bjson_write_bigint(JSContext *ctx, DynBuf *buf, JSValueConst value) {
    int sign = 0;
    size_t word_count = 0;
    uint64_t *words = NULL;
    size_t mag_len;

    if (JS_GetBigIntWords(ctx, value, &sign, &word_count, NULL) < 0) {
        return -1;
    }
    if (word_count > 0) {
        if (word_count > SIZE_MAX / sizeof(*words)) {
            JS_ThrowRangeError(ctx, "BJSON bigint too large");
            return -1;
        }
        words = js_mallocz(ctx, word_count * sizeof(*words));
        if (!words) {
            JS_ThrowOutOfMemory(ctx);
            return -1;
        }
        size_t avail = word_count;
        if (JS_GetBigIntWords(ctx, value, &sign, &avail, words) < 0) {
            js_free(ctx, words);
            return -1;
        }
        word_count = avail;
    }

    if (word_count > SIZE_MAX / 8) {
        js_free(ctx, words);
        JS_ThrowRangeError(ctx, "BJSON bigint too large");
        return -1;
    }
    mag_len = word_count * 8;
    while (mag_len > 0) {
        size_t idx = mag_len - 1;
        uint8_t byte = (uint8_t)(words[idx / 8] >> ((idx % 8) * 8));
        if (byte != 0) {
            break;
        }
        mag_len--;
    }

    if (bjson_put_len(buf, BJSON_BIGINT, (uint64_t)mag_len + 1) ||
        dbuf_putc(buf, sign ? 1 : 0)) {
        js_free(ctx, words);
        return -1;
    }
    for (size_t i = mag_len; i > 0; i--) {
        size_t idx = i - 1;
        uint8_t byte = (uint8_t)(words[idx / 8] >> ((idx % 8) * 8));
        if (dbuf_putc(buf, byte)) {
            js_free(ctx, words);
            return -1;
        }
    }
    js_free(ctx, words);
    return 0;
}

static int bjson_is_plain_object(JSContext *ctx, JSValueConst value) {
    if (JS_IsProxy(value)) {
        return 0;
    }
    JSValue proto = JS_GetPrototype(ctx, value);
    if (JS_IsException(proto)) {
        return -1;
    }
    if (JS_IsNull(proto)) {
        JS_FreeValue(ctx, proto);
        return 1;
    }
    if (JS_IsProxy(proto)) {
        JS_FreeValue(ctx, proto);
        return 0;
    }

    JSValue parent = JS_GetPrototype(ctx, proto);
    int ok = JS_IsException(parent) ? -1 : (JS_IsNull(parent) ? 1 : 0);

    JS_FreeValue(ctx, parent);
    JS_FreeValue(ctx, proto);
    return ok;
}

static int bjson_seen(JSContext *ctx, JSValueConst value, JSValueConst *stack, int depth) {
    for (int i = 0; i < depth; i++) {
        if (JS_IsSameValue(ctx, value, stack[i])) {
            return 1;
        }
    }
    return 0;
}

static int bjson_encode_value(JSContext *ctx, DynBuf *buf, JSValueConst value, JSValueConst *stack, int depth) {
    int tag = JS_VALUE_GET_NORM_TAG(value);

    if (depth >= BJSON_MAX_DEPTH) {
        JS_ThrowRangeError(ctx, "BJSON cannot encode values deeper than %d levels", BJSON_MAX_DEPTH);
        return -1;
    }

    switch (tag) {
        case JS_TAG_NULL:
            return dbuf_putc(buf, (uint8_t)(BJSON_NULL << 4));
        case JS_TAG_UNDEFINED:
            return dbuf_putc(buf, (uint8_t)(BJSON_UNDEFINED << 4));
        case JS_TAG_BOOL:
            return dbuf_putc(buf, (uint8_t)((BJSON_BOOL << 4) | (JS_VALUE_GET_BOOL(value) ? 1 : 0)));
        case JS_TAG_INT:
        case JS_TAG_FLOAT64: {
            double number;
            if (JS_ToFloat64(ctx, &number, value)) {
                return -1;
            }
            return bjson_put_double(buf, BJSON_NUMBER, number);
        }
        case JS_TAG_STRING: {
            size_t len = 0;
            const char *str = JS_ToCStringLen(ctx, &len, value);
            if (!str) {
                return -1;
            }
            int ret = bjson_put_len(buf, BJSON_STRING, (uint64_t)len) ||
                      dbuf_put(buf, (const uint8_t *)str, len);
            JS_FreeCString(ctx, str);
            return ret;
        }
        case JS_TAG_BIG_INT:
        case JS_TAG_SHORT_BIG_INT:
            return bjson_write_bigint(ctx, buf, value);
        case JS_TAG_SYMBOL:
            JS_ThrowTypeError(ctx, "BJSON cannot encode symbol values");
            return -1;
        default:
            break;
    }

    if (!JS_IsObject(value)) {
        JS_ThrowTypeError(ctx, "BJSON cannot encode unsupported value tag %d", tag);
        return -1;
    }
    if (JS_IsFunction(ctx, value)) {
        JS_ThrowTypeError(ctx, "BJSON cannot encode function values");
        return -1;
    }
    if (JS_IsProxy(value)) {
        JS_ThrowTypeError(ctx, "BJSON cannot encode Proxy values");
        return -1;
    }

    if (JS_IsArrayBuffer(value) || JS_IsDataView(value) || JS_GetTypedArrayType(value) >= 0) {
        size_t bin_len = 0;
        uint8_t *bin = JS_GetAnyBuffer(ctx, &bin_len, value);
        if (JS_HasException(ctx)) {
            return -1;
        }
        if (!bin && bin_len != 0) {
            return -1;
        }
        return bjson_put_len(buf, BJSON_BINARY, (uint64_t)bin_len) || dbuf_put(buf, bin, bin_len);
    }

    if (JS_IsDate(value)) {
        JSAtom get_time_atom = JS_NewAtom(ctx, "getTime");
        if (get_time_atom == JS_ATOM_NULL) {
            return -1;
        }
        JSValue time_value = JS_Invoke(ctx, value, get_time_atom, 0, NULL);
        JS_FreeAtom(ctx, get_time_atom);
        if (JS_IsException(time_value)) {
            return -1;
        }
        double time_ms;
        int ret = JS_ToFloat64(ctx, &time_ms, time_value);
        JS_FreeValue(ctx, time_value);
        if (ret) {
            return -1;
        }
        return bjson_put_double(buf, BJSON_DATE, time_ms);
    }

    if (bjson_seen(ctx, value, stack, depth)) {
        JS_ThrowTypeError(ctx, "BJSON cannot encode cyclic values");
        return -1;
    }
    stack[depth] = value;

    if (JS_IsArray(value)) {
        JSValue len_value = JS_GetPropertyStr(ctx, value, "length");
        uint64_t len = 0;
        if (JS_IsException(len_value)) {
            return -1;
        }
        int ret = JS_ToIndex(ctx, &len, len_value);
        JS_FreeValue(ctx, len_value);
        if (ret) {
            return -1;
        }
        if (len > UINT32_MAX) {
            JS_ThrowRangeError(ctx, "BJSON cannot encode arrays longer than %u elements", UINT32_MAX);
            return -1;
        }
        if (bjson_put_len(buf, BJSON_ARRAY, len)) {
            return -1;
        }
        for (uint32_t i = 0; i < (uint32_t)len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, value, i);
            if (JS_IsException(item)) {
                return -1;
            }
            ret = bjson_encode_value(ctx, buf, item, stack, depth + 1);
            JS_FreeValue(ctx, item);
            if (ret) {
                return -1;
            }
        }
        return 0;
    }

    int plain = bjson_is_plain_object(ctx, value);
    if (plain < 0) {
        return -1;
    }
    if (!plain) {
        JS_ThrowTypeError(ctx, "BJSON can only encode plain objects, arrays, Date, and binary views");
        return -1;
    }

    JSPropertyEnum *props = NULL;
    uint32_t prop_count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, value, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) < 0) {
        return -1;
    }
    if (bjson_put_len(buf, BJSON_OBJECT, prop_count)) {
        JS_FreePropertyEnum(ctx, props, prop_count);
        return -1;
    }

    for (uint32_t i = 0; i < prop_count; i++) {
        size_t key_len = 0;
        const char *key = JS_AtomToCStringLen(ctx, &key_len, props[i].atom);
        if (!key) {
            JS_FreePropertyEnum(ctx, props, prop_count);
            return -1;
        }
        JSPropertyDescriptor desc;
        int got = JS_GetOwnProperty(ctx, &desc, value, props[i].atom);
        if (got <= 0) {
            JS_FreeCString(ctx, key);
            JS_FreePropertyEnum(ctx, props, prop_count);
            if (got < 0) {
                return -1;
            }
            JS_ThrowTypeError(ctx, "BJSON object key disappeared during encode");
            return -1;
        }
        if (desc.flags & JS_PROP_GETSET) {
            JS_FreeValue(ctx, desc.getter);
            JS_FreeValue(ctx, desc.setter);
            JS_FreeCString(ctx, key);
            JS_FreePropertyEnum(ctx, props, prop_count);
            JS_ThrowTypeError(ctx, "BJSON cannot encode accessor properties");
            return -1;
        }

        int ret = bjson_put_len(buf, 0, (uint64_t)key_len) ||
                  dbuf_put(buf, (const uint8_t *)key, key_len) ||
                  bjson_encode_value(ctx, buf, desc.value, stack, depth + 1);
        JS_FreeValue(ctx, desc.value);
        JS_FreeCString(ctx, key);
        if (ret) {
            JS_FreePropertyEnum(ctx, props, prop_count);
            return -1;
        }
    }

    JS_FreePropertyEnum(ctx, props, prop_count);
    return 0;
}

static JSValue bjson_encode(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "BJSON.encode requires 1 argument");
    }

    DynBuf buf;
    JSValueConst stack[BJSON_MAX_DEPTH];
    int ret;
    dbuf_init(&buf);
    ret = dbuf_put(&buf, bjson_magic, sizeof(bjson_magic));
    if (!ret) {
        ret = bjson_encode_value(ctx, &buf, argv[0], stack, 0);
    }
    if (ret || dbuf_error(&buf)) {
        dbuf_free(&buf);
        return ret ? JS_EXCEPTION : JS_ThrowOutOfMemory(ctx);
    }

    if (buf.size > (size_t)BJSON_MAX_ARRAYBUFFER_LEN) {
        dbuf_free(&buf);
        return JS_ThrowRangeError(ctx, "BJSON output too large");
    }
    uint8_t *out = js_malloc(ctx, buf.size);
    if (!out) {
        dbuf_free(&buf);
        return JS_ThrowOutOfMemory(ctx);
    }
    memcpy(out, buf.buf, buf.size);
    size_t size = buf.size;
    dbuf_free(&buf);
    return TJS_NewUint8Array(ctx, out, size);
}

static int bjson_read_u8(JSContext *ctx, BJSONReader *r, uint8_t *out) {
    if (r->off >= r->len) {
        JS_ThrowSyntaxError(ctx, "truncated BJSON value at offset %zu", r->off);
        return -1;
    }
    *out = r->data[r->off++];
    return 0;
}

static int bjson_read_bytes(JSContext *ctx, BJSONReader *r, size_t len, const uint8_t **out) {
    if (len > r->len - r->off) {
        JS_ThrowSyntaxError(ctx, "truncated BJSON value at offset %zu", r->off);
        return -1;
    }
    *out = r->data + r->off;
    r->off += len;
    return 0;
}

static int bjson_read_len(JSContext *ctx, BJSONReader *r, uint8_t arg, uint64_t *out) {
    uint64_t len = 0;
    if (arg == 0 || arg > 8) {
        JS_ThrowSyntaxError(ctx, "invalid BJSON length width %u at offset %zu", arg, r->off ? r->off - 1 : 0);
        return -1;
    }
    for (uint8_t i = 0; i < arg; i++) {
        uint8_t byte;
        if (bjson_read_u8(ctx, r, &byte)) {
            return -1;
        }
        len = (len << 8) | byte;
    }
    *out = len;
    return 0;
}

static int bjson_read_u64be(JSContext *ctx, BJSONReader *r, uint64_t *out) {
    const uint8_t *bytes;
    uint64_t value = 0;
    if (bjson_read_bytes(ctx, r, 8, &bytes)) {
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    *out = value;
    return 0;
}

static int bjson_read_double(JSContext *ctx, BJSONReader *r, uint8_t arg, double *out) {
    uint64_t bits;
    if (arg != 8) {
        JS_ThrowSyntaxError(ctx, "invalid BJSON f64 width %u at offset %zu", arg, r->off ? r->off - 1 : 0);
        return -1;
    }
    if (bjson_read_u64be(ctx, r, &bits)) {
        return -1;
    }
    memcpy(out, &bits, sizeof(bits));
    return 0;
}

static JSValue bjson_decode_value(JSContext *ctx, BJSONReader *r, int depth) {
    uint8_t header;
    uint8_t type;
    uint8_t arg;

    if (depth >= BJSON_MAX_DEPTH) {
        return JS_ThrowRangeError(ctx, "BJSON cannot decode values deeper than %d levels", BJSON_MAX_DEPTH);
    }
    if (bjson_read_u8(ctx, r, &header)) {
        return JS_EXCEPTION;
    }
    type = header >> 4;
    arg = header & 0x0f;

    switch (type) {
        case BJSON_NULL:
            if (arg != 0) {
                return JS_ThrowSyntaxError(ctx, "invalid BJSON null tag at offset %zu", r->off - 1);
            }
            return JS_NULL;
        case BJSON_UNDEFINED:
            if (arg != 0) {
                return JS_ThrowSyntaxError(ctx, "invalid BJSON undefined tag at offset %zu", r->off - 1);
            }
            return JS_UNDEFINED;
        case BJSON_BOOL:
            if (arg > 1) {
                return JS_ThrowSyntaxError(ctx, "invalid BJSON boolean tag at offset %zu", r->off - 1);
            }
            return JS_NewBool(ctx, arg);
        case BJSON_NUMBER: {
            double value;
            if (bjson_read_double(ctx, r, arg, &value)) {
                return JS_EXCEPTION;
            }
            return JS_NewFloat64(ctx, value);
        }
        case BJSON_STRING: {
            uint64_t len;
            const uint8_t *bytes;
            if (bjson_read_len(ctx, r, arg, &len)) {
                return JS_EXCEPTION;
            }
            if (len > SIZE_MAX) {
                return JS_ThrowRangeError(ctx, "BJSON string too large");
            }
            if (bjson_read_bytes(ctx, r, (size_t)len, &bytes)) {
                return JS_EXCEPTION;
            }
            return JS_NewStringLen(ctx, (const char *)bytes, (size_t)len);
        }
        case BJSON_BIGINT: {
            uint64_t len;
            const uint8_t *bytes;
            if (bjson_read_len(ctx, r, arg, &len)) {
                return JS_EXCEPTION;
            }
            if (len == 0 || len > SIZE_MAX) {
                return JS_ThrowSyntaxError(ctx, "invalid BJSON bigint length");
            }
            if (bjson_read_bytes(ctx, r, (size_t)len, &bytes)) {
                return JS_EXCEPTION;
            }
            int sign = bytes[0];
            if (sign > 1) {
                return JS_ThrowSyntaxError(ctx, "invalid BJSON bigint sign");
            }
            size_t mag_len = (size_t)len - 1;
            if (mag_len > SIZE_MAX - 7) {
                return JS_ThrowRangeError(ctx, "BJSON bigint too large");
            }
            size_t word_count = (mag_len + 7) / 8;
            if (word_count > SIZE_MAX / sizeof(uint64_t)) {
                return JS_ThrowRangeError(ctx, "BJSON bigint too large");
            }
            uint64_t *words = word_count ? js_mallocz(ctx, word_count * sizeof(*words)) : NULL;
            if (word_count && !words) {
                return JS_ThrowOutOfMemory(ctx);
            }
            for (size_t i = 0; i < mag_len; i++) {
                size_t little = mag_len - 1 - i;
                words[little / 8] |= (uint64_t)bytes[i + 1] << ((little % 8) * 8);
            }
            JSValue value = JS_NewBigIntWords(ctx, sign, word_count, words);
            js_free(ctx, words);
            return value;
        }
        case BJSON_BINARY: {
            uint64_t len;
            const uint8_t *bytes;
            if (bjson_read_len(ctx, r, arg, &len)) {
                return JS_EXCEPTION;
            }
            if (len > SIZE_MAX) {
                return JS_ThrowRangeError(ctx, "BJSON binary too large");
            }
            if (len > BJSON_MAX_ARRAYBUFFER_LEN) {
                return JS_ThrowRangeError(ctx, "BJSON binary too large");
            }
            if (bjson_read_bytes(ctx, r, (size_t)len, &bytes)) {
                return JS_EXCEPTION;
            }
            uint8_t *copy = js_malloc(ctx, (size_t)len);
            if (len > 0 && !copy) {
                return JS_ThrowOutOfMemory(ctx);
            }
            if (len > 0) {
                memcpy(copy, bytes, (size_t)len);
            }
            return TJS_NewUint8Array(ctx, copy, (size_t)len);
        }
        case BJSON_ARRAY: {
            uint64_t len;
            if (bjson_read_len(ctx, r, arg, &len)) {
                return JS_EXCEPTION;
            }
            if (len > UINT32_MAX) {
                return JS_ThrowRangeError(ctx, "BJSON array too large");
            }
            JSValue array = JS_NewArray(ctx);
            if (JS_IsException(array)) {
                return JS_EXCEPTION;
            }
            for (uint32_t i = 0; i < (uint32_t)len; i++) {
                JSValue item = bjson_decode_value(ctx, r, depth + 1);
                if (JS_IsException(item)) {
                    JS_FreeValue(ctx, array);
                    return JS_EXCEPTION;
                }
                if (JS_DefinePropertyValueUint32(ctx, array, i, item, JS_PROP_C_W_E) < 0) {
                    JS_FreeValue(ctx, array);
                    return JS_EXCEPTION;
                }
            }
            return array;
        }
        case BJSON_OBJECT: {
            uint64_t count;
            if (bjson_read_len(ctx, r, arg, &count)) {
                return JS_EXCEPTION;
            }
            if (count > UINT32_MAX) {
                return JS_ThrowRangeError(ctx, "BJSON object too large");
            }
            JSValue object = JS_NewObject(ctx);
            if (JS_IsException(object)) {
                return JS_EXCEPTION;
            }
            for (uint32_t i = 0; i < (uint32_t)count; i++) {
                uint8_t key_header;
                uint64_t key_len;
                const uint8_t *key;
                if (bjson_read_u8(ctx, r, &key_header)) {
                    JS_FreeValue(ctx, object);
                    return JS_EXCEPTION;
                }
                if ((key_header >> 4) != 0) {
                    JS_FreeValue(ctx, object);
                    return JS_ThrowSyntaxError(ctx, "invalid BJSON object key header at offset %zu", r->off - 1);
                }
                if (bjson_read_len(ctx, r, key_header & 0x0f, &key_len)) {
                    JS_FreeValue(ctx, object);
                    return JS_EXCEPTION;
                }
                if (key_len > SIZE_MAX) {
                    JS_FreeValue(ctx, object);
                    return JS_ThrowRangeError(ctx, "BJSON object key too large");
                }
                if (bjson_read_bytes(ctx, r, (size_t)key_len, &key)) {
                    JS_FreeValue(ctx, object);
                    return JS_EXCEPTION;
                }
                JSValue item = bjson_decode_value(ctx, r, depth + 1);
                if (JS_IsException(item)) {
                    JS_FreeValue(ctx, object);
                    return JS_EXCEPTION;
                }
                JSAtom atom = JS_NewAtomLen(ctx, (const char *)key, (size_t)key_len);
                if (atom == JS_ATOM_NULL) {
                    JS_FreeValue(ctx, item);
                    JS_FreeValue(ctx, object);
                    return JS_EXCEPTION;
                }
                int ret = JS_DefinePropertyValue(ctx, object, atom, item, JS_PROP_C_W_E);
                JS_FreeAtom(ctx, atom);
                if (ret < 0) {
                    JS_FreeValue(ctx, object);
                    return JS_EXCEPTION;
                }
            }
            return object;
        }
        case BJSON_DATE: {
            double time_ms;
            if (bjson_read_double(ctx, r, arg, &time_ms)) {
                return JS_EXCEPTION;
            }
            return JS_NewDate(ctx, time_ms);
        }
        default:
            return JS_ThrowSyntaxError(ctx, "unknown BJSON type %u at offset %zu", type, r->off - 1);
    }
}

static JSValue bjson_decode(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val;
    size_t len = 0;
    uint8_t *data;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "BJSON.decode requires 1 argument");
    }
    if (!JS_IsArrayBuffer(argv[0]) && !JS_IsDataView(argv[0]) && JS_GetTypedArrayType(argv[0]) < 0) {
        return JS_ThrowTypeError(ctx, "BJSON.decode expects Uint8Array or ArrayBuffer input");
    }
    data = JS_GetAnyBuffer(ctx, &len, argv[0]);
    if (JS_HasException(ctx)) {
        return JS_EXCEPTION;
    }
    if (!data && len != 0) {
        return JS_EXCEPTION;
    }
    if (len < sizeof(bjson_magic) || memcmp(data, bjson_magic, sizeof(bjson_magic)) != 0) {
        return JS_ThrowSyntaxError(ctx, "unsupported BJSON value format: expected CNOBJSON v1");
    }

    BJSONReader r = {
        .data = data,
        .len = len,
        .off = sizeof(bjson_magic),
    };
    JSValue value = bjson_decode_value(ctx, &r, 0);
    if (JS_IsException(value)) {
        return JS_EXCEPTION;
    }
    if (r.off != r.len) {
        JS_FreeValue(ctx, value);
        return JS_ThrowSyntaxError(ctx, "trailing bytes after BJSON value at offset %zu", r.off);
    }
    return value;
}

static const JSCFunctionListEntry bjson_funcs[] = {
    TJS_CFUNC_DEF("encode", 1, bjson_encode),
    TJS_CFUNC_DEF("decode", 1, bjson_decode),
};

void tjs__mod_bjson_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, bjson_funcs, countof(bjson_funcs));
}
