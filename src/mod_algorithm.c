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

typedef struct {
	JSValue value;
	uint8_t* data;
	size_t len;
} TJSBytesChunk;

static inline bool tjs_is_uint8_array(JSValueConst val){
	return JS_GetTypedArrayType(val) == JS_TYPED_ARRAY_UINT8;
}

static void tjs_free_bytes_chunks(JSContext* ctx, TJSBytesChunk* chunks, uint32_t count) {
	for (uint32_t i = 0; i < count; i++) {
		JS_FreeValue(ctx, chunks[i].value);
	}
	js_free(ctx, chunks);
}

static inline uint32_t read_u32_le(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint64_t read_u64_le(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void ws_mask_bytes(const uint8_t *inbuf, size_t inbuflen, const uint8_t *keybuf, uint8_t *outbuf) {
    uint32_t key32;
    memcpy(&key32, keybuf, 4);

    size_t i = 0;

    size_t align_bytes = (8 - ((uintptr_t)outbuf & 7)) & 7;
    if (align_bytes > inbuflen) align_bytes = inbuflen;
    for (; i < align_bytes; i++) {
        outbuf[i] = inbuf[i] ^ keybuf[i & 3];
    }

    if (i < inbuflen) {
        uint32_t phase = (uint32_t)(i & 3);
        uint32_t rotated_key32;
        if (phase == 0) {
            rotated_key32 = key32;
        } else {
            rotated_key32 = (key32 >> (phase * 8)) | (key32 << (32 - phase * 8));
        }
        uint64_t bulk_key64 = ((uint64_t)rotated_key32 << 32) | rotated_key32;

        size_t bulk_end = i + ((inbuflen - i) & ~(size_t)7);
        for (; i < bulk_end; i += 8) {
            uint64_t v;
            memcpy(&v, inbuf + i, 8);
            v ^= bulk_key64;
            memcpy(outbuf + i, &v, 8);
        }
    }

    for (; i < inbuflen; i++) {
        outbuf[i] = inbuf[i] ^ keybuf[i & 3];
    }
}

static JSValue tjs_ws_mask(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !tjs_is_uint8_array(argv[0]) || !tjs_is_uint8_array(argv[1])){
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

    ws_mask_bytes(inbuf, inbuflen, keybuf, outbuf);

	return TJS_NewUint8Array(ctx, outbuf, inbuflen);
}

static JSValue tjs_ws_mask_into(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 3 || !tjs_is_uint8_array(argv[0]) || !tjs_is_uint8_array(argv[1]) || !tjs_is_uint8_array(argv[2])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array, Uint8Array, number?)");
	}

	uint64_t out_offset64 = 0;
	if (argc >= 4 && !JS_IsUndefined(argv[3])) {
		if (JS_ToIndex(ctx, &out_offset64, argv[3])) {
			return JS_EXCEPTION;
		}
	}
	if (out_offset64 > SIZE_MAX) {
		return JS_ThrowRangeError(ctx, "Output offset is too large");
	}

	size_t inbuflen, keybuflen, outbuflen;
	uint8_t* inbuf = JS_GetUint8Array(ctx, &inbuflen, argv[0]);
	uint8_t* keybuf = JS_GetUint8Array(ctx, &keybuflen, argv[1]);
	uint8_t* outbuf = JS_GetUint8Array(ctx, &outbuflen, argv[2]);
    if (!inbuf || !keybuf || !outbuf) {
        return JS_EXCEPTION;
    }
	if(keybuflen != 4){
		return JS_ThrowTypeError(ctx, "Invalid ws mask key. expected: 4 bytes");
	}

	size_t out_offset = (size_t)out_offset64;
	if (out_offset > outbuflen || inbuflen > outbuflen - out_offset) {
		return JS_ThrowRangeError(ctx, "Output buffer is too small");
	}

    ws_mask_bytes(inbuf, inbuflen, keybuf, outbuf + out_offset);
	return JS_DupValue(ctx, argv[2]);
}

static JSValue tjs_bytes_compare(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !tjs_is_uint8_array(argv[0]) || !tjs_is_uint8_array(argv[1])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array)");
	}

	size_t alen, blen;
	uint8_t* a = JS_GetUint8Array(ctx, &alen, argv[0]);
	uint8_t* b = JS_GetUint8Array(ctx, &blen, argv[1]);
	if (!a || !b) {
		return JS_EXCEPTION;
	}

	size_t n = alen < blen ? alen : blen;
	int cmp = n == 0 ? 0 : memcmp(a, b, n);
	if (cmp < 0) return JS_NewInt32(ctx, -1);
	if (cmp > 0) return JS_NewInt32(ctx, 1);
	if (alen < blen) return JS_NewInt32(ctx, -1);
	if (alen > blen) return JS_NewInt32(ctx, 1);
	return JS_NewInt32(ctx, 0);
}

static JSValue tjs_bytes_equal(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !tjs_is_uint8_array(argv[0]) || !tjs_is_uint8_array(argv[1])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array)");
	}

	size_t alen, blen;
	uint8_t* a = JS_GetUint8Array(ctx, &alen, argv[0]);
	uint8_t* b = JS_GetUint8Array(ctx, &blen, argv[1]);
	if (!a || !b) {
		return JS_EXCEPTION;
	}
	if (alen != blen) return JS_FALSE;

	uint8_t diff = 0;
	for (size_t i = 0; i < alen; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff == 0 ? JS_TRUE : JS_FALSE;
}

static JSValue tjs_bytes_is_ascii(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	for (size_t i = 0; i < len; i++) {
		if (data[i] > 0x7f) return JS_FALSE;
	}
	return JS_TRUE;
}

static bool bytes_is_utf8(const uint8_t* data, size_t len) {
	size_t i = 0;
	while (i < len) {
		uint8_t c = data[i++];
		if (c < 0x80) continue;
		if (c < 0xc2) return false;

		if (c < 0xe0) {
			if (i >= len || (data[i] & 0xc0) != 0x80) return false;
			i++;
			continue;
		}

		if (c < 0xf0) {
			if (i + 1 >= len) return false;
			uint8_t c1 = data[i];
			uint8_t c2 = data[i + 1];
			if ((c1 & 0xc0) != 0x80 || (c2 & 0xc0) != 0x80) return false;
			if (c == 0xe0 && c1 < 0xa0) return false;
			if (c == 0xed && c1 >= 0xa0) return false;
			i += 2;
			continue;
		}

		if (c < 0xf5) {
			if (i + 2 >= len) return false;
			uint8_t c1 = data[i];
			uint8_t c2 = data[i + 1];
			uint8_t c3 = data[i + 2];
			if ((c1 & 0xc0) != 0x80 || (c2 & 0xc0) != 0x80 || (c3 & 0xc0) != 0x80) return false;
			if (c == 0xf0 && c1 < 0x90) return false;
			if (c == 0xf4 && c1 >= 0x90) return false;
			i += 3;
			continue;
		}

		return false;
	}
	return true;
}

static JSValue tjs_bytes_is_utf8(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	return bytes_is_utf8(data, len) ? JS_TRUE : JS_FALSE;
}

static JSValue tjs_bytes_invert(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	for (size_t i = 0; i < len; i++) {
		data[i] = (uint8_t)~data[i];
	}
	return JS_DupValue(ctx, argv[0]);
}

static JSValue tjs_bytes_reverse(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	for (size_t i = 0, j = len; i < j; i++) {
		j--;
		uint8_t t = data[i];
		data[i] = data[j];
		data[j] = t;
	}
	return JS_DupValue(ctx, argv[0]);
}

static int base64_loose_value(uint8_t c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+' || c == '-') return 62;
	if (c == '/' || c == '_') return 63;
	return -1;
}

static JSValue tjs_base64_decode_loose(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (string)");
	}

	size_t str_len;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &str_len, argv[0]);
	if (!str) {
		return JS_EXCEPTION;
	}

	if (str_len > SIZE_MAX / 3) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_ThrowRangeError(ctx, "Base64 input is too large");
	}

	size_t out_cap = (str_len * 3) >> 2;
	if (out_cap == 0) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t* out = js_malloc(ctx, out_cap);
	if (!out) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_ThrowOutOfMemory(ctx);
	}

	size_t written = 0;
	uint32_t acc = 0;
	int bits = 0;
	for (size_t i = 0; i < str_len; i++) {
		int v = base64_loose_value((uint8_t)(str[i] & 0xff));
		if (v < 0) continue;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[written++] = (uint8_t)((acc >> bits) & 0xff);
		}
	}

	JS_FreeCStringUTF16(ctx, str);
	if (written == 0) {
		js_free(ctx, out);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}
	return TJS_NewUint8Array(ctx, out, written);
}

static int hex_loose_value(uint16_t c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static JSValue tjs_hex_decode_loose(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (string)");
	}

	size_t str_len;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &str_len, argv[0]);
	if (!str) {
		return JS_EXCEPTION;
	}

	size_t out_cap = str_len >> 1;
	if (out_cap == 0) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t* out = js_malloc(ctx, out_cap);
	if (!out) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_ThrowOutOfMemory(ctx);
	}

	size_t written = 0;
	for (size_t i = 0; i < out_cap; i++) {
		int hi = hex_loose_value(str[i * 2]);
		int lo = hex_loose_value(str[i * 2 + 1]);
		if (hi < 0 || lo < 0) break;
		out[written++] = (uint8_t)((hi << 4) | lo);
	}

	JS_FreeCStringUTF16(ctx, str);
	if (written == 0) {
		js_free(ctx, out);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}
	return TJS_NewUint8Array(ctx, out, written);
}

static JSValue tjs_ascii_encode_loose(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (string)");
	}

	size_t str_len;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &str_len, argv[0]);
	if (!str) {
		return JS_EXCEPTION;
	}

	if (str_len == 0) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t* out = js_malloc(ctx, str_len);
	if (!out) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_ThrowOutOfMemory(ctx);
	}

	for (size_t i = 0; i < str_len; i++) {
		out[i] = (uint8_t)(str[i] & 0x7f);
	}
	JS_FreeCStringUTF16(ctx, str);
	return TJS_NewUint8Array(ctx, out, str_len);
}

static JSValue tjs_latin1_encode_loose(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (string)");
	}

	size_t str_len;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &str_len, argv[0]);
	if (!str) {
		return JS_EXCEPTION;
	}

	if (str_len == 0) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t* out = js_malloc(ctx, str_len);
	if (!out) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_ThrowOutOfMemory(ctx);
	}

	for (size_t i = 0; i < str_len; i++) {
		out[i] = (uint8_t)(str[i] & 0xff);
	}
	JS_FreeCStringUTF16(ctx, str);
	return TJS_NewUint8Array(ctx, out, str_len);
}

static JSValue tjs_encode_replace(JSContext* ctx, JSValueConst value, uint16_t limit){
	size_t str_len;
	const uint16_t* str = JS_ToCStringLenUTF16(ctx, &str_len, value);
	if (!str) {
		return JS_EXCEPTION;
	}

	if (str_len == 0) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t* out = js_malloc(ctx, str_len);
	if (!out) {
		JS_FreeCStringUTF16(ctx, str);
		return JS_ThrowOutOfMemory(ctx);
	}
	for (size_t i = 0; i < str_len; i++) {
		uint16_t c = str[i];
		out[i] = c < limit ? (uint8_t)c : 0x3f;
	}
	JS_FreeCStringUTF16(ctx, str);
	return TJS_NewUint8Array(ctx, out, str_len);
}

static JSValue tjs_ascii_encode_replace(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (string)");
	}
	return tjs_encode_replace(ctx, argv[0], 0x80);
}

static JSValue tjs_latin1_encode_replace(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsString(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (string)");
	}
	return tjs_encode_replace(ctx, argv[0], 0x100);
}

static JSValue tjs_ascii_decode_loose(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	if (len == 0) {
		return JS_NewStringLen(ctx, "", 0);
	}

	bool needs_mask = false;
	for (size_t i = 0; i < len; i++) {
		if (data[i] >= 0x80) {
			needs_mask = true;
			break;
		}
	}
	if (!needs_mask) {
		return JS_NewStringLen(ctx, (const char*)data, len);
	}

	char* out = js_malloc(ctx, len);
	if (!out) {
		return JS_ThrowOutOfMemory(ctx);
	}
	for (size_t i = 0; i < len; i++) {
		out[i] = (char)(data[i] & 0x7f);
	}
	JSValue result = JS_NewStringLen(ctx, out, len);
	js_free(ctx, out);
	return result;
}

static JSValue tjs_latin1_decode_loose(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	if (len == 0) {
		return JS_NewStringLen(ctx, "", 0);
	}

	size_t extra = 0;
	for (size_t i = 0; i < len; i++) {
		extra += data[i] >= 0x80;
	}
	if (extra == 0) {
		return JS_NewStringLen(ctx, (const char*)data, len);
	}
	if (len > SIZE_MAX - extra) {
		return JS_ThrowRangeError(ctx, "Decoded string is too large");
	}

	char* out = js_malloc(ctx, len + extra);
	if (!out) {
		return JS_ThrowOutOfMemory(ctx);
	}
	size_t j = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = data[i];
		if (c < 0x80) {
			out[j++] = (char)c;
		} else {
			out[j++] = (char)(0xc0 | (c >> 6));
			out[j++] = (char)(0x80 | (c & 0x3f));
		}
	}
	JSValue result = JS_NewStringLen(ctx, out, j);
	js_free(ctx, out);
	return result;
}

static JSValue tjs_base64_url_encode(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	if (len == 0) {
		return JS_NewStringLen(ctx, "", 0);
	}
	if (len > (SIZE_MAX - 2) / 4 * 3) {
		return JS_ThrowRangeError(ctx, "Input is too large");
	}

	static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t full = len / 3;
	size_t rem = len - full * 3;
	size_t out_len = full * 4 + (rem == 0 ? 0 : rem + 1);
	char* out = js_malloc(ctx, out_len);
	if (!out) {
		return JS_ThrowOutOfMemory(ctx);
	}

	size_t i = 0;
	size_t j = 0;
	for (size_t n = 0; n < full; n++) {
		uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
		i += 3;
		out[j++] = table[(v >> 18) & 0x3f];
		out[j++] = table[(v >> 12) & 0x3f];
		out[j++] = table[(v >> 6) & 0x3f];
		out[j++] = table[v & 0x3f];
	}
	if (rem == 1) {
		uint32_t v = (uint32_t)data[i] << 16;
		out[j++] = table[(v >> 18) & 0x3f];
		out[j++] = table[(v >> 12) & 0x3f];
	} else if (rem == 2) {
		uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
		out[j++] = table[(v >> 18) & 0x3f];
		out[j++] = table[(v >> 12) & 0x3f];
		out[j++] = table[(v >> 6) & 0x3f];
	}

	JSValue result = JS_NewStringLen(ctx, out, out_len);
	js_free(ctx, out);
	return result;
}

static int source_map_put_vlq(DynBuf* buf, int32_t value) {
	static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint64_t vlq;
	if (value < 0) {
		vlq = (((uint64_t)(-(int64_t)value)) << 1) | 1;
	} else {
		vlq = ((uint64_t)value) << 1;
	}
	do {
		uint8_t digit = (uint8_t)(vlq & 31);
		vlq >>= 5;
		if (vlq > 0) {
			digit |= 32;
		}
		if (dbuf_putc(buf, table[digit])) {
			return -1;
		}
	} while (vlq > 0);
	return 0;
}

static JSValue tjs_source_map_mappings_encode(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || JS_GetTypedArrayType(argv[0]) != JS_TYPED_ARRAY_INT32){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Int32Array)");
	}

	/* Convert argv[1] BEFORE acquiring the backing store: JS_ToIndex can run a
	 * user valueOf() that detaches argv[0], which would free `buffer` below and
	 * leave the segment loop reading freed heap. Validating the value against
	 * int_count still happens after the acquisition. */
	bool has_requested_count = (argc >= 2 && !JS_IsUndefined(argv[1]));
	uint64_t requested_count = 0;
	if (has_requested_count && JS_ToIndex(ctx, &requested_count, argv[1])) {
		return JS_EXCEPTION;
	}

	size_t offset = 0;
	size_t byte_len = 0;
	size_t bytes_per_element = 0;
	JSValue array_buffer = JS_GetTypedArrayBuffer(ctx, argv[0], &offset, &byte_len, &bytes_per_element);
	if (JS_IsException(array_buffer)) {
		return JS_EXCEPTION;
	}
	if (bytes_per_element != sizeof(int32_t) || (byte_len % sizeof(int32_t)) != 0) {
		JS_FreeValue(ctx, array_buffer);
		return JS_ThrowTypeError(ctx, "Invalid Int32Array view");
	}

	size_t buffer_len = 0;
	uint8_t* buffer = JS_GetArrayBuffer(ctx, &buffer_len, array_buffer);
	if (!buffer && buffer_len != 0) {
		JS_FreeValue(ctx, array_buffer);
		return JS_EXCEPTION;
	}
	if (offset > buffer_len || byte_len > buffer_len - offset) {
		JS_FreeValue(ctx, array_buffer);
		return JS_ThrowRangeError(ctx, "Invalid Int32Array view");
	}

	size_t int_count = byte_len / sizeof(int32_t);
	if (has_requested_count) {
		if (requested_count > int_count) {
			JS_FreeValue(ctx, array_buffer);
			return JS_ThrowRangeError(ctx, "Source map segment count exceeds Int32Array length");
		}
		int_count = (size_t)requested_count;
	}
	if ((int_count & 3) != 0) {
		JS_FreeValue(ctx, array_buffer);
		return JS_ThrowRangeError(ctx, "Source map segment data must be a multiple of 4");
	}
	if (int_count == 0) {
		JS_FreeValue(ctx, array_buffer);
		return JS_NewStringLen(ctx, "", 0);
	}

	int32_t* segments = (int32_t*)(void*)(buffer + offset);
	size_t segment_count = int_count >> 2;
	DynBuf out;
	tjs_dbuf_init(ctx, &out);

	int32_t line = 0;
	int32_t prev_generated_column = 0;
	int32_t prev_source_index = 0;
	int32_t prev_source_line = 0;
	int32_t prev_source_column = 0;
	bool needs_comma = false;
	int32_t last_segment_generated_column = INT32_MIN;
	size_t last_segment_start = 0;
	int32_t last_prev_generated_column = 0;
	int32_t last_prev_source_index = 0;
	int32_t last_prev_source_line = 0;
	int32_t last_prev_source_column = 0;
	bool last_needs_comma = false;

	for (size_t i = 0; i < segment_count; i++) {
		int32_t segment_line = segments[i * 4];
		int32_t generated_column = segments[i * 4 + 1];
		int32_t source_line = segments[i * 4 + 2];
		int32_t source_column = segments[i * 4 + 3];

		if (segment_line < line) {
			dbuf_free(&out);
			JS_FreeValue(ctx, array_buffer);
			return JS_ThrowRangeError(ctx, "Source map segments must be sorted by line");
		}
		while (line < segment_line) {
			if (dbuf_putc(&out, ';')) {
				goto oom;
			}
			line++;
			prev_generated_column = 0;
			needs_comma = false;
			last_segment_generated_column = INT32_MIN;
		}
		if (last_segment_generated_column == generated_column) {
			out.size = last_segment_start;
			prev_generated_column = last_prev_generated_column;
			prev_source_index = last_prev_source_index;
			prev_source_line = last_prev_source_line;
			prev_source_column = last_prev_source_column;
			needs_comma = last_needs_comma;
		}

		last_segment_start = out.size;
		last_prev_generated_column = prev_generated_column;
		last_prev_source_index = prev_source_index;
		last_prev_source_line = prev_source_line;
		last_prev_source_column = prev_source_column;
		last_needs_comma = needs_comma;
		if (needs_comma) {
			if (dbuf_putc(&out, ',')) {
				goto oom;
			}
		} else {
			needs_comma = true;
		}
		if (source_map_put_vlq(&out, generated_column - prev_generated_column) ||
			source_map_put_vlq(&out, 0 - prev_source_index) ||
			source_map_put_vlq(&out, source_line - prev_source_line) ||
			source_map_put_vlq(&out, source_column - prev_source_column)) {
			goto oom;
		}

		prev_generated_column = generated_column;
		prev_source_index = 0;
		prev_source_line = source_line;
		prev_source_column = source_column;
		last_segment_generated_column = generated_column;
	}

	JSValue result = JS_NewStringLen(ctx, (char*)out.buf, out.size);
	dbuf_free(&out);
	JS_FreeValue(ctx, array_buffer);
	return result;

oom:
	dbuf_free(&out);
	JS_FreeValue(ctx, array_buffer);
	return JS_ThrowOutOfMemory(ctx);
}

static JSValue tjs_bytes_from_array_like(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (ArrayLike<number>)");
	}

	int64_t length;
	if (JS_GetLength(ctx, argv[0], &length) < 0) {
		return JS_EXCEPTION;
	}
	if (length < 0) {
		return JS_ThrowRangeError(ctx, "Invalid array-like length");
	}
	if (length > UINT32_MAX) {
		return JS_ThrowRangeError(ctx, "Array-like object is too large");
	}
	uint32_t len = (uint32_t)length;
	if (len == 0) {
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t* out = js_malloc(ctx, len);
	if (!out) {
		return JS_ThrowOutOfMemory(ctx);
	}
	for (uint32_t i = 0; i < len; i++) {
		JSValue item = JS_GetPropertyUint32(ctx, argv[0], i);
		if (JS_IsException(item)) {
			js_free(ctx, out);
			return JS_EXCEPTION;
		}
		uint32_t value;
		int ret = JS_ToUint32(ctx, &value, item);
		JS_FreeValue(ctx, item);
		if (ret) {
			js_free(ctx, out);
			return JS_EXCEPTION;
		}
		out[i] = (uint8_t)(value & 0xff);
	}
	return TJS_NewUint8Array(ctx, out, len);
}

static JSValue tjs_bytes_concat(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !JS_IsArray(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array[])");
	}

	int64_t length;
	if (JS_GetLength(ctx, argv[0], &length) < 0) {
		return JS_EXCEPTION;
	}
	if (length > UINT32_MAX || length > SIZE_MAX / sizeof(TJSBytesChunk)) {
		return JS_ThrowRangeError(ctx, "Too many chunks");
	}
	if (length == 0) {
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	TJSBytesChunk* chunks = js_malloc(ctx, sizeof(*chunks) * length);
	if (!chunks) {
		return JS_ThrowOutOfMemory(ctx);
	}

	size_t total = 0;
	uint32_t collected = 0, length_u32 = (uint32_t)length;
	for (uint32_t i = 0; i < length_u32; i++) {
		JSValue chunk = JS_GetPropertyUint32(ctx, argv[0], i);
		if (JS_IsException(chunk)) {
			tjs_free_bytes_chunks(ctx, chunks, collected);
			return JS_EXCEPTION;
		}
		chunks[collected].value = chunk;

		if (!tjs_is_uint8_array(chunk)) {
			tjs_free_bytes_chunks(ctx, chunks, collected + 1);
			return JS_ThrowTypeError(ctx, "Invalid chunk. expected: Uint8Array");
		}

		chunks[collected].data = NULL;
		chunks[collected].len = 0;
		collected++;
	}

	for (uint32_t i = 0; i < collected; i++) {
		size_t chunk_len;
		uint8_t *chunk_buf = JS_GetUint8Array(ctx, &chunk_len, chunks[i].value);
		if (!chunk_buf) {
			tjs_free_bytes_chunks(ctx, chunks, collected);
			return JS_EXCEPTION;
		}
		if (chunk_len > SIZE_MAX - total) {
			tjs_free_bytes_chunks(ctx, chunks, collected);
			return JS_ThrowRangeError(ctx, "Concatenated buffer is too large");
		}
		chunks[i].data = chunk_buf;
		chunks[i].len = chunk_len;
		total += chunk_len;
	}

	if (total == 0) {
		tjs_free_bytes_chunks(ctx, chunks, collected);
		return JS_NewUint8ArrayCopy(ctx, NULL, 0);
	}

	uint8_t *outbuf = js_malloc(ctx, total);
	if (!outbuf) {
		tjs_free_bytes_chunks(ctx, chunks, collected);
		return JS_ThrowOutOfMemory(ctx);
	}

	size_t offset = 0;
	for (uint32_t i = 0; i < collected; i++) {
		memcpy(outbuf + offset, chunks[i].data, chunks[i].len);
		offset += chunks[i].len;
		JS_FreeValue(ctx, chunks[i].value);
	}
	js_free(ctx, chunks);

	return TJS_NewUint8Array(ctx, outbuf, total);
}

static JSValue tjs_bytes_repeat_into(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !tjs_is_uint8_array(argv[0]) || !tjs_is_uint8_array(argv[1])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array, number?, number?)");
	}

	uint64_t start64 = 0;
	uint64_t end64 = UINT64_MAX;
	if (argc >= 3 && !JS_IsUndefined(argv[2])) {
		if (JS_ToIndex(ctx, &start64, argv[2])) {
			return JS_EXCEPTION;
		}
	}
	if (argc >= 4 && !JS_IsUndefined(argv[3])) {
		if (JS_ToIndex(ctx, &end64, argv[3])) {
			return JS_EXCEPTION;
		}
	}

	size_t target_len, pattern_len;
	uint8_t* target = JS_GetUint8Array(ctx, &target_len, argv[0]);
	uint8_t* pattern = JS_GetUint8Array(ctx, &pattern_len, argv[1]);
	if (!target || !pattern) {
		return JS_EXCEPTION;
	}

	if (start64 > target_len) start64 = target_len;
	if (end64 > target_len) end64 = target_len;
	if (end64 <= start64 || pattern_len == 0) {
		return JS_DupValue(ctx, argv[0]);
	}

	uint8_t* out = target + (size_t)start64;
	size_t len = (size_t)(end64 - start64);
	size_t first = pattern_len < len ? pattern_len : len;
	memmove(out, pattern, first);

	size_t filled = first;
	while (filled < len) {
		size_t copy_len = filled < len - filled ? filled : len - filled;
		memcpy(out + filled, out, copy_len);
		filled += copy_len;
	}
	return JS_DupValue(ctx, argv[0]);
}

static JSValue tjs_bytes_swap16(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	if ((len & 1) != 0) return JS_ThrowRangeError(ctx, "Buffer size must be a multiple of 16-bits");

	for (size_t i = 0; i < len; i += 2) {
		uint8_t t = data[i];
		data[i] = data[i + 1];
		data[i + 1] = t;
	}
	return JS_DupValue(ctx, argv[0]);
}

static JSValue tjs_bytes_swap32(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	if ((len & 3) != 0) return JS_ThrowRangeError(ctx, "Buffer size must be a multiple of 32-bits");

	for (size_t i = 0; i < len; i += 4) {
		uint8_t t = data[i];
		data[i] = data[i + 3];
		data[i + 3] = t;
		t = data[i + 1];
		data[i + 1] = data[i + 2];
		data[i + 2] = t;
	}
	return JS_DupValue(ctx, argv[0]);
}

static JSValue tjs_bytes_swap64(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 1 || !tjs_is_uint8_array(argv[0])){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array)");
	}

	size_t len;
	uint8_t* data = JS_GetUint8Array(ctx, &len, argv[0]);
	if (!data) {
		return JS_EXCEPTION;
	}
	if ((len & 7) != 0) return JS_ThrowRangeError(ctx, "Buffer size must be a multiple of 64-bits");

	for (size_t i = 0; i < len; i += 8) {
		uint8_t t = data[i];
		data[i] = data[i + 7];
		data[i + 7] = t;
		t = data[i + 1];
		data[i + 1] = data[i + 6];
		data[i + 6] = t;
		t = data[i + 2];
		data[i + 2] = data[i + 5];
		data[i + 5] = t;
		t = data[i + 3];
		data[i + 3] = data[i + 4];
		data[i + 4] = t;
	}
	return JS_DupValue(ctx, argv[0]);
}

static JSValue tjs_bytes_index_of(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !tjs_is_uint8_array(argv[0]) || (!tjs_is_uint8_array(argv[1]) && !JS_IsNumber(argv[1]))){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array | number, number?)");
	}

	uint64_t offset64 = 0;
	if (argc >= 3 && !JS_IsUndefined(argv[2])) {
		if (JS_ToIndex(ctx, &offset64, argv[2])) {
			return JS_EXCEPTION;
		}
	}
	if (offset64 > SIZE_MAX) return JS_NewInt64(ctx, -1);
	size_t offset = (size_t)offset64;

	uint32_t byte_value = 0;
	bool needle_is_byte = JS_IsNumber(argv[1]);
	if (needle_is_byte && JS_ToUint32(ctx, &byte_value, argv[1])) {
		return JS_EXCEPTION;
	}

	size_t haylen;
	uint8_t* hay = JS_GetUint8Array(ctx, &haylen, argv[0]);
	if (!hay) {
		return JS_EXCEPTION;
	}

	if (needle_is_byte) {
		if (offset >= haylen) return JS_NewInt64(ctx, -1);
		void* found = memchr(hay + offset, byte_value & 0xff, haylen - offset);
		return JS_NewInt64(ctx, found ? (int64_t)((uint8_t*)found - hay) : -1);
	}

	size_t needlelen;
	uint8_t* needle = JS_GetUint8Array(ctx, &needlelen, argv[1]);
	if (!needle) {
		return JS_EXCEPTION;
	}
	if (needlelen == 0) return JS_NewInt64(ctx, (int64_t)(offset > haylen ? haylen : offset));
	if (offset > haylen || needlelen > haylen - offset) return JS_NewInt64(ctx, -1);

	if (needlelen == 1) {
		void* found = memchr(hay + offset, needle[0], haylen - offset);
		return JS_NewInt64(ctx, found ? (int64_t)((uint8_t*)found - hay) : -1);
	}

	const uint8_t first = needle[0];
	const uint8_t* cursor = hay + offset;
	const uint8_t* last = hay + haylen - needlelen;
	while (cursor <= last) {
		cursor = memchr(cursor, first, (size_t)(last - cursor + 1));
		if (!cursor) {
			break;
		}
		if (memcmp(cursor, needle, needlelen) == 0) {
			return JS_NewInt64(ctx, (int64_t)(cursor - hay));
		}
		cursor++;
	}
	return JS_NewInt64(ctx, -1);
}

static JSValue tjs_bytes_last_index_of(JSContext* ctx, JSValue this_arg, int argc, JSValue* argv){
	if(argc < 2 || !tjs_is_uint8_array(argv[0]) || (!tjs_is_uint8_array(argv[1]) && !JS_IsNumber(argv[1]))){
		return JS_ThrowTypeError(ctx, "Invalid arguments. expected: (Uint8Array, Uint8Array | number, number?)");
	}

	uint64_t offset64 = UINT64_MAX;
	if (argc >= 3 && !JS_IsUndefined(argv[2])) {
		if (JS_ToIndex(ctx, &offset64, argv[2])) {
			return JS_EXCEPTION;
		}
	}

	uint32_t byte_value = 0;
	bool needle_is_byte = JS_IsNumber(argv[1]);
	if (needle_is_byte && JS_ToUint32(ctx, &byte_value, argv[1])) {
		return JS_EXCEPTION;
	}

	size_t haylen;
	uint8_t* hay = JS_GetUint8Array(ctx, &haylen, argv[0]);
	if (!hay) {
		return JS_EXCEPTION;
	}

	if (offset64 == UINT64_MAX) offset64 = haylen;

	if (needle_is_byte) {
		if (haylen == 0) return JS_NewInt64(ctx, -1);
		size_t start = offset64 >= haylen ? haylen - 1 : (size_t)offset64;
		for (size_t i = start;; i--) {
			if (hay[i] == (byte_value & 0xff)) return JS_NewInt64(ctx, (int64_t)i);
			if (i == 0) break;
		}
		return JS_NewInt64(ctx, -1);
	}

	size_t needlelen;
	uint8_t* needle = JS_GetUint8Array(ctx, &needlelen, argv[1]);
	if (!needle) {
		return JS_EXCEPTION;
	}
	if (needlelen == 0) {
		size_t pos = offset64 > haylen ? haylen : (size_t)offset64;
		return JS_NewInt64(ctx, (int64_t)pos);
	}
	if (needlelen > haylen) return JS_NewInt64(ctx, -1);

	size_t max_start = haylen - needlelen;
	size_t start = offset64 > max_start ? max_start : (size_t)offset64;
	if (needlelen == 1) {
		for (size_t i = start;; i--) {
			if (hay[i] == needle[0]) return JS_NewInt64(ctx, (int64_t)i);
			if (i == 0) break;
		}
		return JS_NewInt64(ctx, -1);
	}

	const uint8_t first = needle[0];
	const uint8_t last = needle[needlelen - 1];
	for (size_t i = start;; i--) {
		if (hay[i] == first && hay[i + needlelen - 1] == last && memcmp(hay + i, needle, needlelen) == 0) {
			return JS_NewInt64(ctx, (int64_t)i);
		}
		if (i == 0) break;
	}
	return JS_NewInt64(ctx, -1);
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
    xoshiro256_state state;
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
    rng->state.s[0] = seed * 0x9e3779b97f4a7c15ULL;
    rng->state.s[1] = rotl64(seed, 21) * 0x9e3779b97f4a7c15ULL;
    rng->state.s[2] = rotl64(seed, 42) * 0x9e3779b97f4a7c15ULL;
    rng->state.s[3] = rotl64(seed, 63) * 0x9e3779b97f4a7c15ULL;
}

static bool xoshiro256_is_zero(const XoshiroRNG *rng) {
    return rng->state.s[0] == 0 && rng->state.s[1] == 0 && rng->state.s[2] == 0 && rng->state.s[3] == 0;
}

static JSValue xoshiro_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    XoshiroRNG *rng;
    JSValue obj;
    
    rng = js_mallocz(ctx, sizeof(*rng));
    if (!rng) return JS_EXCEPTION;
    
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
                rng->state.s[i] = val;
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
    XoshiroRNG *rng = JS_GetOpaque2(ctx, this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    uint64_t result = xoshiro256_next(&rng->state);
    return JS_NewBigUint64(ctx, result);
}

static JSValue xoshiro_next_double(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque2(ctx, this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    uint64_t result = xoshiro256_next(&rng->state);
    double d = (result >> 11) * 0x1.0p-53;
    return JS_NewFloat64(ctx, d);
}

static JSValue xoshiro_jump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque2(ctx, this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    xoshiro256_jump(&rng->state);
    
    return JS_UNDEFINED;
}

static JSValue xoshiro_long_jump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque2(ctx, this_val, xoshiro_class_id);
    if (!rng) return JS_EXCEPTION;
    
    xoshiro256_long_jump(&rng->state);
    
    return JS_UNDEFINED;
}

static JSValue xoshiro_clone(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    XoshiroRNG *rng = JS_GetOpaque2(ctx, this_val, xoshiro_class_id);
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
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
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
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
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
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
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

static uint32_t xxHash32(const uint8_t *input, size_t len, uint32_t seed) {
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
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
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
    uint32_t result = xxHash32(data, len, seed);
    return JS_NewUint32(ctx, result);
}

/* MurmurHash2, xxHash64, CityHash and wyhash (Zig-compatible v4.2), ported
 * from the Bun.hash polyfill implementations. */

static uint32_t murmur2_32(const uint8_t *data, size_t len, uint32_t seed) {
    const uint32_t m = 0x5bd1e995u;
    uint32_t h = seed ^ (uint32_t)len;
    size_t offset = 0;

    for (; offset + 4 <= len; offset += 4) {
        uint32_t k = read_u32_le(data + offset) * m;
        k ^= k >> 24;
        k *= m;
        h = h * m ^ k;
    }

    size_t remaining = len - offset;
    if (remaining >= 3) {
        h ^= (uint32_t)data[offset + 2] << 16;
    }
    if (remaining >= 2) {
        h ^= (uint32_t)data[offset + 1] << 8;
    }
    if (remaining >= 1) {
        h = (h ^ data[offset]) * m;
    }

    h ^= h >> 13;
    h *= m;
    return h ^ (h >> 15);
}

static uint64_t murmur2_64(const uint8_t *data, size_t len, uint64_t seed) {
    const uint64_t m = 0xc6a4a7935bd1e995ull;
    uint64_t h = seed ^ ((uint64_t)len * m);
    size_t offset = 0;

    for (; offset + 8 <= len; offset += 8) {
        uint64_t k = read_u64_le(data + offset) * m;
        k ^= k >> 47;
        k *= m;
        h ^= k;
        h *= m;
    }

    if (offset < len) {
        uint64_t tail = 0;
        for (size_t i = 0; offset + i < len; i++) {
            tail |= (uint64_t)data[offset + i] << (i * 8);
        }
        h ^= tail;
        h *= m;
    }

    h ^= h >> 47;
    h *= m;
    return h ^ (h >> 47);
}

static const uint64_t XXH_PRIME64_1 = 0x9e3779b185ebca87ull;
static const uint64_t XXH_PRIME64_2 = 0xc2b2ae3d27d4eb4full;
static const uint64_t XXH_PRIME64_3 = 0x165667b19e3779f9ull;
static const uint64_t XXH_PRIME64_4 = 0x85ebca77c2b2ae63ull;
static const uint64_t XXH_PRIME64_5 = 0x27d4eb2f165667c5ull;

static uint64_t xxh64_round(uint64_t acc, uint64_t input) {
    acc += input * XXH_PRIME64_2;
    acc = (acc << 31) | (acc >> 33);
    acc *= XXH_PRIME64_1;
    return acc;
}

static uint64_t xxh64_merge(uint64_t acc, uint64_t value) {
    acc ^= xxh64_round(0, value);
    return acc * XXH_PRIME64_1 + XXH_PRIME64_4;
}

static uint64_t xxHash64(const uint8_t *input, size_t len, uint64_t seed) {
    const uint8_t *p = input;
    const uint8_t *const bEnd = input + len;
    uint64_t h64;

    if (len >= 32) {
        const uint8_t *const limit = bEnd - 32;
        uint64_t v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = seed + XXH_PRIME64_2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - XXH_PRIME64_1;

        do {
            v1 = xxh64_round(v1, read_u64_le(p));
            p += 8;
            v2 = xxh64_round(v2, read_u64_le(p));
            p += 8;
            v3 = xxh64_round(v3, read_u64_le(p));
            p += 8;
            v4 = xxh64_round(v4, read_u64_le(p));
            p += 8;
        } while (p <= limit);

        h64 = (v1 << 1) | (v1 >> 63);
        h64 += (v2 << 7) | (v2 >> 57);
        h64 += (v3 << 12) | (v3 >> 52);
        h64 += (v4 << 18) | (v4 >> 46);
        h64 = xxh64_merge(h64, v1);
        h64 = xxh64_merge(h64, v2);
        h64 = xxh64_merge(h64, v3);
        h64 = xxh64_merge(h64, v4);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += (uint64_t)len;

    while (p + 8 <= bEnd) {
        uint64_t k = xxh64_round(0, read_u64_le(p));
        h64 = (((h64 ^ k) << 27) | ((h64 ^ k) >> 37)) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
    }
    if (p + 4 <= bEnd) {
        uint64_t k = (uint64_t)read_u32_le(p) * XXH_PRIME64_1;
        h64 = (((h64 ^ k) << 23) | ((h64 ^ k) >> 41)) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
    }
    while (p < bEnd) {
        h64 = (((h64 ^ (*p * XXH_PRIME64_5)) << 11) | ((h64 ^ (*p * XXH_PRIME64_5)) >> 53)) * XXH_PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}

/* 64x64 -> 128 multiply: __uint128_t where available, 32-bit limbs otherwise. */
static inline uint64_t mul64x128(uint64_t a, uint64_t b, uint64_t *hi) {
#if defined(__SIZEOF_INT128__)
    __uint128_t p = (__uint128_t)a * b;
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
#else
    uint32_t a0 = (uint32_t)a, a1 = (uint32_t)(a >> 32);
    uint32_t b0 = (uint32_t)b, b1 = (uint32_t)(b >> 32);
    uint64_t p00 = (uint64_t)a0 * b0;
    uint64_t p01 = (uint64_t)a0 * b1;
    uint64_t p10 = (uint64_t)a1 * b0;
    uint64_t p11 = (uint64_t)a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return (p00 & 0xffffffffull) | (mid << 32);
#endif
}

#define WYHASH_SECRET0 0xa0761d6478bd642full
#define WYHASH_SECRET1 0xe7037ed1a0b428dbull
#define WYHASH_SECRET2 0x8ebc6af09c88c6e3ull
#define WYHASH_SECRET3 0x589965cc75374cc3ull

static uint64_t wyhash_mix(uint64_t a, uint64_t b) {
    uint64_t hi;
    uint64_t lo = mul64x128(a, b, &hi);
    return lo ^ hi;
}

static uint64_t wyhash(const uint8_t *data, size_t len, uint64_t seed) {
    uint64_t a, b;

    seed ^= wyhash_mix(seed ^ WYHASH_SECRET0, WYHASH_SECRET1);

    if (len <= 16) {
        if (len >= 4) {
            uint64_t quarter = (len >> 3) << 2;
            size_t end = len - 4;
            a = ((uint64_t)read_u32_le(data) << 32) | read_u32_le(data + quarter);
            b = ((uint64_t)read_u32_le(data + end) << 32) | read_u32_le(data + end - quarter);
        } else if (len > 0) {
            a = ((uint64_t)data[0] << 16) | ((uint64_t)data[len >> 1] << 8) | data[len - 1];
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        uint64_t s0 = seed, s1 = seed, s2 = seed;
        size_t offset = 0;

        if (len >= 48) {
            while (offset + 48 < len) {
                s0 = wyhash_mix(read_u64_le(data + offset) ^ WYHASH_SECRET1,
                                read_u64_le(data + offset + 8) ^ s0);
                s1 = wyhash_mix(read_u64_le(data + offset + 16) ^ WYHASH_SECRET2,
                                read_u64_le(data + offset + 24) ^ s1);
                s2 = wyhash_mix(read_u64_le(data + offset + 32) ^ WYHASH_SECRET3,
                                read_u64_le(data + offset + 40) ^ s2);
                offset += 48;
            }
            s0 ^= s1 ^ s2;
        }

        size_t remaining = len - offset;
        while (remaining > 16) {
            s0 = wyhash_mix(read_u64_le(data + offset) ^ WYHASH_SECRET1,
                            read_u64_le(data + offset + 8) ^ s0);
            offset += 16;
            remaining -= 16;
        }

        a = read_u64_le(data + len - 16);
        b = read_u64_le(data + len - 8);
        seed = s0;
    }

    a ^= WYHASH_SECRET1;
    b ^= seed;
    uint64_t hi;
    uint64_t lo = mul64x128(a, b, &hi);
    return wyhash_mix(lo ^ WYHASH_SECRET0 ^ (uint64_t)len, hi ^ WYHASH_SECRET1);
}

/* CityHash32 */

#define CITY_C1 0xcc9e2d51u
#define CITY_C2 0x1b873593u

static inline uint32_t city_ror32(uint32_t v, int shift) {
    return shift == 0 ? v : (v >> shift) | (v << (32 - shift));
}

static inline uint32_t city_bswap32(uint32_t v) {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

static inline uint64_t city_bswap64(uint64_t v) {
#if defined(_MSC_VER)
    return _byteswap_uint64(v);
#else
    return __builtin_bswap64(v);
#endif
}

static uint32_t city_fmix32(uint32_t value) {
    value ^= value >> 16;
    value *= 0x85ebca6bu;
    value ^= value >> 13;
    value *= 0xc2b2ae35u;
    value ^= value >> 16;
    return value;
}

static uint32_t city_mur(uint32_t value, uint32_t hash) {
    value *= CITY_C1;
    value = (value >> 17) | (value << 15);
    value *= CITY_C2;
    hash ^= value;
    hash = (hash >> 19) | (hash << 13);
    return hash * 5 + 0xe6546b64u;
}

static uint32_t city32_length0to4(const uint8_t *data, size_t len) {
    uint32_t b = 0;
    uint32_t c = 9;
    for (size_t i = 0; i < len; i++) {
        b = b * CITY_C1 + (uint32_t)(int8_t)data[i];
        c ^= b;
    }
    return city_fmix32(city_mur(b, city_mur((uint32_t)len, c)));
}

static uint32_t city32_length5to12(const uint8_t *data, size_t len) {
    uint32_t a = (uint32_t)len;
    uint32_t b = (uint32_t)(len * 5);
    uint32_t c = 9;
    uint32_t d = b;
    a += read_u32_le(data);
    b += read_u32_le(data + len - 4);
    c += read_u32_le(data + ((len >> 1) & 4));
    return city_fmix32(city_mur(c, city_mur(b, city_mur(a, d))));
}

static uint32_t city32_length13to24(const uint8_t *data, size_t len) {
    uint32_t a = read_u32_le(data + ((len >> 1) - 4));
    uint32_t b = read_u32_le(data + 4);
    uint32_t c = read_u32_le(data + len - 8);
    uint32_t d = read_u32_le(data + (len >> 1));
    uint32_t e = read_u32_le(data);
    uint32_t f = read_u32_le(data + len - 4);
    return city_fmix32(city_mur(f, city_mur(e, city_mur(d, city_mur(c, city_mur(b, city_mur(a, (uint32_t)len)))))));
}

static uint32_t cityHash32(const uint8_t *data, size_t len) {
    if (len <= 24) {
        if (len <= 4) {
            return city32_length0to4(data, len);
        }
        return len <= 12 ? city32_length5to12(data, len) : city32_length13to24(data, len);
    }

    uint32_t hash = (uint32_t)len;
    uint32_t g = CITY_C1 * (uint32_t)len;
    uint32_t f = g;
    uint32_t a0 = city_ror32(read_u32_le(data + len - 4) * CITY_C1, 17) * CITY_C2;
    uint32_t a1 = city_ror32(read_u32_le(data + len - 8) * CITY_C1, 17) * CITY_C2;
    uint32_t a2 = city_ror32(read_u32_le(data + len - 16) * CITY_C1, 17) * CITY_C2;
    uint32_t a3 = city_ror32(read_u32_le(data + len - 12) * CITY_C1, 17) * CITY_C2;
    uint32_t a4 = city_ror32(read_u32_le(data + len - 20) * CITY_C1, 17) * CITY_C2;

    hash ^= a0;
    hash = city_ror32(hash, 19) * 5 + 0xe6546b64u;
    hash ^= a2;
    hash = city_ror32(hash, 19) * 5 + 0xe6546b64u;
    g ^= a1;
    g = city_ror32(g, 19) * 5 + 0xe6546b64u;
    g ^= a3;
    g = city_ror32(g, 19) * 5 + 0xe6546b64u;
    f += a4;
    f = city_ror32(f, 19) * 5 + 0xe6546b64u;

    size_t offset = 0;
    size_t iterations = (len - 1) / 20;
    do {
        uint32_t x0 = city_ror32(read_u32_le(data + offset) * CITY_C1, 17) * CITY_C2;
        uint32_t x1 = read_u32_le(data + offset + 4);
        uint32_t x2 = city_ror32(read_u32_le(data + offset + 8) * CITY_C1, 17) * CITY_C2;
        uint32_t x3 = city_ror32(read_u32_le(data + offset + 12) * CITY_C1, 17) * CITY_C2;
        uint32_t x4 = read_u32_le(data + offset + 16);
        hash ^= x0;
        hash = city_ror32(hash, 18) * 5 + 0xe6546b64u;
        f = city_ror32(f + x1, 19) * CITY_C1;
        g += x2;
        g = city_ror32(g, 18) * 5 + 0xe6546b64u;
        uint32_t merged = x3 + x1;
        hash ^= merged;
        hash = city_ror32(hash, 19) * 5 + 0xe6546b64u;
        g ^= x4;
        g = city_bswap32(g) * 5;
        hash = city_bswap32(hash + x4 * 5);
        f += x0;
        uint32_t swap = hash;
        hash = f;
        f = g;
        g = swap;
        offset += 20;
    } while (--iterations != 0);

    g = city_ror32(g, 11) * CITY_C1;
    g = city_ror32(g, 17) * CITY_C1;
    f = city_ror32(f, 11) * CITY_C1;
    f = city_ror32(f, 17) * CITY_C1;
    hash = city_ror32(hash + g, 19) * 5 + 0xe6546b64u;
    hash = city_ror32(hash, 17) * CITY_C1;
    hash = city_ror32(hash + f, 19) * 5 + 0xe6546b64u;
    return city_ror32(hash, 17) * CITY_C1;
}

/* CityHash64 */

#define CITY_K0 0xc3a5c85c97cb3127ull
#define CITY_K1 0xb492b66fbe98f273ull
#define CITY_K2 0x9ae16a3b2f90404full

static uint64_t city_shift_mix(uint64_t value) {
    return value ^ (value >> 47);
}

static uint64_t city_hash_len16(uint64_t left, uint64_t right, uint64_t multiplier) {
    uint64_t a = (left ^ right) * multiplier;
    a ^= a >> 47;
    uint64_t b = (right ^ a) * multiplier;
    b ^= b >> 47;
    return b * multiplier;
}

static uint64_t city_hash_len16_default(uint64_t left, uint64_t right) {
    return city_hash_len16(left, right, 0x9ddfea08eb382d69ull);
}

static uint64_t city_hash_0to16(const uint8_t *data, size_t len) {
    if (len >= 8) {
        uint64_t multiplier = CITY_K2 + (uint64_t)len * 2;
        uint64_t a = read_u64_le(data) + CITY_K2;
        uint64_t b = read_u64_le(data + len - 8);
        uint64_t c = ((b >> 37) | (b << 27)) * multiplier + a;
        uint64_t d = (((a >> 25) | (a << 39)) + b) * multiplier;
        return city_hash_len16(c, d, multiplier);
    }
    if (len >= 4) {
        uint64_t multiplier = CITY_K2 + (uint64_t)len * 2;
        uint64_t a = read_u32_le(data);
        return city_hash_len16((uint64_t)len + (a << 3), read_u32_le(data + len - 4), multiplier);
    }
    if (len > 0) {
        uint64_t y = data[0] + ((uint64_t)data[len >> 1] << 8);
        uint64_t z = (uint64_t)len + ((uint64_t)data[len - 1] << 2);
        return city_shift_mix(y * CITY_K2 ^ z * CITY_K0) * CITY_K2;
    }
    return CITY_K2;
}

static uint64_t city_hash_17to32(const uint8_t *data, size_t len) {
    uint64_t multiplier = CITY_K2 + (uint64_t)len * 2;
    uint64_t a = read_u64_le(data) * CITY_K1;
    uint64_t b = read_u64_le(data + 8);
    uint64_t c = read_u64_le(data + len - 8) * multiplier;
    uint64_t d = read_u64_le(data + len - 16) * CITY_K2;
    uint64_t left = ((a + b) >> 43) | ((a + b) << 21);
    left += (c >> 30) | (c << 34);
    left += d;
    uint64_t right = a + (((b + CITY_K2) >> 18) | ((b + CITY_K2) << 46)) + c;
    return city_hash_len16(left, right, multiplier);
}

static void city_weak_hash32(const uint8_t *data, size_t offset, uint64_t a, uint64_t b, uint64_t out[2]) {
    uint64_t w = read_u64_le(data + offset);
    uint64_t x = read_u64_le(data + offset + 8);
    uint64_t y = read_u64_le(data + offset + 16);
    uint64_t z = read_u64_le(data + offset + 24);
    a += w;
    b = ((b + a + z) >> 21) | ((b + a + z) << 43);
    uint64_t c = a;
    a += x + y;
    b += (a >> 44) | (a << 20);
    out[0] = a + z;
    out[1] = b + c;
}

static uint64_t city_hash_33to64(const uint8_t *data, size_t len) {
    uint64_t mul = CITY_K2 + (uint64_t)len * 2;
    uint64_t a = read_u64_le(data) * CITY_K2;
    uint64_t b = read_u64_le(data + 8);
    uint64_t c = read_u64_le(data + len - 24);
    uint64_t d = read_u64_le(data + len - 32);
    uint64_t e = read_u64_le(data + 16) * CITY_K2;
    uint64_t f = read_u64_le(data + 24) * 9;
    uint64_t g = read_u64_le(data + len - 8);
    uint64_t h = read_u64_le(data + len - 16) * mul;
    uint64_t u = ((a + g) >> 43) | ((a + g) << 21);
    u += (((b >> 30) | (b << 34)) + c) * 9;
    uint64_t v = ((a + g) ^ d) + f + 1;
    uint64_t w = city_bswap64((u + v) * mul) + h;
    uint64_t x = ((e + f) >> 42) | ((e + f) << 22);
    x += c;
    uint64_t y = (city_bswap64((v + w) * mul) + g) * mul;
    uint64_t z = e + f + c;
    a = city_bswap64((x + z) * mul + y) + b;
    b = city_shift_mix((z + a) * mul + d + h) * mul;
    return b + x;
}

static uint64_t city_hash_long(const uint8_t *data, size_t len) {
    uint64_t x = read_u64_le(data + len - 40);
    uint64_t y = read_u64_le(data + len - 16) + read_u64_le(data + len - 56);
    uint64_t z = city_hash_len16_default(read_u64_le(data + len - 48) + (uint64_t)len, read_u64_le(data + len - 24));
    uint64_t v[2], w[2];
    city_weak_hash32(data, len - 64, (uint64_t)len, z, v);
    city_weak_hash32(data, len - 32, y + CITY_K1, x, w);

    x = x * CITY_K1 + read_u64_le(data);
    size_t end = ((len - 1) / 64) * 64;
    size_t offset = 0;
    do {
        uint64_t rx = x + y + v[0] + read_u64_le(data + offset + 8);
        x = ((rx >> 37) | (rx << 27)) * CITY_K1;
        uint64_t ry = y + v[1] + read_u64_le(data + offset + 48);
        y = ((ry >> 42) | (ry << 22)) * CITY_K1;
        x ^= w[1];
        y += v[0] + read_u64_le(data + offset + 40);
        uint64_t rz = z + w[0];
        z = ((rz >> 33) | (rz << 31)) * CITY_K1;
        city_weak_hash32(data, offset, v[1] * CITY_K1, x + w[0], v);
        city_weak_hash32(data, offset + 32, z + w[1], y + read_u64_le(data + offset + 16), w);
        uint64_t swap = z;
        z = x;
        x = swap;
        offset += 64;
    } while (offset != end);

    return city_hash_len16_default(
        city_hash_len16_default(v[0], w[0]) + city_shift_mix(y) * CITY_K1 + z,
        city_hash_len16_default(v[1], w[1]) + x);
}

static uint64_t cityHash64WithSeed(const uint8_t *data, size_t len, uint64_t seed) {
    uint64_t unseeded;
    if (len <= 16) {
        unseeded = city_hash_0to16(data, len);
    } else if (len <= 32) {
        unseeded = city_hash_17to32(data, len);
    } else if (len <= 64) {
        unseeded = city_hash_33to64(data, len);
    } else {
        unseeded = city_hash_long(data, len);
    }
    return city_hash_len16_default(unseeded - CITY_K2, seed);
}

static JSValue tjs_hash_wyhash(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    uint64_t seed = 0;
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        int64_t s;
        if (JS_ToBigInt64(ctx, &s, argv[1])) {
            return JS_EXCEPTION;
        }
        seed = (uint64_t)s;
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    return JS_NewBigUint64(ctx, wyhash(data, len, seed));
}

static JSValue tjs_hash_murmur2_32(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
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
    return JS_NewUint32(ctx, murmur2_32(data, len, seed));
}

static JSValue tjs_hash_murmur2_64(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    uint64_t seed = 0;
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        int64_t s;
        if (JS_ToBigInt64(ctx, &s, argv[1])) {
            return JS_EXCEPTION;
        }
        seed = (uint64_t)s;
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    return JS_NewBigUint64(ctx, murmur2_64(data, len, seed));
}

static JSValue tjs_hash_cityhash32(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    return JS_NewUint32(ctx, cityHash32(data, len));
}

static JSValue tjs_hash_cityhash64(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    uint64_t seed = 0;
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        int64_t s;
        if (JS_ToBigInt64(ctx, &s, argv[1])) {
            return JS_EXCEPTION;
        }
        seed = (uint64_t)s;
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    return JS_NewBigUint64(ctx, cityHash64WithSeed(data, len, seed));
}

static JSValue tjs_hash_xxhash64(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !tjs_is_uint8_array(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected Uint8Array");
    }
    uint64_t seed = 0;
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        int64_t s;
        if (JS_ToBigInt64(ctx, &s, argv[1])) {
            return JS_EXCEPTION;
        }
        seed = (uint64_t)s;
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    return JS_NewBigUint64(ctx, xxHash64(data, len, seed));
}

static const JSCFunctionListEntry tjs_algorithm_funcs[] = {
	TJS_CFUNC_DEF("wsMask", 2, tjs_ws_mask),
	TJS_CFUNC_DEF("wsMaskInto", 4, tjs_ws_mask_into),
	TJS_CFUNC_DEF("bytesCompare", 2, tjs_bytes_compare),
	TJS_CFUNC_DEF("bytesEqual", 2, tjs_bytes_equal),
	TJS_CFUNC_DEF("bytesIsAscii", 1, tjs_bytes_is_ascii),
	TJS_CFUNC_DEF("bytesIsUtf8", 1, tjs_bytes_is_utf8),
	TJS_CFUNC_DEF("bytesInvert", 1, tjs_bytes_invert),
	TJS_CFUNC_DEF("bytesReverse", 1, tjs_bytes_reverse),
	TJS_CFUNC_DEF("base64DecodeLoose", 1, tjs_base64_decode_loose),
	TJS_CFUNC_DEF("hexDecodeLoose", 1, tjs_hex_decode_loose),
	TJS_CFUNC_DEF("asciiEncodeLoose", 1, tjs_ascii_encode_loose),
	TJS_CFUNC_DEF("latin1EncodeLoose", 1, tjs_latin1_encode_loose),
	TJS_CFUNC_DEF("asciiEncodeReplace", 1, tjs_ascii_encode_replace),
	TJS_CFUNC_DEF("latin1EncodeReplace", 1, tjs_latin1_encode_replace),
	TJS_CFUNC_DEF("asciiDecodeLoose", 1, tjs_ascii_decode_loose),
	TJS_CFUNC_DEF("latin1DecodeLoose", 1, tjs_latin1_decode_loose),
	TJS_CFUNC_DEF("base64UrlEncode", 1, tjs_base64_url_encode),
	TJS_CFUNC_DEF("sourceMapMappingsEncode", 2, tjs_source_map_mappings_encode),
	TJS_CFUNC_DEF("bytesFromArrayLike", 1, tjs_bytes_from_array_like),
	TJS_CFUNC_DEF("bytesConcat", 1, tjs_bytes_concat),
	TJS_CFUNC_DEF("bytesRepeatInto", 4, tjs_bytes_repeat_into),
	TJS_CFUNC_DEF("bytesSwap16", 1, tjs_bytes_swap16),
	TJS_CFUNC_DEF("bytesSwap32", 1, tjs_bytes_swap32),
	TJS_CFUNC_DEF("bytesSwap64", 1, tjs_bytes_swap64),
	TJS_CFUNC_DEF("bytesIndexOf", 3, tjs_bytes_index_of),
	TJS_CFUNC_DEF("bytesLastIndexOf", 3, tjs_bytes_last_index_of),
    TJS_CFUNC_DEF("fnv1a32", 1, tjs_hash_fnv1a32),
    TJS_CFUNC_DEF("fnv1a64", 1, tjs_hash_fnv1a64),
    TJS_CFUNC_DEF("murmur3", 2, tjs_hash_murmur3),
    TJS_CFUNC_DEF("murmur32v2", 2, tjs_hash_murmur2_32),
    TJS_CFUNC_DEF("murmur64v2", 2, tjs_hash_murmur2_64),
    TJS_CFUNC_DEF("xxHash32", 2, tjs_hash_xxhash32),
    TJS_CFUNC_DEF("xxHash64", 2, tjs_hash_xxhash64),
    TJS_CFUNC_DEF("wyhash", 2, tjs_hash_wyhash),
    TJS_CFUNC_DEF("cityHash32", 1, tjs_hash_cityhash32),
    TJS_CFUNC_DEF("cityHash64", 2, tjs_hash_cityhash64),
};

void tjs__mod_algorithm_init(JSContext* ctx, JSValue ns){
	JS_SetPropertyFunctionList(ctx, ns, tjs_algorithm_funcs, countof(tjs_algorithm_funcs));

	JSValue xoshiro_obj = xoshiro_init(ctx);
	JS_SetPropertyStr(ctx, ns, "XoshiroRNG", xoshiro_obj);
}
