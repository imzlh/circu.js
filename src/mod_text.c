/*
 * txiki.js Text Module - libiconv wrapper
 *
 * Copyright (c) 2025-2026 iz <himzlh@163.com>
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
#include <iconv.h>
#include <errno.h>
#include <string.h>

#ifdef _WIN32
#include <ctype.h>
// Windows doesn't have strings.h, use _stricmp instead of strcasecmp
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#include "private.h"
#include "tjs.h"

/* Encoding conversion constants */
#define INITIAL_BUFFER_SIZE 1024
#define BUFFER_GROWTH_RATE  1.5
#define MAX_PENDING_BUFFER  16  // Max bytes for incomplete sequences (UTF-32 max)

/*
 * TextDecoder instance state
 * 
 * Web API: https://encoding.spec.whatwg.org/#textdecoder
 */
typedef struct {
    JSContext *ctx;
    iconv_t cd;                    // iconv conversion descriptor
    char *encoding;                // Normalized encoding name
    bool fatal;                    // Throw on encoding errors
    bool ignore_bom;               // Skip BOM detection
    
    // Streaming support: buffer for incomplete multi-byte sequences
    uint8_t pending[MAX_PENDING_BUFFER];
    size_t pending_len;
} decoder_t;

/*
 * TextEncoder instance state
 * 
 * Web API: https://encoding.spec.whatwg.org/#textencoder
 * 
 * Note: Web standard requires UTF-8 only, but we keep internal
 * encoding support via iconv for potential extended usage.
 */
typedef struct {
    JSContext *ctx;
    iconv_t cd;                    // Always UTF-8 in standard mode
    char *encoding;
} encoder_t;

/* Class IDs for QuickJS finalizers */
static JSClassID tjs_text_decoder_class_id;
static JSClassID tjs_text_encoder_class_id;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/*
 * Detect and return BOM length for common Unicode encodings.
 * Returns number of bytes to skip (0 if no BOM or ignored).
 */
static size_t detect_bom_skip(const uint8_t *data, size_t len, const char *encoding, bool ignore_bom) {
    if (!data || len == 0 || ignore_bom) return 0;
    
    // UTF-8: EF BB BF
    if (strcasecmp(encoding, "UTF-8") == 0 && len >= 3) {
        if (data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            return 3;
    }
    // UTF-16 BE: FE FF
    else if (strcasecmp(encoding, "UTF-16BE") == 0 && len >= 2) {
        if (data[0] == 0xFE && data[1] == 0xFF)
            return 2;
    }
    // UTF-16 LE: FF FE
    else if (strcasecmp(encoding, "UTF-16LE") == 0 && len >= 2) {
        if (data[0] == 0xFF && data[1] == 0xFE)
            return 2;
    }
    // UTF-32 BE: 00 00 FE FF
    else if (strcasecmp(encoding, "UTF-32BE") == 0 && len >= 4) {
        if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0xFE && data[3] == 0xFF)
            return 4;
    }
    // UTF-32 LE: FF FE 00 00
    else if (strcasecmp(encoding, "UTF-32LE") == 0 && len >= 4) {
        if (data[0] == 0xFF && data[1] == 0xFE && data[2] == 0x00 && data[3] == 0x00)
            return 4;
    }
    
    return 0;
}

/*
 * Convert encoding name to canonical form for comparison.
 * Handles common aliases and normalizes case.
 */
static const char* normalize_encoding_name(const char *enc) {
    if (!enc) return "utf-8";
    
    // Common aliases mapping
    if (strcasecmp(enc, "utf8") == 0) return "UTF-8";
    if (strcasecmp(enc, "utf-16") == 0) return "UTF-16LE"; // Platform default usually LE
    if (strcasecmp(enc, "utf-32") == 0) return "UTF-32LE";
    
    return enc;
}

/*
 * Perform iconv conversion with dynamic buffer growth.
 * Note: Handles E2BIG (buffer growth), EILSEQ/EINVAL (replacement or error)
 */
static int perform_iconv_conversion(JSContext *ctx, iconv_t cd,
                                    const char *inbuf, size_t inlen,
                                    bool fatal, bool is_to_utf8,
                                    JSValue *out_result) {
    size_t outbuf_size = INITIAL_BUFFER_SIZE;
    char *outbuf = js_malloc(ctx, outbuf_size);
    if (!outbuf) {
        JS_ThrowOutOfMemory(ctx);
        return -1;
    }
    
    char *inptr = (char *)inbuf;
    char *outptr = outbuf;
    size_t inleft = inlen;
    size_t outleft = outbuf_size;
    
    while (inleft > 0) {
        size_t ret = iconv(cd, &inptr, &inleft, &outptr, &outleft);
        
        if (ret == (size_t)-1) {
            switch (errno) {
                case E2BIG: {
                    // Output buffer full - grow it
                    size_t used = outptr - outbuf;
                    size_t new_size = (size_t)(outbuf_size * BUFFER_GROWTH_RATE);
                    if (new_size == outbuf_size) new_size += INITIAL_BUFFER_SIZE;
                    
                    char *new_buf = js_realloc(ctx, outbuf, new_size);
                    if (!new_buf) {
                        js_free(ctx, outbuf);
                        JS_ThrowOutOfMemory(ctx);
                        return -1;
                    }
                    
                    outbuf = new_buf;
                    outptr = outbuf + used;
                    outleft = new_size - used;
                    outbuf_size = new_size;
                    break;
                }
                    
                case EILSEQ:  // Invalid byte sequence in input
                case EINVAL: { // Incomplete byte sequence at end of input
                    if (fatal) {
                        js_free(ctx, outbuf);
                        JS_ThrowTypeError(ctx, "The encoded data was not valid for encoding %s", 
                                         is_to_utf8 ? "UTF-8" : "target");
                        return -1;
                    }
                    
                    // Skip invalid byte
                    if (inleft > 0) {
                        inptr++;
                        inleft--;
                        
                        // Insert replacement character only if converting to UTF-8
                        // For non-UTF-8 targets, we skip without replacement (best effort)
                        if (is_to_utf8 && outleft >= 3) {
                            // U+FFFD in UTF-8: EF BF BD
                            *outptr++ = (char)0xEF;
                            *outptr++ = (char)0xBF;
                            *outptr++ = (char)0xBD;
                            outleft -= 3;
                        } else if (!is_to_utf8 && outleft >= 1) {
                            // For byte output, use '?' as replacement
                            *outptr++ = '?';
                            outleft--;
                        }
                    }
                    break;
                }
                    
                default:
                    js_free(ctx, outbuf);
                    JS_ThrowTypeError(ctx, "Encoding conversion error: %s", strerror(errno));
                    return -1;
            }
        }
    }
    
    // Calculate actual output size
    size_t total_out = outptr - outbuf;
    
    // Create result based on output type
    if (is_to_utf8) {
        *out_result = JS_NewStringLen(ctx, outbuf, total_out);
    } else {
        *out_result = JS_NewUint8ArrayCopy(ctx, (uint8_t *)outbuf, total_out);
    }
    
    js_free(ctx, outbuf);
    return JS_IsException(*out_result) ? -1 : 0;
}

static void tjs_text_decoder_finalizer(JSRuntime *rt, JSValue val) {
    decoder_t *dec = JS_GetOpaque(val, tjs_text_decoder_class_id);
    if (!dec) return;
    
    if (dec->cd != (iconv_t)-1) {
        iconv_close(dec->cd);
    }
    if (dec->encoding) {
        js_free_rt(rt, dec->encoding);
    }
    js_free_rt(rt, dec);
}

static JSClassDef tjs_text_decoder_class = {
    "TextDecoder",
    .finalizer = tjs_text_decoder_finalizer,
};

/*
 * TextDecoder constructor(utfLabel, options)
 * Web API: new TextDecoder([utfLabel [, options]])
 */
static JSValue tjs_text_decoder_constructor(JSContext *ctx, JSValueConst new_target,
                                            int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_text_decoder_class_id);
    if (JS_IsException(obj)) return obj;
    
    decoder_t *dec = js_mallocz(ctx, sizeof(*dec));
    if (!dec) goto fail_obj;
    
    dec->ctx = ctx;
    dec->cd = (iconv_t)-1;
    dec->pending_len = 0;
    
    // Parse encoding label (defaults to "utf-8")
    const char *label = argc > 0 ? JS_ToCString(ctx, argv[0]) : "utf-8";
    if (!label) goto fail_dec;
    
    dec->encoding = js_strdup(ctx, normalize_encoding_name(label));
    if (argc > 0) JS_FreeCString(ctx, label);
    if (!dec->encoding) goto fail_dec;
    
    // Parse options: {fatal: bool, ignoreBOM: bool}
    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue fatal_val = JS_GetPropertyStr(ctx, argv[1], "fatal");
        JSValue ignore_bom_val = JS_GetPropertyStr(ctx, argv[1], "ignoreBOM");
        
        dec->fatal = JS_ToBool(ctx, fatal_val);
        dec->ignore_bom = JS_ToBool(ctx, ignore_bom_val);
        
        JS_FreeValue(ctx, fatal_val);
        JS_FreeValue(ctx, ignore_bom_val);
    }
    
    // Initialize iconv for decoding (from encoding to UTF-8)
    dec->cd = iconv_open("UTF-8", dec->encoding);
    if (dec->cd == (iconv_t)-1) {
        JS_ThrowTypeError(ctx, "Unsupported encoding: %s", dec->encoding);
        goto fail_encoding;
    }
    
    JS_SetOpaque(obj, dec);
    return obj;
    
fail_encoding:
    js_free(ctx, dec->encoding);
fail_dec:
    js_free(ctx, dec);
fail_obj:
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}

/*
 * Decode input buffer with streaming support.
 */
static JSValue tjs_text_decoder_decode(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec) return JS_EXCEPTION;
    
    // Extract input buffer (ArrayBuffer or TypedArray)
    size_t inlen = 0;
    uint8_t *inbuf = NULL;
    JSValue buffer_val = JS_UNDEFINED;
    
    if (argc > 0 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        inbuf = JS_GetAnyBuffer(ctx, &inlen, argv[0]);
        if (!inbuf) {
            return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer or ArrayBufferView");
        }
    }
    
    // If no input, process any pending bytes or return empty string
    if (!inbuf || inlen == 0) {
        JS_FreeValue(ctx, buffer_val);
        
        // Check for stream option
        bool stream = false;
        if (argc > 1 && JS_IsObject(argv[1])) {
            JSValue stream_val = JS_GetPropertyStr(ctx, argv[1], "stream");
            stream = JS_ToBool(ctx, stream_val);
            JS_FreeValue(ctx, stream_val);
        }
        
        if (!stream && dec->pending_len > 0) {
            // Flush pending buffer: either error or ignore based on fatal
            if (dec->fatal) {
                dec->pending_len = 0; // Clear state
                return JS_ThrowTypeError(ctx, "Incomplete character sequence at end of stream");
            }
            dec->pending_len = 0;
        }
        
        return JS_NewString(ctx, "");
    }
    
    // Parse options
    bool stream = false;
    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue stream_val = JS_GetPropertyStr(ctx, argv[1], "stream");
        stream = JS_ToBool(ctx, stream_val);
        JS_FreeValue(ctx, stream_val);
    }
    
    // Handle BOM detection (only on first call or if not streaming)
    size_t bom_skip = 0;
    if (dec->pending_len == 0) { // First chunk or non-streaming
        bom_skip = detect_bom_skip(inbuf, inlen, dec->encoding, dec->ignore_bom);
    }
    
    // Calculate total input size including pending bytes
    size_t total_inlen = dec->pending_len + (inlen - bom_skip);
    char *total_input = NULL;
    bool need_free_input = false;
    
    if (dec->pending_len > 0) {
        // Merge pending + new data
        total_input = js_malloc(ctx, total_inlen);
        if (!total_input) {
            JS_FreeValue(ctx, buffer_val);
            return JS_EXCEPTION;
        }
        memcpy(total_input, dec->pending, dec->pending_len);
        memcpy(total_input + dec->pending_len, inbuf + bom_skip, inlen - bom_skip);
        need_free_input = true;
    } else {
        // Use input directly (skip BOM)
        total_input = (char *)(inbuf + bom_skip);
    }
    
    // Reset iconv state if not streaming (Web API requirement)
    if (!stream) {
        iconv(dec->cd, NULL, NULL, NULL, NULL);
    }
    
    // Perform conversion
    JSValue result;
    char *inptr = total_input;
    size_t inleft = total_inlen;
    size_t outbuf_size = INITIAL_BUFFER_SIZE;
    char *outbuf = js_malloc(ctx, outbuf_size);
    
    if (!outbuf) {
        if (need_free_input) js_free(ctx, total_input);
        JS_FreeValue(ctx, buffer_val);
        return JS_EXCEPTION;
    }
    
    char *outptr = outbuf;
    size_t outleft = outbuf_size;
    int conversion_status = 0; // 0=success, 1=incomplete, 2=error
    
    while (inleft > 0) {
        size_t ret = iconv(dec->cd, &inptr, &inleft, &outptr, &outleft);
        
        if (ret == (size_t)-1) {
            if (errno == E2BIG) {
                // Grow output buffer
                size_t used = outptr - outbuf;
                size_t new_size = (size_t)(outbuf_size * BUFFER_GROWTH_RATE);
                if (new_size == outbuf_size) new_size += INITIAL_BUFFER_SIZE;
                
                char *new_buf = js_realloc(ctx, outbuf, new_size);
                if (!new_buf) {
                    js_free(ctx, outbuf);
                    if (need_free_input) js_free(ctx, total_input);
                    JS_FreeValue(ctx, buffer_val);
                    return JS_EXCEPTION;
                }
                outbuf = new_buf;
                outptr = outbuf + used;
                outleft = new_size - used;
                outbuf_size = new_size;
            } else if (errno == EINVAL) {
                // Incomplete sequence at end
                if (stream && inleft <= MAX_PENDING_BUFFER) {
                    // Save to pending for next call
                    memcpy(dec->pending, inptr, inleft);
                    dec->pending_len = inleft;
                    inleft = 0; // Mark as consumed
                    conversion_status = 1;
                } else {
                    // Non-streaming or too big for pending
                    if (dec->fatal) {
                        conversion_status = 2;
                        break;
                    }
                    // Skip byte and continue with replacement
                    inptr++;
                    inleft--;
                    if (outleft >= 3) {
                        *outptr++ = (char)0xEF;
                        *outptr++ = (char)0xBF;
                        *outptr++ = (char)0xBD;
                        outleft -= 3;
                    }
                }
            } else if (errno == EILSEQ) {
                // Invalid sequence
                if (dec->fatal) {
                    conversion_status = 2;
                    break;
                }
                inptr++;
                inleft--;
                if (outleft >= 3) {
                    *outptr++ = (char)0xEF;
                    *outptr++ = (char)0xBF;
                    *outptr++ = (char)0xBD;
                    outleft -= 3;
                }
            } else {
                conversion_status = 2;
                break;
            }
        }
    }
    
    // Cleanup input buffer if we allocated it
    if (need_free_input) js_free(ctx, total_input);
    JS_FreeValue(ctx, buffer_val);
    
    // Handle conversion status
    if (conversion_status == 2) {
        js_free(ctx, outbuf);
        if (errno == EINVAL || errno == EILSEQ) {
            return JS_ThrowTypeError(ctx, "Invalid encoded data");
        }
        return JS_ThrowTypeError(ctx, "Decoding error: %s", strerror(errno));
    }
    
    // If non-streaming, clear any pending state (shouldn't happen, but safety)
    if (!stream) {
        dec->pending_len = 0;
    }
    
    // Create result string
    size_t outlen = outptr - outbuf;
    result = JS_NewStringLen(ctx, outbuf, outlen);
    js_free(ctx, outbuf);
    
    return result;
}

/* Getter: decoder.encoding */
static JSValue tjs_text_decoder_get_encoding(JSContext *ctx, JSValueConst this_val) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec) return JS_EXCEPTION;
    return JS_NewString(ctx, dec->encoding);
}

/* Getter: decoder.fatal */
static JSValue tjs_text_decoder_get_fatal(JSContext *ctx, JSValueConst this_val) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec) return JS_EXCEPTION;
    return JS_NewBool(ctx, dec->fatal);
}

/* Getter: decoder.ignoreBOM */
static JSValue tjs_text_decoder_get_ignore_bom(JSContext *ctx, JSValueConst this_val) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec) return JS_EXCEPTION;
    return JS_NewBool(ctx, dec->ignore_bom);
}

static const JSCFunctionListEntry tjs_text_decoder_proto_funcs[] = {
    JS_CFUNC_DEF("decode", 2, tjs_text_decoder_decode),
    JS_CGETSET_DEF("encoding", tjs_text_decoder_get_encoding, NULL),
    JS_CGETSET_DEF("fatal", tjs_text_decoder_get_fatal, NULL),
    JS_CGETSET_DEF("ignoreBOM", tjs_text_decoder_get_ignore_bom, NULL),
};

static void tjs_text_encoder_finalizer(JSRuntime *rt, JSValue val) {
    encoder_t *enc = JS_GetOpaque(val, tjs_text_encoder_class_id);
    if (!enc) return;
    
    if (enc->cd != (iconv_t)-1) {
        iconv_close(enc->cd);
    }
    if (enc->encoding) {
        js_free_rt(rt, enc->encoding);
    }
    js_free_rt(rt, enc);
}

static JSClassDef tjs_text_encoder_class = {
    "TextEncoder",
    .finalizer = tjs_text_encoder_finalizer,
};

/*
 * TextEncoder constructor()
 * 
 * Web API: new TextEncoder()
 * Note: Web standard only supports UTF-8. We accept an optional encoding
 * parameter for extended usage, but default to UTF-8.
 */
static JSValue tjs_text_encoder_constructor(JSContext *ctx, JSValueConst new_target,
                                            int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_text_encoder_class_id);
    if (JS_IsException(obj)) return obj;
    
    encoder_t *enc = js_mallocz(ctx, sizeof(*enc));
    if (!enc) goto fail_obj;
    
    enc->ctx = ctx;
    enc->cd = (iconv_t)-1;
    
    // Parse encoding (defaults to utf-8, standard Web API behavior)
    const char *label = argc > 0 ? JS_ToCString(ctx, argv[0]) : "utf-8";
    if (!label) goto fail_enc;
    
    enc->encoding = js_strdup(ctx, normalize_encoding_name(label));
    if (argc > 0) JS_FreeCString(ctx, label);
    if (!enc->encoding) goto fail_enc;
    
    // Initialize iconv (UTF-8 to target encoding)
    enc->cd = iconv_open(enc->encoding, "UTF-8");
    if (enc->cd == (iconv_t)-1) {
        JS_ThrowTypeError(ctx, "Unsupported encoding for TextEncoder: %s", enc->encoding);
        goto fail_encoding;
    }
    
    JS_SetOpaque(obj, enc);
    return obj;
    
fail_encoding:
    js_free(ctx, enc->encoding);
fail_enc:
    js_free(ctx, enc);
fail_obj:
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}

/*
 * encoder.encode(string)
 * Returns: Uint8Array
 */
static JSValue tjs_text_encoder_encode(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    encoder_t *enc = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!enc) return JS_EXCEPTION;
    
    size_t str_len;
    const char *str = JS_ToCStringLen(ctx, &str_len, argv[0]);
    if (!str) return JS_EXCEPTION;
    
    // Reset iconv state
    iconv(enc->cd, NULL, NULL, NULL, NULL);
    
    JSValue result;
    int ret = perform_iconv_conversion(ctx, enc->cd, str, str_len, 
                                       true, false, &result);
    JS_FreeCString(ctx, str);
    
    return ret == 0 ? result : JS_EXCEPTION;
}

/*
 * encoder.encodeInto(string, uint8Array)
 * Returns: {read: number, written: number}
 * 
 * Web API encodes as much as possible into the provided buffer without
 * overflow. Returns counts of source chars read and bytes written.
 */
static JSValue tjs_text_encoder_encode_into(JSContext *ctx, JSValueConst this_val,
                                            int argc, JSValueConst *argv) {
    encoder_t *enc = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!enc) return JS_EXCEPTION;
    
    // Get source string
    size_t str_len;
    const char *str = JS_ToCStringLen(ctx, &str_len, argv[0]);
    if (!str) return JS_EXCEPTION;
    
    // Get destination buffer (TypedArray or ArrayBuffer)
    size_t buf_len;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &buf_len, argv[1]);
    JSValue buf_holder = JS_UNDEFINED;
    
    if (!buf) {
        return JS_ThrowTypeError(ctx, "Second argument must be an ArrayBufferView");
    }
    
    if (!buf) {
        JS_FreeCString(ctx, str);
        JS_FreeValue(ctx, buf_holder);
        return JS_EXCEPTION;
    }
    
    // Reset iconv state
    iconv(enc->cd, NULL, NULL, NULL, NULL);
    
    // Perform conversion directly into user buffer
    char *inptr = (char *)str;
    char *outptr = (char *)buf;
    size_t inleft = str_len;
    size_t outleft = buf_len;
    size_t read = 0;
    size_t written = 0;
    bool error = false;
    
    while (inleft > 0 && outleft > 0) {
        size_t ret = iconv(enc->cd, &inptr, &inleft, &outptr, &outleft);
        
        if (ret == (size_t)-1) {
            if (errno == E2BIG) {
                // Output buffer full - this is expected, stop here
                break;
            } else if (errno == EILSEQ || errno == EINVAL) {
                // Invalid input sequence - skip and continue
                inptr++;
                inleft--;
                if (outleft > 0) {
                    *outptr++ = '?';
                    outleft--;
                }
            } else {
                error = true;
                break;
            }
        }
    }
    
    read = str_len - inleft;
    written = buf_len - outleft;
    
    JS_FreeCString(ctx, str);
    JS_FreeValue(ctx, buf_holder);
    
    if (error) {
        return JS_ThrowTypeError(ctx, "Encoding conversion failed: %s", strerror(errno));
    }
    
    // Return result object {read, written}
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "read", JS_NewInt64(ctx, read));
    JS_SetPropertyStr(ctx, result, "written", JS_NewInt64(ctx, written));
    
    return result;
}

/* Getter: encoder.encoding (Web API requires "utf-8") */
static JSValue tjs_text_encoder_get_encoding(JSContext *ctx, JSValueConst this_val) {
    encoder_t *enc = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!enc) return JS_EXCEPTION;
    // Per Web API spec, TextEncoder always reports "utf-8"
    return JS_NewString(ctx, "utf-8");
}

static const JSCFunctionListEntry tjs_text_encoder_proto_funcs[] = {
    JS_CFUNC_DEF("encode", 1, tjs_text_encoder_encode),
    JS_CFUNC_DEF("encodeInto", 2, tjs_text_encoder_encode_into),
    JS_CGETSET_DEF("encoding", tjs_text_encoder_get_encoding, NULL),
};

/*
 * Convert data between arbitrary encodings.
 */
static JSValue tjs_text_convert(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "convert requires 3 arguments: from, to, data");
    }
    
    const char *from = JS_ToCString(ctx, argv[0]);
    const char *to = JS_ToCString(ctx, argv[1]);
    if (!from || !to) {
        if (from) JS_FreeCString(ctx, from);
        if (to) JS_FreeCString(ctx, to);
        return JS_EXCEPTION;
    }
    
    iconv_t cd = iconv_open(to, from);
    if (cd == (iconv_t)-1) {
        /* format the error first — from/to are about to be freed */
        JSValue err = JS_ThrowTypeError(ctx, "Conversion from %s to %s not supported", from, to);
        JS_FreeCString(ctx, from);
        JS_FreeCString(ctx, to);
        return err;
    }
    
    // Extract input data
    size_t inlen;
    uint8_t *inbuf = NULL;
    JSValue buf_holder = JS_UNDEFINED;
    
    inbuf = JS_GetAnyBuffer(ctx, &inlen, argv[2]);
    if (!inbuf) {
        return JS_ThrowTypeError(ctx, "Third argument must be an ArrayBufferView");
    }
    
    if (!inbuf) {
        iconv_close(cd);
        JS_FreeCString(ctx, from);
        JS_FreeCString(ctx, to);
        JS_FreeValue(ctx, buf_holder);
        return JS_EXCEPTION;
    }
    
    bool is_to_utf8 = (strcasecmp(to, "UTF-8") == 0);
    JSValue result;
    int ret = perform_iconv_conversion(ctx, cd, (char *)inbuf, inlen, 
                                       false, is_to_utf8, &result);
    
    iconv_close(cd);
    JS_FreeCString(ctx, from);
    JS_FreeCString(ctx, to);
    JS_FreeValue(ctx, buf_holder);
    
    return ret == 0 ? result : JS_EXCEPTION;
}

/*
 * Return list of commonly supported encodings.
 * Note: Actual availability depends on system iconv implementation.
 */
static JSValue tjs_text_list_encodings(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    static const char *encodings[] = {
        "UTF-8",
        "UTF-16LE", "UTF-16BE",
        "UTF-32LE", "UTF-32BE",
        "ASCII", "ISO-8859-1", "ISO-8859-15",
        "Windows-1252", "Windows-1251",
        "GBK", "GB18030", "Big5",
        "EUC-JP", "Shift_JIS", "ISO-2022-JP",
        "EUC-KR",
        "KOI8-R", "KOI8-U",
        "macintosh",
        "IBM866"
    };
    
    JSValue arr = JS_NewArray(ctx);
    if (JS_IsException(arr)) return arr;
    
    for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); i++) {
        JSValue str = JS_NewString(ctx, encodings[i]);
        if (JS_IsException(str)) {
            JS_FreeValue(ctx, arr);
            return JS_EXCEPTION;
        }
        JS_SetPropertyUint32(ctx, arr, i, str);
    }
    
    return arr;
}

static const JSCFunctionListEntry tjs_text_funcs[] = {
    JS_CFUNC_DEF("convert", 3, tjs_text_convert),
    JS_CFUNC_DEF("listEncodings", 0, tjs_text_list_encodings),
};

void tjs__mod_text_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    
    /* Register TextDecoder */
    JS_NewClassID(rt, &tjs_text_decoder_class_id);
    JS_NewClass(rt, tjs_text_decoder_class_id, &tjs_text_decoder_class);
    
    JSValue decoder_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, decoder_proto, tjs_text_decoder_proto_funcs,
                               sizeof(tjs_text_decoder_proto_funcs) / sizeof(JSCFunctionListEntry));
    JS_SetClassProto(ctx, tjs_text_decoder_class_id, decoder_proto);
    
    JSValue decoder_ctor = JS_NewCFunction2(ctx, tjs_text_decoder_constructor,
                                            "TextDecoder", 2,
                                            JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, decoder_ctor, decoder_proto);
    JS_SetPropertyStr(ctx, ns, "Decoder", decoder_ctor);
    
    /* Register TextEncoder */
    JS_NewClassID(rt, &tjs_text_encoder_class_id);
    JS_NewClass(rt, tjs_text_encoder_class_id, &tjs_text_encoder_class);
    
    JSValue encoder_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, encoder_proto, tjs_text_encoder_proto_funcs,
                               sizeof(tjs_text_encoder_proto_funcs) / sizeof(JSCFunctionListEntry));
    JS_SetClassProto(ctx, tjs_text_encoder_class_id, encoder_proto);
    
    JSValue encoder_ctor = JS_NewCFunction2(ctx, tjs_text_encoder_constructor,
                                            "TextEncoder", 1,
                                            JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, encoder_ctor, encoder_proto);
    JS_SetPropertyStr(ctx, ns, "Encoder", encoder_ctor);
    
    /* Register utility functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_text_funcs,
                               sizeof(tjs_text_funcs) / sizeof(JSCFunctionListEntry));
}