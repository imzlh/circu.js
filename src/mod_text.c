/*
 * txiki.js Text Module - libiconv wrapper
 * Requires: libiconv-dev
 */

#include "private.h"
#include "tjs.h"
#include <iconv.h>
#include <errno.h>
#include <string.h>

/* Macro for iconv error handling */
#define ICONV_ERROR_CHECK(ctx, cd, operation) do { \
    if ((cd) == (iconv_t)-1) { \
        return JS_ThrowTypeError(ctx, "iconv error: %s - %s", \
                                operation, strerror(errno)); \
    } \
} while(0)

/* Macro for buffer growth strategy */
#define BUFFER_GROW_SIZE 4096
#define INITIAL_BUFFER_SIZE 1024

/* Macro for safe buffer reallocation */
#define SAFE_REALLOC(ctx, ptr, old_size, new_size) ({ \
    void *_new_ptr = js_realloc(ctx, ptr, new_size); \
    if (!_new_ptr && (new_size) > 0) { \
        js_free(ctx, ptr); \
        JS_ThrowOutOfMemory(ctx); \
    } \
    _new_ptr; \
})

/* TextDecoder state */
typedef struct {
    JSContext *ctx;
    iconv_t cd;
    char *encoding;
    bool fatal;
    bool ignore_bom;
} TJSTextDecoder;

/* TextEncoder state */
typedef struct {
    JSContext *ctx;
    iconv_t cd;
    char *encoding;
} TJSTextEncoder;

/* Helper: Detect and skip BOM */
static size_t skip_bom(const uint8_t *data, size_t len, const char *encoding) {
    if (!data || len < 2) return 0;
    
    /* UTF-8 BOM: EF BB BF */
    if (strcasecmp(encoding, "UTF-8") == 0 && len >= 3) {
        if (data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
            return 3;
        }
    }
    /* UTF-16 BE BOM: FE FF */
    else if (strcasecmp(encoding, "UTF-16BE") == 0 && len >= 2) {
        if (data[0] == 0xFE && data[1] == 0xFF) {
            return 2;
        }
    }
    /* UTF-16 LE BOM: FF FE */
    else if (strcasecmp(encoding, "UTF-16LE") == 0 && len >= 2) {
        if (data[0] == 0xFF && data[1] == 0xFE) {
            return 2;
        }
    }
    /* UTF-32 BE BOM: 00 00 FE FF */
    else if (strcasecmp(encoding, "UTF-32BE") == 0 && len >= 4) {
        if (data[0] == 0x00 && data[1] == 0x00 && 
            data[2] == 0xFE && data[3] == 0xFF) {
            return 4;
        }
    }
    /* UTF-32 LE BOM: FF FE 00 00 */
    else if (strcasecmp(encoding, "UTF-32LE") == 0 && len >= 4) {
        if (data[0] == 0xFF && data[1] == 0xFE && 
            data[2] == 0x00 && data[3] == 0x00) {
            return 4;
        }
    }
    
    return 0;
}

/* Helper: Perform iconv conversion with dynamic buffer */
static JSValue iconv_convert(JSContext *ctx, iconv_t cd, 
                             const char *inbuf, size_t inlen,
                             bool fatal, bool is_to_utf8) {
    size_t outsize = INITIAL_BUFFER_SIZE;
    char *outbuf = js_malloc(ctx, outsize);
    if (!outbuf) return JS_EXCEPTION;
    
    char *inptr = (char *)inbuf;
    char *outptr = outbuf;
    size_t inleft = inlen;
    size_t outleft = outsize;
    size_t total_written = 0;
    
    while (inleft > 0) {
        size_t ret = iconv(cd, &inptr, &inleft, &outptr, &outleft);
        
        if (ret == (size_t)-1) {
            if (errno == E2BIG) {
                /* Need more output space */
                size_t written = outptr - outbuf;
                total_written += written;
                outsize += BUFFER_GROW_SIZE;
                outbuf = SAFE_REALLOC(ctx, outbuf, outsize - BUFFER_GROW_SIZE, outsize);
                if (!outbuf) return JS_EXCEPTION;
                outptr = outbuf + total_written;
                outleft = outsize - total_written;
            } else if (errno == EILSEQ || errno == EINVAL) {
                if (fatal) {
                    js_free(ctx, outbuf);
                    return JS_ThrowTypeError(ctx, "Invalid byte sequence in conversion");
                }
                /* Skip invalid byte and insert replacement character */
                if (inleft > 0) {
                    inptr++;
                    inleft--;
                    /* Insert UTF-8 replacement character U+FFFD if converting to UTF-8 */
                    if (is_to_utf8 && outleft >= 3) {
                        *outptr++ = 0xEF;
                        *outptr++ = 0xBF;
                        *outptr++ = 0xBD;
                        outleft -= 3;
                    } else if (outleft >= 1) {
                        *outptr++ = '?';
                        outleft--;
                    }
                }
            } else {
                js_free(ctx, outbuf);
                return JS_ThrowTypeError(ctx, "iconv conversion error: %s", strerror(errno));
            }
        }
    }
    
    total_written += (outptr - outbuf);
    
    if (is_to_utf8) {
        JSValue result = JS_NewStringLen(ctx, outbuf, total_written);
        js_free(ctx, outbuf);
        return result;
    } else {
        JSValue result = JS_NewArrayBufferCopy(ctx, (const uint8_t *)outbuf, total_written);
        js_free(ctx, outbuf);
        return result;
    }
}

#pragma region TextDecoder

static JSClassID tjs_text_decoder_class_id;

static void tjs_text_decoder_finalizer(JSRuntime *rt, JSValue val) {
    TJSTextDecoder *decoder = JS_GetOpaque(val, tjs_text_decoder_class_id);
    if (decoder) {
        if (decoder->cd != (iconv_t)-1) {
            iconv_close(decoder->cd);
        }
        if (decoder->encoding) {
            js_free_rt(rt, decoder->encoding);
        }
        js_free_rt(rt, decoder);
    }
}

static JSClassDef tjs_text_decoder_class = {
    "TextDecoder",
    .finalizer = tjs_text_decoder_finalizer,
};

/* new TextDecoder(encoding, options) */
static JSValue tjs_text_decoder_constructor(JSContext *ctx, JSValueConst new_target,
                                             int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_text_decoder_class_id);
    if (JS_IsException(obj)) return obj;
    
    TJSTextDecoder *decoder = js_mallocz(ctx, sizeof(*decoder));
    if (!decoder) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    decoder->ctx = ctx;
    decoder->cd = (iconv_t)-1;
    decoder->fatal = false;
    decoder->ignore_bom = false;
    
    /* Parse encoding */
    const char *encoding = argc > 0 ? JS_ToCString(ctx, argv[0]) : "utf-8";
    if (!encoding) {
        js_free(ctx, decoder);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    decoder->encoding = js_strdup(ctx, encoding);
    JS_FreeCString(ctx, encoding);
    
    /* Parse options */
    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue fatal_val = JS_GetPropertyStr(ctx, argv[1], "fatal");
        JSValue ignore_bom_val = JS_GetPropertyStr(ctx, argv[1], "ignoreBOM");
        
        decoder->fatal = JS_ToBool(ctx, fatal_val);
        decoder->ignore_bom = JS_ToBool(ctx, ignore_bom_val);
        
        JS_FreeValue(ctx, fatal_val);
        JS_FreeValue(ctx, ignore_bom_val);
    }
    
    /* Create iconv descriptor */
    decoder->cd = iconv_open("UTF-8", decoder->encoding);
    ICONV_ERROR_CHECK(ctx, decoder->cd, "iconv_open");
    
    JS_SetOpaque(obj, decoder);
    return obj;
}

/* decoder.decode(buffer, options) */
static JSValue tjs_text_decoder_decode(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    TJSTextDecoder *decoder = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!decoder) return JS_EXCEPTION;
    
    /* Get input buffer */
    size_t size;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &size, argv[0]);
    if (!buf) {
        /* Try to get typed array */
        JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[0], NULL, NULL, NULL);
        if (JS_IsException(buffer)) {
            return JS_ThrowTypeError(ctx, "Argument must be ArrayBuffer or TypedArray");
        }
        buf = JS_GetArrayBuffer(ctx, &size, buffer);
        JS_FreeValue(ctx, buffer);
        if (!buf) return JS_EXCEPTION;
    }
    
    /* Handle BOM */
    size_t offset = 0;
    if (!decoder->ignore_bom) {
        offset = skip_bom(buf, size, decoder->encoding);
    }
    
    /* Parse stream option */
    bool stream = false;
    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue stream_val = JS_GetPropertyStr(ctx, argv[1], "stream");
        stream = JS_ToBool(ctx, stream_val);
        JS_FreeValue(ctx, stream_val);
    }
    
    /* Reset decoder if not streaming */
    if (!stream) {
        iconv(decoder->cd, NULL, NULL, NULL, NULL);
    }
    
    /* Convert */
    return iconv_convert(ctx, decoder->cd, 
                        (const char *)(buf + offset), size - offset,
                        decoder->fatal, true);
}

/* Getter: decoder.encoding */
static JSValue tjs_text_decoder_get_encoding(JSContext *ctx, JSValueConst this_val) {
    TJSTextDecoder *decoder = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!decoder) return JS_EXCEPTION;
    return JS_NewString(ctx, decoder->encoding);
}

/* Getter: decoder.fatal */
static JSValue tjs_text_decoder_get_fatal(JSContext *ctx, JSValueConst this_val) {
    TJSTextDecoder *decoder = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!decoder) return JS_EXCEPTION;
    return JS_NewBool(ctx, decoder->fatal);
}

/* Getter: decoder.ignoreBOM */
static JSValue tjs_text_decoder_get_ignore_bom(JSContext *ctx, JSValueConst this_val) {
    TJSTextDecoder *decoder = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!decoder) return JS_EXCEPTION;
    return JS_NewBool(ctx, decoder->ignore_bom);
}

static const JSCFunctionListEntry tjs_text_decoder_proto_funcs[] = {
    JS_CFUNC_DEF("decode", 2, tjs_text_decoder_decode),
    JS_CGETSET_DEF("encoding", tjs_text_decoder_get_encoding, NULL),
    JS_CGETSET_DEF("fatal", tjs_text_decoder_get_fatal, NULL),
    JS_CGETSET_DEF("ignoreBOM", tjs_text_decoder_get_ignore_bom, NULL),
};

#pragma region TextEncoder

static JSClassID tjs_text_encoder_class_id;

static void tjs_text_encoder_finalizer(JSRuntime *rt, JSValue val) {
    TJSTextEncoder *encoder = JS_GetOpaque(val, tjs_text_encoder_class_id);
    if (encoder) {
        if (encoder->cd != (iconv_t)-1) {
            iconv_close(encoder->cd);
        }
        if (encoder->encoding) {
            js_free_rt(rt, encoder->encoding);
        }
        js_free_rt(rt, encoder);
    }
}

static JSClassDef tjs_text_encoder_class = {
    "TextEncoder",
    .finalizer = tjs_text_encoder_finalizer,
};

/* new TextEncoder(encoding) */
static JSValue tjs_text_encoder_constructor(JSContext *ctx, JSValueConst new_target,
                                             int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_text_encoder_class_id);
    if (JS_IsException(obj)) return obj;
    
    TJSTextEncoder *encoder = js_mallocz(ctx, sizeof(*encoder));
    if (!encoder) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    encoder->ctx = ctx;
    encoder->cd = (iconv_t)-1;
    
    /* Parse encoding */
    const char *encoding = argc > 0 ? JS_ToCString(ctx, argv[0]) : "utf-8";
    if (!encoding) {
        js_free(ctx, encoder);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    encoder->encoding = js_strdup(ctx, encoding);
    JS_FreeCString(ctx, encoding);
    
    /* Create iconv descriptor */
    encoder->cd = iconv_open(encoder->encoding, "UTF-8");
    ICONV_ERROR_CHECK(ctx, encoder->cd, "iconv_open");
    
    JS_SetOpaque(obj, encoder);
    return obj;
}

/* encoder.encode(string) */
static JSValue tjs_text_encoder_encode(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    TJSTextEncoder *encoder = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!encoder) return JS_EXCEPTION;
    
    size_t len;
    const char *str = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!str) return JS_EXCEPTION;
    
    /* Reset encoder state */
    iconv(encoder->cd, NULL, NULL, NULL, NULL);
    
    /* Convert */
    JSValue result = iconv_convert(ctx, encoder->cd, str, len, true, false);
    JS_FreeCString(ctx, str);
    
    return result;
}

/* encoder.encodeInto(string, buffer) */
static JSValue tjs_text_encoder_encode_into(JSContext *ctx, JSValueConst this_val,
                                              int argc, JSValueConst *argv) {
    TJSTextEncoder *encoder = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!encoder) return JS_EXCEPTION;
    
    size_t str_len;
    const char *str = JS_ToCStringLen(ctx, &str_len, argv[0]);
    if (!str) return JS_EXCEPTION;
    
    /* Get output buffer */
    size_t buf_size;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &buf_size, argv[1]);
    if (!buf) {
        JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[1], NULL, NULL, NULL);
        if (JS_IsException(buffer)) {
            JS_FreeCString(ctx, str);
            return JS_ThrowTypeError(ctx, "Second argument must be ArrayBuffer or TypedArray");
        }
        buf = JS_GetArrayBuffer(ctx, &buf_size, buffer);
        JS_FreeValue(ctx, buffer);
        if (!buf) {
            JS_FreeCString(ctx, str);
            return JS_EXCEPTION;
        }
    }
    
    /* Reset encoder state */
    iconv(encoder->cd, NULL, NULL, NULL, NULL);
    
    /* Convert into buffer */
    char *inptr = (char *)str;
    char *outptr = (char *)buf;
    size_t inleft = str_len;
    size_t outleft = buf_size;
    
    size_t ret = iconv(encoder->cd, &inptr, &inleft, &outptr, &outleft);
    size_t read = str_len - inleft;
    size_t written = buf_size - outleft;
    
    JS_FreeCString(ctx, str);

	if (ret == -1){
		if (errno == EILSEQ || errno == EINVAL) {
			/* Invalid input byte sequence */
			return JS_ThrowTypeError(ctx, "Invalid input byte sequence");
		} else {
			return JS_ThrowTypeError(ctx, "iconv conversion error(errno=%d): %s", errno, strerror(errno));
		}
	}
    
    /* Return result object */
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "read", JS_NewInt64(ctx, read));
    JS_SetPropertyStr(ctx, result, "written", JS_NewInt64(ctx, written));
    
    return result;
}

/* Getter: encoder.encoding */
static JSValue tjs_text_encoder_get_encoding(JSContext *ctx, JSValueConst this_val) {
    TJSTextEncoder *encoder = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!encoder) return JS_EXCEPTION;
    return JS_NewString(ctx, encoder->encoding);
}

static const JSCFunctionListEntry tjs_text_encoder_proto_funcs[] = {
    JS_CFUNC_DEF("encode", 1, tjs_text_encoder_encode),
    JS_CFUNC_DEF("encodeInto", 2, tjs_text_encoder_encode_into),
    JS_CGETSET_DEF("encoding", tjs_text_encoder_get_encoding, NULL),
};

#pragma region Utility Functions

/* convert(from, to, data) */
static JSValue tjs_text_convert(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    const char *from = JS_ToCString(ctx, argv[0]);
    const char *to = JS_ToCString(ctx, argv[1]);
    if (!from || !to) {
        if (from) JS_FreeCString(ctx, from);
        if (to) JS_FreeCString(ctx, to);
        return JS_EXCEPTION;
    }
    
    iconv_t cd = iconv_open(to, from);
    JS_FreeCString(ctx, from);
    JS_FreeCString(ctx, to);
    ICONV_ERROR_CHECK(ctx, cd, "iconv_open");
    
    /* Get input data */
    size_t size;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &size, argv[2]);
    if (!buf) {
        JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[2], NULL, NULL, NULL);
        if (JS_IsException(buffer)) {
            iconv_close(cd);
            return JS_ThrowTypeError(ctx, "Third argument must be ArrayBuffer or TypedArray");
        }
        buf = JS_GetArrayBuffer(ctx, &size, buffer);
        JS_FreeValue(ctx, buffer);
        if (!buf) {
            iconv_close(cd);
            return JS_EXCEPTION;
        }
    }
    
    bool is_to_utf8 = (strcasecmp(to, "UTF-8") == 0);
    JSValue result = iconv_convert(ctx, cd, (const char *)buf, size, false, is_to_utf8);
    
    iconv_close(cd);
    return result;
}

/* listEncodings() */
static JSValue tjs_text_list_encodings(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    /* Common encodings supported by most iconv implementations */
    const char *encodings[] = {
        "UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE", "UTF-32", "UTF-32BE", "UTF-32LE",
        "ASCII", "ISO-8859-1", "ISO-8859-2", "ISO-8859-3", "ISO-8859-4", "ISO-8859-5",
        "ISO-8859-6", "ISO-8859-7", "ISO-8859-8", "ISO-8859-9", "ISO-8859-10",
        "ISO-8859-13", "ISO-8859-14", "ISO-8859-15", "ISO-8859-16",
        "Windows-1250", "Windows-1251", "Windows-1252", "Windows-1253", "Windows-1254",
        "Windows-1255", "Windows-1256", "Windows-1257", "Windows-1258",
        "GB2312", "GBK", "GB18030", "BIG5", "EUC-JP", "SHIFT_JIS", "ISO-2022-JP",
        "EUC-KR", "KOI8-R", "KOI8-U", "TIS-620"
    };
    
    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); i++) {
        JS_SetPropertyUint32(ctx, arr, i, JS_NewString(ctx, encodings[i]));
    }
    
    return arr;
}

static const JSCFunctionListEntry tjs_text_funcs[] = {
    JS_CFUNC_DEF("convert", 3, tjs_text_convert),
    JS_CFUNC_DEF("listEncodings", 0, tjs_text_list_encodings),
};


void tjs__mod_text_init(JSContext *ctx, JSValue ns) {
    /* Register TextDecoder */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_text_decoder_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_text_decoder_class_id, &tjs_text_decoder_class);
    
    JSValue decoder_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, decoder_proto, tjs_text_decoder_proto_funcs,
                              countof(tjs_text_decoder_proto_funcs));
    JS_SetClassProto(ctx, tjs_text_decoder_class_id, decoder_proto);
    
    JSValue decoder_ctor = JS_NewCFunction2(ctx, tjs_text_decoder_constructor,
                                           "TextDecoder", 2,
                                           JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, ns, "Decoder", decoder_ctor);
    
    /* Register TextEncoder */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_text_encoder_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_text_encoder_class_id, &tjs_text_encoder_class);
    
    JSValue encoder_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, encoder_proto, tjs_text_encoder_proto_funcs,
                              countof(tjs_text_encoder_proto_funcs));
    JS_SetClassProto(ctx, tjs_text_encoder_class_id, encoder_proto);
    
    JSValue encoder_ctor = JS_NewCFunction2(ctx, tjs_text_encoder_constructor,
                                           "TextEncoder", 1,
                                           JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, ns, "Encoder", encoder_ctor);
    
    /* Register utility functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_text_funcs, countof(tjs_text_funcs));
}