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
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <ctype.h>
/* Windows doesn't have strings.h, use _stricmp instead of strcasecmp */
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#include "private.h"
#include "tjs.h"

/* ============================================================================
 * Tunables
 * ============================================================================ */
#define INITIAL_BUFFER_SIZE 1024
/* Minimum free space we keep available before each iconv() call. Must be >= 4
 * so a single multi-byte code unit always fits and we cannot livelock on a
 * spurious E2BIG that makes no progress. */
#define MIN_OUT_HEADROOM    64
/* Max bytes held back for an incomplete multi-byte sequence while streaming.
 * 8 covers every stateful/stateless encoding iconv supports (UTF-32 = 4,
 * ISO-2022 shift sequences are short); we keep a little slack. */
#define MAX_PENDING_BUFFER  16

/* UTF-8 encoding of U+FFFD REPLACEMENT CHARACTER. */
static const uint8_t kUtf8Replacement[3] = { 0xEF, 0xBF, 0xBD };

/* ============================================================================
 * Instance state
 * ============================================================================ */

/*
 * TextDecoder instance state
 * Web API: https://encoding.spec.whatwg.org/#textdecoder
 */
typedef struct {
    iconv_t cd;                          /* iconv conversion descriptor      */
    char *encoding;                      /* normalized encoding name         */
    bool fatal;                          /* throw on encoding errors         */
    bool ignore_bom;                     /* skip BOM detection               */
    bool bom_seen;                       /* BOM already handled this stream  */
    uint8_t pending[MAX_PENDING_BUFFER]; /* buffered incomplete sequence     */
    size_t pending_len;
} decoder_t;

/*
 * TextEncoder instance state
 * Web API: https://encoding.spec.whatwg.org/#textencoder
 */
typedef struct {
    iconv_t cd;
    char *encoding;
    bool is_utf8;   /* true when output encoding is plain UTF-8 */
} encoder_t;

/* Class IDs for QuickJS finalizers */
static JSClassID tjs_text_decoder_class_id;
static JSClassID tjs_text_encoder_class_id;

/* ============================================================================
 * Growable output buffer
 * ============================================================================ */
typedef struct {
    char *buf;
    size_t size; /* allocated capacity   */
    size_t len;  /* bytes used           */
} growbuf_t;

/* Ensure at least `extra` free bytes are available. Returns 0 on success,
 * -1 on allocation failure (no exception thrown here; caller decides). */
static int gb_ensure(JSContext *ctx, growbuf_t *gb, size_t extra) {
    if (gb->buf && gb->len + extra <= gb->size)
        return 0;

    size_t need = gb->len + extra;
    size_t new_size = gb->size ? gb->size : INITIAL_BUFFER_SIZE;
    while (new_size < need) {
        size_t grown = new_size + (new_size >> 1); /* *1.5 */
        if (grown <= new_size)                      /* overflow / no growth */
            grown = new_size + INITIAL_BUFFER_SIZE;
        new_size = grown;
    }

    char *nb = js_realloc(ctx, gb->buf, new_size);
    if (!nb)
        return -1;
    gb->buf = nb;
    gb->size = new_size;
    return 0;
}

static void gb_free(JSContext *ctx, growbuf_t *gb) {
    if (gb->buf) {
        js_free(ctx, gb->buf);
        gb->buf = NULL;
    }
    gb->size = gb->len = 0;
}

static inline int gb_put(JSContext *ctx, growbuf_t *gb, const uint8_t *src, size_t n) {
    if (gb_ensure(ctx, gb, n) < 0)
        return -1;
    memcpy(gb->buf + gb->len, src, n);
    gb->len += n;
    return 0;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Return the BOM byte sequence for an encoding (written into out[0..3]) and
 * its length, or 0 if the encoding has no BOM. Comparing against the assembled
 * input lets us recognize a BOM that is split across streamed chunks. */
static size_t bom_bytes(const char *encoding, uint8_t out[4]) {
    if (strcasecmp(encoding, "UTF-8") == 0) {
        out[0] = 0xEF; out[1] = 0xBB; out[2] = 0xBF;
        return 3;
    } else if (strcasecmp(encoding, "UTF-16BE") == 0) {
        out[0] = 0xFE; out[1] = 0xFF;
        return 2;
    } else if (strcasecmp(encoding, "UTF-16LE") == 0) {
        out[0] = 0xFF; out[1] = 0xFE;
        return 2;
    } else if (strcasecmp(encoding, "UTF-32BE") == 0) {
        out[0] = 0x00; out[1] = 0x00; out[2] = 0xFE; out[3] = 0xFF;
        return 4;
    } else if (strcasecmp(encoding, "UTF-32LE") == 0) {
        out[0] = 0xFF; out[1] = 0xFE; out[2] = 0x00; out[3] = 0x00;
        return 4;
    }
    return 0;
}

/* Normalize a few common encoding aliases. Returns either a static literal or
 * the input pointer; the caller must js_strdup the result if it needs to own
 * a copy (it never frees the returned pointer directly). */
static const char *normalize_encoding_name(const char *enc) {
    if (!enc || enc[0] == '\0')
        return "UTF-8";
    if (strcasecmp(enc, "utf8") == 0 || strcasecmp(enc, "utf-8") == 0 ||
        strcasecmp(enc, "unicode-1-1-utf-8") == 0)
        return "UTF-8";
    if (strcasecmp(enc, "utf-16") == 0 || strcasecmp(enc, "utf16") == 0 ||
        strcasecmp(enc, "utf-16le") == 0)
        return "UTF-16LE";
    if (strcasecmp(enc, "utf-16be") == 0)
        return "UTF-16BE";
    if (strcasecmp(enc, "utf-32") == 0 || strcasecmp(enc, "utf32") == 0 ||
        strcasecmp(enc, "utf-32le") == 0)
        return "UTF-32LE";
    if (strcasecmp(enc, "utf-32be") == 0)
        return "UTF-32BE";
    if (strcasecmp(enc, "latin1") == 0 || strcasecmp(enc, "iso-8859-1") == 0 ||
        strcasecmp(enc, "l1") == 0)
        return "ISO-8859-1";
    if (strcasecmp(enc, "us-ascii") == 0 || strcasecmp(enc, "ascii") == 0)
        return "ASCII";
    return enc;
}

/* Count UTF-16 code units in the first `n` bytes of a (valid) UTF-8 buffer.
 * Used by encodeInto() to report `read` per the WHATWG spec. iconv only ever
 * consumes whole code points, so `n` always lands on a code-point boundary. */
static size_t utf8_prefix_utf16_units(const char *s, size_t n) {
    size_t units = 0, i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        size_t adv;
        if (c < 0x80)            adv = 1;
        else if ((c >> 5) == 0x6)  adv = 2;
        else if ((c >> 4) == 0xE)  adv = 3;
        else if ((c >> 3) == 0x1E) adv = 4;
        else                       adv = 1; /* stray byte: treat as 1 */
        if (i + adv > n)
            break;
        units += (adv == 4) ? 2 : 1; /* supplementary plane -> surrogate pair */
        i += adv;
    }
    return units;
}

/* ============================================================================
 * Core iconv driver
 *
 * Converts `inlen` bytes from `inbuf` through `cd`, appending output to `gb`.
 *
 *  - Grows `gb` on E2BIG (never drops output, never overflows).
 *  - On EILSEQ: if `fatal`, throws and returns -1; otherwise emits one
 *    replacement (U+FFFD for UTF-8 targets, '?' otherwise) and resyncs by
 *    skipping one input byte.
 *  - On EINVAL (incomplete trailing sequence): stops and reports the number of
 *    unconsumed trailing bytes via *trailing_out (caller decides whether to
 *    buffer them for streaming or treat them as an error / replacement).
 *
 * Returns 0 on success (exception-free) or -1 with a pending JS exception.
 * ==========================================================================*/
static int iconv_drive(JSContext *ctx, iconv_t cd,
                       const char *inbuf, size_t inlen,
                       bool fatal, bool to_utf8,
                       growbuf_t *gb, size_t *trailing_out) {
    char *inptr = (char *)inbuf;
    size_t inleft = inlen;
    if (trailing_out)
        *trailing_out = 0;

    while (inleft > 0) {
        if (gb_ensure(ctx, gb, MIN_OUT_HEADROOM) < 0) {
            JS_ThrowOutOfMemory(ctx);
            return -1;
        }

        char *outptr = gb->buf + gb->len;
        size_t outleft = gb->size - gb->len;
        size_t ret = iconv(cd, &inptr, &inleft, &outptr, &outleft);
        gb->len = gb->size - outleft; /* commit whatever iconv produced */

        if (ret != (size_t)-1)
            break; /* all input consumed */

        int e = errno;
        if (e == E2BIG) {
            /* Output full: force real growth before retrying. */
            if (gb_ensure(ctx, gb, gb->size ? gb->size : INITIAL_BUFFER_SIZE) < 0) {
                JS_ThrowOutOfMemory(ctx);
                return -1;
            }
            continue;
        }
        if (e == EINVAL) {
            if (trailing_out)
                *trailing_out = inleft;
            return 0; /* incomplete trailing sequence: defer to caller */
        }
        if (e == EILSEQ) {
            if (fatal) {
                JS_ThrowTypeError(ctx, "The encoded data was not valid");
                return -1;
            }
            /* Resync: drop one byte and emit a single replacement. */
            inptr++;
            inleft--;
            if (to_utf8) {
                if (gb_put(ctx, gb, kUtf8Replacement, sizeof kUtf8Replacement) < 0) {
                    JS_ThrowOutOfMemory(ctx);
                    return -1;
                }
            } else {
                static const uint8_t q = (uint8_t)'?';
                if (gb_put(ctx, gb, &q, 1) < 0) {
                    JS_ThrowOutOfMemory(ctx);
                    return -1;
                }
            }
            continue;
        }
        /* Unexpected errno (e.g. EBADF): surface a clear error. */
        JS_ThrowTypeError(ctx, "Encoding conversion error: %s", strerror(e));
        return -1;
    }
    return 0;
}

/* ============================================================================
 * TextDecoder
 * ============================================================================ */
static void tjs_text_decoder_finalizer(JSRuntime *rt, JSValue val) {
    decoder_t *dec = JS_GetOpaque(val, tjs_text_decoder_class_id);
    if (!dec)
        return;
    if (dec->cd != (iconv_t)-1)
        iconv_close(dec->cd);
    if (dec->encoding)
        js_free_rt(rt, dec->encoding);
    js_free_rt(rt, dec);
}

static JSClassDef tjs_text_decoder_class = {
    "TextDecoder",
    .finalizer = tjs_text_decoder_finalizer,
};

static JSValue tjs_text_decoder_constructor(JSContext *ctx, JSValueConst new_target,
                                            int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_text_decoder_class_id);
    if (JS_IsException(obj))
        return obj;

    decoder_t *dec = js_mallocz(ctx, sizeof(*dec));
    if (!dec) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    dec->cd = (iconv_t)-1;

    /* Read the encoding label (defaults to "utf-8"). */
    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        const char *label = JS_ToCString(ctx, argv[0]);
        if (!label)
            goto fail;
        dec->encoding = js_strdup(ctx, normalize_encoding_name(label));
        JS_FreeCString(ctx, label);
    } else {
        dec->encoding = js_strdup(ctx, "UTF-8");
    }
    if (!dec->encoding) {
        JS_ThrowOutOfMemory(ctx);
        goto fail;
    }

    /* Options: { fatal, ignoreBOM }. Read these (which may invoke getters)
     * before touching any raw buffers elsewhere. */
    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue v;
        v = JS_GetPropertyStr(ctx, argv[1], "fatal");
        if (JS_IsException(v))
            goto fail;
        dec->fatal = JS_ToBool(ctx, v);
        JS_FreeValue(ctx, v);

        v = JS_GetPropertyStr(ctx, argv[1], "ignoreBOM");
        if (JS_IsException(v))
            goto fail;
        dec->ignore_bom = JS_ToBool(ctx, v);
        JS_FreeValue(ctx, v);
    }

    dec->cd = iconv_open("UTF-8", dec->encoding);
    if (dec->cd == (iconv_t)-1) {
        JS_ThrowTypeError(ctx, "Unsupported encoding: %s", dec->encoding);
        goto fail;
    }

    JS_SetOpaque(obj, dec);
    return obj;

fail:
    /* Opaque was never set, so the finalizer will not run: clean up by hand. */
    if (dec->encoding)
        js_free(ctx, dec->encoding);
    js_free(ctx, dec);
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}

/* Read the boolean `stream` option from an optional options object.
 * Returns 0 on success (sets *out), -1 with a pending exception. */
static int read_stream_option(JSContext *ctx, int argc, JSValueConst *argv, bool *out) {
    *out = false;
    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue v = JS_GetPropertyStr(ctx, argv[1], "stream");
        if (JS_IsException(v))
            return -1;
        *out = JS_ToBool(ctx, v);
        JS_FreeValue(ctx, v);
    }
    return 0;
}

static JSValue tjs_text_decoder_decode(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec)
        return JS_EXCEPTION;

    /* Parse options first (may run user getters) before acquiring any raw
     * buffer pointer, so a getter cannot detach/resize the input out from
     * under us. */
    bool stream;
    if (read_stream_option(ctx, argc, argv, &stream) < 0)
        return JS_EXCEPTION;

    /* Acquire input view (if any). After this point we make no calls that can
     * run JS or trigger GC relocation until we are done reading `inbuf`. */
    size_t inlen = 0;
    uint8_t *inbuf = NULL;
    if (argc > 0 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        inbuf = JS_GetAnyBuffer(ctx, &inlen, argv[0]);
        if (!inbuf)
            return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer or ArrayBufferView");
    }

    /* No input: end-of-stream / flush handling. */
    if (!inbuf || inlen == 0) {
        if (!stream) {
            bool had_pending = dec->pending_len > 0;
            dec->pending_len = 0;
            dec->bom_seen = false;
            iconv(dec->cd, NULL, NULL, NULL, NULL); /* reset shift state */
            if (had_pending && dec->fatal)
                return JS_ThrowTypeError(ctx, "Incomplete character sequence at end of stream");
            if (had_pending)
                return JS_NewStringLen(ctx, (const char *)kUtf8Replacement,
                                       sizeof kUtf8Replacement);
        }
        return JS_NewStringLen(ctx, "", 0);
    }

    /* Assemble pending + new bytes into one contiguous run first, so a BOM (or
     * any multi-byte sequence) split across streamed chunks is handled
     * correctly. */
    const char *conv_in;
    size_t conv_len = dec->pending_len + inlen;
    char *merged = NULL;
    if (dec->pending_len > 0) {
        merged = js_malloc(ctx, conv_len ? conv_len : 1);
        if (!merged)
            return JS_ThrowOutOfMemory(ctx);
        memcpy(merged, dec->pending, dec->pending_len);
        memcpy(merged + dec->pending_len, inbuf, inlen);
        dec->pending_len = 0;
        conv_in = merged;
    } else {
        conv_in = (const char *)inbuf;
    }

    /* BOM handling, evaluated on the assembled bytes (so a BOM straddling a
     * chunk boundary is still recognized). Only at the very start of a stream. */
    if (!dec->ignore_bom && !dec->bom_seen) {
        uint8_t bom[4];
        size_t bomlen = bom_bytes(dec->encoding, bom);
        if (bomlen == 0) {
            dec->bom_seen = true;
        } else if (conv_len > 0) {
            size_t cmp = conv_len < bomlen ? conv_len : bomlen;
            if (memcmp(conv_in, bom, cmp) == 0) {
                if (conv_len >= bomlen) {
                    conv_in += bomlen;
                    conv_len -= bomlen;
                    dec->bom_seen = true;
                } else if (stream) {
                    /* Partial BOM prefix: hold the bytes until more arrive. */
                    memcpy(dec->pending, conv_in, conv_len);
                    dec->pending_len = conv_len;
                    if (merged)
                        js_free(ctx, merged);
                    return JS_NewStringLen(ctx, "", 0);
                }
                /* else: non-stream partial match -> treat as ordinary data. */
            } else {
                dec->bom_seen = true; /* definitively not a BOM */
            }
        }
    }

    /* For one-shot decoding, reset iconv shift state up front. */
    if (!stream)
        iconv(dec->cd, NULL, NULL, NULL, NULL);

    growbuf_t gb = {0};
    size_t trailing = 0;
    int rc = iconv_drive(ctx, dec->cd, conv_in, conv_len,
                         dec->fatal, /*to_utf8=*/true, &gb, &trailing);

    if (rc == 0 && trailing > 0) {
        /* Incomplete sequence at the end of input. */
        const char *tail = conv_in + (conv_len - trailing);
        if (stream && trailing <= MAX_PENDING_BUFFER) {
            memcpy(dec->pending, tail, trailing);
            dec->pending_len = trailing;
        } else if (dec->fatal) {
            gb_free(ctx, &gb);
            if (merged)
                js_free(ctx, merged);
            return JS_ThrowTypeError(ctx, "Incomplete character sequence");
        } else {
            /* One replacement char stands in for the dropped tail. */
            if (gb_put(ctx, &gb, kUtf8Replacement, sizeof kUtf8Replacement) < 0) {
                gb_free(ctx, &gb);
                if (merged)
                    js_free(ctx, merged);
                return JS_ThrowOutOfMemory(ctx);
            }
        }
    }

    if (merged)
        js_free(ctx, merged);

    if (rc != 0) {
        gb_free(ctx, &gb);
        return JS_EXCEPTION;
    }

    if (!stream) {
        dec->pending_len = 0;
        dec->bom_seen = false;
    }

    JSValue result = JS_NewStringLen(ctx, gb.buf ? gb.buf : "", gb.len);
    gb_free(ctx, &gb);
    return result;
}

static JSValue tjs_text_decoder_get_encoding(JSContext *ctx, JSValueConst this_val) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec)
        return JS_EXCEPTION;
    return JS_NewString(ctx, dec->encoding);
}

static JSValue tjs_text_decoder_get_fatal(JSContext *ctx, JSValueConst this_val) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec)
        return JS_EXCEPTION;
    return JS_NewBool(ctx, dec->fatal);
}

static JSValue tjs_text_decoder_get_ignore_bom(JSContext *ctx, JSValueConst this_val) {
    decoder_t *dec = JS_GetOpaque2(ctx, this_val, tjs_text_decoder_class_id);
    if (!dec)
        return JS_EXCEPTION;
    return JS_NewBool(ctx, dec->ignore_bom);
}

static const JSCFunctionListEntry tjs_text_decoder_proto_funcs[] = {
    JS_CFUNC_DEF("decode", 2, tjs_text_decoder_decode),
    JS_CGETSET_DEF("encoding", tjs_text_decoder_get_encoding, NULL),
    JS_CGETSET_DEF("fatal", tjs_text_decoder_get_fatal, NULL),
    JS_CGETSET_DEF("ignoreBOM", tjs_text_decoder_get_ignore_bom, NULL),
};

/* ============================================================================
 * TextEncoder
 * ============================================================================ */
static void tjs_text_encoder_finalizer(JSRuntime *rt, JSValue val) {
    encoder_t *enc = JS_GetOpaque(val, tjs_text_encoder_class_id);
    if (!enc)
        return;
    if (enc->cd != (iconv_t)-1)
        iconv_close(enc->cd);
    if (enc->encoding)
        js_free_rt(rt, enc->encoding);
    js_free_rt(rt, enc);
}

static JSClassDef tjs_text_encoder_class = {
    "TextEncoder",
    .finalizer = tjs_text_encoder_finalizer,
};

static JSValue tjs_text_encoder_constructor(JSContext *ctx, JSValueConst new_target,
                                            int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_text_encoder_class_id);
    if (JS_IsException(obj))
        return obj;

    encoder_t *enc = js_mallocz(ctx, sizeof(*enc));
    if (!enc) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    enc->cd = (iconv_t)-1;

    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        const char *label = JS_ToCString(ctx, argv[0]);
        if (!label)
            goto fail;
        enc->encoding = js_strdup(ctx, normalize_encoding_name(label));
        JS_FreeCString(ctx, label);
    } else {
        enc->encoding = js_strdup(ctx, "UTF-8");
    }
    if (!enc->encoding) {
        JS_ThrowOutOfMemory(ctx);
        goto fail;
    }
    enc->is_utf8 = (strcasecmp(enc->encoding, "UTF-8") == 0);

    enc->cd = iconv_open(enc->encoding, "UTF-8");
    if (enc->cd == (iconv_t)-1) {
        JS_ThrowTypeError(ctx, "Unsupported encoding for TextEncoder: %s", enc->encoding);
        goto fail;
    }

    JS_SetOpaque(obj, enc);
    return obj;

fail:
    if (enc->encoding)
        js_free(ctx, enc->encoding);
    js_free(ctx, enc);
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}

/* encoder.encode(string) -> Uint8Array */
static JSValue tjs_text_encoder_encode(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv) {
    encoder_t *enc = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!enc)
        return JS_EXCEPTION;

    /* encode() with no argument is defined as encoding the empty string. */
    if (argc < 1 || JS_IsUndefined(argv[0]))
        return JS_NewUint8ArrayCopy(ctx, (const uint8_t *)"", 0);

    size_t str_len = 0;
    const char *str = JS_ToCStringLen(ctx, &str_len, argv[0]);
    if (!str)
        return JS_EXCEPTION;

    iconv(enc->cd, NULL, NULL, NULL, NULL); /* reset shift state */

    growbuf_t gb = {0};
    /* TextEncoder never throws on bad data; unrepresentable chars in a custom
     * target encoding become '?'. */
    int rc = iconv_drive(ctx, enc->cd, str, str_len,
                         /*fatal=*/false, /*to_utf8=*/enc->is_utf8, &gb, NULL);
    JS_FreeCString(ctx, str);

    if (rc != 0) {
        gb_free(ctx, &gb);
        return JS_EXCEPTION;
    }

    JSValue result = JS_NewUint8ArrayCopy(ctx, (const uint8_t *)(gb.buf ? gb.buf : ""), gb.len);
    gb_free(ctx, &gb);
    return result;
}

/* encoder.encodeInto(string, uint8Array) -> { read, written } */
static JSValue tjs_text_encoder_encode_into(JSContext *ctx, JSValueConst this_val,
                                            int argc, JSValueConst *argv) {
    encoder_t *enc = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!enc)
        return JS_EXCEPTION;

    if (argc < 2)
        return JS_ThrowTypeError(ctx, "encodeInto requires (string, Uint8Array)");

    size_t str_len = 0;
    const char *str = JS_ToCStringLen(ctx, &str_len, argv[0]);
    if (!str)
        return JS_EXCEPTION;

    /* Acquire the destination buffer last and touch no JS afterwards, so a
     * getter cannot detach it under us. */
    size_t buf_len = 0;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &buf_len, argv[1]);
    if (!buf) {
        JS_FreeCString(ctx, str);
        return JS_ThrowTypeError(ctx, "Second argument must be an ArrayBufferView");
    }

    iconv(enc->cd, NULL, NULL, NULL, NULL);

    char *inptr = (char *)str;
    char *outptr = (char *)buf;
    size_t inleft = str_len;
    size_t outleft = buf_len;
    bool hard_error = false;

    while (inleft > 0 && outleft > 0) {
        size_t ret = iconv(enc->cd, &inptr, &inleft, &outptr, &outleft);
        if (ret != (size_t)-1)
            break; /* fully consumed */
        int e = errno;
        if (e == E2BIG)
            break; /* destination full: stop without overflowing */
        if (e == EINVAL)
            break; /* incomplete trailing unit: leave it unread */
        if (e == EILSEQ) {
            /* Unrepresentable char in a custom target encoding. */
            if (outleft == 0)
                break;
            *outptr++ = '?';
            outleft--;
            /* Skip one whole UTF-8 code point in the source. */
            unsigned char c = (unsigned char)*inptr;
            size_t adv = (c < 0x80) ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 1;
            if (adv > inleft)
                adv = inleft;
            inptr += adv;
            inleft -= adv;
            continue;
        }
        hard_error = true;
        break;
    }

    size_t consumed_bytes = str_len - inleft;
    size_t written = buf_len - outleft;
    size_t read_units = utf8_prefix_utf16_units(str, consumed_bytes);

    JS_FreeCString(ctx, str);

    if (hard_error)
        return JS_ThrowTypeError(ctx, "Encoding conversion failed: %s", strerror(errno));

    JSValue result = JS_NewObject(ctx);
    if (JS_IsException(result))
        return result;
    JS_SetPropertyStr(ctx, result, "read", JS_NewInt64(ctx, (int64_t)read_units));
    JS_SetPropertyStr(ctx, result, "written", JS_NewInt64(ctx, (int64_t)written));
    return result;
}

static JSValue tjs_text_encoder_get_encoding(JSContext *ctx, JSValueConst this_val) {
    encoder_t *enc = JS_GetOpaque2(ctx, this_val, tjs_text_encoder_class_id);
    if (!enc)
        return JS_EXCEPTION;
    /* Per the Web API, TextEncoder always reports "utf-8". */
    return JS_NewString(ctx, "utf-8");
}

static const JSCFunctionListEntry tjs_text_encoder_proto_funcs[] = {
    JS_CFUNC_DEF("encode", 1, tjs_text_encoder_encode),
    JS_CFUNC_DEF("encodeInto", 2, tjs_text_encoder_encode_into),
    JS_CGETSET_DEF("encoding", tjs_text_encoder_get_encoding, NULL),
};

/* ============================================================================
 * Standalone conversion helpers
 * ============================================================================ */

/* convert(fromEncoding, toEncoding, data) -> string | Uint8Array */
static JSValue tjs_text_convert(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    if (argc < 3)
        return JS_ThrowTypeError(ctx, "convert requires 3 arguments: from, to, data");

    const char *from = JS_ToCString(ctx, argv[0]);
    if (!from)
        return JS_EXCEPTION;
    const char *to = JS_ToCString(ctx, argv[1]);
    if (!to) {
        JS_FreeCString(ctx, from);
        return JS_EXCEPTION;
    }

    const char *from_n = normalize_encoding_name(from);
    const char *to_n = normalize_encoding_name(to);

    iconv_t cd = iconv_open(to_n, from_n);
    if (cd == (iconv_t)-1) {
        JSValue err = JS_ThrowTypeError(ctx, "Conversion from %s to %s not supported", from, to);
        JS_FreeCString(ctx, from);
        JS_FreeCString(ctx, to);
        return err;
    }

    bool is_to_utf8 = (strcasecmp(to_n, "UTF-8") == 0);

    /* from/to C strings are no longer needed for formatting; the data buffer is
     * acquired last and used without any further JS calls. */
    JS_FreeCString(ctx, from);
    JS_FreeCString(ctx, to);

    size_t inlen = 0;
    uint8_t *inbuf = JS_GetAnyBuffer(ctx, &inlen, argv[2]);
    if (!inbuf) {
        iconv_close(cd);
        return JS_ThrowTypeError(ctx, "Third argument must be an ArrayBuffer or ArrayBufferView");
    }

    growbuf_t gb = {0};
    size_t trailing = 0;
    int rc = iconv_drive(ctx, cd, (const char *)inbuf, inlen,
                         /*fatal=*/false, is_to_utf8, &gb, &trailing);

    if (rc == 0 && trailing > 0) {
        /* Best-effort: stand in one replacement for the incomplete tail. */
        if (is_to_utf8)
            rc = gb_put(ctx, &gb, kUtf8Replacement, sizeof kUtf8Replacement);
        else {
            static const uint8_t q = (uint8_t)'?';
            rc = gb_put(ctx, &gb, &q, 1);
        }
        if (rc < 0)
            JS_ThrowOutOfMemory(ctx);
    }

    iconv_close(cd);

    if (rc != 0) {
        gb_free(ctx, &gb);
        return JS_EXCEPTION;
    }

    JSValue result;
    if (is_to_utf8)
        result = JS_NewStringLen(ctx, gb.buf ? gb.buf : "", gb.len);
    else
        result = JS_NewUint8ArrayCopy(ctx, (const uint8_t *)(gb.buf ? gb.buf : ""), gb.len);
    gb_free(ctx, &gb);
    return result;
}

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
    if (JS_IsException(arr))
        return arr;

    for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); i++) {
        JSValue str = JS_NewString(ctx, encodings[i]);
        if (JS_IsException(str)) {
            JS_FreeValue(ctx, arr);
            return JS_EXCEPTION;
        }
        if (JS_SetPropertyUint32(ctx, arr, i, str) < 0) {
            JS_FreeValue(ctx, arr);
            return JS_EXCEPTION;
        }
    }
    return arr;
}

static const JSCFunctionListEntry tjs_text_funcs[] = {
    JS_CFUNC_DEF("convert", 3, tjs_text_convert),
    JS_CFUNC_DEF("listEncodings", 0, tjs_text_list_encodings),
};

/* ============================================================================
 * Module init
 * ============================================================================ */
void tjs__mod_text_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    /* TextDecoder */
    JS_NewClassID(rt, &tjs_text_decoder_class_id);
    JS_NewClass(rt, tjs_text_decoder_class_id, &tjs_text_decoder_class);

    JSValue decoder_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, decoder_proto, tjs_text_decoder_proto_funcs,
                               sizeof(tjs_text_decoder_proto_funcs) / sizeof(JSCFunctionListEntry));
    JS_SetClassProto(ctx, tjs_text_decoder_class_id, decoder_proto);

    JSValue decoder_ctor = JS_NewCFunction2(ctx, tjs_text_decoder_constructor,
                                            "TextDecoder", 2, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, decoder_ctor, decoder_proto);
    JS_SetPropertyStr(ctx, ns, "Decoder", decoder_ctor);

    /* TextEncoder */
    JS_NewClassID(rt, &tjs_text_encoder_class_id);
    JS_NewClass(rt, tjs_text_encoder_class_id, &tjs_text_encoder_class);

    JSValue encoder_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, encoder_proto, tjs_text_encoder_proto_funcs,
                               sizeof(tjs_text_encoder_proto_funcs) / sizeof(JSCFunctionListEntry));
    JS_SetClassProto(ctx, tjs_text_encoder_class_id, encoder_proto);

    JSValue encoder_ctor = JS_NewCFunction2(ctx, tjs_text_encoder_constructor,
                                            "TextEncoder", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, encoder_ctor, encoder_proto);
    JS_SetPropertyStr(ctx, ns, "Encoder", encoder_ctor);

    /* Utility functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_text_funcs,
                               sizeof(tjs_text_funcs) / sizeof(JSCFunctionListEntry));
}
