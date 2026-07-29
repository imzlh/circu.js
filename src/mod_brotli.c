/**
 * Circu.js Brotli compression/decompression module
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
#include "private.h"
#include "utils.h"

#ifdef CJS_HAVE_BROTLI
#include <brotli/encode.h>
#include <brotli/decode.h>
#include <string.h>
#include <stdint.h>

/* Decompression bomb guard: cap streamed output at 256MB */
#define BROTLI_MAX_OUTPUT (256 * 1024 * 1024)

static JSValue tjs_brotli_empty_buffer(JSContext *ctx) {
    return JS_NewUint8ArrayCopy(ctx, NULL, 0);
}

/* Encoder settings parsed from the options object */
typedef struct {
    int quality;
    int lgwin;
    int mode;
    int lgblock;       /* 0 = encoder default */
    int large_window;  /* bool */
    int64_t size_hint; /* -1 = auto (use input length) */
} TJSBrotliOpts;

static void tjs_brotli_opts_default(TJSBrotliOpts *o) {
    o->quality = BROTLI_DEFAULT_QUALITY;
    o->lgwin = BROTLI_DEFAULT_WINDOW;
    o->mode = BROTLI_MODE_GENERIC;
    o->lgblock = 0;
    o->large_window = 0;
    o->size_hint = -1;
}

static int tjs_brotli_get_int(JSContext *ctx, JSValueConst obj, const char *key, int *out, int *present) {
    JSValue v = JS_GetPropertyStr(ctx, obj, key);
    if (JS_IsException(v))
        return -1;
    if (JS_IsUndefined(v)) {
        JS_FreeValue(ctx, v);
        *present = 0;
        return 0;
    }
    int r = JS_ToInt32(ctx, out, v);
    JS_FreeValue(ctx, v);
    if (r < 0)
        return -1;
    *present = 1;
    return 0;
}

/* Parse the {quality, lgwin, mode, lgblock, sizeHint, largeWindow} options.
 * A bare number is accepted as shorthand for quality (back-compat). */
static int tjs_brotli_parse_opts(JSContext *ctx, JSValueConst arg, TJSBrotliOpts *o) {
    if (JS_IsUndefined(arg) || JS_IsNull(arg))
        return 0;

    if (JS_IsNumber(arg)) {
        if (JS_ToInt32(ctx, &o->quality, arg) < 0)
            return -1;
        if (o->quality < BROTLI_MIN_QUALITY || o->quality > BROTLI_MAX_QUALITY) {
            JS_ThrowRangeError(ctx, "quality must be between 0 and 11");
            return -1;
        }
        return 0;
    }

    if (!JS_IsObject(arg)) {
        JS_ThrowTypeError(ctx, "brotli options must be a number or an object");
        return -1;
    }

    int present;
    int large = 0;

    JSValue lw = JS_GetPropertyStr(ctx, arg, "largeWindow");
    if (JS_IsException(lw))
        return -1;
    if (!JS_IsUndefined(lw))
        large = JS_ToBool(ctx, lw);
    JS_FreeValue(ctx, lw);
    o->large_window = large;

    if (tjs_brotli_get_int(ctx, arg, "quality", &o->quality, &present) < 0)
        return -1;
    if (present && (o->quality < BROTLI_MIN_QUALITY || o->quality > BROTLI_MAX_QUALITY)) {
        JS_ThrowRangeError(ctx, "quality must be between 0 and 11");
        return -1;
    }

    if (tjs_brotli_get_int(ctx, arg, "lgwin", &o->lgwin, &present) < 0)
        return -1;
    if (present) {
        int max = large ? BROTLI_LARGE_MAX_WINDOW_BITS : BROTLI_MAX_WINDOW_BITS;
        if (o->lgwin < BROTLI_MIN_WINDOW_BITS || o->lgwin > max) {
            JS_ThrowRangeError(ctx, "lgwin must be between 10 and %d", max);
            return -1;
        }
    }

    if (tjs_brotli_get_int(ctx, arg, "mode", &o->mode, &present) < 0)
        return -1;
    if (present && (o->mode < BROTLI_MODE_GENERIC || o->mode > BROTLI_MODE_FONT)) {
        JS_ThrowRangeError(ctx, "mode must be 0 (generic), 1 (text), or 2 (font)");
        return -1;
    }

    if (tjs_brotli_get_int(ctx, arg, "lgblock", &o->lgblock, &present) < 0)
        return -1;
    if (present && o->lgblock != 0 &&
        (o->lgblock < BROTLI_MIN_INPUT_BLOCK_BITS || o->lgblock > BROTLI_MAX_INPUT_BLOCK_BITS)) {
        JS_ThrowRangeError(ctx, "lgblock must be 0 or between %d and %d",
                           BROTLI_MIN_INPUT_BLOCK_BITS, BROTLI_MAX_INPUT_BLOCK_BITS);
        return -1;
    }

    JSValue sh = JS_GetPropertyStr(ctx, arg, "sizeHint");
    if (JS_IsException(sh))
        return -1;
    if (!JS_IsUndefined(sh)) {
        int64_t hint;
        int r = JS_ToInt64(ctx, &hint, sh);
        JS_FreeValue(ctx, sh);
        if (r < 0)
            return -1;
        if (hint < 0) {
            JS_ThrowRangeError(ctx, "sizeHint must be non-negative");
            return -1;
        }
        o->size_hint = hint;
    } else {
        JS_FreeValue(ctx, sh);
    }

    return 0;
}

/* Create and configure an encoder from parsed options. size_hint, when auto
 * (-1), is filled from data_len so one-shot compression gets the hint too. */
static BrotliEncoderState *tjs_brotli_make_encoder(const TJSBrotliOpts *o, size_t data_len) {
    BrotliEncoderState *s = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (!s)
        return NULL;

    BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, (uint32_t)o->quality);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_MODE, (uint32_t)o->mode);
    if (o->large_window)
        BrotliEncoderSetParameter(s, BROTLI_PARAM_LARGE_WINDOW, 1);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_LGWIN, (uint32_t)o->lgwin);
    if (o->lgblock)
        BrotliEncoderSetParameter(s, BROTLI_PARAM_LGBLOCK, (uint32_t)o->lgblock);

    int64_t hint = o->size_hint >= 0 ? o->size_hint : (int64_t)data_len;
    if (hint > UINT32_MAX)
        hint = UINT32_MAX;
    BrotliEncoderSetParameter(s, BROTLI_PARAM_SIZE_HINT, (uint32_t)hint);

    return s;
}

/* Run a configured encoder over the whole input to a finished stream. Consumes
 * (takes ownership of) the encoder state. Returns a Uint8Array or exception. */
static JSValue tjs_brotli_encode_all(JSContext *ctx, BrotliEncoderState *s, const uint8_t *data, size_t data_len) {
    size_t out_size = BrotliEncoderMaxCompressedSize(data_len);
    if (out_size < 1024)
        out_size = 1024;

    uint8_t *out = js_malloc(ctx, out_size);
    if (!out) {
        BrotliEncoderDestroyInstance(s);
        return JS_EXCEPTION;
    }

    const uint8_t *next_in = data ? data : (const uint8_t *)"";
    size_t avail_in = data_len;
    size_t produced = 0;

    for (;;) {
        uint8_t *next_out = out + produced;
        size_t avail_out = out_size - produced;

        BROTLI_BOOL ok = BrotliEncoderCompressStream(
            s, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, NULL);
        if (!ok) {
            js_free(ctx, out);
            BrotliEncoderDestroyInstance(s);
            return JS_ThrowInternalError(ctx, "Brotli compression failed");
        }

        produced = out_size - avail_out;

        if (BrotliEncoderIsFinished(s))
            break;

        if (produced == out_size) {
            if (out_size > SIZE_MAX / 2) {
                js_free(ctx, out);
                BrotliEncoderDestroyInstance(s);
                return JS_ThrowInternalError(ctx, "Brotli compressed output too large");
            }
            size_t new_size = out_size * 2;
            uint8_t *new_out = js_realloc(ctx, out, new_size);
            if (!new_out) {
                js_free(ctx, out);
                BrotliEncoderDestroyInstance(s);
                return JS_EXCEPTION;
            }
            out = new_out;
            out_size = new_size;
        }
    }

    BrotliEncoderDestroyInstance(s);

    if (produced == 0) {
        js_free(ctx, out);
        return tjs_brotli_empty_buffer(ctx);
    }
    if (produced < out_size) {
        uint8_t *trim = js_realloc(ctx, out, produced);
        if (trim)
            out = trim;
    }
    return TJS_NewUint8Array(ctx, out, produced);
}

/* One-shot compress: compress(data, {quality, lgwin, mode, lgblock, sizeHint, largeWindow}) */
static JSValue tjs_brotli_compress(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    size_t data_len;
    const uint8_t *data;
    TJSBrotliOpts o;
    tjs_brotli_opts_default(&o);

    if (argc < 1)
        return JS_ThrowTypeError(ctx, "compress() requires 1 argument: data");

    /* Parse options before getting the buffer pointer (may run user code) */
    if (argc >= 2 && tjs_brotli_parse_opts(ctx, argv[1], &o) < 0)
        return JS_EXCEPTION;

    data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
    if (!data)
        return JS_EXCEPTION;

    BrotliEncoderState *s = tjs_brotli_make_encoder(&o, data_len);
    if (!s)
        return JS_ThrowInternalError(ctx, "Failed to create Brotli encoder");

    return tjs_brotli_encode_all(ctx, s, data, data_len);
}

/* One-shot decompress with growable output (max 256MB) */
static JSValue tjs_brotli_decompress(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    size_t data_len;
    const uint8_t *data;
    int large_window = 0;

    if (argc < 1)
        return JS_ThrowTypeError(ctx, "decompress() requires 1 argument: data");

    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue lw = JS_GetPropertyStr(ctx, argv[1], "largeWindow");
        if (JS_IsException(lw))
            return JS_EXCEPTION;
        if (!JS_IsUndefined(lw))
            large_window = JS_ToBool(ctx, lw);
        JS_FreeValue(ctx, lw);
    }

    data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
    if (!data)
        return JS_EXCEPTION;

    if (data_len > SIZE_MAX / 4)
        return JS_ThrowInternalError(ctx, "Brotli input too large");

    size_t out_size = data_len * 4;
    if (out_size < 4096)
        out_size = 4096;

    uint8_t *out = js_malloc(ctx, out_size);
    if (!out)
        return JS_EXCEPTION;

    BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!state) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Failed to create Brotli decoder");
    }
    if (large_window)
        BrotliDecoderSetParameter(state, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1);

    const uint8_t *next_in = data;
    size_t avail_in = data_len;
    uint8_t *next_out = out;
    size_t avail_out = out_size;
    size_t total_out = 0;

    for (;;) {
        BrotliDecoderResult ret = BrotliDecoderDecompressStream(
            state, &avail_in, &next_in, &avail_out, &next_out, &total_out);

        if (ret == BROTLI_DECODER_RESULT_SUCCESS)
            break;

        if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            if (out_size > BROTLI_MAX_OUTPUT) {
                BrotliDecoderDestroyInstance(state);
                js_free(ctx, out);
                return JS_ThrowRangeError(ctx, "Brotli decompressed output exceeds maximum size (256MB)");
            }
            size_t used = out_size - avail_out;
            size_t new_size = out_size * 2;
            if (new_size < out_size) {
                BrotliDecoderDestroyInstance(state);
                js_free(ctx, out);
                return JS_ThrowInternalError(ctx, "Brotli decompressed output too large");
            }
            uint8_t *new_out = js_realloc(ctx, out, new_size);
            if (!new_out) {
                BrotliDecoderDestroyInstance(state);
                js_free(ctx, out);
                return JS_EXCEPTION;
            }
            out = new_out;
            out_size = new_size;
            next_out = out + used;
            avail_out = out_size - used;
            continue;
        }

        if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
            BrotliDecoderDestroyInstance(state);
            js_free(ctx, out);
            return JS_ThrowInternalError(ctx, "Brotli decompression incomplete input");
        }

        BrotliDecoderErrorCode ec = BrotliDecoderGetErrorCode(state);
        const char *msg = BrotliDecoderErrorString(ec);
        BrotliDecoderDestroyInstance(state);
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Brotli decompression failed: %s", msg);
    }

    BrotliDecoderDestroyInstance(state);

    if (total_out == 0) {
        js_free(ctx, out);
        return tjs_brotli_empty_buffer(ctx);
    }
    if (total_out < out_size) {
        uint8_t *trim = js_realloc(ctx, out, total_out);
        if (trim)
            out = trim;
    }
    return TJS_NewUint8Array(ctx, out, total_out);
}

/* maxCompressedSize(length) - upper bound on compressed output for length bytes */
static JSValue tjs_brotli_max_compressed_size(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    int64_t len;
    if (argc < 1 || JS_ToInt64(ctx, &len, argv[0]) < 0)
        return JS_EXCEPTION;
    if (len < 0)
        return JS_ThrowRangeError(ctx, "length must be non-negative");
    return JS_NewInt64(ctx, (int64_t)BrotliEncoderMaxCompressedSize((size_t)len));
}

/* Class IDs */
static thread_local JSClassID tjs_brotli_compress_class_id;
static thread_local JSClassID tjs_brotli_decompress_class_id;

/* Streaming Brotli encoder object */
typedef struct {
    BrotliEncoderState *state;
    int finished;
    uint64_t total_in;
    uint64_t total_out;
} TJSBrotliCompress;

static void tjs_brotli_compress_finalizer(JSRuntime *rt, JSValue val) {
    TJSBrotliCompress *c = JS_GetOpaque(val, tjs_brotli_compress_class_id);
    if (c) {
        if (c->state)
            BrotliEncoderDestroyInstance(c->state);
        js_free_rt(rt, c);
    }
}

static JSClassDef tjs_brotli_compress_class = {
    "BrotliCompress",
    .finalizer = tjs_brotli_compress_finalizer,
};

/* Streaming Brotli decoder object */
typedef struct {
    BrotliDecoderState *state;
    int finished;
    uint64_t total_in;
    uint64_t total_out;
} TJSBrotliDecompress;

static void tjs_brotli_decompress_finalizer(JSRuntime *rt, JSValue val) {
    TJSBrotliDecompress *d = JS_GetOpaque(val, tjs_brotli_decompress_class_id);
    if (d) {
        if (d->state)
            BrotliDecoderDestroyInstance(d->state);
        js_free_rt(rt, d);
    }
}

static JSClassDef tjs_brotli_decompress_class = {
    "BrotliDecompress",
    .finalizer = tjs_brotli_decompress_finalizer,
};

/* createCompress({quality, lgwin, mode, lgblock, sizeHint, largeWindow}) */
static JSValue tjs_brotli_create_compress(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSBrotliOpts o;
    tjs_brotli_opts_default(&o);

    if (argc >= 1 && tjs_brotli_parse_opts(ctx, argv[0], &o) < 0)
        return JS_EXCEPTION;

    TJSBrotliCompress *c = js_mallocz(ctx, sizeof(*c));
    if (!c)
        return JS_EXCEPTION;

    /* size_hint stays auto (0) for streams: total input is unknown up front */
    c->state = tjs_brotli_make_encoder(&o, 0);
    if (!c->state) {
        js_free(ctx, c);
        return JS_ThrowInternalError(ctx, "Failed to create Brotli encoder");
    }

    JSValue obj = JS_NewObjectClass(ctx, tjs_brotli_compress_class_id);
    if (JS_IsException(obj)) {
        BrotliEncoderDestroyInstance(c->state);
        js_free(ctx, c);
        return obj;
    }

    JS_SetOpaque(obj, c);
    return obj;
}

/* createDecompress({largeWindow}) */
static JSValue tjs_brotli_create_decompress(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    int large_window = 0;
    if (argc >= 1 && JS_IsObject(argv[0])) {
        JSValue lw = JS_GetPropertyStr(ctx, argv[0], "largeWindow");
        if (JS_IsException(lw))
            return JS_EXCEPTION;
        if (!JS_IsUndefined(lw))
            large_window = JS_ToBool(ctx, lw);
        JS_FreeValue(ctx, lw);
    }

    TJSBrotliDecompress *d = js_mallocz(ctx, sizeof(*d));
    if (!d)
        return JS_EXCEPTION;

    d->state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!d->state) {
        js_free(ctx, d);
        return JS_ThrowInternalError(ctx, "Failed to create Brotli decoder");
    }
    if (large_window)
        BrotliDecoderSetParameter(d->state, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1);

    JSValue obj = JS_NewObjectClass(ctx, tjs_brotli_decompress_class_id);
    if (JS_IsException(obj)) {
        BrotliDecoderDestroyInstance(d->state);
        js_free(ctx, d);
        return obj;
    }

    JS_SetOpaque(obj, d);
    return obj;
}

/* BrotliCompress.compress()/flush()/finish() - process data. Op from magic. */
static JSValue tjs_brotli_compress_process(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic) {
    TJSBrotliCompress *c = JS_GetOpaque2(ctx, this_val, tjs_brotli_compress_class_id);
    if (!c)
        return JS_EXCEPTION;

    if (c->finished)
        return JS_ThrowInternalError(ctx, "Brotli compress stream already finished");

    BrotliEncoderOperation op = magic;

    size_t data_len = 0;
    const uint8_t *data = NULL;
    if (argc >= 1 && !JS_IsUndefined(argv[0])) {
        data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
        if (!data)
            return JS_EXCEPTION;
    }

    size_t out_size = data_len + (data_len >> 1) + 1024;
    uint8_t *out = js_malloc(ctx, out_size);
    if (!out)
        return JS_EXCEPTION;

    const uint8_t *next_in = data;
    size_t avail_in = data_len;
    size_t produced = 0;

    for (;;) {
        uint8_t *next_out = out + produced;
        size_t avail_out = out_size - produced;

        BROTLI_BOOL ok = BrotliEncoderCompressStream(
            c->state, op, &avail_in, &next_in, &avail_out, &next_out, NULL);
        if (!ok) {
            js_free(ctx, out);
            return JS_ThrowInternalError(ctx, "Brotli compress failed");
        }

        produced = out_size - avail_out;

        /* Done when all input consumed and the encoder has nothing buffered */
        if (avail_in == 0 && !BrotliEncoderHasMoreOutput(c->state))
            break;

        if (produced == out_size) {
            if (out_size > SIZE_MAX / 2) {
                js_free(ctx, out);
                return JS_ThrowInternalError(ctx, "Brotli compressed output too large");
            }
            size_t new_size = out_size * 2;
            uint8_t *new_out = js_realloc(ctx, out, new_size);
            if (!new_out) {
                js_free(ctx, out);
                return JS_EXCEPTION;
            }
            out = new_out;
            out_size = new_size;
        }
    }

    c->total_in += data_len;
    c->total_out += produced;
    if (op == BROTLI_OPERATION_FINISH && BrotliEncoderIsFinished(c->state))
        c->finished = 1;

    if (produced == 0) {
        js_free(ctx, out);
        return tjs_brotli_empty_buffer(ctx);
    }
    uint8_t *out_copy = js_malloc(ctx, produced);
    if (!out_copy) {
        js_free(ctx, out);
        return JS_EXCEPTION;
    }
    memcpy(out_copy, out, produced);
    js_free(ctx, out);

    return TJS_NewUint8Array(ctx, out_copy, produced);
}

/* BrotliCompress.getTotalIn() */
static JSValue tjs_brotli_compress_total_in(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSBrotliCompress *c = JS_GetOpaque2(ctx, this_val, tjs_brotli_compress_class_id);
    if (!c)
        return JS_EXCEPTION;
    return JS_NewInt64(ctx, (int64_t)c->total_in);
}

/* BrotliCompress.getTotalOut() */
static JSValue tjs_brotli_compress_total_out(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSBrotliCompress *c = JS_GetOpaque2(ctx, this_val, tjs_brotli_compress_class_id);
    if (!c)
        return JS_EXCEPTION;
    return JS_NewInt64(ctx, (int64_t)c->total_out);
}

static const JSCFunctionListEntry tjs_brotli_compress_proto_funcs[] = {
    JS_CFUNC_MAGIC_DEF("compress", 1, tjs_brotli_compress_process, BROTLI_OPERATION_PROCESS),
    JS_CFUNC_MAGIC_DEF("flush", 0, tjs_brotli_compress_process, BROTLI_OPERATION_FLUSH),
    JS_CFUNC_MAGIC_DEF("finish", 0, tjs_brotli_compress_process, BROTLI_OPERATION_FINISH),
    JS_CFUNC_DEF("getTotalIn", 0, tjs_brotli_compress_total_in),
    JS_CFUNC_DEF("getTotalOut", 0, tjs_brotli_compress_total_out),
};

/* BrotliDecompress.decompress() - process data */
static JSValue tjs_brotli_decompress_process(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic) {
    TJSBrotliDecompress *d = JS_GetOpaque2(ctx, this_val, tjs_brotli_decompress_class_id);
    if (!d)
        return JS_EXCEPTION;

    if (d->finished && magic != 1)
        return JS_ThrowInternalError(ctx, "Brotli decompress stream already finished");
    if (d->finished)
        return tjs_brotli_empty_buffer(ctx);

    if (argc < 1 && magic != 1)
        return JS_ThrowTypeError(ctx, "decompress() requires 1 argument: data");

    size_t data_len = 0;
    const uint8_t *data = NULL;
    if (argc >= 1 && !JS_IsUndefined(argv[0])) {
        data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
        if (!data)
            return JS_EXCEPTION;
    }

    if (data_len > SIZE_MAX / 4)
        return JS_ThrowInternalError(ctx, "Brotli input too large");

    size_t out_size = data_len * 4;
    if (out_size < 4096)
        out_size = 4096;

    uint8_t *out = js_malloc(ctx, out_size);
    if (!out)
        return JS_EXCEPTION;

    const uint8_t *next_in = data ? data : (const uint8_t *)"";
    size_t avail_in = data_len;
    size_t produced = 0;

    for (;;) {
        uint8_t *next_out = out + produced;
        size_t avail_out = out_size - produced;
        size_t total_out = 0;

        BrotliDecoderResult ret = BrotliDecoderDecompressStream(
            d->state, &avail_in, &next_in, &avail_out, &next_out, &total_out);

        produced = out_size - avail_out;

        if (ret == BROTLI_DECODER_RESULT_SUCCESS) {
            d->finished = 1;
            break;
        }

        if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && magic == 1) {
            js_free(ctx, out);
            return JS_ThrowInternalError(ctx, "Brotli decompression incomplete input");
        }

        if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
            break;  /* Consumed this chunk; await more via a later call */

        if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            if (out_size > BROTLI_MAX_OUTPUT) {
                js_free(ctx, out);
                return JS_ThrowRangeError(ctx, "Brotli decompressed output exceeds maximum size (256MB)");
            }
            size_t new_size = out_size * 2;
            if (new_size < out_size) {
                js_free(ctx, out);
                return JS_ThrowInternalError(ctx, "Brotli decompressed output too large");
            }
            uint8_t *new_out = js_realloc(ctx, out, new_size);
            if (!new_out) {
                js_free(ctx, out);
                return JS_EXCEPTION;
            }
            out = new_out;
            out_size = new_size;
            continue;
        }

        BrotliDecoderErrorCode ec = BrotliDecoderGetErrorCode(d->state);
        const char *msg = BrotliDecoderErrorString(ec);
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Brotli decompression failed: %s", msg);
    }

    d->total_in += data_len - avail_in;
    d->total_out += produced;

    if (produced == 0) {
        js_free(ctx, out);
        return tjs_brotli_empty_buffer(ctx);
    }
    uint8_t *out_copy = js_malloc(ctx, produced);
    if (!out_copy) {
        js_free(ctx, out);
        return JS_EXCEPTION;
    }
    memcpy(out_copy, out, produced);
    js_free(ctx, out);

    return TJS_NewUint8Array(ctx, out_copy, produced);
}

/* BrotliDecompress.getTotalIn() */
static JSValue tjs_brotli_decompress_total_in(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSBrotliDecompress *d = JS_GetOpaque2(ctx, this_val, tjs_brotli_decompress_class_id);
    if (!d)
        return JS_EXCEPTION;
    return JS_NewInt64(ctx, (int64_t)d->total_in);
}

/* BrotliDecompress.getTotalOut() */
static JSValue tjs_brotli_decompress_total_out(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    TJSBrotliDecompress *d = JS_GetOpaque2(ctx, this_val, tjs_brotli_decompress_class_id);
    if (!d)
        return JS_EXCEPTION;
    return JS_NewInt64(ctx, (int64_t)d->total_out);
}

static const JSCFunctionListEntry tjs_brotli_decompress_proto_funcs[] = {
    JS_CFUNC_MAGIC_DEF("decompress", 1, tjs_brotli_decompress_process, 0),
    JS_CFUNC_MAGIC_DEF("finish", 0, tjs_brotli_decompress_process, 1),
    JS_CFUNC_DEF("getTotalIn", 0, tjs_brotli_decompress_total_in),
    JS_CFUNC_DEF("getTotalOut", 0, tjs_brotli_decompress_total_out),
};

/* Module function list */
static const JSCFunctionListEntry tjs_brotli_funcs[] = {
    /* One-shot */
    JS_CFUNC_DEF("compress", 2, tjs_brotli_compress),
    JS_CFUNC_DEF("decompress", 2, tjs_brotli_decompress),

    /* Streaming */
    JS_CFUNC_DEF("createCompress", 1, tjs_brotli_create_compress),
    JS_CFUNC_DEF("createDecompress", 1, tjs_brotli_create_decompress),

    /* Utility */
    JS_CFUNC_DEF("maxCompressedSize", 1, tjs_brotli_max_compressed_size),

    JS_PROP_INT32_DEF("available", 1, JS_PROP_CONFIGURABLE),

    /* Quality */
    JS_PROP_INT32_DEF("MIN_QUALITY", BROTLI_MIN_QUALITY, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("MAX_QUALITY", BROTLI_MAX_QUALITY, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("DEFAULT_QUALITY", BROTLI_DEFAULT_QUALITY, JS_PROP_CONFIGURABLE),

    /* Window bits */
    JS_PROP_INT32_DEF("MIN_WINDOW_BITS", BROTLI_MIN_WINDOW_BITS, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("MAX_WINDOW_BITS", BROTLI_MAX_WINDOW_BITS, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("LARGE_MAX_WINDOW_BITS", BROTLI_LARGE_MAX_WINDOW_BITS, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("DEFAULT_WINDOW", BROTLI_DEFAULT_WINDOW, JS_PROP_CONFIGURABLE),

    /* Input block bits (lgblock) */
    JS_PROP_INT32_DEF("MIN_INPUT_BLOCK_BITS", BROTLI_MIN_INPUT_BLOCK_BITS, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("MAX_INPUT_BLOCK_BITS", BROTLI_MAX_INPUT_BLOCK_BITS, JS_PROP_CONFIGURABLE),

    /* Mode */
    JS_PROP_INT32_DEF("MODE_GENERIC", BROTLI_MODE_GENERIC, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("MODE_TEXT", BROTLI_MODE_TEXT, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("MODE_FONT", BROTLI_MODE_FONT, JS_PROP_CONFIGURABLE),

    /* Stream operations */
    JS_PROP_INT32_DEF("OPERATION_PROCESS", BROTLI_OPERATION_PROCESS, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("OPERATION_FLUSH", BROTLI_OPERATION_FLUSH, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("OPERATION_FINISH", BROTLI_OPERATION_FINISH, JS_PROP_CONFIGURABLE),
};

void tjs__mod_brotli_init(JSContext *ctx, JSValue ns) {
    /* BrotliCompress class */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_brotli_compress_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_brotli_compress_class_id, &tjs_brotli_compress_class);
    JSValue compress_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, compress_proto, tjs_brotli_compress_proto_funcs,
                               countof(tjs_brotli_compress_proto_funcs));
    JS_SetClassProto(ctx, tjs_brotli_compress_class_id, compress_proto);

    /* BrotliDecompress class */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_brotli_decompress_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_brotli_decompress_class_id, &tjs_brotli_decompress_class);
    JSValue decompress_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, decompress_proto, tjs_brotli_decompress_proto_funcs,
                               countof(tjs_brotli_decompress_proto_funcs));
    JS_SetClassProto(ctx, tjs_brotli_decompress_class_id, decompress_proto);

    JS_SetPropertyFunctionList(ctx, ns, tjs_brotli_funcs, countof(tjs_brotli_funcs));

    /* Runtime version string, e.g. "1.1.0" */
    uint32_t v = BrotliEncoderVersion();
    char ver[32];
    snprintf(ver, sizeof(ver), "%u.%u.%u", (v >> 24) & 0xFFF, (v >> 12) & 0xFFF, v & 0xFFF);
    JS_DefinePropertyValueStr(ctx, ns, "version", JS_NewString(ctx, ver), JS_PROP_C_W_E);
}

#else /* !CJS_HAVE_BROTLI */

/* Brotli unavailable at build time: expose only a feature-detection flag. */
void tjs__mod_brotli_init(JSContext *ctx, JSValue ns) {
    JS_DefinePropertyValueStr(ctx, ns, "available", JS_NewBool(ctx, 0), JS_PROP_C_W_E);
}

#endif /* CJS_HAVE_BROTLI */
