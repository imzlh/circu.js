/**
 * Circu.js zlib compression/decompression module
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
#include <zlib.h>

/* Magic values for compression methods */
enum {
    METHOD_DEFLATE = 0,
    METHOD_GZIP,
    METHOD_RAW_DEFLATE,
};

/* Magic values for compression levels */
enum {
    LEVEL_DEFAULT = Z_DEFAULT_COMPRESSION,
    LEVEL_NO = Z_NO_COMPRESSION,
    LEVEL_BEST_SPEED = Z_BEST_SPEED,
    LEVEL_BEST = Z_BEST_COMPRESSION,
};

/* Magic values for strategy */
enum {
    STRATEGY_DEFAULT = Z_DEFAULT_STRATEGY,
    STRATEGY_FILTERED = Z_FILTERED,
    STRATEGY_HUFFMAN_ONLY = Z_HUFFMAN_ONLY,
    STRATEGY_RLE = Z_RLE,
    STRATEGY_FIXED = Z_FIXED,
};

/* Magic values for flush modes */
enum {
    FLUSH_NO = Z_NO_FLUSH,
    FLUSH_PARTIAL = Z_PARTIAL_FLUSH,
    FLUSH_SYNC = Z_SYNC_FLUSH,
    FLUSH_FULL = Z_FULL_FLUSH,
    FLUSH_FINISH = Z_FINISH,
    FLUSH_BLOCK = Z_BLOCK,
    FLUSH_TREES = Z_TREES,
};

/* Get window bits from method magic */
static int get_window_bits(int method) {
    switch (method) {
        case METHOD_DEFLATE:
            return 15;  /* Standard deflate */
        case METHOD_GZIP:
            return 15 + 16;  /* Add 16 for gzip header */
        case METHOD_RAW_DEFLATE:
            return -15;  /* Negative for raw deflate */
        default:
            return 15;
    }
}

/* One-shot compression */
static JSValue tjs_zlib_compress(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t data_len;
    const uint8_t* data;
    int level = Z_DEFAULT_COMPRESSION;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "compress() requires at least 1 argument: data");
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &level, argv[1]) < 0) {
            return JS_EXCEPTION;
        }
        if (level < -1 || level > 9) {
            return JS_ThrowRangeError(ctx, "Level must be between -1 and 9");
        }
    }
    
    int method = magic & 0xFF;
    int window_bits = get_window_bits(method);
    
    /* Calculate maximum output size */
    uLong bound = deflateBound(NULL, data_len);
    if (method == METHOD_GZIP) {
        bound += 18;  /* Extra space for gzip header/footer */
    }
    
    uint8_t* out = js_malloc(ctx, bound);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    z_stream strm = {0};
    strm.next_in = (Bytef*)data;
    strm.avail_in = data_len;
    strm.next_out = out;
    strm.avail_out = bound;
    
    int ret = deflateInit2(&strm, level, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Failed to initialize compression");
    }
    
    ret = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);
    
    if (ret != Z_STREAM_END) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Compression failed");
    }
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, strm.total_out);
    js_free(ctx, out);
    
    return result;
}

/* One-shot decompression */
static JSValue tjs_zlib_decompress(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t data_len;
    const uint8_t* data;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "decompress() requires 1 argument: data");
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    int method = magic & 0xFF;
    int window_bits = get_window_bits(method);
    
    /* Initial output buffer size (will grow if needed) */
    size_t out_size = data_len * 4;
    if (out_size < 4096) out_size = 4096;
    
    uint8_t* out = js_malloc(ctx, out_size);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    z_stream strm = {0};
    strm.next_in = (Bytef*)data;
    strm.avail_in = data_len;
    strm.next_out = out;
    strm.avail_out = out_size;
    
    int ret = inflateInit2(&strm, window_bits);
    if (ret != Z_OK) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Failed to initialize decompression");
    }
    
    /* Decompress with automatic buffer growth */
    while (1) {
        ret = inflate(&strm, Z_NO_FLUSH);
        
        if (ret == Z_STREAM_END) {
            break;
        }
        
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            inflateEnd(&strm);
            js_free(ctx, out);
            return JS_ThrowInternalError(ctx, "Decompression failed");
        }
        
        if (strm.avail_out == 0) {
            /* Need more output space */
            size_t new_size = out_size * 2;
            uint8_t* new_out = js_realloc(ctx, out, new_size);
            if (!new_out) {
                inflateEnd(&strm);
                js_free(ctx, out);
                return JS_EXCEPTION;
            }
            out = new_out;
            strm.next_out = out + out_size;
            strm.avail_out = out_size;
            out_size = new_size;
        }
    }
    
    inflateEnd(&strm);
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, strm.total_out);
    js_free(ctx, out);
    
    return result;
}

/* CRC32 computation */
static JSValue tjs_zlib_crc32(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t data_len;
    const uint8_t* data;
    uint32_t crc = 0;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "crc32() requires at least 1 argument: data");
    }
    
    /* Optional initial CRC value */
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToUint32(ctx, &crc, argv[1]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    crc = crc32(crc, data, data_len);
    
    return JS_NewUint32(ctx, crc);
}

/* Adler32 computation */
static JSValue tjs_zlib_adler32(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t data_len;
    const uint8_t* data;
    uint32_t adler = 1;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "adler32() requires at least 1 argument: data");
    }
    
    /* Optional initial Adler32 value */
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToUint32(ctx, &adler, argv[1]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    adler = adler32(adler, data, data_len);
    
    return JS_NewUint32(ctx, adler);
}

/* Class IDs */
static JSClassID tjs_deflate_class_id;
static JSClassID tjs_inflate_class_id;

/* Deflate stream object */
typedef struct {
    z_stream strm;
    int initialized;
    int finished;
} TJSDeflate;

static void tjs_deflate_finalizer(JSRuntime* rt, JSValue val) {
    TJSDeflate* d = JS_GetOpaque(val, tjs_deflate_class_id);
    if (d) {
        if (d->initialized) {
            deflateEnd(&d->strm);
        }
        js_free_rt(rt, d);
    }
}

static JSClassDef tjs_deflate_class = {
    "Deflate",
    .finalizer = tjs_deflate_finalizer,
};

/* Inflate stream object */
typedef struct {
    z_stream strm;
    int initialized;
    int finished;
} TJSInflate;

static void tjs_inflate_finalizer(JSRuntime* rt, JSValue val) {
    TJSInflate* i = JS_GetOpaque(val, tjs_inflate_class_id);
    if (i) {
        if (i->initialized) {
            inflateEnd(&i->strm);
        }
        js_free_rt(rt, i);
    }
}

static JSClassDef tjs_inflate_class = {
    "Inflate",
    .finalizer = tjs_inflate_finalizer,
};

/* Create deflate stream */
static JSValue tjs_zlib_create_deflate(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    int level = Z_DEFAULT_COMPRESSION;
    int strategy = Z_DEFAULT_STRATEGY;
    int mem_level = 8;
    
    /* Optional level */
    if (argc >= 1 && !JS_IsUndefined(argv[0])) {
        if (JS_ToInt32(ctx, &level, argv[0]) < 0) {
            return JS_EXCEPTION;
        }
        if (level < -1 || level > 9) {
            return JS_ThrowRangeError(ctx, "Level must be between -1 and 9");
        }
    }
    
    /* Optional strategy */
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &strategy, argv[1]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    /* Optional memory level */
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &mem_level, argv[2]) < 0) {
            return JS_EXCEPTION;
        }
        if (mem_level < 1 || mem_level > 9) {
            return JS_ThrowRangeError(ctx, "Memory level must be between 1 and 9");
        }
    }
    
    int method = magic & 0xFF;
    int window_bits = get_window_bits(method);
    
    TJSDeflate* d = js_mallocz(ctx, sizeof(*d));
    if (!d) {
        return JS_EXCEPTION;
    }
    
    int ret = deflateInit2(&d->strm, level, Z_DEFLATED, window_bits, mem_level, strategy);
    if (ret != Z_OK) {
        js_free(ctx, d);
        return JS_ThrowInternalError(ctx, "Failed to initialize deflate");
    }
    
    d->initialized = 1;
    d->finished = 0;
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_deflate_class_id);
    if (JS_IsException(obj)) {
        deflateEnd(&d->strm);
        js_free(ctx, d);
        return obj;
    }
    
    JS_SetOpaque(obj, d);
    return obj;
}

/* Create inflate stream */
static JSValue tjs_zlib_create_inflate(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    int method = magic & 0xFF;
    int window_bits = get_window_bits(method);
    
    TJSInflate* i = js_mallocz(ctx, sizeof(*i));
    if (!i) {
        return JS_EXCEPTION;
    }
    
    int ret = inflateInit2(&i->strm, window_bits);
    if (ret != Z_OK) {
        js_free(ctx, i);
        return JS_ThrowInternalError(ctx, "Failed to initialize inflate");
    }
    
    i->initialized = 1;
    i->finished = 0;
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_inflate_class_id);
    if (JS_IsException(obj)) {
        inflateEnd(&i->strm);
        js_free(ctx, i);
        return obj;
    }
    
    JS_SetOpaque(obj, i);
    return obj;
}

/* Deflate.deflate() - process data */
static JSValue tjs_deflate_process(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    TJSDeflate* d = JS_GetOpaque2(ctx, this_val, tjs_deflate_class_id);
    if (!d) {
        return JS_EXCEPTION;
    }
    
    if (d->finished) {
        return JS_ThrowInternalError(ctx, "Deflate stream already finished");
    }
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "deflate() requires at least 1 argument: data");
    }
    
    size_t data_len;
    const uint8_t* data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    int flush = magic;  /* Flush mode from magic */
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &flush, argv[1]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    /* Allocate output buffer */
    size_t out_size = deflateBound(&d->strm, data_len);
    if (out_size < 1024) out_size = 1024;
    
    uint8_t* out = js_malloc(ctx, out_size);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    d->strm.next_in = (Bytef*)data;
    d->strm.avail_in = data_len;
    d->strm.next_out = out;
    d->strm.avail_out = out_size;
    
    int ret = deflate(&d->strm, flush);
    
    if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Deflate failed");
    }
    
    if (ret == Z_STREAM_END) {
        d->finished = 1;
    }
    
    size_t produced = out_size - d->strm.avail_out;
    JSValue result = JS_NewArrayBufferCopy(ctx, out, produced);
    js_free(ctx, out);
    
    return result;
}

/* Deflate.reset() */
static JSValue tjs_deflate_reset(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSDeflate* d = JS_GetOpaque2(ctx, this_val, tjs_deflate_class_id);
    if (!d) {
        return JS_EXCEPTION;
    }
    
    if (deflateReset(&d->strm) != Z_OK) {
        return JS_ThrowInternalError(ctx, "Deflate reset failed");
    }
    
    d->finished = 0;
    
    return JS_UNDEFINED;
}

/* Deflate.params() - change compression parameters */
static JSValue tjs_deflate_params(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSDeflate* d = JS_GetOpaque2(ctx, this_val, tjs_deflate_class_id);
    if (!d) {
        return JS_EXCEPTION;
    }
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "params() requires 2 arguments: level and strategy");
    }
    
    int level, strategy;
    if (JS_ToInt32(ctx, &level, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    if (JS_ToInt32(ctx, &strategy, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (deflateParams(&d->strm, level, strategy) != Z_OK) {
        return JS_ThrowInternalError(ctx, "Failed to change deflate parameters");
    }
    
    return JS_UNDEFINED;
}

/* Deflate.getTotalIn() */
static JSValue tjs_deflate_total_in(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSDeflate* d = JS_GetOpaque2(ctx, this_val, tjs_deflate_class_id);
    if (!d) {
        return JS_EXCEPTION;
    }
    return JS_NewInt64(ctx, d->strm.total_in);
}

/* Deflate.getTotalOut() */
static JSValue tjs_deflate_total_out(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSDeflate* d = JS_GetOpaque2(ctx, this_val, tjs_deflate_class_id);
    if (!d) {
        return JS_EXCEPTION;
    }
    return JS_NewInt64(ctx, d->strm.total_out);
}

static const JSCFunctionListEntry tjs_deflate_proto_funcs[] = {
    JS_CFUNC_MAGIC_DEF("deflate", 2, tjs_deflate_process, Z_NO_FLUSH),
    JS_CFUNC_MAGIC_DEF("flush", 1, tjs_deflate_process, Z_SYNC_FLUSH),
    JS_CFUNC_MAGIC_DEF("finish", 1, tjs_deflate_process, Z_FINISH),
    JS_CFUNC_DEF("reset", 0, tjs_deflate_reset),
    JS_CFUNC_DEF("params", 2, tjs_deflate_params),
    JS_CFUNC_DEF("getTotalIn", 0, tjs_deflate_total_in),
    JS_CFUNC_DEF("getTotalOut", 0, tjs_deflate_total_out),
};

/* Inflate.inflate() - process data */
static JSValue tjs_inflate_process(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    TJSInflate* i = JS_GetOpaque2(ctx, this_val, tjs_inflate_class_id);
    if (!i) {
        return JS_EXCEPTION;
    }
    
    if (i->finished) {
        return JS_ThrowInternalError(ctx, "Inflate stream already finished");
    }
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "inflate() requires 1 argument: data");
    }
    
    size_t data_len;
    const uint8_t* data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    int flush = magic;  /* Flush mode from magic */
    
    /* Allocate output buffer with room to grow */
    size_t out_size = data_len * 4;
    if (out_size < 4096) out_size = 4096;
    
    uint8_t* out = js_malloc(ctx, out_size);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    i->strm.next_in = (Bytef*)data;
    i->strm.avail_in = data_len;
    i->strm.next_out = out;
    i->strm.avail_out = out_size;
    
    int ret;
    while (1) {
        ret = inflate(&i->strm, flush);
        
        if (ret == Z_STREAM_END) {
            i->finished = 1;
            break;
        }
        
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            js_free(ctx, out);
            return JS_ThrowInternalError(ctx, "Inflate failed");
        }
        
        if (i->strm.avail_out == 0) {
            /* Need more output space */
            size_t new_size = out_size * 2;
            uint8_t* new_out = js_realloc(ctx, out, new_size);
            if (!new_out) {
                js_free(ctx, out);
                return JS_EXCEPTION;
            }
            out = new_out;
            i->strm.next_out = out + out_size;
            i->strm.avail_out = out_size;
            out_size = new_size;
        } else {
            break;
        }
    }
    
    size_t produced = out_size - i->strm.avail_out;
    JSValue result = JS_NewArrayBufferCopy(ctx, out, produced);
    js_free(ctx, out);
    
    return result;
}

/* Inflate.reset() */
static JSValue tjs_inflate_reset(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSInflate* i = JS_GetOpaque2(ctx, this_val, tjs_inflate_class_id);
    if (!i) {
        return JS_EXCEPTION;
    }
    
    if (inflateReset(&i->strm) != Z_OK) {
        return JS_ThrowInternalError(ctx, "Inflate reset failed");
    }
    
    i->finished = 0;
    
    return JS_UNDEFINED;
}

/* Inflate.getTotalIn() */
static JSValue tjs_inflate_total_in(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSInflate* i = JS_GetOpaque2(ctx, this_val, tjs_inflate_class_id);
    if (!i) {
        return JS_EXCEPTION;
    }
    return JS_NewInt64(ctx, i->strm.total_in);
}

/* Inflate.getTotalOut() */
static JSValue tjs_inflate_total_out(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSInflate* i = JS_GetOpaque2(ctx, this_val, tjs_inflate_class_id);
    if (!i) {
        return JS_EXCEPTION;
    }
    return JS_NewInt64(ctx, i->strm.total_out);
}

static const JSCFunctionListEntry tjs_inflate_proto_funcs[] = {
    JS_CFUNC_MAGIC_DEF("inflate", 1, tjs_inflate_process, Z_NO_FLUSH),
    JS_CFUNC_MAGIC_DEF("flush", 0, tjs_inflate_process, Z_SYNC_FLUSH),
    JS_CFUNC_DEF("reset", 0, tjs_inflate_reset),
    JS_CFUNC_DEF("getTotalIn", 0, tjs_inflate_total_in),
    JS_CFUNC_DEF("getTotalOut", 0, tjs_inflate_total_out),
};

/* Module function list */
static const JSCFunctionListEntry tjs_zlib_funcs[] = {
    /* One-shot compression */
    JS_CFUNC_MAGIC_DEF("deflate", 2, tjs_zlib_compress, METHOD_DEFLATE),
    JS_CFUNC_MAGIC_DEF("gzip", 2, tjs_zlib_compress, METHOD_GZIP),
    JS_CFUNC_MAGIC_DEF("deflateRaw", 2, tjs_zlib_compress, METHOD_RAW_DEFLATE),
    
    /* One-shot decompression */
    JS_CFUNC_MAGIC_DEF("inflate", 1, tjs_zlib_decompress, METHOD_DEFLATE),
    JS_CFUNC_MAGIC_DEF("gunzip", 1, tjs_zlib_decompress, METHOD_GZIP),
    JS_CFUNC_MAGIC_DEF("inflateRaw", 1, tjs_zlib_decompress, METHOD_RAW_DEFLATE),
    
    /* Streaming compression */
    JS_CFUNC_MAGIC_DEF("createDeflate", 3, tjs_zlib_create_deflate, METHOD_DEFLATE),
    JS_CFUNC_MAGIC_DEF("createGzip", 3, tjs_zlib_create_deflate, METHOD_GZIP),
    JS_CFUNC_MAGIC_DEF("createDeflateRaw", 3, tjs_zlib_create_deflate, METHOD_RAW_DEFLATE),
    
    /* Streaming decompression */
    JS_CFUNC_MAGIC_DEF("createInflate", 0, tjs_zlib_create_inflate, METHOD_DEFLATE),
    JS_CFUNC_MAGIC_DEF("createGunzip", 0, tjs_zlib_create_inflate, METHOD_GZIP),
    JS_CFUNC_MAGIC_DEF("createInflateRaw", 0, tjs_zlib_create_inflate, METHOD_RAW_DEFLATE),
    
    /* Checksums */
    JS_CFUNC_DEF("crc32", 2, tjs_zlib_crc32),
    JS_CFUNC_DEF("adler32", 2, tjs_zlib_adler32),
    
    /* Constants */
    JS_PROP_INT32_DEF("NO_COMPRESSION", Z_NO_COMPRESSION, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("BEST_SPEED", Z_BEST_SPEED, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("BEST_COMPRESSION", Z_BEST_COMPRESSION, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("DEFAULT_COMPRESSION", Z_DEFAULT_COMPRESSION, JS_PROP_CONFIGURABLE),
    
    JS_PROP_INT32_DEF("FILTERED", Z_FILTERED, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("HUFFMAN_ONLY", Z_HUFFMAN_ONLY, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("RLE", Z_RLE, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("FIXED", Z_FIXED, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("DEFAULT_STRATEGY", Z_DEFAULT_STRATEGY, JS_PROP_CONFIGURABLE),
    
    JS_PROP_INT32_DEF("NO_FLUSH", Z_NO_FLUSH, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("PARTIAL_FLUSH", Z_PARTIAL_FLUSH, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("SYNC_FLUSH", Z_SYNC_FLUSH, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("FULL_FLUSH", Z_FULL_FLUSH, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("FINISH", Z_FINISH, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("BLOCK", Z_BLOCK, JS_PROP_CONFIGURABLE),
};

void tjs__mod_zlib_init(JSContext* ctx, JSValue ns) {
    /* Initialize Deflate class */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_deflate_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_deflate_class_id, &tjs_deflate_class);
    JSValue deflate_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, deflate_proto, tjs_deflate_proto_funcs, countof(tjs_deflate_proto_funcs));
    JS_SetClassProto(ctx, tjs_deflate_class_id, deflate_proto);
    
    /* Initialize Inflate class */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_inflate_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_inflate_class_id, &tjs_inflate_class);
    JSValue inflate_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, inflate_proto, tjs_inflate_proto_funcs, countof(tjs_inflate_proto_funcs));
    JS_SetClassProto(ctx, tjs_inflate_class_id, inflate_proto);
    
    /* Set zlib functions and constants */
    JS_SetPropertyFunctionList(ctx, ns, tjs_zlib_funcs, countof(tjs_zlib_funcs));
}