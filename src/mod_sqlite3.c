/*
 * circu.js
 *
 * Copyright (c) 2023-present Saúl Ibarra Corretgé <s@saghul.net>
 * Copyright (c) 2025-2026 iz
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

#include <sqlite3.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>

#define TJS_SQLITE3_MAX_SAFE_INTEGER INT64_C(9007199254740991)

static thread_local JSClassID tjs_sqlite3_class_id;

typedef struct {
    sqlite3 *handle;
} TJSSqlite3Handle;

static void tjs_sqlite3_finalizer(JSRuntime *rt, JSValue val) {
    TJSSqlite3Handle *h = JS_GetOpaque(val, tjs_sqlite3_class_id);
    if (!h) {
        return;
    }
    if (h->handle) {
        sqlite3_close_v2(h->handle);
    }
    js_free_rt(rt, h);
}

static JSClassDef tjs_sqlite3_class = {
    "Handle",
    .finalizer = tjs_sqlite3_finalizer,
};

static JSValue tjs_new_sqlite3(JSContext *ctx, sqlite3 *handle) {
    TJSSqlite3Handle *h;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_sqlite3_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    h = js_mallocz(ctx, sizeof(*h));
    if (!h) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    h->handle = handle;

    JS_SetOpaque(obj, h);
    return obj;
}

static TJSSqlite3Handle *tjs_sqlite3_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_sqlite3_class_id);
}

static TJSSqlite3Handle *tjs_sqlite3_get_open(JSContext *ctx, JSValue obj) {
    TJSSqlite3Handle *h = tjs_sqlite3_get(ctx, obj);
    if (!h) {
        return NULL;
    }
    if (!h->handle) {
        JS_ThrowInternalError(ctx, "database closed");
        return NULL;
    }
    return h;
}

static thread_local JSClassID tjs_sqlite3_stmt_class_id;

typedef struct {
    sqlite3_stmt *stmt;
} TJSSqlite3Stmt;

static void tjs_sqlite3_stmt_finalizer(JSRuntime *rt, JSValue val) {
    TJSSqlite3Stmt *h = JS_GetOpaque(val, tjs_sqlite3_stmt_class_id);
    if (!h) {
        return;
    }
    if (h->stmt) {
        sqlite3_reset(h->stmt);
        sqlite3_finalize(h->stmt);
    }
    js_free_rt(rt, h);
}

static JSClassDef tjs_sqlite3_stmt_class = {
    "Statement",
    .finalizer = tjs_sqlite3_stmt_finalizer,
};

static JSValue tjs_new_sqlite3_stmt(JSContext *ctx, sqlite3_stmt *stmt) {
    TJSSqlite3Stmt *h;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_sqlite3_stmt_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    h = js_mallocz(ctx, sizeof(*h));
    if (!h) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    h->stmt = stmt;

    JS_SetOpaque(obj, h);
    return obj;
}

static TJSSqlite3Stmt *tjs_sqlite3_stmt_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_sqlite3_stmt_class_id);
}

JSValue tjs_throw_sqlite3_errno(JSContext *ctx, int err) {
    JSValue obj;
    obj = JS_NewError(ctx);
    JS_DefinePropertyValueStr(ctx,
                              obj,
                              "message",
                              JS_NewString(ctx, sqlite3_errstr(err)),
                              JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, obj, "errno", JS_NewInt32(ctx, err), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    if (JS_IsException(obj)) {
        obj = JS_NULL;
    }
    return JS_Throw(ctx, obj);
}

static JSValue tjs_sqlite3_open(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    const char *db_name = JS_ToCString(ctx, argv[0]);

    if (!db_name) {
        return JS_EXCEPTION;
    }

    int flags;
    if (JS_ToInt32(ctx, &flags, argv[1])) {
        JS_FreeCString(ctx, db_name);
        return JS_EXCEPTION;
    }

    sqlite3 *handle = NULL;
    int r = sqlite3_open_v2(db_name, &handle, flags, NULL);

    JS_FreeCString(ctx, db_name);

    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    // Enable sqlite extensions (but only via C calls)
#ifdef SQLITE_HAS_LOAD_EXTENSION
    r = sqlite3_db_config(handle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL);
    if (r != SQLITE_OK) {
        sqlite3_close_v2(handle);
        return tjs_throw_sqlite3_errno(ctx, r);
    }
#endif

    JSValue obj = tjs_new_sqlite3(ctx, handle);
    if (JS_IsException(obj)) {
        sqlite3_close_v2(handle);
    }

    return obj;
}

static JSValue tjs_sqlite3_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }
    if (!h->handle) {
        return JS_UNDEFINED;
    }

    int r = sqlite3_close_v2(h->handle);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    h->handle = NULL;

    return JS_UNDEFINED;
}

#ifdef SQLITE_HAS_LOAD_EXTENSION
static JSValue tjs_sqlite3_load_extension(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    const char *zFile = JS_ToCString(ctx, argv[0]);
    if (!zFile) {
        return JS_EXCEPTION;
    }
    const char *zProc = JS_IsUndefined(argv[1]) ? NULL : JS_ToCString(ctx, argv[1]);
    if (!JS_IsUndefined(argv[1]) && !zProc) {
        JS_FreeCString(ctx, zFile);
        return JS_EXCEPTION;
    }

    // zProc can be 0, it means "sqlite, do your best to quess it"

    int r = sqlite3_db_config(h->handle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 1, NULL);
    if (r != SQLITE_OK) {
        JS_FreeCString(ctx, zFile);
        if (zProc) {
            JS_FreeCString(ctx, zProc);
        }
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    r = sqlite3_load_extension(h->handle, zFile, zProc, NULL);
    sqlite3_db_config(h->handle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL);

    JS_FreeCString(ctx, zFile);
    if (zProc) {
        JS_FreeCString(ctx, zProc);
    }

    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return JS_UNDEFINED;
}
#endif

static JSValue tjs_sqlite3_exec(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    const char *sql = JS_ToCString(ctx, argv[0]);

    if (!sql) {
        return JS_EXCEPTION;
    }

    int r = sqlite3_exec(h->handle, sql, NULL, NULL, NULL);

    JS_FreeCString(ctx, sql);

    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return JS_UNDEFINED;
}

static JSValue tjs_sqlite3_prepare(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    const char *sql = JS_ToCString(ctx, argv[0]);

    if (!sql) {
        return JS_EXCEPTION;
    }

    sqlite3_stmt *stmt = NULL;
    int r = sqlite3_prepare_v2(h->handle, sql, -1, &stmt, NULL);

    JS_FreeCString(ctx, sql);

    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    JSValue obj = tjs_new_sqlite3_stmt(ctx, stmt);
    if (JS_IsException(obj)) {
        sqlite3_finalize(stmt);
    }

    return obj;
}

static JSValue tjs_sqlite3_in_transaction(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    return JS_NewBool(ctx, sqlite3_get_autocommit(h->handle) == 0);
}

static JSValue tjs_sqlite3_changes(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    return JS_NewInt32(ctx, sqlite3_changes(h->handle));
}

static JSValue tjs_sqlite3_last_insert_rowid(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    return JS_NewInt64(ctx, sqlite3_last_insert_rowid(h->handle));
}

static JSValue tjs_sqlite3_interrupt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    sqlite3_interrupt(h->handle);
    return JS_UNDEFINED;
}

static JSValue tjs_sqlite3_busy_timeout(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    int ms;
    if (JS_ToInt32(ctx, &ms, argv[0])) {
        return JS_EXCEPTION;
    }

    int r = sqlite3_busy_timeout(h->handle, ms);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return JS_UNDEFINED;
}

/* JS scalar UDF registration (sqlite3_create_function_v2) */
typedef struct {
    JSContext *ctx;
    JSRuntime *rt;
    JSValue func;
    int use_bigint;
} TJSSqlite3Func;

static void tjs_sqlite3_func_destroy(void *p) {
    TJSSqlite3Func *f = p;
    if (!f)
        return;
    JS_FreeValueRT(f->rt, f->func);
    js_free_rt(f->rt, f);
}

static void tjs__sqlite3_result_exception(JSContext *ctx, sqlite3_context *context, const char *fallback) {
    JSValue exc = JS_GetException(ctx);
    const char *msg = JS_ToCString(ctx, exc);
    if (msg) {
        sqlite3_result_error(context, msg, -1);
        JS_FreeCString(ctx, msg);
    } else {
        JS_FreeValue(ctx, JS_GetException(ctx));
        sqlite3_result_error(context, fallback, -1);
    }
    JS_FreeValue(ctx, exc);
}

static JSValue tjs__sqlite3_value_to_js(JSContext *ctx, sqlite3_value *val, int use_bigint) {
    switch (sqlite3_value_type(val)) {
        case SQLITE_INTEGER: {
            int64_t x = sqlite3_value_int64(val);
            if (use_bigint)
                return JS_NewBigInt64(ctx, x);
            if (x < -TJS_SQLITE3_MAX_SAFE_INTEGER || x > TJS_SQLITE3_MAX_SAFE_INTEGER) {
                return JS_ThrowRangeError(ctx, "Value is too large to be represented as a JavaScript number: %" PRId64, x);
            }
            if (x >= INT32_MIN && x <= INT32_MAX)
                return JS_NewInt32(ctx, (int32_t)x);
            return JS_NewInt64(ctx, x);
        }
        case SQLITE_FLOAT:
            return JS_NewFloat64(ctx, sqlite3_value_double(val));
        case SQLITE3_TEXT: {
            const unsigned char *text = sqlite3_value_text(val);
            int len = text ? sqlite3_value_bytes(val) : 0;
            return JS_NewStringLen(ctx, text ? (const char *)text : "", (size_t)len);
        }
        case SQLITE_BLOB: {
            int len = sqlite3_value_bytes(val);
            const void *blob = sqlite3_value_blob(val);
            return JS_NewUint8ArrayCopy(ctx,
                                         len > 0 ? (const uint8_t *)blob : NULL,
                                         len > 0 ? (size_t)len : 0);
        }
        default:
            return JS_NULL;
    }
}

static int tjs__sqlite3_result_from_js(JSContext *ctx, sqlite3_context *context, JSValue v) {
    int r;

    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        sqlite3_result_null(context);
        return 0;
    }

    switch (JS_VALUE_GET_NORM_TAG(v)) {
        case JS_TAG_BIG_INT: {
            int64_t x;
            if (JS_ToBigInt64(ctx, &x, v))
                return -1;
            sqlite3_result_int64(context, x);
            return 0;
        }
        case JS_TAG_STRING: {
            size_t len;
            const char *x = JS_ToCStringLen(ctx, &len, v);
            if (!x)
                return -1;
            if (len > INT_MAX) {
                JS_FreeCString(ctx, x);
                sqlite3_result_error(context, "string result too large", -1);
                return 1;
            }
            sqlite3_result_text(context, x, (int)len, SQLITE_TRANSIENT);
            JS_FreeCString(ctx, x);
            return 0;
        }
        case JS_TAG_OBJECT: {
            size_t len = 0;
            const uint8_t *x = JS_GetUint8Array(ctx, &len, v);
            if (!x) {
                JS_FreeValue(ctx, JS_GetException(ctx));
                sqlite3_result_error(context, "unsupported object result type", -1);
                return 1;
            }
            if (len > INT_MAX) {
                sqlite3_result_error(context, "blob result too large", -1);
                return 1;
            }
            sqlite3_result_blob(context, x, (int)len, SQLITE_TRANSIENT);
            return 0;
        }
        case JS_TAG_INT: {
            int64_t x;
            if (JS_ToInt64(ctx, &x, v))
                return -1;
            if (x < INT_MIN || x > INT_MAX)
                sqlite3_result_int64(context, x);
            else
                sqlite3_result_int(context, (int)x);
            return 0;
        }
        case JS_TAG_BOOL: {
            r = JS_ToBool(ctx, v);
            if (r < 0)
                return -1;
            sqlite3_result_int(context, r);
            return 0;
        }
        case JS_TAG_FLOAT64: {
            double x;
            if (JS_ToFloat64(ctx, &x, v))
                return -1;
            sqlite3_result_double(context, x);
            return 0;
        }
        default:
            sqlite3_result_error(context, "unsupported function result type", -1);
            return 1;
    }
}

static void tjs_sqlite3_func_xFunc(sqlite3_context *context, int argc, sqlite3_value **argv) {
    TJSSqlite3Func *f = sqlite3_user_data(context);
    if (!f || !f->ctx) {
        sqlite3_result_error(context, "missing function state", -1);
        return;
    }

    JSContext *ctx = f->ctx;
    JSValue *js_argv = NULL;
    if (argc > 0) {
        js_argv = js_malloc(ctx, (size_t)argc * sizeof(JSValue));
        if (!js_argv) {
            sqlite3_result_error_nomem(context);
            return;
        }
        for (int i = 0; i < argc; i++) {
            js_argv[i] = tjs__sqlite3_value_to_js(ctx, argv[i], f->use_bigint);
            if (JS_IsException(js_argv[i])) {
                for (int j = 0; j < i; j++)
                    JS_FreeValue(ctx, js_argv[j]);
                js_free(ctx, js_argv);
                JS_FreeValue(ctx, JS_GetException(ctx));
                sqlite3_result_error(context, "failed to convert argument", -1);
                return;
            }
        }
    }

    JSValue ret = JS_Call(ctx, f->func, JS_UNDEFINED, argc, js_argv);
    if (js_argv) {
        for (int i = 0; i < argc; i++)
            JS_FreeValue(ctx, js_argv[i]);
        js_free(ctx, js_argv);
    }

    if (JS_IsException(ret)) {
        tjs__sqlite3_result_exception(ctx, context, "function threw");
        return;
    }

    if (tjs__sqlite3_result_from_js(ctx, context, ret) < 0) {
        JS_FreeValue(ctx, ret);
        JS_FreeValue(ctx, JS_GetException(ctx));
        sqlite3_result_error(context, "failed to convert result", -1);
        return;
    }
    JS_FreeValue(ctx, ret);
}

/* Aggregate UDF: createAggregate(name, nArg, { start, step, result?, inverse? }) */
typedef struct {
    JSContext *ctx;
    JSRuntime *rt;
    JSValue start;
    int start_is_func;
    JSValue step;
    JSValue result;
    int has_result;
    JSValue inverse;
    int has_inverse;
    int use_bigint;
} TJSSqlite3Agg;

typedef struct {
    JSValue acc;
    int inited;
    int failed;
} TJSSqlite3AggCtx;

static void tjs_sqlite3_agg_destroy(void *p) {
    TJSSqlite3Agg *a = p;
    if (!a)
        return;
    JS_FreeValueRT(a->rt, a->start);
    JS_FreeValueRT(a->rt, a->step);
    if (a->has_result)
        JS_FreeValueRT(a->rt, a->result);
    if (a->has_inverse)
        JS_FreeValueRT(a->rt, a->inverse);
    js_free_rt(a->rt, a);
}

static int tjs_sqlite3_agg_ensure(sqlite3_context *context, TJSSqlite3Agg *a, TJSSqlite3AggCtx **out) {
    TJSSqlite3AggCtx *ac = sqlite3_aggregate_context(context, (int)sizeof(TJSSqlite3AggCtx));
    if (!ac) {
        sqlite3_result_error_nomem(context);
        return -1;
    }
    if (ac->failed)
        return -1;
    if (!ac->inited) {
        JSContext *ctx = a->ctx;
        JSValue acc;
        if (a->start_is_func) {
            acc = JS_Call(ctx, a->start, JS_UNDEFINED, 0, NULL);
            if (JS_IsException(acc)) {
                ac->failed = 1;
                tjs__sqlite3_result_exception(ctx, context, "aggregate start threw");
                return -1;
            }
        } else {
            acc = JS_DupValue(ctx, a->start);
        }
        ac->acc = acc;
        ac->inited = 1;
    }
    *out = ac;
    return 0;
}

static void tjs_sqlite3_agg_clear(JSContext *ctx, TJSSqlite3AggCtx *ac) {
    if (ac->inited)
        JS_FreeValue(ctx, ac->acc);
    ac->acc = JS_UNDEFINED;
    ac->inited = 0;
}

static int tjs_sqlite3_agg_emit(sqlite3_context *context, TJSSqlite3Agg *a, TJSSqlite3AggCtx *ac) {
    JSContext *ctx = a->ctx;
    JSValue out;
    if (a->has_result) {
        JSValue argv0 = JS_DupValue(ctx, ac->acc);
        out = JS_Call(ctx, a->result, JS_UNDEFINED, 1, &argv0);
        JS_FreeValue(ctx, argv0);
        if (JS_IsException(out)) {
            ac->failed = 1;
            tjs__sqlite3_result_exception(ctx, context, "aggregate result threw");
            return -1;
        }
    } else {
        out = JS_DupValue(ctx, ac->acc);
    }

    int r = tjs__sqlite3_result_from_js(ctx, context, out);
    JS_FreeValue(ctx, out);
    if (r < 0) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        sqlite3_result_error(context, "failed to convert aggregate result", -1);
    }
    if (r != 0)
        ac->failed = 1;
    return r;
}

static void tjs_sqlite3_agg_xStep(sqlite3_context *context, int argc, sqlite3_value **argv) {
    TJSSqlite3Agg *a = sqlite3_user_data(context);
    if (!a || !a->ctx) {
        sqlite3_result_error(context, "missing aggregate state", -1);
        return;
    }
    TJSSqlite3AggCtx *ac;
    if (tjs_sqlite3_agg_ensure(context, a, &ac) < 0)
        return;

    JSContext *ctx = a->ctx;
    int n = argc + 1;
    JSValue *js_argv = js_malloc(ctx, (size_t)n * sizeof(JSValue));
    if (!js_argv) {
        ac->failed = 1;
        sqlite3_result_error_nomem(context);
        return;
    }
    js_argv[0] = JS_DupValue(ctx, ac->acc);
    for (int i = 0; i < argc; i++) {
        js_argv[i + 1] = tjs__sqlite3_value_to_js(ctx, argv[i], a->use_bigint);
        if (JS_IsException(js_argv[i + 1])) {
            for (int j = 0; j <= i; j++)
                JS_FreeValue(ctx, js_argv[j]);
            js_free(ctx, js_argv);
            JS_FreeValue(ctx, JS_GetException(ctx));
            ac->failed = 1;
            sqlite3_result_error(context, "failed to convert aggregate argument", -1);
            return;
        }
    }

    JSValue ret = JS_Call(ctx, a->step, JS_UNDEFINED, n, js_argv);
    for (int i = 0; i < n; i++)
        JS_FreeValue(ctx, js_argv[i]);
    js_free(ctx, js_argv);

    if (JS_IsException(ret)) {
        ac->failed = 1;
        tjs__sqlite3_result_exception(ctx, context, "aggregate step threw");
        return;
    }
    JS_FreeValue(ctx, ac->acc);
    ac->acc = ret;
}

static void tjs_sqlite3_agg_xInverse(sqlite3_context *context, int argc, sqlite3_value **argv) {
    TJSSqlite3Agg *a = sqlite3_user_data(context);
    if (!a || !a->ctx || !a->has_inverse) {
        sqlite3_result_error(context, "aggregate inverse not configured", -1);
        return;
    }
    TJSSqlite3AggCtx *ac;
    if (tjs_sqlite3_agg_ensure(context, a, &ac) < 0)
        return;

    JSContext *ctx = a->ctx;
    int n = argc + 1;
    JSValue *js_argv = js_malloc(ctx, (size_t)n * sizeof(JSValue));
    if (!js_argv) {
        ac->failed = 1;
        sqlite3_result_error_nomem(context);
        return;
    }
    js_argv[0] = JS_DupValue(ctx, ac->acc);
    for (int i = 0; i < argc; i++) {
        js_argv[i + 1] = tjs__sqlite3_value_to_js(ctx, argv[i], a->use_bigint);
        if (JS_IsException(js_argv[i + 1])) {
            for (int j = 0; j <= i; j++)
                JS_FreeValue(ctx, js_argv[j]);
            js_free(ctx, js_argv);
            JS_FreeValue(ctx, JS_GetException(ctx));
            ac->failed = 1;
            sqlite3_result_error(context, "failed to convert inverse argument", -1);
            return;
        }
    }

    JSValue ret = JS_Call(ctx, a->inverse, JS_UNDEFINED, n, js_argv);
    for (int i = 0; i < n; i++)
        JS_FreeValue(ctx, js_argv[i]);
    js_free(ctx, js_argv);

    if (JS_IsException(ret)) {
        ac->failed = 1;
        tjs__sqlite3_result_exception(ctx, context, "aggregate inverse threw");
        return;
    }
    JS_FreeValue(ctx, ac->acc);
    ac->acc = ret;
}

static void tjs_sqlite3_agg_xFinal(sqlite3_context *context) {
    TJSSqlite3Agg *a = sqlite3_user_data(context);
    if (!a || !a->ctx) {
        sqlite3_result_error(context, "missing aggregate state", -1);
        return;
    }

    TJSSqlite3AggCtx *ac = sqlite3_aggregate_context(context, (int)sizeof(TJSSqlite3AggCtx));
    if (!ac) {
        sqlite3_result_error_nomem(context);
        return;
    }
    if (ac->failed) {
        tjs_sqlite3_agg_clear(a->ctx, ac);
        return;
    }
    if (!ac->inited) {
        if (tjs_sqlite3_agg_ensure(context, a, &ac) < 0)
            return;
    }

    tjs_sqlite3_agg_emit(context, a, ac);
    tjs_sqlite3_agg_clear(a->ctx, ac);
}

static void tjs_sqlite3_agg_xValue(sqlite3_context *context) {
    TJSSqlite3Agg *a = sqlite3_user_data(context);
    if (!a || !a->ctx) {
        sqlite3_result_error(context, "missing aggregate state", -1);
        return;
    }

    TJSSqlite3AggCtx *ac;
    if (tjs_sqlite3_agg_ensure(context, a, &ac) < 0)
        return;
    tjs_sqlite3_agg_emit(context, a, ac);
}

/* createAggregate(name, nArg, optionsObject)
 * options: start (value|function), step (function), result? (function),
 *          inverse? (function), deterministic?, useBigIntArguments?
 */
static JSValue tjs_sqlite3_create_aggregate(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);
    if (!h)
        return JS_EXCEPTION;

    if (argc < 3)
        return JS_ThrowTypeError(ctx, "createAggregate(name, nArg, options) requires 3 arguments");

    const char *name = JS_ToCString(ctx, argv[0]);
    if (!name)
        return JS_EXCEPTION;

    int n_arg;
    if (JS_ToInt32(ctx, &n_arg, argv[1])) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }
    if (n_arg < -1) {
        JS_FreeCString(ctx, name);
        return JS_ThrowRangeError(ctx, "nArg must be >= -1");
    }

    if (!JS_IsObject(argv[2])) {
        JS_FreeCString(ctx, name);
        return JS_ThrowTypeError(ctx, "createAggregate options must be an object");
    }

    JSValue start = JS_GetPropertyStr(ctx, argv[2], "start");
    if (JS_IsException(start)) {
        JS_FreeCString(ctx, name);
        return start;
    }
    if (JS_IsUndefined(start)) {
        JS_FreeValue(ctx, start);
        JS_FreeCString(ctx, name);
        return JS_ThrowTypeError(ctx, "options.start must be a function or a primitive value");
    }

    JSValue step = JS_GetPropertyStr(ctx, argv[2], "step");
    if (JS_IsException(step)) {
        JS_FreeValue(ctx, start);
        JS_FreeCString(ctx, name);
        return step;
    }
    if (!JS_IsFunction(ctx, step)) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        JS_FreeCString(ctx, name);
        return JS_ThrowTypeError(ctx, "options.step must be a function");
    }

    JSValue result = JS_GetPropertyStr(ctx, argv[2], "result");
    if (JS_IsException(result)) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        JS_FreeCString(ctx, name);
        return result;
    }
    int has_result = 0;
    if (!JS_IsUndefined(result) && !JS_IsNull(result)) {
        if (!JS_IsFunction(ctx, result)) {
            JS_FreeValue(ctx, start);
            JS_FreeValue(ctx, step);
            JS_FreeValue(ctx, result);
            JS_FreeCString(ctx, name);
            return JS_ThrowTypeError(ctx, "options.result must be a function");
        }
        has_result = 1;
    } else {
        JS_FreeValue(ctx, result);
        result = JS_UNDEFINED;
    }

    JSValue inverse = JS_GetPropertyStr(ctx, argv[2], "inverse");
    if (JS_IsException(inverse)) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        if (has_result)
            JS_FreeValue(ctx, result);
        JS_FreeCString(ctx, name);
        return inverse;
    }
    int has_inverse = 0;
    if (!JS_IsUndefined(inverse) && !JS_IsNull(inverse)) {
        if (!JS_IsFunction(ctx, inverse)) {
            JS_FreeValue(ctx, start);
            JS_FreeValue(ctx, step);
            if (has_result)
                JS_FreeValue(ctx, result);
            JS_FreeValue(ctx, inverse);
            JS_FreeCString(ctx, name);
            return JS_ThrowTypeError(ctx, "options.inverse must be a function");
        }
        has_inverse = 1;
    } else {
        JS_FreeValue(ctx, inverse);
        inverse = JS_UNDEFINED;
    }

    int eflags = SQLITE_UTF8;
    int use_bigint = 0;
    JSValue det = JS_GetPropertyStr(ctx, argv[2], "deterministic");
    if (JS_IsException(det)) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        if (has_result)
            JS_FreeValue(ctx, result);
        if (has_inverse)
            JS_FreeValue(ctx, inverse);
        JS_FreeCString(ctx, name);
        return det;
    }
    if (JS_ToBool(ctx, det))
        eflags |= SQLITE_DETERMINISTIC;
    JS_FreeValue(ctx, det);

    JSValue direct = JS_GetPropertyStr(ctx, argv[2], "directOnly");
    if (JS_IsException(direct)) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        if (has_result)
            JS_FreeValue(ctx, result);
        if (has_inverse)
            JS_FreeValue(ctx, inverse);
        JS_FreeCString(ctx, name);
        return direct;
    }
    if (JS_ToBool(ctx, direct))
        eflags |= SQLITE_DIRECTONLY;
    JS_FreeValue(ctx, direct);

    JSValue bi = JS_GetPropertyStr(ctx, argv[2], "useBigIntArguments");
    if (JS_IsException(bi)) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        if (has_result)
            JS_FreeValue(ctx, result);
        if (has_inverse)
            JS_FreeValue(ctx, inverse);
        JS_FreeCString(ctx, name);
        return bi;
    }
    use_bigint = JS_ToBool(ctx, bi) ? 1 : 0;
    JS_FreeValue(ctx, bi);

    TJSSqlite3Agg *agg = js_mallocz(ctx, sizeof(*agg));
    if (!agg) {
        JS_FreeValue(ctx, start);
        JS_FreeValue(ctx, step);
        if (has_result)
            JS_FreeValue(ctx, result);
        if (has_inverse)
            JS_FreeValue(ctx, inverse);
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }
    agg->ctx = ctx;
    agg->rt = JS_GetRuntime(ctx);
    agg->start = start;
    agg->start_is_func = JS_IsFunction(ctx, start);
    agg->step = step;
    agg->result = result;
    agg->has_result = has_result;
    agg->inverse = inverse;
    agg->has_inverse = has_inverse;
    agg->use_bigint = use_bigint;

    int r;
    if (has_inverse) {
        r = sqlite3_create_window_function(h->handle,
                                           name,
                                           n_arg,
                                           eflags,
                                           agg,
                                           tjs_sqlite3_agg_xStep,
                                           tjs_sqlite3_agg_xFinal,
                                           tjs_sqlite3_agg_xValue,
                                           tjs_sqlite3_agg_xInverse,
                                           tjs_sqlite3_agg_destroy);
    } else {
        r = sqlite3_create_function_v2(h->handle,
                                       name,
                                       n_arg,
                                       eflags,
                                       agg,
                                       NULL,
                                       tjs_sqlite3_agg_xStep,
                                       tjs_sqlite3_agg_xFinal,
                                       tjs_sqlite3_agg_destroy);
    }
    JS_FreeCString(ctx, name);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }
    return JS_UNDEFINED;
}

/* backupTo(destPath [, sourceName [, destName]]) — online copy via sqlite3_backup_*
 * Returns total page count of the completed backup (Node backup() result shape).
 */
static JSValue tjs_sqlite3_backup_to(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);
    if (!h)
        return JS_EXCEPTION;

    if (argc < 1)
        return JS_ThrowTypeError(ctx, "backupTo(destPath[, sourceName[, destName]]) requires destPath");

    const char *dest_path = JS_ToCString(ctx, argv[0]);
    if (!dest_path)
        return JS_EXCEPTION;

    const char *src_name = "main";
    const char *dst_name = "main";
    char *src_owned = NULL;
    char *dst_owned = NULL;

    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        src_owned = (char *)JS_ToCString(ctx, argv[1]);
        if (!src_owned) {
            JS_FreeCString(ctx, dest_path);
            return JS_EXCEPTION;
        }
        src_name = src_owned;
    }
    if (argc >= 3 && !JS_IsUndefined(argv[2]) && !JS_IsNull(argv[2])) {
        dst_owned = (char *)JS_ToCString(ctx, argv[2]);
        if (!dst_owned) {
            JS_FreeCString(ctx, dest_path);
            if (src_owned)
                JS_FreeCString(ctx, src_owned);
            return JS_EXCEPTION;
        }
        dst_name = dst_owned;
    }

    sqlite3 *dest = NULL;
    int r = sqlite3_open_v2(dest_path, &dest, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (r != SQLITE_OK) {
        JS_FreeCString(ctx, dest_path);
        if (src_owned)
            JS_FreeCString(ctx, src_owned);
        if (dst_owned)
            JS_FreeCString(ctx, dst_owned);
        if (dest)
            sqlite3_close_v2(dest);
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    sqlite3_backup *bak = sqlite3_backup_init(dest, dst_name, h->handle, src_name);
    if (!bak) {
        int err = sqlite3_errcode(dest);
        sqlite3_close_v2(dest);
        JS_FreeCString(ctx, dest_path);
        if (src_owned)
            JS_FreeCString(ctx, src_owned);
        if (dst_owned)
            JS_FreeCString(ctx, dst_owned);
        return tjs_throw_sqlite3_errno(ctx, err != SQLITE_OK ? err : SQLITE_ERROR);
    }

    do {
        r = sqlite3_backup_step(bak, -1);
    } while (r == SQLITE_OK || r == SQLITE_BUSY || r == SQLITE_LOCKED);

    int pages = sqlite3_backup_pagecount(bak);
    int fin = sqlite3_backup_finish(bak);
    if (r != SQLITE_DONE) {
        int err = r != SQLITE_OK ? r : fin;
        sqlite3_close_v2(dest);
        JS_FreeCString(ctx, dest_path);
        if (src_owned)
            JS_FreeCString(ctx, src_owned);
        if (dst_owned)
            JS_FreeCString(ctx, dst_owned);
        return tjs_throw_sqlite3_errno(ctx, err);
    }
    if (fin != SQLITE_OK) {
        sqlite3_close_v2(dest);
        JS_FreeCString(ctx, dest_path);
        if (src_owned)
            JS_FreeCString(ctx, src_owned);
        if (dst_owned)
            JS_FreeCString(ctx, dst_owned);
        return tjs_throw_sqlite3_errno(ctx, fin);
    }

    sqlite3_close_v2(dest);
    JS_FreeCString(ctx, dest_path);
    if (src_owned)
        JS_FreeCString(ctx, src_owned);
    if (dst_owned)
        JS_FreeCString(ctx, dst_owned);

    return JS_NewInt32(ctx, pages);
}

/* createFunction(name, nArg, func [, options])
 * options.deterministic (bool), options.useBigIntArguments (bool)
 * nArg < 0 → SQLITE varargs (-1)
 */
static JSValue tjs_sqlite3_create_function(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Handle *h = tjs_sqlite3_get_open(ctx, this_val);
    if (!h)
        return JS_EXCEPTION;

    if (argc < 3)
        return JS_ThrowTypeError(ctx, "createFunction(name, nArg, func[, options]) requires 3 arguments");

    const char *name = JS_ToCString(ctx, argv[0]);
    if (!name)
        return JS_EXCEPTION;

    int n_arg;
    if (JS_ToInt32(ctx, &n_arg, argv[1])) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }
    if (n_arg < -1) {
        JS_FreeCString(ctx, name);
        return JS_ThrowRangeError(ctx, "nArg must be >= -1");
    }

    if (!JS_IsFunction(ctx, argv[2])) {
        JS_FreeCString(ctx, name);
        return JS_ThrowTypeError(ctx, "createFunction func must be a function");
    }

    int eflags = SQLITE_UTF8;
    int use_bigint = 0;
    if (argc >= 4 && !JS_IsUndefined(argv[3]) && !JS_IsNull(argv[3])) {
        if (!JS_IsObject(argv[3])) {
            JS_FreeCString(ctx, name);
            return JS_ThrowTypeError(ctx, "createFunction options must be an object");
        }
        JSValue det = JS_GetPropertyStr(ctx, argv[3], "deterministic");
        if (JS_IsException(det)) {
            JS_FreeCString(ctx, name);
            return det;
        }
        if (JS_ToBool(ctx, det))
            eflags |= SQLITE_DETERMINISTIC;
        JS_FreeValue(ctx, det);

        JSValue direct = JS_GetPropertyStr(ctx, argv[3], "directOnly");
        if (JS_IsException(direct)) {
            JS_FreeCString(ctx, name);
            return direct;
        }
        if (JS_ToBool(ctx, direct))
            eflags |= SQLITE_DIRECTONLY;
        JS_FreeValue(ctx, direct);

        JSValue bi = JS_GetPropertyStr(ctx, argv[3], "useBigIntArguments");
        if (JS_IsException(bi)) {
            JS_FreeCString(ctx, name);
            return bi;
        }
        use_bigint = JS_ToBool(ctx, bi) ? 1 : 0;
        JS_FreeValue(ctx, bi);
    }

    TJSSqlite3Func *f = js_mallocz(ctx, sizeof(*f));
    if (!f) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }
    f->ctx = ctx;
    f->rt = JS_GetRuntime(ctx);
    f->func = JS_DupValue(ctx, argv[2]);
    f->use_bigint = use_bigint;

    int r = sqlite3_create_function_v2(h->handle,
                                       name,
                                       n_arg,
                                       eflags,
                                       f,
                                       tjs_sqlite3_func_xFunc,
                                       NULL,
                                       NULL,
                                       tjs_sqlite3_func_destroy);
    JS_FreeCString(ctx, name);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return JS_UNDEFINED;
}

static JSValue tjs_sqlite3_stmt_finalize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Stmt *h = tjs_sqlite3_stmt_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    if (!h->stmt) {
        return JS_UNDEFINED;
    }

    sqlite3_reset(h->stmt);

    int r = sqlite3_finalize(h->stmt);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    h->stmt = NULL;

    return JS_UNDEFINED;
}

static JSValue tjs_sqlite3_stmt_expand(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Stmt *h = tjs_sqlite3_stmt_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    if (!h->stmt) {
        return JS_NewString(ctx, "");
    }

    char *sql = sqlite3_expanded_sql(h->stmt);
    if (sql == NULL) {
        return JS_ThrowOutOfMemory(ctx);
    }

    JSValue ret = JS_NewString(ctx, sql);
    sqlite3_free(sql);
    return ret;
}

static JSValue tjs__stmt2obj(JSContext *ctx, TJSSqlite3Stmt *h) {
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(obj))
        return obj;

    int count = sqlite3_column_count(h->stmt);

    for (int i = 0; i < count; i++) {
        const char *name = sqlite3_column_name(h->stmt, i);
        if (!name) {
            JS_FreeValue(ctx, obj);
            return JS_ThrowOutOfMemory(ctx);
        }
        JSValue value;

        switch (sqlite3_column_type(h->stmt, i)) {
            case SQLITE_INTEGER: {
                value = JS_NewInt64(ctx, sqlite3_column_int64(h->stmt, i));
                break;
            }
            case SQLITE_FLOAT: {
                value = JS_NewFloat64(ctx, sqlite3_column_double(h->stmt, i));
                break;
            }
            case SQLITE3_TEXT: {
                const unsigned char *text = sqlite3_column_text(h->stmt, i);
                value = JS_NewString(ctx, text ? (const char *)text : "");
                break;
            }
            case SQLITE_BLOB: {
                int len = sqlite3_column_bytes(h->stmt, i);
                const void *blob = sqlite3_column_blob(h->stmt, i);
                value = JS_NewUint8ArrayCopy(ctx,
                                             len > 0 ? (const uint8_t *)blob : NULL,
                                             len > 0 ? (size_t)len : 0);
                break;
            }
            default: {
                value = JS_NULL;
                break;
            }
        }

        if (JS_IsException(value)) {
            JS_FreeValue(ctx, obj);
            return value;
        }

        if (JS_DefinePropertyValueStr(ctx, obj, name, value, JS_PROP_C_W_E) < 0) {
            JS_FreeValue(ctx, value);
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
    }

    return obj;
}

static JSValue tjs__sqlite3_bind_param(JSContext *ctx, sqlite3_stmt *stmt, int idx, JSValue v) {
    int r;

#define CHECK_VALUE(ret, i)                                                                                            \
    if (ret == -1) {                                                                                                   \
        return JS_ThrowTypeError(ctx, "Failed to convert type at position %d", idx);                                   \
    }

#define CHECK_RET(ret)                                                                                                 \
    if (r != SQLITE_OK) {                                                                                              \
        return tjs_throw_sqlite3_errno(ctx, ret);                                                                      \
    }

    switch (JS_VALUE_GET_NORM_TAG(v)) {
        case JS_TAG_BIG_INT: {
            int64_t x;
            r = JS_ToBigInt64(ctx, &x, v);
            CHECK_VALUE(r, idx);
            r = sqlite3_bind_int64(stmt, idx, x);
            CHECK_RET(r);
            break;
        }
        case JS_TAG_STRING: {
            size_t len;
            const char *x = JS_ToCStringLen(ctx, &len, v);
            if (!x) {
                return JS_EXCEPTION;
            }
            if (len > INT_MAX) {
                JS_FreeCString(ctx, x);
                return JS_ThrowRangeError(ctx, "Bound string is too large");
            }
            r = sqlite3_bind_text(stmt, idx, x, len, SQLITE_TRANSIENT);
            JS_FreeCString(ctx, x);
            CHECK_RET(r);
            break;
        }
        case JS_TAG_OBJECT: {
            size_t len = 0;
            const uint8_t *x = JS_GetUint8Array(ctx, &len, v);
            if (!x) {
                return JS_EXCEPTION;
            }
            if (len > INT_MAX) {
                return JS_ThrowRangeError(ctx, "Bound blob is too large");
            }
            r = sqlite3_bind_blob(stmt, idx, x, len, SQLITE_TRANSIENT);
            CHECK_RET(r);
            break;
        }
        case JS_TAG_INT: {
            int64_t x;
            r = JS_ToInt64(ctx, &x, v);
            CHECK_VALUE(r, idx);
            if (x < INT_MIN || x > INT_MAX) {
                r = sqlite3_bind_int64(stmt, idx, x);
            } else {
                r = sqlite3_bind_int(stmt, idx, x);
            }
            CHECK_RET(r);
            break;
        }
        case JS_TAG_BOOL: {
            r = JS_ToBool(ctx, v);
            CHECK_VALUE(r, idx);
            r = sqlite3_bind_int(stmt, idx, r);
            CHECK_RET(r);
            break;
        }
        case JS_TAG_NULL: {
            r = sqlite3_bind_null(stmt, idx);
            CHECK_RET(r);
            break;
        }
        case JS_TAG_FLOAT64: {
            double x;
            r = JS_ToFloat64(ctx, &x, v);
            CHECK_VALUE(r, idx);
            r = sqlite3_bind_double(stmt, idx, x);
            CHECK_RET(r);
            break;
        }
        default:
            return JS_ThrowTypeError(ctx, "Invalid bound parameter type at position %d", idx);
    }

    return JS_UNDEFINED;

#undef CHECK_VALUE
#undef CHECK_RET
}

static JSValue tjs__sqlite3_bind_params(JSContext *ctx, sqlite3_stmt *stmt, JSValue params) {
    sqlite3_clear_bindings(stmt);

    if (JS_IsArray(params)) {
        JSValue js_length = JS_GetPropertyStr(ctx, params, "length");
        uint64_t len;
        if (JS_ToIndex(ctx, &len, js_length)) {
            JS_FreeValue(ctx, js_length);
            return JS_EXCEPTION;
        }
        JS_FreeValue(ctx, js_length);
        if (len > UINT32_MAX) {
            return JS_ThrowRangeError(ctx, "Too many bound parameters");
        }
        for (uint32_t i = 0; i < (uint32_t)len; i++) {
            JSValue v = JS_GetPropertyUint32(ctx, params, i);
            if (JS_IsException(v)) {
                return v;
            }
            bool is_exception = JS_IsException(tjs__sqlite3_bind_param(ctx, stmt, i + 1, v));
            JS_FreeValue(ctx, v);
            if (is_exception) {
                return JS_EXCEPTION;
            }
        }
    } else if (JS_IsObject(params)) {
        JSPropertyEnum *ptab;
        uint32_t plen;
        if (JS_GetOwnPropertyNames(ctx, &ptab, &plen, params, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY)) {
            return JS_EXCEPTION;
        }
        for (uint32_t i = 0; i < plen; i++) {
            JSAtom patom = ptab[i].atom;
            JSValue prop = JS_GetProperty(ctx, params, patom);
            if (JS_IsException(prop)) {
                JS_FreePropertyEnum(ctx, ptab, plen);
                return JS_EXCEPTION;
            }
            const char *key = JS_AtomToCString(ctx, patom);
            if (!key) {
                JS_FreeValue(ctx, prop);
                JS_FreePropertyEnum(ctx, ptab, plen);
                return JS_EXCEPTION;
            }
            int idx = sqlite3_bind_parameter_index(stmt, key);
            if (idx == 0 || JS_IsException(tjs__sqlite3_bind_param(ctx, stmt, idx, prop))) {
                if (idx == 0) {
                    JS_ThrowReferenceError(ctx, "Could not find parameter '%s'", key);
                }
                JS_FreeValue(ctx, prop);
                JS_FreeCString(ctx, key);
                JS_FreePropertyEnum(ctx, ptab, plen);
                return JS_EXCEPTION;
            }
            JS_FreeValue(ctx, prop);
            JS_FreeCString(ctx, key);
        }
        JS_FreePropertyEnum(ctx, ptab, plen);
    } else {
        return JS_ThrowTypeError(ctx, "Invalid bind parameters type: expected object or array");
    }

    return JS_UNDEFINED;
}

static JSValue tjs_sqlite3_stmt_bind(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Stmt *h = tjs_sqlite3_stmt_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    if (!h->stmt) {
        return JS_ThrowInternalError(ctx, "Statement has been finalized");
    }

    int r = sqlite3_reset(h->stmt);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    if (argc == 0 || JS_IsUndefined(argv[0])) {
        r = sqlite3_clear_bindings(h->stmt);
        if (r != SQLITE_OK) {
            return tjs_throw_sqlite3_errno(ctx, r);
        }
        return JS_UNDEFINED;
    }

    return tjs__sqlite3_bind_params(ctx, h->stmt, argv[0]);
}

static JSValue tjs_sqlite3_stmt_reset(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Stmt *h = tjs_sqlite3_stmt_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    if (!h->stmt) {
        return JS_ThrowInternalError(ctx, "Statement has been finalized");
    }

    int r = sqlite3_reset(h->stmt);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return JS_UNDEFINED;
}

static JSValue tjs_sqlite3_stmt_all(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Stmt *h = tjs_sqlite3_stmt_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    if (!h->stmt) {
        return JS_ThrowInternalError(ctx, "Statement has been finalized");
    }

    int r = sqlite3_reset(h->stmt);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    if (argc == 1) {
        JSValue params = argv[0];

        if (JS_IsException(tjs__sqlite3_bind_params(ctx, h->stmt, params))) {
            return JS_EXCEPTION;
        }
    }

    JSValue result = JS_NewArray(ctx);
    if (JS_IsException(result)) {
        return result;
    }
    uint32_t i = 0;

    while ((r = sqlite3_step(h->stmt)) == SQLITE_ROW) {
        JSValue row = tjs__stmt2obj(ctx, h);
        if (JS_IsException(row)) {
            JS_FreeValue(ctx, result);
            return row;
        }
        if (JS_DefinePropertyValueUint32(ctx, result, i, row, JS_PROP_C_W_E) < 0) {
            JS_FreeValue(ctx, row);
            JS_FreeValue(ctx, result);
            return JS_EXCEPTION;
        }
        i++;
    }

    if (r != SQLITE_OK && r != SQLITE_DONE) {
        JS_FreeValue(ctx, result);
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return result;
}

static JSValue tjs_sqlite3_stmt_run(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSSqlite3Stmt *h = tjs_sqlite3_stmt_get(ctx, this_val);

    if (!h) {
        return JS_EXCEPTION;
    }

    if (!h->stmt) {
        return JS_ThrowInternalError(ctx, "Statement has been finalized");
    }

    int r = sqlite3_reset(h->stmt);
    if (r != SQLITE_OK) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    if (argc == 1) {
        JSValue params = argv[0];

        if (JS_IsException(tjs__sqlite3_bind_params(ctx, h->stmt, params))) {
            return JS_EXCEPTION;
        }
    }

    r = sqlite3_step(h->stmt);
    if (r != SQLITE_OK && r != SQLITE_DONE && r != SQLITE_ROW) {
        return tjs_throw_sqlite3_errno(ctx, r);
    }

    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_sqlite3_proto_funcs[] = {
    TJS_CFUNC_DEF("close", 0, tjs_sqlite3_close),
#ifdef SQLITE_HAS_LOAD_EXTENSION
    TJS_CFUNC_DEF("loadExtension", 2, tjs_sqlite3_load_extension),
#endif
    TJS_CFUNC_DEF("exec", 1, tjs_sqlite3_exec),
    TJS_CFUNC_DEF("prepare", 1, tjs_sqlite3_prepare),
    TJS_CFUNC_DEF("inTransaction", 0, tjs_sqlite3_in_transaction),
    TJS_CFUNC_DEF("changes", 0, tjs_sqlite3_changes),
    TJS_CFUNC_DEF("lastInsertRowid", 0, tjs_sqlite3_last_insert_rowid),
    TJS_CFUNC_DEF("interrupt", 0, tjs_sqlite3_interrupt),
    TJS_CFUNC_DEF("busyTimeout", 1, tjs_sqlite3_busy_timeout),
    TJS_CFUNC_DEF("createFunction", 4, tjs_sqlite3_create_function),
    TJS_CFUNC_DEF("createAggregate", 4, tjs_sqlite3_create_aggregate),
    TJS_CFUNC_DEF("backupTo", 3, tjs_sqlite3_backup_to),
};

static const JSCFunctionListEntry tjs_sqlite3_stmt_proto_funcs[] = {
    TJS_CFUNC_DEF("finalize", 0, tjs_sqlite3_stmt_finalize),
    TJS_CFUNC_DEF("expand", 0, tjs_sqlite3_stmt_expand),
    TJS_CFUNC_DEF("bind", 1, tjs_sqlite3_stmt_bind),
    TJS_CFUNC_DEF("reset", 0, tjs_sqlite3_stmt_reset),
    TJS_CFUNC_DEF("all", 1, tjs_sqlite3_stmt_all),
    TJS_CFUNC_DEF("run", 1, tjs_sqlite3_stmt_run),
};

static const JSCFunctionListEntry tjs_sqlite3_funcs[] = {
    TJS_CFUNC_DEF("open", 2, tjs_sqlite3_open),
    TJS_CONST2("O_CREATE", SQLITE_OPEN_CREATE),
    TJS_CONST2("O_READONLY", SQLITE_OPEN_READONLY),
    TJS_CONST2("O_READWRITE", SQLITE_OPEN_READWRITE),
	TJS_CONST2("O_MEMORY", SQLITE_OPEN_MEMORY),
	TJS_CONST2("O_URI", SQLITE_OPEN_URI),
	TJS_CONST2("O_URL", SQLITE_OPEN_URI),
	TJS_CONST2("O_NOMUTEX", SQLITE_OPEN_NOMUTEX),
    TJS_CONST2("O_FULLMUTEX", SQLITE_OPEN_FULLMUTEX),
    TJS_CONST2("O_SHAREDCACHE", SQLITE_OPEN_SHAREDCACHE),
    TJS_CONST2("O_PRIVATECACHE", SQLITE_OPEN_PRIVATECACHE),
	TJS_CONST2("O_NOFOLLOW", SQLITE_OPEN_NOFOLLOW)
};


void tjs__mod_sqlite3_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    /* Handle object */
    JS_NewClassID(rt, &tjs_sqlite3_class_id);
    JS_NewClass(rt, tjs_sqlite3_class_id, &tjs_sqlite3_class);
    JSValue handle_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, handle_proto, tjs_sqlite3_proto_funcs, countof(tjs_sqlite3_proto_funcs));
    JS_SetClassProto(ctx, tjs_sqlite3_class_id, handle_proto);

    /* Statement object */
    JS_NewClassID(rt, &tjs_sqlite3_stmt_class_id);
    JS_NewClass(rt, tjs_sqlite3_stmt_class_id, &tjs_sqlite3_stmt_class);
    JSValue stmt_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, stmt_proto, tjs_sqlite3_stmt_proto_funcs, countof(tjs_sqlite3_stmt_proto_funcs));
    JS_SetClassProto(ctx, tjs_sqlite3_stmt_class_id, stmt_proto);

    JS_SetPropertyFunctionList(ctx, ns, tjs_sqlite3_funcs, countof(tjs_sqlite3_funcs));
}
