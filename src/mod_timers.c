/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
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

#include "hash.h"
#include "mem.h"
#include "private.h"
#include "utils.h"

#define MAX_SAFE_INTEGER (((int64_t) 1 << 53) - 1)

struct TJSTimer {
    JSContext *ctx;
    int64_t id;
    uv_timer_t handle;
    UT_hash_handle hh;
    int interval;
    bool in_cb;
    bool values_pending;
    JSValue func;
    int argc;
    JSValue argv[];
};

static void uv__timer_close(uv_handle_t *handle) {
    TJSTimer *th = handle->data;
    if (!th) return;
    /* libuv invokes close callbacks after the active timer callback has
     * returned, so the in_cb guard has already been cleared by then. */
    tjs__free(th);
}

/* Release the JS values owned by a timer that has not been inserted into the
 * runtime hash yet.  The normal destroy_timer() path also removes the hash
 * entry and closes the uv handle, so keep this helper limited to construction
 * failures. */
static void free_timer_values(JSContext *ctx, TJSTimer *th) {
    if (!th) return;
    if (!JS_IsUndefined(th->func)) {
        JS_FreeValue(ctx, th->func);
        th->func = JS_UNDEFINED;
    }
    for (int i = 0; i < th->argc; i++) {
        JS_FreeValue(ctx, th->argv[i]);
        th->argv[i] = JS_UNDEFINED;
    }
    th->argc = 0;
}

static void destroy_timer(TJSTimer *th) {
    JSContext *ctx = th->ctx;
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    /* Already being destroyed. */
    if (uv_is_closing((uv_handle_t *) &th->handle)) {
        return;
    }

    /* The callback owns the argument array while JS_Call is on the stack.
     * Defer releasing those JS values when clearTimeout() is called from the
     * callback itself; otherwise a refcounted object can be freed underneath
     * QuickJS while it is still being passed as an argument. */
    if (th->in_cb) {
        HASH_DEL(qrt->timers.timers, th);
        th->values_pending = true;
        uv_close((uv_handle_t *) &th->handle, uv__timer_close);
        return;
    }

    free_timer_values(ctx, th);

    HASH_DEL(qrt->timers.timers, th);

    uv_close((uv_handle_t *) &th->handle, uv__timer_close);
}

void tjs__destroy_timers(TJSRuntime *qrt) {
    TJSTimer *th, *tmp;

    HASH_ITER(hh, qrt->timers.timers, th, tmp) {
        destroy_timer(th);
    }
}

static void uv__timer_cb(uv_timer_t *handle) {
    TJSTimer *th = handle->data;
    CHECK_NOT_NULL(th);

	/* It's possible our timer was scheduled to run but was already destroyed. */
    if (uv_is_closing((uv_handle_t *) handle)) {
        return;
    }

    th->in_cb = true;

    /* Micro-tasks should run before timers. */
    tjs__execute_jobs(TJS_GetRuntime(th->ctx));

	/* Check again in case the timer was destroyed during job execution. */
    if (uv_is_closing((uv_handle_t *) handle)) {
        th->in_cb = false;
        if (th->values_pending)
            free_timer_values(th->ctx, th);
        return;
    }
    tjs_call_handler(th->ctx, th->func, th->argc, th->argv);

    if (!th->interval) {
        /* clearTimeout() from inside the callback may already have started
         * closing this handle. Avoid a second destroy, while the in_cb guard
         * keeps `th` valid until the close callback is complete. */
        if (!uv_is_closing((uv_handle_t *) handle))
            destroy_timer(th);
    }

    th->in_cb = false;
    if (th->values_pending)
        free_timer_values(th->ctx, th);
}

static JSValue tjs_setTimeout(JSContext *ctx, JSValue this_val, int argc, JSValue *argv, int magic) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "callback is required");
    }

    int64_t delay;
    JSValue func;
    TJSTimer *th;

    func = argv[0];
    if (!JS_IsFunction(ctx, func)) {
        return JS_ThrowTypeError(ctx, "not a function");
    }

    if (argc <= 1) {
        delay = 0;
    } else if (JS_ToInt64(ctx, &delay, argv[1])) {
        return JS_EXCEPTION;
    }

    /* Negative delays would wrap to a huge uint64 timeout in libuv. */
    if (delay < 0) {
        delay = 0;
    }

    int nargs = argc - 2;
    if (nargs < 0) {
        nargs = 0;
    }

    /* Guard the flexible-array allocation against size_t wraparound. */
    if ((size_t)nargs > (SIZE_MAX - sizeof(*th)) / sizeof(JSValue)) {
        return JS_ThrowRangeError(ctx, "too many timer arguments");
    }
    th = tjs__malloc(sizeof(*th) + (size_t)nargs * sizeof(JSValue));
    if (!th) {
        return JS_ThrowOutOfMemory(ctx);
    }

    th->func = JS_UNDEFINED;
    th->argc = 0;
    th->in_cb = false;
    th->values_pending = false;

    th->id = qrt->timers.next_timer++;
    if (qrt->timers.next_timer > MAX_SAFE_INTEGER) {
        qrt->timers.next_timer = 1;
    }

    th->ctx = ctx;
    int uv_r = uv_timer_init(tjs_get_loop(ctx), &th->handle);
    if (uv_r != 0) {
        tjs__free(th);
        return tjs_throw_errno(ctx, uv_r);
    }
    th->handle.data = th;
    th->interval = magic;
    th->func = JS_DupValue(ctx, func);
    th->argc = nargs;
    for (int i = 0; i < nargs; i++) {
        th->argv[i] = JS_DupValue(ctx, argv[i + 2]);
    }

    uv_update_time(tjs_get_loop(ctx));
    /* libuv treats repeat=0 as a one-shot timer.  A zero-delay interval must
     * still repeat; use libuv's minimum practical repeat period to avoid
     * leaving a one-shot timer (and its JS callback arguments) retained in
     * the timer table forever. */
    uint64_t repeat = magic ? (delay == 0 ? 1u : (uint64_t)delay) : 0;
    uv_r = uv_timer_start(&th->handle, uv__timer_cb, (uint64_t)delay, repeat);
    if (uv_r != 0) {
        free_timer_values(ctx, th);
        uv_close((uv_handle_t *)&th->handle, uv__timer_close);
        return tjs_throw_errno(ctx, uv_r);
    }

    HASH_ADD_INT64(qrt->timers.timers, id, th);

    return JS_NewInt64(ctx, th->id);
}

static JSValue tjs_clearTimeout(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);
    int64_t timer_id;
    TJSTimer *th = NULL;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "timer id is required");
    }

    if (JS_ToInt64(ctx, &timer_id, argv[0])) {
        return JS_EXCEPTION;
    }

    HASH_FIND_INT64(qrt->timers.timers, &timer_id, th);

    if (th != NULL) {
        CHECK_EQ(uv_timer_stop(&th->handle), 0);
        destroy_timer(th);
    }

    return JS_UNDEFINED;
}

static JSValue tjs_timer_ref(JSContext *ctx, JSValue this_val, int argc, JSValue *argv, int magic) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);
    int64_t timer_id;
    TJSTimer *th = NULL;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "timer id is required");
    }

    if (JS_ToInt64(ctx, &timer_id, argv[0])) {
        return JS_EXCEPTION;
    }

    HASH_FIND_INT64(qrt->timers.timers, &timer_id, th);

    if (th == NULL) return JS_ThrowTypeError(ctx, "timer not found");

    switch (magic) {
        case 0:
            uv_ref((uv_handle_t *)&th->handle);
            break;
        case 1:
            uv_unref((uv_handle_t *)&th->handle);
            break;
        case 2:
            return JS_NewBool(ctx, uv_has_ref((uv_handle_t *)&th->handle));
    }

    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_timer_funcs[] = {
    JS_CFUNC_MAGIC_DEF("setTimeout", 2, tjs_setTimeout, 0),
    TJS_CFUNC_DEF("clearTimeout", 1, tjs_clearTimeout),
    JS_CFUNC_MAGIC_DEF("setInterval", 2, tjs_setTimeout, 1),
    TJS_CFUNC_DEF("clearInterval", 1, tjs_clearTimeout),
    JS_CFUNC_MAGIC_DEF("refTimer", 1, tjs_timer_ref, 0),
    JS_CFUNC_MAGIC_DEF("unrefTimer", 1, tjs_timer_ref, 1),
    JS_CFUNC_MAGIC_DEF("hasRef", 1, tjs_timer_ref, 2),
};

void tjs__mod_timers_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_timer_funcs, countof(tjs_timer_funcs));
}
