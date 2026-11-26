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
    bool immediate;
    bool in_cb;
    bool close_completed;
    bool destroyed;
    bool immediate_queued;
    bool immediate_refed;
    unsigned active_refs;
    TJSImmediateState *immediate_state;
    struct TJSTimer *immediate_prev;
    struct TJSTimer *immediate_next;
    JSValue func;
    int argc;
    JSValue argv[];
};

struct TJSImmediateState {
    TJSRuntime *runtime;
    uv_check_t check;
    size_t refed_count;
    size_t dispatch_refs;
    TJSTimer *head;
    TJSTimer *tail;
};

static void free_timer_values(JSContext *ctx, TJSTimer *th);
static void immediate_state_maybe_close(TJSImmediateState *state);

static TJSImmediateState *immediate_state_for_runtime(TJSRuntime *qrt) {
    TJSImmediateState *state = qrt->timers.immediates;
    if (state) return state;

    state = tjs__mallocz(sizeof(*state));
    if (!state) return NULL;
    state->runtime = qrt;
    if (uv_check_init(&qrt->loop, &state->check) != 0) {
        tjs__free(state);
        return NULL;
    }
    state->check.data = state;
    qrt->timers.immediates = state;
    return state;
}

static void immediate_state_close_cb(uv_handle_t *handle) {
    TJSImmediateState *state = handle->data;
    if (!state) return;
    handle->data = NULL;
    tjs__free(state);
}

static void immediate_state_update_ref(TJSImmediateState *state) {
    if (!state || uv_is_closing((uv_handle_t *)&state->check)) return;
    if (state->refed_count > 0)
        uv_ref((uv_handle_t *)&state->check);
    else
        uv_unref((uv_handle_t *)&state->check);
}

static void immediate_state_queue_add(TJSImmediateState *state, TJSTimer *th) {
    th->immediate_prev = state->tail;
    th->immediate_next = NULL;
    if (state->tail)
        state->tail->immediate_next = th;
    else
        state->head = th;
    state->tail = th;
    th->immediate_queued = true;
}

static void immediate_state_queue_remove(TJSTimer *th) {
    TJSImmediateState *state = th->immediate_state;
    if (!state || !th->immediate_queued) return;
    if (th->immediate_prev)
        th->immediate_prev->immediate_next = th->immediate_next;
    else
        state->head = th->immediate_next;
    if (th->immediate_next)
        th->immediate_next->immediate_prev = th->immediate_prev;
    else
        state->tail = th->immediate_prev;
    th->immediate_prev = NULL;
    th->immediate_next = NULL;
    th->immediate_queued = false;
}

static void immediate_state_maybe_close(TJSImmediateState *state) {
    if (!state || state->head || state->dispatch_refs ||
        uv_is_closing((uv_handle_t *)&state->check)) return;
    uv_check_stop(&state->check);
    state->runtime->timers.immediates = NULL;
    uv_close((uv_handle_t *)&state->check, immediate_state_close_cb);
}

static void immediate_timer_release_ref(TJSTimer *th) {
    TJSImmediateState *state = th->immediate_state;
    if (!state) return;
    CHECK_GT(state->dispatch_refs, 0);
    CHECK_GT(th->active_refs, 0);
    th->active_refs--;
    if (th->destroyed && th->active_refs == 0) {
        free_timer_values(th->ctx, th);
        tjs__free(th);
    }
    state->dispatch_refs--;
    immediate_state_maybe_close(state);
}

static uv_handle_t *uv_handle_for_timer(TJSTimer *th) {
    if (th->immediate)
        return (uv_handle_t *)&th->immediate_state->check;
    return (uv_handle_t *)&th->handle;
}

static void uv__timer_close(uv_handle_t *handle) {
    TJSTimer *th = handle->data;
    if (!th) return;
    th->close_completed = true;
    if (th->active_refs == 0)
        tjs__free(th);
}

static void timer_release_ref(TJSTimer *th) {
    if (th->immediate) {
        immediate_timer_release_ref(th);
        return;
    }
    CHECK_GT(th->active_refs, 0);
    th->active_refs--;
    if (th->active_refs == 0 && th->close_completed)
        tjs__free(th);
}

static void free_timer_values(JSContext *ctx, TJSTimer *th) {
    if (!th) return;
    JSValue func = th->func;
    int argc = th->argc;
    th->func = JS_UNDEFINED;
    th->argc = 0;
    JS_FreeValue(ctx, func);
    for (int i = 0; i < argc; i++) {
        JSValue argument = th->argv[i];
        th->argv[i] = JS_UNDEFINED;
        JS_FreeValue(ctx, argument);
    }
}

static void stop_timer(TJSTimer *th, TJSRuntime *qrt) {
    (void) qrt;
    CHECK_EQ(uv_timer_stop(&th->handle), 0);
}

static void destroy_timer(TJSTimer *th) {
    JSContext *ctx = th->ctx;
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    if (th->immediate) {
        TJSImmediateState *state = th->immediate_state;
        bool free_now;
        if (th->destroyed) return;
        state->dispatch_refs++;
        th->destroyed = true;
        if (th->immediate_queued) {
            immediate_state_queue_remove(th);
            CHECK_GT(qrt->timers.pending_immediates, 0);
            qrt->timers.pending_immediates--;
            if (!qrt->freeing) tjs__notify_work(qrt);
        }
        if (th->immediate_refed) {
            CHECK_GT(state->refed_count, 0);
            state->refed_count--;
            th->immediate_refed = false;
            immediate_state_update_ref(state);
        }
        HASH_DEL(qrt->timers.timers, th);
        free_now = !th->in_cb && th->active_refs == 0;
        if (free_now) {
            free_timer_values(ctx, th);
            tjs__free(th);
        }
        state->dispatch_refs--;
        immediate_state_maybe_close(state);
        return;
    }

    uv_handle_t *handle = uv_handle_for_timer(th);

    if (uv_is_closing(handle))
        return;

    th->active_refs++;
    stop_timer(th, qrt);
    HASH_DEL(qrt->timers.timers, th);

    uv_close(handle, uv__timer_close);
    if (!th->in_cb)
        free_timer_values(ctx, th);
    timer_release_ref(th);
}

void tjs__destroy_timers(TJSRuntime *qrt) {
    while (qrt->timers.timers)
        destroy_timer(qrt->timers.timers);
}

void tjs__cancel_timers_for_context(TJSRuntime *qrt, JSContext *ctx) {
    for (;;) {
        TJSTimer *timer = qrt->timers.timers;
        while (timer && timer->ctx != ctx)
            timer = timer->hh.next;
        if (!timer)
            return;
        destroy_timer(timer);
    }
}

static void finish_timer_callback(TJSTimer *th) {
    if (th->immediate) {
        th->in_cb = false;
        timer_release_ref(th);
        return;
    }
    if (uv_is_closing(uv_handle_for_timer(th)))
        free_timer_values(th->ctx, th);
    th->in_cb = false;
    timer_release_ref(th);
}

static bool run_timer(TJSTimer *th) {
    CHECK_NOT_NULL(th);
    TJSRuntime *qrt = TJS_GetRuntime(th->ctx);
    uv_handle_t *handle = uv_handle_for_timer(th);

    if (qrt->freeing || th->in_cb || th->destroyed || uv_is_closing(handle))
        return false;

    if (!th->immediate)
        th->active_refs++;
    th->in_cb = true;
    /* Micro-tasks should run before timers. */
    tjs__execute_jobs(qrt);

    /* Check again in case the timer was destroyed during job execution. */
    if (!th->immediate && uv_is_closing(handle)) {
        finish_timer_callback(th);
        return true;
    }
    if (th->destroyed) {
        finish_timer_callback(th);
        return true;
    }
    tjs_call_handler(th->ctx, th->func, th->argc, th->argv);

    if ((th->immediate || !th->interval) && !uv_is_closing(handle))
        destroy_timer(th);

    finish_timer_callback(th);
    return true;
}

static void uv__timer_cb(uv_timer_t *handle) {
    run_timer(handle->data);
}

static void uv__immediate_cb(uv_check_t *handle) {
    TJSImmediateState *state = handle->data;
    if (state->dispatch_refs) return;
    state->dispatch_refs++;
    TJSTimer *th = state->head;
    state->head = NULL;
    state->tail = NULL;
    for (TJSTimer *queued = th; queued; queued = queued->immediate_next) {
        queued->immediate_prev = NULL;
        queued->immediate_queued = false;
        state->dispatch_refs++;
        queued->active_refs++;
    }
    while (th) {
        TJSTimer *next = th->immediate_next;
        th->immediate_next = NULL;
        CHECK_EQ(state->runtime->timers.pending_immediates > 0, true);
        state->runtime->timers.pending_immediates--;
        tjs__notify_work(state->runtime);
        if (th->destroyed) {
            immediate_timer_release_ref(th);
        } else if (!run_timer(th)) {
            /* A skipped Immediate never reaches finish_timer_callback(). */
            destroy_timer(th);
            immediate_timer_release_ref(th);
        }
        th = next;
    }
    state->dispatch_refs--;
    immediate_state_maybe_close(state);
}

static JSValue tjs_setTimer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv, int magic) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    if (qrt->freeing)
        return tjs_throw_errno_msg(ctx, UV_ESHUTDOWN, "runtime is shutting down");

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "callback is required");
    }

    bool immediate = magic == 2;
    int arg_offset = immediate ? 1 : 2;
    int64_t delay = 0;
    JSValue func;
    TJSTimer *th;

    func = argv[0];
    if (!JS_IsFunction(ctx, func)) {
        return JS_ThrowTypeError(ctx, "not a function");
    }

    if (!immediate) {
        if (argc <= 1) {
            delay = 0;
        } else if (JS_ToInt64(ctx, &delay, argv[1])) {
            return JS_EXCEPTION;
        }
    }

    /* Negative delays would wrap to a huge uint64 timeout in libuv. */
    if (delay < 0) {
        delay = 0;
    }

    int nargs = argc - arg_offset;
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
    th->interval = !immediate && magic == 1;
    th->immediate = immediate;
    th->in_cb = false;
    th->active_refs = 0;
    th->close_completed = false;
    th->destroyed = false;
    th->immediate_queued = false;
    th->immediate_refed = false;
    th->immediate_state = NULL;
    th->immediate_prev = NULL;
    th->immediate_next = NULL;

    th->id = qrt->timers.next_timer++;
    if (qrt->timers.next_timer > MAX_SAFE_INTEGER) {
        qrt->timers.next_timer = 1;
    }

    th->ctx = ctx;
    int uv_r = 0;
    TJSImmediateState *state = NULL;
    if (immediate) {
        state = immediate_state_for_runtime(qrt);
        if (!state) {
            tjs__free(th);
            return JS_ThrowOutOfMemory(ctx);
        }
        th->immediate_state = state;
    } else {
        uv_r = uv_timer_init(tjs_get_loop(ctx), &th->handle);
        if (uv_r == 0)
            th->handle.data = th;
    }
    if (uv_r != 0) {
        tjs__free(th);
        return tjs_throw_errno(ctx, uv_r);
    }
    th->func = JS_DupValue(ctx, func);
    th->argc = nargs;
    for (int i = 0; i < nargs; i++) {
        th->argv[i] = JS_DupValue(ctx, argv[i + arg_offset]);
    }

    if (!immediate) {
        uv_update_time(tjs_get_loop(ctx));
        /* libuv treats repeat=0 as one-shot; a zero-delay interval must still
         * repeat, or the timer (and its JS args) stay in the table forever. */
        uint64_t repeat = th->interval ? (delay == 0 ? 1u : (uint64_t)delay) : 0;
        uv_r = uv_timer_start(&th->handle, uv__timer_cb, (uint64_t)delay, repeat);
    }
    if (!immediate && uv_r != 0) {
        th->active_refs++;
        uv_close(uv_handle_for_timer(th), uv__timer_close);
        free_timer_values(ctx, th);
        timer_release_ref(th);
        return tjs_throw_errno(ctx, uv_r);
    }

    if (immediate) {
        HASH_ADD_INT64(qrt->timers.timers, id, th);
        immediate_state_queue_add(state, th);
        state->refed_count++;
        th->immediate_refed = true;
        qrt->timers.pending_immediates++;
        if (!uv_is_active((uv_handle_t *)&state->check)) {
            uv_r = uv_check_start(&state->check, uv__immediate_cb);
            if (uv_r != 0) {
                destroy_timer(th);
                return tjs_throw_errno(ctx, uv_r);
            }
        }
        immediate_state_update_ref(state);
        tjs__notify_work(qrt);
    } else {
        HASH_ADD_INT64(qrt->timers.timers, id, th);
    }

    return JS_NewInt64(ctx, th->id);
}

static JSValue tjs_clearTimer(JSContext *ctx, JSValue this_val, int argc,
                              JSValue *argv, int magic) {
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

    bool immediate = magic != 0;
    if (th != NULL && th->immediate == immediate)
        destroy_timer(th);

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

    bool immediate = magic >= 3;
    if (th->immediate != immediate)
        return JS_ThrowTypeError(ctx, "timer type mismatch");

    uv_handle_t *handle = uv_handle_for_timer(th);
    if (th->immediate) {
        TJSImmediateState *state = th->immediate_state;
        switch (magic % 3) {
            case 0:
                if (!th->immediate_refed) {
                    th->immediate_refed = true;
                    state->refed_count++;
                    immediate_state_update_ref(state);
                }
                break;
            case 1:
                if (th->immediate_refed) {
                    th->immediate_refed = false;
                    CHECK_GT(state->refed_count, 0);
                    state->refed_count--;
                    immediate_state_update_ref(state);
                }
                break;
            case 2:
                return JS_NewBool(ctx, th->immediate_refed);
        }
    } else switch (magic % 3) {
        case 0:
            uv_ref(handle);
            break;
        case 1:
            uv_unref(handle);
            break;
        case 2:
            return JS_NewBool(ctx, uv_has_ref(handle));
    }

    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_timer_funcs[] = {
    JS_CFUNC_MAGIC_DEF("setTimeout", 2, tjs_setTimer, 0),
    JS_CFUNC_MAGIC_DEF("clearTimeout", 1, tjs_clearTimer, 0),
    JS_CFUNC_MAGIC_DEF("setInterval", 2, tjs_setTimer, 1),
    JS_CFUNC_MAGIC_DEF("clearInterval", 1, tjs_clearTimer, 0),
    JS_CFUNC_MAGIC_DEF("setImmediate", 1, tjs_setTimer, 2),
    JS_CFUNC_MAGIC_DEF("clearImmediate", 1, tjs_clearTimer, 1),
    JS_CFUNC_MAGIC_DEF("refTimer", 1, tjs_timer_ref, 0),
    JS_CFUNC_MAGIC_DEF("unrefTimer", 1, tjs_timer_ref, 1),
    JS_CFUNC_MAGIC_DEF("hasRef", 1, tjs_timer_ref, 2),
    JS_CFUNC_MAGIC_DEF("refImmediate", 1, tjs_timer_ref, 3),
    JS_CFUNC_MAGIC_DEF("unrefImmediate", 1, tjs_timer_ref, 4),
    JS_CFUNC_MAGIC_DEF("hasRefImmediate", 1, tjs_timer_ref, 5),
};

void tjs__mod_timers_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_timer_funcs, countof(tjs_timer_funcs));
}
