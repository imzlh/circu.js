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

#include "mem.h"
#include "private.h"
#include "tjs.h"
#include "binary.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#ifdef CJS__HAS_WASM
#include "wasm_export.h"
#endif

#define TJS__DEFAULT_STACK_SIZE 6 * 1024 * 1024  // 6MB

static int tjs__argc = 0;
static char** tjs__argv = NULL;

/* Keep the standard descriptor numbers reserved when the parent closes one. */
static void tjs__normalize_stdio(void) {
#ifdef _WIN32
    const int modes[3] = { _O_RDONLY | _O_BINARY, _O_WRONLY | _O_BINARY, _O_WRONLY | _O_BINARY };
    for (int fd = 0; fd < 3; fd++) {
        /* Do not probe a missing CRT fd with _get_osfhandle(): MSVCRT may
         * invoke the process-wide invalid-parameter handler for that call.
         * Opening NUL allocates the lowest free slot, so its result tells us
         * whether this descriptor number was vacant without an unsafe probe. */
        int nullfd = _open("NUL", modes[fd], 0);
        if (nullfd < 0) continue;
        if (nullfd == fd) continue;
        _close(nullfd);
    }
#else
    const int modes[3] = { O_RDONLY, O_WRONLY, O_WRONLY };
    for (int fd = 0; fd < 3; fd++) {
        int flags;
        do {
            flags = fcntl(fd, F_GETFD);
        } while (flags == -1 && errno == EINTR);
        if (flags != -1 || errno != EBADF) continue;
        int nullfd = open("/dev/null", modes[fd], 0);
        if (nullfd < 0 || nullfd == fd) continue;
        if (dup2(nullfd, fd) < 0) {
            close(nullfd);
            continue;
        }
        close(nullfd);
    }
#endif
}


/* JS malloc functions */
static void* tjs__mf_calloc(void* opaque, size_t count, size_t size) {
    (void) opaque;
    return tjs__calloc(count, size);
}

static void* tjs__mf_malloc(void* opaque, size_t size) {
    (void) opaque;
    return tjs__malloc(size);
}

static void tjs__mf_free(void* opaque, void* ptr) {
    (void) opaque;
    tjs__free(ptr);
}

static void* tjs__mf_realloc(void* opaque, void* ptr, size_t size) {
    (void) opaque;
    return tjs__realloc(ptr, size);
}

static const JSMallocFunctions tjs_mf = {
    .js_calloc = tjs__mf_calloc,
    .js_malloc = tjs__mf_malloc,
    .js_free = tjs__mf_free,
    .js_realloc = tjs__mf_realloc,
    .js_malloc_usable_size = tjs__malloc_usable_size,
};

/* SharedArrayBuffer functions */

typedef struct {
    _Atomic int ref_count;
    uint8_t buf[0];
} TJSSABHeader;

static int atomic_add_int(_Atomic int* ptr, int v) {
    return atomic_fetch_add_explicit(ptr, v, memory_order_acq_rel) + v;
}

void* tjs__sab_alloc(void* opaque, size_t size) {
    TJSSABHeader* sab = tjs__malloc(sizeof(*sab) + size);
    if (!sab) {
        return NULL;
    }
    sab->ref_count = 1;
    return sab->buf;
}

void tjs__sab_free(void* opaque, void* ptr) {
    TJSSABHeader* sab = (TJSSABHeader*) ((uint8_t*) ptr - sizeof(TJSSABHeader));
    int ref_count = atomic_add_int(&sab->ref_count, -1);
    assert(ref_count >= 0);
    if (ref_count == 0) {
        tjs__free(sab);
    }
}

void tjs__sab_dup(void* opaque, void* ptr) {
    TJSSABHeader* sab = (TJSSABHeader*) ((uint8_t*) ptr - sizeof(TJSSABHeader));
    atomic_add_int(&sab->ref_count, 1);
}

static const JSSharedArrayBufferFunctions tjs_sf = {
    .sab_alloc = tjs__sab_alloc,
    .sab_dup = tjs__sab_dup,
    .sab_free = tjs__sab_free,
    .sab_opaque = NULL,
};

typedef struct {
    uint32_t count;
} TJSClosingHandleCount;

static void tjs__count_closing_handles_walk_cb(uv_handle_t *handle, void *opaque) {
    TJSClosingHandleCount *state = opaque;
    if (uv_is_closing(handle)) {
        state->count++;
    }
}

static uint32_t tjs__count_closing_handles(TJSRuntime *qrt) {
    TJSClosingHandleCount state = { 0 };
    uv_walk(&qrt->loop, tjs__count_closing_handles_walk_cb, &state);
    return state.count;
}

static void tjs__drain_closing_handles(TJSRuntime *qrt, int max_ticks) {
    for (int i = 0; i < max_ticks; i++) {
        if (tjs__count_closing_handles(qrt) == 0) {
            return;
        }
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
}

// utils

JSContext* TJS_GetJSContext(App* app) {
    return app->ctx;
}

App* TJS_GetApp(JSContext* ctx) {
    return JS_GetContextOpaque(ctx);
}

TJSRuntime* TJS_GetRuntime(JSContext* ctx) {
    return JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
}

JSValue tjs__get_args(JSContext* ctx) {
    JSValue args = JS_NewArray(ctx);
    for (int i = 0; i < tjs__argc; i++) {
        JS_SetPropertyUint32(ctx, args, i, JS_NewString(ctx, tjs__argv[i]));
    }
    return args;
}

static int tjs__use_sourcemap(JSContext* ctx, const char* name, int* line, int* col) {
    TJSRuntime* qrt = TJS_GetRuntime(ctx);

    MappingResult res = js_get_source_mapping(qrt->module.mapctx, name, *line, *col);
    if (res.found) {
        *line = res.original_line;
        *col = res.original_column;
    }
    return res.found;
}

static JSValue tjs__promise_rejection_dispatch(JSContext* ctx, int argc, JSValueConst* argv) {
    JSValue promise = argv[0], reason = argv[1];
    if (JS_PromiseIsHandled(ctx, promise)) return JS_UNDEFINED;

    JSValue args = JS_NewArrayFrom(ctx, 2, (JSValueConst[]) {
        JS_DupValue(ctx, promise), JS_DupValue(ctx, reason)
    });

    JSValue ret = tjs__dispatch_event(ctx, EV_UNHANDLED_REJECTION, args);
    JS_FreeValue(ctx, args);

    if (JS_IsException(ret)) {
        TJS_DumpException(ctx);
        goto fail;
    }
    else {
        if (!JS_IsEqual(ctx, ret, JS_FALSE)) {
            // The event wasn't cancelled or not handled(true), maybe abort.
        fail:;
            TJSRuntime* qrt = TJS_GetRuntime(ctx);
            CHECK_NOT_NULL(qrt);
#ifdef DEBUG
            fprintf(stderr, "[CORE] PROMISE_REJECTION: ");
            tjs_dump_error(ctx, reason);
#endif
            JS_FreeValue(ctx, ret);
            return JS_EXCEPTION;
        }
    }

    JS_FreeValue(ctx, ret);
    return JS_UNDEFINED;
}

static void tjs__promise_rejection_tracker(JSContext* ctx, JSValue promise, JSValue reason, bool is_handled, void* opaque) {
    (void) opaque;
    TJSRuntime* qrt = TJS_GetRuntime(ctx);
    App* app = TJS_GetApp(ctx);
    CHECK_NOT_NULL(app);

    if (!qrt->freeing && !is_handled) {
        JSValue argv[2] = { promise, reason };
        if (JS_EnqueueJob(app->ctx, tjs__promise_rejection_dispatch, 2, (JSValueConst*) argv) < 0) {
            TJS_DumpException(ctx);
        }
    }
}

static void uv__stop(uv_async_t* handle) {
    TJSRuntime* trt = handle->data;
    CHECK_NOT_NULL(trt);

    /* Dispatch EV_EXIT here (inside the event loop) to ensure JS calls are
     * always made from the correct thread. TJS_Stop may be called from a
     * different thread (e.g. main thread stopping a worker), so JS dispatch
     * must NOT happen in TJS_Stop itself. */
    tjs__dispatch_event2(trt->main_ctx, EV_EXIT, JS_NewInt32(trt->main_ctx, trt->exit_code));
    uv_stop(&trt->loop);
}

void TJS_DefaultOptions(TJSRunOptions* options) {
    static TJSRunOptions default_options = { .mem_limit = 0, .stack_size = TJS__DEFAULT_STACK_SIZE };

    memcpy(options, &default_options, sizeof(*options));
}

TJSRuntime* TJS_NewRuntime(void) {
    TJSRunOptions options;
    TJS_DefaultOptions(&options);
    return TJS_NewRuntimeInternal(false, &options);
}

TJSRuntime* TJS_NewRuntimeOptions(TJSRunOptions* options) {
    return TJS_NewRuntimeInternal(false, options);
}

TJSRuntime* TJS_NewRuntimeWorker(void) {
    TJSRunOptions options;
    TJS_DefaultOptions(&options);
    return TJS_NewRuntimeInternal(true, &options);
}

App* TJS_NewAppInternal(TJSRuntime* trt, bool is_sandbox) {
    JSContext* ctx = is_sandbox ? JS_NewContextRaw(trt->rt) : JS_NewContext(trt->rt);
    App* app = tjs__mallocz(sizeof(App));
    app->ctx = ctx;
    app->is_sandbox = is_sandbox;
    app->trt = trt;
    init_list_head(&app->link);
    JS_SetContextOpaque(ctx, app);

    if (is_sandbox) {
        App* main_app = TJS_GetApp(trt->main_ctx);
        list_add_tail(&app->link, &main_app->link);
    }
    return app;
}

App* TJS_NewApp(TJSRuntime* trt) {
    return TJS_NewAppInternal(trt, true);
}

TJSRuntime* TJS_NewRuntimeInternal(bool is_worker, TJSRunOptions* options) {
    JSRuntime* rt = NULL;
    TJSRuntime* qrt = tjs__mallocz(sizeof(*qrt));

    memcpy(&qrt->options, options, sizeof(*options));

    /* Create Runtime */
    rt = JS_NewRuntime2(&tjs_mf, NULL);
    CHECK_NOT_NULL(rt);
    qrt->rt = rt;
    JS_SetRuntimeOpaque(rt, qrt);

    /* Create main app */
    App* app = TJS_NewAppInternal(qrt, false);
    JSContext* ctx = app->ctx;
    qrt->main_ctx = ctx;

    /* Set memory limit */
    JS_SetMemoryLimit(rt, options->mem_limit);

    /* Set stack size */
    JS_SetMaxStackSize(rt, options->stack_size);

    /* SharedArrayBuffer functions */
    JS_SetSharedArrayBufferFunctions(rt, &tjs_sf);

    /* Debug */
#ifdef DEBUG
    JS_SetDumpFlags(rt, JS_DUMP_LEAKS);
#endif

    /* Worker support */
    qrt->is_worker = is_worker;
    JS_SetCanBlock(rt, true);
    init_list_head(&qrt->workers);
    init_list_head(&qrt->streams);
    init_list_head(&qrt->msgpipes);

    CHECK_EQ(uv_loop_init(&qrt->loop), 0);

    /* handle which runs the job queue */
    CHECK_EQ(uv_prepare_init(&qrt->loop, &qrt->jobs.prepare), 0);
    qrt->jobs.prepare.data = qrt;

    /* handle to prevent the loop from blocking for i/o when there are pending jobs. */
    CHECK_EQ(uv_idle_init(&qrt->loop, &qrt->jobs.idle), 0);
    qrt->jobs.idle.data = qrt;

    /* handle which runs the job queue */
    CHECK_EQ(uv_check_init(&qrt->loop, &qrt->jobs.check), 0);
    qrt->jobs.check.data = qrt;

    /* Initialize job control state */
    qrt->jobs.paused = false;
    qrt->jobs.waitio_depth = 0;

    /* handle for stopping this runtime (also works from another thread) */
    CHECK_EQ(uv_async_init(&qrt->loop, &qrt->stop, uv__stop), 0);
    qrt->stop.data = qrt;

    /* loader for ES modules */
    JS_SetModuleLoaderFunc2(rt, tjs__module_normalizer, tjs__module_loader, tjs__module_checkattr, qrt);
    JS_SetModuleNormalizeFunc2(rt, tjs__module_normalizer_attr);
    qrt->module.resolver = qrt->module.loader =
        qrt->module.metaloader = qrt->module.attrchecker = JS_UNDEFINED;

    /* unhandled promise rejection tracker */
    JS_SetHostPromiseRejectionTracker(rt, tjs__promise_rejection_tracker, NULL);

    /* debug hook */
    qrt->module.mapctx = js_create_mapping_context();
    JS_SetBacktraceHook(rt, tjs__use_sourcemap, NULL);

    /* define some global properties */
    JSValue global_obj = JS_GetGlobalObject(ctx);
    CHECK_EQ(JS_DefinePropertyValueStr(ctx, global_obj, "isWorker", JS_NewBool(ctx, is_worker), JS_PROP_ENUMERABLE), true);

    /* Load some builtin references for easy access */
    qrt->builtins.promise_hook_fn = JS_UNDEFINED;
    qrt->builtins.dispatch_event_fn = JS_UNDEFINED;
    qrt->builtins.worker_udata = JS_UNDEFINED;
    qrt->builtins.message_pipe = JS_UNDEFINED;

    /* debug */
    qrt->debug.onBreak = JS_UNDEFINED;
    qrt->debug.onException = JS_UNDEFINED;
    qrt->debug.active = false;
    qrt->debug.exception_break_mode = 0;
    qrt->debug.breakpoints_active = true;
    qrt->debug.breakpoints = NULL;
    qrt->debug.step_mode = 0;
    qrt->debug.step_depth = 0;
    qrt->debug.pause_depth = 0;

    /* runtime-shared module namespace cache */
    qrt->module.imod_ns = JS_NewObjectProto(ctx, JS_NULL);

    /* external native module registry */
    qrt->module.dyn_registry = JS_NewObjectProto(ctx, JS_NULL);
    init_list_head(&qrt->module.dyn_libs);

    /* if import.meta.use not enabled, inject to global */
#ifdef CJS__DISABLE_MODULE_USE
    // define use()
    JSValue use_sym = JS_NewSymbol(ctx, "cjs.internal.use", true);
    JSAtom use_atom = JS_ValueToAtom(ctx, use_sym);
    JSValue use_func = JS_NewCFunctionData(ctx, tjs__module_use, 1, 0, 1, (JSValueConst[]) { qrt->module.imod_ns });
    JS_DefinePropertyValue(ctx, global_obj, use_atom, use_func, JS_PROP_C_W_E);
    JS_FreeAtom(ctx, use_atom);
    JS_FreeValue(ctx, use_sym);

    // define register() for external native modules
    JSValue reg_sym = JS_NewSymbol(ctx, "cjs.internal.register", true);
    JSAtom reg_atom = JS_ValueToAtom(ctx, reg_sym);
    JSValue reg_func = JS_NewCFunction(ctx, tjs__module_register, "register", 2);
    JS_DefinePropertyValue(ctx, global_obj, reg_atom, reg_func, JS_PROP_C_W_E);
    JS_FreeAtom(ctx, reg_atom);
    JS_FreeValue(ctx, reg_sym);
#endif

    /* end bootstrap */
    JS_FreeValue(ctx, global_obj);

    /* WASM */
#ifdef CJS__HAS_WASM

// 	RunningMode pref_mode;
// #define MCHECK(mode) if (wasm_runtime_is_running_mode_supported (mode)) pref_mode = mode; else
// 	MCHECK(Mode_Multi_Tier_JIT) MCHECK(Mode_Fast_JIT) MCHECK(Mode_Interp) abort();
// #undef MCHECK

// 	RuntimeInitArgs init_args = {
// 		.mem_alloc_type = Alloc_With_Allocator,
// 		.mem_alloc_option = {
// 			.allocator = {
// 				.malloc_func = tjs__malloc,
// 				.realloc_func = tjs__realloc,
// 				.free_func = tjs__free,
// 				.user_data = NULL
// 			}
// 		},
// 		.max_thread_num = 0,
// 		.running_mode = pref_mode,
// 		0				// NULL padding
// 	};

// 	CHECK_EQ(wasm_runtime_full_init(&init_args), true);
    wasm_runtime_init();

#ifdef DEBUG
    wasm_runtime_set_log_level(WASM_LOG_LEVEL_VERBOSE);
#endif
#endif

    /* Timers */
    qrt->timers.timers = NULL;
    qrt->timers.next_timer = 1;

    return qrt;
}

void TJS_FreeRuntime(TJSRuntime* qrt) {
    qrt->freeing = true;

    /* Stop all workers and wait for their threads to finish before freeing
     * any shared state.  TJS_Stop is async (uv_async_send), so we must
     * join to ensure the thread has exited. The TJSWorker struct itself is
     * owned by the JS Worker object and freed by tjs_worker_finalizer below
     * (which runs from JS_FreeRuntime). */
    {
        struct list_head* p, * tmp;
        list_for_each_safe(p, tmp, &qrt->workers) {
            TJSWorker* worker = list_entry(p, TJSWorker, link);
            tjs__worker_stop_and_join(worker->ctx, worker);
        }
    }

    /* Close stream handles before freeing JS so stream_pin() self-references
     * don't survive into QuickJS leak checking as TCP/Pipe/TTY objects. */
    tjs__close_all_streams(qrt);
    tjs__close_all_msgpipes(qrt);
    tjs__drain_closing_handles(qrt, 64);

    /* Close all core loop handles. */
    uv_close((uv_handle_t*) &qrt->jobs.prepare, NULL);
    uv_close((uv_handle_t*) &qrt->jobs.idle, NULL);
    uv_close((uv_handle_t*) &qrt->jobs.check, NULL);
    uv_close((uv_handle_t*) &qrt->stop, NULL);
    tjs__drain_closing_handles(qrt, 64);

    /* Poison module hooks so that any subsequent access from C closures
     * (e.g. enqueue/tryDone) triggers an immediate ASan report instead of
     * silent use-after-free inside JS_FreeRuntime's GC phase. */
    JSContext* ctx = qrt->main_ctx;
    JSValue old_resolver = qrt->module.resolver;
    JSValue old_loader = qrt->module.loader;
    JSValue old_metaloader = qrt->module.metaloader;
    JSValue old_attrchecker = qrt->module.attrchecker;
    qrt->module.resolver = qrt->module.loader =
        qrt->module.metaloader = qrt->module.attrchecker = JS_UNDEFINED;

    /* Now free the JSValues.  If any C closure still holds a reference,
     * ASan will flag the access to old_resolver/old_loader below. */
    JS_FreeValue(ctx, old_resolver);
    JS_FreeValue(ctx, old_loader);
    JS_FreeValue(ctx, old_metaloader);
    JS_FreeValue(ctx, old_attrchecker);

    /* remove built-in data */
    JS_FreeValue(ctx, qrt->builtins.worker_udata);
    qrt->builtins.worker_udata = JS_UNDEFINED;
    JS_FreeValue(ctx, qrt->builtins.dispatch_event_fn);
    qrt->builtins.dispatch_event_fn = JS_UNDEFINED;
    JS_FreeValue(ctx, qrt->builtins.promise_hook_fn);
    qrt->builtins.promise_hook_fn = JS_UNDEFINED;
    JS_FreeValue(ctx, qrt->builtins.message_pipe);
    qrt->builtins.message_pipe = JS_UNDEFINED;

    /* Destroy shared module namespace */
    JS_FreeValue(ctx, qrt->module.imod_ns);

    /* Destroy external native module registry */
    JS_FreeValue(ctx, qrt->module.dyn_registry);

    /* remove debug sourcemap */
    js_destroy_mapping_context(qrt->module.mapctx);

    /* cleanup debug state */
    {
        TJSBreakpoint *bp, *tmp;
        HASH_ITER(hh, qrt->debug.breakpoints, bp, tmp) {
            HASH_DEL(qrt->debug.breakpoints, bp);
            JS_FreeAtom(ctx, bp->filename);
            js_free(ctx, bp);
        }
    }
    JS_FreeValue(ctx, qrt->debug.onBreak);
    JS_FreeValue(ctx, qrt->debug.onException);

    /* Destroy all timers and drain the Promise job queue. */
    JSContext *job_ctx;
    tjs__destroy_timers(qrt);
    while (JS_ExecutePendingJob(qrt->rt, &job_ctx) != 0) {
        /* drain */
    }

    /* Release Node-API persistent JS references before QuickJS leak checking.
     * The env structs remain alive until JS_FreeRuntime finalizers, so JS object
     * finalizers can still call native addon finalizers with a valid env. */
    tjs__nodeapi_cleanup_runtime(qrt);
    for (int i = 0; i < 5; i++) {
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
    JS_RunGC(qrt->rt);
    tjs__drain_closing_handles(qrt, 64);
    tjs__nodeapi_cleanup_runtime(qrt);
    for (int i = 0; i < 5; i++) {
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
    JS_RunGC(qrt->rt);
    tjs__drain_closing_handles(qrt, 64);

    /* Cleanup all contexts: main app first, then sandbox apps.
     * The list is headed by &main_app->link (created in
     * TJS_NewRuntimeInternal).  Sandbox apps are appended via
     * list_add_tail in TJS_NewAppInternal. */
    {
        App* main_app = TJS_GetApp(ctx);
        JS_FreeContext(main_app->ctx);
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &main_app->link) {
            App* app = list_entry(cur, App, link);
            JS_FreeContext(app->ctx);
            list_del(&app->link);
            tjs__free(app);
        }
        tjs__free(main_app);
    }

    /* Destroy the JS engine. */
    JS_FreeRuntime(qrt->rt);
    tjs__drain_closing_handles(qrt, 64);
    tjs__free_orphaned_streams(qrt);


    {
        struct list_head* p, * tmp;
        list_for_each_safe(p, tmp, &qrt->module.dyn_libs) {
            TJSDynLib* node = list_entry(p, TJSDynLib, link);
            list_del(p);
            uv_dlclose(&node->lib);
            free(node);
        }
    }

    /* Destroy WASM runtime. */
#ifdef CJS__HAS_WASM
    wasm_runtime_destroy();
#endif

    /* Cleanup loop. All handles should be closed. */
    int closed = 0;
    for (int i = 0; i < 5; i++) {
        if (uv_loop_close(&qrt->loop) == 0) {
            closed = 1;
            break;
        }
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
#ifdef DEBUG
    if (!closed) {
        uv_print_all_handles(&qrt->loop, stderr);
    }
    CHECK_EQ(closed, 1);
#else
    (void) closed;
#endif

    tjs__free(qrt);
}

void TJS_Initialize(int argc, char** argv) {
    CHECK_EQ(0, uv_replace_allocator(tjs__malloc, tjs__realloc, tjs__calloc, tjs__free));

    tjs__normalize_stdio();

    tjs__argc = argc;
    tjs__argv = uv_setup_args(argc, argv);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
}

static void uv__idle_cb(uv_idle_t* handle) {
    // Noop
}

static void uv__maybe_idle(TJSRuntime* qrt) {
    if (JS_IsJobPending(qrt->rt)) {
        CHECK_EQ(uv_idle_start(&qrt->jobs.idle, uv__idle_cb), 0);
    }
    else {
        CHECK_EQ(uv_idle_stop(&qrt->jobs.idle), 0);
    }
}

static void uv__prepare_cb(uv_prepare_t* handle) {
    TJSRuntime* qrt = handle->data;
    CHECK_NOT_NULL(qrt);

    uv__maybe_idle(qrt);
}

void tjs__execute_jobs(TJSRuntime* trt) {
    JSContext* ctx1;
    int err;

    assert(trt != NULL);

    /* execute the pending jobs */
    while (!trt->jobs.paused) {
        err = JS_ExecutePendingJob(trt->rt, &ctx1);
        if (err <= 0) {
            if (err < 0) {
                JSValue js_err = JS_GetException(ctx1);
                if (JS_IsUncatchableError(js_err)) {
                    TJS_Stop(trt);
                    JS_FreeValue(ctx1, js_err);
                    break;
                }
                JSValue retv = tjs__dispatch_event(ctx1, EV_JOB_EXCEPTION, js_err);
                if (JS_IsEqual(ctx1, retv, JS_FALSE)) {
#ifdef DEBUG
                    fprintf(stderr, "[CORE] JOB: ");
                    tjs_dump_error(ctx1, js_err);
#endif
                    TJS_Stop(trt);
                }
                JS_FreeValue(ctx1, js_err);
                JS_FreeValue(ctx1, retv);
            }

            break;
        }
    }
}

static void uv__check_cb(uv_check_t* handle) {
    TJSRuntime* qrt = handle->data;
    CHECK_NOT_NULL(qrt);

    /* Don't execute jobs here if we're inside waitIO - it handles jobs itself */
    if (qrt->jobs.waitio_depth == 0) {
        tjs__execute_jobs(qrt);
    }

    uv__maybe_idle(qrt);
}

static int tjs__eval_bytecode(JSContext* ctx, const uint8_t* buf, size_t buf_len, bool check_promise) {
    JSValue obj = JS_ReadObject(ctx, buf, buf_len, JS_READ_OBJ_BYTECODE);
    bool obj_owned = !JS_IsException(obj);
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    (void) trt;

    if (JS_IsException(obj)) {
        goto error;
    }

    if (JS_VALUE_GET_TAG(obj) == JS_TAG_MODULE) {
        if (JS_ResolveModule(ctx, obj) < 0) {
            goto error;  // obj still owned, freed at error label
        }

        // define module meta
        JSModuleDef* m = JS_VALUE_GET_PTR(obj);
        JSValue meta = JS_GetImportMeta(ctx, m);
        if (JS_IsException(meta)) {
            goto error;  // obj still owned, freed at error label
        }

#ifndef CJS__DISABLE_MODULE_USE
        // define use()
        JSValue use_func = JS_NewCFunctionData(ctx, tjs__module_use, 1, 0, 1, (JSValueConst[]) { trt->module.imod_ns });
        JS_DefinePropertyValueStr(ctx, meta, "use", use_func, JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, meta, "module", tjs__mod_list_init(ctx), JS_PROP_C_W_E);

        // define register() for external native modules
        JSValue reg_func = JS_NewCFunction(ctx, tjs__module_register, "register", 2);
        JS_DefinePropertyValueStr(ctx, meta, "register", reg_func, JS_PROP_C_W_E);
#endif

        // end
        JS_FreeValue(ctx, meta);
    }

    JSValue val = JS_EvalFunction(ctx, obj);
    obj_owned = false;  // obj consumed by JS_EvalFunction
    if (JS_IsException(val)) {
        goto error;
    }

    if (check_promise) {
        JSPromiseStateEnum promise_state = JS_PromiseState(ctx, val);
        if (promise_state != -1) {
            // It's a promise!
            if (promise_state == JS_PROMISE_REJECTED) {
                JSValue res = JS_PromiseResult(ctx, val);
                tjs_dump_error(ctx, res);
                JS_FreeValue(ctx, res);
                JS_FreeValue(ctx, val);

                return -1;
            }
        }
    }

    JS_FreeValue(ctx, val);

    return 0;

error:
    if (obj_owned) {
        JS_FreeValue(ctx, obj);
    }
    TJS_DumpException(ctx);
    return -1;
}

void tjs__run_main(TJSRuntime* qrt) {
    /* get built-in script */
    uint8_t* tjs__core_js = NULL;
    uint32_t tjs__core_js_size = 0;
    tjs__core_js = tjs__read_self_attached(&tjs__core_js_size);
    if (tjs__core_js_size == 0 || !tjs__core_js) {
        fprintf(stderr, "CorePanic: Cannot load embedded core JS script\n");
        exit(1);
    }

    /* If we are running the main interpreter, run the entrypoint. */
    if (tjs__eval_bytecode(qrt->main_ctx, tjs__core_js, tjs__core_js_size, true) != 0) {
#ifdef DEBUG
        fprintf(stderr, "CorePanic: Eval entry script failed immediately\n");
#endif
        exit(1);
    }
}

/* main loop which calls the user JS callbacks */
int TJS_Run(TJSRuntime* qrt) {
    CHECK_EQ(uv_prepare_start(&qrt->jobs.prepare, uv__prepare_cb), 0);
    uv_unref((uv_handle_t*) &qrt->jobs.prepare);
    CHECK_EQ(uv_check_start(&qrt->jobs.check, uv__check_cb), 0);
    uv_unref((uv_handle_t*) &qrt->jobs.check);

    uv_unref((uv_handle_t*) &qrt->stop);
    if (!qrt->is_worker) {
        tjs__run_main(qrt);
    }

    if (qrt->exit_code != 0) {
        return qrt->exit_code;
    }

    int r;
    do {
        uv__maybe_idle(qrt);
        r = uv_run(&qrt->loop, UV_RUN_DEFAULT);
    } while (r != 0 && JS_IsJobPending(qrt->rt));

    return qrt->exit_code;
}

void TJS_Stop(TJSRuntime* qrt) {
    CHECK_NOT_NULL(qrt);
    if (!qrt->is_worker && qrt->exit_code == 0) qrt->exit_code = 1;
    /* Only uv_async_send is thread-safe; JS dispatch is deferred to uv__stop
     * which runs inside the target runtime's own event loop thread. */
    uv_async_send(&qrt->stop);
}

uv_loop_t* TJS_GetLoop(TJSRuntime* qrt) {
    return &qrt->loop;
}
