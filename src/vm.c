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
#include "capability.h"

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

/* Implemented in utils.c — see the OBSERVED table there. Declared locally
 * rather than in utils.h because that header is shared with concurrent work. */
size_t tjs__clamp_stack_size(size_t requested, bool *was_clamped);

static int tjs__argc = 0;
static char** tjs__argv = NULL;

/* Keep the standard descriptor numbers reserved when the parent closes one,
 * and force binary mode on the ones we inherited. */
static void tjs__normalize_stdio(void) {
#ifdef _WIN32
    const int modes[3] = { _O_RDONLY | _O_BINARY, _O_WRONLY | _O_BINARY, _O_WRONLY | _O_BINARY };
    for (int fd = 0; fd < 3; fd++) {
        /* Probing a missing CRT fd with _get_osfhandle() can trip MSVCRT's
         * invalid-parameter handler; opening NUL reveals the slot safely. */
        int nullfd = _open("NUL", modes[fd], 0);
        if (nullfd < 0) continue;
        /* Vacant: our NUL fd now owns the slot and was opened _O_BINARY. */
        if (nullfd == fd) continue;
        _close(nullfd);
        /* Inherited fds start in TEXT mode, corrupting binary stdio; force
         * _O_BINARY. Reaching here proves the descriptor exists. */
        _setmode(fd, _O_BINARY);
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
        if (tjs__count_closing_handles(qrt) == 0)
            return;
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
}

struct TJSRuntimeCleanup {
    struct list_head link;
    void (*callback)(void *);
    void *opaque;
};

TJSRuntimeCleanup *TJS_AddRuntimeCleanup(TJSRuntime *runtime,
                                         void (*callback)(void *), void *opaque) {
    if (!runtime || runtime->freeing || !callback) return NULL;
    TJSRuntimeCleanup *cleanup = tjs__malloc(sizeof(*cleanup));
    if (!cleanup) return NULL;
    cleanup->callback = callback;
    cleanup->opaque = opaque;
    list_add(&cleanup->link, &runtime->native_cleanup);
    return cleanup;
}

void TJS_RemoveRuntimeCleanup(TJSRuntimeCleanup *cleanup) {
    /* A running callback has already been detached into a self-linked node. */
    if (!cleanup || list_empty(&cleanup->link)) return;
    list_del(&cleanup->link);
    tjs__free(cleanup);
}

static void tjs__cleanup_native_resources(TJSRuntime *runtime) {
    while (!list_empty(&runtime->native_cleanup)) {
        TJSRuntimeCleanup *cleanup = list_entry(runtime->native_cleanup.next, TJSRuntimeCleanup, link);
        void (*callback)(void *) = cleanup->callback;
        void *opaque = cleanup->opaque;
        list_del(&cleanup->link);
        init_list_head(&cleanup->link);
        callback(opaque);
        tjs__free(cleanup);
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

JSContext* TJS_GetMainContext(TJSRuntime* runtime) {
    return runtime ? runtime->main_ctx : NULL;
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

    /* js_get_source_mapping's column contract is 0-based in and out; QuickJS
     * backtrace columns are 1-based: convert in, restore on the way out. */
    MappingResult res = js_get_source_mapping(qrt->module.mapctx, name, *line, *col > 0 ? *col - 1 : 0);
    if (res.found) {
        *line = res.original_line;
        *col = res.original_column + 1;
    }
    return res.found;
}

/* Hop bound used ONLY while another deferral is already outstanding. See the
 * termination argument in tjs__promise_rejection_dispatch. */
#define TJS_REJECTION_MAX_HOPS 16

static JSValue tjs__promise_rejection_dispatch(JSContext* ctx, int argc, JSValueConst* argv) {
    TJSRuntime* qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);
    JSValue promise = argv[0], reason = argv[1];

    /* argv[2] is the re-enqueued hop count; the matching decrement must hit
     * every exit path or the counter leaks and disables the unbounded wait. */
    int hop = 0;
    if (argc > 2) {
        hop = JS_VALUE_GET_INT(argv[2]);
        CHECK_GT(qrt->jobs.rejection_deferrals, 0);
        qrt->jobs.rejection_deferrals--;
    }

    if (JS_PromiseIsHandled(ctx, promise)) return JS_UNDEFINED;

    /* Thenable adoption lands one job later: re-enqueue (FIFO) and look again.
     * Unbounded wait only with no other deferral outstanding; else capped. */
    if (JS_IsJobPending(JS_GetRuntime(ctx)) &&
        (qrt->jobs.rejection_deferrals == 0 || hop < TJS_REJECTION_MAX_HOPS)) {
        JSValue again[3] = { promise, reason, JS_NewInt32(ctx, hop + 1) };
        /* JS_EnqueueJob dups argv and frees its copies, so no manual dup/free;
         * if the enqueue fails, fall through and report now. */
        if (JS_EnqueueJob(ctx, tjs__promise_rejection_dispatch, 3, (JSValueConst*) again) >= 0) {
            qrt->jobs.rejection_deferrals++;
            return JS_UNDEFINED;
        }
    }

    JSValue args = JS_NewArrayFrom(ctx, 2, (JSValueConst[]) {
        JS_DupValue(ctx, promise), JS_DupValue(ctx, reason)
    });

    JSValue ret = JS_IsException(args) ? JS_EXCEPTION
        : tjs__dispatch_event(ctx, EV_UNHANDLED_REJECTION, args);
    JS_FreeValue(ctx, args);

    if (JS_IsException(ret)) {
        TJS_DumpException(ctx);
        goto fail;
    }
    else {
        if (!JS_IsEqual(ctx, ret, JS_FALSE)) {
            // The event wasn't cancelled or not handled(true), maybe abort.
        fail:;
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
    /* TJS_FreeRuntime() still pumps libuv to complete close callbacks after
     * setting freeing.  A stop notification already queued at that point must
     * not re-enter the JS event bus or dispatch user EV_EXIT listeners. */
    if (trt->freeing) {
        atomic_store_explicit(&trt->jobs.stop_pending, false, memory_order_release);
        uv_stop(&trt->loop);
        return;
    }
    if (trt->unload_dispatched) {
        atomic_store_explicit(&trt->jobs.stop_pending, false, memory_order_release);
        uv_stop(&trt->loop);
        return;
    }
    if (!trt->is_worker && trt->exit_code == 0)
        trt->exit_code = 1;
    atomic_store_explicit(&trt->jobs.stop_pending, false, memory_order_release);

    /* Dispatch EV_EXIT inside the loop thread: TJS_Stop may run on another
     * thread, so JS dispatch must not happen in TJS_Stop itself. */
    /* Mark teardown done so a later natural drain neither re-fires EV_EXIT nor
     * adds a 'beforeunload' Deno does not fire on explicit exit. */
    trt->unload_dispatched = true;
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
    if (!ctx)
        return NULL;
    App* app = tjs__mallocz(sizeof(App));
    if (!app) {
        JS_FreeContext(ctx);
        return NULL;
    }
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

static void tjs__script_boundary_hook(JSRuntime* rt, void* opaque);

TJSRuntime* TJS_NewRuntimeInternal(bool is_worker, TJSRunOptions* options) {
    JSRuntime* rt = NULL;
    TJSRuntime* qrt = tjs__mallocz(sizeof(*qrt));
    if (!qrt)
        return NULL;
    atomic_init(&qrt->jobs.stop_pending, false);

    memcpy(&qrt->options, options, sizeof(*options));

    /* Create Runtime */
    rt = JS_NewRuntime2(&tjs_mf, NULL);
    if (!rt) {
        tjs__free(qrt);
        return NULL;
    }
    qrt->rt = rt;
    JS_SetRuntimeOpaque(rt, qrt);

    /* Create main app */
    App* app = TJS_NewAppInternal(qrt, false);
    if (!app) {
        JS_FreeRuntime(rt);
        tjs__free(qrt);
        return NULL;
    }
    JSContext* ctx = app->ctx;
    qrt->main_ctx = ctx;

    /* Set memory limit */
    JS_SetMemoryLimit(rt, options->mem_limit);

    /* Set stack size */
    /* QuickJS never checks the limit against the real stack, and this runs on
     * the worker's own thread. NULL was_clamped: tier default is silent. */
    JS_SetMaxStackSize(rt, tjs__clamp_stack_size(options->stack_size, NULL));

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
    init_list_head(&qrt->dns_queries);
    init_list_head(&qrt->dns_getaddrinfo);
    init_list_head(&qrt->dns_getnameinfo);
    init_list_head(&qrt->asyncfs_requests);
    init_list_head(&qrt->processes);
    init_list_head(&qrt->sockets);
    init_list_head(&qrt->udps);
    init_list_head(&qrt->native_cleanup);

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

    /* Module-body boundaries are macrotask boundaries for process.nextTick:
       the checkpoint lives in mod_engine.c and runs the registered drain
       before the body's own microtasks. */
    JS_SetScriptBoundaryHook(rt, tjs__script_boundary_hook, qrt);  /* defined below */

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
    qrt->builtins.worker_udata = JS_UNDEFINED;
    qrt->builtins.message_pipe = JS_UNDEFINED;
    qrt->builtins.nexttick_drain_fn = JS_UNDEFINED;

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
    wasm_runtime_init();

#ifdef DEBUG
    wasm_runtime_set_log_level(WASM_LOG_LEVEL_VERBOSE);
#endif
#endif

    /* Timers */
    qrt->timers.timers = NULL;
    qrt->timers.next_timer = 1;

    qrt->console.counters = NULL;
    qrt->console.timers = NULL;
    qrt->console.group_indent = 0;
    qrt->console.map_size = qrt->console.map_entries =
        qrt->console.map_iterator_next = qrt->console.set_size =
        qrt->console.set_values = qrt->console.set_iterator_next =
        qrt->console.date_to_iso_string = JS_UNDEFINED;
    if (tjs__console_init_runtime(qrt) < 0) {
        TJS_FreeRuntime(qrt);
        return NULL;
    }

    return qrt;
}

void TJS_FreeRuntime(TJSRuntime* qrt) {
    /* Must precede `freeing = true`: TJS_SetCapabilityHook won't clear the
     * global hook count once freeing is set. */
    TJS_SetCapabilityHook(qrt, NULL, NULL, 0);
    qrt->freeing = true;

    JS_SetPromiseHook(qrt->rt, NULL, NULL);
    JS_SetHostPromiseRejectionTracker(qrt->rt, NULL, NULL);
    JS_SetScriptBoundaryHook(qrt->rt, NULL, NULL);
    JS_SetBacktraceHook(qrt->rt, NULL, NULL);

    /* Cleanup may pump libuv; stop JS scheduling before any native teardown. */
    uv_close((uv_handle_t*) &qrt->jobs.prepare, NULL);
    uv_close((uv_handle_t*) &qrt->jobs.idle, NULL);
    uv_close((uv_handle_t*) &qrt->jobs.check, NULL);

    tjs__console_cleanup_runtime(qrt);

    /* Stop every callback source before any loop pump. Requests and handles
     * below retain JSContext pointers; their callbacks only become safe once
     * they have either completed or entered their RT-only freeing branch. */
    tjs__destroy_timers(qrt);
    tjs__mod_asyncfs_cleanup_runtime(qrt);
    tjs__mod_process_cleanup_runtime(qrt);
    tjs__mod_socket_cleanup_runtime(qrt);
    tjs__mod_udp_cleanup_runtime(qrt);
    tjs__cleanup_native_resources(qrt);

    /* Release raw DNS JS refs while the runtime is valid. Its resolver and UDP
     * callbacks are now teardown-only, so they can be drained with the rest. */
    tjs__mod_dns_cleanup_runtime(qrt);

    /* Stop workers and join their threads before freeing shared state;
     * TJS_Stop is async. TJSWorker is freed by the JS finalizer. */
    for (;;) {
        TJSWorker *worker = NULL;
        struct list_head *p;

        /* Joining can release a worker's self-reference, which may run a
         * finalizer that removes and frees another worker record. Restart the
         * scan after every join instead of retaining a successor pointer. */
        list_for_each(p, &qrt->workers) {
            TJSWorker *candidate = list_entry(p, TJSWorker, link);
            if (!tjs__worker_is_joined(candidate)) {
                worker = candidate;
                break;
            }
        }
        if (!worker) break;
        tjs__worker_stop_and_join(worker->ctx, worker);
    }
    /* Close stream handles before freeing JS so stream_pin() self-references
     * don't survive into QuickJS leak checking as TCP/Pipe/TTY objects. */
    tjs__close_all_streams(qrt);
    tjs__close_all_msgpipes(qrt);

    /* Native addon callbacks must be disabled before pumping libuv too. */
    tjs__nodeapi_cleanup_runtime(qrt);
    uv_close((uv_handle_t*) &qrt->stop, NULL);

    /* Every module callback source is now stopped or has a freeing-only
     * callback. Drain requests only after that invariant holds; UV_RUN_ONCE in
     * one module can dispatch callbacks owned by every other module. */
    tjs__mod_asyncfs_drain_runtime(qrt);
    tjs__mod_process_drain_runtime(qrt);
    tjs__mod_udp_drain_runtime(qrt);
    tjs__mod_dns_drain_runtime(qrt);
    tjs__drain_closing_handles(qrt, 64);

    /* Poison module hooks: later C-closure access ASan-reports, not UAF. */
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
    JS_FreeValue(ctx, qrt->builtins.promise_hook_fn);
    qrt->builtins.promise_hook_fn = JS_UNDEFINED;
    JS_FreeValue(ctx, qrt->builtins.message_pipe);
    qrt->builtins.message_pipe = JS_UNDEFINED;
    /* Cleared before the job drain below: that drain must not call back into a
     * nextTick queue whose module is being torn down. */
    JS_FreeValue(ctx, qrt->builtins.nexttick_drain_fn);
    qrt->builtins.nexttick_drain_fn = JS_UNDEFINED;
    qrt->jobs.ticks_pending = false;

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

    /* Remove runtime-owned values before contexts and their atoms are freed. */
    tjs__evbus_cleanup_rt(qrt);

    /* Do not execute pending Promise jobs during teardown. They are user JS
     * and may create a Worker, timer, stream, or other native resource after
     * the corresponding close pass above has completed. QuickJS releases
     * queued job arguments from JS_FreeRuntime(). */
    tjs__mod_ffi_drain_runtime(qrt);

    /* Release Node-API persistent refs before leak checking; env structs stay
     * alive until JS_FreeRuntime finalizers. */
    tjs__nodeapi_cleanup_runtime(qrt);
    for (int i = 0; i < 5; i++) {
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
    JS_RunGC(qrt->rt);
    tjs__mod_ffi_drain_runtime(qrt);
    tjs__drain_closing_handles(qrt, 64);
    tjs__nodeapi_cleanup_runtime(qrt);
    for (int i = 0; i < 5; i++) {
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
    }
    JS_RunGC(qrt->rt);
    tjs__mod_ffi_drain_runtime(qrt);
    tjs__drain_closing_handles(qrt, 64);

    /* Native users have drained; release the runtime's retained contexts. */
    App* main_app = TJS_GetApp(ctx);
    {
        JS_FreeContext(main_app->ctx);
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &main_app->link) {
            App* app = list_entry(cur, App, link);
            JS_FreeContext(app->ctx);
        }
    }

    /* Destroy the JS engine. */
    tjs__mod_ffi_drain_runtime(qrt);
    JS_FreeRuntime(qrt->rt);
    /* Finalizers run by JS_FreeRuntime may enqueue native-only disposers. */
    tjs__mod_ffi_drain_runtime(qrt);

    /* Context opaque pointers remain valid through JS_FreeRuntime finalizers;
     * App storage itself has no QuickJS references and can now be released. */
    {
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &main_app->link) {
            App* app = list_entry(cur, App, link);
            list_del(&app->link);
            tjs__free(app);
        }
        tjs__free(main_app);
    }
    tjs__drain_closing_handles(qrt, 64);
    tjs__free_orphaned_streams(qrt);


    {
        struct list_head* p, * tmp;
        list_for_each_safe(p, tmp, &qrt->module.dyn_libs) {
            TJSDynLib* node = list_entry(p, TJSDynLib, link);
            list_del(p);
            if (node->nodeapi && tjs__nodeapi_defer_dynlib(node)) {
                continue;
            }
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

static void uv__maybe_idle(TJSRuntime* qrt);

void tjs__notify_work(TJSRuntime* qrt) {
    uv__maybe_idle(qrt);
}

static void uv__maybe_idle(TJSRuntime* qrt) {
    /* Cleanup callbacks may notify after the core handles have closed. */
    if (qrt->freeing) return;

    /* ticks_pending counts as work: the nextTick queue lives outside the
     * QuickJS job queue, so JS_IsJobPending() cannot see it. stop_pending
     * likewise: a TJS_Stop from a callback must keep the loop alive until
     * uv__stop dispatches EV_EXIT, or a natural drain races the async and
     * the exit status is lost. */
    bool pending_jobs = JS_IsJobPending(qrt->rt) || qrt->jobs.ticks_pending ||
        atomic_load_explicit(&qrt->jobs.stop_pending, memory_order_acquire);
    if (pending_jobs || qrt->timers.pending_immediates) {
        if (pending_jobs)
            uv_ref((uv_handle_t *)&qrt->jobs.idle);
        else
            uv_unref((uv_handle_t *)&qrt->jobs.idle);
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

/* Returns true when a job error stopped the runtime; caller stops draining. */
static bool tjs__execute_pending_jobs(TJSRuntime* trt) {
    JSContext* ctx1;
    int err;

    /* execute the pending jobs */
    while (!trt->jobs.paused) {
        err = JS_ExecutePendingJob(trt->rt, &ctx1);
        if (err <= 0) {
            if (err < 0) {
                JSValue js_err = JS_GetException(ctx1);
                if (JS_IsUncatchableError(js_err)) {
                    tjs__stop_uncatchable_error(ctx1, js_err);
                    JS_FreeValue(ctx1, js_err);
                    return true;
                }
                JSValue retv = tjs__dispatch_event(ctx1, EV_JOB_EXCEPTION, js_err);
                if (JS_IsException(retv)) {
                    TJS_DumpException(ctx1);
                }
                bool stop = JS_IsException(retv) || (JS_IsBool(retv) && !JS_VALUE_GET_BOOL(retv));
                if (stop) {
#ifdef DEBUG
                    fprintf(stderr, "[CORE] JOB: ");
                    tjs_dump_error(ctx1, js_err);
#endif
                    TJS_Stop(trt);
                }
                JS_FreeValue(ctx1, js_err);
                JS_FreeValue(ctx1, retv);
                return stop;
            }

            break;
        }
    }
    return false;
}

void tjs__execute_jobs(TJSRuntime* trt) {
    assert(trt != NULL);

    /* Node's microtask checkpoint: ticks registered before this point run
       first; ticks queued during the drain re-checkpoint after the promise
       queue reaches exhaustion. A module boundary starts with Promise jobs,
       so it suppresses only this checkpoint's initial tick drain. */
    if (!trt->jobs.module_checkpoint_pending)
        tjs__run_next_ticks(trt);

    for (;;) {
        if (tjs__execute_pending_jobs(trt)) {
            trt->jobs.module_checkpoint_pending = false;
            break;
        }

        if (trt->jobs.paused)
            break;
        if (trt->jobs.module_checkpoint_pending || trt->jobs.ticks_pending) {
            trt->jobs.module_checkpoint_pending = false;
            tjs__run_next_ticks(trt);
            continue;
        }
        break;
    }
    tjs__mod_ffi_drain_runtime(trt);
}

/* Module evaluation is an ESM microtask checkpoint: mark it here so the event
 * loop drains Promise jobs before nextTick, as Node does for ESM. */
static void tjs__script_boundary_hook(JSRuntime* rt, void* opaque) {
    (void) rt;
    TJSRuntime* trt = opaque;
    if (trt->freeing) return;
    /* Let the outer checkpoint drain jobs. Calling JS_ExecutePendingJob here
     * would re-enter an active job drain when a module is loaded by import(). */
    trt->jobs.module_checkpoint_pending = true;
}

static void uv__check_cb(uv_check_t* handle) {
    TJSRuntime* qrt = handle->data;
    CHECK_NOT_NULL(qrt);

    /* Teardown still pumps libuv to deliver close callbacks. Those passes must
     * never execute user Promise jobs after native resources have started
     * closing; JS_FreeRuntime() owns the queued job arguments. */
    if (!qrt->freeing && qrt->jobs.waitio_depth == 0) {
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

int tjs__run_main(TJSRuntime* qrt) {
    /* get built-in script */
    uint8_t* tjs__core_js = NULL;
    uint32_t tjs__core_js_size = 0;
    tjs__core_js = tjs__read_self_attached(&tjs__core_js_size);
    if (tjs__core_js_size == 0 || !tjs__core_js) {
        fprintf(stderr, "CorePanic: Cannot load embedded core JS script\n");
        return -1;
    }

    /* If we are running the main interpreter, run the entrypoint. */
    if (tjs__eval_bytecode(qrt->main_ctx, tjs__core_js, tjs__core_js_size, true) != 0) {
#ifdef DEBUG
        fprintf(stderr, "CorePanic: Eval entry script failed immediately\n");
#endif
        return -1;
    }
    return 0;
}

/* exit_code wins when nonzero (fatal paths only); else js_exit_code, including
 * an explicit 0 that withdraws an earlier nonzero. */
static int tjs__resolved_exit_code(TJSRuntime* qrt) {
    if (qrt->exit_code != 0)
        return qrt->exit_code;
    if (qrt->js_exit_code_set)
        return qrt->js_exit_code;
    return 0;
}

/* Three independent queues, all must be checked: promise jobs, nextTick
 * (invisible to JS_IsJobPending), and live libuv handles. */
static bool tjs__has_new_work(TJSRuntime* qrt) {
    return JS_IsJobPending(qrt->rt) || qrt->jobs.ticks_pending ||
        atomic_load_explicit(&qrt->jobs.stop_pending, memory_order_acquire) ||
        uv_loop_alive(&qrt->loop) != 0;
}

/* Lifecycle teardown; true = caller runs another loop pass. Only an explicit
 * JS `true` from beforeunload cancels, sticky across listeners. */
static bool tjs__lifecycle_drain(TJSRuntime* qrt) {
    if (qrt->unload_dispatched)
        return false;
    /* Deno fires no unload events in workers; teardown stays on uv__stop. */
    if (qrt->is_worker)
        return false;

    JSContext* ctx = qrt->main_ctx;

    /* beforeExit before beforeunload: beforeExit re-fires per drain when it
     * queues work; beforeunload is the once-only last word before teardown. */
    JSValue be = tjs__dispatch_event(ctx, EV_BEFORE_EXIT, JS_NewInt32(ctx, tjs__resolved_exit_code(qrt)));
    if (JS_IsException(be)) {
        /* A throwing 'beforeExit' still fires 'exit' with the forced code
         * (node parity): report and fall through to teardown. */
        TJS_DumpException(ctx);
        if (qrt->exit_code == 0)
            qrt->exit_code = 1;
    } else {
        JS_FreeValue(ctx, be);
        /* Return to the caller so a real loop pass separates beforeExit
         * rounds; the next drain re-enters here from the top. */
        if (tjs__has_new_work(qrt))
            return true;
    }

    JSValue bu = tjs__dispatch_event(ctx, EV_BEFORE_UNLOAD, JS_UNDEFINED);
    if (JS_IsException(bu)) {
        /* Throwing 'beforeunload' = uncaught error (Deno): force exit 1,
         * suppress EV_EXIT, stop looping. */
        TJS_DumpException(ctx);
        if (qrt->exit_code == 0)
            qrt->exit_code = 1;
        qrt->unload_dispatched = true;
        return false;
    }

    /* Tag test, not JS_IsEqual: loose == runs user valueOf() inside teardown
     * and can throw; a tag test cannot, and keeps true = cancelled. */
    bool cancelled = JS_IsBool(bu) && JS_VALUE_GET_BOOL(bu);
    JS_FreeValue(ctx, bu);

    if (cancelled) {
        /* No cap: Deno re-dispatches per drain indefinitely; a cancel-forever
         * listener spins there too. */
        return true;
    }

    /* Uncancelled: teardown proceeds. Set the flag before dispatching so a
     * throwing 'unload'/'exit' listener cannot re-enter this path. */
    qrt->unload_dispatched = true;
    tjs__dispatch_event2(ctx, EV_EXIT, JS_NewInt32(ctx, tjs__resolved_exit_code(qrt)));

    /* No extra loop pass: Deno and Node both drop work queued from
     * unload/exit listeners, and a ref'd handle there would hang the process. */
    return false;
}

/* main loop which calls the user JS callbacks */
int TJS_Run(TJSRuntime* qrt) {
    CHECK_EQ(uv_prepare_start(&qrt->jobs.prepare, uv__prepare_cb), 0);
    uv_unref((uv_handle_t*) &qrt->jobs.prepare);
    CHECK_EQ(uv_check_start(&qrt->jobs.check, uv__check_cb), 0);
    uv_unref((uv_handle_t*) &qrt->jobs.check);

    uv_unref((uv_handle_t*) &qrt->stop);
    if (!qrt->is_worker &&
        atomic_load_explicit(&qrt->jobs.stop_pending, memory_order_acquire)) {
        /* TJS_Stop() is allowed before the first TJS_Run() call.  There is no
         * event-loop pass to deliver the async notification yet, so dispatch
         * the same loop-thread callback directly and preserve EV_EXIT. */
        uv__stop(&qrt->stop);
        return tjs__resolved_exit_code(qrt);
    }
    if (!qrt->is_worker) {
        if (tjs__run_main(qrt) < 0) {
            qrt->exit_code = 1;
            return qrt->exit_code;
        }
    }

    if (qrt->exit_code != 0) {
        return qrt->exit_code;
    }

    /* Not a do-while: `continue` there jumps to the condition (r != 0), making
     * cancellation a silent no-op. */
    int r;
    for (;;) {
        uv__maybe_idle(qrt);
        r = uv_run(&qrt->loop, UV_RUN_DEFAULT);

        if (r != 0
            ? (JS_IsJobPending(qrt->rt) ||
               atomic_load_explicit(&qrt->jobs.stop_pending, memory_order_acquire))
            : (!qrt->jobs.paused &&
               (JS_IsJobPending(qrt->rt) || qrt->jobs.ticks_pending ||
                atomic_load_explicit(&qrt->jobs.stop_pending, memory_order_acquire)))
        )
            continue;

        /* r == 0 is a natural drain; r != 0 with no jobs means uv_stop already
         * dispatched EV_EXIT, so the drain declines. */
        if (r == 0 && tjs__lifecycle_drain(qrt))
            continue;

        break;
    }

    /* Resolved, not raw: 'exit'/'beforeExit' listeners assign js_exit_code and
     * this read follows both dispatches (the early return stays raw). */
    return tjs__resolved_exit_code(qrt);
}

void TJS_Stop(TJSRuntime* qrt) {
    CHECK_NOT_NULL(qrt);
    /* This may be called from another thread. The exit code is assigned by
     * uv__stop on the loop thread; this atomic keeps the natural-drain path
     * from racing past the async event. */
    atomic_store_explicit(&qrt->jobs.stop_pending, true, memory_order_release);
    /* Only uv_async_send is thread-safe; JS dispatch is deferred to uv__stop
     * which runs inside the target runtime's own event loop thread. */
    uv_async_send(&qrt->stop);
}

uv_loop_t* TJS_GetLoop(TJSRuntime* qrt) {
    return &qrt->loop;
}
