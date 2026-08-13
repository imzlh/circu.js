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
        /* Do not probe a missing CRT fd with _get_osfhandle(): MSVCRT may
         * invoke the process-wide invalid-parameter handler for that call.
         * Opening NUL allocates the lowest free slot, so its result tells us
         * whether this descriptor number was vacant without an unsafe probe. */
        int nullfd = _open("NUL", modes[fd], 0);
        if (nullfd < 0) continue;
        /* Vacant: our NUL fd now owns the slot and was opened _O_BINARY. */
        if (nullfd == fd) continue;
        _close(nullfd);
        /* Occupied by an inherited handle. Inherited CRT descriptors start in
         * TEXT mode, which rewrites \n as \r\n on write and strips \r (and
         * stops at Ctrl-Z) on read — that corrupts all binary stdio. Node and
         * Deno never translate, so force binary for parity. Reaching here
         * proves the descriptor exists, so _setmode cannot trip the
         * invalid-parameter handler the comment above warns about. */
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

    /* Base conversion belongs here, not in js_get_source_mapping().
     *
     * That function converts the LINE (`gen_line - 1`, and returns
     * `original_line + 1`) but passes the COLUMN through raw against 0-based
     * mapping data, returning `original_column` raw as well. Its column
     * contract is therefore 0-based in and out, and the other consumer relies
     * on that: the getMapping() binding hands original_column straight to JS,
     * where src/inspector/shared/console-utils.ts documents it as "already
     * 0-based" for CDP. Adjusting sourcemap.c would break the inspector.
     *
     * Backtrace columns from QuickJS are 1-based, so feeding one in unadjusted
     * mis-SELECTS the segment rather than merely reporting an off-by-one: with
     * segments at 0-based 10 and 20, col=20 resolves to the 20 segment where it
     * should resolve to the 10 one. Convert on the way in, restore on the way
     * out, and leave the line alone since both sides already agree on 1-based. */
    MappingResult res = js_get_source_mapping(qrt->module.mapctx, name, *line, *col > 0 ? *col - 1 : 0);
    if (res.found) {
        *line = res.original_line;
        *col = res.original_column + 1;
    }
    return res.found;
}

/* Number of deferral hops currently outstanding on this thread. Only ever
 * touched from the job loop, which is single-threaded per runtime, but workers
 * each get their own runtime on their own thread, so it must not be shared. */
static thread_local int tjs__rejection_deferrals = 0;

/* Hop bound used ONLY while another deferral is already outstanding. See the
 * termination argument in tjs__promise_rejection_dispatch. */
#define TJS_REJECTION_MAX_HOPS 16

static JSValue tjs__promise_rejection_dispatch(JSContext* ctx, int argc, JSValueConst* argv) {
    JSValue promise = argv[0], reason = argv[1];

    /* argv[2], when present, is the hop count of a re-enqueued dispatch. Read it
     * before anything can return: the matching decrement has to happen on EVERY
     * exit path, or a promise that gets handled while deferred (the common good
     * case) would leak the counter and permanently disable the unbounded wait
     * below. Read with JS_VALUE_GET_INT rather than JS_ToInt32 -- we put the int
     * there ourselves, so there is no conversion-failure path to handle. */
    int hop = 0;
    if (argc > 2) {
        hop = JS_VALUE_GET_INT(argv[2]);
        tjs__rejection_deferrals--;
    }

    if (JS_PromiseIsHandled(ctx, promise)) return JS_UNDEFINED;

    /* Thenable adoption is not synchronous. `return inner()` from an async
     * function resolves the outer promise WITH inner's rejected promise, and the
     * handler that marks inner handled is only attached by a later
     * PromiseResolveThenableJob. The tracker enqueued us the moment inner
     * rejected, so on the first pass we can be exactly one job too early and
     * would report a rejection that is about to be handled. `return await
     * inner()` attaches in the same job and never had the problem -- the two
     * differ only in WHEN the handler lands, so reporting the first is a timing
     * artifact, not a real unhandled rejection.
     *
     * So: while other jobs are still pending, go to the back of the queue and
     * look again. JS_EnqueueJob uses list_add_tail and the loop pops from
     * job_list.next, i.e. FIFO, so the re-enqueued dispatch is guaranteed to run
     * AFTER the adoption job that is already queued (OBSERVED in quickjs.c).
     *
     * TERMINATION. Deferring unconditionally on JS_IsJobPending hangs, because a
     * deferral is itself a pending job: with two rejections in one tick each one
     * keeps seeing the other's deferral and they ping-pong forever. Hence the
     * counter. An unbounded wait is only taken while NO other deferral is
     * outstanding (tjs__rejection_deferrals == 0), which is the single-rejection
     * case where the only thing we can be waiting on is real work; the moment a
     * second deferral coexists, both fall back to the hop bound and the loop is
     * capped at TJS_REJECTION_MAX_HOPS. The counter is decremented on entry, so
     * a lone rejection oscillates 0 <-> 1 and keeps its unbounded wait, while
     * two or more can never both see 0 again. */
    if (JS_IsJobPending(JS_GetRuntime(ctx)) &&
        (tjs__rejection_deferrals == 0 || hop < TJS_REJECTION_MAX_HOPS)) {
        JSValue again[3] = { promise, reason, JS_NewInt32(ctx, hop + 1) };
        /* No manual dup/free: JS_EnqueueJob dups every argv element and the job
         * loop frees the entry's copies after job_func returns, and js_dup on an
         * int tag is a no-op (OBSERVED in quickjs.c). If the enqueue fails we
         * must NOT swallow the report -- fall through and report it now. */
        if (JS_EnqueueJob(ctx, tjs__promise_rejection_dispatch, 3, (JSValueConst*) again) >= 0) {
            tjs__rejection_deferrals++;
            return JS_UNDEFINED;
        }
    }

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
    /* Explicit exit: mark teardown as done so a later natural drain in TJS_Run
     * neither re-fires EV_EXIT nor introduces a 'beforeunload' that Deno does
     * not fire on an explicit exit (OBSERVED against Deno 2.9.3). */
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
    /* Clamp against the stack this thread actually owns, because QuickJS just
     * computes stack_limit = stack_top - stack_size and never checks it against
     * the real stack (deps/quickjs/quickjs.c:3473-3484). An unclamped limit at
     * or past the real stack means js_check_stack_overflow can never fire and
     * recursion walks into the guard page instead of raising RangeError.
     *
     * Reading the bounds HERE is load-bearing for workers: a Worker calls
     * TJS_NewRuntimeWorker from inside worker_entry (mod_worker.c:679-682),
     * i.e. already on the new thread, so the clamp measures that thread's own
     * stack rather than the parent's.
     *
     * Worker stack sizes, OBSERVED by reading deps/libuv/src/unix/thread.c:
     * uv_thread_create defers to uv_thread_create_ex with no explicit size, so
     * the thread gets uv__thread_stack_size() = RLIMIT_STACK page-aligned on
     * both macOS and Linux (:101-122). libuv deliberately compensates for
     * Darwin's reduced secondary-thread default, so the usual worker stack is
     * ~8MB, NOT 512KB. The 6MB default therefore normally fits. It does not fit
     * in two reachable cases: RLIMIT_STACK is RLIM_INFINITY or getrlimit fails,
     * where uv__default_stack_size() returns 0 on non-Linux and libuv skips
     * pthread_attr_setstacksize entirely, leaving the Darwin 512KB default; and
     * Linux, where that same fallback is 2MB (4MB on ppc). Those are the cases
     * this clamp exists for. REASONED: only the Windows main thread was
     * measured directly; the POSIX worker figures are read from libuv's source,
     * not observed.
     *
     * NULL for was_clamped on purpose: this path has no user-supplied flag to
     * report against. The tier default arriving here silently reduced is
     * correct behaviour, whereas an explicit --max-stack-size that cannot be
     * honoured is reported by the mod_engine.c call site. */
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
    /* Unregister before freeing the function: the hook fires from
     * js_promise_new and fulfill_or_reject_promise, both of which are still
     * reachable from the job drain and GC below. Leaving rt->promise_hook
     * installed over a freed hook_fn is a use-after-free. */
    JS_SetPromiseHook(qrt->rt, NULL, NULL);
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
    /* ticks_pending counts as work: the nextTick queue lives outside the QuickJS
     * job queue, so JS_IsJobPending() cannot see it. Without this a bare
     * `process.nextTick(cb)` -- no promise anywhere -- would stop the idle
     * handle, let the loop go quiet and never reach the checkpoint that runs cb. */
    if (JS_IsJobPending(qrt->rt) || qrt->jobs.ticks_pending) {
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

/* The pending-job loop, lifted out of tjs__execute_jobs() unchanged so the
 * nextTick checkpoint below can run it more than once per checkpoint. Returns
 * true when a job error stopped the runtime, so the caller stops draining. */
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
                    TJS_Stop(trt);
                    JS_FreeValue(ctx1, js_err);
                    return true;
                }
                JSValue retv = tjs__dispatch_event(ctx1, EV_JOB_EXCEPTION, js_err);
                bool stop = JS_IsEqual(ctx1, retv, JS_FALSE);
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

    /* Node's microtask checkpoint */
    do {
        tjs__run_next_ticks(trt);
    } while (!tjs__execute_pending_jobs(trt) && trt->jobs.ticks_pending && !trt->jobs.paused);
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

/* The status this run will exit with, resolving the two sources.
 *
 * exit_code wins when nonzero: it is only set that way by a fatal path
 * (TJS_Stop, a throwing 'beforeunload', a worker os.exit), and node likewise
 * lets an uncaught fatal override `process.exitCode` (OBSERVED v24.18.0: rc 1
 * with `process.exitCode = 5` and a top-level throw). Otherwise a JS-pushed code
 * applies, including an explicit 0 that withdraws an earlier nonzero. */
static int tjs__resolved_exit_code(TJSRuntime* qrt) {
    if (qrt->exit_code != 0)
        return qrt->exit_code;
    if (qrt->js_exit_code_set)
        return qrt->js_exit_code;
    return 0;
}

/* Did a 'beforeExit' listener queue work that must run before teardown?
 *
 * All three queues have to be consulted and they are genuinely independent:
 * JS_IsJobPending covers promise jobs, ticks_pending covers the nextTick queue
 * (which lives outside the QuickJS job queue, see uv__maybe_idle), and
 * uv_loop_alive covers a fresh ref'd handle such as a setTimeout. Reaching here
 * at all means uv_run returned 0, i.e. every one of them was empty a moment ago,
 * so any true reading is new work the listener just created. */
static bool tjs__has_new_work(TJSRuntime* qrt) {
    return JS_IsJobPending(qrt->rt) || qrt->jobs.ticks_pending || uv_loop_alive(&qrt->loop) != 0;
}

/* Lifecycle teardown, run when the event loop has nothing left to do.
 *
 * Returns true when the caller must give the loop another pass.
 *
 * RETURN-VALUE POLARITY: only an explicit JS `true` means "cancelled, keep
 * running". This is forced by the JS side, not a free choice. The multiplexer
 * that owns the native receiver ends every dispatch with
 * `typeof ret === 'boolean' ? ret : defaultReturn(name)`, and defaultReturn
 * (cts/src/runtime/event-mux.ts:104-107) yields `false` for every id except
 * EV_JOB_EXCEPTION. No receiver knows EV_BEFORE_UNLOAD, so an un-bridged mux
 * returns `false` on every dispatch. Had `false` meant "cancelled" (as the
 * other two sites' polarities might suggest) every single run would re-dispatch
 * forever and never exit. Choosing `true` also makes both degenerate returns
 * safe: tjs__dispatch_event yields JS_UNDEFINED when the runtime is freeing or
 * no receiver is installed, and JS_EXCEPTION when a listener throws — neither
 * is JS_TRUE, so both fall through to teardown instead of hanging. */
static bool tjs__lifecycle_drain(TJSRuntime* qrt) {
    if (qrt->unload_dispatched)
        return false;
    /* Deno fires neither 'beforeunload' nor 'unload' inside a worker, on
     * self.close() or on natural drain (both OBSERVED). Worker teardown keeps
     * going through uv__stop, which is unchanged. */
    if (qrt->is_worker)
        return false;

    JSContext* ctx = qrt->main_ctx;

    /* Node's 'beforeExit', ahead of Deno's 'beforeunload'.
     *
     * Ordering is forced, not stylistic: 'beforeExit' may legitimately queue work
     * and get re-dispatched several times, whereas 'beforeunload' is the last
     * word before teardown. Dispatching beforeunload first would mean a listener
     * saw "about to unload", then watched the loop run again — and it would fire
     * once per beforeExit round instead of once.
     *
     * Not reached on process.exit() (mod_os.c goes straight to libc exit, and
     * sets unload_dispatched, which the guard above declines on) nor after an
     * uncaught fatal (TJS_Stop -> uv__stop dispatches EV_EXIT and sets the same
     * flag). Both match node: neither fires 'beforeExit' (OBSERVED v24.18.0).
     *
     * tjs__dispatch_event, not the _event2 wrapper: the return value decides
     * whether a listener threw, and _event2 returns void after freeing it. */
    JSValue be = tjs__dispatch_event(ctx, EV_BEFORE_EXIT, JS_NewInt32(ctx, tjs__resolved_exit_code(qrt)));
    if (JS_IsException(be)) {
        /* A throwing 'beforeExit' listener is an uncaught error: node reports it
         * and exits 1, but still fires 'exit' with that code (OBSERVED — unlike
         * 'beforeunload', which suppresses EV_EXIT). So report, force the code,
         * and fall through to teardown instead of returning. */
        TJS_DumpException(ctx);
        if (qrt->exit_code == 0)
            qrt->exit_code = 1;
    } else {
        JS_FreeValue(ctx, be);
        /* The listener queued something. Hand the loop back so it runs; node
         * re-fires 'beforeExit' on each subsequent drain, and returning to the
         * caller (rather than looping in place) is what puts a real loop pass
         * between the rounds. unload_dispatched is still clear, so the next drain
         * re-enters here from the top. */
        if (tjs__has_new_work(qrt))
            return true;
    }

    JSValue bu = tjs__dispatch_event(ctx, EV_BEFORE_UNLOAD, JS_UNDEFINED);
    if (JS_IsException(bu)) {
        /* Deno: a throwing 'beforeunload' listener is an uncaught error — exit
         * code 1, later listeners skipped, 'unload' never fires (OBSERVED).
         * Suppress EV_EXIT to reproduce that, and stop looping. */
        TJS_DumpException(ctx);
        if (qrt->exit_code == 0)
            qrt->exit_code = 1;
        qrt->unload_dispatched = true;
        return false;
    }

    /* Tag test, not JS_IsEqual: that is loose `==` (js_eq_slow), and this is the
     * teardown path where a pending exception has no later consumer.
     *
     * Two OBSERVED consequences of the loose form, both against the documented
     * contract above. `engine.onEvent` is a single-slot setter reachable from
     * user JS (Symbol.for('cjs.internal.use')('engine'), because
     * CJS_USE_SYMBOL_INTERNAL puts `use` on a global symbol), so a receiver that
     * is not the multiplexer is not hypothetical -- the REPL shipped one, see
     * src/commands/repl/index.ts.
     *   1. '1', [1], new Boolean(true) and 1 all cancelled teardown, so the
     *      "only an explicit JS `true`" contract was not enforced.
     *   2. For an object receiver, js_eq_slow reaches JS_ToPrimitiveFree and runs
     *      a user valueOf()/toString() INSIDE teardown. A throw there makes
     *      JS_IsEqual return -1, so `-1 == 1` left cancelled false, and the
     *      function went on to dispatch EV_EXIT with that exception still
     *      pending in ctx and nothing left to consume it.
     * A tag test runs no JS, cannot throw, and keeps the polarity unchanged:
     * true still means "cancelled, keep running". */
    bool cancelled = JS_IsBool(bu) && JS_VALUE_GET_BOOL(bu);
    JS_FreeValue(ctx, bu);

    if (cancelled) {
        /* Deno re-dispatches on every subsequent drain with no cap at all: 13
         * consecutive cancels that queued no work produced 13 dispatches and
         * exited only when the listener stopped cancelling (OBSERVED). A cap
         * would deviate from the oracle, so there is none here either. A
         * listener that cancels forever spins, exactly as it does under Deno. */
        return true;
    }

    /* Uncancelled: teardown proceeds. Set the flag before dispatching so a
     * throwing 'unload'/'exit' listener cannot re-enter this path. */
    qrt->unload_dispatched = true;
    tjs__dispatch_event2(ctx, EV_EXIT, JS_NewInt32(ctx, tjs__resolved_exit_code(qrt)));

    /* Deliberately no extra loop pass. Work queued from a non-cancelling
     * 'beforeunload' listener, and from an 'unload' listener, is DROPPED by
     * Deno — neither a setTimeout nor a microtask ran (both OBSERVED) — and
     * Node likewise does not drain work queued in a 'exit' handler. Running
     * another pass here would also let an exit listener that creates a ref'd
     * handle wedge the process forever, so both oracles and the hang risk agree
     * on stopping. */
    return false;
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

    /* Restructured from `do { ... } while (r != 0 && JS_IsJobPending(...))`.
     * A `continue` inside a do-while jumps to the controlling expression, not
     * the body, and that expression tests `r != 0` — false in the only branch
     * that wants to re-dispatch (we get there only when r == 0). Patching the
     * drain into the old shape would therefore have made cancellation a silent
     * no-op. The original continue condition is preserved verbatim below. */
    int r;
    for (;;) {
        uv__maybe_idle(qrt);
        r = uv_run(&qrt->loop, UV_RUN_DEFAULT);

        if (r != 0
            ? JS_IsJobPending(qrt->rt)
            : (!qrt->jobs.paused && (JS_IsJobPending(qrt->rt) || qrt->jobs.ticks_pending))
        )
            continue;

        /* Nothing left to run. r == 0 is a genuine natural drain; r != 0 with no
         * pending jobs means uv_stop ran, and that path already dispatched
         * EV_EXIT and set unload_dispatched, so the drain declines. */
        if (r == 0 && tjs__lifecycle_drain(qrt))
            continue;

        break;
    }

    /* Resolved, not the raw field: a code assigned from an 'exit' or 'beforeExit'
     * listener lands in js_exit_code, and this read happens after both dispatches.
     * The early return at the top of this function deliberately still tests the
     * raw exit_code -- see the private.h field comment. */
    return tjs__resolved_exit_code(qrt);
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
