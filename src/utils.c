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

/* pthread_getattr_np (used by tjs__native_stack_bounds below) is a GNU
 * extension: glibc hides it behind __USE_GNU, which only _GNU_SOURCE sets. It
 * has to be defined before ANY header is pulled in, hence above "utils.h" —
 * that header reaches <uv.h> and from there the libc headers. Without it the
 * call is an implicit declaration, and the POSIX build compiles with
 * -Wall -Werror (CMakeLists.txt:58), so it is a hard build break on Linux;
 * modern gcc/clang reject implicit declarations outright regardless. MSVC
 * takes the _WIN32 branch and never sees it, so /Zs on Windows cannot catch
 * this. Same guard style as src/mod_ffi.c:1-3. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "utils.h"

#include "private.h"
#include "tjs.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
/* utils.h -> <uv.h> -> uv/win.h already defines _WIN32_WINNT as 0x0A00
 * (deps/libuv/include/uv/win.h:23), so GetCurrentThreadStackLimits — which
 * needs >= 0x0602 — is declared. This matters because the build compiles with
 * /W4 /WX (CMakeLists.txt:46), where an implicit declaration is a hard error. */
#include <windows.h>
#elif defined(__APPLE__)
#include <pthread.h>
#else
#include <pthread.h>
#include <sys/resource.h>
#endif


/* ---- native stack bounds -------------------------------------------------
 *
 * JS_SetMaxStackSize only stores the number; QuickJS derives its soft limit as
 * `stack_limit = stack_top - stack_size` (deps/quickjs/quickjs.c,
 * update_stack_limit at :3473) and nothing checks that against the stack the
 * thread actually owns. Once stack_size reaches the real stack size the limit
 * lands at or below the guard page, js_check_stack_overflow (:2320) can never
 * fire, and an ordinary JS recursion walks into the guard page instead of
 * raising a RangeError.
 *
 * OBSERVED 2026-08-06, Windows 11 x64, build/stage/cno.exe (Debug build, links
 * /STACK:8388608 per CMakeLists.txt:51), script recursing until it catches:
 *
 *     --max-stack-size=8160KB -> rc 0, "CAUGHT RangeError depth= 382"
 *     --max-stack-size=8176KB -> rc -1073741571 (0xC00000FD,
 *                                STATUS_STACK_OVERFLOW) with stdout AND
 *                                stderr COMPLETELY EMPTY
 *     --max-stack-size=8MB..1GB -> same silent 0xC00000FD
 *
 * So the cliff sat ~16-32KB under the 8MB reserve, i.e. exactly at the guard
 * region. Real node has the same defect (`node --stack-size=16000` dies with
 * no output at all, OBSERVED), so clamping here is hardening past node rather
 * than a parity fix.
 *
 * A requested size of 0 is NOT "engine default" either: update_stack_limit
 * reads 0 as "no limit", which is the same silent crash with no way to opt out
 * of it. tjs__clamp_stack_size therefore maps 0 onto the platform maximum.
 *
 * Both bounds come from the OS, never from the current stack pointer, so the
 * answer does not depend on how deep the caller happens to be. That is
 * required: the CLI flag arrives via engine.setMaxStackSize() from
 * cts/src/config.ts:356, dozens of JS frames deep, where an sp-relative
 * measurement would under-report by hundreds of KB.
 */
static bool tjs__native_stack_bounds(uintptr_t *low, uintptr_t *high) {
#if defined(_WIN32)
    ULONG_PTR lo = 0, hi = 0;
    GetCurrentThreadStackLimits(&lo, &hi);
    if (hi <= lo) {
        return false;
    }
    *low = (uintptr_t) lo;
    *high = (uintptr_t) hi;
    return true;
#elif defined(__APPLE__)
    /* Returns the BASE (highest address) on Darwin, not the low end. */
    void *base = pthread_get_stackaddr_np(pthread_self());
    size_t size = pthread_get_stacksize_np(pthread_self());
    if (base == NULL || size == 0) {
        return false;
    }
    *high = (uintptr_t) base;
    *low = (uintptr_t) base - size;
    return true;
#elif defined(__linux__) && defined(__GLIBC__)
    pthread_attr_t attr;
    void *addr = NULL;
    size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) {
        return false;
    }
    if (pthread_attr_getstack(&attr, &addr, &size) != 0 || addr == NULL || size == 0) {
        pthread_attr_destroy(&attr);
        return false;
    }
    pthread_attr_destroy(&attr);
    *low = (uintptr_t) addr;
    *high = (uintptr_t) addr + size;
    return true;
#else
    /* Portable fallback: no way to locate the stack, so only its SIZE is
     * known. Report a synthetic window of that size ending at the current
     * frame — tjs__clamp_stack_size only ever uses (high - low). */
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) != 0) {
        return false;
    }
    if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur == 0) {
        return false; /* unknown -> caller leaves the request alone */
    }
    uintptr_t here = (uintptr_t) &rl;
    if ((uintptr_t) rl.rlim_cur >= here) {
        return false;
    }
    *high = here;
    *low = here - (uintptr_t) rl.rlim_cur;
    return true;
#endif
}

/* Headroom kept below QuickJS's soft limit, so that the limit fires while
 * there is still real stack left for the guard region and for the C frames
 * that build and propagate the RangeError. The observed cliff needed only
 * ~32KB; 512KB costs ~6% of usable depth on an 8MB stack and absorbs the
 * platform-to-platform variation in guard size and frame cost. Small stacks
 * (Darwin secondary threads default to 512KB) take the proportional branch so
 * the headroom can never consume the whole stack. */
#define TJS__STACK_HEADROOM   (512 * 1024)
#define TJS__STACK_MIN_LIMIT  (64 * 1024)

/* Mirrors TJS__DEFAULT_STACK_SIZE (vm.c:49). Duplicated rather than shared
 * because that macro lives in vm.c, not in a header, and utils.h is owned
 * elsewhere. Keep the two in sync. */
#define TJS__STACK_FALLBACK   (6 * 1024 * 1024)

size_t tjs__clamp_stack_size(size_t requested, bool *was_clamped) {
    uintptr_t low = 0, high = 0;

    if (was_clamped != NULL) {
        *was_clamped = false;
    }

    if (!tjs__native_stack_bounds(&low, &high)) {
        /* Platform did not tell us. Honour the request rather than silently
         * shrinking it — but never leave it at 0/"no limit", which is the one
         * value guaranteed to crash. */
        return requested == 0 ? (size_t) TJS__STACK_FALLBACK : requested;
    }

    size_t total = (size_t) (high - low);
    size_t headroom = total / 8 < (size_t) TJS__STACK_HEADROOM ? total / 8 : (size_t) TJS__STACK_HEADROOM;
    size_t max_usable = total > headroom ? total - headroom : 0;

    if (max_usable < (size_t) TJS__STACK_MIN_LIMIT) {
        /* Pathologically small stack: a limit this low cannot be honoured
         * meaningfully, but 0 must still not be propagated. */
        max_usable = (size_t) TJS__STACK_MIN_LIMIT;
    }

    /* 0 means "no limit" to QuickJS, so it is the maximum request, not a
     * pass-through. */
    if (requested == 0 || requested > max_usable) {
        if (was_clamped != NULL) {
            *was_clamped = true;
        }
        return max_usable;
    }
    return requested;
}

/* Total bytes the current thread's stack spans, or 0 when the platform did not
 * report bounds. Only feeds the diagnostic in mod_engine.c, which is reached
 * exclusively on the path where tjs__clamp_stack_size DID find bounds, so a 0
 * can never reach a printed message. */
size_t tjs__native_stack_total_size(void) {
    uintptr_t low = 0, high = 0;

    if (!tjs__native_stack_bounds(&low, &high)) {
        return 0;
    }
    return (size_t) (high - low);
}


void tjs_assert(const struct AssertionInfo info) {
    fprintf(stderr,
            "%s:%s%s Assertion `%s' failed.\n",
            info.file_line,
            info.function,
            *info.function ? ":" : "",
            info.message);
    fflush(stderr);
    abort();
}

uv_loop_t *tjs_get_loop(JSContext *ctx) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    return TJS_GetLoop(qrt);
}

int tjs_obj2addr(JSContext *ctx, JSValue obj, struct sockaddr_storage *ss) {
    JSValue js_ip;
    JSValue js_port;
    const char *ip;
    uint32_t port = 0;
    int r;
    int ret = 0;

    js_ip = JS_GetPropertyStr(ctx, obj, "ip");
    ip = JS_ToCString(ctx, js_ip);
    JS_FreeValue(ctx, js_ip);
    if (!ip) {
        return -1;
    }

    js_port = JS_GetPropertyStr(ctx, obj, "port");
    r = JS_ToUint32(ctx, &port, js_port);
    JS_FreeValue(ctx, js_port);
    if (r != 0) {
        ret = -1;
        goto end;
    }

    memset(ss, 0, sizeof(*ss));

    if (uv_inet_pton(AF_INET, ip, &((struct sockaddr_in *) ss)->sin_addr) == 0) {
        ss->ss_family = AF_INET;
        ((struct sockaddr_in *) ss)->sin_port = htons(port);
    } else if (uv_inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *) ss)->sin6_addr) == 0) {
        ss->ss_family = AF_INET6;
        ((struct sockaddr_in6 *) ss)->sin6_port = htons(port);
    } else {
        tjs_throw_errno(ctx, UV_EAFNOSUPPORT);
        ret = -1;
    }

end:
    JS_FreeCString(ctx, ip);
    return ret;
}

void tjs_addr2obj(JSContext *ctx, JSValue obj, const struct sockaddr *sa, bool skip_port) {
    char buf[INET6_ADDRSTRLEN + 1];

    if (!sa) {
        return;
    }

    switch (sa->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr4 = (struct sockaddr_in *) sa;
            uv_ip4_name(addr4, buf, sizeof(buf));

            JS_DefinePropertyValueStr(ctx, obj, "family", JS_NewInt32(ctx, 4), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ip", JS_NewString(ctx, buf), JS_PROP_C_W_E);
            if (!skip_port) {
                JS_DefinePropertyValueStr(ctx, obj, "port", JS_NewInt32(ctx, ntohs(addr4->sin_port)), JS_PROP_C_W_E);
            }

            break;
        }

        case AF_INET6: {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) sa;
            uv_ip6_name(addr6, buf, sizeof(buf));

            JS_DefinePropertyValueStr(ctx, obj, "family", JS_NewInt32(ctx, 6), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ip", JS_NewString(ctx, buf), JS_PROP_C_W_E);
            if (!skip_port) {
                JS_DefinePropertyValueStr(ctx, obj, "port", JS_NewInt32(ctx, ntohs(addr6->sin6_port)), JS_PROP_C_W_E);
            }
            JS_DefinePropertyValueStr(ctx,
                                      obj,
                                      "flowInfo",
                                      JS_NewInt32(ctx, ntohl(addr6->sin6_flowinfo)),
                                      JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "scopeId", JS_NewInt32(ctx, addr6->sin6_scope_id), JS_PROP_C_W_E);

            break;
        }
    }
}

JSValue tjs__dispatch_event(JSContext *ctx, TJSEvents ev, JSValue data) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    if (qrt->freeing || JS_IsUndefined(qrt->builtins.dispatch_event_fn)) {
        return JS_UNDEFINED;
    }

    JSValue ret = JS_Call(ctx, qrt->builtins.dispatch_event_fn, JS_NULL, 2, (JSValueConst[]){
		JS_NewInt32(ctx, ev), data
	});
    return ret;
}

void tjs__dispatch_event2(JSContext *ctx, TJSEvents ev, JSValue data) {
    JSValue ret = tjs__dispatch_event(ctx, ev, data);
	JS_FreeValue(ctx, ret);
}
void tjs_call_handler(JSContext *ctx, JSValue func, int argc, JSValue *argv) {
    JSValue ret, func1;
    TJSRuntime *trt = TJS_GetRuntime(ctx);

    // Don't call handlers if runtime is being freed
    if (trt && trt->freeing) {
        for (int i = 0; i < argc; i++) {
            JS_FreeValue(ctx, argv[i]);
        }
        return;
    }

    /* 'func' might be destroyed when calling itself (if it frees the
       handler), so must take extra care */
    func1 = JS_DupValue(ctx, func);
    ret = JS_Call(ctx, func1, JS_UNDEFINED, argc, argv);
    JS_FreeValue(ctx, func1);
    if (JS_IsException(ret)) {
		// alias to jobexception
		JSValue err = JS_GetException(ctx);
        if (JS_IsUncatchableError(err)) {
            CHECK_NOT_NULL(trt);
            TJS_Stop(trt);
            JS_FreeValue(ctx, err);
            JS_FreeValue(ctx, ret);
            return;
        }
		JSValue retv = tjs__dispatch_event(ctx, EV_JOB_EXCEPTION, err);
		if (JS_IsEqual(ctx, retv, JS_FALSE)) {
			CHECK_NOT_NULL(trt);
#ifdef DEBUG
			fprintf(stderr, "[CORE] CALLED: ");
			tjs_dump_error(ctx, err);
#endif
			TJS_Stop(trt);
		}
		JS_FreeValue(ctx, err);
		JS_FreeValue(ctx, retv);
    }
    JS_FreeValue(ctx, ret);
}

JSValue TJS_InitPromise(JSContext *ctx, TJSPromise *p) {
    /* Callers commonly queue a libuv request before creating the promise.
     * Keep every field in a known state before entering QuickJS: on an OOM
     * path JS_NewPromiseCapability() returns JS_EXCEPTION and leaves its
     * resolving_funcs output unspecified.  A late native callback must be
     * able to observe that state and release its own resources safely. */
    p->p = JS_UNDEFINED;
    p->rfuncs[0] = JS_UNDEFINED;
    p->rfuncs[1] = JS_UNDEFINED;

    JSValue rfuncs[2] = { JS_UNDEFINED, JS_UNDEFINED };
    p->p = JS_NewPromiseCapability(ctx, rfuncs);
    if (JS_IsException(p->p)) {
        /* QuickJS is allowed to leave partially-created resolving functions
         * in the output array when capability construction fails.  Release
         * any such values before returning the exception. */
        JS_FreeValue(ctx, rfuncs[0]);
        JS_FreeValue(ctx, rfuncs[1]);
        p->p = JS_UNDEFINED;
        return JS_EXCEPTION;
    }
    p->rfuncs[0] = rfuncs[0];
    p->rfuncs[1] = rfuncs[1];
    return JS_DupValue(ctx, p->p);
}

bool TJS_IsPromisePending(JSContext *ctx, TJSPromise *p) {
    (void)ctx;
    /* JS_EXCEPTION is never a usable promise.  Treat it as non-pending too
     * for compatibility with callers that inspect a partially initialized
     * request after promise allocation failed. */
    return !JS_IsUndefined(p->p) && !JS_IsException(p->p);
}

void TJS_FreePromise(JSContext *ctx, TJSPromise *p) {
    /* Detach before dropping references. JS_FreeValue() can run native
     * finalizers, so reading from an enclosing request after the first free
     * is not safe. Clearing first also makes repeated teardown a no-op. */
    TJSPromise owned = *p;
    TJS_ClearPromise(ctx, p);
    JS_FreeValue(ctx, owned.rfuncs[0]);
    JS_FreeValue(ctx, owned.rfuncs[1]);
    JS_FreeValue(ctx, owned.p);
}

void TJS_FreePromiseRT(JSRuntime *rt, TJSPromise *p) {
    TJSPromise owned = *p;
    TJS_ClearPromise(NULL, p);
    JS_FreeValueRT(rt, owned.rfuncs[0]);
    JS_FreeValueRT(rt, owned.rfuncs[1]);
    JS_FreeValueRT(rt, owned.p);
}

void TJS_ClearPromise(JSContext *ctx, TJSPromise *p) {
    p->p = JS_UNDEFINED;
    p->rfuncs[0] = JS_UNDEFINED;
    p->rfuncs[1] = JS_UNDEFINED;
}

void TJS_MarkPromise(JSRuntime *rt, TJSPromise *p, JS_MarkFunc *mark_func) {
    JS_MarkValue(rt, p->p, mark_func);
    JS_MarkValue(rt, p->rfuncs[0], mark_func);
    JS_MarkValue(rt, p->rfuncs[1], mark_func);
}

void TJS_SettlePromise(JSContext *ctx, TJSPromise *p, bool is_reject, int argc, JSValue *argv) {
    /* A native operation may have been queued before promise allocation.  If
     * allocation failed (or teardown already cleared the promise), there is
     * no resolver to call.  The callback still owns `argv`, so release those
     * values and clear the record before returning. */
    if (!TJS_IsPromisePending(ctx, p)) {
        TJSPromise owned = *p;
        TJS_ClearPromise(ctx, p);
        for (int i = 0; i < argc; i++) {
            JS_FreeValue(ctx, argv[i]);
        }
        /* Normally all three fields are already undefined here.  Freeing the
         * detached copy also covers a partially-created capability and keeps
         * this path leak-free if a future QuickJS version returns one. */
        JS_FreeValue(ctx, owned.rfuncs[0]);
        JS_FreeValue(ctx, owned.rfuncs[1]);
        JS_FreeValue(ctx, owned.p);
        return;
    }

    /* Resolving a promise invokes the host promise hook synchronously. That
     * hook is user JS and may re-enter the native object that owns `p` (or
     * even finalize it). Move the capability out and mark the record settled
     * before calling JS; afterwards, never dereference `p` again. */
    TJSPromise owned = *p;
    TJS_ClearPromise(ctx, p);

    JSValue ret = JS_Call(ctx, owned.rfuncs[is_reject], JS_UNDEFINED, argc, argv);
    for (int i = 0; i < argc; i++) {
        JS_FreeValue(ctx, argv[i]);
    }
    JS_FreeValue(ctx, ret);
    TJS_FreePromise(ctx, &owned);
}

void TJS_ResolvePromise(JSContext *ctx, TJSPromise *p, int argc, JSValue *argv) {
    TJS_SettlePromise(ctx, p, false, argc, argv);
}

void TJS_RejectPromise(JSContext *ctx, TJSPromise *p, int argc, JSValue *argv) {
    TJS_SettlePromise(ctx, p, true, argc, argv);
}

static inline JSValue tjs__settled_promise(JSContext *ctx, bool is_reject, int argc, JSValue *argv) {
    JSValue promise, resolving_funcs[2] = { JS_UNDEFINED, JS_UNDEFINED }, ret;

    promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise)) {
        /* The helper takes ownership of argv even when promise creation
         * fails.  Release it here; otherwise every OOM on a fast-path
         * resolved/rejected promise leaks the result value. */
        for (int i = 0; i < argc; i++) {
            JS_FreeValue(ctx, argv[i]);
        }
        JS_FreeValue(ctx, resolving_funcs[0]);
        JS_FreeValue(ctx, resolving_funcs[1]);
        return JS_EXCEPTION;
    }

    ret = JS_Call(ctx, resolving_funcs[is_reject], JS_UNDEFINED, argc, argv);

    for (int i = 0; i < argc; i++) {
        JS_FreeValue(ctx, argv[i]);
    }
    if (JS_IsException(ret)) {
        JS_FreeValue(ctx, ret);
        JS_FreeValue(ctx, resolving_funcs[0]);
        JS_FreeValue(ctx, resolving_funcs[1]);
        JS_FreeValue(ctx, promise);
        return JS_EXCEPTION;
    }
    JS_FreeValue(ctx, ret);
    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);

    return promise;
}

JSValue TJS_NewResolvedPromise(JSContext *ctx, int argc, JSValue *argv) {
    return tjs__settled_promise(ctx, false, argc, argv);
}

JSValue TJS_NewRejectedPromise(JSContext *ctx, int argc, JSValue *argv) {
    return tjs__settled_promise(ctx, true, argc, argv);
}

static void* tjs__buf_realloc(JSRuntime *rt, void *opaque, void *ptr, size_t size) {
    if (size == 0){
        js_free_rt(rt, ptr);
        return NULL;
    } else {
        return js_realloc_rt(rt, ptr, size);
    }
}

JSValue TJS_NewUint8Array(JSContext *ctx, uint8_t *data, size_t size) {
    return JS_NewUint8Array(ctx, data, size, tjs__buf_realloc, NULL, false);
}

const char *tjs_signal_map[] = {
#ifdef SIGHUP
    [SIGHUP] = "SIGHUP",
#endif
#ifdef SIGINT
    [SIGINT] = "SIGINT",
#endif
#ifdef SIGQUIT
    [SIGQUIT] = "SIGQUIT",
#endif
#ifdef SIGILL
    [SIGILL] = "SIGILL",
#endif
#ifdef SIGTRAP
    [SIGTRAP] = "SIGTRAP",
#endif
#ifdef SIGABRT
    [SIGABRT] = "SIGABRT",
#endif
#ifdef SIGBUS
    [SIGBUS] = "SIGBUS",
#endif
#ifdef SIGFPE
    [SIGFPE] = "SIGFPE",
#endif
#ifdef SIGKILL
    [SIGKILL] = "SIGKILL",
#endif
#ifdef SIGUSR1
    [SIGUSR1] = "SIGUSR1",
#endif
#ifdef SIGSEGV
    [SIGSEGV] = "SIGSEGV",
#endif
#ifdef SIGUSR2
    [SIGUSR2] = "SIGUSR2",
#endif
#ifdef SIGPIPE
    [SIGPIPE] = "SIGPIPE",
#endif
#ifdef SIGALRM
    [SIGALRM] = "SIGALRM",
#endif
#ifdef SIGTERM
    [SIGTERM] = "SIGTERM",
#endif
#ifdef SIGSTKFLT
    [SIGSTKFLT] = "SIGSTKFLT",
#endif
#ifdef SIGCHLD
    [SIGCHLD] = "SIGCHLD",
#endif
#ifdef SIGCONT
    [SIGCONT] = "SIGCONT",
#endif
#ifdef SIGSTOP
    [SIGSTOP] = "SIGSTOP",
#endif
#ifdef SIGTSTP
    [SIGTSTP] = "SIGTSTP",
#endif
#ifdef SIGBREAK
    [SIGBREAK] = "SIGBREAK",
#endif
#ifdef SIGTTIN
    [SIGTTIN] = "SIGTTIN",
#endif
#ifdef SIGTTOU
    [SIGTTOU] = "SIGTTOU",
#endif
#ifdef SIGURG
    [SIGURG] = "SIGURG",
#endif
#ifdef SIGXCPU
    [SIGXCPU] = "SIGXCPU",
#endif
#ifdef SIGXFSZ
    [SIGXFSZ] = "SIGXFSZ",
#endif
#ifdef SIGVTALRM
    [SIGVTALRM] = "SIGVTALRM",
#endif
#ifdef SIGPROF
    [SIGPROF] = "SIGPROF",
#endif
#ifdef SIGWINCH
    [SIGWINCH] = "SIGWINCH",
#endif
#ifdef SIGPOLL
    [SIGPOLL] = "SIGPOLL",
#endif
#ifdef SIGLOST
    [SIGLOST] = "SIGLOST",
#endif
#ifdef SIGPWR
    [SIGPWR] = "SIGPWR",
#endif
#ifdef SIGINFO
    [SIGINFO] = "SIGINFO",
#endif
#ifdef SIGSYS
    [SIGSYS] = "SIGSYS",
#endif
};

size_t tjs_signal_map_count = ARRAY_SIZE(tjs_signal_map);

const char *tjs_getsig(int sig) {
    if (sig < 0 || sig >= tjs_signal_map_count || !tjs_signal_map[sig]) {
        return NULL;
    }

    return tjs_signal_map[sig];
}

int tjs_getsignum(const char *sig_str) {
    for (int i = 0; i < tjs_signal_map_count; i++) {
        const char *s = tjs_signal_map[i];
        if (s && strcmp(sig_str, s) == 0) {
            return i;
        }
    }

    return -1;
}

void tjs_dbuf_init(JSContext *ctx, DynBuf *s) {
    dbuf_init2(s, JS_GetRuntime(ctx), (DynBufReallocFunc *) js_realloc_rt);
}


int tjs__load_file(JSContext *ctx, DynBuf *dbuf, const char *filename) {
    uv_fs_t req;
    uv_file fd;
    int r;

    r = uv_fs_open(NULL, &req, filename, O_RDONLY, 0, NULL);
    uv_fs_req_cleanup(&req);
    if (r < 0) {
        return r;
    }

    fd = r;
    char buf[64 * 1024];
    uv_buf_t b = uv_buf_init(buf, sizeof(buf));
    size_t offset = 0;

    do {
        r = uv_fs_read(NULL, &req, fd, &b, 1, offset, NULL);
        uv_fs_req_cleanup(&req);
        if (r <= 0) {
            break;
        }
        offset += r;
        r = dbuf_put(dbuf, (const uint8_t *) b.base, r);
        if (r != 0) {
            break;
        }
    } while (1);

    uv_fs_close(NULL, &req, fd, NULL);
    uv_fs_req_cleanup(&req);

    return r;
}

JSValue TJS_EvalModuleContent(JSContext *ctx,
                              const char *specifier,
                              bool is_main,
                              bool use_real_path,
                              const char *content,
                              size_t len) {
    /* Compile then run to be able to set import.meta */
    JSValue ret = JS_Eval(ctx, content, len, specifier, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (!JS_IsException(ret)) {
        js_module_set_import_meta(ctx, ret, use_real_path, is_main);
        ret = JS_EvalFunction(ctx, ret);
    }

    /* Emit window 'load' event. */
    if (!JS_IsException(ret) && is_main) {
		JSValue ret = tjs__dispatch_event(ctx, EV_LOAD, JS_UNDEFINED);
		if (JS_IsException(ret)){
			TJS_DumpException(ctx);
		}
		JS_FreeValue(ctx, ret);
    }

    return ret;
}

JSValue TJS_EvalScript(JSContext *ctx, const char *filename) {
    DynBuf dbuf;
    size_t dbuf_size;
    int r;
    JSValue ret;

    tjs_dbuf_init(ctx, &dbuf);
    r = tjs__load_file(ctx, &dbuf, filename);
    if (r != 0) {
        dbuf_free(&dbuf);
        JS_ThrowReferenceError(ctx, "could not load '%s' - %s: %s", filename, uv_err_name(r), uv_strerror(r));
        return JS_EXCEPTION;
    }

    dbuf_size = dbuf.size;

    /* Add null termination, required by JS_Eval. */
    dbuf_putc(&dbuf, '\0');

    ret = JS_Eval(ctx, (char *) dbuf.buf, dbuf_size, filename, JS_EVAL_TYPE_GLOBAL);

    dbuf_free(&dbuf);
    return ret;
}

JSValue TJS_EvalModule(JSContext *ctx, const char *filename, bool is_main) {
    DynBuf dbuf;
    size_t dbuf_size;
    int r;
    JSValue ret;

    tjs_dbuf_init(ctx, &dbuf);
    r = tjs__load_file(ctx, &dbuf, filename);
    if (r != 0) {
        dbuf_free(&dbuf);
        JS_ThrowReferenceError(ctx, "could not load '%s' - %s: %s", filename, uv_err_name(r), uv_strerror(r));
        return JS_EXCEPTION;
    }

    dbuf_size = dbuf.size;

    /* Add null termination, required by JS_Eval. */
    dbuf_putc(&dbuf, '\0');

    ret = TJS_EvalModuleContent(ctx, filename, is_main, true, (char *) dbuf.buf, dbuf_size);

    dbuf_free(&dbuf);
    return ret;
}
