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

/* _GNU_SOURCE must precede any header: pthread_getattr_np is GNU-only. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "utils.h"

#include "private.h"
#include "capability.h"
#include "tjs.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#elif defined(__APPLE__)
#include <pthread.h>
#else
#include <pthread.h>
#include <sys/resource.h>
#endif


/* JS_SetMaxStackSize only stores the number; QuickJS derives its soft limit
 * as stack_top - stack_size, never checked against the real stack. */
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
    /* No real bounds: synthetic window; the clamp only uses (high - low). */
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

/* Headroom so the limit fires with stack left for the guard region and the
 * C frames building the RangeError; small stacks take the /8 branch. */
#define TJS__STACK_HEADROOM   (512 * 1024)
#define TJS__STACK_MIN_LIMIT  (64 * 1024)

/* Mirrors TJS__DEFAULT_STACK_SIZE in vm.c; keep in sync. */
#define TJS__STACK_FALLBACK   (6 * 1024 * 1024)

size_t tjs__clamp_stack_size(size_t requested, bool *was_clamped) {
    uintptr_t low = 0, high = 0;

    if (was_clamped != NULL) {
        *was_clamped = false;
    }

    if (!tjs__native_stack_bounds(&low, &high)) {
        /* Honour the request, but never 0: "no limit" crashes. */
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

/* Stack bytes on this thread, or 0 when no bounds were reported. */
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

    if (qrt->freeing) {
        return JS_UNDEFINED;
    }
    return tjs__mod_evbus_dispatch_runtime_event(ctx, ev, data);
}

void tjs__dispatch_event2(JSContext *ctx, TJSEvents ev, JSValue data) {
    JSValue ret = tjs__dispatch_event(ctx, ev, data);
	JS_FreeValue(ctx, ret);
}

void tjs__stop_uncatchable_error(JSContext *ctx, JSValueConst error) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(trt);
    if (!trt->explicit_exit) {
        tjs_dump_error(ctx, error);
        trt->exit_code = 1;
    }
    TJS_Stop(trt);
}

void tjs_call_handler(JSContext *ctx, JSValue func, int argc, JSValue *argv) {
    JSValue ret, func1;
    TJSRuntime *trt = TJS_GetRuntime(ctx);

    /* Do not call user code after teardown starts. The caller retains
     * ownership of argv and will release those values after this helper
     * returns, just as it does on the normal path. */
    if (trt && trt->freeing) {
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
            tjs__stop_uncatchable_error(ctx, err);
            JS_FreeValue(ctx, err);
            JS_FreeValue(ctx, ret);
            return;
        }
		JSValue retv = tjs__dispatch_event(ctx, EV_JOB_EXCEPTION, err);
        if (JS_IsException(retv)) {
            TJS_DumpException(ctx);
        }
		if (JS_IsException(retv) || (JS_IsBool(retv) && !JS_VALUE_GET_BOOL(retv))) {
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
    /* Initialize fields first: OOM leaves JS_NewPromiseCapability's outputs
     * unspecified and a late native callback must see a known state. */
    p->p = JS_UNDEFINED;
    p->rfuncs[0] = JS_UNDEFINED;
    p->rfuncs[1] = JS_UNDEFINED;

    JSValue rfuncs[2] = { JS_UNDEFINED, JS_UNDEFINED };
    p->p = JS_NewPromiseCapability(ctx, rfuncs);
    if (JS_IsException(p->p)) {
        /* Failed capability creation may leave partial rfuncs in the array. */
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
    /* JS_EXCEPTION is never usable; treat as non-pending for OOM callers. */
    return !JS_IsUndefined(p->p) && !JS_IsException(p->p);
}

void TJS_FreePromise(JSContext *ctx, TJSPromise *p) {
    /* Detach first: JS_FreeValue can run finalizers that touch the enclosing
     * request; clearing also makes repeated teardown a no-op. */
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
    /* No resolver when allocation failed or teardown cleared; the callback
     * still owns argv, so release it and clear the record. */
    if (!TJS_IsPromisePending(ctx, p)) {
        TJSPromise owned = *p;
        TJS_ClearPromise(ctx, p);
        for (int i = 0; i < argc; i++) {
            JS_FreeValue(ctx, argv[i]);
        }
        /* Freeing the detached copy also covers a partial capability. */
        JS_FreeValue(ctx, owned.rfuncs[0]);
        JS_FreeValue(ctx, owned.rfuncs[1]);
        JS_FreeValue(ctx, owned.p);
        return;
    }

    /* Resolving invokes the host promise hook (user JS) synchronously; it may
     * re-enter or finalize the owner. Detach first, never touch p after. */
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
        /* Owns argv even on failure; release it or OOM leaks the values. */
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
    /* JS_NewUint8Array only consumes data once its ArrayBuffer was created.
     * Split the two allocations so this helper consumes data on every path. */
    JSValue buffer = JS_NewArrayBuffer(ctx, data, size, 0, tjs__buf_realloc, NULL, false);
    if (JS_IsException(buffer)) {
        js_free(ctx, data);
        return buffer;
    }
    JSValue array = JS_NewTypedArray(ctx, 1, &buffer, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(ctx, buffer);
    return array;
}

TJSPinnedFd TJS_PinFd(int fd) {
    TJSPinnedFd pin = { fd, 0, false };
    int pinned_fd;
#ifdef _WIN32
    if (uv_get_osfhandle(fd) == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        pinned_fd = -1;
    } else {
        pinned_fd = _dup(fd);
    }
    if (pinned_fd >= 0) {
        HANDLE handle = uv_get_osfhandle(pinned_fd);
        if (handle == INVALID_HANDLE_VALUE ||
            !SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)) {
            int saved_errno = handle == INVALID_HANDLE_VALUE ? EBADF : EINVAL;
            _close(pinned_fd);
            errno = saved_errno;
            pinned_fd = -1;
        }
    }
#elif defined(F_DUPFD_CLOEXEC)
    do {
        pinned_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    } while (pinned_fd < 0 && errno == EINTR);
#else
    do {
        pinned_fd = dup(fd);
    } while (pinned_fd < 0 && errno == EINTR);
    if (pinned_fd >= 0) {
        int fd_flags;
        do {
            fd_flags = fcntl(pinned_fd, F_GETFD);
        } while (fd_flags < 0 && errno == EINTR);
        if (fd_flags < 0 || fcntl(pinned_fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
            int saved_errno = errno;
            close(pinned_fd);
            errno = saved_errno;
            pinned_fd = -1;
        }
    }
#endif

    if (pinned_fd < 0) {
        pin.fd = -1;
        pin.error = errno ? errno : EBADF;
        return pin;
    }
    pin.fd = pinned_fd;
    pin.owned = true;
    return pin;
}

void TJS_UnpinFd(TJSPinnedFd *pin) {
    if (!pin || !pin->owned) return;

    int saved_errno = errno;
#ifdef _WIN32
    DWORD saved_error = GetLastError();
    _close(pin->fd);
    SetLastError(saved_error);
#else
    close(pin->fd);
#endif
    errno = saved_errno;
    pin->fd = -1;
    pin->owned = false;
}

TJSObjectHandleIdentity TJS_CompareObjectHandlesCached(
    TJSObjectHandleCompareCache *cache,
    TJSObjectHandleCompareResolver resolver,
    void *opaque,
    void *first,
    void *second) {
    if (!cache->initialized) {
        cache->compare = resolver ? resolver(opaque) : NULL;
        cache->initialized = true;
    }
    if (!cache->compare) {
        return TJS_OBJECT_HANDLE_IDENTITY_UNSUPPORTED;
    }
    return cache->compare(first, second)
        ? TJS_OBJECT_HANDLE_IDENTITY_SAME
        : TJS_OBJECT_HANDLE_IDENTITY_DIFFERENT;
}

#ifdef _WIN32
static INIT_ONCE tjs__compare_object_handles_once = INIT_ONCE_STATIC_INIT;
static TJSObjectHandleCompareCache tjs__compare_object_handles_cache;

static TJSObjectHandleCompareFunction tjs__resolve_compare_object_handles(
    void *opaque) {
    (void) opaque;
    static const wchar_t *const module_names[] = {
        L"kernelbase.dll",
        L"kernel32.dll",
    };

    for (size_t i = 0; i < ARRAY_SIZE(module_names); i++) {
        HMODULE module = GetModuleHandleW(module_names[i]);
        bool loaded_here = false;
        if (!module) {
            module = LoadLibraryW(module_names[i]);
            loaded_here = module != NULL;
        }
        if (!module) continue;

        /* This union is the warning-free conversion also used by bundled
         * libuv: a direct FARPROC/function-pointer cast trips MSVC /W4 /WX. */
        union {
            FARPROC proc;
            TJSObjectHandleCompareFunction compare;
        } symbol;
        symbol.proc = GetProcAddress(module, "CompareObjectHandles");
        if (symbol.proc) {
            /* Keep a module loaded by us resident: the cached pointer must
             * remain valid for the rest of the process. */
            return symbol.compare;
        }
        if (loaded_here) FreeLibrary(module);
    }
    return NULL;
}

static BOOL CALLBACK tjs__init_compare_object_handles(
    PINIT_ONCE once, PVOID parameter, PVOID *context) {
    (void) once;
    (void) parameter;
    (void) context;
    tjs__compare_object_handles_cache.compare =
        tjs__resolve_compare_object_handles(NULL);
    tjs__compare_object_handles_cache.initialized = true;
    return TRUE;
}

TJSObjectHandleIdentity TJS_CompareObjectHandles(void *first, void *second) {
    if (!InitOnceExecuteOnce(&tjs__compare_object_handles_once,
                            tjs__init_compare_object_handles, NULL, NULL)) {
        return TJS_OBJECT_HANDLE_IDENTITY_UNSUPPORTED;
    }
    return TJS_CompareObjectHandlesCached(&tjs__compare_object_handles_cache,
                                          NULL, NULL, first, second);
}
#endif

JSValue TJS_ThrowObjectHandleIdentityUnsupported(JSContext *ctx) {
    return JS_ThrowTypeError(
        ctx,
        "object handle identity comparison is not supported on this platform");
}

static const char *const tjs_signal_map[] = {
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

JSValue TJS_NewSignalEnum(JSContext *ctx) {
    JSValue signals = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(signals)) return signals;

    for (size_t i = 0; i < ARRAY_SIZE(tjs_signal_map); i++) {
        const char *name = tjs_signal_map[i];
        if (name && JS_SetPropertyStr(ctx, signals, name, JS_NewInt32(ctx, (int32_t)i)) < 0) {
            JS_FreeValue(ctx, signals);
            return JS_EXCEPTION;
        }
    }

    return signals;
}

int TJS_ToSignal(JSContext *ctx, JSValueConst value, int default_signal) {
    if (JS_IsUndefined(value)) {
        if (default_signal >= 0) return default_signal;
        JS_ThrowTypeError(ctx, "signal must be a number from signals.signals");
        return -1;
    }
    if (!JS_IsNumber(value)) {
        JS_ThrowTypeError(ctx, "signal must be a number from signals.signals");
        return -1;
    }

    double number;
    int32_t signal;
    if (JS_ToFloat64(ctx, &number, value) < 0 || JS_ToInt32(ctx, &signal, value) < 0) return -1;
    if (number != (double)signal || signal < 0) {
        JS_ThrowRangeError(ctx, "invalid signal number");
        return -1;
    }

    if ((size_t)signal >= ARRAY_SIZE(tjs_signal_map) || !tjs_signal_map[signal]) {
        JS_ThrowRangeError(ctx, "unknown signal number: %d", signal);
        return -1;
    }
    return signal;
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

static JSValue tjs__eval_module_content(JSContext *ctx,
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

JSValue TJS_EvalModuleContent(JSContext *ctx,
                              const char *specifier,
                              bool is_main,
                              bool use_real_path,
                              const char *content,
                              size_t len) {
    if (use_real_path) { TJS_CAPABILITY(tjs__capability_io(ctx, TJS_CAP_IO | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "runtime.evalModuleContent", specifier), (void)0); }
    return tjs__eval_module_content(ctx, specifier, is_main, use_real_path, content, len);
}

JSValue TJS_EvalScript(JSContext *ctx, const char *filename) {
    DynBuf dbuf;
    size_t dbuf_size;
    int r;
    JSValue ret;

    TJS_CAPABILITY(tjs__capability_io(ctx, TJS_CAP_IO | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "runtime.evalScript", filename), (void)0);

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

    TJS_CAPABILITY(tjs__capability_io(ctx, TJS_CAP_IO | TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "runtime.evalModule", filename), (void)0);

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

    ret = tjs__eval_module_content(ctx, filename, is_main, true, (char *) dbuf.buf, dbuf_size);

    dbuf_free(&dbuf);
    return ret;
}
