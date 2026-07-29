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

#include "utils.h"

#include "private.h"
#include "tjs.h"

#include <stdlib.h>
#include <string.h>


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
    JSValue rfuncs[2];
    p->p = JS_NewPromiseCapability(ctx, rfuncs);
    if (JS_IsException(p->p)) {
        return JS_EXCEPTION;
    }
    p->rfuncs[0] = rfuncs[0];
    p->rfuncs[1] = rfuncs[1];
    return JS_DupValue(ctx, p->p);
}

bool TJS_IsPromisePending(JSContext *ctx, TJSPromise *p) {
    return !JS_IsUndefined(p->p);
}

void TJS_FreePromise(JSContext *ctx, TJSPromise *p) {
    JS_FreeValue(ctx, p->rfuncs[0]);
    JS_FreeValue(ctx, p->rfuncs[1]);
    JS_FreeValue(ctx, p->p);
}

void TJS_FreePromiseRT(JSRuntime *rt, TJSPromise *p) {
    JS_FreeValueRT(rt, p->rfuncs[0]);
    JS_FreeValueRT(rt, p->rfuncs[1]);
    JS_FreeValueRT(rt, p->p);
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
    JSValue ret = JS_Call(ctx, p->rfuncs[is_reject], JS_UNDEFINED, argc, argv);
    for (int i = 0; i < argc; i++) {
        JS_FreeValue(ctx, argv[i]);
    }
    JS_FreeValue(ctx, ret); /* XXX: what to do if exception ? */
    TJS_FreePromise(ctx, p);
    TJS_ClearPromise(ctx, p);
}

void TJS_ResolvePromise(JSContext *ctx, TJSPromise *p, int argc, JSValue *argv) {
    TJS_SettlePromise(ctx, p, false, argc, argv);
}

void TJS_RejectPromise(JSContext *ctx, TJSPromise *p, int argc, JSValue *argv) {
    TJS_SettlePromise(ctx, p, true, argc, argv);
}

static inline JSValue tjs__settled_promise(JSContext *ctx, bool is_reject, int argc, JSValue *argv) {
    JSValue promise, resolving_funcs[2], ret;

    promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise)) {
        return JS_EXCEPTION;
    }

    ret = JS_Call(ctx, resolving_funcs[is_reject], JS_UNDEFINED, argc, argv);

    for (int i = 0; i < argc; i++) {
        JS_FreeValue(ctx, argv[i]);
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

static void tjs__buf_free(JSRuntime *rt, void *opaque, void *ptr) {
    js_free_rt(rt, ptr);
}

JSValue TJS_NewUint8Array(JSContext *ctx, uint8_t *data, size_t size) {
    return JS_NewUint8Array(ctx, data, size, tjs__buf_free, NULL, false);
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
