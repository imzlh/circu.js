#include "private.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

/* Keep this standalone target meaningful in Release builds too. */
#undef assert
#define assert(expr) CHECK(expr)

static int jobs_run;

static JSValue teardown_job(JSContext *ctx, int argc, JSValueConst *argv) {
    (void)ctx;
    (void)argc;
    (void)argv;
    jobs_run++;
    return JS_UNDEFINED;
}

static void eval(JSContext *ctx, const char *source) {
    JSValue result = JS_Eval(ctx, source, strlen(source), "<teardown-test>",
                             JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result)) {
        JSValue error = JS_GetException(ctx);
        tjs_dump_error(ctx, error);
        JS_FreeValue(ctx, error);
    }
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
}

static JSValue call_method(JSContext *ctx, JSValue obj, const char *name,
                           int argc, JSValue *argv) {
    JSValue fn = JS_GetPropertyStr(ctx, obj, name);
    assert(JS_IsFunction(ctx, fn));
    JSValue result = JS_Call(ctx, fn, obj, argc, argv);
    JS_FreeValue(ctx, fn);
    return result;
}

typedef struct {
    JSValue udp;
    JSValue buffer;
    JSPromiseHookType type;
    bool close;
    bool called;
    bool nested_threw;
} UdpRecvHookState;

static void udp_recv_promise_hook(JSContext *ctx, JSPromiseHookType type,
                                  JSValueConst promise, JSValueConst parent,
                                  void *opaque) {
    (void)promise;
    (void)parent;
    UdpRecvHookState *state = opaque;
    if (type != state->type || state->called) return;
    state->called = true;
    JS_SetPromiseHook(JS_GetRuntime(ctx), NULL, NULL);
    JSValue result = state->close
        ? call_method(ctx, state->udp, "close", 0, NULL)
        : call_method(ctx, state->udp, "recv", 1, &state->buffer);
    state->nested_threw = JS_IsException(result);
    if (state->nested_threw) JS_FreeValue(ctx, JS_GetException(ctx));
    JS_FreeValue(ctx, result);
}

static void test_udp_recv_promise_reentry(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = TJS_GetMainContext(runtime);
    JSValue ns = JS_NewObject(ctx);
    tjs__mod_udp_init(ctx, ns);
    JSValue ctor = JS_GetPropertyStr(ctx, ns, "UDP");
    JSValue udp = JS_CallConstructor(ctx, ctor, 0, NULL);
    uint8_t bytes[16] = { 0 };
    JSValue buffer = JS_NewUint8ArrayCopy(ctx, bytes, sizeof(bytes));
    assert(!JS_IsException(udp));
    assert(!JS_IsException(buffer));

    UdpRecvHookState state = { .udp = udp, .buffer = buffer };
    JS_SetPromiseHook(runtime->rt, udp_recv_promise_hook, &state);
    JSValue recv_args[] = { buffer };
    JSValue promise = call_method(ctx, udp, "recv", 1, recv_args);
    assert(state.called && state.nested_threw);
    assert(!JS_IsException(promise));
    assert(JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING);

    state.called = false;
    state.nested_threw = false;
    state.type = JS_PROMISE_HOOK_RESOLVE;
    JS_SetPromiseHook(runtime->rt, udp_recv_promise_hook, &state);
    JSValue closed = call_method(ctx, udp, "close", 0, NULL);
    CHECK(!JS_IsException(closed));
    CHECK(state.called && state.nested_threw);
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_REJECTED);
    JS_FreeValue(ctx, closed);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, udp);

    udp = JS_CallConstructor(ctx, ctor, 0, NULL);
    CHECK(!JS_IsException(udp));
    state = (UdpRecvHookState) { .udp = udp, .buffer = buffer, .close = true };
    JS_SetPromiseHook(runtime->rt, udp_recv_promise_hook, &state);
    promise = call_method(ctx, udp, "recv", 1, &buffer);
    CHECK(state.called && !state.nested_threw);
    CHECK(JS_IsException(promise));
    JS_FreeValue(ctx, JS_GetException(ctx));

    JS_SetPromiseHook(runtime->rt, NULL, NULL);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, buffer);
    JS_FreeValue(ctx, udp);
    JS_FreeValue(ctx, ctor);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
}

typedef struct {
    JSValue pool;
    unsigned calls;
} CurlCloseHookState;

static void curl_close_promise_hook(JSContext *ctx, JSPromiseHookType type,
                                    JSValueConst promise, JSValueConst parent,
                                    void *opaque) {
    CurlCloseHookState *state = opaque;
    if (type != JS_PROMISE_HOOK_RESOLVE) return;
    state->calls++;
    JS_SetPromiseHook(JS_GetRuntime(ctx), NULL, NULL);
    JSValue result = call_method(ctx, state->pool, "close", 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
}

static void test_curl_completion_closes_pool(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue module = JS_NewObject(ctx);
    tjs__mod_curl_init(ctx, module);
    CHECK(!JS_HasException(ctx));
    JSValue pool_constructor = JS_GetPropertyStr(ctx, module, "ConnPool");
    JSValue curl_constructor = JS_GetPropertyStr(ctx, module, "CURL");
    JSValue pool = JS_CallConstructor(ctx, pool_constructor, 0, NULL);
    CHECK(!JS_IsException(pool));

    JSValue url = JS_NewString(ctx, "circu-test-unsupported://completion");
    CHECK(!JS_IsException(url));

    JSValue curls[2];
    JSValue promises[2];
    for (unsigned index = 0; index < countof(curls); index++) {
        curls[index] = JS_CallConstructor(ctx, curl_constructor, 1, &pool);
        CHECK(!JS_IsException(curls[index]));
        JSValue configured = call_method(ctx, curls[index], "setUrl", 1, &url);
        CHECK(!JS_IsException(configured));
        JS_FreeValue(ctx, configured);
        promises[index] = call_method(ctx, curls[index], "perform", 0, NULL);
        CHECK(!JS_IsException(promises[index]));
        CHECK_EQ(JS_PromiseState(ctx, promises[index]), JS_PROMISE_PENDING);
    }

    CurlCloseHookState state = { .pool = pool };
    JS_SetPromiseHook(runtime->rt, curl_close_promise_hook, &state);
    JSValue processed = call_method(ctx, pool, "process", 0, NULL);
    CHECK(!JS_IsException(processed));
    CHECK_EQ(state.calls, 1);
    CHECK_EQ(JS_PromiseState(ctx, promises[0]), JS_PROMISE_REJECTED);
    CHECK_EQ(JS_PromiseState(ctx, promises[1]), JS_PROMISE_REJECTED);
    const int expected_codes[] = { CURLE_UNSUPPORTED_PROTOCOL, CURLE_ABORTED_BY_CALLBACK };
    for (unsigned index = 0; index < countof(promises); index++) {
        JSValue error = JS_PromiseResult(ctx, promises[index]);
        JSValue code = JS_GetPropertyStr(ctx, error, "code");
        int32_t actual_code;
        CHECK_EQ(JS_ToInt32(ctx, &actual_code, code), 0);
        CHECK_EQ(actual_code, expected_codes[index]);
        JS_FreeValue(ctx, code);
        JS_FreeValue(ctx, error);
    }
    JS_SetPromiseHook(runtime->rt, NULL, NULL);
    JS_FreeValue(ctx, processed);
    for (unsigned index = 0; index < countof(curls); index++) {
        JS_FreeValue(ctx, promises[index]);
        JS_FreeValue(ctx, curls[index]);
    }
    JS_FreeValue(ctx, url);
    JS_FreeValue(ctx, curl_constructor);
    JS_FreeValue(ctx, pool_constructor);
    JS_FreeValue(ctx, pool);
    JS_FreeValue(ctx, module);
    TJS_FreeRuntime(runtime);
}

#ifndef _WIN32
static void test_curl_runtime_teardown_detaches_socket(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK_GE(listener, 0);

    int reuse = 1;
    CHECK_EQ(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)), 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(0),
    };
    CHECK_EQ(bind(listener, (const struct sockaddr *)&address, sizeof(address)), 0);
    CHECK_EQ(listen(listener, 1), 0);

    socklen_t address_len = sizeof(address);
    CHECK_EQ(getsockname(listener, (struct sockaddr *)&address, &address_len), 0);
    int flags = fcntl(listener, F_GETFL, 0);
    CHECK_GE(flags, 0);
    CHECK_EQ(fcntl(listener, F_SETFL, flags | O_NONBLOCK), 0);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue module = JS_NewObject(ctx);
    tjs__mod_curl_init(ctx, module);
    CHECK(!JS_HasException(ctx));
    JSValue pool_constructor = JS_GetPropertyStr(ctx, module, "ConnPool");
    JSValue curl_constructor = JS_GetPropertyStr(ctx, module, "CURL");
    JSValue pool = JS_CallConstructor(ctx, pool_constructor, 0, NULL);
    CHECK(!JS_IsException(pool));
    JSValue curl = JS_CallConstructor(ctx, curl_constructor, 1, &pool);
    CHECK(!JS_IsException(curl));

    char url_text[64];
    int url_length = snprintf(url_text, sizeof(url_text), "http://127.0.0.1:%u/", ntohs(address.sin_port));
    CHECK(url_length > 0 && (size_t)url_length < sizeof(url_text));
    JSValue url = JS_NewStringLen(ctx, url_text, (size_t)url_length);
    JSValue configured = call_method(ctx, curl, "setUrl", 1, &url);
    CHECK(!JS_IsException(configured));
    JS_FreeValue(ctx, configured);
    JSValue promise = call_method(ctx, curl, "perform", 0, NULL);
    CHECK(!JS_IsException(promise));
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);

    int peer = -1;
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    do {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        peer = accept(listener, NULL, NULL);
        if (peer < 0)
            CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
        CHECK_LT(uv_hrtime(), deadline);
    } while (peer < 0);

    /* Make the active curl poll readable, but let runtime teardown consume the
     * event. Its freeing path must detach libcurl's socketp before uv_close(). */
    static const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    CHECK_EQ(write(peer, response, sizeof(response) - 1), (ssize_t)(sizeof(response) - 1));
    close(listener);

    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, url);
    JS_FreeValue(ctx, curl);
    JS_FreeValue(ctx, curl_constructor);
    JS_FreeValue(ctx, pool_constructor);
    JS_FreeValue(ctx, pool);
    JS_FreeValue(ctx, module);
    TJS_FreeRuntime(runtime);
    close(peer);
}
#endif

static void test_socket_cleanup_reentry(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = TJS_GetMainContext(runtime);
    JSValue module = JS_NewObject(ctx);
    tjs__mod_socket_init(ctx, module);
    JSValue global = JS_GetGlobalObject(ctx);
    assert(JS_SetPropertyStr(ctx, global, "socket", module) >= 0);
    JS_FreeValue(ctx, global);

    /* The newer socket is first in the runtime list. Its callback is the
     * only owner of the older socket, so releasing it during teardown removes
     * the next list node synchronously. */
    eval(ctx,
         "(() => {"
         "  const peer = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);"
         "  const owner = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);"
         "  owner.bind({ ip: '127.0.0.1', port: 0 });"
         "  const callback = () => peer.fileno;"
         "  owner.poll(socket.READABLE, callback);"
         "})()");
    TJS_FreeRuntime(runtime);
}

static JSValue new_bound_socket(JSContext *ctx) {
    JSValue module = JS_NewObject(ctx);
    tjs__mod_socket_init(ctx, module);
    JSValue constructor = JS_GetPropertyStr(ctx, module, "Socket");
    JSValue arguments[] = {
        JS_GetPropertyStr(ctx, module, "AF_INET"),
        JS_GetPropertyStr(ctx, module, "SOCK_DGRAM"),
    };
    JSValue socket = JS_CallConstructor(ctx, constructor, countof(arguments), arguments);
    CHECK(!JS_IsException(socket));
    JS_FreeValue(ctx, constructor);
    JS_FreeValue(ctx, module);
    JSValue address = JS_NewObject(ctx);
    CHECK_GE(JS_SetPropertyStr(ctx, address, "ip", JS_NewString(ctx, "127.0.0.1")), 0);
    CHECK_GE(JS_SetPropertyStr(ctx, address, "port", JS_NewInt32(ctx, 0)), 0);
    JSValue result = call_method(ctx, socket, "bind", 1, &address);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, address);
    return socket;
}

typedef struct {
    TJSRuntime *runtime;
    JSContext *ctx;
    JSValue socket;
    JSValue replacement;
    unsigned releases;
    unsigned calls;
    unsigned replacement_calls;
    bool restart;
    bool replacing;
    bool nested_threw;
    bool inside_callback;
    bool cleanup;
#ifndef _WIN32
    int socket_fd;
    int witness_fd;
#endif
} SocketReentryProbe;

static JSValue socket_replacement_callback(JSContext *ctx, JSValueConst self,
                                           int argc, JSValueConst *argv,
                                           int magic, void *opaque) {
    SocketReentryProbe *probe = opaque;
    CHECK(!probe->inside_callback);
    probe->replacement_calls++;
    return JS_UNDEFINED;
}

static JSValue unused_socket_callback(JSContext *ctx, JSValueConst self,
                                      int argc, JSValueConst *argv,
                                      int magic, void *opaque) {
    CHECK(false);
    return JS_UNDEFINED;
}

static void reenter_socket_ref_release(void *opaque) {
    SocketReentryProbe *probe = opaque;
    CHECK_EQ(++probe->releases, 1);
    JSValue arguments[] = { JS_NewInt32(probe->ctx, UV_WRITABLE), probe->replacement };
    JSValue result = probe->restart
        ? call_method(probe->ctx, probe->socket, "poll", countof(arguments), arguments)
        : call_method(probe->ctx, probe->socket, "close", 0, NULL);
    probe->nested_threw = JS_IsException(result);
    if (probe->nested_threw)
        JS_FreeValue(probe->ctx, JS_GetException(probe->ctx));
    JS_FreeValue(probe->ctx, result);
    if (!probe->restart) {
#ifndef _WIN32
        /* Reuse the socket's slot after the nested close. The outer close must
         * not close it again when this callback finalizer returns. */
        CHECK_EQ(dup2(probe->witness_fd, probe->socket_fd), probe->socket_fd);
#endif
        uv_run(&probe->runtime->loop, UV_RUN_NOWAIT);
    }
}

static void test_socket_ref_release_reentry(bool restart, bool replacing) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    SocketReentryProbe probe = {
        .runtime = runtime,
        .ctx = ctx,
        .socket = new_bound_socket(ctx),
        .restart = restart,
        .replacing = replacing,
    };
    probe.replacement = JS_NewCClosure(ctx, socket_replacement_callback, NULL,
                                      NULL, 2, 0, &probe);
    CHECK(!JS_IsException(probe.replacement));
    JSValue arguments[] = {
        JS_NewInt32(ctx, UV_READABLE),
        JS_NewCClosure(ctx, unused_socket_callback, NULL,
                        reenter_socket_ref_release, 2, 0, &probe),
    };
    CHECK(!JS_IsException(arguments[1]));
    JSValue result = call_method(ctx, probe.socket, "poll", countof(arguments), arguments);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, arguments[1]);
#ifndef _WIN32
    if (!restart) {
        JSValue fd = JS_GetPropertyStr(ctx, probe.socket, "fileno");
        CHECK_EQ(JS_ToInt32(ctx, &probe.socket_fd, fd), 0);
        JS_FreeValue(ctx, fd);
        probe.witness_fd = open("/dev/null", O_RDONLY);
        CHECK_GE(probe.witness_fd, 0);
    }
#endif
    if (replacing) {
        arguments[0] = JS_NewInt32(ctx, UV_WRITABLE);
        arguments[1] = probe.replacement;
        result = call_method(ctx, probe.socket, "poll", countof(arguments), arguments);
    } else {
        result = call_method(ctx, probe.socket, restart ? "stopPoll" : "close", 0, NULL);
    }
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    CHECK_EQ(probe.releases, 1);
    CHECK_EQ(probe.nested_threw, !restart && !replacing);
    if (restart) {
        uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
        do {
            uv_run(&runtime->loop, UV_RUN_NOWAIT);
            CHECK_LT(uv_hrtime(), deadline);
        } while (probe.replacement_calls == 0);
        result = call_method(ctx, probe.socket, "close", 0, NULL);
        CHECK(!JS_IsException(result));
        JS_FreeValue(ctx, result);
    }
#ifndef _WIN32
    else {
        CHECK_GE(fcntl(probe.socket_fd, F_GETFD), 0);
        CHECK_EQ(close(probe.socket_fd), 0);
        CHECK_EQ(close(probe.witness_fd), 0);
    }
#endif
    JS_FreeValue(ctx, probe.replacement);
    JS_FreeValue(ctx, probe.socket);
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    do {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        CHECK_LT(uv_hrtime(), deadline);
    } while (!list_empty(&runtime->sockets));
    TJS_FreeRuntime(runtime);
}

static void release_running_socket_callback(void *opaque) {
    SocketReentryProbe *probe = opaque;
    CHECK(!probe->inside_callback);
    CHECK_EQ(++probe->releases, 1);
}

static JSValue reenter_socket_poll_callback(JSContext *ctx, JSValueConst self,
                                           int argc, JSValueConst *argv,
                                           int magic, void *opaque) {
    SocketReentryProbe *probe = opaque;
    CHECK_EQ(++probe->calls, 1);
    probe->inside_callback = true;
    if (probe->cleanup) {
        /* No external wrapper ref: cleanup drops the callback and self-root,
         * then a nested pump completes the native poll close. */
        tjs__mod_socket_cleanup_runtime(probe->runtime);
        CHECK(list_empty(&probe->runtime->sockets));
    } else {
        JSValue arguments[] = { JS_NewInt32(ctx, UV_WRITABLE), probe->replacement };
        JSValue result = call_method(ctx, self, "poll", countof(arguments), arguments);
        CHECK(!JS_IsException(result));
        JS_FreeValue(ctx, result);
    }
    CHECK_EQ(probe->releases, 0);
    uv_run(&probe->runtime->loop, UV_RUN_NOWAIT);
    CHECK_EQ(probe->replacement_calls, 0);
    if (!probe->cleanup) {
        JSValue result = call_method(ctx, self, "close", 0, NULL);
        CHECK(JS_IsException(result));
        JS_FreeValue(ctx, JS_GetException(ctx));
        JS_FreeValue(ctx, result);
    }
    probe->inside_callback = false;
    return JS_UNDEFINED;
}

static void test_socket_poll_callback_reentry(bool cleanup) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue socket = new_bound_socket(ctx);
    SocketReentryProbe probe = { .runtime = runtime, .ctx = ctx, .cleanup = cleanup };
    probe.replacement = JS_NewCClosure(ctx, socket_replacement_callback, NULL,
                                      NULL, 2, 0, &probe);
    CHECK(!JS_IsException(probe.replacement));
    JSValue arguments[] = {
        JS_NewInt32(ctx, UV_WRITABLE),
        JS_NewCClosure(ctx, reenter_socket_poll_callback, NULL,
                        release_running_socket_callback, 2, 0, &probe),
    };
    CHECK(!JS_IsException(arguments[1]));
    JSValue result = call_method(ctx, socket, "poll", countof(arguments), arguments);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, arguments[1]);
    JS_FreeValue(ctx, socket);
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    do {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        CHECK_LT(uv_hrtime(), deadline);
    } while (probe.calls == 0);
    CHECK_EQ(probe.releases, 1);
    if (!cleanup) {
        /* The native self-root is now the wrapper's only owner. */
        tjs__mod_socket_cleanup_runtime(runtime);
    }
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    CHECK(list_empty(&runtime->sockets));
    JS_FreeValue(ctx, probe.replacement);
    TJS_FreeRuntime(runtime);
}

static void test_udp_cleanup_reentry(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = TJS_GetMainContext(runtime);
    JSValue module = JS_NewObject(ctx);
    tjs__mod_udp_init(ctx, module);
    JSValue global = JS_GetGlobalObject(ctx);
    assert(JS_SetPropertyStr(ctx, global, "udp", module) >= 0);
    JS_FreeValue(ctx, global);

    /* A pending receive buffer keeps the already-closed successor alive.
     * Freeing that buffer in cleanup must not invalidate iteration. */
    eval(ctx,
         "(() => {"
         "  const peer = new udp.UDP();"
         "  peer.close();"
         "  const owner = new udp.UDP();"
         "  const buffer = new Uint8Array(1);"
         "  buffer.peer = peer;"
         "  globalThis.udpOwner = owner;"
         "  owner.recv(buffer);"
         "})()");
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    TJS_FreeRuntime(runtime);
}

static void test_immediate_context_cancellation(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);

    JSContext *main_ctx = TJS_GetMainContext(runtime);
    JSValue main_timers = JS_NewObject(main_ctx);
    tjs__mod_timers_init(main_ctx, main_timers);
    JSValue main_global = JS_GetGlobalObject(main_ctx);
    assert(JS_SetPropertyStr(main_ctx, main_global, "timers", main_timers) >= 0);
    JS_FreeValue(main_ctx, main_global);
    eval(main_ctx,
         "globalThis.mainImmediateCalls = 0;"
         "timers.setImmediate(() => mainImmediateCalls++)");

    App *sandbox = TJS_NewAppInternal(runtime, true);
    assert(sandbox != NULL);
    JSContext *sandbox_ctx = sandbox->ctx;
    JS_AddIntrinsicBaseObjects(sandbox_ctx);
    JS_AddIntrinsicEval(sandbox_ctx);
    JSValue sandbox_timers = JS_NewObject(sandbox_ctx);
    tjs__mod_timers_init(sandbox_ctx, sandbox_timers);
    JSValue sandbox_global = JS_GetGlobalObject(sandbox_ctx);
    assert(JS_SetPropertyStr(sandbox_ctx, sandbox_global, "timers", sandbox_timers) >= 0);
    JS_FreeValue(sandbox_ctx, sandbox_global);
    eval(sandbox_ctx,
         "globalThis.sandboxImmediateCalls = 0;"
         "timers.setImmediate(() => sandboxImmediateCalls++)");

    tjs__cancel_timers_for_context(runtime, sandbox_ctx);
    uv_run(&runtime->loop, UV_RUN_NOWAIT);

    const char *main_expr = "mainImmediateCalls";
    JSValue main_calls = JS_Eval(main_ctx, main_expr, strlen(main_expr),
                                 "<timer-context-test>", JS_EVAL_TYPE_GLOBAL);
    assert(!JS_IsException(main_calls));
    int32_t main_count;
    assert(JS_ToInt32(main_ctx, &main_count, main_calls) == 0);
    assert(main_count == 1);
    JS_FreeValue(main_ctx, main_calls);

    const char *sandbox_expr = "sandboxImmediateCalls";
    JSValue sandbox_calls = JS_Eval(sandbox_ctx, sandbox_expr, strlen(sandbox_expr),
                                    "<timer-context-test>", JS_EVAL_TYPE_GLOBAL);
    assert(!JS_IsException(sandbox_calls));
    int32_t sandbox_count;
    assert(JS_ToInt32(sandbox_ctx, &sandbox_count, sandbox_calls) == 0);
    assert(sandbox_count == 0);
    JS_FreeValue(sandbox_ctx, sandbox_calls);

    TJS_FreeRuntime(runtime);
}

static void test_immediate_loop_wakeup(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue timers = JS_NewObject(ctx);
    tjs__mod_timers_init(ctx, timers);
    JSValue global = JS_GetGlobalObject(ctx);
    CHECK(JS_SetPropertyStr(ctx, global, "timers", timers) >= 0);
    JS_FreeValue(ctx, global);
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    uv_unref((uv_handle_t *)&runtime->stop);

    eval(ctx, "globalThis.immediateCalls = 0;"
              "timers.setImmediate(() => immediateCalls++)");
    CHECK_EQ(uv_backend_timeout(&runtime->loop), 0);
    CHECK_EQ(uv_run(&runtime->loop, UV_RUN_DEFAULT), 0);
    eval(ctx, "if (immediateCalls !== 1) throw new Error('immediate did not run')");

    eval(ctx, "globalThis.unreferencedImmediate = timers.setImmediate(() => immediateCalls++);"
              "timers.unrefImmediate(unreferencedImmediate)");
    CHECK_EQ(uv_loop_alive(&runtime->loop), 0);
    CHECK_EQ(uv_run(&runtime->loop, UV_RUN_DEFAULT), 0);
    eval(ctx, "if (immediateCalls !== 1) throw new Error('unref immediate kept loop alive');"
              "timers.clearImmediate(unreferencedImmediate)");
    TJS_FreeRuntime(runtime);
}

static void test_timer_type_isolation(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue timers = JS_NewObject(ctx);
    tjs__mod_timers_init(ctx, timers);
    JSValue global = JS_GetGlobalObject(ctx);
    CHECK(JS_SetPropertyStr(ctx, global, "timers", timers) >= 0);
    JS_FreeValue(ctx, global);

    eval(ctx,
         "globalThis.immediateCalls = 0;"
         "globalThis.immediateId = timers.setImmediate(() => immediateCalls++);"
         "timers.clearTimeout(immediateId);"
         "(() => {"
         "  try { timers.refTimer(immediateId); throw new Error('wrong ref accepted'); }"
         "  catch (error) { if (error.message === 'wrong ref accepted') throw error; }"
         "})();");
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    eval(ctx, "if (immediateCalls !== 1) throw new Error('wrong clear canceled immediate')");

    eval(ctx,
         "globalThis.timeoutCalls = 0;"
         "globalThis.timeoutId = timers.setTimeout(() => timeoutCalls++, 0);"
         "timers.clearImmediate(timeoutId);"
         "(() => {"
         "  try { timers.hasRefImmediate(timeoutId); throw new Error('wrong ref accepted'); }"
         "  catch (error) { if (error.message === 'wrong ref accepted') throw error; }"
         "})();");
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    eval(ctx, "if (timeoutCalls !== 1) throw new Error('wrong clear canceled timeout')");

    TJS_FreeRuntime(runtime);
}

typedef struct {
    TJSRuntime *runtime;
    bool pump_first;
    unsigned releases;
} TimerCleanupProbe;

static JSValue unused_timer_callback(JSContext *ctx, JSValueConst self, int argc,
                                     JSValueConst *argv, int magic, void *opaque) {
    CHECK(false);
    return JS_UNDEFINED;
}

static void reenter_timer_cleanup(void *opaque) {
    TimerCleanupProbe *probe = opaque;
    probe->releases++;
    if (probe->pump_first)
        uv_run(&probe->runtime->loop, UV_RUN_NOWAIT);
    tjs__destroy_timers(probe->runtime);
    uv_run(&probe->runtime->loop, UV_RUN_NOWAIT);
}

static void test_timer_cleanup_reentry(bool freeing_runtime, bool pump_first) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue timers = JS_NewObject(ctx);
    tjs__mod_timers_init(ctx, timers);
    JSValue schedule = JS_GetPropertyStr(ctx, timers, "setTimeout");
    CHECK(JS_IsFunction(ctx, schedule));
    TimerCleanupProbe probe = { .runtime = runtime, .pump_first = pump_first };
    for (unsigned index = 0; index < 2; index++) {
        JSValue arguments[] = {
            JS_NewCClosure(ctx, unused_timer_callback, "timer_cleanup",
                            reenter_timer_cleanup, 0, 0, &probe),
            JS_NewInt32(ctx, pump_first && index == 1 ? 0 : 60000),
        };
        CHECK(!JS_IsException(arguments[0]));
        JSValue timer = JS_Call(ctx, schedule, timers, 2, arguments);
        CHECK(!JS_IsException(timer));
        JS_FreeValue(ctx, timer);
        JS_FreeValue(ctx, arguments[0]);
    }
    JS_FreeValue(ctx, schedule);
    JS_FreeValue(ctx, timers);
    int previous_jobs = jobs_run;
    if (freeing_runtime)
        CHECK_EQ(JS_EnqueueJob(ctx, teardown_job, 0, NULL), 0);
    if (freeing_runtime)
        TJS_FreeRuntime(runtime);
    else {
        tjs__cancel_timers_for_context(runtime, ctx);
        CHECK(runtime->timers.timers == NULL);
        TJS_FreeRuntime(runtime);
    }
    CHECK_EQ(probe.releases, 2);
    if (freeing_runtime)
        CHECK_EQ(jobs_run, previous_jobs);
}

typedef struct {
    TJSRuntime *runtime;
    JSValue clear;
    JSValue timer;
    bool immediate;
    unsigned calls;
} TimerCallbackProbe;

static JSValue reenter_timer_loop(JSContext *ctx, JSValueConst self, int argc,
                                  JSValueConst *argv, int magic, void *opaque) {
    TimerCallbackProbe *probe = opaque;
    probe->calls++;
    CHECK_EQ(probe->calls, 1);
    if (probe->immediate) {
        CHECK_EQ(probe->runtime->timers.pending_immediates, 0);
        CHECK_EQ(uv_is_active((uv_handle_t *)&probe->runtime->jobs.idle), 0);
    }
    if (!JS_IsUndefined(probe->clear)) {
        JSValue result = JS_Call(ctx, probe->clear, JS_UNDEFINED, 1, &probe->timer);
        CHECK(!JS_IsException(result));
        JS_FreeValue(ctx, result);
    }
    uv_run(&probe->runtime->loop, UV_RUN_NOWAIT);
    return JS_UNDEFINED;
}

static void test_timer_callback_reentry(bool immediate, bool clear_timer) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue timers = JS_NewObject(ctx);
    tjs__mod_timers_init(ctx, timers);
    JSValue schedule = JS_GetPropertyStr(ctx, timers, immediate ? "setImmediate" : "setTimeout");
    TimerCallbackProbe probe = {
        .runtime = runtime,
        .immediate = immediate,
        .clear = clear_timer
            ? JS_GetPropertyStr(ctx, timers,
                                immediate ? "clearImmediate" : "clearTimeout")
            : JS_UNDEFINED,
    };
    JSValue arguments[] = {
        JS_NewCClosure(ctx, reenter_timer_loop, "timer_loop", NULL, 0, 0, &probe),
        JS_NewInt32(ctx, 0),
    };
    CHECK(!JS_IsException(arguments[0]));
    probe.timer = JS_Call(ctx, schedule, timers, immediate ? 1 : 2, arguments);
    CHECK(!JS_IsException(probe.timer));
    JS_FreeValue(ctx, arguments[0]);
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    CHECK_EQ(probe.calls, 1);
    CHECK(runtime->timers.timers == NULL);
    JS_FreeValue(ctx, probe.timer);
    JS_FreeValue(ctx, probe.clear);
    JS_FreeValue(ctx, schedule);
    JS_FreeValue(ctx, timers);
    TJS_FreeRuntime(runtime);
}

int main(void) {
    TJSRuntime *stopped = TJS_NewRuntime();
    assert(stopped != NULL);
    TJS_Stop(stopped);
    assert(TJS_Run(stopped) != 0);
    assert(stopped->unload_dispatched);
    TJS_FreeRuntime(stopped);

    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);

    JSContext *ctx = TJS_GetMainContext(runtime);
    assert(ctx != NULL);
    assert(JS_EnqueueJob(ctx, teardown_job, 0, NULL) == 0);

    /* Runtime teardown must release queued job arguments without executing
     * user code after native handles have already been closed. */
    TJS_FreeRuntime(runtime);
    assert(jobs_run == 0);
    test_socket_cleanup_reentry();
    test_socket_ref_release_reentry(false, false);
    test_socket_ref_release_reentry(true, false);
    test_socket_ref_release_reentry(false, true);
    test_socket_poll_callback_reentry(false);
    test_socket_poll_callback_reentry(true);
    test_udp_cleanup_reentry();
    test_udp_recv_promise_reentry();
    test_curl_completion_closes_pool();
#ifndef _WIN32
    test_curl_runtime_teardown_detaches_socket();
#endif
    test_immediate_context_cancellation();
    test_immediate_loop_wakeup();
    test_timer_type_isolation();
    test_timer_cleanup_reentry(false, false);
    test_timer_cleanup_reentry(true, false);
    test_timer_cleanup_reentry(true, true);
    test_timer_callback_reentry(false, true);
    test_timer_callback_reentry(true, false);
    test_timer_callback_reentry(true, true);
    return 0;
}
