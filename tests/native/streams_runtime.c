#include "private.h"

#ifndef _WIN32
#include <unistd.h>
#else
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

typedef struct {
    TJSRuntime *runtime;
    unsigned released;
    bool reenter;
} CleanupProbe;

static JSValue unused_handler(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv, int magic,
                              JSValueConst *data) {
    CHECK(false); /* Teardown must release handlers without invoking them. */
    return JS_UNDEFINED;
}

static JSValue unused_closure(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv, int magic, void *opaque) {
    CHECK(false);
    return JS_UNDEFINED;
}

static void release_probe(void *opaque) {
    CleanupProbe *probe = opaque;
    probe->released++;
    if (probe->reenter)
        tjs__close_all_streams(probe->runtime);
}

static void count_pipe_handles(uv_handle_t *handle, void *opaque) {
    unsigned *count = opaque;
    if (handle->type == UV_NAMED_PIPE)
        (*count)++;
}

static unsigned count_streams(TJSRuntime *runtime) {
    unsigned count = 0;
    struct list_head *p;
    list_for_each(p, &runtime->streams)
        count++;
    return count;
}

static void init_streams_module(JSContext *ctx) {
    JSValue streams = JS_NewObject(ctx);
    CHECK(!JS_IsException(streams));
    tjs__mod_streams_init(ctx, streams);
    JS_FreeValue(ctx, streams);
    CHECK(!JS_HasException(ctx));
}

#ifndef _WIN32
typedef struct {
    JSContext *ctx;
    JSValue stream;
    JSValue read_fn;
    JSValue close_fn;
    JSValue first_promise;
    JSValue replacement_promise;
    bool replacement_started;
    bool close_called;
} ReadReentry;

static JSValue mark_read_stream_closed(JSContext *ctx, JSValueConst this_val,
                                       int argc, JSValueConst *argv,
                                       int magic, void *opaque) {
    (void)this_val;
    (void)argc;
    (void)argv;
    (void)magic;
    *(bool *)opaque = true;
    return JS_UNDEFINED;
}

static void read_reentry_promise_hook(JSContext *ctx, JSPromiseHookType type,
                                      JSValueConst promise,
                                      JSValueConst parent_promise, void *opaque) {
    (void)parent_promise;
    ReadReentry *state = opaque;
    if (type != JS_PROMISE_HOOK_RESOLVE || state->replacement_started ||
        !JS_IsSameValue(ctx, promise, state->first_promise))
        return;

    state->replacement_started = true;
    uint8_t zeroes[8] = { 0 };
    JSValue buffer = JS_NewUint8ArrayCopy(ctx, zeroes, sizeof(zeroes));
    CHECK(!JS_IsException(buffer));
    state->replacement_promise = JS_Call(ctx, state->read_fn, state->stream,
                                         1, (JSValueConst[]) { buffer });
    JS_FreeValue(ctx, buffer);
    CHECK(!JS_IsException(state->replacement_promise));

    /* Close while the original read's settlement hook is still on the stack.
     * The replacement read must remain accounted for until uv__close_cb sees
     * it; the old completion must not clear its ownership flag afterwards. */
    JSValue closed = JS_Call(ctx, state->close_fn, state->stream, 0, NULL);
    CHECK(!JS_IsException(closed));
    JS_FreeValue(ctx, closed);
}

static void test_read_replacement_close_reentry(void) {
    TJSRuntime *runtime = TJS_NewRuntimeWorker();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    init_streams_module(ctx);
    int fds[2];
    CHECK_EQ(pipe(fds), 0);

    JSValue stream = tjs_new_pipe(ctx);
    CHECK(!JS_IsException(stream));
    uv_pipe_t *pipe_handle = tjs_pipe_get_pipe(ctx, stream);
    CHECK(pipe_handle);
    CHECK_EQ(uv_pipe_open(pipe_handle, fds[0]), 0);

    ReadReentry state = {
        .ctx = ctx,
        .stream = JS_DupValue(ctx, stream),
        .read_fn = JS_GetPropertyStr(ctx, stream, "read"),
        .close_fn = JS_GetPropertyStr(ctx, stream, "close"),
        .first_promise = JS_UNDEFINED,
        .replacement_promise = JS_UNDEFINED,
    };
    CHECK(!JS_IsException(state.read_fn));
    CHECK(!JS_IsException(state.close_fn));
    JSValue onclose = JS_NewCClosure(ctx, mark_read_stream_closed,
                                     "read_reentry_closed", NULL, 0, 0,
                                     &state.close_called);
    CHECK(!JS_IsException(onclose));
    CHECK_GE(JS_SetPropertyStr(ctx, stream, "onclose", onclose), 0);
    JS_SetPromiseHook(runtime->rt, read_reentry_promise_hook, &state);

    uint8_t first_bytes[8] = { 0 };
    JSValue first_buffer = JS_NewUint8ArrayCopy(ctx, first_bytes,
                                                sizeof(first_bytes));
    CHECK(!JS_IsException(first_buffer));
    JSValue first = JS_Call(ctx, state.read_fn, stream, 1,
                            (JSValueConst[]) { first_buffer });
    JS_FreeValue(ctx, first_buffer);
    CHECK(!JS_IsException(first));
    state.first_promise = JS_DupValue(ctx, first);

    CHECK_EQ(write(fds[1], "A", 1), 1);
    close(fds[1]);
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    while (!state.close_called) {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        CHECK_LT(uv_hrtime(), deadline);
    }
    CHECK(state.replacement_started);
    CHECK(JS_IsUndefined(state.replacement_promise) == false);

    JS_SetPromiseHook(runtime->rt, NULL, NULL);
    JS_FreeValue(ctx, first);
    JS_FreeValue(ctx, state.replacement_promise);
    JS_FreeValue(ctx, state.first_promise);
    JS_FreeValue(ctx, state.read_fn);
    JS_FreeValue(ctx, state.close_fn);
    JS_FreeValue(ctx, state.stream);
    JS_FreeValue(ctx, stream);
    JS_RunGC(runtime->rt);
    CHECK(list_empty(&runtime->streams));
    TJS_FreeRuntime(runtime);
}
#endif

#ifdef _WIN32
static JSValue ignore_read_rejection(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    (void)ctx;
    (void)this_val;
    (void)argc;
    (void)argv;
    return JS_UNDEFINED;
}

static void ignore_promise_rejection(JSContext *ctx, JSValueConst promise) {
    JSValue catcher = JS_GetPropertyStr(ctx, promise, "catch");
    JSValue handler = JS_NewCFunction(ctx, ignore_read_rejection,
                                      "ignoreReadRejection", 1);
    CHECK(JS_IsFunction(ctx, catcher));
    CHECK(!JS_IsException(handler));
    JSValue handled = JS_Call(ctx, catcher, promise, 1,
                              (JSValueConst[]) { handler });
    CHECK(!JS_IsException(handled));
    JS_FreeValue(ctx, handled);
    JS_FreeValue(ctx, handler);
    JS_FreeValue(ctx, catcher);
}

static JSValue call_stream_method(JSContext *ctx, JSValueConst stream,
                                 const char *name, int argc,
                                 JSValueConst *argv) {
    JSValue method = JS_GetPropertyStr(ctx, stream, name);
    CHECK(JS_IsFunction(ctx, method));
    JSValue result = JS_Call(ctx, method, stream, argc, argv);
    JS_FreeValue(ctx, method);
    return result;
}

static bool write_console_line(int fd, wchar_t character) {
    HANDLE input = (HANDLE)_get_osfhandle(fd);
    if (input == INVALID_HANDLE_VALUE)
        return false;

    INPUT_RECORD records[2] = { 0 };
    records[0].EventType = KEY_EVENT;
    records[0].Event.KeyEvent.bKeyDown = TRUE;
    records[0].Event.KeyEvent.wRepeatCount = 1;
    records[0].Event.KeyEvent.wVirtualKeyCode =
        LOBYTE(VkKeyScanW(character));
    records[0].Event.KeyEvent.wVirtualScanCode =
        (WORD)MapVirtualKeyW(records[0].Event.KeyEvent.wVirtualKeyCode,
                             MAPVK_VK_TO_VSC);
    records[0].Event.KeyEvent.uChar.UnicodeChar = character;

    records[1] = records[0];
    records[1].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
    records[1].Event.KeyEvent.wVirtualScanCode =
        (WORD)MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC);
    records[1].Event.KeyEvent.uChar.UnicodeChar = L'\r';

    DWORD written = 0;
    return WriteConsoleInputW(input, records, 2, &written) && written == 2;
}

static void pump_for(TJSRuntime *runtime, uint64_t milliseconds) {
    uint64_t deadline = uv_hrtime() + milliseconds * UINT64_C(1000000);
    do {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    } while (uv_hrtime() < deadline);
}

static void pump_until_promise(TJSRuntime *runtime, JSContext *ctx,
                               JSValueConst promise,
                               JSPromiseStateEnum state) {
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    while (JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING) {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        CHECK_LT(uv_hrtime(), deadline);
    }
    CHECK_EQ(JS_PromiseState(ctx, promise), state);
}

static void test_windows_tty_read_cancel_runtime_close(void) {
    TJSRuntime *runtime = TJS_NewRuntimeWorker();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;

    /* Windows CI runners without an attached console cannot exercise libuv's
     * ReadConsole worker; keep the native test runnable in that environment. */
    int fd = _open("CONIN$", _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        TJS_FreeRuntime(runtime);
        return;
    }
    HANDLE input = (HANDLE)_get_osfhandle(fd);
    DWORD console_mode;
    if (input == INVALID_HANDLE_VALUE ||
        !GetConsoleMode(input, &console_mode) ||
        !FlushConsoleInputBuffer(input)) {
        TJS_FreeRuntime(runtime);
        return;
    }

    JSValue streams = JS_NewObject(ctx);
    CHECK(!JS_IsException(streams));
    tjs__mod_streams_init(ctx, streams);
    CHECK(!JS_HasException(ctx));
    JSValue tty_ctor = JS_GetPropertyStr(ctx, streams, "TTY");
    CHECK(JS_IsFunction(ctx, tty_ctor));
    JSValue tty = JS_CallConstructor(ctx, tty_ctor, 2,
                                     (JSValueConst[]) {
                                         JS_NewInt32(ctx, fd), JS_TRUE
                                     });
    JS_FreeValue(ctx, tty_ctor);
    JS_FreeValue(ctx, streams);
    if (JS_IsException(tty)) {
        JS_FreeValue(ctx, tty);
        _close(fd);
        TJS_FreeRuntime(runtime);
        return;
    }

    uint8_t bytes[8] = { 0 };
    JSValue buffer = JS_NewUint8ArrayCopy(ctx, bytes, sizeof(bytes));
    CHECK(!JS_IsException(buffer));
    JSValue read_promise = call_stream_method(
        ctx, tty, "read", 1, (JSValueConst[]) { buffer });
    JS_FreeValue(ctx, buffer);
    CHECK(!JS_IsException(read_promise));
    ignore_promise_rejection(ctx, read_promise);
    JSValue result = call_stream_method(ctx, tty, "cancelRead", 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    CHECK_EQ(JS_PromiseState(ctx, read_promise), JS_PROMISE_REJECTED);
    JS_FreeValue(ctx, read_promise);

    /* A canceled line-read worker remains the sole native owner. B is
     * deferred and must not receive A's completion bytes. */
    buffer = JS_NewUint8ArrayCopy(ctx, bytes, sizeof(bytes));
    CHECK(!JS_IsException(buffer));
    JSValue replacement_promise = call_stream_method(
        ctx, tty, "read", 1, (JSValueConst[]) { buffer });
    JSValue replacement_buffer = JS_DupValue(ctx, buffer);
    JS_FreeValue(ctx, buffer);
    CHECK(!JS_IsException(replacement_promise));
    CHECK_EQ(JS_PromiseState(ctx, replacement_promise), JS_PROMISE_PENDING);

    CHECK(write_console_line(fd, L'A'));
    pump_for(runtime, 250);
    CHECK_EQ(JS_PromiseState(ctx, replacement_promise), JS_PROMISE_PENDING);

    CHECK(write_console_line(fd, L'B'));
    pump_until_promise(runtime, ctx, replacement_promise,
                       JS_PROMISE_FULFILLED);
    JSValue bytes_read = JS_PromiseResult(ctx, replacement_promise);
    int32_t count;
    CHECK_EQ(JS_ToInt32(ctx, &count, bytes_read), 0);
    CHECK_EQ(count, 1);
    size_t replacement_size;
    uint8_t *replacement_data = JS_GetAnyBuffer(
        ctx, &replacement_size, replacement_buffer);
    CHECK(replacement_data);
    CHECK_GE(replacement_size, 1);
    CHECK_EQ(replacement_data[0], (uint8_t)'B');
    JS_FreeValue(ctx, bytes_read);
    JS_FreeValue(ctx, replacement_promise);
    JS_FreeValue(ctx, replacement_buffer);

    /* Exercise cancellation of a deferred B as well. The old C completion
     * must release C and make a later startRead possible, without ever
     * settling D. */
    buffer = JS_NewUint8ArrayCopy(ctx, bytes, sizeof(bytes));
    CHECK(!JS_IsException(buffer));
    read_promise = call_stream_method(
        ctx, tty, "read", 1, (JSValueConst[]) { buffer });
    JS_FreeValue(ctx, buffer);
    CHECK(!JS_IsException(read_promise));
    ignore_promise_rejection(ctx, read_promise);
    result = call_stream_method(ctx, tty, "cancelRead", 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, read_promise);

    buffer = JS_NewUint8ArrayCopy(ctx, bytes, sizeof(bytes));
    CHECK(!JS_IsException(buffer));
    replacement_promise = call_stream_method(
        ctx, tty, "read", 1, (JSValueConst[]) { buffer });
    JS_FreeValue(ctx, buffer);
    CHECK(!JS_IsException(replacement_promise));
    ignore_promise_rejection(ctx, replacement_promise);
    result = call_stream_method(ctx, tty, "cancelRead", 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    CHECK_EQ(JS_PromiseState(ctx, replacement_promise), JS_PROMISE_REJECTED);
    JS_FreeValue(ctx, replacement_promise);

    result = call_stream_method(ctx, tty, "startRead", 0, NULL);
    CHECK(JS_IsException(result));
    JS_FreeValue(ctx, JS_GetException(ctx));

    CHECK(write_console_line(fd, L'C'));
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    bool restarted = false;
    while (!restarted) {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        result = call_stream_method(ctx, tty, "startRead", 0, NULL);
        if (!JS_IsException(result)) {
            restarted = true;
            JS_FreeValue(ctx, result);
            break;
        }
        JS_FreeValue(ctx, JS_GetException(ctx));
        CHECK_LT(uv_hrtime(), deadline);
    }

    result = call_stream_method(ctx, tty, "stopRead", 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);

    /* Teardown closes the TTY and drains any worker before releasing the
     * stream-owned native buffer. */
    JS_FreeValue(ctx, tty);
    TJS_FreeRuntime(runtime);
}
#endif

static void check_cleanup_captured_streams(bool free_runtime, bool reenter) {
    TJSRuntime *runtime = TJS_NewRuntimeWorker();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    init_streams_module(ctx);
    /* Leave a live wrapper on each side of the pair being finalized. They
     * must both be closed and remain tracked until their finalizers run. */
    JSValue prefix = tjs_new_pipe(ctx);
    JSValue owner = tjs_new_pipe(ctx);
    JSValue successor = tjs_new_pipe(ctx);
    JSValue tail = tjs_new_pipe(ctx);
    CHECK(!JS_IsException(prefix));
    CHECK(!JS_IsException(owner));
    CHECK(!JS_IsException(successor));
    CHECK(!JS_IsException(tail));

    CleanupProbe probe = { .runtime = runtime, .reenter = reenter };
    JSValue handler = JS_NewCClosure(ctx, unused_closure, "cleanup_probe",
                                     release_probe, 0, 0, &probe);
    CHECK(!JS_IsException(handler));
    CHECK_GE(JS_SetPropertyStr(ctx, successor, "onclose", handler), 0);
    handler = JS_NewCFunctionData(ctx, unused_handler, 0, 0, 1, &successor);
    CHECK(!JS_IsException(handler));
    CHECK_GE(JS_SetPropertyStr(ctx, owner, "onclose", handler), 0);
    handler = JS_NewCFunctionData(ctx, unused_handler, 0, 0, 0, NULL);
    CHECK(!JS_IsException(handler));
    CHECK_GE(JS_SetPropertyStr(ctx, prefix, "onclose", JS_DupValue(ctx, handler)), 0);
    CHECK_GE(JS_SetPropertyStr(ctx, tail, "onclose", handler), 0);

    JSValue close = JS_GetPropertyStr(ctx, owner, "close");
    CHECK(JS_IsFunction(ctx, close));
    JSValue result = JS_Call(ctx, close, owner, 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, close);
    JS_FreeValue(ctx, owner);
    JS_FreeValue(ctx, successor);
    /* No loop pump: close() still owns the owner's only JS pin, and its
     * handler owns the successor's only reference. Unpinning the owner will
     * synchronously unlink both, invalidating list_for_each_safe's successor. */
    CHECK_EQ(probe.released, 0);
    CHECK_EQ(count_streams(runtime), 4);
    unsigned handles = 0;
    uv_walk(&runtime->loop, count_pipe_handles, &handles);
    CHECK_EQ(handles, 4);

    if (free_runtime) {
        JSValue global = JS_GetGlobalObject(ctx);
        CHECK_GE(JS_SetPropertyStr(ctx, global, "prefix", prefix), 0);
        CHECK_GE(JS_SetPropertyStr(ctx, global, "tail", tail), 0);
        JS_FreeValue(ctx, global);
        TJS_FreeRuntime(runtime);
        CHECK_EQ(probe.released, 1);
        return;
    }

    runtime->freeing = true;
    tjs__close_all_streams(runtime);
    CHECK_EQ(probe.released, 1);
    CHECK_EQ(count_streams(runtime), 2);
    CHECK(uv_is_closing((uv_handle_t *)tjs_pipe_get_pipe(ctx, prefix)));
    CHECK(uv_is_closing((uv_handle_t *)tjs_pipe_get_pipe(ctx, tail)));
    tjs__close_all_streams(runtime);

    /* Deliver the actual close callbacks, including the owner's callback
     * whose native reference outlives its JS wrapper. No onclose may run. */
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    do {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        handles = 0;
        uv_walk(&runtime->loop, count_pipe_handles, &handles);
        CHECK_LT(uv_hrtime(), deadline);
    } while (handles != 0);
    CHECK_EQ(probe.released, 1);
    CHECK_EQ(count_streams(runtime), 2);
    tjs__close_all_streams(runtime);
    JS_FreeValue(ctx, prefix);
    JS_FreeValue(ctx, tail);
    CHECK(list_empty(&runtime->streams));
    tjs__close_all_streams(runtime);
    TJS_FreeRuntime(runtime);
}

int main(void) {
#ifndef _WIN32
    test_read_replacement_close_reentry();
#else
    test_windows_tty_read_cancel_runtime_close();
#endif
    check_cleanup_captured_streams(false, false);
    check_cleanup_captured_streams(false, true);
    check_cleanup_captured_streams(true, false);
    check_cleanup_captured_streams(true, true);
    return 0;
}
