#include "private.h"

#ifndef _WIN32
#include <unistd.h>
#else
#include <winsock2.h>
#endif

/* Keep the transport implementation private; cleanup-only endpoints need no
 * transfer channel and do not require the executable's attached JS core. */
struct TJSMessagePipeChannel;
extern JSValue tjs_new_msgpipe(JSContext *ctx, uv_os_sock_t fd,
                              struct TJSMessagePipeChannel *channel,
                              unsigned side);

static void count_pipe_handles(uv_handle_t *handle, void *opaque) {
    unsigned *count = opaque;
    if (handle->type == UV_NAMED_PIPE || handle->type == UV_TCP)
        (*count)++;
}

static JSValue new_closed_msgpipe(TJSRuntime *qrt) {
    uv_os_sock_t fds[2];
    CHECK_EQ(uv_socketpair(SOCK_STREAM, 0, fds,
                          UV_NONBLOCK_PIPE, UV_NONBLOCK_PIPE), 0);
    JSValue pipe = tjs_new_msgpipe(qrt->main_ctx, fds[0], NULL, 0);
    CHECK(!JS_IsException(pipe));
#ifndef _WIN32
    CHECK_EQ(close(fds[1]), 0);
#else
    CHECK_EQ(closesocket(fds[1]), 0);
#endif
    /* Complete the actual MessagePipe EOF/close callbacks while its JS
     * wrapper remains alive. Its later finalizer can then free it inline. */
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    for (;;) {
        uv_run(&qrt->loop, UV_RUN_NOWAIT);
        unsigned remaining = 0;
        uv_walk(&qrt->loop, count_pipe_handles, &remaining);
        if (remaining == 0) break;
        CHECK_LT(uv_hrtime(), deadline);
    }
    return pipe;
}

static TJSRuntime *new_runtime_with_worker_module(void) {
    TJSRuntime *qrt = TJS_NewRuntime();
    CHECK(qrt);
    JSContext *ctx = qrt->main_ctx;
    JSValue ns = JS_NewObject(ctx);
    CHECK(!JS_IsException(ns));
    tjs__mod_worker_init(ctx, ns);
    CHECK(!JS_HasException(ctx));
    tjs__mod_worker_init(ctx, ns);
    CHECK(!JS_HasException(ctx));
    JS_FreeValue(ctx, ns);
    return qrt;
}

static JSValue unused_handler(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv, int magic,
                              JSValueConst *data) {
    CHECK(false); /* Runtime cleanup must release, never invoke, handlers. */
    return JS_UNDEFINED;
}

static void check_cleanup_captured_pipes(void) {
    TJSRuntime *qrt = new_runtime_with_worker_module();
    JSContext *ctx = qrt->main_ctx;
    /* Retain the intentional self-cycle until close_all breaks it. */
    JS_SetGCThreshold(qrt->rt, SIZE_MAX);
    JSValue owner = new_closed_msgpipe(qrt);
    JSValue successor = new_closed_msgpipe(qrt);
    JSValue captures[] = { owner, successor };
    JSValue handler = JS_NewCFunctionData(ctx, unused_handler, 0, 0,
                                          2, captures);
    CHECK(!JS_IsException(handler));
    CHECK_GE(JS_SetPropertyStr(ctx, owner, "onmessage", handler), 0);
    JS_FreeValue(ctx, owner);
    JS_FreeValue(ctx, successor);
    /* Releasing the first handler removes both the current pipe and the
     * cached successor. The old list_for_each_safe loop used freed nodes. */
    tjs__close_all_msgpipes(qrt);
    CHECK(list_empty(&qrt->msgpipes));
    tjs__close_all_msgpipes(qrt);
    TJS_FreeRuntime(qrt);
}

typedef struct {
    TJSRuntime *qrt;
    unsigned calls;
} CleanupReentry;

static JSValue unused_closure(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv, int magic, void *opaque) {
    CHECK(false);
    return JS_UNDEFINED;
}

static void reenter_cleanup(void *opaque) {
    CleanupReentry *state = opaque;
    state->calls++;
    tjs__close_all_msgpipes(state->qrt);
}

static void check_cleanup_reentry(bool from_finalizer) {
    TJSRuntime *qrt = new_runtime_with_worker_module();
    JSContext *ctx = qrt->main_ctx;
    JSValue owner = new_closed_msgpipe(qrt);
    JSValue successor = new_closed_msgpipe(qrt);
    CleanupReentry state = { .qrt = qrt };
    JSValue handler = JS_NewCClosure(ctx, unused_closure, "cleanup_reentry",
                                     reenter_cleanup, 0, 0, &state);
    CHECK(!JS_IsException(handler));
    CHECK_GE(JS_SetPropertyStr(ctx, owner, "onmessage", handler), 0);
    if (from_finalizer)
        JS_FreeValue(ctx, owner);
    else {
        tjs__close_all_msgpipes(qrt);
        JS_FreeValue(ctx, owner);
    }
    CHECK_EQ(state.calls, 1);
    CHECK(list_empty(&qrt->msgpipes));
    JS_FreeValue(ctx, successor);
    tjs__close_all_msgpipes(qrt);
    TJS_FreeRuntime(qrt);
}

static void check_worker_module_init(void) {
    TJSRuntime *runtime = TJS_NewRuntimeWorker();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = JS_NewObject(ctx);
    CHECK(!JS_IsException(ns));
    tjs__mod_worker_init(ctx, ns);
    CHECK(!JS_HasException(ctx));
    JSValue worker = JS_GetPropertyStr(ctx, ns, "Worker");
    CHECK(JS_IsFunction(ctx, worker));
    JS_FreeValue(ctx, worker);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
}

static void check_worker_class_ids_are_process_wide(void) {
    TJSRuntime *first = new_runtime_with_worker_module();
    CHECK(first);
    JSValue first_pipe = new_closed_msgpipe(first);

    TJSRuntime *second = TJS_NewRuntime();
    CHECK(second);
    JSContext *ctx = second->main_ctx;
    JSValue streams_ns = JS_NewObject(ctx);
    CHECK(!JS_IsException(streams_ns));
    tjs__mod_streams_init(ctx, streams_ns);
    CHECK(!JS_HasException(ctx));
    JS_FreeValue(ctx, streams_ns);

    JSValue worker_ns = JS_NewObject(ctx);
    CHECK(!JS_IsException(worker_ns));
    tjs__mod_worker_init(ctx, worker_ns);
    CHECK(!JS_HasException(ctx));
    JSValue pipe = new_closed_msgpipe(second);
    CHECK(!JS_IsException(pipe));
    CHECK_EQ(JS_GetClassID(first_pipe), JS_GetClassID(pipe));
    JSAtom class_name = JS_GetClassName(second->rt, JS_GetClassID(pipe));
    const char *class_name_str = JS_AtomToCString(ctx, class_name);
    CHECK(class_name_str);
    CHECK_EQ(strcmp(class_name_str, "MessagePipe"), 0);
    JS_FreeCString(ctx, class_name_str);
    JS_FreeAtom(ctx, class_name);

    /* Interleave two live runtimes whose module initialization order differs.
     * Access and finalization must retain the same process-wide class IDs. */
    JSValue first_ref = JS_GetPropertyStr(first->main_ctx, first_pipe, "ref");
    JSValue result = JS_Call(first->main_ctx, first_ref, first_pipe, 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(first->main_ctx, result);
    JS_FreeValue(first->main_ctx, first_ref);
    JSValue first_later_pipe = new_closed_msgpipe(first);
    JS_FreeValue(first->main_ctx, first_later_pipe);
    JS_FreeValue(first->main_ctx, first_pipe);
    CHECK(list_empty(&first->msgpipes));
    TJS_FreeRuntime(first);

    JS_FreeValue(ctx, pipe);
    CHECK(list_empty(&second->msgpipes));
    JS_FreeValue(ctx, worker_ns);
    TJS_FreeRuntime(second);
}

int main(void) {
    check_worker_module_init();
    check_worker_class_ids_are_process_wide();
    check_cleanup_captured_pipes();
    check_cleanup_reentry(false);
    check_cleanup_reentry(true);
    return 0;
}
