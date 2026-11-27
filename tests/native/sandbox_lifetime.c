#include "private.h"

/* Keep this standalone target meaningful in Release builds too. */
#undef assert
#define assert(expr) CHECK(expr)

static App *first_sandbox(TJSRuntime *runtime) {
    App *main_app = TJS_GetApp(runtime->main_ctx);
    struct list_head *entry;

    if (main_app->link.next == &main_app->link)
        return NULL;
    entry = main_app->link.next;
    return list_entry(entry, App, link);
}

int main(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime != NULL);
    JSContext *main_ctx = runtime->main_ctx;

    JSValue engine = JS_NewObject(main_ctx);
    JSValue streams = JS_NewObject(main_ctx);
    CHECK(!JS_IsException(engine));
    CHECK(!JS_IsException(streams));
    tjs__mod_engine_init(main_ctx, engine);
    tjs__mod_streams_init(main_ctx, streams);

    JSValue sandbox_ctor = JS_GetPropertyStr(main_ctx, engine, "Sandbox");
    JSValue pipe_ctor = JS_GetPropertyStr(main_ctx, streams, "Pipe");
    CHECK(JS_IsFunction(main_ctx, sandbox_ctor));
    CHECK(JS_IsFunction(main_ctx, pipe_ctor));

    JSValue sandbox = JS_CallConstructor(main_ctx, sandbox_ctor, 0, NULL);
    CHECK(!JS_IsException(sandbox));
    JSClassID sandbox_class_id;
    TJSSandbox *sandbox_state = JS_GetAnyOpaque(sandbox, &sandbox_class_id);
    CHECK(sandbox_state != NULL && sandbox_state->app != NULL);
    JSContext *sandbox_ctx = sandbox_state->app->ctx;
    App *sandbox_app = sandbox_state->app;

    /* Invoke the stream constructor with the sandbox as the active context.
     * The pipe remains reachable from that context after the Sandbox wrapper
     * itself is collected, so runtime teardown must close it before freeing
     * sandbox_ctx. */
    JSValue sandbox_global = JS_GetGlobalObject(sandbox_ctx);
    CHECK(!JS_IsException(sandbox_global));
    CHECK(JS_SetPropertyStr(sandbox_ctx, sandbox_global, "Pipe",
                            JS_DupValue(main_ctx, pipe_ctor)) >= 0);
    /* JS_CallConstructor switches to the constructor's realm, so using the
     * main realm's Pipe constructor here would not exercise sandbox ownership. */
    JSValue pipe = tjs_new_pipe(sandbox_ctx);
    CHECK(!JS_IsException(pipe));
    CHECK(JS_SetPropertyStr(sandbox_ctx, sandbox_global, "pipe", pipe) >= 0);
    JS_FreeValue(sandbox_ctx, sandbox_global);

    JS_FreeValue(main_ctx, pipe_ctor);
    JS_FreeValue(main_ctx, sandbox_ctor);
    JS_FreeValue(main_ctx, streams);
    JS_FreeValue(main_ctx, engine);
    JS_FreeValue(main_ctx, sandbox);

    JS_RunGC(runtime->rt);
    CHECK(first_sandbox(runtime) == sandbox_app);
    CHECK(sandbox_app->context_invalid);
    sandbox_global = JS_GetGlobalObject(sandbox_ctx);
    CHECK(!JS_IsException(sandbox_global));
    pipe = JS_GetPropertyStr(sandbox_ctx, sandbox_global, "pipe");
    CHECK(JS_IsObject(pipe));
    JS_FreeValue(sandbox_ctx, pipe);
    JS_FreeValue(sandbox_ctx, sandbox_global);
    CHECK(!list_empty(&runtime->streams));

    /* TJS_FreeRuntime() must close the sandbox-owned pipe while sandbox_ctx is
     * still valid, then release the context. ASan catches the old ordering. */
    TJS_FreeRuntime(runtime);
    return 0;
}
