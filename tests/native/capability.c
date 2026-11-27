#include "private.h"
#include "capability.h"

#include <assert.h>
#include <string.h>

#ifndef _WIN32
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

/* Keep this standalone target meaningful in Release builds too. */
#undef assert
#define assert(expr) CHECK(expr)

typedef enum HookMode {
    HOOK_PASS,
    HOOK_REPLACE,
    HOOK_THROW,
    HOOK_EXCEPTION_WITHOUT_THROW,
    HOOK_PASS_WITH_EXCEPTION,
    HOOK_REPLACE_WITH_EXCEPTION,
    HOOK_INVALID_PASS,
    HOOK_REENTER,
    HOOK_REENTER_MACRO,
    HOOK_UNINSTALL,
    HOOK_REUSE_FD,
} HookMode;

typedef struct HookState {
    HookMode mode;
    int calls;
    TJSCapabilityMask mask;
    const char *api;
    const char *detail;
    uint32_t stream;
    uint32_t argc;
    TJSRuntime *runtime;
    JSValue callback;
    const char *reuse_api;
    int reuse_target_fd;
    int reuse_source_fd;
    bool reused_fd;
} HookState;

typedef struct HandleResolverState {
    int resolve_calls;
    int compare_calls;
    bool available;
} HandleResolverState;

static HandleResolverState *handle_resolver_state;

static int TJS_OBJECT_HANDLE_CALL mock_compare_object_handles(
    void *first, void *second) {
    handle_resolver_state->compare_calls++;
    return first == second;
}

static TJSObjectHandleCompareFunction mock_resolve_compare_object_handles(
    void *opaque) {
    HandleResolverState *state = opaque;
    state->resolve_calls++;
    handle_resolver_state = state;
    return state->available ? mock_compare_object_handles : NULL;
}

static void test_object_handle_compare_cache(void) {
    HandleResolverState state = { .available = true };
    TJSObjectHandleCompareCache cache = { 0 };
    void *first = (void *) (uintptr_t) 1;
    void *second = (void *) (uintptr_t) 2;

    assert(TJS_CompareObjectHandlesCached(
               &cache, mock_resolve_compare_object_handles, &state,
               first, first) == TJS_OBJECT_HANDLE_IDENTITY_SAME);
    assert(TJS_CompareObjectHandlesCached(
               &cache, mock_resolve_compare_object_handles, &state,
               first, second) == TJS_OBJECT_HANDLE_IDENTITY_DIFFERENT);
    assert(state.resolve_calls == 1);
    assert(state.compare_calls == 2);

    HandleResolverState unavailable = { 0 };
    TJSObjectHandleCompareCache unavailable_cache = { 0 };
    assert(TJS_CompareObjectHandlesCached(
               &unavailable_cache, mock_resolve_compare_object_handles,
               &unavailable, first, first) ==
           TJS_OBJECT_HANDLE_IDENTITY_UNSUPPORTED);
    assert(TJS_CompareObjectHandlesCached(
               &unavailable_cache, mock_resolve_compare_object_handles,
               &unavailable, first, first) ==
           TJS_OBJECT_HANDLE_IDENTITY_UNSUPPORTED);
    assert(unavailable.resolve_calls == 1);
    assert(unavailable.compare_calls == 0);
}

static JSValue nested_macro_probe(JSContext *ctx,
                                  const TJSCapability *capability,
                                  int *continued,
                                  int *cleaned,
                                  int *evaluated,
                                  int *revalidated) {
    TJS_CAPABILITY_REVALIDATE(
        (++*evaluated, TJS_CheckCapability(ctx, capability)), ++*cleaned,
        ++*revalidated);
    ++*continued;
    return JS_UNDEFINED;
}

static JSValue capability_hook(JSContext *ctx,
                               const TJSCapability *capability,
                               void *userdata) {
    HookState *state = userdata;
    state->calls++;
    state->mask = capability->mask;
    state->api = capability->api;
    state->detail = NULL;
    state->stream = 0;
    state->argc = 0;

    if (!JS_IsUndefined(state->callback)) {
        JSValue callback_result = JS_Call(ctx, state->callback, JS_UNDEFINED,
                                          0, NULL);
        if (JS_IsException(callback_result)) return callback_result;
        JS_FreeValue(ctx, callback_result);
    }

    if (TJS_CAP_CATEGORY(capability->mask) == TJS_CAP_CONSOLE) {
            state->stream = capability->details.console.stream;
            state->argc = capability->details.console.argc;
    } else {
        state->detail = capability->details.resource;
    }

    switch (state->mode) {
        case HOOK_PASS:
            return TJS_CAPABILITY_PASS;
        case HOOK_REPLACE:
            return JS_NewString(ctx, "replaced");
        case HOOK_THROW:
            return JS_ThrowTypeError(ctx, "denied");
        case HOOK_EXCEPTION_WITHOUT_THROW:
            return JS_EXCEPTION;
        case HOOK_PASS_WITH_EXCEPTION:
            JS_ThrowTypeError(ctx, "pending while passing");
            return TJS_CAPABILITY_PASS;
        case HOOK_REPLACE_WITH_EXCEPTION:
            JS_ThrowTypeError(ctx, "pending while replacing");
            return JS_NewString(ctx, "discard me");
        case HOOK_INVALID_PASS:
            return JS_MKVAL(JS_TAG_UNINITIALIZED, 1);
        case HOOK_REENTER: {
            JSValue nested = TJS_CheckCapability(ctx, capability);
            assert(JS_IsUninitialized(nested));
            return TJS_CAPABILITY_PASS;
        }
        case HOOK_REENTER_MACRO: {
            int continued = 0;
            int cleaned = 0;
            int evaluated = 0;
            int revalidated = 0;
            JSValue nested = nested_macro_probe(ctx, capability, &continued,
                                                &cleaned, &evaluated,
                                                &revalidated);
            assert(JS_IsUndefined(nested));
            assert(continued == 1 && cleaned == 0 && evaluated == 0 &&
                   revalidated == 0);
            return TJS_CAPABILITY_PASS;
        }
        case HOOK_UNINSTALL:
            TJS_SetCapabilityHook(state->runtime, NULL, NULL, 0);
            return TJS_CAPABILITY_PASS;
        case HOOK_REUSE_FD:
#ifndef _WIN32
            if (!state->reused_fd && state->reuse_api &&
                strcmp(capability->api, state->reuse_api) == 0) {
                assert(close(state->reuse_target_fd) == 0);
                assert(dup2(state->reuse_source_fd, state->reuse_target_fd) ==
                       state->reuse_target_fd);
                state->reused_fd = true;
            }
#endif
            return TJS_CAPABILITY_PASS;
    }
    assert(0);
    return JS_EXCEPTION;
}

static void clear_exception(JSContext *ctx) {
    assert(JS_HasException(ctx));
    JSValue exception = JS_GetException(ctx);
    JS_FreeValue(ctx, exception);
}

static void expect_invalid(JSContext *ctx,
                           const TJSCapability *capability,
                           HookState *state) {
    int calls = state->calls;
    JSValue result = TJS_CheckCapability(ctx, capability);
    assert(JS_IsException(result));
    assert(state->calls == calls);
    clear_exception(ctx);
}

static JSValue macro_probe(JSContext *ctx,
                           const TJSCapability *capability,
                           int *continued,
                           int *cleaned,
                           int *evaluated,
                           int *revalidated) {
    TJS_CAPABILITY_REVALIDATE(
        (++*evaluated, TJS_CheckCapability(ctx, capability)), ++*cleaned,
        ++*revalidated);
    ++*continued;
    return JS_UNDEFINED;
}

static JSValue macro_revalidation_failure_probe(
    JSContext *ctx,
    const TJSCapability *capability,
    int *continued,
    int *cleaned,
    int *revalidated) {
    TJS_CAPABILITY_REVALIDATE(
        TJS_CheckCapability(ctx, capability), ++*cleaned,
        do {
            ++*revalidated;
            return JS_ThrowTypeError(ctx, "revalidation failed");
        } while (0));
    ++*continued;
    return JS_UNDEFINED;
}

static JSValue guarded_macro_probe(JSContext *ctx,
                                   const TJSCapability *capability,
                                   int *prepared,
                                   int *continued,
                                   int *cleaned,
                                   int *evaluated,
                                   int *revalidated) {
    TJS_CAPABILITY_GUARDED(
        ++*prepared,
        (++*evaluated, TJS_CheckCapability(ctx, capability)), ++*cleaned,
        ++*revalidated);
    ++*continued;
    return JS_UNDEFINED;
}

static TJSCapability io_capability(void) {
    return (TJSCapability) {
        .abi_version = TJS_CAPABILITY_ABI_VERSION,
        .struct_size = sizeof(TJSCapability),
        .flags = TJS_CAP_FLAG_REPLACEABLE,
        .mask = TJS_CAP_IO | TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ,
        .api = "fs.readFile",
        .details.resource = "/borrowed",
    };
}

static JSValue eval_function(JSContext *ctx,
                             const char *source,
                             size_t source_len) {
    return JS_Eval(ctx, source, source_len, "<capability-test>",
                   JS_EVAL_TYPE_GLOBAL);
}

static JSValue use_module(JSContext *ctx, const char *name) {
    TJSRuntime *runtime = TJS_GetRuntime(ctx);
    JSValue name_value = JS_NewString(ctx, name);
    JSValue module = tjs__module_use(ctx, JS_UNDEFINED, 1, &name_value, 0,
                                    &runtime->module.imod_ns);
    JS_FreeValue(ctx, name_value);
    return module;
}

static void set_global(JSContext *ctx, const char *name, JSValue value) {
    JSValue global = JS_GetGlobalObject(ctx);
    assert(JS_SetPropertyStr(ctx, global, name, value) >= 0);
    JS_FreeValue(ctx, global);
}

static void expect_hook_revalidation(JSContext *ctx,
                                     TJSRuntime *runtime,
                                     HookState *state,
                                     const char *source,
                                     const char *expected_error) {
    size_t source_len = strlen(source);
    state->callback = eval_function(ctx, source, source_len);
    if (JS_IsException(state->callback)) TJS_DumpException(ctx);
    assert(JS_IsFunction(ctx, state->callback));
    TJS_SetCapabilityHook(runtime, capability_hook, state, 0);

    JSValue result = eval_function(ctx, "run()", sizeof("run()") - 1);
    assert(JS_IsException(result));
    assert(JS_HasException(ctx));
    JSValue exception = JS_GetException(ctx);
    if (expected_error) {
        const char *message = JS_ToCString(ctx, exception);
        assert(message && strcmp(message, expected_error) == 0);
        JS_FreeCString(ctx, message);
    }
    JS_FreeValue(ctx, exception);

    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    JS_FreeValue(ctx, state->callback);
    state->callback = JS_UNDEFINED;
}

int main(void) {
    test_object_handle_compare_cache();

    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = runtime->main_ctx;
    assert(ctx != NULL);
    assert(JS_AddIntrinsicEval(ctx) == 0);
    set_global(ctx, "asyncfs", use_module(ctx, "asyncfs"));
    set_global(ctx, "curl", use_module(ctx, "curl"));
    set_global(ctx, "sqlite3", use_module(ctx, "sqlite3"));
    set_global(ctx, "socket", use_module(ctx, "socket"));
    set_global(ctx, "streams", use_module(ctx, "streams"));

    HookState state = {
        .mode = HOOK_PASS,
        .runtime = runtime,
        .callback = JS_UNDEFINED,
    };
    assert(TJS_SetCapabilityHook(runtime, capability_hook, &state, 0));
    assert(atomic_load_explicit(&tjs__capability_hook_count,
                                memory_order_relaxed) == 1);
    int calls;

    TJSCapability capability = io_capability();
    JSValue result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));
    assert(state.calls == 1);
    assert(state.mask ==
           (TJS_CAP_IO | TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ));
    assert(TJS_CAP_CATEGORY(state.mask) == TJS_CAP_IO);
    assert(TJS_CAP_OPERATIONS(state.mask) ==
           (TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ));
    assert(strcmp(state.api, "fs.readFile") == 0);
    assert(strcmp(state.detail, "/borrowed") == 0);

    /* Every non-console category uses the same optional resource string. */
    capability.mask = TJS_CAP_NETWORK | TJS_CAP_IO_CONNECT;
    capability.api = "socket.connect";
    capability.details.resource = "127.0.0.1:8080";
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));
    assert(strcmp(state.detail, "127.0.0.1:8080") == 0);

    capability.mask = TJS_CAP_ENV | TJS_CAP_IO_READ;
    capability.api = "os.getenv";
    capability.details.resource = "PATH";
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));
    assert(strcmp(state.detail, "PATH") == 0);

    calls = state.calls;
    assert(!TJS_SetCapabilityHook(runtime, capability_hook, &state,
                                  UINT32_C(1) << 31));
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));
    assert(state.calls == calls + 1);

    capability = io_capability();
    state.mode = HOOK_REPLACE;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsString(result));
    const char *text = JS_ToCString(ctx, result);
    assert(text != NULL && strcmp(text, "replaced") == 0);
    JS_FreeCString(ctx, text);
    JS_FreeValue(ctx, result);

    state.mode = HOOK_THROW;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    clear_exception(ctx);

    state.mode = HOOK_REPLACE;
    capability.flags = 0;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    clear_exception(ctx);
    capability.flags = TJS_CAP_FLAG_REPLACEABLE;

    state.mode = HOOK_EXCEPTION_WITHOUT_THROW;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    clear_exception(ctx);

    state.mode = HOOK_PASS_WITH_EXCEPTION;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    clear_exception(ctx);

    state.mode = HOOK_REPLACE_WITH_EXCEPTION;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    clear_exception(ctx);

    state.mode = HOOK_INVALID_PASS;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    clear_exception(ctx);

    /* A trusted hook may use another controlled libcjs operation for logging
     * or diagnostics. It must not recursively call itself forever. */
    calls = state.calls;
    state.mode = HOOK_REENTER;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));
    assert(state.calls == calls + 1);

    /* A pre-existing exception is propagated without entering the hook. */
    calls = state.calls;
    JS_ThrowTypeError(ctx, "already pending");
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsException(result));
    assert(state.calls == calls);
    clear_exception(ctx);

    /* Malformed descriptors are rejected before invoking embedder code. */
    state.mode = HOOK_PASS;
    uint32_t saved = capability.abi_version;
    capability.abi_version++;
    expect_invalid(ctx, &capability, &state);
    capability.abi_version = saved;

    saved = capability.struct_size;
    capability.struct_size = TJS_CAPABILITY_V1_SIZE - 1;
    expect_invalid(ctx, &capability, &state);
    capability.struct_size = saved;

    saved = capability.flags;
    capability.flags = UINT32_C(1) << 31;
    expect_invalid(ctx, &capability, &state);
    capability.flags = saved;

    const char *saved_api = capability.api;
    capability.api = NULL;
    expect_invalid(ctx, &capability, &state);
    capability.api = "";
    expect_invalid(ctx, &capability, &state);
    capability.api = saved_api;

    TJSCapabilityMask saved_mask = capability.mask;
    capability.mask = TJS_CAP_IO;
    expect_invalid(ctx, &capability, &state);
    capability.mask = TJS_CAP_CATEGORY_BIT(15) | TJS_CAP_IO_READ;
    expect_invalid(ctx, &capability, &state);
    capability.mask = TJS_CAP_IO | TJS_CAP_ENV | TJS_CAP_IO_READ;
    expect_invalid(ctx, &capability, &state);
    capability.mask = TJS_CAP_IO | (UINT32_C(1) << 15);
    expect_invalid(ctx, &capability, &state);
    capability.mask = saved_mask;

    TJSCapability console = {
        .abi_version = TJS_CAPABILITY_ABI_VERSION,
        .struct_size = sizeof(TJSCapability),
        .flags = TJS_CAP_FLAG_REPLACEABLE,
        .mask = TJS_CAP_CONSOLE | TJS_CAP_IO_WRITE,
        .api = "console.log",
        .details.console = {
            .stream = TJS_CONSOLE_STDOUT,
            .argc = 1,
            .argv = NULL,
        },
    };
    expect_invalid(ctx, &console, &state);
    console.details.console.argc = 0;
    console.details.console.stream = 0;
    expect_invalid(ctx, &console, &state);

    /* The one-line integration macro returns only on interception and runs
     * cleanup only on that path. Async replacement is returned unchanged. */
    int continued = 0;
    int cleaned = 0;
    int evaluated = 0;
    int revalidated = 0;
    state.mode = HOOK_PASS;
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsUndefined(result));
    assert(continued == 1 && cleaned == 0 && evaluated == 1 &&
           revalidated == 1);

    /* A pure native policy can promise at installation time that PASS neither
     * re-enters nor mutates native state. This avoids both post-hook checks and
     * protection such as fd duplication that must otherwise happen first. */
    TJS_SetCapabilityHook(runtime, capability_hook, &state,
                          TJS_CAPABILITY_HOOK_PASS_IS_STABLE);
    state.mode = HOOK_PASS;
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsUndefined(result));
    assert(continued == 2 && cleaned == 0 && evaluated == 2 &&
           revalidated == 1);
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result) && JS_VALUE_GET_INT(result) == 0);

    int prepared = 0;
    int guarded_continued = 0;
    int guarded_cleaned = 0;
    int guarded_evaluated = 0;
    int guarded_revalidated = 0;
    result = guarded_macro_probe(ctx, &capability, &prepared,
                                 &guarded_continued, &guarded_cleaned,
                                 &guarded_evaluated, &guarded_revalidated);
    assert(JS_IsUndefined(result));
    assert(prepared == 0 && guarded_continued == 1 && guarded_cleaned == 0 &&
           guarded_evaluated == 1 && guarded_revalidated == 0);

    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = guarded_macro_probe(ctx, &capability, &prepared,
                                 &guarded_continued, &guarded_cleaned,
                                 &guarded_evaluated, &guarded_revalidated);
    assert(JS_IsUndefined(result));
    assert(prepared == 1 && guarded_continued == 2 && guarded_cleaned == 0 &&
           guarded_evaluated == 2 && guarded_revalidated == 1);

    state.mode = HOOK_REPLACE;
    capability.flags = TJS_CAP_FLAG_REPLACEABLE | TJS_CAP_FLAG_ASYNC;
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsString(result));
    JS_FreeValue(ctx, result);
    assert(continued == 2 && cleaned == 1 && revalidated == 1);

    state.mode = HOOK_THROW;
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsException(result));
    assert(continued == 2 && cleaned == 2 && revalidated == 1);
    clear_exception(ctx);

    /* Revalidation owns its failure path; interception cleanup must not run. */
    state.mode = HOOK_PASS;
    int revalidation_continued = 0;
    int revalidation_cleaned = 0;
    int revalidation_count = 0;
    result = macro_revalidation_failure_probe(
        ctx, &capability, &revalidation_continued, &revalidation_cleaned,
        &revalidation_count);
    assert(JS_IsException(result));
    assert(revalidation_continued == 0 && revalidation_cleaned == 0 &&
           revalidation_count == 1);
    clear_exception(ctx);

    /* A hook may uninstall itself, but this invocation still needs the state
     * revalidation implied by its PASS result. */
    state.mode = HOOK_UNINSTALL;
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsUndefined(result));
    assert(continued == 3 && revalidated == 2);
    assert(atomic_load_explicit(&tjs__capability_hook_count,
                                memory_order_relaxed) == 0);
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);

    /* Reentrant native operations see the global hook count but must skip the
     * check expression for the runtime whose hook is already executing. */
    state.mode = HOOK_REENTER_MACRO;
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));

    /* The direct module-loader helper has the same three-state gate. */
    calls = state.calls;
    assert(tjs__capability_require_io(ctx, TJS_CAP_IO | TJS_CAP_IO_READ,
                                      "test.require", "/borrowed"));
    assert(state.calls == calls + 1);
    calls = state.calls;
    JS_ThrowTypeError(ctx, "require pending");
    assert(!tjs__capability_require_io(ctx, TJS_CAP_IO | TJS_CAP_IO_READ,
                                       "test.require", "/borrowed"));
    assert(state.calls == calls);
    clear_exception(ctx);

    /* A process-wide count is only a negative cache. Another runtime's hook
     * must not make this hookless runtime evaluate its descriptor. */
    TJSRuntime *runtime2 = TJS_NewRuntime();
    assert(runtime2 != NULL);
    JSContext *ctx2 = runtime2->main_ctx;
    assert(ctx2 != NULL);
    assert(JS_AddIntrinsicEval(ctx2) == 0);

    int continued2 = 0;
    int cleaned2 = 0;
    int evaluated2 = 0;
    int revalidated2 = 0;
    result = macro_probe(ctx2, &capability, &continued2, &cleaned2,
                         &evaluated2, &revalidated2);
    assert(JS_IsUndefined(result));
    assert(continued2 == 1 && cleaned2 == 0 && evaluated2 == 0 &&
           revalidated2 == 0);

    /* Public descriptors remain defensive even when this runtime has no hook. */
    calls = state.calls;
    capability.abi_version++;
    result = TJS_CheckCapability(ctx2, &capability);
    assert(JS_IsException(result));
    assert(state.calls == calls);
    clear_exception(ctx2);
    capability.abi_version--;

    HookState state2 = {
        .mode = HOOK_PASS,
        .runtime = runtime2,
        .callback = JS_UNDEFINED,
    };
    TJS_SetCapabilityHook(runtime2, capability_hook, &state2, 0);
    assert(atomic_load_explicit(&tjs__capability_hook_count,
                                memory_order_relaxed) == 2);
    result = macro_probe(ctx2, &capability, &continued2, &cleaned2,
                         &evaluated2, &revalidated2);
    assert(JS_IsUndefined(result));
    assert(continued2 == 2 && cleaned2 == 0 && evaluated2 == 1 &&
           revalidated2 == 1);
    assert(state2.calls == 1);

    TJS_SetCapabilityHook(runtime, NULL, &state, 0);
    assert(atomic_load_explicit(&tjs__capability_hook_count,
                                memory_order_relaxed) == 1);
    capability.flags = TJS_CAP_FLAG_REPLACEABLE;
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsUndefined(result));
    assert(continued == 4 && cleaned == 2 && evaluated == 5 &&
           revalidated == 2);
    result = TJS_CheckCapability(ctx, &capability);
    assert(JS_IsUninitialized(result));
    assert(state.calls == calls);

    assert(tjs__capability_require_io(ctx, TJS_CAP_IO | TJS_CAP_IO_READ,
                                      "test.require", "/borrowed"));

    /* Hook code is a second reentry point after ordinary argument conversion.
     * Closed SQLite and pipe receivers must be reacquired before native use. */
    expect_hook_revalidation(
        ctx, runtime, &state,
        "globalThis.db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);\n"
        "globalThis.run = () => db.exec('SELECT 1');\n"
        "globalThis.closeTarget = () => db.close();\n"
        "closeTarget", NULL);

    expect_hook_revalidation(
        ctx, runtime, &state,
        "globalThis.pipe = new streams.Pipe();\n"
        "globalThis.run = () => pipe.open(0);\n"
        "globalThis.closeTarget = () => pipe.close();\n"
        "closeTarget", NULL);

    expect_hook_revalidation(
        ctx, runtime, &state,
        "(() => { const pool = new curl.ConnPool(); const request = new curl.CURL(pool);"
        " globalThis.run = () => request.performSync(); return () => pool.close(); })()",
        "TypeError: ConnPool is closed");

#ifndef _WIN32
    /* A borrowed asyncfs.createFrom must retain the pre-hook file description
     * through its duplicate and never take ownership of either the original
     * slot or its replacement. */
    int original_pipe[2];
    int replacement_pipe[2];
    assert(pipe(original_pipe) == 0);
    assert(pipe(replacement_pipe) == 0);
    set_global(ctx, "fileFd", JS_NewInt32(ctx, original_pipe[0]));
    state.mode = HOOK_REUSE_FD;
    state.reuse_api = "asyncfs.createFrom";
    state.reuse_target_fd = original_pipe[0];
    state.reuse_source_fd = replacement_pipe[0];
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx,
        "globalThis.pinnedFile = asyncfs.createFrom(fileFd)",
        sizeof("globalThis.pinnedFile = asyncfs.createFrom(fileFd)") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);

    result = eval_function(ctx, "pinnedFile.fileno()",
                           sizeof("pinnedFile.fileno()") - 1);
    assert(JS_VALUE_GET_TAG(result) == JS_TAG_INT);
    int pinned_file_fd = JS_VALUE_GET_INT(result);
    JS_FreeValue(ctx, result);
    unsigned char byte = 88;
    assert(write(original_pipe[1], &byte, 1) == 1);
    byte = 99;
    assert(write(replacement_pipe[1], &byte, 1) == 1);
    byte = 0;
    assert(read(pinned_file_fd, &byte, 1) == 1);
    assert(byte == 88);
    assert(read(original_pipe[0], &byte, 1) == 1);
    assert(byte == 99);
    result = eval_function(ctx, "globalThis.pinnedFile = undefined",
                           sizeof("globalThis.pinnedFile = undefined") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    JS_RunGC(JS_GetRuntime(ctx));
    assert(fcntl(original_pipe[0], F_GETFD) != -1);
    close(original_pipe[0]);
    close(original_pipe[1]);
    close(replacement_pipe[0]);
    close(replacement_pipe[1]);

    /* Transferring ownership must still wrap the originally named file, not a
     * same-numbered replacement installed by the hook. */
    int owned_pipe[2];
    int owned_replacement[2];
    assert(pipe(owned_pipe) == 0);
    assert(pipe(owned_replacement) == 0);
    set_global(ctx, "fileFd", JS_NewInt32(ctx, owned_pipe[0]));
    state.mode = HOOK_REUSE_FD;
    state.reuse_api = "asyncfs.createFrom";
    state.reuse_target_fd = owned_pipe[0];
    state.reuse_source_fd = owned_replacement[0];
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx,
        "globalThis.ownedFile = asyncfs.createFrom(fileFd, undefined, { closeOnClose: true })",
        sizeof("globalThis.ownedFile = asyncfs.createFrom(fileFd, undefined, { closeOnClose: true })") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    result = eval_function(ctx, "ownedFile.fileno()",
                           sizeof("ownedFile.fileno()") - 1);
    assert(JS_VALUE_GET_TAG(result) == JS_TAG_INT);
    int owned_file_fd = JS_VALUE_GET_INT(result);
    JS_FreeValue(ctx, result);
    byte = 88;
    assert(write(owned_pipe[1], &byte, 1) == 1);
    byte = 99;
    assert(write(owned_replacement[1], &byte, 1) == 1);
    byte = 0;
    assert(read(owned_file_fd, &byte, 1) == 1);
    assert(byte == 88);
    byte = 0;
    assert(read(owned_pipe[0], &byte, 1) == 1);
    assert(byte == 99);
    result = eval_function(ctx, "ownedFile.close()",
                           sizeof("ownedFile.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    /* close() hands the descriptor to the thread pool. Pump the loop until
     * that close(2) has landed, otherwise the probe below races the worker
     * and the descriptor still looks open. */
    for (int spin = 0; spin < 1000 && fcntl(owned_file_fd, F_GETFD) != -1;
         spin++) {
        uv_run(&runtime->loop, UV_RUN_ONCE);
    }
    errno = 0;
    assert(fcntl(owned_file_fd, F_GETFD) == -1);
    assert(errno == EBADF);
    assert(fcntl(owned_pipe[0], F_GETFD) != -1);
    close(owned_pipe[0]);
    close(owned_pipe[1]);
    close(owned_replacement[0]);
    close(owned_replacement[1]);

    int getter_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, getter_pair) == 0);
    set_global(ctx, "fs", use_module(ctx, "fs"));
    set_global(ctx, "fileFd", JS_NewInt32(ctx, getter_pair[0]));
    const char getter_transfer[] =
        "asyncfs.createFrom(fileFd, undefined, { get closeOnClose() {"
        "  fs.close(fileFd);"
        "  if (fs.open('/dev/null', 'r') !== fileFd) throw Error('fd not reused');"
        "  return true;"
        "} }).detach()";
    result = eval_function(ctx, getter_transfer, sizeof(getter_transfer) - 1);
    assert(JS_VALUE_GET_TAG(result) == JS_TAG_INT);
    int getter_fd = JS_VALUE_GET_INT(result);
    JS_FreeValue(ctx, result);
    assert(getter_fd != getter_pair[0]);
    assert(send(getter_pair[1], &byte, 1, 0) == 1);
    assert(recv(getter_fd, &byte, 1, MSG_DONTWAIT) == 1);
    assert(close(getter_fd) == 0);
    assert(read(getter_pair[0], &byte, 1) == 0);
    assert(close(getter_pair[0]) == 0);
    assert(close(getter_pair[1]) == 0);

    int identity_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, identity_pair) == 0);
    set_global(ctx, "fileFd", JS_NewInt32(ctx, identity_pair[0]));
    state.mode = HOOK_PASS;
    state.reuse_api = NULL;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    const char identity_transfer[] =
        "asyncfs.createFrom(fileFd, undefined, { closeOnClose: true }).detach()";
    result = eval_function(ctx, identity_transfer, sizeof(identity_transfer) - 1);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    if (JS_IsException(result)) {
        JSValue exception = JS_GetException(ctx);
        const char *message = JS_ToCString(ctx, exception);
        assert(message && strcmp(message, "TypeError: object handle identity comparison is not supported on this platform") == 0);
        JS_FreeCString(ctx, message);
        JS_FreeValue(ctx, exception);
    } else {
        assert(JS_VALUE_GET_TAG(result) == JS_TAG_INT);
        assert(JS_VALUE_GET_INT(result) == identity_pair[0]);
        JS_FreeValue(ctx, result);
    }
    assert(close(identity_pair[0]) == 0);
    assert(recv(identity_pair[1], &byte, 1, MSG_DONTWAIT) == 0);
    assert(close(identity_pair[1]) == 0);

    /* createFrom itself must pin before its capability hook. Otherwise a hook
     * can replace the numeric slot and make the returned wrapper target the
     * wrong socket. */
    int original_pair[2];
    int replacement_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, original_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement_pair) == 0);
    set_global(ctx, "socketFd", JS_NewInt32(ctx, original_pair[0]));
    state.mode = HOOK_REUSE_FD;
    state.reuse_api = "socket.createFrom";
    state.reuse_target_fd = original_pair[0];
    state.reuse_source_fd = replacement_pair[0];
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx,
        "globalThis.pinnedSocket = socket.createFrom(socketFd)",
        sizeof("globalThis.pinnedSocket = socket.createFrom(socketFd)") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);

    result = eval_function(
        ctx, "pinnedSocket.send(new Uint8Array([89]))",
        sizeof("pinnedSocket.send(new Uint8Array([89]))") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    byte = 0;
    assert(recv(original_pair[1], (char *) &byte, 1, MSG_DONTWAIT) == 1);
    assert(byte == 89);
    errno = 0;
    assert(recv(replacement_pair[1], (char *) &byte, 1, MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    result = eval_function(ctx, "pinnedSocket.close()",
                           sizeof("pinnedSocket.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    close(original_pair[0]);
    close(original_pair[1]);
    close(replacement_pair[0]);
    close(replacement_pair[1]);

    /* Explicit ownership closes the transferred descriptor on wrapper close. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, original_pair) == 0);
    set_global(ctx, "socketFd", JS_NewInt32(ctx, original_pair[0]));
    result = eval_function(
        ctx,
        "socket.createFrom(socketFd, { closeOnClose: true }).close()",
        sizeof("socket.createFrom(socketFd, { closeOnClose: true }).close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    errno = 0;
    assert(close(original_pair[0]) == -1);
    assert(errno == EBADF);
    close(original_pair[1]);

    /* A conservative hook can close a numeric descriptor and reuse the slot
     * without touching the JS wrapper. The authorized operation must stay on
     * the pre-hook socket description, not the replacement in the same slot. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, original_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement_pair) == 0);
    set_global(ctx, "socketFd", JS_NewInt32(ctx, original_pair[0]));
    result = eval_function(
        ctx,
        "globalThis.pinnedSocket = socket.createFrom(socketFd)",
        sizeof("globalThis.pinnedSocket = socket.createFrom(socketFd)") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);

    state.mode = HOOK_REUSE_FD;
    state.reuse_api = "socket.send";
    state.reuse_target_fd = original_pair[0];
    state.reuse_source_fd = replacement_pair[0];
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx, "pinnedSocket.send(new Uint8Array([90]))",
        sizeof("pinnedSocket.send(new Uint8Array([90]))") - 1);
    assert(!JS_IsException(result));
    assert(JS_VALUE_GET_TAG(result) == JS_TAG_INT &&
           JS_VALUE_GET_INT(result) == 1);
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);

    byte = 0;
    assert(recv(original_pair[1], (char *) &byte, 1, MSG_DONTWAIT) == 1);
    assert(byte == 90);
    errno = 0;
    assert(recv(replacement_pair[1], (char *) &byte, 1, MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);

    result = eval_function(ctx, "pinnedSocket.close()",
                           sizeof("pinnedSocket.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    close(original_pair[0]);
    close(original_pair[1]);
    close(replacement_pair[0]);
    close(replacement_pair[1]);

    /* Address and metadata getters must query the pre-hook socket description,
     * even when the hook replaces the wrapper's numeric descriptor. */
    result = eval_function(
        ctx,
        "globalThis.originalSocket = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
        "globalThis.replacementSocket = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
        "originalSocket.bind({ ip: '127.0.0.1', port: 0 });\n"
        "replacementSocket.bind({ ip: '127.0.0.1', port: 0 });\n"
        "globalThis.expectedSocketPort = originalSocket.sockname.port",
        sizeof(
            "globalThis.originalSocket = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
            "globalThis.replacementSocket = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
            "originalSocket.bind({ ip: '127.0.0.1', port: 0 });\n"
            "replacementSocket.bind({ ip: '127.0.0.1', port: 0 });\n"
            "globalThis.expectedSocketPort = originalSocket.sockname.port") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "originalSocket.fileno",
                           sizeof("originalSocket.fileno") - 1);
    assert(JS_ToInt32(ctx, &state.reuse_target_fd, result) == 0);
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "replacementSocket.fileno",
                           sizeof("replacementSocket.fileno") - 1);
    assert(JS_ToInt32(ctx, &state.reuse_source_fd, result) == 0);
    JS_FreeValue(ctx, result);
    state.mode = HOOK_REUSE_FD;
    state.reuse_api = "socket.sockname";
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx, "originalSocket.sockname.port === expectedSocketPort",
        sizeof("originalSocket.sockname.port === expectedSocketPort") - 1);
    assert(JS_IsBool(result) && JS_VALUE_GET_BOOL(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    result = eval_function(
        ctx, "originalSocket.close(); replacementSocket.close()",
        sizeof("originalSocket.close(); replacementSocket.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);

    result = eval_function(
        ctx,
        "globalThis.originalPeer = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
        "globalThis.replacementPeer = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
        "globalThis.originalDestination = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
        "globalThis.replacementDestination = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
        "originalDestination.bind({ ip: '127.0.0.1', port: 0 });\n"
        "replacementDestination.bind({ ip: '127.0.0.1', port: 0 });\n"
        "originalPeer.connect(originalDestination.sockname);\n"
        "replacementPeer.connect(replacementDestination.sockname);\n"
        "globalThis.expectedPeerPort = originalDestination.sockname.port",
        sizeof(
            "globalThis.originalPeer = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
            "globalThis.replacementPeer = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
            "globalThis.originalDestination = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
            "globalThis.replacementDestination = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);\n"
            "originalDestination.bind({ ip: '127.0.0.1', port: 0 });\n"
            "replacementDestination.bind({ ip: '127.0.0.1', port: 0 });\n"
            "originalPeer.connect(originalDestination.sockname);\n"
            "replacementPeer.connect(replacementDestination.sockname);\n"
            "globalThis.expectedPeerPort = originalDestination.sockname.port") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "originalPeer.fileno",
                           sizeof("originalPeer.fileno") - 1);
    assert(JS_ToInt32(ctx, &state.reuse_target_fd, result) == 0);
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "replacementPeer.fileno",
                           sizeof("replacementPeer.fileno") - 1);
    assert(JS_ToInt32(ctx, &state.reuse_source_fd, result) == 0);
    JS_FreeValue(ctx, result);
    state.reuse_api = "socket.peername";
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx, "originalPeer.peername.port === expectedPeerPort",
        sizeof("originalPeer.peername.port === expectedPeerPort") - 1);
    assert(JS_IsBool(result) && JS_VALUE_GET_BOOL(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    result = eval_function(
        ctx,
        "originalPeer.close(); replacementPeer.close();\n"
        "originalDestination.close(); replacementDestination.close()",
        sizeof(
            "originalPeer.close(); replacementPeer.close();\n"
            "originalDestination.close(); replacementDestination.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);

    result = eval_function(
        ctx,
        "globalThis.originalInfoSocket = new socket.Socket(socket.AF_INET, socket.SOCK_STREAM);\n"
        "globalThis.replacementInfoSocket = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM)",
        sizeof(
            "globalThis.originalInfoSocket = new socket.Socket(socket.AF_INET, socket.SOCK_STREAM);\n"
            "globalThis.replacementInfoSocket = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM)") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "originalInfoSocket.fileno",
                           sizeof("originalInfoSocket.fileno") - 1);
    assert(JS_ToInt32(ctx, &state.reuse_target_fd, result) == 0);
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "replacementInfoSocket.fileno",
                           sizeof("replacementInfoSocket.fileno") - 1);
    assert(JS_ToInt32(ctx, &state.reuse_source_fd, result) == 0);
    JS_FreeValue(ctx, result);
    state.reuse_api = "socket.info";
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx, "originalInfoSocket.info.type === socket.SOCK_STREAM",
        sizeof("originalInfoSocket.info.type === socket.SOCK_STREAM") - 1);
    assert(JS_IsBool(result) && JS_VALUE_GET_BOOL(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    result = eval_function(
        ctx, "originalInfoSocket.close(); replacementInfoSocket.close()",
        sizeof("originalInfoSocket.close(); replacementInfoSocket.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);

    /* fileno cannot expose its temporary duplicate. If same-slot reuse changes
     * the identity, fail instead, and release the pin before propagating. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, original_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement_pair) == 0);
    set_global(ctx, "socketFd", JS_NewInt32(ctx, original_pair[0]));
    result = eval_function(
        ctx, "globalThis.pinnedSocket = socket.createFrom(socketFd)",
        sizeof("globalThis.pinnedSocket = socket.createFrom(socketFd)") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    state.reuse_target_fd = original_pair[0];
    state.reuse_source_fd = replacement_pair[0];
    state.reuse_api = "socket.fileno";
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(ctx, "pinnedSocket.fileno",
                           sizeof("pinnedSocket.fileno") - 1);
    assert(JS_IsException(result));
    clear_exception(ctx);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    assert(recv(original_pair[1], (char *) &byte, 1, MSG_DONTWAIT) == 0);
    result = eval_function(ctx, "pinnedSocket.close()",
                           sizeof("pinnedSocket.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    close(original_pair[0]);
    close(original_pair[1]);
    close(replacement_pair[0]);
    close(replacement_pair[1]);

    /* uv_poll_t retains its descriptor after poll() returns. Its pinned copy
     * must therefore remain alive until the handle's close callback, while
     * still protecting initialization from same-slot reuse in the hook. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, original_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement_pair) == 0);
    set_global(ctx, "socketFd", JS_NewInt32(ctx, original_pair[0]));
    result = eval_function(
        ctx,
        "globalThis.pinnedSocket = socket.createFrom(socketFd);\n"
        "globalThis.pollCalls = 0",
        sizeof("globalThis.pinnedSocket = socket.createFrom(socketFd);\n"
               "globalThis.pollCalls = 0") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);

    state.mode = HOOK_REUSE_FD;
    state.reuse_api = "socket.poll";
    state.reuse_target_fd = original_pair[0];
    state.reuse_source_fd = replacement_pair[0];
    state.reused_fd = false;
    TJS_SetCapabilityHook(runtime, capability_hook, &state, 0);
    result = eval_function(
        ctx,
        "pinnedSocket.poll(socket.READABLE, () => { pollCalls++ })",
        sizeof("pinnedSocket.poll(socket.READABLE, () => { pollCalls++ })") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    assert(state.reused_fd);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);

    byte = 91;
    assert(send(original_pair[1], (const char *) &byte, 1, 0) == 1);
    assert(uv_run(&runtime->loop, UV_RUN_ONCE) != 0);
    result = eval_function(ctx, "pollCalls",
                           sizeof("pollCalls") - 1);
    assert(JS_VALUE_GET_TAG(result) == JS_TAG_INT &&
           JS_VALUE_GET_INT(result) == 1);
    JS_FreeValue(ctx, result);
    result = eval_function(ctx, "pinnedSocket.stopPoll(); pinnedSocket.close()",
                           sizeof("pinnedSocket.stopPoll(); pinnedSocket.close()") - 1);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    uv_run(&runtime->loop, UV_RUN_NOWAIT);

    close(original_pair[0]);
    close(original_pair[1]);
    close(replacement_pair[0]);
    close(replacement_pair[1]);
#endif

    /* Freeing a hooked runtime must retire its contribution to the negative
     * cache. The remaining runtime then takes the one-load zero-hook path. */
    TJS_FreeRuntime(runtime2);
    assert(atomic_load_explicit(&tjs__capability_hook_count,
                                memory_order_relaxed) == 0);
    result = macro_probe(ctx, &capability, &continued, &cleaned, &evaluated,
                         &revalidated);
    assert(JS_IsUndefined(result));
    assert(continued == 5 && cleaned == 2 && evaluated == 5 &&
           revalidated == 2);

    TJS_FreeRuntime(runtime);
    return 0;
}
