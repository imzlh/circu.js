#include "private.h"
#include "capability.h"

#include <assert.h>
#include <string.h>

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
} HookState;

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
                                     const char *source) {
    size_t source_len = strlen(source);
    state->callback = eval_function(ctx, source, source_len);
    if (JS_IsException(state->callback)) TJS_DumpException(ctx);
    assert(JS_IsFunction(ctx, state->callback));
    TJS_SetCapabilityHook(runtime, capability_hook, state, 0);

    JSValue result = eval_function(ctx, "run()", sizeof("run()") - 1);
    assert(JS_IsException(result));
    clear_exception(ctx);

    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    JS_FreeValue(ctx, state->callback);
    state->callback = JS_UNDEFINED;
}

int main(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = runtime->main_ctx;
    assert(ctx != NULL);
    assert(JS_AddIntrinsicEval(ctx) == 0);
    set_global(ctx, "sqlite3", use_module(ctx, "sqlite3"));
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
        "closeTarget");

    expect_hook_revalidation(
        ctx, runtime, &state,
        "globalThis.pipe = new streams.Pipe();\n"
        "globalThis.run = () => pipe.open(0);\n"
        "globalThis.closeTarget = () => pipe.close();\n"
        "closeTarget");

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
