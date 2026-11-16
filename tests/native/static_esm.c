#include "private.h"

#include <assert.h>
#include <string.h>

/* Keep this standalone target meaningful in Release builds too. */
#undef assert
#define assert(expr) CHECK(expr)

extern int cjs_test_native_esm_init_count(void);

typedef struct CapabilityState {
    int calls;
    bool saw_module_load;
    bool saw_evbus_resource;
} CapabilityState;

static JSValue reject_capability(JSContext *ctx,
                                 const TJSCapability *capability,
                                 void *userdata) {
    CapabilityState *state = userdata;
    state->calls++;
    state->saw_module_load = capability->api &&
        strcmp(capability->api, "module.load") == 0;
    state->saw_evbus_resource = capability->details.resource &&
        strcmp(capability->details.resource, "evbus") == 0;
    return JS_ThrowTypeError(ctx, "test capability denied");
}

static JSValue eval_module(JSContext *ctx, const char *specifier,
                           const char *source) {
    return TJS_EvalModuleContent(ctx, specifier, false, false, source,
                                 strlen(source));
}

static JSValue eval_global(JSContext *ctx, const char *source) {
    return JS_Eval(ctx, source, strlen(source), "<static-esm-test>",
                   JS_EVAL_TYPE_GLOBAL);
}

static void clear_exception(JSContext *ctx) {
    assert(JS_HasException(ctx));
    JS_FreeValue(ctx, JS_GetException(ctx));
}

static void test_runtime(int expected_init_count) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = TJS_GetMainContext(runtime);
    assert(ctx != NULL);

    CapabilityState capability = { 0 };
    assert(TJS_SetCapabilityHook(runtime, reject_capability, &capability, 0));

    static const char first_source[] =
        "import { singleton, NativeToken, initCount } "
        "  from 'cjs:test-native-esm';\n"
        "globalThis.staticEsmFirst = {\n"
        "  singleton, NativeToken, initCount,\n"
        "  hiddenFromUse: "
        "    import.meta.use('cjs:test-native-esm') === null,\n"
        "  hiddenFromList: "
        "    !import.meta.module.includes('cjs:test-native-esm'),\n"
        "};\n";
    JSValue result = eval_module(ctx, "<static-esm-first>", first_source);
    if (JS_IsException(result)) TJS_DumpException(ctx);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    assert(capability.calls == 0);
    assert(cjs_test_native_esm_init_count() == expected_init_count);

    static const char second_source[] =
        "import { singleton, NativeToken, initCount } "
        "  from 'cjs:test-native-esm';\n"
        "globalThis.staticEsmIdentity =\n"
        "  staticEsmFirst.singleton === singleton &&\n"
        "  staticEsmFirst.NativeToken === NativeToken &&\n"
        "  staticEsmFirst.initCount === initCount &&\n"
        "  staticEsmFirst.hiddenFromUse &&\n"
        "  staticEsmFirst.hiddenFromList;\n";
    result = eval_module(ctx, "<static-esm-second>", second_source);
    if (JS_IsException(result)) TJS_DumpException(ctx);
    assert(!JS_IsException(result));
    JS_FreeValue(ctx, result);
    assert(capability.calls == 0);
    assert(cjs_test_native_esm_init_count() == expected_init_count);

    result = eval_global(ctx, "staticEsmIdentity === true");
    assert(JS_IsBool(result) && JS_VALUE_GET_BOOL(result));
    JS_FreeValue(ctx, result);

    static const char builtin_source[] =
        "import { on } from 'evbus';\n"
        "globalThis.unexpectedBuiltinEsm = on;\n";
    result = eval_module(ctx, "<non-esm-builtin>", builtin_source);
    assert(JS_IsException(result));
    clear_exception(ctx);
    assert(capability.calls == 1);
    assert(capability.saw_module_load);
    assert(capability.saw_evbus_resource);

    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    TJS_FreeRuntime(runtime);
}

int main(void) {
    test_runtime(1);
    test_runtime(2);
    return 0;
}
