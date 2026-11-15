#include "private.h"

#include <assert.h>
#include <string.h>

/* Keep this standalone target meaningful in Release builds too. */
#undef assert
#define assert(expr) CHECK(expr)

static JSValue eval_function(JSContext *ctx, const char *source) {
    return JS_Eval(ctx, source, strlen(source), "<evbus-api-test>",
                   JS_EVAL_TYPE_GLOBAL);
}

static void set_global(JSContext *ctx, const char *name, JSValue value) {
    JSValue global = JS_GetGlobalObject(ctx);
    assert(!JS_IsException(global));
    assert(JS_SetPropertyStr(ctx, global, name, value) >= 0);
    JS_FreeValue(ctx, global);
}

static void clear_exception(JSContext *ctx) {
    assert(JS_HasException(ctx));
    JS_FreeValue(ctx, JS_GetException(ctx));
}

int main(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    assert(runtime != NULL);
    JSContext *ctx = runtime->main_ctx;
    assert(ctx != NULL);
    assert(JS_AddIntrinsicEval(ctx) == 0);

    JSValue evbus = JS_NewObject(ctx);
    assert(!JS_IsException(evbus));
    tjs__mod_evbus_init(ctx, evbus);
    assert(!JS_HasException(ctx));
    set_global(ctx, "evbus", evbus);

    JSValue setup = eval_function(
        ctx,
        "globalThis.nativePayload = { marker: 42 };\n"
        "globalThis.nativeCalls = [];\n"
        "globalThis.nativeOffFirst = evbus.on('native.test', 'message', value => {\n"
        "  nativeCalls.push(['first', value]);\n"
        "});\n"
        "globalThis.nativeOffSecond = evbus.on('native.test', 'message', value => {\n"
        "  nativeCalls.push(['second', value]);\n"
        "});");
    if (JS_IsException(setup)) TJS_DumpException(ctx);
    assert(!JS_IsException(setup));
    JS_FreeValue(ctx, setup);

    JSValue global = JS_GetGlobalObject(ctx);
    assert(!JS_IsException(global));
    JSValue payload = JS_GetPropertyStr(ctx, global, "nativePayload");
    assert(!JS_IsException(payload));

    JSValue result = TJS_EvBusEmit(ctx, "native.test", "missing", payload);
    assert(JS_IsBool(result) && !JS_VALUE_GET_BOOL(result));
    JS_FreeValue(ctx, result);

    result = TJS_EvBusEmit(ctx, "native.test", "message", payload);
    assert(JS_IsBool(result) && JS_VALUE_GET_BOOL(result));
    JS_FreeValue(ctx, result);

    JSValue verified = eval_function(
        ctx,
        "nativeCalls.length === 2 &&\n"
        "nativeCalls[0][0] === 'first' && nativeCalls[0][1] === nativePayload &&\n"
        "nativeCalls[1][0] === 'second' && nativeCalls[1][1] === nativePayload");
    assert(JS_IsBool(verified) && JS_VALUE_GET_BOOL(verified));
    JS_FreeValue(ctx, verified);

    JSValue error_setup = eval_function(
        ctx,
        "globalThis.nativeMarker = { from: 'listener' };\n"
        "globalThis.nativeLaterCalls = 0;\n"
        "globalThis.nativeOffThrow = evbus.on('native.test', 'throw', () => {\n"
        "  throw nativeMarker;\n"
        "});\n"
        "globalThis.nativeOffLater = evbus.on('native.test', 'throw', () => {\n"
        "  nativeLaterCalls++;\n"
        "});");
    if (JS_IsException(error_setup)) TJS_DumpException(ctx);
    assert(!JS_IsException(error_setup));
    JS_FreeValue(ctx, error_setup);

    result = TJS_EvBusEmit(ctx, "native.test", "throw", JS_UNDEFINED);
    assert(JS_IsException(result));
    JSValue exception = JS_GetException(ctx);
    JSValue marker = JS_GetPropertyStr(ctx, global, "nativeMarker");
    assert(JS_VALUE_GET_PTR(exception) == JS_VALUE_GET_PTR(marker));
    JS_FreeValue(ctx, exception);
    JS_FreeValue(ctx, marker);

    verified = eval_function(ctx, "nativeLaterCalls === 0");
    assert(JS_IsBool(verified) && JS_VALUE_GET_BOOL(verified));
    JS_FreeValue(ctx, verified);

    result = TJS_EvBusEmit(ctx, NULL, "event", JS_UNDEFINED);
    assert(JS_IsException(result));
    clear_exception(ctx);
    result = TJS_EvBusEmit(ctx, "namespace", NULL, JS_UNDEFINED);
    assert(JS_IsException(result));
    clear_exception(ctx);

    JSValue cleanup = eval_function(
        ctx,
        "nativeOffFirst(); nativeOffSecond(); nativeOffThrow(); nativeOffLater();\n"
        "nativePayload = nativeMarker = nativeOffFirst = nativeOffSecond =\n"
        "  nativeOffThrow = nativeOffLater = undefined;");
    assert(!JS_IsException(cleanup));
    JS_FreeValue(ctx, cleanup);
    JS_FreeValue(ctx, payload);
    JS_FreeValue(ctx, global);

    TJS_FreeRuntime(runtime);
    return 0;
}
