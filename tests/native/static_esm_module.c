#include "private.h"

#include <string.h>

static int init_count;

int cjs_test_native_esm_init_count(void) {
    return init_count;
}

void cjs_test_native_esm_init(JSContext *ctx, JSValue ns) {
    init_count++;

    JSValue singleton = JS_NewObject(ctx);
    if (JS_IsException(singleton)) return;
    if (JS_SetPropertyStr(ctx, singleton, "marker", JS_NewInt32(ctx, 42)) < 0) {
        JS_FreeValue(ctx, singleton);
        return;
    }
    if (JS_SetPropertyStr(ctx, ns, "singleton", singleton) < 0) return;

    static const char constructor_source[] = "(class NativeToken {})";
    JSValue constructor = JS_Eval(ctx, constructor_source,
                                  strlen(constructor_source),
                                  "<static-esm-constructor>",
                                  JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(constructor)) return;
    if (JS_SetPropertyStr(ctx, ns, "NativeToken", constructor) < 0) return;

    JS_SetPropertyStr(ctx, ns, "initCount", JS_NewInt32(ctx, init_count));
}
