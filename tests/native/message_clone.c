#include "message_clone.h"
#include "tjs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define assert(expr) do {                                                    \
    if (!(expr)) {                                                           \
        fprintf(stderr, "assertion failed: %s (%s:%d)\n", #expr,           \
                __FILE__, __LINE__);                                         \
        abort();                                                             \
    }                                                                        \
} while (0)

static JSValue eval(JSContext *ctx, const char *source) {
    return JS_Eval(ctx, source, strlen(source), "<message-clone-test>",
                   JS_EVAL_TYPE_GLOBAL);
}

static void discard_unread(void) {
    TJSRuntime *runtime = TJS_NewRuntimeWorker();
    JSContext *ctx = TJS_GetMainContext(runtime);
    JSValue value = eval(ctx,
        "({sab: new SharedArrayBuffer(32), ab: new ArrayBuffer(16)})");
    JSValue ab = JS_GetPropertyStr(ctx, value, "ab");
    JSValue transfers = JS_NewArray(ctx);
    assert(JS_SetPropertyUint32(ctx, transfers, 0,
                               JS_DupValue(ctx, ab)) >= 0);
    TJSMessageClone *clone =
        tjs__message_clone_prepare(ctx, value, transfers);
    assert(clone && tjs__message_clone_commit(ctx, clone) == 0);
    JS_FreeValue(ctx, transfers);
    JS_FreeValue(ctx, ab);
    JS_FreeValue(ctx, value);
    TJS_FreeRuntime(runtime);
    tjs__message_clone_free(clone);
}

int main(void) {
    TJSRuntime *source_runtime = TJS_NewRuntimeWorker();
    JSContext *source = TJS_GetMainContext(source_runtime);
    assert(source_runtime && source);

    JSValue value = eval(source,
        "globalThis.ab = new ArrayBuffer(16);"
        "new Uint8Array(ab)[3] = 77;"
        "globalThis.sab = new SharedArrayBuffer(8);"
        "new Uint8Array(sab)[2] = 55;"
        "({ nested: [1, 2, 3], ab, sab })");
    assert(!JS_IsException(value));
    JSValue global = JS_GetGlobalObject(source);
    JSValue ab = JS_GetPropertyStr(source, global, "ab");
    JSValue transfers = JS_NewArray(source);
    assert(JS_SetPropertyUint32(source, transfers, 0,
                               JS_DupValue(source, ab)) >= 0);

    TJSMessageClone *clone =
        tjs__message_clone_prepare(source, value, transfers);
    assert(clone && tjs__message_clone_size(clone) > 0);
    assert(tjs__message_clone_transfer_count(clone) == 2);
    size_t attached_size = 0;
    assert(JS_GetArrayBuffer(source, &attached_size, ab) != NULL);
    assert(attached_size == 16);
    assert(tjs__message_clone_commit(source, clone) == 0);
    size_t detached_size = 99;
    assert(JS_GetArrayBuffer(source, &detached_size, ab) == NULL);
    assert(detached_size == 0);

    JS_FreeValue(source, transfers);
    JS_FreeValue(source, ab);
    JS_FreeValue(source, global);
    JS_FreeValue(source, value);
    TJS_FreeRuntime(source_runtime);

    TJSRuntime *target_runtime = TJS_NewRuntimeWorker();
    JSContext *target = TJS_GetMainContext(target_runtime);
    JSValue copied = tjs__message_clone_read(target, clone);
    assert(!JS_IsException(copied));
    JSValue target_global = JS_GetGlobalObject(target);
    assert(JS_SetPropertyStr(target, target_global, "copied", copied) >= 0);
    JSValue verified = eval(target,
        "copied.nested.join(',') === '1,2,3' &&"
        "new Uint8Array(copied.ab)[3] === 77 &&"
        "new Uint8Array(copied.sab)[2] === 55");
    assert(JS_IsBool(verified) && JS_VALUE_GET_BOOL(verified));
    JS_FreeValue(target, verified);
    JSValue twice = tjs__message_clone_read(target, clone);
    assert(JS_IsException(twice));
    JS_FreeValue(target, JS_GetException(target));
    JS_FreeValue(target, target_global);
    TJS_FreeRuntime(target_runtime);
    tjs__message_clone_free(clone);

    discard_unread();
    return 0;
}
