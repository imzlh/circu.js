#include "private.h"

static void (*const module_inits[])(JSContext *, JSValue) = {
    tjs__mod_algorithm_init,
    tjs__mod_asyncfs_init,
#ifdef CJS_HAVE_BROTLI
    tjs__mod_brotli_init,
#endif
    tjs__mod_crypto_init,
    tjs__mod_curl_init,
    tjs__mod_debug_init,
    tjs__mod_dns_init,
    tjs__mod_engine_init,
    tjs__mod_ffi_init,
    tjs__mod_fswatch_init,
    tjs__mod_http_init,
    tjs__mod_nodeapi_init,
    tjs__mod_signals_init,
    tjs__mod_socket_init,
    tjs__mod_sqlite3_init,
    tjs__mod_ssl_init,
    tjs__mod_streams_init,
#ifdef CJS__HAS_ICONV
    tjs__mod_text_init,
#endif
    tjs__mod_udp_init,
#ifdef CJS__HAS_WASM
    tjs__mod_wasm_init,
#endif
#ifdef _WIN32
    tjs__mod_win32_init,
#endif
    tjs__mod_xml_init,
    tjs__mod_zlib_init,
};

enum { CLASS_ID_LIMIT = UINT16_MAX + 1 };

typedef struct {
    bool registered[CLASS_ID_LIMIT];
    JSClassID rng_class;
} ClassSnapshot;

static JSValue init_modules(JSContext *ctx, bool reverse) {
    JSValue rng = JS_UNDEFINED;
    for (size_t i = 0; i < countof(module_inits); i++) {
        size_t index = reverse ? countof(module_inits) - 1 - i : i;
        JSValue ns = JS_NewObject(ctx);
        CHECK(!JS_IsException(ns));
        module_inits[index](ctx, ns);
        CHECK(!JS_HasException(ctx));
        if (module_inits[index] == tjs__mod_algorithm_init) {
            JSValue ctor = JS_GetPropertyStr(ctx, ns, "XoshiroRNG");
            JSValue seed = JS_NewInt32(ctx, 42);
            rng = JS_CallConstructor(ctx, ctor, 1, &seed);
            CHECK(!JS_IsException(rng));
            JS_FreeValue(ctx, ctor);
        }
        JS_FreeValue(ctx, ns);
    }
    CHECK(JS_IsObject(rng));
    return rng;
}

static JSValue call_method(JSContext *ctx, JSValue obj, const char *name) {
    JSValue method = JS_GetPropertyStr(ctx, obj, name);
    CHECK(JS_IsFunction(ctx, method));
    JSValue result = JS_Call(ctx, method, obj, 0, NULL);
    CHECK(!JS_IsException(result));
    JS_FreeValue(ctx, method);
    return result;
}

static void check_rng(JSContext *ctx, JSValue rng) {
    JSValue clone = call_method(ctx, rng, "clone");
    CHECK_EQ(JS_GetClassID(clone), JS_GetClassID(rng));
    JSValue first = call_method(ctx, rng, "nextDouble");
    JSValue second = call_method(ctx, clone, "nextDouble");
    double first_number, second_number;
    CHECK_EQ(JS_ToFloat64(ctx, &first_number, first), 0);
    CHECK_EQ(JS_ToFloat64(ctx, &second_number, second), 0);
    CHECK_EQ(first_number, second_number);
    JS_FreeValue(ctx, first);
    JS_FreeValue(ctx, second);
    JS_FreeValue(ctx, clone);
}

static void check_reverse_runtime(void *opaque) {
    const ClassSnapshot *snapshot = opaque;
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = JS_NewContext(runtime->rt);
    CHECK(ctx);
    JSValue rng = init_modules(ctx, true);
    CHECK_EQ(JS_GetClassID(rng), snapshot->rng_class);
    for (JSClassID id = 1; id < CLASS_ID_LIMIT; id++)
        CHECK_EQ(JS_IsRegisteredClass(runtime->rt, id), snapshot->registered[id]);
    check_rng(ctx, rng);
    JS_FreeValue(ctx, rng);
    JS_FreeContext(ctx);
    TJS_FreeRuntime(runtime);
}

int main(void) {
    TJSRuntime *first = TJS_NewRuntime();
    CHECK(first);
    JSValue rng = init_modules(first->main_ctx, false);
    ClassSnapshot snapshot = { .rng_class = JS_GetClassID(rng) };
    for (JSClassID id = 1; id < CLASS_ID_LIMIT; id++)
        snapshot.registered[id] = JS_IsRegisteredClass(first->rt, id);

    JSValue repeated_rng = init_modules(first->main_ctx, true);
    CHECK_EQ(JS_GetClassID(repeated_rng), snapshot.rng_class);
    for (JSClassID id = 1; id < CLASS_ID_LIMIT; id++)
        CHECK_EQ(JS_IsRegisteredClass(first->rt, id), snapshot.registered[id]);
    check_rng(first->main_ctx, repeated_rng);
    JS_FreeValue(first->main_ctx, repeated_rng);

    check_reverse_runtime(&snapshot);
    check_rng(first->main_ctx, rng);

    /* TLS class IDs would allocate a different set on this thread. */
    uv_thread_t thread;
    CHECK_EQ(uv_thread_create(&thread, check_reverse_runtime, &snapshot), 0);
    CHECK_EQ(uv_thread_join(&thread), 0);
    check_rng(first->main_ctx, rng);

    JS_FreeValue(first->main_ctx, rng);
    TJS_FreeRuntime(first);
    return 0;
}
