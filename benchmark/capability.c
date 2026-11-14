#include "capability.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct BenchmarkState {
    JSValue pass;
    uint64_t calls;
} BenchmarkState;

static JSValue benchmark_hook(JSContext *ctx,
                              const TJSCapability *capability,
                              void *userdata) {
    BenchmarkState *state = userdata;
    (void) ctx;
    (void) capability;
    state->calls++;
    return state->pass;
}

static JSValue benchmark_probe(JSContext *ctx,
                               uint64_t iterations,
                               uint64_t *evaluated,
                               uint64_t *revalidated,
                               uint32_t revalidation_work) {
    for (uint64_t i = 0; i < iterations; i++) {
        TJS_CAPABILITY_REVALIDATE(
            (++*evaluated,
             tjs__capability(ctx,
                             TJS_CAP_IO | TJS_CAP_IO_ACCESS,
                             TJS_CAP_FLAG_REPLACEABLE,
                             "benchmark.capability")),
            abort(),
            do {
                for (uint32_t j = 0; j < revalidation_work; j++) {
                    *revalidated += TJS_GetRuntime(ctx) != NULL;
                }
            } while (0));
    }
    return JS_UNDEFINED;
}

static void run_case(const char *name,
                     TJSRuntime *runtime,
                     JSContext *ctx,
                     BenchmarkState *state,
                     JSValue pass,
                     uint64_t iterations,
                     uint32_t revalidation_work) {
    state->pass = pass;
    state->calls = 0;
    uint64_t evaluated = 0;
    uint64_t revalidated = 0;

    uint64_t warmup_iterations = iterations / 20 + 1;
    benchmark_probe(ctx, warmup_iterations, &evaluated, &revalidated,
                    revalidation_work);
    state->calls = 0;
    evaluated = 0;
    revalidated = 0;

    uint64_t start = uv_hrtime();
    benchmark_probe(ctx, iterations, &evaluated, &revalidated,
                    revalidation_work);
    uint64_t elapsed = uv_hrtime() - start;

    printf("%-12s %9.2f ns/op  calls=%" PRIu64
           " evaluated=%" PRIu64 " revalidated=%" PRIu64 "\n",
           name,
           (double) elapsed / (double) iterations,
           state->calls,
           evaluated,
           revalidated);

    (void) runtime;
}

int main(int argc, char **argv) {
    uint64_t iterations = UINT64_C(10000000);
    if (argc > 1) {
        char *end;
        iterations = strtoull(argv[1], &end, 10);
        if (*end != '\0' || iterations == 0) {
            fprintf(stderr, "usage: %s [positive-iterations]\n", argv[0]);
            return 2;
        }
    }

    TJSRuntime *runtime = TJS_NewRuntime();
    App *app = runtime ? TJS_NewApp(runtime) : NULL;
    JSContext *ctx = app ? TJS_GetJSContext(app) : NULL;
    if (!ctx) return 1;

    BenchmarkState state = { 0 };
    run_case("no-hook", runtime, ctx, &state, TJS_CAPABILITY_PASS,
             iterations, 4);

    TJS_SetCapabilityHook(runtime, benchmark_hook, &state, 0);
    run_case("pass", runtime, ctx, &state, TJS_CAPABILITY_PASS,
             iterations, 4);
    TJS_SetCapabilityHook(runtime, benchmark_hook, &state,
                          TJS_CAPABILITY_HOOK_PASS_IS_STABLE);
    run_case("stable-hook", runtime, ctx, &state, TJS_CAPABILITY_PASS,
             iterations, 4);

    TJS_FreeRuntime(runtime);
    return 0;
}
