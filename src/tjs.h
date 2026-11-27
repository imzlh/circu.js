
/*
 * QuickJS libuv bindings
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TJS_H
#define TJS_H

#ifdef FOREIGN_QJS
#include <quickjs.h>
#else
#include "../deps/quickjs/quickjs.h"
#endif

#include <uv.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TJSRuntime TJSRuntime;
typedef struct TJSApp App;
typedef struct TJSRuntimeCleanup TJSRuntimeCleanup;

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/* v2 adds the runtime-cleanup registration exports below.  Extensions that
 * use them must not load into a v1 host, whose dynamic loader cannot provide
 * those symbols. */
#define TJS_ABI_VERSION 2u

/* Capability hook ABI: one category bit (high 16) plus operation bits (low 16);
 * strings and JS values are borrowed for the duration of the hook. */
#define TJS_CAPABILITY_ABI_VERSION 1u

typedef uint32_t TJSCapabilityMask;
typedef struct TJSCapability TJSCapability;

#define TJS_CAP_CATEGORY_MASK  UINT32_C(0xffff0000)
#define TJS_CAP_OPERATION_MASK UINT32_C(0x0000ffff)
#define TJS_CAP_CATEGORY(mask) ((TJSCapabilityMask)(mask) & TJS_CAP_CATEGORY_MASK)
#define TJS_CAP_OPERATIONS(mask) ((TJSCapabilityMask)(mask) & TJS_CAP_OPERATION_MASK)
#define TJS_CAP_CATEGORY_BIT(index) (UINT32_C(1) << (16u + (index)))

enum {
    TJS_CAP_IO_ACCESS  = UINT32_C(1) << 0,
    TJS_CAP_IO_READ    = UINT32_C(1) << 1,
    TJS_CAP_IO_WRITE   = UINT32_C(1) << 2,
    TJS_CAP_IO_WATCH   = UINT32_C(1) << 3,
    TJS_CAP_IO_CONNECT = UINT32_C(1) << 4,
    TJS_CAP_IO_LISTEN  = UINT32_C(1) << 5,
    TJS_CAP_IO_CONTROL = UINT32_C(1) << 6,

    TJS_CAP_IO      = TJS_CAP_CATEGORY_BIT(0),
    TJS_CAP_ENV     = TJS_CAP_CATEGORY_BIT(1),
    TJS_CAP_PROCESS = TJS_CAP_CATEGORY_BIT(2),
    TJS_CAP_OS      = TJS_CAP_CATEGORY_BIT(3),
    TJS_CAP_NETWORK = TJS_CAP_CATEGORY_BIT(4),
    TJS_CAP_DYNLIB  = TJS_CAP_CATEGORY_BIT(5),
    TJS_CAP_WORKER  = TJS_CAP_CATEGORY_BIT(6),
    TJS_CAP_WIN32   = TJS_CAP_CATEGORY_BIT(7),
    TJS_CAP_POSIX   = TJS_CAP_CATEGORY_BIT(8),
    TJS_CAP_DEBUG   = TJS_CAP_CATEGORY_BIT(9),
    TJS_CAP_SHM     = TJS_CAP_CATEGORY_BIT(10),
    TJS_CAP_CONSOLE = TJS_CAP_CATEGORY_BIT(11),
};

enum {
    TJS_CAP_FLAG_REPLACEABLE = UINT32_C(1) << 0,
    TJS_CAP_FLAG_ASYNC       = UINT32_C(1) << 1,
};

typedef enum TJSConsoleStream {
    TJS_CONSOLE_STDOUT = 1,
    TJS_CONSOLE_STDERR,
} TJSConsoleStream;

typedef struct TJSCapabilityConsoleDetailsV1 {
    uint32_t stream;
    uint32_t argc;
    JSValueConst *argv;
} TJSCapabilityConsoleDetailsV1;

/* This type is part of the frozen v1 prefix. Do not add members: future
 * details must be appended to TJSCapability or introduced by a new ABI. */
typedef union TJSCapabilityDetailsV1 {
    /* Optional for every non-console category. The meaning follows the
     * category and api; NULL means no useful name is available. */
    const char *resource;
    /* TJS_CAP_CONSOLE. */
    TJSCapabilityConsoleDetailsV1 console;
} TJSCapabilityDetailsV1;

struct TJSCapability {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t flags;
    TJSCapabilityMask mask;
    const char *api;
    TJSCapabilityDetailsV1 details;
};

/* ABI freeze: validators must use this v1 prefix, never a future sizeof. */
#define TJS_CAPABILITY_V1_SIZE \
    (offsetof(TJSCapability, details) + sizeof(TJSCapabilityDetailsV1))

typedef JSValue (*TJSCapabilityHook)(JSContext *ctx,
                                     const TJSCapability *capability,
                                     void *userdata);

/* PASS continues, JS_EXCEPTION aborts, an owned JSValue replaces a
 * REPLACEABLE descriptor (async values returned unwrapped). */
#define TJS_CAPABILITY_PASS JS_UNINITIALIZED

enum {
    /* PASS promises no user JS, no re-entry into libcjs, and no mutation of
     * state the pending native operation relies on. */
    TJS_CAPABILITY_HOOK_PASS_IS_STABLE = UINT32_C(1) << 0,
};

EXPORT bool TJS_SetCapabilityHook(TJSRuntime *runtime,
                                  TJSCapabilityHook hook,
                                  void *userdata,
                                  uint32_t hook_flags);
EXPORT JSValue TJS_CheckCapability(JSContext *ctx,
                                   const TJSCapability *capability);

/* Synchronously publish a borrowed payload to the runtime-local event bus.
 * The namespace and event are non-NULL, NUL-terminated UTF-8 strings. The
 * returned JSValue is owned by the caller: it is true when at least one
 * listener was snapshotted, false otherwise, or JS_EXCEPTION when dispatch
 * failed. This API must be called on the thread that owns ctx. */
EXPORT JSValue TJS_EvBusEmit(JSContext *ctx,
                             const char *namespace_name,
                             const char *event_name,
                             JSValueConst payload);


typedef struct TJSModuleInfo {
    uint32_t abi_version;
    const char *name;
    void (*init)(JSContext *ctx, JSValue ns);
    bool worker_safe;
} TJSModuleInfo;

#define DEF_MODULE(_name, _entry, _worker_safe)                            \
    EXPORT const TJSModuleInfo *tjs_module_info(void) {                \
        static const TJSModuleInfo _tjs_module_info_inst = {               \
            .abi_version = TJS_ABI_VERSION,                                \
            .name = (_name),                                               \
            .init = (_entry),                                              \
            .worker_safe = (_worker_safe),                                 \
        };                                                                 \
        return &_tjs_module_info_inst;                                     \
    }

typedef struct TJSRunOptions {
    int mem_limit;
    size_t stack_size;
} TJSRunOptions;

EXPORT void TJS_DefaultOptions(TJSRunOptions *options);
EXPORT TJSRuntime *TJS_NewRuntime(void);
EXPORT TJSRuntime *TJS_NewRuntimeOptions(TJSRunOptions *options);
EXPORT App* TJS_NewApp(TJSRuntime* trt);
EXPORT void TJS_FreeRuntime(TJSRuntime *qrt);
EXPORT TJSRuntimeCleanup *TJS_AddRuntimeCleanup(TJSRuntime *runtime,
                                                void (*callback)(void *), void *opaque);
/* A token may be removed once; removal invalidates it. A cleanup callback may
 * remove its own token. Tokens still registered are reclaimed with the runtime. */
EXPORT void TJS_RemoveRuntimeCleanup(TJSRuntimeCleanup *cleanup);
EXPORT void TJS_Initialize(int argc, char **argv);
/* Borrowed main context. It is owned by runtime and may only be used from the
 * runtime's owner thread. */
EXPORT JSContext *TJS_GetMainContext(TJSRuntime *runtime);
EXPORT JSContext *TJS_GetJSContext(App *app);
EXPORT TJSRuntime *TJS_GetRuntime(JSContext *ctx);
EXPORT App *TJS_GetApp(JSContext *ctx);
EXPORT int TJS_Run(TJSRuntime *qrt);
EXPORT void TJS_Stop(TJSRuntime *qrt);

EXPORT uv_loop_t *TJS_GetLoop(TJSRuntime *qrt);
EXPORT TJSRuntime *TJS_NewRuntimeWorker(void);
EXPORT TJSRuntime *TJS_NewRuntimeInternal(bool is_worker, TJSRunOptions *options);
EXPORT JSValue TJS_EvalScript(JSContext *ctx, const char *filename);
EXPORT JSValue TJS_EvalModule(JSContext *ctx, const char *filename, bool is_main);
EXPORT JSValue TJS_EvalModuleContent(JSContext *ctx,
                              const char *filename,
                              bool is_main,
                              bool use_realpath,
                              const char *content,
                              size_t len);

EXPORT void TJS_DumpValue(JSContext *ctx, FILE *f, JSValue val);
EXPORT void TJS_DumpException(JSContext *ctx);

#ifdef __cplusplus
}
#endif

#endif
