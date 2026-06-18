
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
#include <stdint.h>

typedef struct TJSRuntime TJSRuntime;
typedef struct TJSApp App;

/* External native module ABI.
 *
 * A loadable `.so`/`.dll` must export a single function:
 *
 *     TJS_EXPORT const TJSModuleInfo *tjs_module_info(void);
 *
 * Use the DEF_MODULE() macro below to declare it.  The loader validates
 * `abi_version` against TJS_ABI_VERSION before reading any other field,
 * so adding fields in future versions does not break old `.so`s.
 */
#define TJS_ABI_VERSION 1u

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

typedef struct TJSModuleInfo {
    uint32_t abi_version;
    const char *name;
    void (*init)(JSContext *ctx, JSValue ns);
    bool worker_safe;
} TJSModuleInfo;

#define DEF_MODULE(_name, _entry, _worker_safe)                            \
    TJS_EXPORT const TJSModuleInfo *tjs_module_info(void) {                \
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
EXPORT void TJS_Initialize(int argc, char **argv);
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
#endif
