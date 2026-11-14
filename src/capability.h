/*
 * circu.js capability hook helpers
 *
 * Copyright (c) 2026 iz
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TJS_CAPABILITY_H
#define TJS_CAPABILITY_H

#include "tjs.h"
#include "utils.h"

#include <stdatomic.h>

/* Process-wide count so the no-hook case is one relaxed load plus a branch. */
extern TJS__HIDDEN _Atomic uint32_t tjs__capability_hook_count;

enum {
    TJS__CAPABILITY_CALL = UINT32_C(1) << 0,
    TJS__CAPABILITY_REVALIDATE = UINT32_C(1) << 1,
};

/* Slow half of the gate below. It keeps TJSRuntime's private layout out of
 * this header and is reached only while some runtime has a hook installed. */
TJS__HIDDEN uint32_t tjs__capability_runtime_state(JSContext *ctx);

static TJS__ALWAYS_INLINE bool tjs__capability_hooks_active(void) {
    return atomic_load_explicit(&tjs__capability_hook_count,
                                memory_order_relaxed) != 0;
}

static TJS__ALWAYS_INLINE uint32_t tjs__capability_call_state(
    JSContext *ctx) {
    return tjs__capability_hooks_active()
               ? tjs__capability_runtime_state(ctx)
               : 0;
}

/* No-hook path skips check_ (zero overhead). REVALIDATE re-acquires state and
 * owns its cleanup (may return); GUARDED prepares before the hook. */
#define TJS_CAPABILITY(check_, cleanup_)                                  \
    do {                                                                  \
        uint32_t _tjs_capability_state = tjs__capability_call_state(ctx);  \
        if (TJS__UNLIKELY(_tjs_capability_state != 0)) {                  \
            JSValue _tjs_capability_result = (check_);                    \
            if (!JS_IsUninitialized(_tjs_capability_result)) {            \
                cleanup_;                                                 \
                return _tjs_capability_result;                            \
            }                                                             \
        }                                                                 \
    } while (0)

/* Not forwarded via a helper macro: commas in value constants or a `return
 * JS_EXCEPTION` argument would parse as extra macro arguments. */
#define TJS_CAPABILITY_REVALIDATE(check_, cleanup_, revalidate_)          \
    do {                                                                  \
        uint32_t _tjs_capability_state = tjs__capability_call_state(ctx);  \
        if (TJS__UNLIKELY(_tjs_capability_state != 0)) {                  \
            JSValue _tjs_capability_result = (check_);                    \
            if (!JS_IsUninitialized(_tjs_capability_result)) {            \
                cleanup_;                                                 \
                return _tjs_capability_result;                            \
            }                                                             \
            if (_tjs_capability_state & TJS__CAPABILITY_REVALIDATE) {     \
                revalidate_;                                              \
            }                                                             \
        }                                                                 \
    } while (0)

#define TJS_CAPABILITY_GUARDED(prepare_, check_, cleanup_, revalidate_)    \
    do {                                                                  \
        uint32_t _tjs_capability_state = tjs__capability_call_state(ctx);  \
        if (TJS__UNLIKELY(_tjs_capability_state != 0)) {                  \
            if (_tjs_capability_state & TJS__CAPABILITY_REVALIDATE) {     \
                prepare_;                                                 \
            }                                                             \
            JSValue _tjs_capability_result = (check_);                    \
            if (!JS_IsUninitialized(_tjs_capability_result)) {            \
                cleanup_;                                                 \
                return _tjs_capability_result;                            \
            }                                                             \
            if (_tjs_capability_state & TJS__CAPABILITY_REVALIDATE) {     \
                revalidate_;                                              \
            }                                                             \
        }                                                                 \
    } while (0)

TJS__HIDDEN JSValue tjs__capability(JSContext *ctx,
                                    TJSCapabilityMask mask,
                                    uint32_t flags,
                                    const char *api);
TJS__HIDDEN JSValue tjs__capability_resource(JSContext *ctx,
                                             TJSCapabilityMask mask,
                                             uint32_t flags,
                                             const char *api,
                                             const char *resource);
#define tjs__capability_io      tjs__capability_resource
#define tjs__capability_network tjs__capability_resource
#define tjs__capability_env     tjs__capability_resource
TJS__HIDDEN JSValue tjs__capability_console(JSContext *ctx,
                                            const char *api,
                                            uint32_t stream,
                                            int argc,
                                            JSValueConst *argv);
TJS__HIDDEN bool tjs__capability_require_io(JSContext *ctx,
                                            TJSCapabilityMask mask,
                                            const char *api,
                                            const char *path);

#endif
