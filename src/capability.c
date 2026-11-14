/*
 * circu.js capability hook core
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

#include "private.h"
#include "capability.h"

_Atomic uint32_t tjs__capability_hook_count;

_Static_assert(TJS_CAPABILITY_V1_SIZE == sizeof(TJSCapability),
               "capability ABI v1 prefix must cover TJSCapability");

static bool tjs__capability_mask_valid(TJSCapabilityMask mask) {
    TJSCapabilityMask operations = TJS_CAP_OPERATIONS(mask);

    if (operations == 0 ||
        (operations & ~(TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ |
                        TJS_CAP_IO_WRITE | TJS_CAP_IO_WATCH |
                        TJS_CAP_IO_CONNECT | TJS_CAP_IO_LISTEN |
                        TJS_CAP_IO_CONTROL)) != 0) {
        return false;
    }

    switch (TJS_CAP_CATEGORY(mask)) {
        case TJS_CAP_IO:
        case TJS_CAP_ENV:
        case TJS_CAP_PROCESS:
        case TJS_CAP_OS:
        case TJS_CAP_NETWORK:
        case TJS_CAP_DYNLIB:
        case TJS_CAP_WORKER:
        case TJS_CAP_WIN32:
        case TJS_CAP_POSIX:
        case TJS_CAP_DEBUG:
        case TJS_CAP_SHM:
        case TJS_CAP_CONSOLE:
            return true;
        default:
            return false;
    }
}

static bool tjs__capability_details_valid(const TJSCapability *capability) {
    if (TJS_CAP_CATEGORY(capability->mask) != TJS_CAP_CONSOLE) return true;

    return capability->details.console.stream >= TJS_CONSOLE_STDOUT &&
           capability->details.console.stream <= TJS_CONSOLE_STDERR &&
           (capability->details.console.argc == 0 ||
            capability->details.console.argv != NULL);
}

bool TJS_SetCapabilityHook(TJSRuntime *runtime,
                           TJSCapabilityHook hook,
                           void *userdata,
                           uint32_t hook_flags) {
    if (!runtime || runtime->freeing ||
        (hook_flags & ~TJS_CAPABILITY_HOOK_PASS_IS_STABLE) != 0) {
        return false;
    }

    bool had_hook = runtime->capability_hook != NULL;
    runtime->capability_hook = hook;
    runtime->capability_userdata = hook ? userdata : NULL;
    runtime->capability_hook_flags = hook ? hook_flags : 0;
    if (had_hook == (hook != NULL)) return true;

    if (hook) {
        atomic_fetch_add_explicit(&tjs__capability_hook_count, 1,
                                  memory_order_relaxed);
    } else {
        uint32_t previous = atomic_fetch_sub_explicit(
            &tjs__capability_hook_count, 1, memory_order_relaxed);
        CHECK_GT(previous, 0);
    }
    return true;
}

uint32_t tjs__capability_runtime_state(JSContext *ctx) {
    TJSRuntime *runtime = TJS_GetRuntime(ctx);
    if (!runtime || runtime->freeing || !runtime->capability_hook ||
        runtime->capability_hook_depth != 0) {
        return 0;
    }
    return TJS__CAPABILITY_CALL |
           ((runtime->capability_hook_flags &
             TJS_CAPABILITY_HOOK_PASS_IS_STABLE)
                ? 0
                : TJS__CAPABILITY_REVALIDATE);
}

/* This is the active half of the internal dispatch. TJS_CAPABILITY performs
 * the gate before evaluating its check expression, while the public checker
 * gates after validating an external descriptor. Keeping the gate out of this
 * function avoids two runtime lookups for every hook invocation. */
static JSValue tjs__capability_dispatch_active(
    JSContext *ctx,
    const TJSCapability *capability) {
    TJSRuntime *runtime = TJS_GetRuntime(ctx);
    TJSCapabilityHook hook = runtime->capability_hook;
    void *userdata = runtime->capability_userdata;
    runtime->capability_hook_depth++;
    JSValue result = hook(ctx, capability, userdata);
    runtime->capability_hook_depth--;

    if (!JS_IsException(result) && JS_HasException(ctx)) {
        if (!JS_IsUninitialized(result)) JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    if (JS_IsUninitialized(result)) {
        if (JS_VALUE_GET_INT(result) == 0) return result;
        return JS_ThrowTypeError(ctx,
                                 "capability hook returned an invalid PASS value");
    }
    if (JS_IsException(result)) {
        if (!JS_HasException(ctx)) {
            JS_ThrowTypeError(ctx,
                              "capability hook returned JS_EXCEPTION without throwing");
        }
        return JS_EXCEPTION;
    }
    if (!(capability->flags & TJS_CAP_FLAG_REPLACEABLE)) {
        JS_FreeValue(ctx, result);
        return JS_ThrowTypeError(ctx,
                                 "capability event does not support replacement");
    }
    return result;
}

JSValue TJS_CheckCapability(JSContext *ctx,
                            const TJSCapability *capability) {
    if (!ctx || !capability) {
        if (ctx) JS_ThrowTypeError(ctx, "invalid capability descriptor");
        return JS_EXCEPTION;
    }

    /* Native entry points must propagate argument conversion failures before
     * entering an embedder hook. Never replace an exception already pending. */
    if (JS_HasException(ctx)) return JS_EXCEPTION;

    if (capability->abi_version != TJS_CAPABILITY_ABI_VERSION ||
        capability->struct_size < TJS_CAPABILITY_V1_SIZE ||
        (capability->flags & ~(TJS_CAP_FLAG_REPLACEABLE |
                               TJS_CAP_FLAG_ASYNC)) != 0 ||
        capability->api == NULL || capability->api[0] == '\0' ||
        !tjs__capability_mask_valid(capability->mask) ||
        !tjs__capability_details_valid(capability)) {
        return JS_ThrowTypeError(ctx, "invalid capability descriptor");
    }

    /* The hook is trusted embedder code. Let it use libcjs for diagnostics
     * without recursively entering itself. Native entry points must still
     * tolerate the state changes caused by such a nested call. */
    if (tjs__capability_call_state(ctx) == 0) return TJS_CAPABILITY_PASS;

    return tjs__capability_dispatch_active(ctx, capability);
}

JSValue tjs__capability(JSContext *ctx,
                        TJSCapabilityMask mask,
                        uint32_t flags,
                        const char *api) {
    const TJSCapability capability = {
        .abi_version = TJS_CAPABILITY_ABI_VERSION,
        .struct_size = sizeof(capability),
        .flags = flags,
        .mask = mask,
        .api = api,
    };
    return tjs__capability_dispatch_active(ctx, &capability);
}

JSValue tjs__capability_resource(JSContext *ctx,
                                 TJSCapabilityMask mask,
                                 uint32_t flags,
                                 const char *api,
                                 const char *resource) {
    const TJSCapability capability = {
        .abi_version = TJS_CAPABILITY_ABI_VERSION,
        .struct_size = sizeof(capability),
        .flags = flags,
        .mask = mask,
        .api = api,
        .details.resource = resource,
    };
    return tjs__capability_dispatch_active(ctx, &capability);
}

JSValue tjs__capability_console(JSContext *ctx,
                                const char *api,
                                uint32_t stream,
                                int argc,
                                JSValueConst *argv) {
    const TJSCapability capability = {
        .abi_version = TJS_CAPABILITY_ABI_VERSION,
        .struct_size = sizeof(capability),
        .flags = TJS_CAP_FLAG_REPLACEABLE,
        .mask = TJS_CAP_CONSOLE | TJS_CAP_IO_WRITE,
        .api = api,
        .details.console = {
            .stream = stream,
            .argc = argc < 0 ? 0u : (uint32_t)argc,
            .argv = argv,
        },
    };
    return tjs__capability_dispatch_active(ctx, &capability);
}

bool tjs__capability_require_io(JSContext *ctx,
                                TJSCapabilityMask mask,
                                const char *api,
                                const char *path) {
    if (!ctx || JS_HasException(ctx)) return false;
    if (tjs__capability_call_state(ctx) == 0) return true;

    JSValue result = tjs__capability_io(ctx, mask, 0, api, path);
    if (JS_IsUninitialized(result)) return true;

    /* A non-replaceable descriptor makes every non-PASS result exceptional.
     * Keep this defensive branch so a future checker change cannot leak it. */
    if (!JS_IsException(result)) JS_FreeValue(ctx, result);
    return false;
}
