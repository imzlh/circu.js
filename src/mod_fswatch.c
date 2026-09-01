/*
 * circu.js
 *
 * Copyright (c) 2022-present Saúl Ibarra Corretgé <s@saghul.net>
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

#include "mem.h"
#include "private.h"
#include "utils.h"

typedef struct {
    JSContext *ctx;
    uv_fs_event_t handle;
    JSValue callback;
    JSValue this_val;
    int closed;
    int finalized;
} TJSFsWatch;

static thread_local JSClassID tjs_fswatch_class_id;

static TJSFsWatch *tjs_fswatch_get(JSValue obj) {
    return JS_GetOpaque(obj, tjs_fswatch_class_id);
}

static void fswatch_release_callback(JSContext *ctx, TJSFsWatch *fw) {
    JSValue callback = fw->callback;
    fw->callback = JS_UNDEFINED;
    JS_FreeValue(ctx, callback);
}

static void fswatch_release_callback_rt(JSRuntime *rt, TJSFsWatch *fw) {
    JSValue callback = fw->callback;
    fw->callback = JS_UNDEFINED;
    JS_FreeValueRT(rt, callback);
}

/* Drop the native self-pin. Clearing first is essential: releasing the value
 * can synchronously run the class finalizer and free `fw`. */
static void fswatch_release_self(JSContext *ctx, TJSFsWatch *fw) {
    JSValue self = fw->this_val;
    if (JS_IsUndefined(self)) return;
    fw->this_val = JS_UNDEFINED;
    JS_FreeValue(ctx, self);
}

static void fswatch_release_self_rt(JSRuntime *rt, TJSFsWatch *fw) {
    JSValue self = fw->this_val;
    if (JS_IsUndefined(self)) return;
    fw->this_val = JS_UNDEFINED;
    JS_FreeValueRT(rt, self);
}

static void uv__fsevent_close_cb(uv_handle_t *handle) {
    TJSFsWatch *fw = handle->data;
    if (fw) {
        fw->closed = 1;
        if (fw->finalized) {
            tjs__free(fw);
        }
    }
}

static void maybe_close(TJSFsWatch *fw) {
    if (!fw->closed && !uv_is_closing((uv_handle_t *) &fw->handle)) {
        uv_close((uv_handle_t *) &fw->handle, uv__fsevent_close_cb);
    }
}

static void tjs_fswatch_finalizer(JSRuntime *rt, JSValue val) {
    TJSFsWatch *fw = tjs_fswatch_get(val);
    if (fw) {
        /* The wrapper itself is being finalized; its self-pin is consumed by
         * the finalizer and must not be freed recursively. */
        fw->this_val = JS_UNDEFINED;
        fswatch_release_callback_rt(rt, fw);
        fw->finalized = 1;
        if (fw->closed) {
            tjs__free(fw);
        } else {
            maybe_close(fw);
        }
    }
}

static void tjs_fswatch_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSFsWatch *fw = tjs_fswatch_get(val);
    if (fw) {
        JS_MarkValue(rt, fw->callback, mark_func);
        JS_MarkValue(rt, fw->this_val, mark_func);
    }
}

static JSClassDef tjs_fswatch_class = {
    "FsWatcher",
    .finalizer = tjs_fswatch_finalizer,
    .gc_mark = tjs_fswatch_mark,
};

static JSValue tjs_fswatch_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSFsWatch *fw = tjs_fswatch_get(this_val);
    if (!fw) {
        return JS_EXCEPTION;
    }
    maybe_close(fw);

    /* No future event callback can use the function once close was requested. */
    fswatch_release_callback(ctx, fw);

    /* Release the GC-prevention self-reference so the object can be collected. */
    fswatch_release_self(ctx, fw);

    return JS_UNDEFINED;
}

static JSValue tjs_fswatch_path_get(JSContext *ctx, JSValue this_val) {
    TJSFsWatch *fw = tjs_fswatch_get(this_val);
    if (!fw) {
        return JS_UNDEFINED;
    }

    char buf[1024];
    size_t size = sizeof(buf);
    char *dbuf = buf;
    int r;

    r = uv_fs_event_getpath(&fw->handle, dbuf, &size);
    if (r != 0) {
        if (r != UV_ENOBUFS) {
            return tjs_throw_errno(ctx, r);
        }
        dbuf = js_malloc(ctx, size);
        if (!dbuf) {
            return JS_EXCEPTION;
        }
        r = uv_fs_event_getpath(&fw->handle, dbuf, &size);
        if (r != 0) {
            js_free(ctx, dbuf);
            return tjs_throw_errno(ctx, r);
        }
    }

    JSValue ret = JS_NewStringLen(ctx, dbuf, size);

    if (dbuf != buf) {
        js_free(ctx, dbuf);
    }

    return ret;
}

static void uv__fs_event_cb(uv_fs_event_t *handle, const char *filename, int events, int status) {
    TJSFsWatch *fw = handle->data;
    CHECK_NOT_NULL(fw);
    JSContext *ctx = fw->ctx;

    JSRuntime *rt = ctx ? JS_GetRuntime(ctx) : NULL;
    TJSRuntime *qrt = rt ? JS_GetRuntimeOpaque(rt) : NULL;
    if (!qrt || qrt->freeing) {
        /* During runtime teardown no JS callback is allowed. */
        if (rt) fswatch_release_callback_rt(rt, fw);
        maybe_close(fw);
        if (rt) fswatch_release_self_rt(rt, fw);
        return;
    }

    // libuv reports watcher failures without an error callback in this API.
    if (status != 0) {
        maybe_close(fw);
        fswatch_release_callback(ctx, fw);
        fswatch_release_self(ctx, fw);
        return;
    }

    // libuv could set both, if we get rename, ignore change.

    JSValue event;
    if (events & UV_RENAME) {
        event = JS_NewString(ctx, "rename");
    } else if (events & UV_CHANGE) {
        event = JS_NewString(ctx, "change");
    } else {
        return;
    }

    /* libuv may pass filename == NULL (e.g. for some events); JS_NewString
     * would strlen(NULL) and crash, so guard it. */
    JSValue args[2] = {
        filename ? JS_NewString(ctx, filename) : JS_NULL,
        event,
    };

    tjs_call_handler(ctx, fw->callback, countof(args), args);

    JS_FreeValue(ctx, args[0]);
    JS_FreeValue(ctx, args[1]);
}

static JSValue tjs_fs_watch(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    const char *path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }

    if (!JS_IsFunction(ctx, argv[1])) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "no callback function provided");
    }

    JSValue obj = JS_NewObjectClass(ctx, tjs_fswatch_class_id);
    if (JS_IsException(obj)) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }

    TJSFsWatch *fw = tjs__mallocz(sizeof(*fw));
    if (!fw) {
        JS_FreeCString(ctx, path);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    fw->callback = JS_UNDEFINED;
    fw->this_val = JS_UNDEFINED;

    int r = uv_fs_event_init(tjs_get_loop(ctx), &fw->handle);
    if (r != 0) {
        JS_FreeCString(ctx, path);
        JS_FreeValue(ctx, obj);
        tjs__free(fw);
        return JS_ThrowInternalError(ctx, "couldn't initialize handle");
    }

    fw->ctx = ctx;
    fw->handle.data = fw;

    int recursive = 0;
    if (argc > 2) {
        recursive = JS_ToBool(ctx, argv[2]);
    }

    r = uv_fs_event_start(&fw->handle, uv__fs_event_cb, path, recursive ? UV_FS_EVENT_RECURSIVE : 0);
    if (r != 0) {
        JS_FreeCString(ctx, path);
        /* handle is registered with the loop; close before freeing memory. */
        fw->finalized = 1;
        uv_close((uv_handle_t *) &fw->handle, uv__fsevent_close_cb);
        JS_FreeValue(ctx, obj);
        return tjs_throw_errno(ctx, r);
    }

    JS_FreeCString(ctx, path);

    fw->handle.data = fw;
    fw->callback = JS_DupValue(ctx, argv[1]);

    JS_SetOpaque(obj, fw);

    /* Prevent GC while the watcher is active. */
    fw->this_val = JS_DupValue(ctx, obj);

    return obj;
}

static const JSCFunctionListEntry tjs_fswatch_proto_funcs[] = {
    TJS_CFUNC_DEF("close", 0, tjs_fswatch_close),
    JS_CGETSET_DEF("path", tjs_fswatch_path_get, NULL),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "FsWatcher", JS_PROP_CONFIGURABLE),
};

static const JSCFunctionListEntry tjs_fswatch_funcs[] = {
    TJS_CFUNC_DEF("watch", 3, tjs_fs_watch),
};

void tjs__mod_fswatch_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    JS_NewClassID(rt, &tjs_fswatch_class_id);
    JS_NewClass(rt, tjs_fswatch_class_id, &tjs_fswatch_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_fswatch_proto_funcs, countof(tjs_fswatch_proto_funcs));
    JS_SetClassProto(ctx, tjs_fswatch_class_id, proto);

    JS_SetPropertyFunctionList(ctx, ns, tjs_fswatch_funcs, countof(tjs_fswatch_funcs));
}
