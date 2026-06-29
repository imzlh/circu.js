/*
 * circu.js — Node-API (N-API) C ABI runtime on top of QuickJS
 *
 * Copyright (c) 2026-present iz
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 *
 * --------------------------------------------------------------------------
 * Design notes (see also AGENT.md / plan):
 *   - napi_value  == pointer to a JSValue slot owned by the current handle
 *     scope. Handle scopes are block-allocated linked lists so slot pointers
 *     stay stable across growth.
 *   - napi_env    == one per loaded addon, created in tjs__napi_dlopen and
 *     freed by a JS runtime finalizer registered on first use.
 *   - Exceptions follow the N-API "pending exception" model: napi_throw_*
 *     stash the value on env->pending_exception; the C-function trampoline
 *     re-throws into QuickJS when control returns to JS.
 *   - This whole module lives in a single translation unit on purpose: the
 *     napi_* symbols are only referenced dynamically by dlopen'd addons, so
 *     keeping them in one object file (pulled in via tjs__mod_nodeapi_init in
 *     the static module table) guarantees the linker keeps them in the host
 *     executable's dynamic symbol table.
 */

/* Request the full v9 surface from the public headers. Must precede includes. */
#define NAPI_VERSION 9

#include "private.h"
#include "tjs.h"
#include "mem.h"

#include <uv.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../deps/quickjs/list.h"

/* The public Node-API headers. We are the *host*, so we must NOT define
 * BUILDING_NODE_EXTENSION — that makes NAPI_EXTERN expand to the export
 * decoration (dllexport / visibility default) which is exactly what we want. */
#include "../deps/nodeapi/node_api.h"

/* ========================================================================== */
/* Internal structures                                                        */
/* ========================================================================== */

#define NAPI_HS_BLOCK 64

typedef struct napi_hs_block {
    struct napi_hs_block *next;
    size_t used;
    JSValue slots[NAPI_HS_BLOCK];
} napi_hs_block;

struct napi_handle_scope__ {
    struct napi_handle_scope__ *parent;
    napi_hs_block *head;       /* most-recently-allocated block */
    napi_env env;
    bool escapable;
    bool escape_called;
};

struct napi_env__ {
    JSContext *ctx;
    TJSRuntime *trt;
    uv_loop_t *loop;
    napi_extended_error_info last_error;
    JSValue pending_exception;        /* JS_UNINITIALIZED == none */
    napi_handle_scope open_scope;     /* top of the scope stack */
    napi_hs_block *orphan_handles;    /* handles created with no open scope */
    int api_version;                  /* from node_api_module_get_api_version_v1 */
    char *filename;                   /* module path, for node_api_get_module_file_name */
    int refcount;                     /* keepalive (async work, tsfn, refs) */
    bool registered_finalizer;
    bool cleanup_done;
    void *instance_data;
    napi_finalize instance_finalize_cb;
    void *instance_finalize_hint;
    struct list_head refs;            /* live napi_ref values owned by env */
    struct list_head tsfns;           /* live napi_threadsafe_function values */
    struct list_head cleanup_hooks;   /* napi_cleanup_hook entries */
    struct list_head async_cleanup_hooks;
    struct list_head link;            /* all envs, for runtime shutdown */
};

/* External / wrap carrier opaque (shared layout for napi_create_external,
 * napi_wrap and napi_add_finalizer carriers). */
typedef struct {
    napi_env env;
    void *data;
    napi_finalize finalize_cb;
    void *finalize_hint;
    /* optional type tag (napi_type_tag_object) */
    bool has_tag;
    napi_type_tag tag;
} napi_ext_payload;

/* C-function closure bundle, carried inside a func object's data. */
typedef struct {
    napi_env env;
    napi_callback cb;
    void *data;
} napi_cb_bundle;

struct napi_callback_info__ {
    JSContext *ctx;
    JSValueConst this_val;
    int argc;
    JSValueConst *argv;
    JSValueConst new_target;
    void *data;
};

struct napi_ref__ {
    napi_env env;
    JSValue value;            /* strong ref; retained when count>0 */
    JSValue weakref;          /* WeakRef object for object targets at count==0 */
    uint32_t count;
    bool ownership_es5;       /* unused; reserved */
    struct list_head link;
};

struct napi_deferred__ {
    napi_env env;
    JSValue resolve;
    JSValue reject;
};

struct napi_callback_scope__ {
    napi_handle_scope scope;
};

struct napi_async_context__ {
    napi_env env;
    JSValue resource;
    JSValue name;
};

struct napi_async_work__ {
    napi_env env;
    uv_work_t req;
    napi_async_execute_callback execute;
    napi_async_complete_callback complete;
    void *data;
    bool queued;
    bool done;
    bool cancelled;
};

typedef struct napi_tsfn_item {
    void *data;
    struct list_head link;
} napi_tsfn_item;

struct napi_threadsafe_function__ {
    napi_env env;
    JSValue func;
    void *context;
    void *finalize_data;
    napi_finalize finalize_cb;
    napi_threadsafe_function_call_js call_js_cb;
    uv_async_t async;
    uv_mutex_t mutex;
    uv_cond_t cond;
    struct list_head queue;
    size_t queue_size;
    size_t max_queue_size;            /* 0 means unbounded */
    size_t thread_count;
    bool closing;
    bool aborted;
    bool close_started;
    struct list_head link;
};

/* cleanup hook entry */
typedef struct {
    napi_cleanup_hook fn;
    void *arg;
    struct list_head link;
} napi_cleanup_entry;

typedef struct napi_async_cleanup_hook_handle__ {
    napi_env env;
    napi_async_cleanup_hook hook;
    void *data;
    struct list_head link;
} napi_async_cleanup_entry;

typedef struct {
    napi_env env;
    napi_finalize finalize_cb;
    void *finalize_hint;
    bool free_data;
} napi_ab_payload;

/* ========================================================================== */
/* Thread-local class ids & registries                                        */
/* ========================================================================== */

static thread_local JSClassID napi_ext_class_id;   /* external + wrap carriers */
static thread_local JSClassID napi_func_class_id;  /* func bundle carrier      */
static thread_local bool napi_classes_inited = false;

static thread_local struct list_head napi_envs;    /* all napi_env in this ctx */
static thread_local bool napi_envs_inited = false;

/* deprecated napi_module_register capture (set during dlopen) */
static thread_local napi_module *napi_pending_module = NULL;

/* Hidden property key used to attach wrap carriers to user objects. */
#define NAPI_WRAP_PROP "\xff""napi_wrap"

/* ========================================================================== */
/* Forward decls                                                              */
/* ========================================================================== */

static napi_value napi_add_handle(napi_env env, JSValue owned);
static napi_status napi_set_error(napi_env env, napi_status status);
static void napi_capture_exception(napi_env env);
static JSValue napi_fn_call(JSContext *ctx, JSValueConst func_obj,
                            JSValueConst this_val, int argc,
                            JSValueConst *argv, int flags);
static void napi_tsfn_close_cb(uv_handle_t *handle);
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_reference(napi_env env, napi_value value, uint32_t initial_refcount,
                      napi_ref *result);

/* ========================================================================== */
/* Value <-> handle helpers                                                   */
/* ========================================================================== */

static inline JSValue v(napi_value n) {
    return *(JSValue *) n;
}

/* Append an *owned* JSValue to the current handle scope, return its handle.
 * If no scope is open we leak into a per-env implicit slot is undesirable;
 * callers (trampolines) always open a scope first. As a safety net we still
 * store the value but it will be freed at env teardown via... we simply keep
 * a scope always open during register/callbacks, so this path is not hit. */
static napi_value napi_add_handle(napi_env env, JSValue owned) {
    napi_handle_scope s = env->open_scope;
    if (!s) {
        /* No explicit scope: keep the handle stable until env cleanup. */
        napi_hs_block *b = env->orphan_handles;
        if (!b || b->used >= NAPI_HS_BLOCK) {
            napi_hs_block *nb = calloc(1, sizeof(*nb));
            if (!nb) { JS_FreeValue(env->ctx, owned); return NULL; }
            nb->next = env->orphan_handles;
            env->orphan_handles = nb;
            b = nb;
        }
        JSValue *slot = &b->slots[b->used++];
        *slot = owned;
        return (napi_value) slot;
    }
    napi_hs_block *b = s->head;
    if (!b || b->used >= NAPI_HS_BLOCK) {
        napi_hs_block *nb = calloc(1, sizeof(*nb));
        if (!nb) { JS_FreeValue(env->ctx, owned); return NULL; }
        nb->next = s->head;
        s->head = nb;
        b = nb;
    }
    JSValue *slot = &b->slots[b->used++];
    *slot = owned;
    return (napi_value) slot;
}

/* ========================================================================== */
/* Error state                                                                */
/* ========================================================================== */

static const char *napi_error_messages[] = {
    NULL,                                     /* napi_ok */
    "Invalid argument",
    "An object was expected",
    "A string was expected",
    "A string or symbol was expected",
    "A function was expected",
    "A number was expected",
    "A boolean was expected",
    "An array was expected",
    "Unknown failure",
    "An exception is pending",
    "The async work item was cancelled",
    "napi_escape_handle already called on scope",
    "Invalid handle scope usage",
    "Invalid callback scope usage",
    "Thread-safe function queue is full",
    "Thread-safe function handle is closing",
    "A bigint was expected",
    "A date was expected",
    "An arraybuffer was expected",
    "A detachable arraybuffer was expected",
    "Main thread would deadlock",
    "External buffers are not allowed",
    "Cannot run JavaScript",
};

static napi_status napi_set_error(napi_env env, napi_status status) {
    if (!env) return status;
    env->last_error.error_code = status;
    env->last_error.engine_error_code = 0;
    env->last_error.engine_reserved = NULL;
    if (status == napi_ok) {
        env->last_error.error_message = NULL;
    } else {
        size_t n = sizeof(napi_error_messages) / sizeof(napi_error_messages[0]);
        env->last_error.error_message =
            ((size_t) status < n) ? napi_error_messages[status] : "Unknown failure";
    }
    return status;
}

#define NAPI_OK(env)        napi_set_error((env), napi_ok)
#define NAPI_RET(env, st)   napi_set_error((env), (st))

/* check args; on failure return invalid_arg */
#define NAPI_CHECK_ARG(env, a)  do { if ((a) == NULL) return NAPI_RET((env), napi_invalid_arg); } while (0)
#define NAPI_CHECK_ENV(env)     do { if ((env) == NULL) return napi_invalid_arg; } while (0)

/* If a QuickJS call raised, fold it into the pending exception and return
 * napi_pending_exception. */
static void napi_capture_exception(napi_env env) {
    JSValue exc = JS_GetException(env->ctx);
    if (JS_IsUninitialized(env->pending_exception)) {
        env->pending_exception = exc;
    } else {
        JS_FreeValue(env->ctx, exc);
    }
}

#define NAPI_PENDING(env) (!JS_IsUninitialized((env)->pending_exception))

/* ========================================================================== */
/* Class registration (external / wrap carriers)                              */
/* ========================================================================== */

static void napi_ext_finalizer(JSRuntime *rt, JSValue val) {
    napi_ext_payload *p = JS_GetOpaque(val, napi_ext_class_id);
    if (!p) return;
    if (p->finalize_cb) {
        /* Finalizers may call napi APIs; provide the env. Note: running JS in a
         * GC finalizer is restricted, but the common case (free native memory)
         * is fine. */
        p->finalize_cb(p->env, p->data, p->finalize_hint);
    }
    free(p);
}

static void napi_func_finalizer(JSRuntime *rt, JSValue val) {
    napi_cb_bundle *b = JS_GetOpaque(val, napi_func_class_id);
    if (b) free(b);
}

static void napi_ensure_classes(JSContext *ctx) {
    if (napi_classes_inited) return;
    JSRuntime *rt = JS_GetRuntime(ctx);

    static JSClassDef ext_def = { .class_name = "NapiExternal", .finalizer = napi_ext_finalizer };
    static JSClassDef func_def = { .class_name = "NapiFunction",
                                   .finalizer = napi_func_finalizer,
                                   .call = napi_fn_call };

    JS_NewClassID(rt, &napi_ext_class_id);
    JS_NewClass(rt, napi_ext_class_id, &ext_def);
    JS_NewClassID(rt, &napi_func_class_id);
    JS_NewClass(rt, napi_func_class_id, &func_def);

    napi_classes_inited = true;
}

/* Build an external-carrier JSValue (owned). */
static JSValue napi_make_ext(napi_env env, void *data,
                             napi_finalize finalize_cb, void *finalize_hint) {
    napi_ext_payload *p = calloc(1, sizeof(*p));
    if (!p) return JS_ThrowOutOfMemory(env->ctx);
    p->env = env;
    p->data = data;
    p->finalize_cb = finalize_cb;
    p->finalize_hint = finalize_hint;
    JSValue obj = JS_NewObjectClass(env->ctx, napi_ext_class_id);
    if (JS_IsException(obj)) { free(p); return obj; }
    JS_SetOpaque(obj, p);
    return obj;
}

/* ========================================================================== */
/* env lifecycle                                                              */
/* ========================================================================== */

static void napi_run_runtime_finalizer(JSRuntime *rt, void *arg);

static napi_env napi_env_new(JSContext *ctx, const char *filename, int api_version) {
    if (!napi_envs_inited) { init_list_head(&napi_envs); napi_envs_inited = true; }
    napi_ensure_classes(ctx);

    napi_env env = calloc(1, sizeof(*env));
    env->ctx = ctx;
    env->trt = TJS_GetRuntime(ctx);
    env->loop = TJS_GetLoop(env->trt);
    env->pending_exception = JS_UNINITIALIZED;
    env->open_scope = NULL;
    env->api_version = api_version;
    env->filename = filename ? strdup(filename) : NULL;
    env->refcount = 1;
    init_list_head(&env->refs);
    init_list_head(&env->tsfns);
    init_list_head(&env->cleanup_hooks);
    init_list_head(&env->async_cleanup_hooks);
    list_add_tail(&env->link, &napi_envs);

    JS_AddRuntimeFinalizer(JS_GetRuntime(ctx), napi_run_runtime_finalizer, env);
    return env;
}

static void napi_env_cleanup(napi_env env) {
    struct list_head *el, *tmp;

    if (!env->cleanup_done) {
        env->cleanup_done = true;

        /* run cleanup hooks LIFO */
        list_for_each_prev_safe(el, tmp, &env->async_cleanup_hooks) {
            napi_async_cleanup_entry *e = list_entry(el, napi_async_cleanup_entry, link);
            list_del(&e->link);
            if (e->hook) e->hook(e, e->data);
            free(e);
        }
        list_for_each_prev_safe(el, tmp, &env->cleanup_hooks) {
            napi_cleanup_entry *e = list_entry(el, napi_cleanup_entry, link);
            list_del(&e->link);
            if (e->fn) e->fn(e->arg);
            free(e);
        }
        if (env->instance_finalize_cb) {
            env->instance_finalize_cb(env, env->instance_data, env->instance_finalize_hint);
            env->instance_finalize_cb = NULL;
        }
    }

    if (!JS_IsUninitialized(env->pending_exception))
        JS_FreeValue(env->ctx, env->pending_exception);
    env->pending_exception = JS_UNINITIALIZED;

    list_for_each_safe(el, tmp, &env->refs) {
        napi_ref ref = list_entry(el, struct napi_ref__, link);
        list_del(&ref->link);
        if (!JS_IsUninitialized(ref->value)) JS_FreeValue(env->ctx, ref->value);
        if (!JS_IsUninitialized(ref->weakref)) JS_FreeValue(env->ctx, ref->weakref);
        free(ref);
    }

    list_for_each_safe(el, tmp, &env->tsfns) {
        napi_threadsafe_function tsfn = list_entry(el, struct napi_threadsafe_function__, link);
        uv_mutex_lock(&tsfn->mutex);
        while (!list_empty(&tsfn->queue)) {
            struct list_head *item_el = tsfn->queue.next;
            list_del(item_el);
            napi_tsfn_item *item = list_entry(item_el, napi_tsfn_item, link);
            free(item);
        }
        tsfn->queue_size = 0;
        tsfn->closing = true;
        tsfn->aborted = true;
        tsfn->thread_count = 0;
        bool should_close = !tsfn->close_started;
        if (should_close) tsfn->close_started = true;
        uv_mutex_unlock(&tsfn->mutex);
        if (should_close && !uv_is_closing((uv_handle_t *) &tsfn->async)) {
            uv_close((uv_handle_t *) &tsfn->async, napi_tsfn_close_cb);
        }
    }

    napi_hs_block *b = env->orphan_handles;
    env->orphan_handles = NULL;
    while (b) {
        napi_hs_block *next = b->next;
        for (size_t i = 0; i < b->used; i++)
            JS_FreeValue(env->ctx, b->slots[i]);
        free(b);
        b = next;
    }
}

static void napi_env_free(napi_env env) {
    napi_env_cleanup(env);
    free(env->filename);
    free(env);
}

static void napi_run_runtime_finalizer(JSRuntime *rt, void *arg) {
    napi_env env = arg;
    /* Detach from list defensively; the ctx is going away. */
    if (env->link.prev && env->link.next) list_del(&env->link);
    napi_env_free(env);
}

void tjs__nodeapi_cleanup_runtime(TJSRuntime *trt) {
    if (!napi_envs_inited) return;
    struct list_head *el, *tmp;
    list_for_each_safe(el, tmp, &napi_envs) {
        napi_env env = list_entry(el, struct napi_env__, link);
        if (env->trt == trt) napi_env_cleanup(env);
    }
}

/* ========================================================================== */
/* Handle scopes                                                              */
/* ========================================================================== */

static napi_handle_scope napi_scope_open(napi_env env, bool escapable) {
    napi_handle_scope s = calloc(1, sizeof(*s));
    s->parent = env->open_scope;
    s->head = NULL;
    s->env = env;
    s->escapable = escapable;
    s->escape_called = false;
    env->open_scope = s;
    return s;
}

static void napi_scope_close(napi_env env, napi_handle_scope s) {
    napi_hs_block *b = s->head;
    while (b) {
        napi_hs_block *next = b->next;
        for (size_t i = 0; i < b->used; i++)
            JS_FreeValue(env->ctx, b->slots[i]);
        free(b);
        b = next;
    }
    env->open_scope = s->parent;
    free(s);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_open_handle_scope(napi_env env, napi_handle_scope *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, result);
    *result = napi_scope_open(env, false);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_close_handle_scope(napi_env env, napi_handle_scope scope) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, scope);
    if (env->open_scope != scope) return NAPI_RET(env, napi_handle_scope_mismatch);
    napi_scope_close(env, scope);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_open_escapable_handle_scope(napi_env env, napi_escapable_handle_scope *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, result);
    *result = (napi_escapable_handle_scope) napi_scope_open(env, true);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_close_escapable_handle_scope(napi_env env, napi_escapable_handle_scope scope) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, scope);
    napi_handle_scope s = (napi_handle_scope) scope;
    if (env->open_scope != s) return NAPI_RET(env, napi_handle_scope_mismatch);
    napi_scope_close(env, s);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_escape_handle(napi_env env, napi_escapable_handle_scope scope,
                   napi_value escapee, napi_value *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, scope);
    NAPI_CHECK_ARG(env, escapee);
    NAPI_CHECK_ARG(env, result);
    napi_handle_scope s = (napi_handle_scope) scope;
    if (!s->escapable) return NAPI_RET(env, napi_invalid_arg);
    if (s->escape_called) return NAPI_RET(env, napi_escape_called_twice);
    s->escape_called = true;
    /* Promote the value into the parent scope. */
    JSValue dup = JS_DupValue(env->ctx, v(escapee));
    napi_handle_scope saved = env->open_scope;
    env->open_scope = s->parent;
    *result = napi_add_handle(env, dup);
    env->open_scope = saved;
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Errors & exceptions                                                        */
/* ========================================================================== */

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_last_error_info(node_api_basic_env basic_env,
                         const napi_extended_error_info **result) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, result);
    *result = &env->last_error;
    return napi_ok;
}

NAPI_EXTERN napi_status NAPI_CDECL napi_throw(napi_env env, napi_value error) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, error);
    if (NAPI_PENDING(env)) return NAPI_RET(env, napi_pending_exception);
    env->pending_exception = JS_DupValue(env->ctx, v(error));
    return NAPI_OK(env);
}

static napi_status napi_throw_named(napi_env env, const char *error_type,
                                    const char *code, const char *msg) {
    JSValue err = JS_NewError(env->ctx);
    if (msg) JS_SetPropertyStr(env->ctx, err, "message", JS_NewString(env->ctx, msg));
    if (error_type)
        JS_SetPropertyStr(env->ctx, err, "name", JS_NewString(env->ctx, error_type));
    if (code) JS_SetPropertyStr(env->ctx, err, "code", JS_NewString(env->ctx, code));
    if (NAPI_PENDING(env)) { JS_FreeValue(env->ctx, err); return NAPI_RET(env, napi_pending_exception); }
    env->pending_exception = err;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_throw_error(napi_env env, const char *code, const char *msg) {
    NAPI_CHECK_ENV(env);
    return napi_throw_named(env, "Error", code, msg);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_throw_type_error(napi_env env, const char *code, const char *msg) {
    NAPI_CHECK_ENV(env);
    return napi_throw_named(env, "TypeError", code, msg);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_throw_range_error(napi_env env, const char *code, const char *msg) {
    NAPI_CHECK_ENV(env);
    return napi_throw_named(env, "RangeError", code, msg);
}
NAPI_EXTERN napi_status NAPI_CDECL
node_api_throw_syntax_error(napi_env env, const char *code, const char *msg) {
    NAPI_CHECK_ENV(env);
    return napi_throw_named(env, "SyntaxError", code, msg);
}

static napi_status napi_create_error_named(napi_env env, const char *name,
                                           napi_value code, napi_value msg,
                                           napi_value *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, msg);
    NAPI_CHECK_ARG(env, result);
    JSValue err = JS_NewError(env->ctx);
    JS_SetPropertyStr(env->ctx, err, "message", JS_DupValue(env->ctx, v(msg)));
    if (name) JS_SetPropertyStr(env->ctx, err, "name", JS_NewString(env->ctx, name));
    if (code) JS_SetPropertyStr(env->ctx, err, "code", JS_DupValue(env->ctx, v(code)));
    *result = napi_add_handle(env, err);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_error(napi_env env, napi_value code, napi_value msg, napi_value *result) {
    return napi_create_error_named(env, "Error", code, msg, result);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_type_error(napi_env env, napi_value code, napi_value msg, napi_value *result) {
    return napi_create_error_named(env, "TypeError", code, msg, result);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_range_error(napi_env env, napi_value code, napi_value msg, napi_value *result) {
    return napi_create_error_named(env, "RangeError", code, msg, result);
}
NAPI_EXTERN napi_status NAPI_CDECL
node_api_create_syntax_error(napi_env env, napi_value code, napi_value msg, napi_value *result) {
    return napi_create_error_named(env, "SyntaxError", code, msg, result);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_error(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, value);
    NAPI_CHECK_ARG(env, result);
    *result = JS_IsError(v(value));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_exception_pending(napi_env env, bool *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, result);
    *result = NAPI_PENDING(env);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_and_clear_last_exception(napi_env env, napi_value *result) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, result);
    if (!NAPI_PENDING(env)) {
        JSValue undef = JS_UNDEFINED;
        *result = napi_add_handle(env, undef);
        return NAPI_OK(env);
    }
    *result = napi_add_handle(env, env->pending_exception);
    env->pending_exception = JS_UNINITIALIZED;
    return NAPI_OK(env);
}

NAPI_EXTERN NAPI_NO_RETURN void NAPI_CDECL
napi_fatal_error(const char *location, size_t location_len,
                 const char *message, size_t message_len) {
    fprintf(stderr, "FATAL ERROR: %.*s %.*s\n",
            location_len == NAPI_AUTO_LENGTH ? (int) strlen(location) : (int) location_len, location,
            message_len == NAPI_AUTO_LENGTH ? (int) strlen(message) : (int) message_len, message);
    fflush(stderr);
    abort();
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_fatal_exception(napi_env env, napi_value err) {
    NAPI_CHECK_ENV(env);
    NAPI_CHECK_ARG(env, err);
    /* Surface as an uncaught exception. */
    JS_Throw(env->ctx, JS_DupValue(env->ctx, v(err)));
    TJS_DumpException(env->ctx);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Singletons & basic value creation                                          */
/* ========================================================================== */

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_undefined(napi_env env, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_UNDEFINED; *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_null(napi_env env, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NULL; *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_global(napi_env env, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    *result = napi_add_handle(env, JS_GetGlobalObject(env->ctx));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_boolean(napi_env env, bool value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewBool(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_object(napi_env env, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    *result = napi_add_handle(env, JS_NewObject(env->ctx));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_array(napi_env env, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    *result = napi_add_handle(env, JS_NewArray(env->ctx));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_array_with_length(napi_env env, size_t length, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue arr = JS_NewArray(env->ctx);
    JS_SetLength(env->ctx, arr, (int64_t) length);
    *result = napi_add_handle(env, arr);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_double(napi_env env, double value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewFloat64(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_int32(napi_env env, int32_t value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewInt32(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_uint32(napi_env env, uint32_t value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewUint32(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_int64(napi_env env, int64_t value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewInt64(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_bigint_int64(napi_env env, int64_t value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewBigInt64(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_bigint_uint64(napi_env env, uint64_t value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue x = JS_NewBigUint64(env->ctx, value); *result = napi_add_handle(env, x);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_string_utf8(napi_env env, const char *str, size_t length, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    size_t len = (length == NAPI_AUTO_LENGTH) ? strlen(str) : length;
    *result = napi_add_handle(env, JS_NewStringLen(env->ctx, str, len));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_string_latin1(napi_env env, const char *str, size_t length, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    size_t len = (length == NAPI_AUTO_LENGTH) ? strlen(str) : length;
    /* latin1 -> utf16 -> string */
    uint16_t *buf = malloc(sizeof(uint16_t) * (len ? len : 1));
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t) str[i];
    JSValue s = JS_NewStringUTF16(env->ctx, buf, len);
    free(buf);
    *result = napi_add_handle(env, s);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_create_string_utf16(napi_env env, const char16_t *str, size_t length, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    size_t len = length;
    if (length == NAPI_AUTO_LENGTH) { len = 0; while (str[len]) len++; }
    JSValue s = JS_NewStringUTF16(env->ctx, (const uint16_t *) str, len);
    *result = napi_add_handle(env, s);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_symbol(napi_env env, napi_value description, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    const char *desc = NULL;
    if (description) desc = JS_ToCString(env->ctx, v(description));
    JSValue sym = JS_NewSymbol(env->ctx, desc ? desc : "", false);
    if (desc) JS_FreeCString(env->ctx, desc);
    *result = napi_add_handle(env, sym);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* typeof / value readers / coercion                                          */
/* ========================================================================== */

static napi_valuetype napi_typeof_value(JSContext *ctx, JSValue val) {
    if (JS_IsUndefined(val)) return napi_undefined;
    if (JS_IsNull(val)) return napi_null;
    if (JS_IsBool(val)) return napi_boolean;
    if (JS_IsNumber(val)) return napi_number;
    if (JS_IsString(val)) return napi_string;
    if (JS_IsSymbol(val)) return napi_symbol;
    if (JS_IsBigInt(val)) return napi_bigint;
    if (JS_IsFunction(ctx, val)) return napi_function;
    if (JS_GetOpaque(val, napi_ext_class_id)) return napi_external;
    if (JS_IsObject(val)) return napi_object;
    return napi_undefined;
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_typeof(napi_env env, napi_value value, napi_valuetype *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    *result = napi_typeof_value(env->ctx, v(value));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_double(napi_env env, napi_value value, double *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsNumber(v(value))) return NAPI_RET(env, napi_number_expected);
    if (JS_ToFloat64(env->ctx, result, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_number_expected); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_int32(napi_env env, napi_value value, int32_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsNumber(v(value))) return NAPI_RET(env, napi_number_expected);
    if (JS_ToInt32(env->ctx, result, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_number_expected); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_uint32(napi_env env, napi_value value, uint32_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsNumber(v(value))) return NAPI_RET(env, napi_number_expected);
    if (JS_ToUint32(env->ctx, result, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_number_expected); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_int64(napi_env env, napi_value value, int64_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsNumber(v(value))) return NAPI_RET(env, napi_number_expected);
    if (JS_ToInt64(env->ctx, result, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_number_expected); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_bool(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsBool(v(value))) return NAPI_RET(env, napi_boolean_expected);
    *result = JS_ToBool(env->ctx, v(value)) ? true : false;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_bigint_int64(napi_env env, napi_value value, int64_t *result, bool *lossless) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsBigInt(v(value))) return NAPI_RET(env, napi_bigint_expected);
    if (JS_ToBigInt64(env->ctx, result, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_bigint_expected); }
    if (lossless) *lossless = true; /* best-effort */
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_bigint_uint64(napi_env env, napi_value value, uint64_t *result, bool *lossless) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsBigInt(v(value))) return NAPI_RET(env, napi_bigint_expected);
    if (JS_ToBigUint64(env->ctx, result, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_bigint_expected); }
    if (lossless) *lossless = true;
    return NAPI_OK(env);
}

/* String readers. The N-API contract: if buf==NULL, write required length
 * (excluding NUL) to *result; otherwise copy up to bufsize-1 bytes + NUL and
 * write the number of bytes/chars copied to *result. */
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_string_utf8(napi_env env, napi_value value, char *buf, size_t bufsize, size_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value);
    if (!JS_IsString(v(value))) return NAPI_RET(env, napi_string_expected);
    size_t len = 0;
    const char *s = JS_ToCStringLen(env->ctx, &len, v(value));
    if (!s) { napi_capture_exception(env); return NAPI_RET(env, napi_string_expected); }
    if (buf == NULL) {
        if (result) *result = len;
    } else if (bufsize > 0) {
        size_t n = len < bufsize - 1 ? len : bufsize - 1;
        memcpy(buf, s, n);
        buf[n] = '\0';
        if (result) *result = n;
    } else if (result) {
        *result = 0;
    }
    JS_FreeCString(env->ctx, s);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_string_latin1(napi_env env, napi_value value, char *buf, size_t bufsize, size_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value);
    if (!JS_IsString(v(value))) return NAPI_RET(env, napi_string_expected);
    size_t len = 0;
    const uint16_t *s = JS_ToCStringLenUTF16(env->ctx, &len, v(value));
    if (!s) { napi_capture_exception(env); return NAPI_RET(env, napi_string_expected); }
    if (buf == NULL) {
        if (result) *result = len;
    } else if (bufsize > 0) {
        size_t n = len < bufsize - 1 ? len : bufsize - 1;
        for (size_t i = 0; i < n; i++) buf[i] = (char) (s[i] & 0xFF);
        buf[n] = '\0';
        if (result) *result = n;
    } else if (result) {
        *result = 0;
    }
    JS_FreeCStringUTF16(env->ctx, s);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_string_utf16(napi_env env, napi_value value, char16_t *buf, size_t bufsize, size_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value);
    if (!JS_IsString(v(value))) return NAPI_RET(env, napi_string_expected);
    size_t len = 0;
    const uint16_t *s = JS_ToCStringLenUTF16(env->ctx, &len, v(value));
    if (!s) { napi_capture_exception(env); return NAPI_RET(env, napi_string_expected); }
    if (buf == NULL) {
        if (result) *result = len;
    } else if (bufsize > 0) {
        size_t n = len < bufsize - 1 ? len : bufsize - 1;
        memcpy(buf, s, n * sizeof(uint16_t));
        buf[n] = 0;
        if (result) *result = n;
    } else if (result) {
        *result = 0;
    }
    JS_FreeCStringUTF16(env->ctx, s);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_coerce_to_bool(napi_env env, napi_value value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    int b = JS_ToBool(env->ctx, v(value));
    if (b < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, JS_NewBool(env->ctx, b));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_coerce_to_number(napi_env env, napi_value value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    double d;
    if (JS_ToFloat64(env->ctx, &d, v(value)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, JS_NewFloat64(env->ctx, d));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_coerce_to_string(napi_env env, napi_value value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    size_t len; const char *s = JS_ToCStringLen(env->ctx, &len, v(value));
    if (!s) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    JSValue str = JS_NewStringLen(env->ctx, s, len);
    JS_FreeCString(env->ctx, s);
    *result = napi_add_handle(env, str);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_coerce_to_object(napi_env env, napi_value value, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    /* Object(value) via global Object() call */
    JSValue global = JS_GetGlobalObject(env->ctx);
    JSValue objctor = JS_GetPropertyStr(env->ctx, global, "Object");
    JS_FreeValue(env->ctx, global);
    JSValueConst arg = v(value);
    JSValue r = JS_Call(env->ctx, objctor, JS_UNDEFINED, 1, &arg);
    JS_FreeValue(env->ctx, objctor);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, r);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Properties & objects                                                       */
/* ========================================================================== */

NAPI_EXTERN napi_status NAPI_CDECL
napi_set_property(napi_env env, napi_value object, napi_value key, napi_value value) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, key); NAPI_CHECK_ARG(env, value);
    JSAtom atom = JS_ValueToAtom(env->ctx, v(key));
    if (atom == JS_ATOM_NULL) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    int r = JS_SetProperty(env->ctx, v(object), atom, JS_DupValue(env->ctx, v(value)));
    JS_FreeAtom(env->ctx, atom);
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_property(napi_env env, napi_value object, napi_value key, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, key); NAPI_CHECK_ARG(env, result);
    JSAtom atom = JS_ValueToAtom(env->ctx, v(key));
    if (atom == JS_ATOM_NULL) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    JSValue r = JS_GetProperty(env->ctx, v(object), atom);
    JS_FreeAtom(env->ctx, atom);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, r);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_has_property(napi_env env, napi_value object, napi_value key, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, key); NAPI_CHECK_ARG(env, result);
    JSAtom atom = JS_ValueToAtom(env->ctx, v(key));
    if (atom == JS_ATOM_NULL) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    int r = JS_HasProperty(env->ctx, v(object), atom);
    JS_FreeAtom(env->ctx, atom);
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = r ? true : false;
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_delete_property(napi_env env, napi_value object, napi_value key, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, key);
    JSAtom atom = JS_ValueToAtom(env->ctx, v(key));
    if (atom == JS_ATOM_NULL) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    int r = JS_DeleteProperty(env->ctx, v(object), atom, 0);
    JS_FreeAtom(env->ctx, atom);
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    if (result) *result = r ? true : false;
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_has_own_property(napi_env env, napi_value object, napi_value key, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, key); NAPI_CHECK_ARG(env, result);
    /* use Object.prototype.hasOwnProperty */
    JSValue global = JS_GetGlobalObject(env->ctx);
    JSValue objc = JS_GetPropertyStr(env->ctx, global, "Object");
    JSValue proto = JS_GetPropertyStr(env->ctx, objc, "prototype");
    JSValue hop = JS_GetPropertyStr(env->ctx, proto, "hasOwnProperty");
    JSValueConst arg = v(key);
    JSValue r = JS_Call(env->ctx, hop, v(object), 1, &arg);
    JS_FreeValue(env->ctx, global); JS_FreeValue(env->ctx, objc);
    JS_FreeValue(env->ctx, proto); JS_FreeValue(env->ctx, hop);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = JS_ToBool(env->ctx, r) ? true : false;
    JS_FreeValue(env->ctx, r);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_set_named_property(napi_env env, napi_value object, const char *utf8name, napi_value value) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, value);
    int r = JS_SetPropertyStr(env->ctx, v(object), utf8name, JS_DupValue(env->ctx, v(value)));
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_named_property(napi_env env, napi_value object, const char *utf8name, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    JSValue r = JS_GetPropertyStr(env->ctx, v(object), utf8name);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, r);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_has_named_property(napi_env env, napi_value object, const char *utf8name, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    JSAtom atom = JS_NewAtom(env->ctx, utf8name);
    int r = JS_HasProperty(env->ctx, v(object), atom);
    JS_FreeAtom(env->ctx, atom);
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = r ? true : false;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_set_element(napi_env env, napi_value object, uint32_t index, napi_value value) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, value);
    int r = JS_SetPropertyUint32(env->ctx, v(object), index, JS_DupValue(env->ctx, v(value)));
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_element(napi_env env, napi_value object, uint32_t index, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    JSValue r = JS_GetPropertyUint32(env->ctx, v(object), index);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, r);
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_has_element(napi_env env, napi_value object, uint32_t index, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    JSAtom atom = JS_NewAtomUInt32(env->ctx, index);
    int r = JS_HasProperty(env->ctx, v(object), atom);
    JS_FreeAtom(env->ctx, atom);
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = r ? true : false;
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_delete_element(napi_env env, napi_value object, uint32_t index, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object);
    JSAtom atom = JS_NewAtomUInt32(env->ctx, index);
    int r = JS_DeleteProperty(env->ctx, v(object), atom, 0);
    JS_FreeAtom(env->ctx, atom);
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    if (result) *result = r ? true : false;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_prototype(napi_env env, napi_value object, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    JSValue proto = JS_GetPrototype(env->ctx, v(object));
    if (JS_IsException(proto)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, proto);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_property_names(napi_env env, napi_value object, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    JSPropertyEnum *tab = NULL; uint32_t len = 0;
    if (JS_GetOwnPropertyNames(env->ctx, &tab, &len, v(object),
                               JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) < 0) {
        napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception);
    }
    JSValue arr = JS_NewArray(env->ctx);
    for (uint32_t i = 0; i < len; i++) {
        JS_SetPropertyUint32(env->ctx, arr, i, JS_AtomToValue(env->ctx, tab[i].atom));
    }
    JS_FreePropertyEnum(env->ctx, tab, len);
    *result = napi_add_handle(env, arr);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_all_property_names(napi_env env, napi_value object,
                            napi_key_collection_mode key_mode,
                            napi_key_filter key_filter,
                            napi_key_conversion key_conversion,
                            napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, result);
    int flags = 0;
    if (key_filter & napi_key_skip_strings) ; else flags |= JS_GPN_STRING_MASK;
    if (!(key_filter & napi_key_skip_symbols)) flags |= JS_GPN_SYMBOL_MASK;
    if (flags == 0) flags = JS_GPN_STRING_MASK;
    JSPropertyEnum *tab = NULL; uint32_t len = 0;
    if (JS_GetOwnPropertyNames(env->ctx, &tab, &len, v(object), flags) < 0) {
        napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception);
    }
    JSValue arr = JS_NewArray(env->ctx);
    uint32_t outi = 0;
    for (uint32_t i = 0; i < len; i++) {
        JS_SetPropertyUint32(env->ctx, arr, outi++, JS_AtomToValue(env->ctx, tab[i].atom));
    }
    JS_FreePropertyEnum(env->ctx, tab, len);
    *result = napi_add_handle(env, arr);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_array(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    *result = JS_IsArray(v(value));
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_array_length(napi_env env, napi_value value, uint32_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    int64_t len = 0;
    if (JS_GetLength(env->ctx, v(value), &len) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = (uint32_t) len;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_strict_equals(napi_env env, napi_value lhs, napi_value rhs, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, lhs); NAPI_CHECK_ARG(env, rhs); NAPI_CHECK_ARG(env, result);
    /* Implement via a small JS helper to avoid needing internal API. */
    JSValueConst args[2] = { v(lhs), v(rhs) };
    JSValue global = JS_GetGlobalObject(env->ctx);
    JSValue obj = JS_GetPropertyStr(env->ctx, global, "Object");
    JSValue is = JS_GetPropertyStr(env->ctx, obj, "is");
    JSValue r = JS_Call(env->ctx, is, JS_UNDEFINED, 2, args);
    JS_FreeValue(env->ctx, global); JS_FreeValue(env->ctx, obj); JS_FreeValue(env->ctx, is);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = JS_ToBool(env->ctx, r) ? true : false;
    JS_FreeValue(env->ctx, r);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_instanceof(napi_env env, napi_value object, napi_value constructor, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, constructor); NAPI_CHECK_ARG(env, result);
    int r = JS_IsInstanceOf(env->ctx, v(object), v(constructor));
    if (r < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = r ? true : false;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_object_freeze(napi_env env, napi_value object) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object);
    if (JS_FreezeObject(env->ctx, v(object)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_object_seal(napi_env env, napi_value object) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object);
    if (JS_SealObject(env->ctx, v(object)) < 0) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Functions, callbacks, classes                                              */
/* ========================================================================== */

/* The unified call trampoline for every napi-created callable (plain
 * functions and class constructors). Distinguishes construct vs call via the
 * JS_CALL_FLAG_CONSTRUCTOR flag (see JS_CallConstructorInternal). */
static JSValue napi_fn_call(JSContext *ctx, JSValueConst func_obj,
                            JSValueConst this_val, int argc,
                            JSValueConst *argv, int flags) {
    napi_cb_bundle *b = JS_GetOpaque(func_obj, napi_func_class_id);
    if (!b || !b->cb) return JS_ThrowTypeError(ctx, "napi: invalid function");
    napi_env env = b->env;
    bool is_ctor = (flags & JS_CALL_FLAG_CONSTRUCTOR) != 0;

    JSValueConst new_target = JS_UNDEFINED;
    JSValue this_obj;
    bool free_this = false;
    if (is_ctor) {
        new_target = this_val;   /* per quickjs, this_val == new.target here */
        JSValue proto = JS_GetPropertyStr(ctx, new_target, "prototype");
        if (JS_IsException(proto)) return proto;
        this_obj = JS_IsObject(proto) ? JS_NewObjectProto(ctx, proto) : JS_NewObject(ctx);
        JS_FreeValue(ctx, proto);
        free_this = true;
    } else {
        this_obj = JS_DupValue(ctx, this_val);
        free_this = true;
    }

    napi_handle_scope scope = napi_scope_open(env, false);
    struct napi_callback_info__ info = {
        .ctx = ctx, .this_val = this_obj, .argc = argc, .argv = (JSValueConst *) argv,
        .new_target = new_target, .data = b->data,
    };
    napi_value rv = b->cb(env, &info);

    JSValue out;
    if (is_ctor) {
        if (rv && JS_IsObject(v(rv))) out = JS_DupValue(ctx, v(rv));
        else                          out = JS_DupValue(ctx, this_obj);
    } else {
        out = rv ? JS_DupValue(ctx, v(rv)) : JS_UNDEFINED;
    }
    napi_scope_close(env, scope);
    if (free_this) JS_FreeValue(ctx, this_obj);

    if (NAPI_PENDING(env)) {
        JSValue exc = env->pending_exception;
        env->pending_exception = JS_UNINITIALIZED;
        JS_FreeValue(ctx, out);
        return JS_Throw(ctx, exc);
    }
    return out;
}

/* Create a callable object carrying (cb, data). */
static JSValue napi_make_function(napi_env env, napi_callback cb, void *data,
                                  const char *name, size_t name_len) {
    napi_cb_bundle *b = calloc(1, sizeof(*b));
    if (!b) return JS_ThrowOutOfMemory(env->ctx);
    b->env = env; b->cb = cb; b->data = data;
    JSValue fn = JS_NewObjectClass(env->ctx, napi_func_class_id);
    if (JS_IsException(fn)) { free(b); return fn; }
    JS_SetOpaque(fn, b);
    if (name && name_len) {
        size_t n = (name_len == NAPI_AUTO_LENGTH) ? strlen(name) : name_len;
        JS_DefinePropertyValueStr(env->ctx, fn, "name",
                                  JS_NewStringLen(env->ctx, name, n), JS_PROP_CONFIGURABLE);
    }
    return fn;
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_function(napi_env env, const char *utf8name, size_t length,
                     napi_callback cb, void *data, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, cb); NAPI_CHECK_ARG(env, result);
    JSValue fn = napi_make_function(env, cb, data, utf8name, length);
    if (JS_IsException(fn)) { napi_capture_exception(env); return NAPI_RET(env, napi_generic_failure); }
    *result = napi_add_handle(env, fn);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_cb_info(napi_env env, napi_callback_info cbinfo, size_t *argc,
                 napi_value *argv, napi_value *this_arg, void **data) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, cbinfo);
    struct napi_callback_info__ *info = cbinfo;
    if (argv != NULL && argc != NULL) {
        size_t want = *argc;
        size_t have = (size_t) info->argc;
        size_t n = want < have ? want : have;
        for (size_t i = 0; i < n; i++)
            argv[i] = napi_add_handle(env, JS_DupValue(env->ctx, info->argv[i]));
        for (size_t i = n; i < want; i++) {
            JSValue u = JS_UNDEFINED; argv[i] = napi_add_handle(env, u);
        }
    }
    if (argc != NULL) *argc = (size_t) info->argc;
    if (this_arg != NULL)
        *this_arg = napi_add_handle(env, JS_DupValue(env->ctx, info->this_val));
    if (data != NULL) *data = info->data;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_new_target(napi_env env, napi_callback_info cbinfo, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, cbinfo); NAPI_CHECK_ARG(env, result);
    struct napi_callback_info__ *info = cbinfo;
    if (JS_IsUndefined(info->new_target)) {
        *result = NULL;
    } else {
        *result = napi_add_handle(env, JS_DupValue(env->ctx, info->new_target));
    }
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_call_function(napi_env env, napi_value recv, napi_value func,
                   size_t argc, const napi_value *argv, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, func);
    JSValueConst *args = NULL;
    if (argc > 0) {
        args = malloc(sizeof(JSValueConst) * argc);
        if (!args) return NAPI_RET(env, napi_generic_failure);
        for (size_t i = 0; i < argc; i++) args[i] = v(argv[i]);
    }
    JSValueConst this_v = recv ? v(recv) : JS_UNDEFINED;
    JSValue r = JS_Call(env->ctx, v(func), this_v, (int) argc, args);
    free(args);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    if (result) *result = napi_add_handle(env, r);
    else JS_FreeValue(env->ctx, r);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_new_instance(napi_env env, napi_value constructor, size_t argc,
                  const napi_value *argv, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, constructor); NAPI_CHECK_ARG(env, result);
    JSValueConst *args = NULL;
    if (argc > 0) {
        args = malloc(sizeof(JSValueConst) * argc);
        if (!args) return NAPI_RET(env, napi_generic_failure);
        for (size_t i = 0; i < argc; i++) args[i] = v(argv[i]);
    }
    JSValue r = JS_CallConstructor(env->ctx, v(constructor), (int) argc, args);
    free(args);
    if (JS_IsException(r)) { napi_capture_exception(env); return NAPI_RET(env, napi_pending_exception); }
    *result = napi_add_handle(env, r);
    return NAPI_OK(env);
}

/* Apply a single napi_property_descriptor to a target object. */
static napi_status napi_apply_descriptor(napi_env env, JSValue target,
                                         const napi_property_descriptor *p) {
    JSAtom atom;
    if (p->utf8name) atom = JS_NewAtom(env->ctx, p->utf8name);
    else if (p->name) atom = JS_ValueToAtom(env->ctx, v(p->name));
    else return napi_invalid_arg;

    int flags = 0;
    if (p->attributes & napi_writable) flags |= JS_PROP_WRITABLE;
    if (p->attributes & napi_enumerable) flags |= JS_PROP_ENUMERABLE;
    if (p->attributes & napi_configurable) flags |= JS_PROP_CONFIGURABLE;

    if (p->getter || p->setter) {
        JSValue getter = p->getter ? napi_make_function(env, p->getter, p->data, NULL, 0) : JS_UNDEFINED;
        JSValue setter = p->setter ? napi_make_function(env, p->setter, p->data, NULL, 0) : JS_UNDEFINED;
        JS_DefineProperty(env->ctx, target, atom, JS_UNDEFINED, getter, setter,
                          flags | JS_PROP_HAS_GET | JS_PROP_HAS_SET |
                          JS_PROP_HAS_CONFIGURABLE | JS_PROP_HAS_ENUMERABLE);
        JS_FreeValue(env->ctx, getter);
        JS_FreeValue(env->ctx, setter);
    } else if (p->method) {
        JSValue fn = napi_make_function(env, p->method, p->data,
                                        p->utf8name, p->utf8name ? NAPI_AUTO_LENGTH : 0);
        JS_DefinePropertyValue(env->ctx, target, atom, fn,
                               flags | JS_PROP_HAS_VALUE | JS_PROP_HAS_CONFIGURABLE |
                               JS_PROP_HAS_WRITABLE | JS_PROP_HAS_ENUMERABLE);
    } else {
        JS_DefinePropertyValue(env->ctx, target, atom,
                               JS_DupValue(env->ctx, v(p->value)),
                               flags | JS_PROP_HAS_VALUE | JS_PROP_HAS_CONFIGURABLE |
                               JS_PROP_HAS_WRITABLE | JS_PROP_HAS_ENUMERABLE);
    }
    JS_FreeAtom(env->ctx, atom);
    return napi_ok;
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_define_properties(napi_env env, napi_value object, size_t property_count,
                       const napi_property_descriptor *properties) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object);
    for (size_t i = 0; i < property_count; i++) {
        napi_status s = napi_apply_descriptor(env, v(object), &properties[i]);
        if (s != napi_ok) return NAPI_RET(env, s);
    }
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_define_class(napi_env env, const char *utf8name, size_t length,
                  napi_callback constructor, void *data,
                  size_t property_count, const napi_property_descriptor *properties,
                  napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, constructor); NAPI_CHECK_ARG(env, result);

    JSValue ctor = napi_make_function(env, constructor, data, utf8name, length);
    if (JS_IsException(ctor)) { napi_capture_exception(env); return NAPI_RET(env, napi_generic_failure); }
    JS_SetConstructorBit(env->ctx, ctor, true);

    JSValue proto = JS_NewObject(env->ctx);
    /* link ctor.prototype <-> proto.constructor */
    JS_DefinePropertyValueStr(env->ctx, ctor, "prototype",
                              JS_DupValue(env->ctx, proto), JS_PROP_WRITABLE);
    JS_DefinePropertyValueStr(env->ctx, proto, "constructor",
                              JS_DupValue(env->ctx, ctor), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);

    for (size_t i = 0; i < property_count; i++) {
        const napi_property_descriptor *p = &properties[i];
        JSValue tgt = (p->attributes & napi_static) ? ctor : proto;
        napi_apply_descriptor(env, tgt, p);
    }
    JS_FreeValue(env->ctx, proto);
    *result = napi_add_handle(env, ctor);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Wrap / unwrap / external / type tags                                       */
/* ========================================================================== */

NAPI_EXTERN napi_status NAPI_CDECL
napi_wrap(napi_env env, napi_value js_object, void *native_object,
          napi_finalize finalize_cb, void *finalize_hint, napi_ref *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, js_object);
    JSValue carrier = napi_make_ext(env, native_object, finalize_cb, finalize_hint);
    if (JS_IsException(carrier)) { napi_capture_exception(env); return NAPI_RET(env, napi_generic_failure); }
    /* attach as a non-enumerable hidden property */
    JSAtom atom = JS_NewAtom(env->ctx, NAPI_WRAP_PROP);
    int has_wrap = JS_HasProperty(env->ctx, v(js_object), atom);
    if (has_wrap < 0) {
        JS_FreeAtom(env->ctx, atom);
        JS_FreeValue(env->ctx, carrier);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (has_wrap) {
        JS_FreeAtom(env->ctx, atom);
        JS_FreeValue(env->ctx, carrier);
        return NAPI_RET(env, napi_invalid_arg);
    }
    if (JS_DefinePropertyValue(env->ctx, v(js_object), atom, carrier,
                               0 /* not enum/writable/config */) < 0) {
        JS_FreeAtom(env->ctx, atom);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    JS_FreeAtom(env->ctx, atom);
    if (result) {
        /* optional reference to the wrapped object */
        return napi_create_reference(env, js_object, 0, result);
    }
    return NAPI_OK(env);
}

static napi_ext_payload *napi_get_wrap_payload(napi_env env, napi_value js_object) {
    JSValue carrier = JS_GetPropertyStr(env->ctx, v(js_object), NAPI_WRAP_PROP);
    if (JS_IsException(carrier)) { JS_FreeValue(env->ctx, carrier); return NULL; }
    napi_ext_payload *p = JS_GetOpaque(carrier, napi_ext_class_id);
    JS_FreeValue(env->ctx, carrier);
    return p;
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_unwrap(napi_env env, napi_value js_object, void **result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, js_object); NAPI_CHECK_ARG(env, result);
    napi_ext_payload *p = napi_get_wrap_payload(env, js_object);
    if (!p) return NAPI_RET(env, napi_invalid_arg);
    *result = p->data;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_remove_wrap(napi_env env, napi_value js_object, void **result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, js_object);
    napi_ext_payload *p = napi_get_wrap_payload(env, js_object);
    if (!p) return NAPI_RET(env, napi_invalid_arg);
    if (result) *result = p->data;
    p->finalize_cb = NULL;  /* prevent finalizer from running */
    JSAtom atom = JS_NewAtom(env->ctx, NAPI_WRAP_PROP);
    JS_DeleteProperty(env->ctx, v(js_object), atom, 0);
    JS_FreeAtom(env->ctx, atom);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_external(napi_env env, void *data, napi_finalize finalize_cb,
                     void *finalize_hint, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue ext = napi_make_ext(env, data, finalize_cb, finalize_hint);
    if (JS_IsException(ext)) { napi_capture_exception(env); return NAPI_RET(env, napi_generic_failure); }
    *result = napi_add_handle(env, ext);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_external(napi_env env, napi_value value, void **result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    napi_ext_payload *p = JS_GetOpaque(v(value), napi_ext_class_id);
    if (!p) return NAPI_RET(env, napi_invalid_arg);
    *result = p->data;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_type_tag_object(napi_env env, napi_value object, const napi_type_tag *type_tag) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, type_tag);
    /* store tag inside a dedicated carrier hidden property */
    JSValue carrier = napi_make_ext(env, NULL, NULL, NULL);
    if (JS_IsException(carrier)) { napi_capture_exception(env); return NAPI_RET(env, napi_generic_failure); }
    napi_ext_payload *p = JS_GetOpaque(carrier, napi_ext_class_id);
    if (!p) { JS_FreeValue(env->ctx, carrier); return NAPI_RET(env, napi_generic_failure); }
    p->has_tag = true; p->tag = *type_tag;
    JSAtom atom = JS_NewAtom(env->ctx, "\xff""napi_tag");
    JS_DefinePropertyValue(env->ctx, v(object), atom, carrier, 0);
    JS_FreeAtom(env->ctx, atom);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_check_object_type_tag(napi_env env, napi_value object,
                           const napi_type_tag *type_tag, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, object); NAPI_CHECK_ARG(env, type_tag); NAPI_CHECK_ARG(env, result);
    JSValue carrier = JS_GetPropertyStr(env->ctx, v(object), "\xff""napi_tag");
    napi_ext_payload *p = JS_IsException(carrier) ? NULL : JS_GetOpaque(carrier, napi_ext_class_id);
    *result = (p && p->has_tag && p->tag.lower == type_tag->lower && p->tag.upper == type_tag->upper);
    JS_FreeValue(env->ctx, carrier);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_add_finalizer(napi_env env, napi_value js_object, void *finalize_data,
                   napi_finalize finalize_cb, void *finalize_hint, napi_ref *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, js_object); NAPI_CHECK_ARG(env, finalize_cb);
    JSValue carrier = napi_make_ext(env, finalize_data, finalize_cb, finalize_hint);
    if (JS_IsException(carrier)) { napi_capture_exception(env); return NAPI_RET(env, napi_generic_failure); }
    /* attach under a unique-ish key so multiple finalizers can coexist */
    static thread_local uint32_t seq = 0;
    char key[32];
    snprintf(key, sizeof(key), "\xff""napi_fin%u", seq++);
    if (JS_DefinePropertyValueStr(env->ctx, v(js_object), key, carrier, 0) < 0) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (result) return napi_create_reference(env, js_object, 0, result);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* References                                                                 */
/* ========================================================================== */

static void napi_ref_clear_strong(napi_ref ref) {
    if (!JS_IsUninitialized(ref->value)) {
        JS_FreeValue(ref->env->ctx, ref->value);
        ref->value = JS_UNINITIALIZED;
    }
}

static void napi_ref_clear_weak(napi_ref ref) {
    if (!JS_IsUninitialized(ref->weakref)) {
        JS_FreeValue(ref->env->ctx, ref->weakref);
        ref->weakref = JS_UNINITIALIZED;
    }
}

static napi_status napi_ref_make_weak(napi_ref ref) {
    if (JS_IsUninitialized(ref->value) || !JS_IsObject(ref->value)) {
        return NAPI_OK(ref->env);
    }
    JSValue weakref = JS_NewWeakRef(ref->env->ctx, ref->value);
    if (JS_IsException(weakref)) {
        napi_capture_exception(ref->env);
        return NAPI_RET(ref->env, napi_pending_exception);
    }
    napi_ref_clear_weak(ref);
    ref->weakref = weakref;
    napi_ref_clear_strong(ref);
    return NAPI_OK(ref->env);
}

static napi_status napi_ref_make_strong(napi_ref ref) {
    if (JS_IsUninitialized(ref->weakref)) {
        return NAPI_OK(ref->env);
    }
    JSValue target = JS_WeakRefDeref(ref->env->ctx, ref->weakref);
    if (JS_IsException(target)) {
        napi_capture_exception(ref->env);
        return NAPI_RET(ref->env, napi_pending_exception);
    }
    if (JS_IsUndefined(target)) {
        JS_FreeValue(ref->env->ctx, target);
        return NAPI_RET(ref->env, napi_generic_failure);
    }
    napi_ref_clear_strong(ref);
    ref->value = target;
    napi_ref_clear_weak(ref);
    return NAPI_OK(ref->env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_reference(napi_env env, napi_value value, uint32_t initial_refcount,
                      napi_ref *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    napi_ref ref = calloc(1, sizeof(*ref));
    if (!ref) return NAPI_RET(env, napi_generic_failure);
    ref->env = env;
    ref->count = initial_refcount;
    ref->value = JS_UNINITIALIZED;
    ref->weakref = JS_UNINITIALIZED;
    if (initial_refcount == 0) {
        if (JS_IsObject(v(value))) {
            ref->weakref = JS_NewWeakRef(env->ctx, v(value));
            if (JS_IsException(ref->weakref)) {
                napi_capture_exception(env);
                free(ref);
                return NAPI_RET(env, napi_pending_exception);
            }
        } else {
            ref->value = JS_DupValue(env->ctx, v(value));
        }
    } else {
        ref->value = JS_DupValue(env->ctx, v(value));
    }
    init_list_head(&ref->link);
    list_add_tail(&ref->link, &env->refs);
    *result = ref;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_delete_reference(napi_env env, napi_ref ref) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, ref);
    list_del(&ref->link);
    if (!JS_IsUninitialized(ref->value)) JS_FreeValue(env->ctx, ref->value);
    if (!JS_IsUninitialized(ref->weakref)) JS_FreeValue(env->ctx, ref->weakref);
    free(ref);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_reference_ref(napi_env env, napi_ref ref, uint32_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, ref);
    if (ref->count == 0) {
        napi_status st = napi_ref_make_strong(ref);
        if (st != napi_ok) return st;
    }
    ref->count++;
    if (result) *result = ref->count;
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_reference_unref(napi_env env, napi_ref ref, uint32_t *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, ref);
    if (ref->count == 0) return NAPI_RET(env, napi_invalid_arg);
    if (ref->count == 1) {
        napi_status st = napi_ref_make_weak(ref);
        if (st != napi_ok) return st;
    }
    ref->count--;
    if (result) *result = ref->count;
    return NAPI_OK(env);
}
NAPI_EXTERN napi_status NAPI_CDECL
napi_get_reference_value(napi_env env, napi_ref ref, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, ref); NAPI_CHECK_ARG(env, result);
    if (!JS_IsUninitialized(ref->value)) {
        *result = napi_add_handle(env, JS_DupValue(env->ctx, ref->value));
        return NAPI_OK(env);
    }
    if (JS_IsUninitialized(ref->weakref)) {
        *result = NULL;
        return NAPI_OK(env);
    }
    JSValue target = JS_WeakRefDeref(env->ctx, ref->weakref);
    if (JS_IsException(target)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (JS_IsUndefined(target)) {
        JS_FreeValue(env->ctx, target);
        *result = NULL;
        return NAPI_OK(env);
    }
    *result = napi_add_handle(env, target);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* ArrayBuffer / TypedArray / Buffer / DataView                               */
/* ========================================================================== */

static void napi_raw_ab_free(JSRuntime *rt, void *opaque, void *ptr) {
    (void) rt; (void) opaque;
    free(ptr);
}

static void napi_external_ab_free(JSRuntime *rt, void *opaque, void *ptr) {
    (void) rt;
    napi_ab_payload *p = opaque;
    if (!p) return;
    if (p->finalize_cb) p->finalize_cb(p->env, ptr, p->finalize_hint);
    if (p->free_data) free(ptr);
    free(p);
}

static napi_status napi_make_owned_arraybuffer(napi_env env, size_t byte_length,
                                               void **data, napi_value *result) {
    uint8_t *buf = NULL;
    if (byte_length > 0) {
        buf = malloc(byte_length);
        if (!buf) return NAPI_RET(env, napi_generic_failure);
    }
    JSValue ab = JS_NewArrayBuffer(env->ctx, buf, byte_length, napi_raw_ab_free, NULL, false);
    if (JS_IsException(ab)) {
        free(buf);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (data) *data = buf;
    *result = napi_add_handle(env, ab);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_arraybuffer(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    *result = JS_IsArrayBuffer(v(value));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_arraybuffer(napi_env env, size_t byte_length, void **data,
                        napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    return napi_make_owned_arraybuffer(env, byte_length, data, result);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_external_arraybuffer(napi_env env, void *external_data,
                                 size_t byte_length,
                                 napi_finalize finalize_cb,
                                 void *finalize_hint,
                                 napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    napi_ab_payload *p = calloc(1, sizeof(*p));
    if (!p) return NAPI_RET(env, napi_generic_failure);
    p->env = env;
    p->finalize_cb = finalize_cb;
    p->finalize_hint = finalize_hint;
    p->free_data = false;
    JSValue ab = JS_NewArrayBuffer(env->ctx, external_data, byte_length,
                                   napi_external_ab_free, p, false);
    if (JS_IsException(ab)) {
        free(p);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, ab);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_arraybuffer_info(napi_env env, napi_value arraybuffer, void **data,
                          size_t *byte_length) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, arraybuffer);
    if (!JS_IsArrayBuffer(v(arraybuffer))) return NAPI_RET(env, napi_arraybuffer_expected);
    size_t len = 0;
    uint8_t *ptr = JS_GetArrayBuffer(env->ctx, &len, v(arraybuffer));
    if (!ptr && len != 0) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_arraybuffer_expected);
    }
    if (data) *data = ptr;
    if (byte_length) *byte_length = len;
    return NAPI_OK(env);
}

static int napi_to_qjs_typedarray(napi_typedarray_type type) {
    switch (type) {
    case napi_int8_array: return JS_TYPED_ARRAY_INT8;
    case napi_uint8_array: return JS_TYPED_ARRAY_UINT8;
    case napi_uint8_clamped_array: return JS_TYPED_ARRAY_UINT8C;
    case napi_int16_array: return JS_TYPED_ARRAY_INT16;
    case napi_uint16_array: return JS_TYPED_ARRAY_UINT16;
    case napi_int32_array: return JS_TYPED_ARRAY_INT32;
    case napi_uint32_array: return JS_TYPED_ARRAY_UINT32;
    case napi_float32_array: return JS_TYPED_ARRAY_FLOAT32;
    case napi_float64_array: return JS_TYPED_ARRAY_FLOAT64;
    case napi_bigint64_array: return JS_TYPED_ARRAY_BIG_INT64;
    case napi_biguint64_array: return JS_TYPED_ARRAY_BIG_UINT64;
    default: return -1;
    }
}

static napi_typedarray_type napi_from_qjs_typedarray(int type) {
    switch (type) {
    case JS_TYPED_ARRAY_INT8: return napi_int8_array;
    case JS_TYPED_ARRAY_UINT8: return napi_uint8_array;
    case JS_TYPED_ARRAY_UINT8C: return napi_uint8_clamped_array;
    case JS_TYPED_ARRAY_INT16: return napi_int16_array;
    case JS_TYPED_ARRAY_UINT16: return napi_uint16_array;
    case JS_TYPED_ARRAY_INT32: return napi_int32_array;
    case JS_TYPED_ARRAY_UINT32: return napi_uint32_array;
    case JS_TYPED_ARRAY_FLOAT32: return napi_float32_array;
    case JS_TYPED_ARRAY_FLOAT64: return napi_float64_array;
    case JS_TYPED_ARRAY_BIG_INT64: return napi_bigint64_array;
    case JS_TYPED_ARRAY_BIG_UINT64: return napi_biguint64_array;
    default: return napi_uint8_array;
    }
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_typedarray(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    *result = JS_GetTypedArrayType(v(value)) >= 0;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_typedarray(napi_env env, napi_typedarray_type type, size_t length,
                       napi_value arraybuffer, size_t byte_offset,
                       napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, arraybuffer); NAPI_CHECK_ARG(env, result);
    int qtype = napi_to_qjs_typedarray(type);
    if (qtype < 0) return NAPI_RET(env, napi_invalid_arg);
    JSValue offv = JS_NewUint32(env->ctx, (uint32_t) byte_offset);
    JSValue lenv = JS_NewUint32(env->ctx, (uint32_t) length);
    JSValueConst args[3] = {
        v(arraybuffer),
        offv,
        lenv,
    };
    JSValue ta = JS_NewTypedArray(env->ctx, 3, args, (JSTypedArrayEnum) qtype);
    JS_FreeValue(env->ctx, offv);
    JS_FreeValue(env->ctx, lenv);
    if (JS_IsException(ta)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, ta);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_typedarray_info(napi_env env, napi_value typedarray,
                         napi_typedarray_type *type, size_t *length,
                         void **data, napi_value *arraybuffer,
                         size_t *byte_offset) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, typedarray);
    int qtype = JS_GetTypedArrayType(v(typedarray));
    if (qtype < 0) return NAPI_RET(env, napi_invalid_arg);
    size_t off = 0, blen = 0, bpe = 0;
    JSValue ab = JS_GetTypedArrayBuffer(env->ctx, v(typedarray), &off, &blen, &bpe);
    if (JS_IsException(ab)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    size_t ab_len = 0;
    uint8_t *ptr = JS_GetArrayBuffer(env->ctx, &ab_len, ab);
    if (!ptr && ab_len != 0) {
        JS_FreeValue(env->ctx, ab);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (type) *type = napi_from_qjs_typedarray(qtype);
    if (length) *length = bpe ? blen / bpe : 0;
    if (data) *data = ptr ? ptr + off : NULL;
    if (arraybuffer) *arraybuffer = napi_add_handle(env, ab);
    else JS_FreeValue(env->ctx, ab);
    if (byte_offset) *byte_offset = off;
    return NAPI_OK(env);
}

static JSValue napi_get_global_ctor(JSContext *ctx, const char *name) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue ctor = JS_GetPropertyStr(ctx, global, name);
    JS_FreeValue(ctx, global);
    return ctor;
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_dataview(napi_env env, size_t length, napi_value arraybuffer,
                     size_t byte_offset, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, arraybuffer); NAPI_CHECK_ARG(env, result);
    JSValue ctor = napi_get_global_ctor(env->ctx, "DataView");
    JSValue args[3] = {
        v(arraybuffer),
        JS_NewUint32(env->ctx, (uint32_t) byte_offset),
        JS_NewUint32(env->ctx, (uint32_t) length),
    };
    JSValue dv = JS_CallConstructor(env->ctx, ctor, 3, args);
    JS_FreeValue(env->ctx, ctor);
    JS_FreeValue(env->ctx, args[1]);
    JS_FreeValue(env->ctx, args[2]);
    if (JS_IsException(dv)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, dv);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_dataview(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    *result = JS_IsDataView(v(value));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_dataview_info(napi_env env, napi_value dataview, size_t *bytelength,
                       void **data, napi_value *arraybuffer,
                       size_t *byte_offset) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, dataview);
    if (!JS_IsDataView(v(dataview))) return NAPI_RET(env, napi_invalid_arg);
    JSValue ab = JS_GetPropertyStr(env->ctx, v(dataview), "buffer");
    JSValue offv = JS_GetPropertyStr(env->ctx, v(dataview), "byteOffset");
    JSValue lenv = JS_GetPropertyStr(env->ctx, v(dataview), "byteLength");
    if (JS_IsException(ab) || JS_IsException(offv) || JS_IsException(lenv)) {
        JS_FreeValue(env->ctx, ab); JS_FreeValue(env->ctx, offv); JS_FreeValue(env->ctx, lenv);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    uint32_t off = 0, len = 0;
    JS_ToUint32(env->ctx, &off, offv);
    JS_ToUint32(env->ctx, &len, lenv);
    size_t ab_len = 0;
    uint8_t *ptr = JS_GetArrayBuffer(env->ctx, &ab_len, ab);
    JS_FreeValue(env->ctx, offv); JS_FreeValue(env->ctx, lenv);
    if (!ptr && ab_len != 0) {
        JS_FreeValue(env->ctx, ab);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (bytelength) *bytelength = len;
    if (data) *data = ptr ? ptr + off : NULL;
    if (byte_offset) *byte_offset = off;
    if (arraybuffer) *arraybuffer = napi_add_handle(env, ab);
    else JS_FreeValue(env->ctx, ab);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_buffer(napi_env env, size_t length, void **data, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    uint8_t *buf = length ? malloc(length) : NULL;
    if (length && !buf) return NAPI_RET(env, napi_generic_failure);
    JSValue b = JS_NewUint8Array(env->ctx, buf, length, napi_raw_ab_free, NULL, false);
    if (JS_IsException(b)) {
        free(buf);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    if (data) *data = buf;
    *result = napi_add_handle(env, b);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_external_buffer(napi_env env, size_t length, void *data,
                            napi_finalize finalize_cb, void *finalize_hint,
                            napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    napi_ab_payload *p = calloc(1, sizeof(*p));
    if (!p) return NAPI_RET(env, napi_generic_failure);
    p->env = env;
    p->finalize_cb = finalize_cb;
    p->finalize_hint = finalize_hint;
    p->free_data = false;
    JSValue b = JS_NewUint8Array(env->ctx, data, length, napi_external_ab_free, p, false);
    if (JS_IsException(b)) {
        free(p);
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, b);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_buffer_copy(napi_env env, size_t length, const void *data,
                        void **result_data, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    void *buf = NULL;
    napi_status s = napi_create_buffer(env, length, &buf, result);
    if (s != napi_ok) return s;
    if (length && data) memcpy(buf, data, length);
    if (result_data) *result_data = buf;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_buffer(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    *result = JS_GetTypedArrayType(v(value)) == JS_TYPED_ARRAY_UINT8;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_buffer_info(napi_env env, napi_value value, void **data, size_t *length) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value);
    if (JS_GetTypedArrayType(v(value)) != JS_TYPED_ARRAY_UINT8) {
        return NAPI_RET(env, napi_invalid_arg);
    }
    return napi_get_typedarray_info(env, value, NULL, length, data, NULL, NULL);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_detach_arraybuffer(napi_env env, napi_value arraybuffer) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, arraybuffer);
    if (!JS_IsArrayBuffer(v(arraybuffer))) return NAPI_RET(env, napi_arraybuffer_expected);
    JS_DetachArrayBuffer(env->ctx, v(arraybuffer));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_detached_arraybuffer(napi_env env, napi_value value, bool *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsArrayBuffer(v(value))) return NAPI_RET(env, napi_arraybuffer_expected);
    size_t len = 0;
    uint8_t *ptr = JS_GetArrayBuffer(env->ctx, &len, v(value));
    if (!ptr && len != 0) {
        JSValue exc = JS_GetException(env->ctx);
        JS_FreeValue(env->ctx, exc);
        *result = true;
    } else {
        *result = false;
    }
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Promise / Date / BigInt words / misc values                                */
/* ========================================================================== */

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_promise(napi_env env, napi_deferred *deferred, napi_value *promise) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, deferred); NAPI_CHECK_ARG(env, promise);
    JSValue funcs[2];
    JSValue p = JS_NewPromiseCapability(env->ctx, funcs);
    if (JS_IsException(p)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    napi_deferred d = calloc(1, sizeof(*d));
    if (!d) {
        JS_FreeValue(env->ctx, funcs[0]); JS_FreeValue(env->ctx, funcs[1]); JS_FreeValue(env->ctx, p);
        return NAPI_RET(env, napi_generic_failure);
    }
    d->env = env;
    d->resolve = funcs[0];
    d->reject = funcs[1];
    *deferred = d;
    *promise = napi_add_handle(env, p);
    return NAPI_OK(env);
}

static napi_status napi_settle_deferred(napi_env env, napi_deferred deferred,
                                        napi_value value, bool reject) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, deferred); NAPI_CHECK_ARG(env, value);
    JSValue fn = reject ? deferred->reject : deferred->resolve;
    JSValueConst arg = v(value);
    JSValue r = JS_Call(env->ctx, fn, JS_UNDEFINED, 1, &arg);
    JS_FreeValue(env->ctx, deferred->resolve);
    JS_FreeValue(env->ctx, deferred->reject);
    free(deferred);
    if (JS_IsException(r)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    JS_FreeValue(env->ctx, r);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_resolve_deferred(napi_env env, napi_deferred deferred, napi_value resolution) {
    return napi_settle_deferred(env, deferred, resolution, false);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_reject_deferred(napi_env env, napi_deferred deferred, napi_value rejection) {
    return napi_settle_deferred(env, deferred, rejection, true);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_promise(napi_env env, napi_value value, bool *is_promise) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, is_promise);
    *is_promise = JS_IsPromise(v(value));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_date(napi_env env, double time, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    JSValue d = JS_NewDate(env->ctx, time);
    if (JS_IsException(d)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, d);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_is_date(napi_env env, napi_value value, bool *is_date) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, is_date);
    *is_date = JS_IsDate(v(value));
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_date_value(napi_env env, napi_value value, double *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, result);
    if (!JS_IsDate(v(value))) return NAPI_RET(env, napi_date_expected);
    JSValue fn = JS_GetPropertyStr(env->ctx, v(value), "getTime");
    JSValue r = JS_Call(env->ctx, fn, v(value), 0, NULL);
    JS_FreeValue(env->ctx, fn);
    if (JS_IsException(r)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    int rc = JS_ToFloat64(env->ctx, result, r);
    JS_FreeValue(env->ctx, r);
    if (rc < 0) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_number_expected);
    }
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_bigint_words(napi_env env, int sign_bit, size_t word_count,
                         const uint64_t *words, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    if (sign_bit != 0 && sign_bit != 1) return NAPI_RET(env, napi_invalid_arg);
    if (word_count > 0 && words == NULL) return NAPI_RET(env, napi_invalid_arg);
    JSValue bi = JS_NewBigIntWords(env->ctx, sign_bit, word_count, words);
    if (JS_IsException(bi)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, bi);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_value_bigint_words(napi_env env, napi_value value, int *sign_bit,
                            size_t *word_count, uint64_t *words) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, value); NAPI_CHECK_ARG(env, word_count);
    if (!JS_IsBigInt(v(value))) return NAPI_RET(env, napi_bigint_expected);
    size_t count = words ? *word_count : 0;
    if (JS_GetBigIntWords(env->ctx, v(value), sign_bit, &count, words) < 0) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_bigint_expected);
    }
    *word_count = count;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
node_api_symbol_for(napi_env env, const char *utf8description, size_t length,
                    napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, utf8description); NAPI_CHECK_ARG(env, result);
    size_t len = length == NAPI_AUTO_LENGTH ? strlen(utf8description) : length;
    char *desc = malloc(len + 1);
    if (!desc) return NAPI_RET(env, napi_generic_failure);
    memcpy(desc, utf8description, len);
    desc[len] = '\0';
    JSValue sym = JS_NewSymbol(env->ctx, desc, true);
    free(desc);
    *result = napi_add_handle(env, sym);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_run_script(napi_env env, napi_value script, napi_value *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, script); NAPI_CHECK_ARG(env, result);
    size_t len = 0;
    const char *src = JS_ToCStringLen(env->ctx, &len, v(script));
    if (!src) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_string_expected);
    }
    JSValue r = JS_Eval(env->ctx, src, len, "<napi>", JS_EVAL_TYPE_GLOBAL);
    JS_FreeCString(env->ctx, src);
    if (JS_IsException(r)) {
        napi_capture_exception(env);
        return NAPI_RET(env, napi_pending_exception);
    }
    *result = napi_add_handle(env, r);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_adjust_external_memory(node_api_basic_env basic_env, int64_t change_in_bytes,
                            int64_t *adjusted_value) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env);
    if (adjusted_value) *adjusted_value = change_in_bytes;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_version(node_api_basic_env basic_env, uint32_t *result) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    *result = NAPI_VERSION;
    return NAPI_OK(env);
}

static const napi_node_version napi_node_ver = { 22, 0, 0, "node" };

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_node_version(node_api_basic_env basic_env, const napi_node_version **version) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, version);
    *version = &napi_node_ver;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_uv_event_loop(node_api_basic_env basic_env, uv_loop_t **loop) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, loop);
    *loop = env->loop;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
node_api_get_module_file_name(node_api_basic_env basic_env, const char **result) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    *result = env->filename ? env->filename : "";
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_set_instance_data(node_api_basic_env basic_env, void *data,
                       napi_finalize finalize_cb, void *finalize_hint) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env);
    env->instance_data = data;
    env->instance_finalize_cb = finalize_cb;
    env->instance_finalize_hint = finalize_hint;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_instance_data(node_api_basic_env basic_env, void **data) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, data);
    *data = env->instance_data;
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Callback scopes / async hooks / async work                                 */
/* ========================================================================== */

NAPI_EXTERN napi_status NAPI_CDECL
napi_async_init(napi_env env, napi_value async_resource,
                napi_value async_resource_name, napi_async_context *result) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    napi_async_context c = calloc(1, sizeof(*c));
    if (!c) return NAPI_RET(env, napi_generic_failure);
    c->env = env;
    c->resource = async_resource ? JS_DupValue(env->ctx, v(async_resource)) : JS_UNDEFINED;
    c->name = async_resource_name ? JS_DupValue(env->ctx, v(async_resource_name)) : JS_UNDEFINED;
    *result = c;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_async_destroy(napi_env env, napi_async_context async_context) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, async_context);
    JS_FreeValue(env->ctx, async_context->resource);
    JS_FreeValue(env->ctx, async_context->name);
    free(async_context);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_make_callback(napi_env env, napi_async_context async_context,
                   napi_value recv, napi_value func, size_t argc,
                   const napi_value *argv, napi_value *result) {
    (void) async_context;
    return napi_call_function(env, recv, func, argc, argv, result);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_open_callback_scope(napi_env env, napi_value resource_object,
                         napi_async_context context,
                         napi_callback_scope *result) {
    (void) resource_object; (void) context;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    napi_callback_scope s = calloc(1, sizeof(*s));
    if (!s) return NAPI_RET(env, napi_generic_failure);
    s->scope = napi_scope_open(env, false);
    *result = s;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_close_callback_scope(napi_env env, napi_callback_scope scope) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, scope);
    if (env->open_scope != scope->scope) return NAPI_RET(env, napi_callback_scope_mismatch);
    napi_scope_close(env, scope->scope);
    free(scope);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_add_env_cleanup_hook(node_api_basic_env basic_env, napi_cleanup_hook fun,
                          void *arg) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, fun);
    napi_cleanup_entry *e = calloc(1, sizeof(*e));
    if (!e) return NAPI_RET(env, napi_generic_failure);
    e->fn = fun;
    e->arg = arg;
    list_add_tail(&e->link, &env->cleanup_hooks);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_remove_env_cleanup_hook(node_api_basic_env basic_env, napi_cleanup_hook fun,
                             void *arg) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, fun);
    struct list_head *el, *tmp;
    list_for_each_safe(el, tmp, &env->cleanup_hooks) {
        napi_cleanup_entry *e = list_entry(el, napi_cleanup_entry, link);
        if (e->fn == fun && e->arg == arg) {
            list_del(&e->link);
            free(e);
            return NAPI_OK(env);
        }
    }
    return NAPI_RET(env, napi_invalid_arg);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_add_async_cleanup_hook(node_api_basic_env basic_env,
                            napi_async_cleanup_hook hook, void *arg,
                            napi_async_cleanup_hook_handle *remove_handle) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, hook);
    napi_async_cleanup_entry *e = calloc(1, sizeof(*e));
    if (!e) return NAPI_RET(env, napi_generic_failure);
    e->env = env;
    e->hook = hook;
    e->data = arg;
    list_add_tail(&e->link, &env->async_cleanup_hooks);
    if (remove_handle) *remove_handle = e;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_remove_async_cleanup_hook(napi_async_cleanup_hook_handle remove_handle) {
    if (!remove_handle) return napi_invalid_arg;
    napi_env env = remove_handle->env;
    list_del(&remove_handle->link);
    free(remove_handle);
    return NAPI_OK(env);
}

static void napi_async_work_execute(uv_work_t *req) {
    napi_async_work w = req->data;
    if (!w->cancelled && w->execute) w->execute(w->env, w->data);
}

static void napi_async_work_complete(uv_work_t *req, int status) {
    napi_async_work w = req->data;
    w->done = true;
    if (status == UV_ECANCELED) w->cancelled = true;
    if (w->complete) {
        napi_handle_scope scope = napi_scope_open(w->env, false);
        w->complete(w->env, w->cancelled ? napi_cancelled : napi_ok, w->data);
        napi_scope_close(w->env, scope);
    }
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_async_work(napi_env env, napi_value async_resource,
                       napi_value async_resource_name,
                       napi_async_execute_callback execute,
                       napi_async_complete_callback complete,
                       void *data, napi_async_work *result) {
    (void) async_resource; (void) async_resource_name;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, execute); NAPI_CHECK_ARG(env, complete); NAPI_CHECK_ARG(env, result);
    napi_async_work w = calloc(1, sizeof(*w));
    if (!w) return NAPI_RET(env, napi_generic_failure);
    w->env = env;
    w->execute = execute;
    w->complete = complete;
    w->data = data;
    w->req.data = w;
    *result = w;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_queue_async_work(node_api_basic_env basic_env, napi_async_work work) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, work);
    if (work->queued) return NAPI_RET(env, napi_invalid_arg);
    work->queued = true;
    int r = uv_queue_work(env->loop, &work->req, napi_async_work_execute,
                          napi_async_work_complete);
    if (r != 0) {
        work->queued = false;
        return NAPI_RET(env, napi_generic_failure);
    }
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_cancel_async_work(node_api_basic_env basic_env, napi_async_work work) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, work);
    work->cancelled = true;
    int r = uv_cancel((uv_req_t *) &work->req);
    return r == 0 || r == UV_EBUSY ? NAPI_OK(env) : NAPI_RET(env, napi_generic_failure);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_delete_async_work(napi_env env, napi_async_work work) {
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, work);
    if (work->queued && !work->done) return NAPI_RET(env, napi_invalid_arg);
    free(work);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Thread-safe function                                                       */
/* ========================================================================== */

static void napi_tsfn_maybe_close(napi_threadsafe_function tsfn);

static void napi_tsfn_close_cb(uv_handle_t *handle) {
    napi_threadsafe_function tsfn = handle->data;
    if (tsfn->link.prev && tsfn->link.next) list_del(&tsfn->link);
    uv_mutex_destroy(&tsfn->mutex);
    uv_cond_destroy(&tsfn->cond);
    JS_FreeValue(tsfn->env->ctx, tsfn->func);
    if (tsfn->finalize_cb) {
        tsfn->finalize_cb(tsfn->env, tsfn->finalize_data, NULL);
    }
    free(tsfn);
}

static void napi_tsfn_async_cb(uv_async_t *handle) {
    napi_threadsafe_function tsfn = handle->data;
    for (;;) {
        uv_mutex_lock(&tsfn->mutex);
        if (list_empty(&tsfn->queue)) {
            uv_cond_broadcast(&tsfn->cond);
            bool should_close = tsfn->closing && tsfn->thread_count == 0 && !tsfn->close_started;
            if (should_close) {
                tsfn->close_started = true;
                uv_mutex_unlock(&tsfn->mutex);
                uv_close((uv_handle_t *) &tsfn->async, napi_tsfn_close_cb);
                return;
            }
            uv_mutex_unlock(&tsfn->mutex);
            return;
        }
        struct list_head *el = tsfn->queue.next;
        list_del(el);
        tsfn->queue_size--;
        uv_cond_broadcast(&tsfn->cond);
        uv_mutex_unlock(&tsfn->mutex);

        napi_tsfn_item *item = list_entry(el, napi_tsfn_item, link);
        napi_handle_scope scope = napi_scope_open(tsfn->env, false);
        napi_value js_cb = napi_add_handle(tsfn->env, JS_DupValue(tsfn->env->ctx, tsfn->func));
        if (tsfn->call_js_cb) {
            tsfn->call_js_cb(tsfn->env, js_cb, tsfn->context, item->data);
        } else {
            napi_call_function(tsfn->env, NULL, js_cb, 0, NULL, NULL);
        }
        napi_scope_close(tsfn->env, scope);
        free(item);
        napi_tsfn_maybe_close(tsfn);
    }
}

static void napi_tsfn_maybe_close(napi_threadsafe_function tsfn) {
    uv_mutex_lock(&tsfn->mutex);
    bool should_send = tsfn->closing && tsfn->thread_count == 0;
    uv_mutex_unlock(&tsfn->mutex);
    if (should_send && !uv_is_closing((uv_handle_t *) &tsfn->async)) {
        uv_async_send(&tsfn->async);
    }
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_create_threadsafe_function(napi_env env, napi_value func,
                                napi_value async_resource,
                                napi_value async_resource_name,
                                size_t max_queue_size,
                                size_t initial_thread_count,
                                void *thread_finalize_data,
                                napi_finalize thread_finalize_cb,
                                void *context,
                                napi_threadsafe_function_call_js call_js_cb,
                                napi_threadsafe_function *result) {
    (void) async_resource; (void) async_resource_name;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, result);
    if (!func && !call_js_cb) return NAPI_RET(env, napi_invalid_arg);
    napi_threadsafe_function tsfn = calloc(1, sizeof(*tsfn));
    if (!tsfn) return NAPI_RET(env, napi_generic_failure);
    tsfn->env = env;
    tsfn->func = func ? JS_DupValue(env->ctx, v(func)) : JS_UNDEFINED;
    tsfn->context = context;
    tsfn->finalize_data = thread_finalize_data;
    tsfn->finalize_cb = thread_finalize_cb;
    tsfn->call_js_cb = call_js_cb;
    tsfn->max_queue_size = max_queue_size;
    tsfn->thread_count = initial_thread_count;
    init_list_head(&tsfn->queue);
    init_list_head(&tsfn->link);
    uv_mutex_init(&tsfn->mutex);
    uv_cond_init(&tsfn->cond);
    if (uv_async_init(env->loop, &tsfn->async, napi_tsfn_async_cb) != 0) {
        uv_mutex_destroy(&tsfn->mutex);
        uv_cond_destroy(&tsfn->cond);
        JS_FreeValue(env->ctx, tsfn->func);
        free(tsfn);
        return NAPI_RET(env, napi_generic_failure);
    }
    tsfn->async.data = tsfn;
    list_add_tail(&tsfn->link, &env->tsfns);
    *result = tsfn;
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_get_threadsafe_function_context(napi_threadsafe_function func, void **result) {
    if (!func || !result) return napi_invalid_arg;
    *result = func->context;
    return NAPI_OK(func->env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_call_threadsafe_function(napi_threadsafe_function func, void *data,
                              napi_threadsafe_function_call_mode is_blocking) {
    if (!func) return napi_invalid_arg;
    uv_mutex_lock(&func->mutex);
    while (!func->closing && func->max_queue_size > 0 &&
           func->queue_size >= func->max_queue_size) {
        if (is_blocking == napi_tsfn_nonblocking) {
            uv_mutex_unlock(&func->mutex);
            return NAPI_RET(func->env, napi_queue_full);
        }
        uv_cond_wait(&func->cond, &func->mutex);
    }
    if (func->closing) {
        uv_mutex_unlock(&func->mutex);
        return NAPI_RET(func->env, napi_closing);
    }
    napi_tsfn_item *item = calloc(1, sizeof(*item));
    if (!item) {
        uv_mutex_unlock(&func->mutex);
        return NAPI_RET(func->env, napi_generic_failure);
    }
    item->data = data;
    list_add_tail(&item->link, &func->queue);
    func->queue_size++;
    uv_mutex_unlock(&func->mutex);
    uv_async_send(&func->async);
    return NAPI_OK(func->env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_acquire_threadsafe_function(napi_threadsafe_function func) {
    if (!func) return napi_invalid_arg;
    uv_mutex_lock(&func->mutex);
    if (func->closing) {
        uv_mutex_unlock(&func->mutex);
        return NAPI_RET(func->env, napi_closing);
    }
    func->thread_count++;
    uv_mutex_unlock(&func->mutex);
    return NAPI_OK(func->env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_release_threadsafe_function(napi_threadsafe_function func,
                                 napi_threadsafe_function_release_mode mode) {
    if (!func) return napi_invalid_arg;
    uv_mutex_lock(&func->mutex);
    if (func->thread_count > 0) func->thread_count--;
    if (mode == napi_tsfn_abort || func->thread_count == 0) {
        func->closing = true;
        if (mode == napi_tsfn_abort) func->aborted = true;
    }
    uv_mutex_unlock(&func->mutex);
    napi_tsfn_maybe_close(func);
    uv_async_send(&func->async);
    return NAPI_OK(func->env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_unref_threadsafe_function(node_api_basic_env basic_env,
                               napi_threadsafe_function func) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, func);
    uv_unref((uv_handle_t *) &func->async);
    return NAPI_OK(env);
}

NAPI_EXTERN napi_status NAPI_CDECL
napi_ref_threadsafe_function(node_api_basic_env basic_env,
                             napi_threadsafe_function func) {
    napi_env env = (napi_env) basic_env;
    NAPI_CHECK_ENV(env); NAPI_CHECK_ARG(env, func);
    uv_ref((uv_handle_t *) &func->async);
    return NAPI_OK(env);
}

/* ========================================================================== */
/* Node-API addon loading                                                     */
/* ========================================================================== */

NAPI_EXTERN void NAPI_CDECL
napi_module_register(napi_module *mod) {
    napi_pending_module = mod;
}

static JSValue napi_throw_dlerror(JSContext *ctx, uv_lib_t *lib, const char *path) {
    const char *msg = uv_dlerror(lib);
    return JS_ThrowReferenceError(ctx, "cannot load Node-API addon '%s': %s",
                                  path, msg ? msg : "unknown error");
}

static JSValue tjs__napi_dlopen(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    (void) this_val;
    if (argc < 1) return JS_ThrowTypeError(ctx, "dlopen(path) requires a path");
    const char *path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;

    TJSDynLib *node = calloc(1, sizeof(*node));
    if (!node) {
        JS_FreeCString(ctx, path);
        return JS_ThrowOutOfMemory(ctx);
    }
    napi_pending_module = NULL;
    if (uv_dlopen(path, &node->lib) != 0) {
        JSValue err = napi_throw_dlerror(ctx, &node->lib, path);
        uv_dlclose(&node->lib);
        free(node);
        JS_FreeCString(ctx, path);
        return err;
    }

    node_api_addon_get_api_version_func version_fn = NULL;
    if (uv_dlsym(&node->lib, "node_api_module_get_api_version_v1",
                 (void **) &version_fn) != 0) {
        version_fn = NULL;
    }
    int api_version = version_fn ? version_fn() : 8;
    if (api_version <= 0 || api_version > NAPI_VERSION) api_version = NAPI_VERSION;

    napi_addon_register_func register_fn = NULL;
    if (uv_dlsym(&node->lib, "napi_register_module_v1",
                 (void **) &register_fn) != 0) {
        register_fn = NULL;
    }
    if (!register_fn && napi_pending_module) {
        register_fn = napi_pending_module->nm_register_func;
    }
    if (!register_fn) {
        JSValue err = JS_ThrowReferenceError(ctx,
                                             "Node-API addon '%s' has no registration symbol",
                                             path);
        uv_dlclose(&node->lib);
        free(node);
        JS_FreeCString(ctx, path);
        return err;
    }

    napi_env env = napi_env_new(ctx, path, api_version);
    napi_handle_scope scope = napi_scope_open(env, false);
    JSValue exports_obj = JS_NewObject(ctx);
    napi_value exports_handle = napi_add_handle(env, JS_DupValue(ctx, exports_obj));
    napi_value registered = register_fn(env, exports_handle);
    JSValue result = registered ? JS_DupValue(ctx, v(registered)) : JS_DupValue(ctx, exports_obj);
    JS_FreeValue(ctx, exports_obj);
    napi_scope_close(env, scope);

    if (NAPI_PENDING(env)) {
        JSValue exc = env->pending_exception;
        env->pending_exception = JS_UNINITIALIZED;
        JS_FreeValue(ctx, result);
        uv_dlclose(&node->lib);
        free(node);
        JS_FreeCString(ctx, path);
        return JS_Throw(ctx, exc);
    }

    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    list_add_tail(&node->link, &qrt->module.dyn_libs);
    JS_FreeCString(ctx, path);
    return result;
}

static const JSCFunctionListEntry napi_module_funcs[] = {
    TJS_CFUNC_DEF("dlopen", 1, tjs__napi_dlopen),
};

void tjs__mod_nodeapi_init(JSContext *ctx, JSValue ns) {
    napi_ensure_classes(ctx);
    JS_SetPropertyFunctionList(ctx, ns, napi_module_funcs, countof(napi_module_funcs));
}
