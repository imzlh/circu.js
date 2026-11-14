/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
 * Copyright (c) 2026-present iz <himzlh@163.com>
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

#include "private.h"
#include "tjs.h"
#include "utils.h"
#include "capability.h"

#include <stdlib.h>
#include <string.h>
#include <wasm_export.h>

/* Internal WAMR headers for direct access to import/instance structures */
#include "../deps/wamr/core/iwasm/interpreter/wasm.h"
#include "wasm_runtime.h"
#if WASM_ENABLE_AOT != 0
#include "../deps/wamr/core/iwasm/aot/aot_runtime.h"
#endif

#define TJS__WASM_MAX_ARGS       		32
#define TJS__WASM_ERROR_BUF_SIZE		256
#define TJS__WASM_MIN_STACK_SIZE        (16 * 1024)
#define TJS__WASM_DEFAULT_STACK_SIZE    (64 * 1024)
#define TJS__WASM_MAX_STACK_SIZE        (64 * 1024 * 1024)

typedef struct TJSWasmImportGroup TJSWasmImportGroup;
typedef struct TJSWasmInstance TJSWasmInstance;
typedef struct TJSWasmMemoryBuffer TJSWasmMemoryBuffer;
typedef struct TJSWasmExternRefBox TJSWasmExternRefBox;

typedef struct {
    uint8_t kind;
    uint8_t source_is_import;
    uint8_t reserved[2];
    uint32_t import_index;
    uint32_t source_index;
    JSValue provider;
    JSValue owner;
} TJSWasmExternImport;

static thread_local JSClassID tjs_wasm_module_class_id;

typedef struct {
    wasm_module_t module;
    struct {
        uint8_t *bytes;
        size_t size;
    } data;
    struct {
        char **argv;
        uint32_t argc;
        char **env;
        uint32_t env_count;
        char **map_dir_list;
        uint32_t map_dir_count;
    } wasi;
    /* Native import registrations belong to the loaded module and can be used
     * by every instance created from it. */
    TJSWasmImportGroup *import_groups;
    /* Manually allocated table/memory type stubs for link validation. */
    WASMTable **resolved_tables;
    uint32_t resolved_table_count;
    WASMMemory **resolved_memories;
    uint32_t resolved_memory_count;
    /* JS owners for instance-scoped live extern bindings. */
    TJSWasmExternImport *extern_imports;
    uint32_t extern_import_count;
} TJSWasmModule;

static void tjs__wasm_free_import_groups(JSRuntime *rt,
                                         TJSWasmImportGroup *group);
static void tjs_wasm_module_mark(JSRuntime *rt, JSValue val,
                                 JS_MarkFunc *mark_func);
static JSValue tjs_wasm_resolveimports(JSContext *ctx, JSValue this_val,
                                       int argc, JSValue *argv);
JSValue tjs_throw_wasm_error(JSContext *ctx, const char *name,
                             const char *msg);

static void tjs__wasm_free_string_array(JSRuntime *rt, char **values,
                                        uint32_t count) {
    if (!values)
        return;
    for (uint32_t index = 0; index < count; index++)
        js_free_rt(rt, values[index]);
    js_free_rt(rt, values);
}

static void tjs_wasm_module_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmModule *m = JS_GetOpaque(val, tjs_wasm_module_class_id);
    if (m) {
        if (m->module) {
            wasm_runtime_unload(m->module);
        }
        tjs__wasm_free_import_groups(rt, m->import_groups);
        js_free_rt(rt, m->data.bytes);
        /* Free WASI allocations */
        tjs__wasm_free_string_array(rt, m->wasi.argv, m->wasi.argc);
        tjs__wasm_free_string_array(rt, m->wasi.env, m->wasi.env_count);
        tjs__wasm_free_string_array(rt, m->wasi.map_dir_list,
                                    m->wasi.map_dir_count);
        /* Free manually allocated table/memory import stubs */
        for (uint32_t i = 0; i < m->resolved_table_count; i++) {
            wasm_runtime_free(m->resolved_tables[i]);
        }
        js_free_rt(rt, m->resolved_tables);
        for (uint32_t i = 0; i < m->resolved_memory_count; i++) {
            wasm_runtime_free(m->resolved_memories[i]);
        }
        js_free_rt(rt, m->resolved_memories);
        for (uint32_t i = 0; i < m->extern_import_count; i++) {
            JS_FreeValueRT(rt, m->extern_imports[i].provider);
            JS_FreeValueRT(rt, m->extern_imports[i].owner);
        }
        js_free_rt(rt, m->extern_imports);
        js_free_rt(rt, m);
    }
}

static JSClassDef tjs_wasm_module_class = {
    "Module",
    .finalizer = tjs_wasm_module_finalizer,
    .gc_mark = tjs_wasm_module_mark,
};

/* Import trampoline context: bridges WAMR native calls to JS functions */
typedef struct {
    JSContext *ctx;
    JSValue func;          /* The JS callback function */
    wasm_func_type_t type; /* WAMR function type for param/result conversion */
    uint32_t import_index;
    bool is_host_binding;
} TJSWasmImportCtx;

/* Registered native symbols for a single import module name */
typedef struct TJSWasmImportGroup {
    char *module_name;
    NativeSymbol *symbols;
    uint32_t count;
    TJSWasmImportCtx *ctxs;
    bool registered;
    struct TJSWasmImportGroup *next;
} TJSWasmImportGroup;

static void tjs__wasm_free_import_groups(JSRuntime *rt,
                                         TJSWasmImportGroup *group) {
    while (group) {
        TJSWasmImportGroup *next = group->next;
        if (group->registered)
            wasm_runtime_unregister_natives(group->module_name, group->symbols);
        for (uint32_t index = 0; index < group->count; index++) {
            if (group->ctxs)
                JS_FreeValueRT(rt, group->ctxs[index].func);
            if (group->symbols) {
                js_free_rt(rt, (char *)group->symbols[index].symbol);
                js_free_rt(rt, (char *)group->symbols[index].signature);
            }
        }
        js_free_rt(rt, group->ctxs);
        js_free_rt(rt, group->symbols);
        js_free_rt(rt, group->module_name);
        js_free_rt(rt, group);
        group = next;
    }
}

static void tjs_wasm_module_mark(JSRuntime *rt, JSValue val,
                                 JS_MarkFunc *mark_func) {
    TJSWasmModule *m = JS_GetOpaque(val, tjs_wasm_module_class_id);
    if (!m)
        return;
    for (TJSWasmImportGroup *group = m->import_groups; group;
         group = group->next) {
        for (uint32_t index = 0; index < group->count; index++)
            JS_MarkValue(rt, group->ctxs[index].func, mark_func);
    }
    for (uint32_t i = 0; i < m->extern_import_count; i++) {
        JS_MarkValue(rt, m->extern_imports[i].provider, mark_func);
        JS_MarkValue(rt, m->extern_imports[i].owner, mark_func);
    }
}

static thread_local JSClassID tjs_wasm_instance_class_id;

static bool tjs__wasm_is_bytecode_module(wasm_module_t module);

struct TJSWasmInstance {
    /* The creating context is needed to detach externally-held memory
     * ArrayBuffers during finalization. JS_GetRuntimeOpaque() returns a
     * TJSRuntime, not a JSContext. */
    JSContext *ctx;
    wasm_module_inst_t module_inst;
    wasm_exec_env_t exec_env;
    /* Keep the loaded module alive for at least as long as the instance. */
    JSValue module_owner;
    /* Recover the public low-level Instance object for a funcref slot without
     * making the native instance keep its own wrapper alive forever. */
    JSValue weak_self;
    bool has_pending_exception;
    JSValue pending_exception;
    /* The active provider module on which the trampoline installed the WAMR
     * trap. It can differ from this (outer caller) instance's module. */
    wasm_module_inst_t pending_exception_module;
    /* externref: JSValues boxed for WAMR's externref map */
    TJSWasmExternRefBox **externrefs;
    uint32_t externref_count;
    uint32_t externref_capacity;
    /* One cached ArrayBuffer per concrete memory. Multi-memory instances and
     * imported memories cannot share a single "default memory" cache. */
    TJSWasmMemoryBuffer *memory_buffers;
    /* Instance-scoped imported externs and their provider keep-alives. */
    TJSWasmExternImport *extern_imports;
    uint32_t extern_import_count;
    /* Host callbacks are copied from Module configuration so every WAMR
     * instance owns distinct attachments and keep-alives. */
    TJSWasmImportCtx *function_imports;
    uint32_t function_import_count;
    /* Configuration created by instantiate({ functions }). Its strings and
     * duplicate JS values remain alive because WAMR keeps signature pointers
     * for the lifetime of the instance. */
    TJSWasmImportGroup *owned_function_groups;
    TJSWasmExternImport *owned_function_externs;
    uint32_t owned_function_extern_count;
    /* Intrusive thread-local list used to invalidate every JS view of the same
     * concrete imported memory after either borrower grows it. */
    TJSWasmInstance *live_prev;
    TJSWasmInstance *live_next;
};

struct TJSWasmMemoryBuffer {
    wasm_memory_inst_t memory;
    JSValue buffer;
    void *base;
    size_t byte_length;
    TJSWasmMemoryBuffer *next;
};

struct TJSWasmExternRefBox {
    JSRuntime *rt;
    TJSWasmInstance *owner;
    JSValue value;
    TJSWasmExternRefBox *live_prev;
    TJSWasmExternRefBox *live_next;
};

static thread_local TJSWasmInstance *tjs__wasm_live_instances;
static thread_local TJSWasmExternRefBox *tjs__wasm_live_externrefs;

/* Forward declarations — used by the import trampoline before their definition. */
static TJSWasmMemoryBuffer *tjs__wasm_find_memory_buffer(
    TJSWasmInstance *inst, wasm_memory_inst_t memory);
static void tjs__wasm_invalidate_memory(TJSWasmInstance *inst,
                                        wasm_memory_inst_t memory);
static size_t tjs__wasm_mem_byte_length(wasm_memory_inst_t mem);
static wasm_valkind_t tjs__wasm_func_type_get_result_valkind_safe(WASMFuncType *func_type, uint32_t result_index);

/* WAMR-backed ArrayBuffers are marked pin-unsupported before JS can observe
 * them. A failed detach therefore means that invariant was broken after WAMR
 * may already have moved its memory. Continuing would expose a dangling
 * pointer, so clear the diagnostic and terminate instead of returning to JS. */
static void tjs__wasm_detach_membuf(JSContext *ctx, JSValueConst buffer) {
    if (JS_DetachArrayBuffer(ctx, buffer) < 0) {
        JSValue exception = JS_GetException(ctx);
        JS_FreeValue(ctx, exception);
        abort();
    }
}

static void tjs_wasm_instance_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmInstance *i = JS_GetOpaque(val, tjs_wasm_instance_class_id);
    if (i) {
        if (i->live_prev)
            i->live_prev->live_next = i->live_next;
        else if (tjs__wasm_live_instances == i)
            tjs__wasm_live_instances = i->live_next;
        if (i->live_next)
            i->live_next->live_prev = i->live_prev;
        if (i->exec_env) {
            wasm_runtime_destroy_exec_env(i->exec_env);
        }
        /* Detach memory buffer before deinstantiating to prevent UAF if
         * the buffer is held externally beyond instance lifetime. */
        for (TJSWasmMemoryBuffer *cache = i->memory_buffers; cache;
             cache = cache->next) {
            if (!JS_IsUndefined(cache->buffer) && i->ctx)
                tjs__wasm_detach_membuf(i->ctx, cache->buffer);
        }
        /* WAMR owns mapped boxes through their cleanup callback. Detaching the
         * weak creator pointer before deinstantiate lets a Table-retained box
         * outlive this Instance without leaving a dangling owner pointer. */
        for (uint32_t j = 0; j < i->externref_count; j++)
            if (i->externrefs[j])
                i->externrefs[j]->owner = NULL;
        if (i->module_inst) {
            wasm_runtime_deinstantiate(i->module_inst);
        }
        js_free_rt(rt, i->externrefs);
        while (i->memory_buffers) {
            TJSWasmMemoryBuffer *next = i->memory_buffers->next;
            JS_FreeValueRT(rt, i->memory_buffers->buffer);
            js_free_rt(rt, i->memory_buffers);
            i->memory_buffers = next;
        }
        JS_FreeValueRT(rt, i->module_owner);
        JS_FreeValueRT(rt, i->weak_self);
        for (uint32_t j = 0; j < i->extern_import_count; j++) {
            JS_FreeValueRT(rt, i->extern_imports[j].provider);
            JS_FreeValueRT(rt, i->extern_imports[j].owner);
        }
        js_free_rt(rt, i->extern_imports);
        for (uint32_t j = 0; j < i->function_import_count; j++)
            JS_FreeValueRT(rt, i->function_imports[j].func);
        js_free_rt(rt, i->function_imports);
        tjs__wasm_free_import_groups(rt, i->owned_function_groups);
        for (uint32_t j = 0; j < i->owned_function_extern_count; j++) {
            JS_FreeValueRT(rt, i->owned_function_externs[j].provider);
            JS_FreeValueRT(rt, i->owned_function_externs[j].owner);
        }
        js_free_rt(rt, i->owned_function_externs);
        if (i->has_pending_exception)
            JS_FreeValueRT(rt, i->pending_exception);
        if (i->ctx)
            JS_FreeContext(i->ctx);
        js_free_rt(rt, i);
    }
}

static void tjs_wasm_instance_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSWasmInstance *i = JS_GetOpaque(val, tjs_wasm_instance_class_id);
    if (i) {
        if (i->has_pending_exception) {
            JS_MarkValue(rt, i->pending_exception, mark_func);
        }
        /* Each creator owns exactly one native JSValue edge per live box.
         * Once a retained box outlives its creator, it deliberately stops
         * being reported as a collectable internal edge: its native duplicate
         * is then a root until the last Table slot releases it. */
        for (uint32_t j = 0; j < i->externref_count; j++) {
            if (i->externrefs[j])
                JS_MarkValue(rt, i->externrefs[j]->value, mark_func);
        }
        for (TJSWasmMemoryBuffer *cache = i->memory_buffers; cache;
             cache = cache->next)
            JS_MarkValue(rt, cache->buffer, mark_func);
        JS_MarkValue(rt, i->module_owner, mark_func);
        JS_MarkValue(rt, i->weak_self, mark_func);
        for (uint32_t j = 0; j < i->extern_import_count; j++) {
            JS_MarkValue(rt, i->extern_imports[j].provider, mark_func);
            JS_MarkValue(rt, i->extern_imports[j].owner, mark_func);
        }
        for (uint32_t j = 0; j < i->function_import_count; j++)
            JS_MarkValue(rt, i->function_imports[j].func, mark_func);
    }
}

static JSClassDef tjs_wasm_instance_class = {
    "Instance",
    .finalizer = tjs_wasm_instance_finalizer,
    .gc_mark = tjs_wasm_instance_mark,
};

static JSValue tjs_new_wasm_module(JSContext *ctx) {
    TJSWasmModule *m;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_wasm_module_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    m = js_mallocz(ctx, sizeof(*m));
    if (!m) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    JS_SetOpaque(obj, m);
    return obj;
}

static TJSWasmModule *tjs_wasm_module_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_wasm_module_class_id);
}

static bool tjs__wasm_is_bytecode_module(wasm_module_t module) {
    return wasm_runtime_get_module_package_type(module) == Wasm_Module_Bytecode;
}

static bool tjs__wasm_imports_wasi(TJSWasmModule *module) {
#if WASM_ENABLE_LIBC_WASI != 0
    if (!module || !module->module)
        return false;
    if (tjs__wasm_is_bytecode_module(module->module))
        return ((WASMModule *)module->module)->import_wasi_api;
#if WASM_ENABLE_AOT != 0
    return ((AOTModule *)module->module)->import_wasi_api;
#endif
#else
    (void)module;
#endif
    return false;
}

static JSValue tjs__wasm_require_bytecode(JSContext *ctx,
                                          const char *operation) {
    return JS_ThrowTypeError(ctx, "%s is only available for WAMR bytecode modules",
                             operation);
}

static JSValue tjs_new_wasm_instance(JSContext *ctx) {
    TJSWasmInstance *i;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_wasm_instance_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    i = js_mallocz(ctx, sizeof(*i));
    if (!i) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    i->ctx = JS_DupContext(ctx);
    i->module_owner = JS_UNDEFINED;
    i->weak_self = JS_UNDEFINED;
    i->pending_exception = JS_UNDEFINED;
    i->live_next = tjs__wasm_live_instances;
    if (i->live_next)
        i->live_next->live_prev = i;
    tjs__wasm_live_instances = i;
    JS_SetOpaque(obj, i);
    i->weak_self = JS_NewWeakRef(ctx, obj);
    if (JS_IsException(i->weak_self)) {
        JS_SetOpaque(obj, NULL);
        tjs__wasm_live_instances = i->live_next;
        if (i->live_next)
            i->live_next->live_prev = NULL;
        JS_FreeContext(i->ctx);
        js_free(ctx, i);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    return obj;
}

static TJSWasmInstance *tjs_wasm_instance_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_wasm_instance_class_id);
}

static TJSWasmExternImport *tjs__wasm_find_extern_import(
    TJSWasmInstance *instance, uint8_t kind, uint32_t import_index) {
    for (uint32_t index = 0; index < instance->extern_import_count; index++) {
        TJSWasmExternImport *binding = instance->extern_imports + index;
        if (binding->kind == kind && binding->import_index == import_index)
            return binding;
    }
    return NULL;
}

static TJSWasmInstance *tjs__wasm_canonical_extern_owner(
    JSContext *ctx, TJSWasmInstance *instance, uint8_t kind,
    uint32_t extern_index) {
    TJSWasmExternImport *binding;
    while ((binding = tjs__wasm_find_extern_import(
                instance, kind, extern_index))) {
        if (JS_IsUndefined(binding->provider))
            break;
        TJSWasmInstance *provider =
            tjs_wasm_instance_get(ctx, binding->provider);
        if (!provider || provider == instance)
            break;
        instance = provider;
        extern_index = binding->source_index;
    }
    return instance;
}

static int tjs__wasm_kind_from_js(JSContext *ctx, JSValueConst value,
                                  uint8_t *kind) {
    const char *name = JS_ToCString(ctx, value);
    if (!name)
        return -1;
    if (!strcmp(name, "function"))
        *kind = WASM_IMPORT_EXPORT_KIND_FUNC;
    else if (!strcmp(name, "table"))
        *kind = WASM_IMPORT_EXPORT_KIND_TABLE;
    else if (!strcmp(name, "memory"))
        *kind = WASM_IMPORT_EXPORT_KIND_MEMORY;
    else if (!strcmp(name, "global"))
        *kind = WASM_IMPORT_EXPORT_KIND_GLOBAL;
    else {
        JS_FreeCString(ctx, name);
        JS_ThrowTypeError(ctx, "invalid WebAssembly extern kind");
        return -1;
    }
    JS_FreeCString(ctx, name);
    return 0;
}

static TJSWasmInstance *tjs__wasm_canonical_extern(
    JSContext *ctx, TJSWasmInstance *instance, uint8_t kind,
    uint32_t *extern_index) {
    TJSWasmExternImport *binding;
    while ((binding = tjs__wasm_find_extern_import(
                instance, kind, *extern_index))) {
        if (JS_IsUndefined(binding->provider))
            break;
        TJSWasmInstance *provider =
            tjs_wasm_instance_get(ctx, binding->provider);
        if (!provider || provider == instance)
            break;
        instance = provider;
        *extern_index = binding->source_index;
    }
    return instance;
}

static WASMGlobalInstance *tjs__wasm_global_at(TJSWasmInstance *instance,
                                               uint32_t index,
                                               void **data) {
    if (!instance->module_inst
        || !tjs__wasm_is_bytecode_module(
               wasm_runtime_get_module(instance->module_inst)))
        return NULL;
    WASMModuleInstance *module_inst = (WASMModuleInstance *)instance->module_inst;
    if (index >= module_inst->e->global_count)
        return NULL;
    WASMGlobalInstance *global = module_inst->e->globals + index;
#if WASM_ENABLE_MULTI_MODULE != 0
    while (global->import_module_inst && global->import_global_inst) {
        module_inst = global->import_module_inst;
        global = global->import_global_inst;
    }
#endif
    *data = module_inst->global_data + global->data_offset;
    return global;
}

static WASMTableInstance *tjs__wasm_table_at(TJSWasmInstance *instance,
                                             uint32_t index) {
    if (!instance->module_inst
        || !tjs__wasm_is_bytecode_module(
               wasm_runtime_get_module(instance->module_inst)))
        return NULL;
    WASMModuleInstance *module_inst = (WASMModuleInstance *)instance->module_inst;
    if (index >= module_inst->table_count)
        return NULL;
    return wasm_get_table_inst(module_inst, index);
}

static bool tjs__wasm_export_index(TJSWasmInstance *instance,
                                   const char *name, uint8_t kind,
                                   uint32_t *result) {
    wasm_module_t module = wasm_runtime_get_module(instance->module_inst);
    if (tjs__wasm_is_bytecode_module(module)) {
        WASMModule *wasm_module = (WASMModule *)module;
        for (uint32_t index = 0; index < wasm_module->export_count; index++) {
            WASMExport *export = wasm_module->exports + index;
            if (export->kind == kind && !strcmp(export->name, name)) {
                *result = export->index;
                return true;
            }
        }
    }
#if WASM_ENABLE_AOT != 0
    else {
        AOTModule *aot_module = (AOTModule *)module;
        for (uint32_t index = 0; index < aot_module->export_count; index++) {
            AOTExport *export = aot_module->exports + index;
            if (export->kind == kind && !strcmp(export->name, name)) {
                *result = export->index;
                return true;
            }
        }
    }
#endif
    return false;
}

static TJSWasmInstance *tjs__wasm_export_owner(JSContext *ctx,
                                                TJSWasmInstance *instance,
                                                const char *name,
                                                uint8_t kind) {
    uint32_t extern_index;
    if (!tjs__wasm_export_index(instance, name, kind, &extern_index))
        return instance;
    return tjs__wasm_canonical_extern_owner(ctx, instance, kind,
                                            extern_index);
}

static int tjs__wasm_record_extern_import(JSContext *ctx, TJSWasmModule *m,
                                          JSValueConst descriptor,
                                          uint8_t kind,
                                          uint32_t import_index) {
    JSValue provider = JS_GetPropertyStr(ctx, descriptor, "provider");
    if (JS_IsException(provider))
        return -1;

    JSValue owner = JS_GetPropertyStr(ctx, descriptor, "owner");
    if (JS_IsException(owner)) {
        JS_FreeValue(ctx, provider);
        return -1;
    }

    JSValue source_import_value =
        JS_GetPropertyStr(ctx, descriptor, "sourceImportIndex");
    if (JS_IsException(source_import_value)) {
        JS_FreeValue(ctx, provider);
        JS_FreeValue(ctx, owner);
        return -1;
    }
    bool source_is_import = !JS_IsUndefined(source_import_value);
    if (JS_IsUndefined(provider) && JS_IsUndefined(owner)
        && !source_is_import) {
        JS_FreeValue(ctx, provider);
        JS_FreeValue(ctx, owner);
        JS_FreeValue(ctx, source_import_value);
        return 0;
    }

    uint32_t source_index = 0;
    if (!JS_IsUndefined(provider)) {
        if (source_is_import) {
            JS_FreeValue(ctx, provider);
            JS_FreeValue(ctx, owner);
            JS_FreeValue(ctx, source_import_value);
            JS_ThrowTypeError(
                ctx, "provider and sourceImportIndex are mutually exclusive");
            return -1;
        }
        TJSWasmInstance *provider_native =
            tjs_wasm_instance_get(ctx, provider);
        if (!provider_native) {
            JS_FreeValue(ctx, provider);
            JS_FreeValue(ctx, owner);
            JS_FreeValue(ctx, source_import_value);
            return -1;
        }
        if (!provider_native->module_inst
            || !tjs__wasm_is_bytecode_module(
                   wasm_runtime_get_module(provider_native->module_inst))) {
            JS_FreeValue(ctx, provider);
            JS_FreeValue(ctx, owner);
            JS_FreeValue(ctx, source_import_value);
            JS_ThrowTypeError(
                ctx, "live extern providers must be bytecode Instances");
            return -1;
        }

        JSValue source_index_value =
            JS_GetPropertyStr(ctx, descriptor, "sourceIndex");
        if (JS_IsException(source_index_value)
            || JS_ToUint32(ctx, &source_index, source_index_value)) {
            JS_FreeValue(ctx, source_index_value);
            JS_FreeValue(ctx, provider);
            JS_FreeValue(ctx, owner);
            JS_FreeValue(ctx, source_import_value);
            return -1;
        }
        JS_FreeValue(ctx, source_index_value);
    }
    else if (source_is_import) {
        if (JS_ToUint32(ctx, &source_index, source_import_value)) {
            JS_FreeValue(ctx, provider);
            JS_FreeValue(ctx, owner);
            JS_FreeValue(ctx, source_import_value);
            return -1;
        }
        /* Instantiation proceeds in kind-relative import order. Restrict an
         * alias to an already-created slot so cycles and forward references
         * cannot enter WAMR's in-progress instance. */
        if (source_index >= import_index) {
            JS_FreeValue(ctx, provider);
            JS_FreeValue(ctx, owner);
            JS_FreeValue(ctx, source_import_value);
            tjs_throw_wasm_error(
                ctx, "LinkError",
                "sourceImportIndex must refer to an earlier import slot");
            return -1;
        }
    }
    JS_FreeValue(ctx, source_import_value);
    if (JS_IsUndefined(owner)) {
        JS_FreeValue(ctx, owner);
        owner = JS_DupValue(ctx, provider);
    }

    TJSWasmExternImport *imports = js_realloc(
        ctx, m->extern_imports,
        sizeof(*imports) * (m->extern_import_count + 1));
    if (!imports) {
        JS_FreeValue(ctx, provider);
        JS_FreeValue(ctx, owner);
        return -1;
    }
    m->extern_imports = imports;
    TJSWasmExternImport *binding = imports + m->extern_import_count++;
    binding->kind = kind;
    binding->source_is_import = source_is_import;
    binding->reserved[0] = binding->reserved[1] = 0;
    binding->import_index = import_index;
    binding->source_index = source_index;
    binding->provider = provider;
    binding->owner = owner;
    return 1;
}

JSValue tjs_throw_wasm_error(JSContext *ctx, const char *name, const char *msg) {
    CHECK_NOT_NULL(msg);
    JSValue obj = JS_NewError(ctx);
    JS_DefinePropertyValueStr(ctx, obj, "message", JS_NewString(ctx, msg), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, obj, "wasmError", JS_NewString(ctx, name), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    if (JS_IsException(obj)) {
        obj = JS_NULL;
    }
    return JS_Throw(ctx, obj);
}

static JSValue tjs__wasm_val_to_js(JSContext *ctx, const wasm_val_t *val) {
    switch (val->kind) {
        case WASM_I32:
            return JS_NewInt32(ctx, val->of.i32);
        case WASM_I64:
            /* The WebAssembly JS API converts an i64 result with ToBigInt, so it
             * is ALWAYS a BigInt -- magnitude is irrelevant. Returning a Number
             * for int32-fitting values made `typeof f()` "number" where node says
             * "bigint", and (once the inbound path was correctly tightened to
             * reject Numbers) made the identity round trip `id(id(3n))` throw:
             * the inner call handed back Number 3, which the outer call rejected.
             * Every i64 leaving wasm -- function result, global read, table-call
             * result -- goes through here, so this one site fixes all of them. */
            return JS_NewBigInt64(ctx, val->of.i64);
        case WASM_F32:
            return JS_NewFloat64(ctx, (double) val->of.f32);
        case WASM_F64:
            return JS_NewFloat64(ctx, val->of.f64);
        default:
            return JS_UNDEFINED;
    }
}

static bool tjs__js_to_wasm_val(JSContext *ctx, JSValue jsval, wasm_valkind_t type, wasm_val_t *val) {
    val->kind = type;
    switch (type) {
        case WASM_I32: {
            int32_t i32;
            if (JS_ToInt32(ctx, &i32, jsval)) {
                return false;
            }
            val->of.i32 = i32;
            return true;
        }
        case WASM_I64: {
            int64_t i64;
            /* The WebAssembly JS API converts an i64 parameter with ToBigInt64
             * -- ToBigInt, then wrap mod 2^64 -- which throws TypeError for
             * Number, null and undefined. JS_ToBigInt64 implements exactly that
             * (quickjs.c JS_ToBigIntFree fails on JS_TAG_INT/FLOAT64/NULL/
             * UNDEFINED and converts Boolean/String/Object per spec), so its
             * failure MUST propagate. Clearing the exception and retrying with
             * JS_ToInt32 handed wasm a silently truncated value instead:
             * 2**40 arrived as 0, 1e15 as -1530494976, 1.5 as 1. */
            if (JS_ToBigInt64(ctx, &i64, jsval)) {
                return false;
            }
            val->of.i64 = i64;
            return true;
        }
        case WASM_F32: {
            double f64;
            if (JS_ToFloat64(ctx, &f64, jsval)) {
                return false;
            }
            val->of.f32 = (float) f64;
            return true;
        }
        case WASM_F64: {
            double f64;
            if (JS_ToFloat64(ctx, &f64, jsval)) {
                return false;
            }
            val->of.f64 = f64;
            return true;
        }
        case WASM_EXTERNREF:
            /* Handled separately with instance context */
            val->of.foreign = 0;
            return true;
        default:
            return false;
    }
}

static void tjs__externref_box_cleanup(void *opaque) {
    TJSWasmExternRefBox *box = opaque;
    if (!box)
        return;
    if (box->live_prev)
        box->live_prev->live_next = box->live_next;
    else if (tjs__wasm_live_externrefs == box)
        tjs__wasm_live_externrefs = box->live_next;
    if (box->live_next)
        box->live_next->live_prev = box->live_prev;
    if (box->owner) {
        for (uint32_t index = 0; index < box->owner->externref_count;
             index++) {
            if (box->owner->externrefs[index] == box) {
                box->owner->externrefs[index] = NULL;
                break;
            }
        }
    }
    JS_FreeValueRT(box->rt, box->value);
    js_free_rt(box->rt, box);
}

/* Register a JSValue as an externref. Returns the WAMR externref index via p_idx. */
static bool tjs__externref_box(TJSWasmInstance *inst, JSContext *ctx, JSValue val, uint32_t *p_idx) {
    if (JS_IsNull(val)) {
        *p_idx = NULL_REF;
        return true;
    }

    if (inst->externref_count >= inst->externref_capacity) {
        uint32_t new_cap = inst->externref_capacity ? inst->externref_capacity * 2 : 16;
        TJSWasmExternRefBox **new_arr = js_realloc(
            ctx, inst->externrefs, sizeof(*new_arr) * new_cap);
        if (!new_arr) {
            return false;
        }
        inst->externrefs = new_arr;
        inst->externref_capacity = new_cap;
    }

    TJSWasmExternRefBox *box = js_mallocz(ctx, sizeof(*box));
    if (!box)
        return false;
    box->rt = JS_GetRuntime(ctx);
    box->owner = inst;
    box->value = JS_DupValue(ctx, val);

    if (!wasm_externref_obj2ref(inst->module_inst, box, p_idx)) {
        JS_FreeValue(ctx, box->value);
        js_free(ctx, box);
        return false;
    }
    if (!wasm_externref_set_cleanup(inst->module_inst, box,
                                    tjs__externref_box_cleanup)) {
        (void)wasm_externref_objdel(inst->module_inst, box);
        JS_FreeValue(ctx, box->value);
        js_free(ctx, box);
        return false;
    }

    inst->externrefs[inst->externref_count++] = box;
    box->live_next = tjs__wasm_live_externrefs;
    if (box->live_next)
        box->live_next->live_prev = box;
    tjs__wasm_live_externrefs = box;
    return true;
}

/* Box `val` and hand back the stable host-box pointer WAMR's raw-native and
 * wasm_val_t ABIs expect (wasm_externref_obj2ref maps it to an index). */
static bool tjs__externref_box_key(TJSWasmInstance *inst, JSContext *ctx, JSValue val, uintptr_t *p_key) {
    if (JS_IsNull(val)) {
        /* wasm_externref_obj2ref() treats (uintptr_t)-1 as ref.null. */
        *p_key = UINTPTR_MAX;
        return true;
    }

    uint32_t externref_idx;
    if (!tjs__externref_box(inst, ctx, val, &externref_idx)) {
        return false;
    }

    *p_key = (uintptr_t)inst->externrefs[inst->externref_count - 1];
    return true;
}

/* Retrieve a JSValue from a host key pointer. Returns a non-dup'd value. */
static JSValue tjs__externref_unbox_key(TJSWasmInstance *inst, void *key) {
    if (!key) {
        return JS_NULL;
    }

    (void)inst;
    return ((TJSWasmExternRefBox *)key)->value;
}

/* Retrieve a JSValue from a WAMR externref index. Returns a non-dup'd value. */
static JSValue tjs__externref_unbox(TJSWasmInstance *inst, uint32_t externref_idx) {
    if (externref_idx == (uint32_t) NULL_REF) {
        return JS_NULL;
    }

    void *key;
    if (!wasm_externref_ref2obj(externref_idx, &key)) {
        return JS_UNDEFINED;
    }

    return tjs__externref_unbox_key(inst, key);
}

/* Raw native trampoline: called by WAMR, forwards to a JS function. */
static void tjs__wasm_import_trampoline(wasm_exec_env_t exec_env, uint64_t *args) {
    TJSWasmImportCtx *import_ctx = wasm_runtime_get_function_attachment(exec_env);
    if (!import_ctx) {
        return;
    }

    JSContext *ctx = import_ctx->ctx;
    wasm_func_type_t func_type = import_ctx->type;
    /* WAMR temporarily switches exec_env.module_inst while a consumer calls a
     * provider-backed wasm function, but intentionally leaves user_data on the
     * outer execution environment. Keep both identities: provider-local
     * memory/externrefs belong to active_inst, while a JS exception must be
     * parked on caller_inst so the outer JS entry point can rethrow it. */
    wasm_module_inst_t active_module =
        wasm_runtime_get_module_inst(exec_env);
    TJSWasmInstance *active_inst = active_module
                                       ? wasm_runtime_get_custom_data(
                                             active_module)
                                       : NULL;
    TJSWasmInstance *caller_inst = wasm_runtime_get_user_data(exec_env);
    if (!caller_inst)
        caller_inst = active_inst;
    TJSWasmInstance *exception_inst = caller_inst ? caller_inst : active_inst;

    uint32_t param_count = wasm_func_type_get_param_count(func_type);
    uint32_t result_count = wasm_func_type_get_result_count(func_type);

    /* js_args is a fixed-size stack array; clamp so JS_Call and the cleanup
     * loop below never read/free uninitialized slots on an import with more
     * than TJS__WASM_MAX_ARGS parameters. */
    if (param_count > TJS__WASM_MAX_ARGS)
        param_count = TJS__WASM_MAX_ARGS;

    /* Convert WASM args to JS values */
    JSValue js_args[TJS__WASM_MAX_ARGS];
    for (uint32_t i = 0; i < param_count && i < TJS__WASM_MAX_ARGS; i++) {
        wasm_valkind_t kind = wasm_func_type_get_param_valkind(func_type, i);
        wasm_val_t val;
        val.kind = kind;
        switch (kind) {
            case WASM_I32:
                val.of.i32 = (int32_t) args[i];
                break;
            case WASM_I64:
                val.of.i64 = (int64_t) args[i];
                break;
            case WASM_F32: {
                union {
                    uint32_t i;
                    float f;
                } u;
                u.i = (uint32_t) args[i];
                val.of.f32 = u.f;
                break;
            }
            case WASM_F64: {
                union {
                    uint64_t i;
                    double f;
                } u;
                u.i = args[i];
                val.of.f64 = u.f;
                break;
            }
            case WASM_EXTERNREF: {
                /* WAMR's raw-native ABI passes the host object pointer for an
                 * externref.  It is the key registered by
                 * tjs__externref_box(), so recover the original JS value from
                 * the instance-owned keep-alive list. */
                void *key = (void *) (uintptr_t) args[i];
                if (!key || !active_inst) {
                    js_args[i] = JS_NULL;
                } else {
                    js_args[i] = JS_DupValue(
                        ctx, tjs__externref_unbox_key(active_inst, key));
                }
                continue;
            }
            default:
                js_args[i] = JS_UNDEFINED;
                continue;
        }
        js_args[i] = tjs__wasm_val_to_js(ctx, &val);
    }

    /* ------------------------------------------------------------------
     * Guard against stale WASM-memory ArrayBuffers.
     *
     * WAMR may relocate linear memory during memory.grow, freeing the old
     * block.  If that happened earlier in the current WASM call, the cached
     * mem_buffer still points at freed memory, and any TypedArray views
     * derived from it are dangling pointers. WAMR can also grow memory
     * *in place* (base pointer unchanged, committed size larger) when the
     * grow fits inside its pre-reserved region -- so byte length must be
     * compared too, not just the base pointer, or an in-place grow leaves
     * a wrong-sized-but-still-"live" (non-detached) buffer that JS-side
     * staleness checks (e.g. wasm-bindgen's `byteLength === 0`) will never
     * catch.
     *
     * Invalidate BEFORE the JS call so getMemoryBuffer() hands out a fresh
     * ArrayBuffer backed by the current memory base.
     * ------------------------------------------------------------------ */
    wasm_memory_inst_t tjs__tramp_mem = NULL;
    void *tjs__tramp_mem_base = NULL;
    size_t tjs__tramp_mem_len = 0;
    TJSWasmMemoryBuffer *tjs__tramp_cache = NULL;
    if (active_inst) {
        tjs__tramp_mem = active_module
                             ? wasm_runtime_get_default_memory(active_module)
                             : NULL;
        tjs__tramp_cache = tjs__tramp_mem
            ? tjs__wasm_find_memory_buffer(active_inst, tjs__tramp_mem)
            : NULL;
        if (tjs__tramp_mem && tjs__tramp_cache
            && !JS_IsUndefined(tjs__tramp_cache->buffer)) {
            tjs__tramp_mem_base = wasm_memory_get_base_address(tjs__tramp_mem);
            tjs__tramp_mem_len = tjs__wasm_mem_byte_length(tjs__tramp_mem);
            if (tjs__tramp_mem_base != tjs__tramp_cache->base
                || tjs__tramp_mem_len != tjs__tramp_cache->byte_length)
                tjs__wasm_invalidate_memory(active_inst, tjs__tramp_mem);
        }
    }

    /* Call the JS function */
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSValue ret = JS_Call(ctx, import_ctx->func, global_obj, param_count, js_args);
    JS_FreeValue(ctx, global_obj);

    /* Re-check: the JS import may have triggered a nested WASM call that
     * grew memory (e.g. JS → callfunction → memory.grow → return).
     * Reuse the already-resolved memory instance to save API calls. */
    if (tjs__tramp_mem && active_inst && tjs__tramp_cache
        && !JS_IsUndefined(tjs__tramp_cache->buffer)) {
        void *tjs__after_base = wasm_memory_get_base_address(tjs__tramp_mem);
        size_t tjs__after_len = tjs__wasm_mem_byte_length(tjs__tramp_mem);
        if (tjs__after_base != tjs__tramp_mem_base || tjs__after_len != tjs__tramp_mem_len)
            tjs__wasm_invalidate_memory(active_inst, tjs__tramp_mem);
    }

    for (uint32_t i = 0; i < param_count; i++) {
        JS_FreeValue(ctx, js_args[i]);
    }

    if (JS_IsException(ret)) {
        /* Save the JS exception on the instance so tjs__call_wasm_func_inst can re-throw it */
        TJSWasmInstance *inst = exception_inst;
        if (inst) {
            if (inst->has_pending_exception)
                JS_FreeValue(ctx, inst->pending_exception);
            inst->pending_exception = JS_GetException(ctx);
            inst->has_pending_exception = true;
            inst->pending_exception_module = active_module;
        }
        wasm_runtime_set_exception(active_module,
                                   "imported function threw an exception");
        if (caller_inst && caller_inst != active_inst
            && caller_inst->module_inst)
            wasm_runtime_set_exception(
                caller_inst->module_inst,
                "provider imported function threw an exception");
        return;
    }

    /* Convert return value back to WASM.
     *
     * Every conversion here can fail (BigInt where a Number is required and
     * vice versa). A failure MUST become a wasm trap carrying the JS exception:
     *   - ignoring the return value of JS_ToInt32/JS_ToFloat64 left a *pending*
     *     JS exception while wasm kept executing, so the next JS_Call in the
     *     same wasm activation saw a stale exception;
     *   - the i64 case actively cleared the exception and retried with
     *     JS_ToInt32, so an import declared `(result i64)` that returned Number
     *     7 handed wasm 7 instead of throwing TypeError like node does. This is
     *     the same swallow-and-truncate bug that was fixed on the inbound
     *     (parameter) path in tjs__js_to_wasm_val. */
    if (result_count > 0) {
        wasm_valkind_t ret_kind = tjs__wasm_func_type_get_result_valkind_safe(func_type, 0);
        bool conv_failed = false;
        switch (ret_kind) {
            case WASM_I32: {
                int32_t i32 = 0;
                conv_failed = JS_ToInt32(ctx, &i32, ret) != 0;
                args[0] = (uint64_t) (uint32_t) i32;
                break;
            }
            case WASM_I64: {
                int64_t i64 = 0;
                conv_failed = JS_ToBigInt64(ctx, &i64, ret) != 0;
                args[0] = (uint64_t) i64;
                break;
            }
            case WASM_F32: {
                double f64 = 0;
                conv_failed = JS_ToFloat64(ctx, &f64, ret) != 0;
                union {
                    uint32_t i;
                    float f;
                } u;
                u.f = (float) f64;
                args[0] = u.i;
                break;
            }
            case WASM_F64: {
                double f64 = 0;
                conv_failed = JS_ToFloat64(ctx, &f64, ret) != 0;
                union {
                    uint64_t i;
                    double f;
                } u;
                u.f = f64;
                args[0] = u.i;
                break;
            }
            case WASM_EXTERNREF: {
                /* WAMR reads args[0] unconditionally once this trampoline
                 * returns: wasm_runtime_invoke_native_raw() has no exception
                 * check between invoke_native_raw() and the return-value
                 * conversion. So args[0] must hold a defined value on every
                 * path, the allocation-failure one included, or WAMR registers
                 * a leftover parameter cell as an externref. */
                uintptr_t key = UINTPTR_MAX;
                if (active_inst
                    && !tjs__externref_box_key(active_inst, ctx, ret, &key)) {
                    conv_failed = true;
                    key = UINTPTR_MAX;
                }
                args[0] = (uint64_t) key;
                break;
            }
            default:
                args[0] = 0;
                break;
        }

        if (conv_failed) {
            TJSWasmInstance *inst = exception_inst;
            if (inst) {
                /* Drop any exception the caller already parked, then take ours. */
                if (inst->has_pending_exception) {
                    JS_FreeValue(ctx, inst->pending_exception);
                    inst->pending_exception = JS_UNDEFINED;
                    inst->has_pending_exception = false;
                }
                inst->pending_exception = JS_GetException(ctx);
                inst->has_pending_exception = true;
                inst->pending_exception_module = active_module;
            } else {
                JS_FreeValue(ctx, JS_GetException(ctx));
            }
            wasm_runtime_set_exception(active_module,
                                       "imported function returned a value of the wrong type");
            if (caller_inst && caller_inst != active_inst
                && caller_inst->module_inst)
                wasm_runtime_set_exception(
                    caller_inst->module_inst,
                    "provider imported function returned a value of the wrong type");
            JS_FreeValue(ctx, ret);
            return;
        }
    }

    JS_FreeValue(ctx, ret);
}

static JSValue tjs_wasm_setwasioptions(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }

    JSValue js_args = argv[1];
    JSValue js_env = argv[2];
    JSValue js_preopens = argv[3];

    char **wasi_argv = NULL;
    uint32_t wasi_argc = 0;
    char **wasi_env = NULL;
    uint32_t wasi_env_count = 0;
    char **wasi_map_dir_list = NULL;
    uint32_t wasi_map_dir_count = 0;

    /* Parse args array */
    if (JS_IsArray(js_args)) {
        JSValue js_length = JS_GetPropertyStr(ctx, js_args, "length");
        uint64_t len;
        if (JS_ToIndex(ctx, &len, js_length)) {
            JS_FreeValue(ctx, js_length);
            goto fail;
        }
        JS_FreeValue(ctx, js_length);

        wasi_argv = js_mallocz(ctx, sizeof(*wasi_argv) * (len + 1));
        if (!wasi_argv) {
            goto fail;
        }
        wasi_argc = (uint32_t) len;

        for (uint32_t i = 0; i < len; i++) {
            JSValue v = JS_GetPropertyUint32(ctx, js_args, i);
            if (JS_IsException(v)) {
                goto fail;
            }
            const char *arg_str = JS_ToCString(ctx, v);
            JS_FreeValue(ctx, v);
            if (!arg_str) {
                goto fail;
            }
            wasi_argv[i] = js_strdup(ctx, arg_str);
            JS_FreeCString(ctx, arg_str);
            if (!wasi_argv[i]) {
                goto fail;
            }
        }
    }

    /* Parse env object */
    if (JS_IsObject(js_env) && !JS_IsNull(js_env)) {
        JSPropertyEnum *ptab;
        uint32_t plen;
        if (JS_GetOwnPropertyNames(ctx, &ptab, &plen, js_env, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY)) {
            goto fail;
        }

        wasi_env = js_mallocz(ctx, sizeof(*wasi_env) * (plen + 1));
        if (!wasi_env) {
            JS_FreePropertyEnum(ctx, ptab, plen);
            goto fail;
        }
        wasi_env_count = plen;

        for (uint32_t i = 0; i < plen; i++) {
            JSValue prop = JS_GetProperty(ctx, js_env, ptab[i].atom);
            if (JS_IsException(prop)) {
                JS_FreePropertyEnum(ctx, ptab, plen);
                goto fail;
            }
            const char *key = JS_AtomToCString(ctx, ptab[i].atom);
            const char *value = JS_ToCString(ctx, prop);
            JS_FreeValue(ctx, prop);
            if (!key || !value) {
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
                JS_FreePropertyEnum(ctx, ptab, plen);
                goto fail;
            }
            size_t entry_len = strlen(key) + strlen(value) + 2; /* KEY=VALUE\0 */
            wasi_env[i] = js_malloc(ctx, entry_len);
            if (!wasi_env[i]) {
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
                JS_FreePropertyEnum(ctx, ptab, plen);
                goto fail;
            }
            snprintf(wasi_env[i], entry_len, "%s=%s", key, value);
            JS_FreeCString(ctx, key);
            JS_FreeCString(ctx, value);
        }
        JS_FreePropertyEnum(ctx, ptab, plen);
    }

    /* Parse preopens object - format: { "/guest": "/host" } -> "guest::host" */
    if (JS_IsObject(js_preopens) && !JS_IsNull(js_preopens)) {
        JSPropertyEnum *ptab;
        uint32_t plen;
        if (JS_GetOwnPropertyNames(ctx, &ptab, &plen, js_preopens, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY)) {
            goto fail;
        }

        wasi_map_dir_list = js_mallocz(ctx, sizeof(*wasi_map_dir_list) * (plen + 1));
        if (!wasi_map_dir_list) {
            JS_FreePropertyEnum(ctx, ptab, plen);
            goto fail;
        }
        wasi_map_dir_count = plen;

        for (uint32_t i = 0; i < plen; i++) {
            JSValue prop = JS_GetProperty(ctx, js_preopens, ptab[i].atom);
            if (JS_IsException(prop)) {
                JS_FreePropertyEnum(ctx, ptab, plen);
                goto fail;
            }
            const char *guest_path = JS_AtomToCString(ctx, ptab[i].atom);
            const char *host_path = JS_ToCString(ctx, prop);
            JS_FreeValue(ctx, prop);
            if (!guest_path || !host_path) {
                JS_FreeCString(ctx, guest_path);
                JS_FreeCString(ctx, host_path);
                JS_FreePropertyEnum(ctx, ptab, plen);
                goto fail;
            }
            /* Format: guest_path::host_path */
            size_t entry_len = strlen(guest_path) + strlen(host_path) + 3; /* guest::host\0 */
            wasi_map_dir_list[i] = js_malloc(ctx, entry_len);
            if (!wasi_map_dir_list[i]) {
                JS_FreeCString(ctx, guest_path);
                JS_FreeCString(ctx, host_path);
                JS_FreePropertyEnum(ctx, ptab, plen);
                goto fail;
            }
            snprintf(wasi_map_dir_list[i], entry_len, "%s::%s", guest_path, host_path);
            JS_FreeCString(ctx, guest_path);
            JS_FreeCString(ctx, host_path);
        }
        JS_FreePropertyEnum(ctx, ptab, plen);
    }

    /* Call WAMR to set WASI args - must happen before instantiate */
    wasm_runtime_set_wasi_args(m->module,
                               NULL,
                               0, /* dir_list - not used, we use map_dir_list */
                               (const char **) wasi_map_dir_list,
                               wasi_map_dir_count,
                               (const char **) wasi_env,
                               wasi_env_count,
                               wasi_argv,
                               (int) wasi_argc);

    /* WAMR keeps these pointers. Replace the previous configuration only
     * after the new one has been fully parsed and installed. */
    JSRuntime *rt = JS_GetRuntime(ctx);
    tjs__wasm_free_string_array(rt, m->wasi.argv, m->wasi.argc);
    tjs__wasm_free_string_array(rt, m->wasi.env, m->wasi.env_count);
    tjs__wasm_free_string_array(rt, m->wasi.map_dir_list,
                                m->wasi.map_dir_count);
    m->wasi.argv = wasi_argv;
    m->wasi.argc = wasi_argc;
    m->wasi.env = wasi_env;
    m->wasi.env_count = wasi_env_count;
    m->wasi.map_dir_list = wasi_map_dir_list;
    m->wasi.map_dir_count = wasi_map_dir_count;

    return JS_UNDEFINED;

fail:
    if (wasi_argv) {
        for (uint32_t i = 0; i < wasi_argc; i++) {
            js_free(ctx, wasi_argv[i]);
        }
        js_free(ctx, wasi_argv);
    }
    if (wasi_env) {
        for (uint32_t i = 0; i < wasi_env_count; i++) {
            js_free(ctx, wasi_env[i]);
        }
        js_free(ctx, wasi_env);
    }
    if (wasi_map_dir_list) {
        for (uint32_t i = 0; i < wasi_map_dir_count; i++) {
            js_free(ctx, wasi_map_dir_list[i]);
        }
        js_free(ctx, wasi_map_dir_list);
    }
    return JS_EXCEPTION;
}

/* Current committed size of a WAMR memory instance, in bytes. WAMR can grow
 * linear memory in place (same base pointer, larger committed size) when the
 * grow fits inside its pre-reserved region, so callers must not treat an
 * unchanged base pointer alone as proof that memory didn't grow. */
static size_t tjs__wasm_mem_byte_length(wasm_memory_inst_t mem) {
    uint64_t page_count = wasm_memory_get_cur_page_count(mem);
    uint64_t bytes_per_page = wasm_memory_get_bytes_per_page(mem);
    return (size_t) (page_count * bytes_per_page);
}

/* Detach and release the cached linear-memory ArrayBuffer (if any).
 * WAMR may move the linear-memory base when it grows (explicit growMemory or
 * an internal memory.grow during a call), leaving any previously exposed
 * ArrayBuffer pointing at freed/moved memory. Detaching makes stale access
 * throw a clean "detached ArrayBuffer" error instead of corrupting memory. */
static TJSWasmMemoryBuffer *tjs__wasm_find_memory_buffer(
    TJSWasmInstance *inst, wasm_memory_inst_t memory) {
    for (TJSWasmMemoryBuffer *cache = inst->memory_buffers; cache;
         cache = cache->next) {
        if (cache->memory == memory)
            return cache;
    }
    return NULL;
}

static void tjs__wasm_invalidate_memory(TJSWasmInstance *inst,
                                        wasm_memory_inst_t memory) {
    (void)inst;
    for (TJSWasmInstance *candidate = tjs__wasm_live_instances; candidate;
         candidate = candidate->live_next) {
        TJSWasmMemoryBuffer *cache =
            tjs__wasm_find_memory_buffer(candidate, memory);
        if (cache && !JS_IsUndefined(cache->buffer)) {
            tjs__wasm_detach_membuf(candidate->ctx, cache->buffer);
            JS_FreeValue(candidate->ctx, cache->buffer);
            cache->buffer = JS_UNDEFINED;
            cache->base = NULL;
            cache->byte_length = 0;
        }
    }
}

static int tjs__wasm_cached_membuf_is_stale(JSContext *ctx,
                                            TJSWasmMemoryBuffer *cache,
                                            void *base,
                                            size_t byte_length,
                                            bool *pstale) {
    *pstale = true;
    if (!cache || JS_IsUndefined(cache->buffer))
        return 0;

    if (cache->base != base || cache->byte_length != byte_length)
        return 0;

    JSValue detached = JS_GetPropertyStr(ctx, cache->buffer, "detached");
    if (JS_IsException(detached))
        return -1;
    int is_detached = JS_ToBool(ctx, detached);
    JS_FreeValue(ctx, detached);
    if (is_detached < 0)
        return -1;
    if (is_detached)
        return 0;

    JSValue len_val = JS_GetPropertyStr(ctx, cache->buffer, "byteLength");
    if (JS_IsException(len_val))
        return -1;
    uint64_t cached_len;
    int rc = JS_ToIndex(ctx, &cached_len, len_val);
    JS_FreeValue(ctx, len_val);
    if (rc)
        return -1;

    *pstale = cached_len != byte_length;
    return 0;
}

static JSValue tjs__call_wasm_func_inst(JSContext *ctx,
                                        TJSWasmInstance *inst,
                                        wasm_function_inst_t func,
                                        int argc,
                                        JSValue *argv) {
    uint32_t param_count = wasm_func_get_param_count(func, inst->module_inst);
    uint32_t result_count = wasm_func_get_result_count(func, inst->module_inst);

    if (param_count > TJS__WASM_MAX_ARGS || result_count > TJS__WASM_MAX_ARGS) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", "too many parameters or results");
    }

    wasm_valkind_t param_types[TJS__WASM_MAX_ARGS];
    if (param_count > 0) {
        wasm_func_get_param_types(func, inst->module_inst, param_types);
    }

    wasm_val_t params[TJS__WASM_MAX_ARGS];
    for (uint32_t j = 0; j < param_count; j++) {
        if ((int) j < argc) {
            if (!tjs__js_to_wasm_val(ctx, argv[j], param_types[j], &params[j])) {
                return JS_EXCEPTION;
            }
            /* For externref, box the JSValue and store the host pointer WAMR
             * converts back into an externref index (null -> UINTPTR_MAX). */
            if (param_types[j] == WASM_EXTERNREF) {
                uintptr_t key;
                if (!tjs__externref_box_key(inst, ctx, argv[j], &key)) {
                    return JS_ThrowInternalError(ctx, "failed to register externref");
                }
                params[j].of.foreign = key;
            }
        } else {
            params[j].kind = param_types[j];
            params[j].of.i64 = 0;
        }
    }

    wasm_val_t results[TJS__WASM_MAX_ARGS];

    /* Record linear-memory base + committed size to detect an internal
     * memory.grow -- WAMR can grow in place (base unchanged) when the grow
     * fits its pre-reserved region, so the base pointer alone isn't enough
     * (see the matching comment at the import trampoline above). */
    wasm_memory_inst_t tjs__mem = NULL;
    void *tjs__mem_base_before = NULL;
    size_t tjs__mem_len_before = 0;
    {
        tjs__mem = wasm_runtime_get_default_memory(inst->module_inst);
        if (tjs__mem) {
            tjs__mem_base_before = wasm_memory_get_base_address(tjs__mem);
            tjs__mem_len_before = tjs__wasm_mem_byte_length(tjs__mem);
        }
    }

    bool tjs__wasm_call_ok = wasm_runtime_call_wasm_a(
        inst->exec_env, func, result_count, results, param_count, params);

    if (!tjs__wasm_call_ok) {
        /* If an imported JS function threw, re-throw the original JS exception */
        if (inst->has_pending_exception) {
            JSValue exc = inst->pending_exception;
            wasm_module_inst_t exception_module =
                inst->pending_exception_module;
            inst->pending_exception = JS_UNDEFINED;
            inst->has_pending_exception = false;
            inst->pending_exception_module = NULL;
            wasm_runtime_clear_exception(inst->module_inst);
            if (exception_module && exception_module != inst->module_inst)
                wasm_runtime_clear_exception(exception_module);
            return JS_Throw(ctx, exc);
        }

        const char *exception = wasm_runtime_get_exception(inst->module_inst);
        /* Use the exception string before clearing, since clear zeroes the buffer */
        JSValue err = tjs_throw_wasm_error(ctx, "RuntimeError", exception ? exception : "call failed");
        wasm_runtime_clear_exception(inst->module_inst);
        return err;
    }

    /* If linear memory moved or grew in place during the call, any exposed
     * ArrayBuffer is stale. */
    {
        tjs__mem = wasm_runtime_get_default_memory(inst->module_inst);
        void *tjs__mem_base_after = tjs__mem ? wasm_memory_get_base_address(tjs__mem) : NULL;
        size_t tjs__mem_len_after = tjs__mem ? tjs__wasm_mem_byte_length(tjs__mem) : 0;
        if (tjs__mem_base_after != tjs__mem_base_before || tjs__mem_len_after != tjs__mem_len_before)
            tjs__wasm_invalidate_memory(inst, tjs__mem);
    }

    wasm_valkind_t result_types[TJS__WASM_MAX_ARGS];
    if (result_count > 0) {
        wasm_func_get_result_types(func, inst->module_inst, result_types);
    }

    if (result_count == 0) {
        return JS_UNDEFINED;
    } else if (result_count == 1) {
        if (result_types[0] == WASM_EXTERNREF) {
            /* wasm_runtime_call_wasm() finalizes externref results to the
             * host object pointer before wasm_runtime_call_wasm_a() exposes
             * them through wasm_val_t. */
            void *key = (void *) results[0].of.foreign;
            return JS_DupValue(ctx, tjs__externref_unbox_key(inst, key));
        }
        return tjs__wasm_val_to_js(ctx, &results[0]);
    } else {
        JSValue rets = JS_NewArray(ctx);
        for (uint32_t j = 0; j < result_count; j++) {
            if (result_types[j] == WASM_EXTERNREF) {
                void *key = (void *) results[j].of.foreign;
                JS_SetPropertyUint32(ctx, rets, j,
                    JS_DupValue(ctx, tjs__externref_unbox_key(inst, key)));
            } else {
                JS_SetPropertyUint32(ctx, rets, j, tjs__wasm_val_to_js(ctx, &results[j]));
            }
        }
        return rets;
    }
}

static JSValue tjs_wasm_callfunction(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i) {
        return JS_EXCEPTION;
    }
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "call() requires a function name");
    }

    const char *fname = JS_ToCString(ctx, argv[0]);
    if (!fname) {
        return JS_EXCEPTION;
    }

    wasm_function_inst_t func = wasm_runtime_lookup_function(i->module_inst, fname);
    if (!func) {
        JS_FreeCString(ctx, fname);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "function not found");
    }
    JS_FreeCString(ctx, fname);

    return tjs__call_wasm_func_inst(ctx, i, func, argc - 1, argv + 1);
}

static int tjs__wasm_get_u32_option(JSContext *ctx, JSValueConst options,
                                    const char *name, uint32_t default_value,
                                    uint32_t minimum, uint32_t maximum,
                                    uint32_t *result) {
    JSValue value = JS_GetPropertyStr(ctx, options, name);
    if (JS_IsException(value))
        return -1;

    *result = default_value;
    if (!JS_IsUndefined(value)) {
        uint64_t converted;
        if (JS_ToIndex(ctx, &converted, value)) {
            JS_FreeValue(ctx, value);
            return -1;
        }
        if (converted < minimum || converted > maximum) {
            JS_FreeValue(ctx, value);
            JS_ThrowRangeError(ctx, "%s must be between %u and %u", name,
                               minimum, maximum);
            return -1;
        }
        *result = (uint32_t) converted;
    }
    JS_FreeValue(ctx, value);
    return 0;
}

static int tjs__wasm_running_mode_from_js(JSContext *ctx, JSValueConst value,
                                          RunningMode *mode) {
    const char *name = JS_ToCString(ctx, value);
    if (!name)
        return -1;
    if (!strcmp(name, "interpreter"))
        *mode = Mode_Interp;
    else if (!strcmp(name, "fast-jit"))
        *mode = Mode_Fast_JIT;
    else if (!strcmp(name, "llvm-jit"))
        *mode = Mode_LLVM_JIT;
    else if (!strcmp(name, "multi-tier-jit"))
        *mode = Mode_Multi_Tier_JIT;
    else {
        JS_FreeCString(ctx, name);
        JS_ThrowRangeError(ctx, "unknown WAMR running mode");
        return -1;
    }
    JS_FreeCString(ctx, name);
    return 0;
}

static const char *tjs__wasm_running_mode_name(RunningMode mode) {
    switch (mode) {
        case Mode_Interp: return "interpreter";
        case Mode_Fast_JIT: return "fast-jit";
        case Mode_LLVM_JIT: return "llvm-jit";
        case Mode_Multi_Tier_JIT: return "multi-tier-jit";
        default: return "unknown";
    }
}

static TJSWasmExternImport *tjs__wasm_configured_extern_at(
    TJSWasmModule *module, TJSWasmExternImport *instance_imports,
    uint32_t instance_import_count, uint32_t index) {
    if (index < module->extern_import_count)
        return module->extern_imports + index;
    index -= module->extern_import_count;
    return index < instance_import_count ? instance_imports + index : NULL;
}

static JSValue tjs_wasm_buildinstance(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, this_val);
    if (!m) {
        return JS_EXCEPTION;
    }

    if (tjs__wasm_imports_wasi(m)) { TJS_CAPABILITY_REVALIDATE(tjs__capability(ctx, TJS_CAP_OS | TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ | TJS_CAP_IO_WRITE | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "wasm.instantiateWasi"), (void)0, do { m = tjs_wasm_module_get(ctx, this_val); if (!m) return JS_EXCEPTION; } while (0)); }

    uint32_t stack_size = TJS__WASM_DEFAULT_STACK_SIZE;
    uint32_t heap_size = 0;
    uint32_t max_memory_pages = 0;
    bool set_running_mode = false;
    RunningMode running_mode = Mode_Interp;
    bool set_bounds_checks = false;
    bool bounds_checks = true;
    TJSWasmImportGroup *instance_function_groups = NULL;
    TJSWasmExternImport *instance_function_externs = NULL;
    uint32_t instance_function_extern_count = 0;
    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        if (!JS_IsObject(argv[0]) || JS_IsNull(argv[0])) {
            return JS_ThrowTypeError(ctx, "instantiate options must be an object");
        }
        if (tjs__wasm_get_u32_option(ctx, argv[0], "stackSize",
                                     TJS__WASM_DEFAULT_STACK_SIZE,
                                     TJS__WASM_MIN_STACK_SIZE,
                                     TJS__WASM_MAX_STACK_SIZE, &stack_size)
            || tjs__wasm_get_u32_option(ctx, argv[0], "hostManagedHeapSize",
                                        0, 0, UINT32_MAX, &heap_size)
            || tjs__wasm_get_u32_option(ctx, argv[0], "maxMemoryPages",
                                        0, 0, UINT32_MAX,
                                        &max_memory_pages)) {
            return JS_EXCEPTION;
        }

        JSValue mode_value = JS_GetPropertyStr(ctx, argv[0], "runningMode");
        if (JS_IsException(mode_value))
            return JS_EXCEPTION;
        if (!JS_IsUndefined(mode_value)) {
            set_running_mode = true;
            if (tjs__wasm_running_mode_from_js(ctx, mode_value, &running_mode)) {
                JS_FreeValue(ctx, mode_value);
                return JS_EXCEPTION;
            }
        }
        JS_FreeValue(ctx, mode_value);

        JSValue bounds_value = JS_GetPropertyStr(ctx, argv[0], "boundsChecks");
        if (JS_IsException(bounds_value))
            return JS_EXCEPTION;
        if (!JS_IsUndefined(bounds_value)) {
            int enabled = JS_ToBool(ctx, bounds_value);
            if (enabled < 0) {
                JS_FreeValue(ctx, bounds_value);
                return JS_EXCEPTION;
            }
            set_bounds_checks = true;
            bounds_checks = enabled;
        }
        JS_FreeValue(ctx, bounds_value);

        JSValue functions = JS_GetPropertyStr(ctx, argv[0], "functions");
        if (JS_IsException(functions))
            return JS_EXCEPTION;
        if (!JS_IsUndefined(functions)) {
            if (m->import_groups) {
                JS_FreeValue(ctx, functions);
                return tjs_throw_wasm_error(
                    ctx, "LinkError",
                    "function imports were configured both on Module and Instance");
            }
            TJSWasmImportGroup *saved_groups = m->import_groups;
            TJSWasmExternImport *saved_externs = m->extern_imports;
            uint32_t saved_extern_count = m->extern_import_count;
            m->import_groups = NULL;
            m->extern_imports = NULL;
            m->extern_import_count = 0;
            JSValue resolve_args[] = { this_val, functions };
            JSValue result = tjs_wasm_resolveimports(
                ctx, JS_UNDEFINED, 2, resolve_args);
            instance_function_groups = m->import_groups;
            instance_function_externs = m->extern_imports;
            instance_function_extern_count = m->extern_import_count;
            m->import_groups = saved_groups;
            m->extern_imports = saved_externs;
            m->extern_import_count = saved_extern_count;
            JS_FreeValue(ctx, functions);
            if (JS_IsException(result)) {
                tjs__wasm_free_import_groups(
                    JS_GetRuntime(ctx), instance_function_groups);
                for (uint32_t index = 0;
                     index < instance_function_extern_count; index++) {
                    JS_FreeValue(
                        ctx, instance_function_externs[index].provider);
                    JS_FreeValue(ctx,
                                 instance_function_externs[index].owner);
                }
                js_free(ctx, instance_function_externs);
                return result;
            }
            JS_FreeValue(ctx, result);
        }
        else {
            JS_FreeValue(ctx, functions);
        }
    }

    JSValue obj = tjs_new_wasm_instance(ctx);
    if (JS_IsException(obj)) {
        tjs__wasm_free_import_groups(JS_GetRuntime(ctx),
                                     instance_function_groups);
        for (uint32_t index = 0; index < instance_function_extern_count;
             index++) {
            JS_FreeValue(ctx, instance_function_externs[index].provider);
            JS_FreeValue(ctx, instance_function_externs[index].owner);
        }
        js_free(ctx, instance_function_externs);
        return obj;
    }

    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, obj);
    i->owned_function_groups = instance_function_groups;
    i->owned_function_externs = instance_function_externs;
    i->owned_function_extern_count = instance_function_extern_count;
    WASMExternBinding *native_bindings = NULL;
    uint32_t native_binding_count = 0;
    WASMHostFunctionBinding *host_function_bindings = NULL;
    uint32_t host_function_binding_count = 0;
    uint32_t configured_extern_count =
        m->extern_import_count + instance_function_extern_count;
    TJSWasmImportGroup *configured_function_groups =
        instance_function_groups ? instance_function_groups : m->import_groups;

    if (configured_extern_count > 0) {
        i->extern_imports = js_mallocz(
            ctx, sizeof(*i->extern_imports) * configured_extern_count);
        if (!i->extern_imports) {
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
        for (uint32_t index = 0; index < configured_extern_count; index++) {
            TJSWasmExternImport *configured = tjs__wasm_configured_extern_at(
                m, instance_function_externs,
                instance_function_extern_count, index);
            if (!JS_IsUndefined(configured->provider)
                || configured->source_is_import)
                native_binding_count++;
        }
        if (native_binding_count > 0) {
            native_bindings = js_mallocz(
                ctx, sizeof(*native_bindings) * native_binding_count);
            if (!native_bindings) {
                JS_FreeValue(ctx, obj);
                return JS_EXCEPTION;
            }
        }
        i->extern_import_count = configured_extern_count;
        uint32_t native_index = 0;
        for (uint32_t index = 0; index < configured_extern_count; index++) {
            TJSWasmExternImport *configured = tjs__wasm_configured_extern_at(
                m, instance_function_externs,
                instance_function_extern_count, index);
            if (!JS_IsUndefined(configured->provider)) {
                TJSWasmInstance *provider =
                    tjs_wasm_instance_get(ctx, configured->provider);
                if (!provider || !provider->module_inst) {
                    js_free(ctx, native_bindings);
                    JS_FreeValue(ctx, obj);
                    return JS_ThrowTypeError(ctx,
                                             "invalid live extern provider");
                }
                WASMExternBinding *native =
                    native_bindings + native_index++;
                native->kind = configured->kind;
                native->import_index = configured->import_index;
                native->source_instance = provider->module_inst;
                native->source_index = configured->source_index;
            }
            else if (configured->source_is_import) {
                WASMExternBinding *native =
                    native_bindings + native_index++;
                native->kind = configured->kind;
                native->source_is_import = 1;
                native->import_index = configured->import_index;
                native->source_index = configured->source_index;
            }
            i->extern_imports[index] = *configured;
            i->extern_imports[index].provider =
                JS_DupValue(ctx, configured->provider);
            i->extern_imports[index].owner =
                JS_DupValue(ctx, configured->owner);
        }
    }

    for (TJSWasmImportGroup *group = configured_function_groups; group;
         group = group->next)
        host_function_binding_count += group->count;
    if (host_function_binding_count > 0) {
        i->function_imports = js_mallocz(
            ctx, sizeof(*i->function_imports) * host_function_binding_count);
        host_function_bindings = js_mallocz(
            ctx, sizeof(*host_function_bindings)
                     * host_function_binding_count);
        if (!i->function_imports || !host_function_bindings) {
            js_free(ctx, native_bindings);
            js_free(ctx, host_function_bindings);
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
        i->function_import_count = host_function_binding_count;
        uint32_t binding_index = 0;
        for (TJSWasmImportGroup *group = configured_function_groups; group;
             group = group->next) {
            for (uint32_t index = 0; index < group->count; index++) {
                TJSWasmImportCtx *configured = group->ctxs + index;
                TJSWasmImportCtx *instance_ctx =
                    i->function_imports + binding_index;
                *instance_ctx = *configured;
                instance_ctx->func = JS_DupValue(ctx, configured->func);

                WASMHostFunctionBinding *native =
                    host_function_bindings + binding_index++;
                native->import_index = configured->import_index;
                native->func_ptr = tjs__wasm_import_trampoline;
                native->signature = group->symbols[index].signature;
                native->attachment = instance_ctx;
                native->call_conv_raw = true;
            }
        }
    }

    char error_buf[TJS__WASM_ERROR_BUF_SIZE];
    // Resolve any remaining symbols (WASI, etc.) if not already resolved
    wasm_runtime_resolve_symbols(m->module);

    struct InstantiationArgs2 *inst_args;
    if (!wasm_runtime_instantiation_args_create(&inst_args)) {
        js_free(ctx, native_bindings);
        js_free(ctx, host_function_bindings);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    wasm_runtime_instantiation_args_set_default_stack_size(inst_args, stack_size);
    wasm_runtime_instantiation_args_set_host_managed_heap_size(inst_args, heap_size);
    wasm_runtime_instantiation_args_set_max_memory_pages(inst_args, max_memory_pages);
    wasm_runtime_instantiation_args_set_custom_data(inst_args, i);
    inst_args->extern_bindings = native_bindings;
    inst_args->extern_binding_count = native_binding_count;
    inst_args->host_function_bindings = host_function_bindings;
    inst_args->host_function_binding_count = host_function_binding_count;

    // Instantiate the module
    i->module_inst = wasm_runtime_instantiate_ex2(m->module, inst_args,
                                                  error_buf, sizeof(error_buf));
    wasm_runtime_instantiation_args_destroy(inst_args);
    js_free(ctx, native_bindings);
    js_free(ctx, host_function_bindings);
    if (!i->module_inst) {
        if (i->has_pending_exception) {
            JSValue exception = i->pending_exception;
            i->pending_exception = JS_UNDEFINED;
            i->has_pending_exception = false;
            JS_FreeValue(ctx, obj);
            return JS_Throw(ctx, exception);
        }
        JS_FreeValue(ctx, obj);
        return tjs_throw_wasm_error(ctx, "LinkError", error_buf);
    }

    if (set_running_mode
        && !wasm_runtime_set_running_mode(i->module_inst, running_mode)) {
        wasm_runtime_deinstantiate(i->module_inst);
        i->module_inst = NULL;
        JS_FreeValue(ctx, obj);
        return JS_ThrowRangeError(ctx, "WAMR running mode is not supported by this build");
    }
    if (set_bounds_checks) {
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
        wasm_runtime_set_bounds_checks(i->module_inst, bounds_checks);
#else
        if (!bounds_checks) {
            wasm_runtime_deinstantiate(i->module_inst);
            i->module_inst = NULL;
            JS_FreeValue(ctx, obj);
            return JS_ThrowRangeError(
                ctx, "configurable WAMR bounds checks are not enabled in this build");
        }
#endif
    }

    // Create execution environment
    i->exec_env = wasm_runtime_create_exec_env(i->module_inst, stack_size);
    if (!i->exec_env) {
        wasm_runtime_deinstantiate(i->module_inst);
        i->module_inst = NULL;
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

#ifdef TJS__HAS_ASAN
    // ASAN moves local variables to a fake stack, which breaks WAMR's
    // native stack overflow check (it compares &local against the real
    // thread stack boundary — addresses in completely different regions).
    // Disable the check; OS guard pages still catch real overflows.
    wasm_runtime_set_native_stack_boundary(i->exec_env, (uint8_t *) 1);
#endif

    // Set user data so the import trampoline can find the instance
    wasm_runtime_set_user_data(i->exec_env, i);

    i->module_owner = JS_DupValue(ctx, this_val);

    return obj;
}

static const char *tjs__wasm_valkind_name(wasm_valkind_t kind) {
    switch (kind) {
        case WASM_I32: return "i32";
        case WASM_I64: return "i64";
        case WASM_F32: return "f32";
        case WASM_F64: return "f64";
        case WASM_V128: return "v128";
        case WASM_EXTERNREF: return "externref";
        case WASM_FUNCREF: return "funcref";
        default: return "unknown";
    }
}

static wasm_valkind_t tjs__wasm_internal_valkind(uint8_t type) {
    switch (type) {
        case VALUE_TYPE_I32: return WASM_I32;
        case VALUE_TYPE_I64: return WASM_I64;
        case VALUE_TYPE_F32: return WASM_F32;
        case VALUE_TYPE_F64: return WASM_F64;
        case VALUE_TYPE_V128: return WASM_V128;
        case VALUE_TYPE_EXTERNREF: return WASM_EXTERNREF;
        case VALUE_TYPE_FUNCREF: return WASM_FUNCREF;
        default: return (wasm_valkind_t)-1;
    }
}

static int tjs__wasm_define_value_types(JSContext *ctx, JSValueConst item,
                                        const char *property,
                                        wasm_func_type_t type,
                                        bool results) {
    uint32_t count = results ? wasm_func_type_get_result_count(type)
                             : wasm_func_type_get_param_count(type);
    JSValue values = JS_NewArray(ctx);
    if (JS_IsException(values))
        return -1;
    for (uint32_t index = 0; index < count; index++) {
        wasm_valkind_t kind = results
            ? tjs__wasm_func_type_get_result_valkind_safe((WASMFuncType *)type,
                                                          index)
            : wasm_func_type_get_param_valkind(type, index);
        if (JS_SetPropertyUint32(ctx, values, index,
                                 JS_NewString(ctx, tjs__wasm_valkind_name(kind))) < 0) {
            JS_FreeValue(ctx, values);
            return -1;
        }
    }
    return JS_DefinePropertyValueStr(ctx, item, property, values, JS_PROP_C_W_E);
}

static int tjs__wasm_define_external_type(JSContext *ctx, JSValueConst item,
                                          wasm_import_export_kind_t kind,
                                          const wasm_import_t *import_type,
                                          const wasm_export_t *export_type) {
    switch (kind) {
        case WASM_IMPORT_EXPORT_KIND_FUNC: {
            wasm_func_type_t type = import_type ? import_type->u.func_type
                                                : export_type->u.func_type;
            if (tjs__wasm_define_value_types(ctx, item, "parameters", type, false)
                < 0)
                return -1;
            return tjs__wasm_define_value_types(ctx, item, "results", type, true);
        }
        case WASM_IMPORT_EXPORT_KIND_GLOBAL: {
            wasm_global_type_t type = import_type ? import_type->u.global_type
                                                  : export_type->u.global_type;
            if (JS_DefinePropertyValueStr(
                    ctx, item, "value",
                    JS_NewString(ctx, tjs__wasm_valkind_name(
                                          wasm_global_type_get_valkind(type))),
                    JS_PROP_C_W_E) < 0)
                return -1;
            return JS_DefinePropertyValueStr(
                ctx, item, "mutable",
                JS_NewBool(ctx, wasm_global_type_get_mutable(type)),
                JS_PROP_C_W_E);
        }
        case WASM_IMPORT_EXPORT_KIND_MEMORY: {
            wasm_memory_type_t type = import_type ? import_type->u.memory_type
                                                  : export_type->u.memory_type;
            if (JS_DefinePropertyValueStr(
                    ctx, item, "initial",
                    JS_NewUint32(ctx, wasm_memory_type_get_init_page_count(type)),
                    JS_PROP_C_W_E) < 0
                || JS_DefinePropertyValueStr(
                       ctx, item, "maximum",
                       JS_NewUint32(ctx, wasm_memory_type_get_max_page_count(type)),
                       JS_PROP_C_W_E) < 0)
                return -1;
            return JS_DefinePropertyValueStr(
                ctx, item, "shared",
                JS_NewBool(ctx, wasm_memory_type_get_shared(type)), JS_PROP_C_W_E);
        }
        case WASM_IMPORT_EXPORT_KIND_TABLE: {
            wasm_table_type_t type = import_type ? import_type->u.table_type
                                                 : export_type->u.table_type;
            if (JS_DefinePropertyValueStr(
                    ctx, item, "element",
                    JS_NewString(ctx, tjs__wasm_valkind_name(
                                          wasm_table_type_get_elem_kind(type))),
                    JS_PROP_C_W_E) < 0
                || JS_DefinePropertyValueStr(
                       ctx, item, "initial",
                       JS_NewUint32(ctx, wasm_table_type_get_init_size(type)),
                       JS_PROP_C_W_E) < 0
                || JS_DefinePropertyValueStr(
                       ctx, item, "maximum",
                       JS_NewUint32(ctx, wasm_table_type_get_max_size(type)),
                       JS_PROP_C_W_E) < 0)
                return -1;
            return JS_DefinePropertyValueStr(
                ctx, item, "shared",
                JS_NewBool(ctx, wasm_table_type_get_shared(type)), JS_PROP_C_W_E);
        }
    }
    return 0;
}

static JSValue tjs_wasm_moduleexports(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }

    JSValue exports = JS_NewArray(ctx);
    if (JS_IsException(exports)) {
        return exports;
    }

    int32_t export_count = wasm_runtime_get_export_count(m->module);
    if (export_count < 0) {
        return exports;  // Return empty array on error
    }

    uint32_t j = 0;
    for (int32_t idx = 0; idx < export_count; idx++) {
        wasm_export_t export_type;
        wasm_runtime_get_export_type(m->module, idx, &export_type);

        const char *kind_str = NULL;

        switch (export_type.kind) {
            case WASM_IMPORT_EXPORT_KIND_FUNC:
                kind_str = "function";
                break;
            case WASM_IMPORT_EXPORT_KIND_MEMORY:
                kind_str = "memory";
                break;
            case WASM_IMPORT_EXPORT_KIND_TABLE:
                kind_str = "table";
                break;
            case WASM_IMPORT_EXPORT_KIND_GLOBAL:
                kind_str = "global";
                break;
        }

        if (kind_str) {
            JSValue item = JS_NewObjectProto(ctx, JS_NULL);
            if (JS_IsException(item)) {
                JS_FreeValue(ctx, exports);
                return JS_EXCEPTION;
            }
            JS_DefinePropertyValueStr(ctx, item, "name", JS_NewString(ctx, export_type.name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind", JS_NewString(ctx, kind_str), JS_PROP_C_W_E);
            uint32_t extern_index;
            if (tjs__wasm_is_bytecode_module(m->module)) {
                extern_index = ((WASMModule *)m->module)->exports[idx].index;
            }
#if WASM_ENABLE_AOT != 0
            else {
                extern_index = ((AOTModule *)m->module)->exports[idx].index;
            }
#else
            else {
                extern_index = 0;
            }
#endif
            if (tjs__wasm_define_external_type(ctx, item, export_type.kind, NULL,
                                               &export_type) < 0
                || JS_DefinePropertyValueStr(ctx, item, "externIndex",
                                             JS_NewUint32(ctx, extern_index),
                                             JS_PROP_C_W_E) < 0
                || JS_DefinePropertyValueUint32(ctx, exports, j, item,
                                                JS_PROP_C_W_E) < 0) {
                JS_FreeValue(ctx, exports);
                return JS_EXCEPTION;
            }
            j++;
        }
    }

    return exports;
}

static JSValue tjs_wasm_moduleimports(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }

    JSValue imports = JS_NewArray(ctx);
    if (JS_IsException(imports)) {
        return imports;
    }

    int32_t import_count = wasm_runtime_get_import_count(m->module);
    if (import_count < 0) {
        return imports;
    }

    uint32_t kind_indices[4] = { 0 };

    for (int32_t idx = 0; idx < import_count; idx++) {
        wasm_import_t import_type;
        wasm_runtime_get_import_type(m->module, idx, &import_type);

        const char *kind_str = NULL;

        switch (import_type.kind) {
            case WASM_IMPORT_EXPORT_KIND_FUNC:
                kind_str = "function";
                break;
            case WASM_IMPORT_EXPORT_KIND_MEMORY:
                kind_str = "memory";
                break;
            case WASM_IMPORT_EXPORT_KIND_TABLE:
                kind_str = "table";
                break;
            case WASM_IMPORT_EXPORT_KIND_GLOBAL:
                kind_str = "global";
                break;
        }

        if (kind_str) {
            uint32_t extern_index = kind_indices[import_type.kind]++;
            JSValue item = JS_NewObjectProto(ctx, JS_NULL);
            if (JS_IsException(item)) {
                JS_FreeValue(ctx, imports);
                return JS_EXCEPTION;
            }
            JS_DefinePropertyValueStr(ctx, item, "module", JS_NewString(ctx, import_type.module_name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "name", JS_NewString(ctx, import_type.name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind", JS_NewString(ctx, kind_str), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "linked",
                                      JS_NewBool(ctx, import_type.linked),
                                      JS_PROP_C_W_E);
            if (tjs__wasm_define_external_type(ctx, item, import_type.kind,
                                               &import_type, NULL) < 0
                || JS_DefinePropertyValueStr(ctx, item, "externIndex",
                                             JS_NewUint32(ctx, extern_index),
                                             JS_PROP_C_W_E) < 0
                || JS_DefinePropertyValueUint32(ctx, imports, idx, item,
                                                JS_PROP_C_W_E) < 0) {
                JS_FreeValue(ctx, imports);
                return JS_EXCEPTION;
            }
        }
    }

    return imports;
}

/*
 * moduleCustomSections(module, sectionName)
 *
 * Returns an array of ArrayBuffers for every custom section with the given name
 * in module order. WAMR links its list by prepending each section, so the
 * second pass writes matching nodes backwards into the JS array.
 */
static JSValue tjs_wasm_modulecustomsections(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    JSValue result = JS_NewArray(ctx);
    if (JS_IsException(result)) {
        JS_FreeCString(ctx, name);
        return result;
    }

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
    if (tjs__wasm_is_bytecode_module(m->module)) {
        WASMModule *wasm_module = (WASMModule *)m->module;
        WASMCustomSection *section = wasm_module->custom_section_list;
        uint32_t count = 0;
        while (section) {
            if (section->name_len == strlen(name)
                && memcmp(section->name_addr, name, section->name_len) == 0)
                count++;
            section = section->next;
        }
        section = wasm_module->custom_section_list;
        uint32_t index = count;
        while (section) {
            if (section->name_len == strlen(name)
                && memcmp(section->name_addr, name, section->name_len) == 0) {
                JSValue content = JS_NewArrayBufferCopy(
                    ctx, section->content_addr, section->content_len);
                if (JS_IsException(content)
                    || JS_DefinePropertyValueUint32(ctx, result, --index,
                                                    content, JS_PROP_C_W_E)
                           < 0) {
                    JS_FreeValue(ctx, result);
                    JS_FreeCString(ctx, name);
                    return JS_EXCEPTION;
                }
            }
            section = section->next;
        }
    } else {
        uint32_t length = 0;
        const uint8_t *content = wasm_runtime_get_custom_section(
            m->module, name, &length);
        if (content
            && JS_SetPropertyUint32(ctx, result, 0,
                                    JS_NewArrayBufferCopy(ctx, content, length))
                   < 0) {
            JS_FreeValue(ctx, result);
            JS_FreeCString(ctx, name);
            return JS_EXCEPTION;
        }
    }
#endif

    JS_FreeCString(ctx, name);
    return result;
}

/* Direct struct access wrapper for result valkind to avoid WAMR's broken API.
 * wasm_func_type_get_result_valkind asserts on VALUE_TYPE_EXTERNREF; this reads
 * WASMFuncType.types[] directly. Params are at [0..param_count), results at
 * [param_count..param_count+result_count). */
static wasm_valkind_t tjs__wasm_func_type_get_result_valkind_safe(WASMFuncType *func_type, uint32_t result_index) {
    if (!func_type || result_index >= func_type->result_count) {
        return (wasm_valkind_t)-1;
    }
    uint8_t value_type = func_type->types[func_type->param_count + result_index];
    switch (value_type) {
        case VALUE_TYPE_I32:
            return WASM_I32;
        case VALUE_TYPE_I64:
            return WASM_I64;
        case VALUE_TYPE_F32:
            return WASM_F32;
        case VALUE_TYPE_F64:
            return WASM_F64;
        case VALUE_TYPE_V128:
            return WASM_V128;
        case VALUE_TYPE_FUNCREF:
            return WASM_FUNCREF;
        case VALUE_TYPE_EXTERNREF:
            return WASM_EXTERNREF;
        default:
            return (wasm_valkind_t)-1;
    }
}

static char tjs__wasm_valkind_to_sig(wasm_valkind_t kind) {
    switch (kind) {
        case WASM_I32:
            return 'i';
        case WASM_I64:
            return 'I';
        case WASM_F32:
            return 'f';
        case WASM_F64:
            return 'F';
        case WASM_EXTERNREF:
            return 'r';
        default:
            return 'i';
    }
}

/* Configure function imports without mutating WAMR's module-level linkage.
 * The descriptors are matched to import occurrences (not merely names), so a
 * legal module containing the same module/name with different signatures gets
 * one callback context per occurrence. instantiate() copies these contexts and
 * supplies them through InstantiationArgs2. */
static JSValue tjs_wasm_resolveimports(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }
    if (!tjs__wasm_is_bytecode_module(m->module))
        return tjs__wasm_require_bytecode(ctx, "resolveFunctions()");
    if (m->import_groups) {
        return tjs_throw_wasm_error(
            ctx, "LinkError",
            "function imports have already been configured for this module");
    }

    /* argv[1] is the array of import descriptors */
    JSValue arr = argv[1];
    JSValue js_length = JS_GetPropertyStr(ctx, arr, "length");
    uint64_t total;
    if (JS_ToIndex(ctx, &total, js_length)) {
        JS_FreeValue(ctx, js_length);
        return JS_EXCEPTION;
    }
    JS_FreeValue(ctx, js_length);

    WASMModule *module = (WASMModule *)m->module;
    bool *matched = js_mallocz(
        ctx, sizeof(*matched) * module->import_function_count);
    TJSWasmImportGroup *group = js_mallocz(ctx, sizeof(*group));
    uint32_t original_extern_count = m->extern_import_count;
    if ((!matched && module->import_function_count) || !group)
        goto fail;
    if (total > 0) {
        group->symbols = js_mallocz(ctx, sizeof(*group->symbols) * total);
        group->ctxs = js_mallocz(ctx, sizeof(*group->ctxs) * total);
        if (!group->symbols || !group->ctxs)
            goto fail;
        for (uint64_t index = 0; index < total; index++)
            group->ctxs[index].func = JS_UNDEFINED;
    }

    for (uint64_t descriptor_index = 0; descriptor_index < total;
         descriptor_index++) {
        JSValue item = JS_GetPropertyUint32(
            ctx, arr, (uint32_t)descriptor_index);
        if (JS_IsException(item))
            goto fail;
        JSValue module_value = JS_GetPropertyStr(ctx, item, "module");
        JSValue name_value = JS_GetPropertyStr(ctx, item, "name");
        JSValue func = JS_GetPropertyStr(ctx, item, "func");
        const char *module_name = JS_ToCString(ctx, module_value);
        const char *function_name = JS_ToCString(ctx, name_value);
        if (JS_IsException(module_value) || JS_IsException(name_value)
            || JS_IsException(func) || !module_name || !function_name
            || !JS_IsFunction(ctx, func)) {
            if (!JS_IsException(func) && !JS_IsFunction(ctx, func))
                JS_ThrowTypeError(ctx, "function import must be callable");
            JS_FreeCString(ctx, module_name);
            JS_FreeCString(ctx, function_name);
            JS_FreeValue(ctx, module_value);
            JS_FreeValue(ctx, name_value);
            JS_FreeValue(ctx, func);
            JS_FreeValue(ctx, item);
            goto fail;
        }

        uint32_t import_index = UINT32_MAX;
        for (uint32_t index = 0; index < module->import_function_count;
             index++) {
            WASMFunctionImport *import =
                &module->import_functions[index].u.function;
            if (!matched[index]
                && !strcmp(import->module_name, module_name)
                && !strcmp(import->field_name, function_name)) {
                import_index = index;
                matched[index] = true;
                break;
            }
        }
        if (import_index == UINT32_MAX) {
            JS_ThrowReferenceError(ctx, "unknown function import %s.%s",
                                   module_name, function_name);
            JS_FreeCString(ctx, module_name);
            JS_FreeCString(ctx, function_name);
            JS_FreeValue(ctx, module_value);
            JS_FreeValue(ctx, name_value);
            JS_FreeValue(ctx, func);
            JS_FreeValue(ctx, item);
            goto fail;
        }

        WASMFunctionImport *import =
            &module->import_functions[import_index].u.function;
        int extern_result = tjs__wasm_record_extern_import(
            ctx, m, item, WASM_IMPORT_EXPORT_KIND_FUNC, import_index);
        bool has_native_provider =
            extern_result > 0
            && !JS_IsUndefined(
                m->extern_imports[m->extern_import_count - 1].provider);
        if (extern_result < 0) {
            JS_FreeCString(ctx, module_name);
            JS_FreeCString(ctx, function_name);
            JS_FreeValue(ctx, module_value);
            JS_FreeValue(ctx, name_value);
            JS_FreeValue(ctx, func);
            JS_FreeValue(ctx, item);
            goto fail;
        }

        if (!has_native_provider) {
            uint32_t host_index = group->count++;
            TJSWasmImportCtx *import_ctx = group->ctxs + host_index;
            import_ctx->ctx = ctx;
            import_ctx->func = JS_DupValue(ctx, func);
            import_ctx->type = import->func_type;
            import_ctx->import_index = import_index;
            import_ctx->is_host_binding = true;

            uint32_t param_count = import->func_type->param_count;
            uint32_t result_count = import->func_type->result_count;
            char *signature = js_malloc(
                ctx, param_count + result_count + 3);
            if (!signature) {
                JS_FreeCString(ctx, module_name);
                JS_FreeCString(ctx, function_name);
                JS_FreeValue(ctx, module_value);
                JS_FreeValue(ctx, name_value);
                JS_FreeValue(ctx, func);
                JS_FreeValue(ctx, item);
                goto fail;
            }
            uint32_t position = 0;
            signature[position++] = '(';
            for (uint32_t index = 0; index < param_count; index++)
                signature[position++] = tjs__wasm_valkind_to_sig(
                    wasm_func_type_get_param_valkind(import->func_type,
                                                     index));
            signature[position++] = ')';
            if (result_count > 0)
                signature[position++] = tjs__wasm_valkind_to_sig(
                    tjs__wasm_func_type_get_result_valkind_safe(
                        import->func_type, 0));
            signature[position] = '\0';
            group->symbols[host_index].symbol =
                js_strdup(ctx, function_name);
            group->symbols[host_index].signature = signature;
            if (!group->symbols[host_index].symbol) {
                JS_FreeCString(ctx, module_name);
                JS_FreeCString(ctx, function_name);
                JS_FreeValue(ctx, module_value);
                JS_FreeValue(ctx, name_value);
                JS_FreeValue(ctx, func);
                JS_FreeValue(ctx, item);
                goto fail;
            }
        }

        JS_FreeCString(ctx, module_name);
        JS_FreeCString(ctx, function_name);
        JS_FreeValue(ctx, module_value);
        JS_FreeValue(ctx, name_value);
        JS_FreeValue(ctx, func);
        JS_FreeValue(ctx, item);
    }

    js_free(ctx, matched);
    m->import_groups = group;
    return JS_UNDEFINED;

fail:
    js_free(ctx, matched);
    if (group)
        tjs__wasm_free_import_groups(JS_GetRuntime(ctx), group);
    while (m->extern_import_count > original_extern_count) {
        TJSWasmExternImport *binding =
            m->extern_imports + --m->extern_import_count;
        JS_FreeValue(ctx, binding->provider);
        JS_FreeValue(ctx, binding->owner);
    }
    if (JS_HasException(ctx))
        return JS_EXCEPTION;
    return tjs_throw_wasm_error(ctx, "LinkError",
                                "failed to configure function imports");
}

static void tjs__wasm_rollback_extern_imports(JSContext *ctx,
                                               TJSWasmModule *module,
                                               uint32_t original_count) {
    while (module->extern_import_count > original_count) {
        TJSWasmExternImport *binding =
            module->extern_imports + --module->extern_import_count;
        JS_FreeValue(ctx, binding->provider);
        JS_FreeValue(ctx, binding->owner);
    }
}

/* Resolve descriptors by import occurrence. A module may legally contain the
 * same module/name pair more than once, so name lookup alone is insufficient:
 * each descriptor consumes the first still-unmatched occurrence. */
static JSValue tjs_wasm_resolveglobalimports(JSContext *ctx, JSValue this_val,
                                              int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m)
        return JS_EXCEPTION;
    if (!tjs__wasm_is_bytecode_module(m->module))
        return tjs__wasm_require_bytecode(ctx, "resolveGlobals()");

    JSValue arr = argv[1];
    JSValue js_length = JS_GetPropertyStr(ctx, arr, "length");
    uint64_t total;
    if (JS_ToIndex(ctx, &total, js_length)) {
        JS_FreeValue(ctx, js_length);
        return JS_EXCEPTION;
    }
    JS_FreeValue(ctx, js_length);

    WASMModule *wasm_module = (WASMModule *)m->module;
    uint32_t import_count = wasm_module->import_global_count;
    uint32_t original_extern_count = m->extern_import_count;
    bool *matched = js_mallocz(ctx, sizeof(*matched) * import_count);
    WASMGlobalImport *saved = js_malloc(
        ctx, sizeof(*saved) * import_count);
    if ((!matched && import_count) || (!saved && import_count))
        goto fail;
    for (uint32_t index = 0; index < import_count; index++)
        saved[index] = wasm_module->import_globals[index].u.global;

    for (uint64_t descriptor_index = 0; descriptor_index < total;
         descriptor_index++) {
        JSValue item = JS_UNDEFINED;
        JSValue js_mod = JS_UNDEFINED;
        JSValue js_name = JS_UNDEFINED;
        JSValue js_value = JS_UNDEFINED;
        const char *mod_name = NULL;
        const char *field_name = NULL;
        uint32_t import_index = UINT32_MAX;
        bool ok = false;

        item = JS_GetPropertyUint32(ctx, arr, (uint32_t)descriptor_index);
        if (JS_IsException(item))
            goto descriptor_done;
        js_mod = JS_GetPropertyStr(ctx, item, "module");
        js_name = JS_GetPropertyStr(ctx, item, "name");
        js_value = JS_GetPropertyStr(ctx, item, "value");
        if (JS_IsException(js_mod) || JS_IsException(js_name)
            || JS_IsException(js_value))
            goto descriptor_done;
        mod_name = JS_ToCString(ctx, js_mod);
        field_name = JS_ToCString(ctx, js_name);
        if (!mod_name || !field_name)
            goto descriptor_done;

        for (uint32_t index = 0; index < import_count; index++) {
            WASMGlobalImport *candidate =
                &wasm_module->import_globals[index].u.global;
            if (!matched[index]
                && !strcmp(candidate->module_name, mod_name)
                && !strcmp(candidate->field_name, field_name)) {
                import_index = index;
                break;
            }
        }
        if (import_index == UINT32_MAX) {
            tjs_throw_wasm_error(ctx, "LinkError",
                                 "imported global occurrence not found in module");
            goto descriptor_done;
        }

        WASMGlobalImport *global =
            &wasm_module->import_globals[import_index].u.global;
        bool conversion_failed = false;
        switch (global->type.val_type) {
            case VALUE_TYPE_I32: {
                int32_t value = 0;
                conversion_failed = JS_ToInt32(ctx, &value, js_value) != 0;
                global->global_data_linked.i32 = value;
                break;
            }
            case VALUE_TYPE_I64: {
                int64_t value = 0;
                conversion_failed = JS_ToBigInt64(ctx, &value, js_value) != 0;
                global->global_data_linked.i64 = value;
                break;
            }
            case VALUE_TYPE_F32: {
                double value = 0;
                conversion_failed = JS_ToFloat64(ctx, &value, js_value) != 0;
                global->global_data_linked.f32 = (float)value;
                break;
            }
            case VALUE_TYPE_F64: {
                double value = 0;
                conversion_failed = JS_ToFloat64(ctx, &value, js_value) != 0;
                global->global_data_linked.f64 = value;
                break;
            }
            default:
                break;
        }
        if (conversion_failed)
            goto descriptor_done;
        global->is_linked = true;
        if (tjs__wasm_record_extern_import(
                ctx, m, item, WASM_IMPORT_EXPORT_KIND_GLOBAL,
                import_index) < 0)
            goto descriptor_done;
        matched[import_index] = true;
        ok = true;

descriptor_done:
        JS_FreeCString(ctx, mod_name);
        JS_FreeCString(ctx, field_name);
        JS_FreeValue(ctx, js_mod);
        JS_FreeValue(ctx, js_name);
        JS_FreeValue(ctx, js_value);
        JS_FreeValue(ctx, item);
        if (!ok)
            goto fail;
    }

    js_free(ctx, saved);
    js_free(ctx, matched);
    return JS_UNDEFINED;

fail:
    if (saved) {
        for (uint32_t index = 0; index < import_count; index++)
            wasm_module->import_globals[index].u.global = saved[index];
    }
    tjs__wasm_rollback_extern_imports(ctx, m, original_extern_count);
    js_free(ctx, saved);
    js_free(ctx, matched);
    if (JS_HasException(ctx))
        return JS_EXCEPTION;
    return JS_ThrowOutOfMemory(ctx);
}

/*
 * resolveTableImports(module, tableDescs)
 *
 * tableDescs is an array of { module: string, name: string, element: string, initial: number, maximum?: number }
 * Creates a WASMTable stub with the matching type and links it into the module's import.
 * The table elements will be initialized to NULL_REF by WAMR during instantiation.
 */
static JSValue tjs_wasm_resolvetableimports(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }
    if (!tjs__wasm_is_bytecode_module(m->module))
        return tjs__wasm_require_bytecode(ctx, "resolveTables()");

    JSValue arr = argv[1];
    JSValue js_length = JS_GetPropertyStr(ctx, arr, "length");
    uint64_t total;
    if (JS_ToIndex(ctx, &total, js_length)) {
        JS_FreeValue(ctx, js_length);
        return JS_EXCEPTION;
    }
    JS_FreeValue(ctx, js_length);

    WASMModule *wasm_module = (WASMModule *) m->module;
    uint32_t import_count = wasm_module->import_table_count;
    uint32_t original_extern_count = m->extern_import_count;
    uint32_t original_resolved_count = m->resolved_table_count;
    bool *matched = js_mallocz(ctx, sizeof(*matched) * import_count);
    WASMTableImport *saved = js_malloc(ctx, sizeof(*saved) * import_count);
    if ((!matched && import_count) || (!saved && import_count))
        goto fail;
    for (uint32_t index = 0; index < import_count; index++)
        saved[index] = wasm_module->import_tables[index].u.table;

    for (uint64_t i = 0; i < total; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, arr, (uint32_t) i);
        if (JS_IsException(item)) {
            goto fail;
        }

        JSValue js_mod = JS_GetPropertyStr(ctx, item, "module");
        JSValue js_name = JS_GetPropertyStr(ctx, item, "name");
        JSValue js_element = JS_GetPropertyStr(ctx, item, "element");
        JSValue js_initial = JS_GetPropertyStr(ctx, item, "initial");
        JSValue js_maximum = JS_GetPropertyStr(ctx, item, "maximum");

        const char *mod_name = JS_ToCString(ctx, js_mod);
        const char *field_name = JS_ToCString(ctx, js_name);
        const char *elem_kind_str = JS_ToCString(ctx, js_element);
        uint32_t initial_val;
        if (JS_ToUint32(ctx, &initial_val, js_initial)) {
            JS_FreeValue(ctx, js_initial);
            JS_FreeValue(ctx, js_mod);
            JS_FreeValue(ctx, js_name);
            JS_FreeValue(ctx, js_element);
            JS_FreeValue(ctx, js_maximum);
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeCString(ctx, elem_kind_str);
            JS_FreeValue(ctx, item);
            goto fail;
        }
        JS_FreeValue(ctx, js_initial);
        JS_FreeValue(ctx, js_mod);
        JS_FreeValue(ctx, js_name);
        JS_FreeValue(ctx, js_element);

        bool has_max = !JS_IsUndefined(js_maximum);
        uint32_t maximum_val = 0;
        if (has_max) {
            if (JS_ToUint32(ctx, &maximum_val, js_maximum)) {
                JS_FreeValue(ctx, js_maximum);
                JS_FreeCString(ctx, mod_name);
                JS_FreeCString(ctx, field_name);
                JS_FreeCString(ctx, elem_kind_str);
                JS_FreeValue(ctx, item);
                goto fail;
            }
        }
        JS_FreeValue(ctx, js_maximum);

        if (!mod_name || !field_name || !elem_kind_str) {
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeCString(ctx, elem_kind_str);
            JS_FreeValue(ctx, item);
            goto fail;
        }

        /* Parse element kind string to WAMR valtype */
        uint8_t elem_type;
        if (strcmp(elem_kind_str, "funcref") == 0) {
            elem_type = VALUE_TYPE_FUNCREF;
        } else if (strcmp(elem_kind_str, "externref") == 0) {
            elem_type = VALUE_TYPE_EXTERNREF;
        } else {
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeCString(ctx, elem_kind_str);
            JS_FreeValue(ctx, item);
            tjs_throw_wasm_error(ctx, "TypeError", "invalid table element type, expected 'funcref' or 'externref'");
            goto fail;
        }
        JS_FreeCString(ctx, elem_kind_str);

        /* Non-GC WAMR stores a funcref table element as only a function index.
         * A standalone JS Table element also has an owning Instance, so
         * copying just that index would make call_indirect resolve it in the
         * consumer's function space. Do not silently turn existing elements
         * into nulls or mis-bound functions. Null-only tables need no seeding
         * because WAMR already initializes every slot to NULL_REF. */
        if (elem_type == VALUE_TYPE_FUNCREF) {
            JSValue values = JS_GetPropertyStr(ctx, item, "values");
            if (JS_IsException(values)) {
                JS_FreeCString(ctx, mod_name);
                JS_FreeCString(ctx, field_name);
                JS_FreeValue(ctx, item);
                goto fail;
            }
            if (!JS_IsUndefined(values)) {
                JSValue length_value =
                    JS_GetPropertyStr(ctx, values, "length");
                uint64_t value_count;
                if (JS_IsException(length_value)
                    || JS_ToIndex(ctx, &value_count, length_value)) {
                    JS_FreeValue(ctx, length_value);
                    JS_FreeValue(ctx, values);
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    goto fail;
                }
                JS_FreeValue(ctx, length_value);
                for (uint64_t value_index = 0; value_index < value_count;
                     value_index++) {
                    JSValue value = JS_GetPropertyUint32(
                        ctx, values, (uint32_t)value_index);
                    if (JS_IsException(value)) {
                        JS_FreeValue(ctx, values);
                        JS_FreeCString(ctx, mod_name);
                        JS_FreeCString(ctx, field_name);
                        JS_FreeValue(ctx, item);
                        goto fail;
                    }
                    bool is_null = JS_IsNull(value);
                    JS_FreeValue(ctx, value);
                    if (!is_null) {
                        JS_FreeValue(ctx, values);
                        JS_FreeCString(ctx, mod_name);
                        JS_FreeCString(ctx, field_name);
                        JS_FreeValue(ctx, item);
                        tjs_throw_wasm_error(
                            ctx, "LinkError",
                            "non-null standalone funcref Table elements "
                            "cannot be represented by this WAMR build");
                        goto fail;
                    }
                }
            }
            JS_FreeValue(ctx, values);
        }

        if (has_max && maximum_val < initial_val) {
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeValue(ctx, item);
            tjs_throw_wasm_error(ctx, "RangeError", "table maximum must be >= initial");
            goto fail;
        }

        /* Find matching import table in the module */
        bool found = false;
        for (uint32_t j = 0; j < wasm_module->import_table_count; j++) {
            WASMTableImport *tbl_import = &wasm_module->import_tables[j].u.table;
            if (!matched[j]
                && strcmp(tbl_import->module_name, mod_name) == 0 &&
                strcmp(tbl_import->field_name, field_name) == 0) {

                /* Verify type compatibility */
                if (tbl_import->table_type.elem_type != elem_type) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    tjs_throw_wasm_error(ctx, "LinkError", "table element type mismatch");
                    goto fail;
                }
                if (initial_val < tbl_import->table_type.init_size) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    tjs_throw_wasm_error(ctx, "LinkError", "table initial size too small");
                    goto fail;
                }
                uint32_t import_max = tbl_import->table_type.max_size;
                if (has_max && maximum_val > import_max) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    tjs_throw_wasm_error(ctx, "LinkError", "table maximum size too large");
                    goto fail;
                }

                /* Create a WASMTable stub for linking */
                WASMTable *tbl = wasm_runtime_malloc(sizeof(WASMTable));
                if (!tbl) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    JS_ThrowOutOfMemory(ctx);
                    goto fail;
                }
                memset(tbl, 0, sizeof(WASMTable));
                tbl->table_type.elem_type = elem_type;
                tbl->table_type.init_size = initial_val;
                tbl->table_type.max_size = has_max ? maximum_val : initial_val;
                tbl->table_type.flags = has_max ? 1 : 0;
                tbl->table_type.possible_grow = has_max;

                /* Track for cleanup */
                WASMTable **new_arr = js_realloc(ctx, m->resolved_tables, sizeof(WASMTable *) * (m->resolved_table_count + 1));
                if (!new_arr) {
                    wasm_runtime_free(tbl);
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    JS_ThrowOutOfMemory(ctx);
                    goto fail;
                }
                m->resolved_tables = new_arr;
                m->resolved_tables[m->resolved_table_count++] = tbl;

                tbl_import->import_table_linked = tbl;
                if (tjs__wasm_record_extern_import(
                        ctx, m, item, WASM_IMPORT_EXPORT_KIND_TABLE, j) < 0) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    goto fail;
                }
                matched[j] = true;
                found = true;
                break;
            }
        }

        JS_FreeCString(ctx, mod_name);
        JS_FreeCString(ctx, field_name);
        JS_FreeValue(ctx, item);

        if (!found) {
            tjs_throw_wasm_error(ctx, "LinkError", "imported table occurrence not found in module");
            goto fail;
        }
    }

    js_free(ctx, saved);
    js_free(ctx, matched);
    return JS_UNDEFINED;

fail:
    if (saved) {
        for (uint32_t index = 0; index < import_count; index++)
            wasm_module->import_tables[index].u.table = saved[index];
    }
    while (m->resolved_table_count > original_resolved_count)
        wasm_runtime_free(
            m->resolved_tables[--m->resolved_table_count]);
    tjs__wasm_rollback_extern_imports(ctx, m, original_extern_count);
    js_free(ctx, saved);
    js_free(ctx, matched);
    if (JS_HasException(ctx))
        return JS_EXCEPTION;
    return JS_ThrowOutOfMemory(ctx);
}

/*
 * resolveMemoryImports(module, memoryDescs)
 *
 * memoryDescs is an array of { module: string, name: string, initial: number, maximum?: number }
 * Creates a WASMMemory stub with the matching type and links it into the module's import.
 */
static JSValue tjs_wasm_resolvememoryimports(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }
    if (!tjs__wasm_is_bytecode_module(m->module))
        return tjs__wasm_require_bytecode(ctx, "resolveMemories()");

    JSValue arr = argv[1];
    JSValue js_length = JS_GetPropertyStr(ctx, arr, "length");
    uint64_t total;
    if (JS_ToIndex(ctx, &total, js_length)) {
        JS_FreeValue(ctx, js_length);
        return JS_EXCEPTION;
    }
    JS_FreeValue(ctx, js_length);

    WASMModule *wasm_module = (WASMModule *) m->module;
    uint32_t import_count = wasm_module->import_memory_count;
    uint32_t original_extern_count = m->extern_import_count;
    uint32_t original_resolved_count = m->resolved_memory_count;
    bool *matched = js_mallocz(ctx, sizeof(*matched) * import_count);
    WASMMemoryImport *saved = js_malloc(ctx, sizeof(*saved) * import_count);
    if ((!matched && import_count) || (!saved && import_count))
        goto fail;
    for (uint32_t index = 0; index < import_count; index++)
        saved[index] = wasm_module->import_memories[index].u.memory;

    for (uint64_t i = 0; i < total; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, arr, (uint32_t) i);
        if (JS_IsException(item)) {
            goto fail;
        }

        JSValue js_mod = JS_GetPropertyStr(ctx, item, "module");
        JSValue js_name = JS_GetPropertyStr(ctx, item, "name");
        JSValue js_initial = JS_GetPropertyStr(ctx, item, "initial");
        JSValue js_maximum = JS_GetPropertyStr(ctx, item, "maximum");

        const char *mod_name = JS_ToCString(ctx, js_mod);
        const char *field_name = JS_ToCString(ctx, js_name);
        uint32_t initial_val;
        if (JS_ToUint32(ctx, &initial_val, js_initial)) {
            JS_FreeValue(ctx, js_initial);
            JS_FreeValue(ctx, js_mod);
            JS_FreeValue(ctx, js_name);
            JS_FreeValue(ctx, js_maximum);
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeValue(ctx, item);
            goto fail;
        }
        JS_FreeValue(ctx, js_initial);
        JS_FreeValue(ctx, js_mod);
        JS_FreeValue(ctx, js_name);

        bool has_max = !JS_IsUndefined(js_maximum);
        uint32_t maximum_val = 0;
        if (has_max) {
            if (JS_ToUint32(ctx, &maximum_val, js_maximum)) {
                JS_FreeValue(ctx, js_maximum);
                JS_FreeCString(ctx, mod_name);
                JS_FreeCString(ctx, field_name);
                JS_FreeValue(ctx, item);
                goto fail;
            }
        }
        JS_FreeValue(ctx, js_maximum);

        if (!mod_name || !field_name) {
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeValue(ctx, item);
            goto fail;
        }

        if (has_max && maximum_val < initial_val) {
            JS_FreeCString(ctx, mod_name);
            JS_FreeCString(ctx, field_name);
            JS_FreeValue(ctx, item);
            tjs_throw_wasm_error(ctx, "RangeError", "memory maximum must be >= initial");
            goto fail;
        }

        /* Find matching import memory in the module */
        bool found = false;
        for (uint32_t j = 0; j < wasm_module->import_memory_count; j++) {
            WASMMemoryImport *mem_import = &wasm_module->import_memories[j].u.memory;
            if (!matched[j]
                && strcmp(mem_import->module_name, mod_name) == 0 &&
                strcmp(mem_import->field_name, field_name) == 0) {

                /* Verify type compatibility */
                if (initial_val < mem_import->mem_type.init_page_count) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    tjs_throw_wasm_error(ctx, "LinkError", "memory initial page count too small");
                    goto fail;
                }
                if (has_max && maximum_val > mem_import->mem_type.max_page_count) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    tjs_throw_wasm_error(ctx, "LinkError", "memory maximum page count too large");
                    goto fail;
                }

                /* Create a WASMMemory stub for linking */
                WASMMemory *mem = wasm_runtime_malloc(sizeof(WASMMemory));
                if (!mem) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    JS_ThrowOutOfMemory(ctx);
                    goto fail;
                }
                memset(mem, 0, sizeof(WASMMemory));
                mem->num_bytes_per_page = 65536;
                mem->init_page_count = initial_val;
                mem->max_page_count = has_max ? maximum_val : initial_val;
                mem->flags = has_max ? 1 : 0;

                /* Track for cleanup */
                WASMMemory **new_arr = js_realloc(ctx, m->resolved_memories, sizeof(WASMMemory *) * (m->resolved_memory_count + 1));
                if (!new_arr) {
                    wasm_runtime_free(mem);
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    JS_ThrowOutOfMemory(ctx);
                    goto fail;
                }
                m->resolved_memories = new_arr;
                m->resolved_memories[m->resolved_memory_count++] = mem;

                mem_import->import_memory_linked = mem;
                if (tjs__wasm_record_extern_import(
                        ctx, m, item, WASM_IMPORT_EXPORT_KIND_MEMORY, j) < 0) {
                    JS_FreeCString(ctx, mod_name);
                    JS_FreeCString(ctx, field_name);
                    JS_FreeValue(ctx, item);
                    goto fail;
                }
                matched[j] = true;
                found = true;
                break;
            }
        }

        JS_FreeCString(ctx, mod_name);
        JS_FreeCString(ctx, field_name);
        JS_FreeValue(ctx, item);

        if (!found) {
            tjs_throw_wasm_error(ctx, "LinkError", "imported memory occurrence not found in module");
            goto fail;
        }
    }

    js_free(ctx, saved);
    js_free(ctx, matched);
    return JS_UNDEFINED;

fail:
    if (saved) {
        for (uint32_t index = 0; index < import_count; index++)
            wasm_module->import_memories[index].u.memory = saved[index];
    }
    while (m->resolved_memory_count > original_resolved_count)
        wasm_runtime_free(
            m->resolved_memories[--m->resolved_memory_count]);
    tjs__wasm_rollback_extern_imports(ctx, m, original_extern_count);
    js_free(ctx, saved);
    js_free(ctx, matched);
    if (JS_HasException(ctx))
        return JS_EXCEPTION;
    return JS_ThrowOutOfMemory(ctx);
}

static JSValue tjs_wasm_parsemodule(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "load() requires an ArrayBuffer or view");
    size_t size;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &size, argv[0]);
    if (!buf) {
        if (JS_HasException(ctx))
            return JS_EXCEPTION;
        return JS_ThrowTypeError(ctx, "load() requires a non-empty ArrayBuffer or view");
    }

    if (size == 0)
        return JS_ThrowTypeError(ctx, "load() requires a non-empty buffer");
    if (size > UINT32_MAX)
        return JS_ThrowRangeError(ctx, "WASM binary is too large");

    JSValue obj = tjs_new_wasm_module(ctx);
    if (JS_IsException(obj)) {
        return obj;
    }

    TJSWasmModule *m = tjs_wasm_module_get(ctx, obj);

    // WAMR requires the buffer to be writable and kept alive until unload
    m->data.bytes = js_malloc(ctx, size);
    if (!m->data.bytes) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    memcpy(m->data.bytes, buf, size);
    m->data.size = size;

    char error_buf[TJS__WASM_ERROR_BUF_SIZE];
    LoadArgs load_args = { 0 };
    load_args.no_resolve = true;
    load_args.wasm_binary_freeable = true;
    m->module = wasm_runtime_load_ex(m->data.bytes, (uint32_t) size, &load_args, error_buf, sizeof(error_buf));
    if (!m->module) {
        JS_FreeValue(ctx, obj);
        return tjs_throw_wasm_error(ctx, "CompileError", error_buf);
    }

    return obj;
}

/* No-op free function: WAMR owns the memory, not JS */
static void *tjs__wasm_memory_free(JSRuntime *rt, void *opaque, void *ptr, size_t size) {
    (void)rt; (void)opaque; (void)ptr;
    return NULL;
}

static JSValue tjs__wasm_memory_buffer(JSContext *ctx, TJSWasmInstance *i,
                                       wasm_memory_inst_t mem) {
    if (!mem) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", "no memory instance");
    }

    void *base = wasm_memory_get_base_address(mem);
    uint64_t page_count = wasm_memory_get_cur_page_count(mem);
    uint64_t bytes_per_page = wasm_memory_get_bytes_per_page(mem);
    size_t byte_length = (size_t) (page_count * bytes_per_page);

    /* Reuse the cached buffer only while it still describes the current WAMR
     * linear memory. Internal memory.grow can detach or resize behind our JS
     * wrapper before growMemory() is called explicitly. */
    TJSWasmMemoryBuffer *cache = tjs__wasm_find_memory_buffer(i, mem);
    if (cache && !JS_IsUndefined(cache->buffer)) {
        bool stale = true;
        if (tjs__wasm_cached_membuf_is_stale(ctx, cache, base, byte_length,
                                             &stale))
            return JS_EXCEPTION;
        if (!stale)
            return JS_DupValue(ctx, cache->buffer);
        tjs__wasm_invalidate_memory(i, mem);
    }
    if (!cache) {
        cache = js_mallocz(ctx, sizeof(*cache));
        if (!cache)
            return JS_EXCEPTION;
        cache->memory = mem;
        cache->buffer = JS_UNDEFINED;
        cache->next = i->memory_buffers;
        i->memory_buffers = cache;
    }

    JSValue buf = JS_NewArrayBuffer(ctx, (uint8_t *) base, byte_length, 0, tjs__wasm_memory_free, NULL, false);
    if (JS_IsException(buf))
        return buf;
    if (JS_SetArrayBufferPinUnsupported(buf, true) < 0) {
        JS_FreeValue(ctx, buf);
        return JS_ThrowInternalError(
            ctx, "cannot mark WebAssembly memory as unsafe to pin");
    }
    /* Keep our own tracking reference so we can detach it on grow. */
    cache->buffer = JS_DupValue(ctx, buf);
    cache->base = base;
    cache->byte_length = byte_length;
    return buf;
}

static JSValue tjs_wasm_getmemorybuffer(JSContext *ctx, JSValue this_val,
                                        int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i)
        return JS_EXCEPTION;
    return tjs__wasm_memory_buffer(
        ctx, i, wasm_runtime_get_default_memory(i->module_inst));
}

static JSValue tjs_wasm_getmemorybufferat(JSContext *ctx, JSValue this_val,
                                          int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index;
    if (!i || JS_ToUint32(ctx, &index, argv[1]))
        return JS_EXCEPTION;
    return tjs__wasm_memory_buffer(
        ctx, i, wasm_runtime_get_memory(i->module_inst, index));
}

static JSValue tjs_wasm_growmemory(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[1])) {
        return JS_EXCEPTION;
    }

    wasm_memory_inst_t mem = wasm_runtime_get_default_memory(i->module_inst);
    if (!mem) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", "no memory instance");
    }

    uint64_t old_pages = wasm_memory_get_cur_page_count(mem);

    if (delta == 0) {
        return JS_NewUint32(ctx, (uint32_t) old_pages);
    }

    if (!wasm_memory_enlarge(mem, delta)) {
        return JS_ThrowRangeError(ctx, "failed to grow memory");
    }

    /* Base may have moved; invalidate any previously exposed buffer. */
    tjs__wasm_invalidate_memory(i, mem);

    return JS_NewUint32(ctx, (uint32_t) old_pages);
}

static JSValue tjs_wasm_growmemoryat(JSContext *ctx, JSValue this_val,
                                     int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index, delta;
    if (!i || JS_ToUint32(ctx, &index, argv[1])
        || JS_ToUint32(ctx, &delta, argv[2]))
        return JS_EXCEPTION;
    wasm_memory_inst_t memory = wasm_runtime_get_memory(i->module_inst, index);
    if (!memory)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "memory not found");
    uint64_t old_pages = wasm_memory_get_cur_page_count(memory);
    if (delta && !wasm_memory_enlarge(memory, delta))
        return JS_ThrowRangeError(ctx, "failed to grow memory");
    if (delta)
        tjs__wasm_invalidate_memory(i, memory);
    return JS_NewUint32(ctx, (uint32_t)old_pages);
}

static JSValue tjs_wasm_importedextern(JSContext *ctx, JSValue this_val,
                                       int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint8_t kind;
    uint32_t index;
    if (!i || tjs__wasm_kind_from_js(ctx, argv[1], &kind)
        || JS_ToUint32(ctx, &index, argv[2]))
        return JS_EXCEPTION;
    TJSWasmExternImport *binding =
        tjs__wasm_find_extern_import(i, kind, index);
    if (!binding || JS_IsUndefined(binding->owner))
        return JS_UNDEFINED;
    /* An ordinary JS callback is adapted into a new wasm function belonging to
     * this Instance. Only a wasm-origin function with a provider may preserve
     * its original wrapper identity across a re-export. */
    if (kind == WASM_IMPORT_EXPORT_KIND_FUNC
        && JS_IsUndefined(binding->provider))
        return JS_UNDEFINED;
    return JS_DupValue(ctx, binding->owner);
}

static JSValue tjs__wasm_global_get(JSContext *ctx,
                                    TJSWasmInstance *owner,
                                    WASMGlobalInstance *global,
                                    void *data) {
    wasm_val_t value = { .kind = tjs__wasm_internal_valkind(global->type) };
    switch (value.kind) {
        case WASM_I32: memcpy(&value.of.i32, data, sizeof(value.of.i32)); break;
        case WASM_I64: memcpy(&value.of.i64, data, sizeof(value.of.i64)); break;
        case WASM_F32: memcpy(&value.of.f32, data, sizeof(value.of.f32)); break;
        case WASM_F64: memcpy(&value.of.f64, data, sizeof(value.of.f64)); break;
        case WASM_EXTERNREF: {
            uint32_t index;
            memcpy(&index, data, sizeof(index));
            return JS_DupValue(ctx, tjs__externref_unbox(owner, index));
        }
        case WASM_FUNCREF: {
            uint32_t index;
            memcpy(&index, data, sizeof(index));
            return index == (uint32_t)NULL_REF ? JS_NULL
                                               : JS_NewUint32(ctx, index);
        }
        case WASM_V128:
            return JS_NewUint8ArrayCopy(ctx, data, 16);
        default:
            return JS_UNDEFINED;
    }
    return tjs__wasm_val_to_js(ctx, &value);
}

static JSValue tjs__wasm_global_set(JSContext *ctx,
                                    TJSWasmInstance *owner,
                                    WASMGlobalInstance *global,
                                    void *data, JSValueConst value) {
    if (!global->is_mutable)
        return JS_ThrowTypeError(ctx, "cannot set an immutable global");
    switch (tjs__wasm_internal_valkind(global->type)) {
        case WASM_I32: {
            int32_t converted;
            if (JS_ToInt32(ctx, &converted, value)) return JS_EXCEPTION;
            memcpy(data, &converted, sizeof(converted));
            break;
        }
        case WASM_I64: {
            int64_t converted;
            if (JS_ToBigInt64(ctx, &converted, value)) return JS_EXCEPTION;
            memcpy(data, &converted, sizeof(converted));
            break;
        }
        case WASM_F32: {
            double converted;
            if (JS_ToFloat64(ctx, &converted, value)) return JS_EXCEPTION;
            float narrowed = (float)converted;
            memcpy(data, &narrowed, sizeof(narrowed));
            break;
        }
        case WASM_F64: {
            double converted;
            if (JS_ToFloat64(ctx, &converted, value)) return JS_EXCEPTION;
            memcpy(data, &converted, sizeof(converted));
            break;
        }
        case WASM_EXTERNREF: {
            uint32_t index;
            if (!tjs__externref_box(owner, ctx, value, &index))
                return JS_ThrowInternalError(ctx, "failed to register externref");
            memcpy(data, &index, sizeof(index));
            break;
        }
        case WASM_FUNCREF: {
            uint32_t index = (uint32_t)NULL_REF;
            if (!JS_IsNull(value) && !JS_IsUndefined(value)
                && JS_ToUint32(ctx, &index, value))
                return JS_EXCEPTION;
            memcpy(data, &index, sizeof(index));
            break;
        }
        case WASM_V128: {
            size_t length;
            uint8_t *bytes = JS_GetAnyBuffer(ctx, &length, value);
            if (!bytes || length < 16)
                return JS_ThrowTypeError(ctx,
                                         "v128 global requires a 16-byte buffer");
            memcpy(data, bytes, 16);
            break;
        }
        default:
            return JS_ThrowTypeError(ctx, "unsupported global type");
    }
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_getglobalat(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index;
    if (!i || JS_ToUint32(ctx, &index, argv[1])) return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_GLOBAL, &index);
    void *data;
    WASMGlobalInstance *global = tjs__wasm_global_at(owner, index, &data);
    if (!global)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "global not found");
    return tjs__wasm_global_get(ctx, owner, global, data);
}

static JSValue tjs_wasm_setglobalat(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index;
    if (!i || JS_ToUint32(ctx, &index, argv[1])) return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_GLOBAL, &index);
    void *data;
    WASMGlobalInstance *global = tjs__wasm_global_at(owner, index, &data);
    if (!global)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "global not found");
    return tjs__wasm_global_set(ctx, owner, global, data, argv[2]);
}

static JSValue tjs_wasm_getglobalinfoat(JSContext *ctx, JSValue this_val,
                                        int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index;
    if (!i || JS_ToUint32(ctx, &index, argv[1])) return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_GLOBAL, &index);
    void *data;
    WASMGlobalInstance *global = tjs__wasm_global_at(owner, index, &data);
    (void)data;
    if (!global)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "global not found");
    JSValue info = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(info)) return info;
    JS_DefinePropertyValueStr(
        ctx, info, "type",
        JS_NewString(ctx, tjs__wasm_valkind_name(
                              tjs__wasm_internal_valkind(global->type))),
        JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, info, "mutable",
                              JS_NewBool(ctx, global->is_mutable), JS_PROP_C_W_E);
    return info;
}

static int tjs__wasm_table_value(JSContext *ctx, TJSWasmInstance *owner,
                                 WASMTableInstance *table,
                                 JSValueConst value,
                                 table_elem_type_t *result) {
    wasm_valkind_t kind = tjs__wasm_internal_valkind(table->elem_type);
    if (JS_IsNull(value) || JS_IsUndefined(value)) {
        *result = (table_elem_type_t)(uint32_t)NULL_REF;
        return 0;
    }
    if (kind == WASM_FUNCREF) {
        uint32_t index;
        if (JS_ToUint32(ctx, &index, value)) return -1;
        *result = (table_elem_type_t)index;
        return 0;
    }
    if (kind == WASM_EXTERNREF) {
        uint32_t index;
        if (!tjs__externref_box(owner, ctx, value, &index)) {
            JS_ThrowInternalError(ctx, "failed to register externref");
            return -1;
        }
        *result = (table_elem_type_t)index;
        return 0;
    }
    JS_ThrowTypeError(ctx, "unsupported table element type");
    return -1;
}

static JSValue tjs_wasm_gettableinfoat(JSContext *ctx, JSValue this_val,
                                       int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index;
    if (!i || JS_ToUint32(ctx, &index, argv[1])) return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &index);
    WASMTableInstance *table = tjs__wasm_table_at(owner, index);
    if (!table)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    JSValue info = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(info)) return info;
    JS_DefinePropertyValueStr(
        ctx, info, "element",
        JS_NewString(ctx, tjs__wasm_valkind_name(
                              tjs__wasm_internal_valkind(table->elem_type))),
        JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, info, "cur_size",
                              JS_NewUint32(ctx, table->cur_size), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, info, "max_size",
                              JS_NewUint32(ctx, table->max_size), JS_PROP_C_W_E);
    return info;
}

static JSValue tjs_wasm_tablesizeat(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t index;
    if (!i || JS_ToUint32(ctx, &index, argv[1])) return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &index);
    WASMTableInstance *table = tjs__wasm_table_at(owner, index);
    return table ? JS_NewUint32(ctx, table->cur_size)
                 : tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
}

static JSValue tjs_wasm_tablegetat(JSContext *ctx, JSValue this_val,
                                   int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t table_index, element_index;
    if (!i || JS_ToUint32(ctx, &table_index, argv[1])
        || JS_ToUint32(ctx, &element_index, argv[2]))
        return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &table_index);
    WASMTableInstance *table = tjs__wasm_table_at(owner, table_index);
    if (!table)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    if (element_index >= table->cur_size)
        return JS_ThrowRangeError(ctx, "table index out of bounds");
    table_elem_type_t element = table->elems[element_index];
    if ((uint32_t)element == (uint32_t)NULL_REF) return JS_NULL;
    wasm_valkind_t kind = tjs__wasm_internal_valkind(table->elem_type);
    if (kind == WASM_FUNCREF) {
        WASMModuleInstance *element_owner = wasm_table_get_func_owner(
            table, element_index, (WASMModuleInstance *)owner->module_inst);
        TJSWasmInstance *native_owner = element_owner
            ? wasm_runtime_get_custom_data((wasm_module_inst_t)element_owner)
            : NULL;
        if (!native_owner)
            return JS_ThrowInternalError(ctx,
                                         "funcref owner is not available");
        JSValue result = JS_NewObjectProto(ctx, JS_NULL);
        if (JS_IsException(result))
            return result;
        JSValue owner_value = JS_WeakRefDeref(ctx, native_owner->weak_self);
        if (JS_IsException(owner_value)) {
            JS_FreeValue(ctx, result);
            return owner_value;
        }
        if (JS_IsUndefined(owner_value)) {
            JS_FreeValue(ctx, result);
            return JS_ThrowInternalError(ctx,
                                         "funcref owner is no longer alive");
        }
        JS_DefinePropertyValueStr(ctx, result, "index",
                                  JS_NewUint32(ctx, (uint32_t)element),
                                  JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, result, "owner", owner_value,
                                  JS_PROP_C_W_E);
        return result;
    }
    if (kind == WASM_EXTERNREF)
        return JS_DupValue(ctx,
                           tjs__externref_unbox(owner, (uint32_t)element));
    return JS_NULL;
}

static JSValue tjs_wasm_tablesetat(JSContext *ctx, JSValue this_val,
                                   int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t table_index, element_index;
    if (!i || JS_ToUint32(ctx, &table_index, argv[1])
        || JS_ToUint32(ctx, &element_index, argv[2]))
        return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &table_index);
    WASMTableInstance *table = tjs__wasm_table_at(owner, table_index);
    if (!table)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    if (element_index >= table->cur_size)
        return JS_ThrowRangeError(ctx, "table index out of bounds");
    table_elem_type_t element;
    if (tjs__wasm_table_value(ctx, owner, table, argv[3], &element))
        return JS_EXCEPTION;
    if (!wasm_table_set_elem((WASMModuleInstance *)owner->module_inst,
                             table, element_index, element))
        return JS_ThrowInternalError(ctx, "failed to retain table element");
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_tablegrowat(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    uint32_t table_index, delta;
    if (!i || JS_ToUint32(ctx, &table_index, argv[1])
        || JS_ToUint32(ctx, &delta, argv[2]))
        return JS_EXCEPTION;
    TJSWasmInstance *owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &table_index);
    WASMTableInstance *table = tjs__wasm_table_at(owner, table_index);
    if (!table)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    table_elem_type_t init = (table_elem_type_t)(uint32_t)NULL_REF;
    if (argc > 3
        && tjs__wasm_table_value(ctx, owner, table, argv[3], &init))
        return JS_EXCEPTION;
    uint32_t old_size = table->cur_size;
    if (!wasm_enlarge_table((WASMModuleInstance *)owner->module_inst,
                            table_index, delta, init))
        return JS_NewInt32(ctx, -1);
    return JS_NewUint32(ctx, old_size);
}

static JSValue tjs_wasm_getglobal(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    wasm_global_inst_t global_inst;
    if (!wasm_runtime_get_export_global_inst(i->module_inst, name, &global_inst)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "global not found");
    }
    TJSWasmInstance *global_owner = tjs__wasm_export_owner(
        ctx, i, name, WASM_IMPORT_EXPORT_KIND_GLOBAL);
    JS_FreeCString(ctx, name);

    switch (global_inst.kind) {
        case WASM_I32:
        case WASM_I64:
        case WASM_F32:
        case WASM_F64: {
            wasm_val_t val;
            val.kind = global_inst.kind;
            switch (global_inst.kind) {
                case WASM_I32:
                    memcpy(&val.of.i32, global_inst.global_data, sizeof(val.of.i32));
                    break;
                case WASM_I64:
                    memcpy(&val.of.i64, global_inst.global_data, sizeof(val.of.i64));
                    break;
                case WASM_F32:
                    memcpy(&val.of.f32, global_inst.global_data, sizeof(val.of.f32));
                    break;
                case WASM_F64:
                    memcpy(&val.of.f64, global_inst.global_data, sizeof(val.of.f64));
                    break;
                default:
                    break;
            }
            return tjs__wasm_val_to_js(ctx, &val);
        }
        case WASM_EXTERNREF: {
            uint32_t idx = *(uint32_t *) global_inst.global_data;
            return JS_DupValue(ctx,
                               tjs__externref_unbox(global_owner, idx));
        }
        case WASM_FUNCREF: {
            /* funcref globals hold a function index (NULL_REF == null). */
            uint32_t fidx;
            memcpy(&fidx, global_inst.global_data, sizeof(fidx));
            if (fidx == (uint32_t) NULL_REF)
                return JS_NULL;
            return JS_NewUint32(ctx, fidx);
        }
        case WASM_V128:
            /* 128-bit SIMD value exposed as a copied 16-byte Uint8Array. */
            return JS_NewUint8ArrayCopy(ctx, (const uint8_t *) global_inst.global_data, 16);
        default:
            return JS_UNDEFINED;
    }
}

static JSValue tjs_wasm_setglobal(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    wasm_global_inst_t global_inst;
    if (!wasm_runtime_get_export_global_inst(i->module_inst, name, &global_inst)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "global not found");
    }
    TJSWasmInstance *global_owner = tjs__wasm_export_owner(
        ctx, i, name, WASM_IMPORT_EXPORT_KIND_GLOBAL);
    JS_FreeCString(ctx, name);

    if (!global_inst.is_mutable) {
        return JS_ThrowTypeError(ctx, "cannot set an immutable global");
    }

    switch (global_inst.kind) {
        case WASM_I32: {
            int32_t v;
            if (JS_ToInt32(ctx, &v, argv[2])) {
                return JS_EXCEPTION;
            }
            memcpy(global_inst.global_data, &v, sizeof(v));
            break;
        }
        case WASM_I64: {
            /* An i64 global is written with ToBigInt64: a Number must throw,
             * not be silently narrowed through JS_ToInt32 (which is what the
             * cleared-exception fallback here used to do). */
            int64_t v;
            if (JS_ToBigInt64(ctx, &v, argv[2])) {
                return JS_EXCEPTION;
            }
            memcpy(global_inst.global_data, &v, sizeof(v));
            break;
        }
        case WASM_F32: {
            double f64;
            if (JS_ToFloat64(ctx, &f64, argv[2])) {
                return JS_EXCEPTION;
            }
            float f32 = (float) f64;
            memcpy(global_inst.global_data, &f32, sizeof(f32));
            break;
        }
        case WASM_F64: {
            double f64;
            if (JS_ToFloat64(ctx, &f64, argv[2])) {
                return JS_EXCEPTION;
            }
            memcpy(global_inst.global_data, &f64, sizeof(f64));
            break;
        }
        case WASM_EXTERNREF: {
            uint32_t idx;
            if (!tjs__externref_box(global_owner, ctx, argv[2], &idx)) {
                return JS_ThrowInternalError(ctx, "failed to register externref");
            }
            memcpy(global_inst.global_data, &idx, sizeof(idx));
            break;
        }
        case WASM_FUNCREF: {
            /* funcref globals hold a function index; null clears to NULL_REF. */
            if (JS_IsNull(argv[2]) || JS_IsUndefined(argv[2])) {
                uint32_t nullref = (uint32_t) NULL_REF;
                memcpy(global_inst.global_data, &nullref, sizeof(nullref));
            } else {
                uint32_t fidx;
                if (JS_ToUint32(ctx, &fidx, argv[2])) {
                    return JS_EXCEPTION;
                }
                memcpy(global_inst.global_data, &fidx, sizeof(fidx));
            }
            break;
        }
        case WASM_V128: {
            /* Accept any 16-byte view/buffer for the 128-bit SIMD value. */
            size_t len = 0;
            uint8_t *data = JS_GetAnyBuffer(ctx, &len, argv[2]);
            if (!data) {
                return JS_ThrowTypeError(ctx, "v128 global requires a byte buffer");
            }
            if (len < 16) {
                return JS_ThrowTypeError(ctx, "v128 global requires a 16-byte buffer");
            }
            memcpy(global_inst.global_data, data, 16);
            break;
        }
        default:
            return JS_ThrowTypeError(ctx, "unsupported global type");
    }

    return JS_UNDEFINED;
}

static JSValue tjs_wasm_getglobalinfo(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    wasm_global_inst_t global_inst;
    if (!wasm_runtime_get_export_global_inst(i->module_inst, name, &global_inst)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "global not found");
    }
    JS_FreeCString(ctx, name);

    const char *type_str;
    switch (global_inst.kind) {
        case WASM_I32:
            type_str = "i32";
            break;
        case WASM_I64:
            type_str = "i64";
            break;
        case WASM_F32:
            type_str = "f32";
            break;
        case WASM_F64:
            type_str = "f64";
            break;
        case WASM_EXTERNREF:
            type_str = "externref";
            break;
        case WASM_FUNCREF:
            type_str = "funcref";
            break;
        default:
            type_str = "unknown";
            break;
    }

    JSValue obj = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, obj, "type", JS_NewString(ctx, type_str), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "mutable", JS_NewBool(ctx, global_inst.is_mutable), JS_PROP_C_W_E);

    return obj;
}

/* Table operations using internal WAMR structures */

static JSValue tjs_wasm_gettableinfo(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    wasm_table_inst_t tbl;
    if (!wasm_runtime_get_export_table_inst(i->module_inst, name, &tbl)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    }
    JS_FreeCString(ctx, name);

    const char *elem_kind_str;
    switch (tbl.elem_kind) {
        case WASM_FUNCREF:
            elem_kind_str = "funcref";
            break;
        case WASM_EXTERNREF:
            elem_kind_str = "externref";
            break;
        default:
            elem_kind_str = "unknown";
            break;
    }

    JSValue obj = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, obj, "element", JS_NewString(ctx, elem_kind_str), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "cur_size", JS_NewUint32(ctx, tbl.cur_size), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "max_size", JS_NewUint32(ctx, tbl.max_size), JS_PROP_C_W_E);

    return obj;
}

static JSValue tjs_wasm_tablesize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    wasm_table_inst_t tbl;
    if (!wasm_runtime_get_export_table_inst(i->module_inst, name, &tbl)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    }
    JS_FreeCString(ctx, name);

    return JS_NewUint32(ctx, tbl.cur_size);
}

static JSValue tjs_wasm_tableget(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    uint32_t index;
    if (JS_ToUint32(ctx, &index, argv[2])) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }

    /* Get the public table info for bounds and type */
    wasm_table_inst_t tbl;
    if (!wasm_runtime_get_export_table_inst(i->module_inst, name, &tbl)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    }
    uint32_t table_index;
    if (!tjs__wasm_export_index(i, name, WASM_IMPORT_EXPORT_KIND_TABLE,
                                &table_index)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    }
    TJSWasmInstance *table_owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &table_index);
    WASMTableInstance *table = tjs__wasm_table_at(table_owner, table_index);
    JS_FreeCString(ctx, name);

    if (!table)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");

    if (index >= tbl.cur_size) {
        return tjs_throw_wasm_error(ctx, "RangeError", "table index out of bounds");
    }

    /* Access the internal table elements (use memcpy for potentially misaligned WAMR data) */
    table_elem_type_t elem;
    memcpy(&elem, (uint8_t *) tbl.elems + index * sizeof(table_elem_type_t), sizeof(elem));

    if (tbl.elem_kind == WASM_FUNCREF) {
        if ((uint32_t) elem == (uint32_t) NULL_REF) {
            return JS_NULL;
        }
        WASMModuleInstance *element_owner = wasm_table_get_func_owner(
            table, index, (WASMModuleInstance *)table_owner->module_inst);
        TJSWasmInstance *native_owner = element_owner
            ? wasm_runtime_get_custom_data((wasm_module_inst_t)element_owner)
            : NULL;
        if (!native_owner)
            return JS_ThrowInternalError(ctx,
                                         "funcref owner is not available");
        JSValue result = JS_NewObjectProto(ctx, JS_NULL);
        if (JS_IsException(result))
            return result;
        JSValue owner_value = JS_WeakRefDeref(ctx, native_owner->weak_self);
        if (JS_IsException(owner_value)) {
            JS_FreeValue(ctx, result);
            return owner_value;
        }
        if (JS_IsUndefined(owner_value)) {
            JS_FreeValue(ctx, result);
            return JS_ThrowInternalError(ctx,
                                         "funcref owner is no longer alive");
        }
        JS_DefinePropertyValueStr(ctx, result, "index",
                                  JS_NewUint32(ctx, (uint32_t)elem),
                                  JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, result, "owner", owner_value,
                                  JS_PROP_C_W_E);
        return result;
    } else if (tbl.elem_kind == WASM_EXTERNREF) {
        if ((uint32_t) elem == (uint32_t) NULL_REF) {
            return JS_NULL;
        }
        return JS_DupValue(ctx,
                           tjs__externref_unbox(table_owner,
                                                (uint32_t)elem));
    }

    return JS_NULL;
}

static JSValue tjs_wasm_tableset(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    uint32_t index;
    if (JS_ToUint32(ctx, &index, argv[2])) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }

    wasm_table_inst_t tbl;
    if (!wasm_runtime_get_export_table_inst(i->module_inst, name, &tbl)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    }
    uint32_t table_index;
    if (!tjs__wasm_export_index(i, name, WASM_IMPORT_EXPORT_KIND_TABLE,
                                &table_index)) {
        JS_FreeCString(ctx, name);
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");
    }
    TJSWasmInstance *table_owner = tjs__wasm_canonical_extern(
        ctx, i, WASM_IMPORT_EXPORT_KIND_TABLE, &table_index);
    WASMTableInstance *table = tjs__wasm_table_at(table_owner, table_index);
    JS_FreeCString(ctx, name);

    if (!table)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");

    if (index >= tbl.cur_size) {
        return tjs_throw_wasm_error(ctx, "RangeError", "table index out of bounds");
    }

    JSValue val = argv[3];
    table_elem_type_t elem = (table_elem_type_t)(uint32_t)NULL_REF;

    if (tbl.elem_kind == WASM_FUNCREF) {
        if (!JS_IsNull(val)) {
            uint32_t func_idx;
            if (JS_ToUint32(ctx, &func_idx, val)) {
                return JS_EXCEPTION;
            }
            elem = (table_elem_type_t)func_idx;
        }
    } else if (tbl.elem_kind == WASM_EXTERNREF) {
        if (!JS_IsNull(val)) {
            uint32_t idx;
            if (!tjs__externref_box(table_owner, ctx, val, &idx)) {
                return JS_ThrowInternalError(ctx, "failed to register externref");
            }
            elem = (table_elem_type_t)idx;
        }
    }

    if (!wasm_table_set_elem((WASMModuleInstance *)table_owner->module_inst,
                             table, index, elem))
        return JS_ThrowInternalError(ctx, "failed to retain table element");

    return JS_UNDEFINED;
}

static JSValue tjs_wasm_tablegrow(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i)
        return JS_EXCEPTION;
    if (!tjs__wasm_is_bytecode_module(wasm_runtime_get_module(i->module_inst)))
        return tjs__wasm_require_bytecode(ctx, "tableGrow()");

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name)
        return JS_EXCEPTION;

    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[2])) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }

    WASMModuleInstance *module_inst = (WASMModuleInstance *) i->module_inst;
    WASMModule *wasm_module = module_inst->module;
    uint32_t table_idx = UINT32_MAX;

    for (uint32_t j = 0; j < wasm_module->export_count; j++) {
        if (wasm_module->exports[j].kind == EXPORT_KIND_TABLE &&
            strcmp(wasm_module->exports[j].name, name) == 0) {
            table_idx = wasm_module->exports[j].index;
            break;
        }
    }

    JS_FreeCString(ctx, name);

    if (table_idx == UINT32_MAX)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "table not found");

    WASMTableInstance *tbl_inst = wasm_get_table_inst(module_inst, table_idx);
    uint32_t old_size = tbl_inst->cur_size;

    if (!wasm_enlarge_table(module_inst, table_idx, delta, (table_elem_type_t) NULL_REF))
        return JS_NewInt32(ctx, -1);

    return JS_NewUint32(ctx, old_size);
}

/* Get WAMR function index by export name */
static JSValue tjs_wasm_getfuncindex(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }
    if (!tjs__wasm_is_bytecode_module(wasm_runtime_get_module(i->module_inst)))
        return tjs__wasm_require_bytecode(ctx, "functionIndex()");

    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        return JS_EXCEPTION;
    }

    WASMModuleInstance *module_inst = (WASMModuleInstance *) i->module_inst;
    int32_t export_count = wasm_runtime_get_export_count((wasm_module_t) module_inst->module);

    for (int32_t j = 0; j < export_count; j++) {
        wasm_export_t exp;
        wasm_runtime_get_export_type((wasm_module_t) module_inst->module, j, &exp);
        if (exp.kind == WASM_IMPORT_EXPORT_KIND_FUNC && strcmp(exp.name, name) == 0) {
            WASMExport *exports = module_inst->module->exports;
            JS_FreeCString(ctx, name);
            return JS_NewUint32(ctx, exports[j].index);
        }
    }

    JS_FreeCString(ctx, name);
    return JS_NewInt32(ctx, -1);
}

/* Call a WASM function by index (for funcref table entries) */
static JSValue tjs_wasm_callfuncbyindex(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, argv[0]);
    if (!i) {
        return JS_EXCEPTION;
    }
    if (!tjs__wasm_is_bytecode_module(wasm_runtime_get_module(i->module_inst)))
        return tjs__wasm_require_bytecode(ctx, "callByIndex()");

    uint32_t func_idx;
    if (JS_ToUint32(ctx, &func_idx, argv[1])) {
        return JS_EXCEPTION;
    }
    WASMModuleInstance *module_inst = (WASMModuleInstance *) i->module_inst;
    uint32_t total_funcs = module_inst->module->import_function_count + module_inst->module->function_count;

    if (func_idx >= total_funcs) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", "function index out of bounds");
    }

    wasm_function_inst_t func = (wasm_function_inst_t) &module_inst->e->functions[func_idx];

    return tjs__call_wasm_func_inst(ctx, i, func, argc - 2, argv + 2);
}

static JSValue tjs_wasm_validate(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1)
        return JS_FALSE;
    size_t buf_len;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &buf_len, argv[0]);
    if (!buf) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        return JS_FALSE;
    }

    if (buf_len == 0) {
        return JS_FALSE;
    }
    if (buf_len > UINT32_MAX)
        return JS_FALSE;

    char error_buf[TJS__WASM_ERROR_BUF_SIZE];

    /* Make a copy using WAMR's allocator since wasm_runtime_load takes ownership on success */
    uint8_t *copy = wasm_runtime_malloc(buf_len);
    if (!copy) {
        return JS_FALSE;
    }
    memcpy(copy, buf, buf_len);

    wasm_module_t module = wasm_runtime_load(copy, (uint32_t) buf_len, error_buf, sizeof(error_buf));
    if (module) {
        wasm_runtime_unload(module);
        return JS_TRUE;
    }

    wasm_runtime_free(copy);
    return JS_FALSE;
}

static JSValue tjs_wasm_runtimeinfo(JSContext *ctx, JSValue this_val, int argc,
                                    JSValue *argv) {
    (void)this_val;
    (void)argc;
    (void)argv;
    uint32_t major, minor, patch;
    wasm_runtime_get_version(&major, &minor, &patch);
    JSValue info = JS_NewObjectProto(ctx, JS_NULL);
    JSValue modes = JS_NewArray(ctx);
    if (JS_IsException(info) || JS_IsException(modes)) {
        JS_FreeValue(ctx, info);
        JS_FreeValue(ctx, modes);
        return JS_EXCEPTION;
    }
    RunningMode candidates[] = { Mode_Interp, Mode_Fast_JIT, Mode_LLVM_JIT,
                                 Mode_Multi_Tier_JIT };
    uint32_t mode_count = 0;
    for (uint32_t index = 0; index < countof(candidates); index++) {
        if (wasm_runtime_is_running_mode_supported(candidates[index]))
            JS_SetPropertyUint32(
                ctx, modes, mode_count++,
                JS_NewString(ctx, tjs__wasm_running_mode_name(candidates[index])));
    }
    if (JS_DefinePropertyValueStr(ctx, info, "major", JS_NewUint32(ctx, major),
                                  JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(ctx, info, "minor",
                                     JS_NewUint32(ctx, minor), JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(ctx, info, "patch",
                                     JS_NewUint32(ctx, patch), JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(ctx, info, "runningModes", modes,
                                     JS_PROP_C_W_E) < 0) {
        JS_FreeValue(ctx, info);
        return JS_EXCEPTION;
    }
    return info;
}

static JSValue tjs_wasm_module_info_method(JSContext *ctx, JSValue this_val,
                                           int argc, JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmModule *m = tjs_wasm_module_get(ctx, this_val);
    if (!m)
        return JS_EXCEPTION;
    package_type_t package_type = wasm_runtime_get_module_package_type(m->module);
    const char *package_name = package_type == Wasm_Module_Bytecode
        ? "bytecode"
        : package_type == Wasm_Module_AoT ? "aot" : "unknown";
    const char *module_name = wasm_runtime_get_module_name(m->module);
    /* WAMR documents an empty string for an unnamed module, but its bytecode
     * backend can return NULL. Never pass that through to JS_NewString(). */
    if (!module_name)
        module_name = "";
    JSValue info = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(info))
        return info;
    if (JS_DefinePropertyValueStr(ctx, info, "packageType",
                                  JS_NewString(ctx, package_name),
                                  JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "packageVersion",
               JS_NewUint32(ctx,
                            wasm_runtime_get_module_package_version(m->module)),
               JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "name",
               JS_NewString(ctx, module_name),
               JS_PROP_C_W_E) < 0) {
        JS_FreeValue(ctx, info);
        return JS_EXCEPTION;
    }
    return info;
}

static JSValue tjs_wasm_module_setname_method(JSContext *ctx, JSValue this_val,
                                              int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, this_val);
    if (!m)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "setName() requires a name");
    const char *name = JS_ToCString(ctx, argv[0]);
    if (!name)
        return JS_EXCEPTION;
    char error_buf[TJS__WASM_ERROR_BUF_SIZE];
    bool ok = wasm_runtime_set_module_name(m->module, name, error_buf,
                                           sizeof(error_buf));
    JS_FreeCString(ctx, name);
    if (!ok)
        return tjs_throw_wasm_error(ctx, "LinkError", error_buf);
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_instance_memoryinfo_method(JSContext *ctx,
                                                   JSValue this_val, int argc,
                                                   JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    wasm_memory_inst_t memory = wasm_runtime_get_default_memory(i->module_inst);
    if (!memory)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "no memory instance");
    JSValue info = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(info))
        return info;
    if (JS_DefinePropertyValueStr(
            ctx, info, "currentPages",
            JS_NewUint64(ctx, wasm_memory_get_cur_page_count(memory)),
            JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "maximumPages",
               JS_NewUint64(ctx, wasm_memory_get_max_page_count(memory)),
               JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "bytesPerPage",
               JS_NewUint64(ctx, wasm_memory_get_bytes_per_page(memory)),
               JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "shared",
               JS_NewBool(ctx, wasm_memory_get_shared(memory)), JS_PROP_C_W_E)
               < 0) {
        JS_FreeValue(ctx, info);
        return JS_EXCEPTION;
    }
    return info;
}

static JSValue tjs__wasm_memory_info(JSContext *ctx,
                                     wasm_memory_inst_t memory) {
    if (!memory)
        return tjs_throw_wasm_error(ctx, "RuntimeError", "memory not found");
    JSValue info = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(info))
        return info;
    if (JS_DefinePropertyValueStr(
            ctx, info, "currentPages",
            JS_NewUint64(ctx, wasm_memory_get_cur_page_count(memory)),
            JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "maximumPages",
               JS_NewUint64(ctx, wasm_memory_get_max_page_count(memory)),
               JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "bytesPerPage",
               JS_NewUint64(ctx, wasm_memory_get_bytes_per_page(memory)),
               JS_PROP_C_W_E) < 0
        || JS_DefinePropertyValueStr(
               ctx, info, "shared",
               JS_NewBool(ctx, wasm_memory_get_shared(memory)), JS_PROP_C_W_E)
               < 0) {
        JS_FreeValue(ctx, info);
        return JS_EXCEPTION;
    }
    return info;
}

static JSValue tjs_wasm_instance_memoryinfoat_method(JSContext *ctx,
                                                     JSValue this_val,
                                                     int argc,
                                                     JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    uint32_t index;
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1 || JS_ToUint32(ctx, &index, argv[0]))
        return JS_ThrowTypeError(ctx, "memoryInfoAt() requires an index");
    return tjs__wasm_memory_info(
        ctx, wasm_runtime_get_memory(i->module_inst, index));
}

static JSValue tjs_wasm_instance_memoryview_method(JSContext *ctx,
                                                   JSValue this_val, int argc,
                                                   JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 2)
        return JS_ThrowTypeError(ctx, "memoryView() requires offset and length");
    uint64_t offset, length;
    if (JS_ToIndex(ctx, &offset, argv[0]) || JS_ToIndex(ctx, &length, argv[1]))
        return JS_EXCEPTION;
    if (!wasm_runtime_validate_app_addr(i->module_inst, offset, length)) {
        wasm_runtime_clear_exception(i->module_inst);
        return JS_ThrowRangeError(ctx, "WASM memory range is out of bounds");
    }
    JSValue raw_args[] = { this_val };
    JSValue buffer = tjs_wasm_getmemorybuffer(ctx, JS_UNDEFINED, 1, raw_args);
    if (JS_IsException(buffer))
        return buffer;
    JSValue typed_args[] = { buffer, JS_NewUint64(ctx, offset),
                             JS_NewUint64(ctx, length) };
    JSValue view = JS_NewTypedArray(ctx, 3, typed_args, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(ctx, typed_args[1]);
    JS_FreeValue(ctx, typed_args[2]);
    JS_FreeValue(ctx, buffer);
    if (JS_IsException(view))
        return view;
    if (JS_DefinePropertyValueStr(ctx, view, "_wasmOwner",
                                  JS_DupValue(ctx, this_val), 0) < 0) {
        JS_FreeValue(ctx, view);
        return JS_EXCEPTION;
    }
    return view;
}

static JSValue tjs_wasm_instance_malloc_method(JSContext *ctx,
                                               JSValue this_val, int argc,
                                               JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "malloc() requires a size");
    uint64_t size;
    if (JS_ToIndex(ctx, &size, argv[0]))
        return JS_EXCEPTION;
    wasm_memory_inst_t before = wasm_runtime_get_default_memory(i->module_inst);
    void *before_base = before ? wasm_memory_get_base_address(before) : NULL;
    size_t before_length = before ? tjs__wasm_mem_byte_length(before) : 0;
    uint64_t offset = wasm_runtime_module_malloc(i->module_inst, size, NULL);
    wasm_memory_inst_t after = wasm_runtime_get_default_memory(i->module_inst);
    if (after != before
        || (after && (wasm_memory_get_base_address(after) != before_base
                      || tjs__wasm_mem_byte_length(after) != before_length)))
        tjs__wasm_invalidate_memory(i, before ? before : after);
    if (!offset)
        return JS_ThrowOutOfMemory(ctx);
    return JS_NewUint64(ctx, offset);
}

static JSValue tjs_wasm_instance_free_method(JSContext *ctx,
                                             JSValue this_val, int argc,
                                             JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "free() requires an app offset");
    uint64_t offset;
    if (JS_ToIndex(ctx, &offset, argv[0]))
        return JS_EXCEPTION;
    wasm_runtime_module_free(i->module_inst, offset);
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_instance_dupdata_method(JSContext *ctx,
                                                JSValue this_val, int argc,
                                                JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "dupData() requires a buffer");
    size_t size;
    uint8_t *data = JS_GetAnyBuffer(ctx, &size, argv[0]);
    if (!data && JS_HasException(ctx))
        return JS_EXCEPTION;
    if (!data)
        return JS_ThrowTypeError(ctx, "dupData() requires an ArrayBuffer or view");
    wasm_memory_inst_t before = wasm_runtime_get_default_memory(i->module_inst);
    void *before_base = before ? wasm_memory_get_base_address(before) : NULL;
    size_t before_length = before ? tjs__wasm_mem_byte_length(before) : 0;
    uint64_t offset = wasm_runtime_module_dup_data(i->module_inst,
                                                   (const char *)data, size);
    wasm_memory_inst_t after = wasm_runtime_get_default_memory(i->module_inst);
    if (after != before
        || (after && (wasm_memory_get_base_address(after) != before_base
                      || tjs__wasm_mem_byte_length(after) != before_length)))
        tjs__wasm_invalidate_memory(i, before ? before : after);
    if (!offset)
        return JS_ThrowOutOfMemory(ctx);
    return JS_NewUint64(ctx, offset);
}

static JSValue tjs_wasm_instance_validateaddress_method(JSContext *ctx,
                                                        JSValue this_val,
                                                        int argc,
                                                        JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "validateAddress() requires an app offset");
    uint64_t offset, size = 1;
    if (JS_ToIndex(ctx, &offset, argv[0])
        || (argc > 1 && JS_ToIndex(ctx, &size, argv[1])))
        return JS_EXCEPTION;
    bool valid = wasm_runtime_validate_app_addr(i->module_inst, offset, size);
    if (!valid)
        wasm_runtime_clear_exception(i->module_inst);
    return JS_NewBool(ctx, valid);
}

static JSValue tjs_wasm_instance_addressrange_method(JSContext *ctx,
                                                     JSValue this_val,
                                                     int argc,
                                                     JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "addressRange() requires an app offset");
    uint64_t offset, start, end;
    if (JS_ToIndex(ctx, &offset, argv[0]))
        return JS_EXCEPTION;
    if (!wasm_runtime_get_app_addr_range(i->module_inst, offset, &start, &end))
        return JS_NULL;
    JSValue range = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(range))
        return range;
    JS_DefinePropertyValueStr(ctx, range, "start", JS_NewUint64(ctx, start),
                              JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, range, "end", JS_NewUint64(ctx, end),
                              JS_PROP_C_W_E);
    return range;
}

static JSValue tjs_wasm_instance_runningmode_method(JSContext *ctx,
                                                    JSValue this_val, int argc,
                                                    JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    return JS_NewString(ctx, tjs__wasm_running_mode_name(
                                 wasm_runtime_get_running_mode(i->module_inst)));
}

static JSValue tjs_wasm_instance_setrunningmode_method(JSContext *ctx,
                                                       JSValue this_val,
                                                       int argc,
                                                       JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "setRunningMode() requires a mode");
    RunningMode mode;
    if (tjs__wasm_running_mode_from_js(ctx, argv[0], &mode))
        return JS_EXCEPTION;
    if (!wasm_runtime_set_running_mode(i->module_inst, mode))
        return JS_ThrowRangeError(ctx, "WAMR running mode is not supported by this build");
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_instance_boundschecks_method(JSContext *ctx,
                                                     JSValue this_val,
                                                     int argc, JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
    return JS_NewBool(ctx, wasm_runtime_is_bounds_checks_enabled(i->module_inst));
#else
    return JS_TRUE;
#endif
}

static JSValue tjs_wasm_instance_setboundschecks_method(JSContext *ctx,
                                                        JSValue this_val,
                                                        int argc,
                                                        JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "setBoundsChecks() requires a boolean");
    int enabled = JS_ToBool(ctx, argv[0]);
    if (enabled < 0)
        return JS_EXCEPTION;
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
    wasm_runtime_set_bounds_checks(i->module_inst, enabled);
#else
    if (!enabled)
        return JS_ThrowRangeError(
            ctx, "configurable WAMR bounds checks are not enabled in this build");
#endif
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_instance_iswasimode_method(JSContext *ctx,
                                                   JSValue this_val, int argc,
                                                   JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    return i ? JS_NewBool(ctx, wasm_runtime_is_wasi_mode(i->module_inst))
             : JS_EXCEPTION;
}

static JSValue tjs_wasm_instance_wasiexitcode_method(JSContext *ctx,
                                                     JSValue this_val,
                                                     int argc, JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    return i ? JS_NewUint32(ctx, wasm_runtime_get_wasi_exit_code(i->module_inst))
             : JS_EXCEPTION;
}

static JSValue tjs_wasm_instance_exception_method(JSContext *ctx,
                                                  JSValue this_val, int argc,
                                                  JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    const char *exception = wasm_runtime_get_exception(i->module_inst);
    return exception ? JS_NewString(ctx, exception) : JS_NULL;
}

static JSValue tjs_wasm_instance_setexception_method(JSContext *ctx,
                                                     JSValue this_val,
                                                     int argc,
                                                     JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    if (argc < 1 || JS_IsNull(argv[0]) || JS_IsUndefined(argv[0])) {
        wasm_runtime_clear_exception(i->module_inst);
        return JS_UNDEFINED;
    }
    const char *message = JS_ToCString(ctx, argv[0]);
    if (!message)
        return JS_EXCEPTION;
    wasm_runtime_set_exception(i->module_inst, message);
    JS_FreeCString(ctx, message);
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_instance_clearexception_method(JSContext *ctx,
                                                       JSValue this_val,
                                                       int argc,
                                                       JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    wasm_runtime_clear_exception(i->module_inst);
    return JS_UNDEFINED;
}

static JSValue tjs_wasm_instance_terminate_method(JSContext *ctx,
                                                  JSValue this_val, int argc,
                                                  JSValue *argv) {
    (void)argc;
    (void)argv;
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i)
        return JS_EXCEPTION;
    wasm_runtime_terminate(i->module_inst);
    return JS_UNDEFINED;
}

typedef JSValue (*TJSWasmRawBinding)(JSContext *, JSValue, int, JSValue *);

static JSValue tjs__wasm_method0(JSContext *ctx, JSValue this_val, TJSWasmRawBinding binding) {
    JSValue args[] = { this_val };
    return binding(ctx, JS_UNDEFINED, 1, args);
}

static JSValue tjs__wasm_method1(JSContext *ctx, JSValue this_val, int argc, JSValue *argv,
                                 const char *name, TJSWasmRawBinding binding) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "%s() requires 1 argument", name);
    JSValue args[] = { this_val, argv[0] };
    return binding(ctx, JS_UNDEFINED, 2, args);
}

static JSValue tjs__wasm_method2(JSContext *ctx, JSValue this_val, int argc, JSValue *argv,
                                 const char *name, TJSWasmRawBinding binding) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "%s() requires 2 arguments", name);
    JSValue args[] = { this_val, argv[0], argv[1] };
    return binding(ctx, JS_UNDEFINED, 3, args);
}

static JSValue tjs__wasm_method3(JSContext *ctx, JSValue this_val, int argc, JSValue *argv,
                                 const char *name, TJSWasmRawBinding binding) {
    if (argc < 3) return JS_ThrowTypeError(ctx, "%s() requires 3 arguments", name);
    JSValue args[] = { this_val, argv[0], argv[1], argv[2] };
    return binding(ctx, JS_UNDEFINED, 4, args);
}

static JSValue tjs_wasm_module_exports_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method0(ctx, this_val, tjs_wasm_moduleexports);
}

static JSValue tjs_wasm_module_imports_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method0(ctx, this_val, tjs_wasm_moduleimports);
}

static JSValue tjs_wasm_module_customsections_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "customSections", tjs_wasm_modulecustomsections);
}

static JSValue tjs_wasm_module_resolvefunctions_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "resolveFunctions", tjs_wasm_resolveimports);
}

static JSValue tjs_wasm_module_resolveglobals_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "resolveGlobals", tjs_wasm_resolveglobalimports);
}

static JSValue tjs_wasm_module_resolvetables_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "resolveTables", tjs_wasm_resolvetableimports);
}

static JSValue tjs_wasm_module_resolvememories_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "resolveMemories", tjs_wasm_resolvememoryimports);
}

static JSValue tjs_wasm_module_configurewasi_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    JSValue options = argc > 0 ? argv[0] : JS_UNDEFINED;
    if (!JS_IsUndefined(options) && (!JS_IsObject(options) || JS_IsNull(options))) {
        return JS_ThrowTypeError(ctx, "configureWasi options must be an object");
    }

    JSValue args = JS_NULL, env = JS_NULL, preopens = JS_NULL;
    if (!JS_IsUndefined(options)) {
        args = JS_GetPropertyStr(ctx, options, "args");
        if (JS_IsException(args)) goto fail;
        env = JS_GetPropertyStr(ctx, options, "env");
        if (JS_IsException(env)) goto fail;
        preopens = JS_GetPropertyStr(ctx, options, "preopens");
        if (JS_IsException(preopens)) goto fail;
    }

    JSValue call_args[] = { this_val, args, env, preopens };
    JSValue result = tjs_wasm_setwasioptions(ctx, JS_UNDEFINED, 4, call_args);
    JS_FreeValue(ctx, args);
    JS_FreeValue(ctx, env);
    JS_FreeValue(ctx, preopens);
    return result;

fail:
    JS_FreeValue(ctx, args);
    JS_FreeValue(ctx, env);
    JS_FreeValue(ctx, preopens);
    return JS_EXCEPTION;
}

static JSValue tjs_wasm_instance_memorybuffer_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method0(ctx, this_val, tjs_wasm_getmemorybuffer);
}

static JSValue tjs_wasm_instance_memorybufferat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "memoryBufferAt", tjs_wasm_getmemorybufferat);
}

static JSValue tjs_wasm_instance_growmemory_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "growMemory", tjs_wasm_growmemory);
}

static JSValue tjs_wasm_instance_growmemoryat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "growMemoryAt", tjs_wasm_growmemoryat);
}

static JSValue tjs_wasm_instance_importedextern_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "importedExtern", tjs_wasm_importedextern);
}

static JSValue tjs_wasm_instance_getglobalat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "getGlobalAt", tjs_wasm_getglobalat);
}

static JSValue tjs_wasm_instance_setglobalat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "setGlobalAt", tjs_wasm_setglobalat);
}

static JSValue tjs_wasm_instance_globalinfoat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "globalInfoAt", tjs_wasm_getglobalinfoat);
}

static JSValue tjs_wasm_instance_tableinfoat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "tableInfoAt", tjs_wasm_gettableinfoat);
}

static JSValue tjs_wasm_instance_tablesizeat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "tableSizeAt", tjs_wasm_tablesizeat);
}

static JSValue tjs_wasm_instance_tablegetat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "tableGetAt", tjs_wasm_tablegetat);
}

static JSValue tjs_wasm_instance_tablesetat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method3(ctx, this_val, argc, argv, "tableSetAt", tjs_wasm_tablesetat);
}

static JSValue tjs_wasm_instance_tablegrowat_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2)
        return JS_ThrowTypeError(ctx, "tableGrowAt() requires 2 arguments");
    JSValue args[] = {
        this_val,
        argv[0],
        argv[1],
        argc > 2 ? argv[2] : JS_NULL,
    };
    return tjs_wasm_tablegrowat(ctx, JS_UNDEFINED, 4, args);
}

static JSValue tjs_wasm_instance_getglobal_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "getGlobal", tjs_wasm_getglobal);
}

static JSValue tjs_wasm_instance_setglobal_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "setGlobal", tjs_wasm_setglobal);
}

static JSValue tjs_wasm_instance_globalinfo_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "globalInfo", tjs_wasm_getglobalinfo);
}

static JSValue tjs_wasm_instance_tableinfo_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "tableInfo", tjs_wasm_gettableinfo);
}

static JSValue tjs_wasm_instance_tablesize_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "tableSize", tjs_wasm_tablesize);
}

static JSValue tjs_wasm_instance_tableget_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "tableGet", tjs_wasm_tableget);
}

static JSValue tjs_wasm_instance_tableset_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method3(ctx, this_val, argc, argv, "tableSet", tjs_wasm_tableset);
}

static JSValue tjs_wasm_instance_tablegrow_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method2(ctx, this_val, argc, argv, "tableGrow", tjs_wasm_tablegrow);
}

static JSValue tjs_wasm_instance_functionindex_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return tjs__wasm_method1(ctx, this_val, argc, argv, "functionIndex", tjs_wasm_getfuncindex);
}

static JSValue tjs_wasm_instance_callbyindex_method(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "callByIndex() requires a function index");
    if (argc > TJS__WASM_MAX_ARGS + 1) return JS_ThrowRangeError(ctx, "too many WASM arguments");
    JSValue args[TJS__WASM_MAX_ARGS + 2];
    args[0] = this_val;
    for (int i = 0; i < argc; i++) args[i + 1] = argv[i];
    return tjs_wasm_callfuncbyindex(ctx, JS_UNDEFINED, argc + 1, args);
}

static const JSCFunctionListEntry tjs_wasm_funcs[] = {
    TJS_CFUNC_DEF("load", 1, tjs_wasm_parsemodule),
    TJS_CFUNC_DEF("validate", 1, tjs_wasm_validate),
    TJS_CFUNC_DEF("runtimeInfo", 0, tjs_wasm_runtimeinfo),
};

static const JSCFunctionListEntry tjs_wasm_module_funcs[] = {
    TJS_CFUNC_DEF("info", 0, tjs_wasm_module_info_method),
    TJS_CFUNC_DEF("setName", 1, tjs_wasm_module_setname_method),
    TJS_CFUNC_DEF("exports", 0, tjs_wasm_module_exports_method),
    TJS_CFUNC_DEF("imports", 0, tjs_wasm_module_imports_method),
    TJS_CFUNC_DEF("customSections", 1, tjs_wasm_module_customsections_method),
    TJS_CFUNC_DEF("resolveFunctions", 1, tjs_wasm_module_resolvefunctions_method),
    TJS_CFUNC_DEF("resolveGlobals", 1, tjs_wasm_module_resolveglobals_method),
    TJS_CFUNC_DEF("resolveTables", 1, tjs_wasm_module_resolvetables_method),
    TJS_CFUNC_DEF("resolveMemories", 1, tjs_wasm_module_resolvememories_method),
    TJS_CFUNC_DEF("configureWasi", 1, tjs_wasm_module_configurewasi_method),
    TJS_CFUNC_DEF("instantiate", 1, tjs_wasm_buildinstance),
};

static const JSCFunctionListEntry tjs_wasm_instance_funcs[] = {
    TJS_CFUNC_DEF("call", 1, tjs_wasm_callfunction),
    TJS_CFUNC_DEF("callByIndex", 1, tjs_wasm_instance_callbyindex_method),
    TJS_CFUNC_DEF("functionIndex", 1, tjs_wasm_instance_functionindex_method),
    TJS_CFUNC_DEF("importedExtern", 2, tjs_wasm_instance_importedextern_method),
    TJS_CFUNC_DEF("memoryBuffer", 0, tjs_wasm_instance_memorybuffer_method),
    TJS_CFUNC_DEF("memoryBufferAt", 1, tjs_wasm_instance_memorybufferat_method),
    TJS_CFUNC_DEF("memoryInfo", 0, tjs_wasm_instance_memoryinfo_method),
    TJS_CFUNC_DEF("memoryInfoAt", 1, tjs_wasm_instance_memoryinfoat_method),
    TJS_CFUNC_DEF("memoryView", 2, tjs_wasm_instance_memoryview_method),
    TJS_CFUNC_DEF("growMemory", 1, tjs_wasm_instance_growmemory_method),
    TJS_CFUNC_DEF("growMemoryAt", 2, tjs_wasm_instance_growmemoryat_method),
    TJS_CFUNC_DEF("malloc", 1, tjs_wasm_instance_malloc_method),
    TJS_CFUNC_DEF("free", 1, tjs_wasm_instance_free_method),
    TJS_CFUNC_DEF("dupData", 1, tjs_wasm_instance_dupdata_method),
    TJS_CFUNC_DEF("validateAddress", 2, tjs_wasm_instance_validateaddress_method),
    TJS_CFUNC_DEF("addressRange", 1, tjs_wasm_instance_addressrange_method),
    TJS_CFUNC_DEF("getGlobal", 1, tjs_wasm_instance_getglobal_method),
    TJS_CFUNC_DEF("setGlobal", 2, tjs_wasm_instance_setglobal_method),
    TJS_CFUNC_DEF("globalInfo", 1, tjs_wasm_instance_globalinfo_method),
    TJS_CFUNC_DEF("getGlobalAt", 1, tjs_wasm_instance_getglobalat_method),
    TJS_CFUNC_DEF("setGlobalAt", 2, tjs_wasm_instance_setglobalat_method),
    TJS_CFUNC_DEF("globalInfoAt", 1, tjs_wasm_instance_globalinfoat_method),
    TJS_CFUNC_DEF("tableInfo", 1, tjs_wasm_instance_tableinfo_method),
    TJS_CFUNC_DEF("tableSize", 1, tjs_wasm_instance_tablesize_method),
    TJS_CFUNC_DEF("tableGet", 2, tjs_wasm_instance_tableget_method),
    TJS_CFUNC_DEF("tableSet", 3, tjs_wasm_instance_tableset_method),
    TJS_CFUNC_DEF("tableGrow", 2, tjs_wasm_instance_tablegrow_method),
    TJS_CFUNC_DEF("tableInfoAt", 1, tjs_wasm_instance_tableinfoat_method),
    TJS_CFUNC_DEF("tableSizeAt", 1, tjs_wasm_instance_tablesizeat_method),
    TJS_CFUNC_DEF("tableGetAt", 2, tjs_wasm_instance_tablegetat_method),
    TJS_CFUNC_DEF("tableSetAt", 3, tjs_wasm_instance_tablesetat_method),
    TJS_CFUNC_DEF("tableGrowAt", 3, tjs_wasm_instance_tablegrowat_method),
    TJS_CFUNC_DEF("runningMode", 0, tjs_wasm_instance_runningmode_method),
    TJS_CFUNC_DEF("setRunningMode", 1, tjs_wasm_instance_setrunningmode_method),
    TJS_CFUNC_DEF("boundsChecks", 0, tjs_wasm_instance_boundschecks_method),
    TJS_CFUNC_DEF("setBoundsChecks", 1, tjs_wasm_instance_setboundschecks_method),
    TJS_CFUNC_DEF("isWasiMode", 0, tjs_wasm_instance_iswasimode_method),
    TJS_CFUNC_DEF("wasiExitCode", 0, tjs_wasm_instance_wasiexitcode_method),
    TJS_CFUNC_DEF("exception", 0, tjs_wasm_instance_exception_method),
    TJS_CFUNC_DEF("setException", 1, tjs_wasm_instance_setexception_method),
    TJS_CFUNC_DEF("clearException", 0, tjs_wasm_instance_clearexception_method),
    TJS_CFUNC_DEF("terminate", 0, tjs_wasm_instance_terminate_method),
};

void tjs__mod_wasm_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    /* Module object */
    JS_NewClassID(rt, &tjs_wasm_module_class_id);
    JS_NewClass(rt, tjs_wasm_module_class_id, &tjs_wasm_module_class);
    JSValue module_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, module_proto, tjs_wasm_module_funcs, countof(tjs_wasm_module_funcs));
    JS_SetClassProto(ctx, tjs_wasm_module_class_id, module_proto);

    /* Instance object */
    JS_NewClassID(rt, &tjs_wasm_instance_class_id);
    JS_NewClass(rt, tjs_wasm_instance_class_id, &tjs_wasm_instance_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_wasm_instance_funcs, countof(tjs_wasm_instance_funcs));
    JS_SetClassProto(ctx, tjs_wasm_instance_class_id, proto);

    JS_SetPropertyFunctionList(ctx, ns, tjs_wasm_funcs, countof(tjs_wasm_funcs));
}
