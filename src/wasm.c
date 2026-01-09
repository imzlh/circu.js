/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
 * Copyright (c) 2025 iz
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

#ifdef CJS__HAS_WASM

#include "wasm.h"

#include "private.h"
#include "tjs.h"
#include "utils.h"

#define TJS__WASM_MAX_ARGS 32

static JSClassID tjs_wasm_module_class_id;
static JSClassID tjs_wasm_memory_class_id;
static JSClassID tjs_wasm_table_class_id;
static JSClassID tjs_wasm_global_class_id;

typedef struct {
    IM3Module module;
    struct {
        uint8_t *bytes;
        size_t size;
    } data;
} TJSWasmModule;

static void tjs_wasm_module_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmModule *m = JS_GetOpaque(val, tjs_wasm_module_class_id);
    if (m) {
        if (m->module) {
            m3_FreeModule(m->module);
        }
        js_free_rt(rt, m->data.bytes);
        js_free_rt(rt, m);
    }
}

static JSClassDef tjs_wasm_module_class = {
    "Module",
    .finalizer = tjs_wasm_module_finalizer,
};

typedef struct {
    IM3Runtime runtime;
    IM3Memory memory;
    uint8_t *buffer;
    size_t size;
} TJSWasmMemory;

static void tjs_wasm_memory_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmMemory *m = JS_GetOpaque(val, tjs_wasm_memory_class_id);
    if (m) {
        if (m->memory) {
            m3_FreeMemory(m->memory);
        }
        js_free_rt(rt, m->buffer);
        js_free_rt(rt, m);
    }
}

static JSClassDef tjs_wasm_memory_class = {
    "Memory",
    .finalizer = tjs_wasm_memory_finalizer,
};

typedef struct {
    IM3Runtime runtime;
    IM3Table table;
    uint32_t size;
} TJSWasmTable;

static void tjs_wasm_table_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmTable *t = JS_GetOpaque(val, tjs_wasm_table_class_id);
    if (t) {
        if (t->table) {
            m3_FreeTable(t->table);
        }
        js_free_rt(rt, t);
    }
}

static JSClassDef tjs_wasm_table_class = {
    "Table",
    .finalizer = tjs_wasm_table_finalizer,
};

typedef struct {
    IM3Runtime runtime;
    IM3Global global;
    M3ValueType type;
    bool mutable_;
} TJSWasmGlobal;

static void tjs_wasm_global_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmGlobal *g = JS_GetOpaque(val, tjs_wasm_global_class_id);
    if (g) {
        if (g->global) {
            m3_FreeGlobal(g->global);
        }
        js_free_rt(rt, g);
    }
}

static JSClassDef tjs_wasm_global_class = {
    "Global",
    .finalizer = tjs_wasm_global_finalizer,
};

static JSClassID tjs_wasm_instance_class_id;

typedef struct {
    IM3Runtime runtime;
    IM3Module module;
    bool loaded;
    JSValue memory;  // Reference to memory object if any
    JSValue table;   // Reference to table object if any
    JSValue globals; // Array of global objects if any
} TJSWasmInstance;

static void tjs_wasm_instance_finalizer(JSRuntime *rt, JSValue val) {
    TJSWasmInstance *i = JS_GetOpaque(val, tjs_wasm_instance_class_id);
    if (i) {
        if (i->module) {
            // Free the module, only if it wasn't previously loaded.
            if (!i->loaded) {
                m3_FreeModule(i->module);
            }
        }
        if (i->runtime) {
            m3_FreeRuntime(i->runtime);
        }
        JS_FreeValueRT(rt, i->memory);
        JS_FreeValueRT(rt, i->table);
        JS_FreeValueRT(rt, i->globals);
        js_free_rt(rt, i);
    }
}

static JSClassDef tjs_wasm_instance_class = {
    "Instance",
    .finalizer = tjs_wasm_instance_finalizer,
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

static JSValue tjs_new_wasm_memory(JSContext *ctx) {
    TJSWasmMemory *m;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_wasm_memory_class_id);
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

static TJSWasmMemory *tjs_wasm_memory_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_wasm_memory_class_id);
}

static JSValue tjs_new_wasm_table(JSContext *ctx) {
    TJSWasmTable *t;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_wasm_table_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    t = js_mallocz(ctx, sizeof(*t));
    if (!t) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    JS_SetOpaque(obj, t);
    return obj;
}

static TJSWasmTable *tjs_wasm_table_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_wasm_table_class_id);
}

static JSValue tjs_new_wasm_global(JSContext *ctx) {
    TJSWasmGlobal *g;
    JSValue obj;

    obj = JS_NewObjectClass(ctx, tjs_wasm_global_class_id);
    if (JS_IsException(obj)) {
        return obj;
    }

    g = js_mallocz(ctx, sizeof(*g));
    if (!g) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    JS_SetOpaque(obj, g);
    return obj;
}

static TJSWasmGlobal *tjs_wasm_global_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_wasm_global_class_id);
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

    i->memory = JS_UNDEFINED;
    i->table = JS_UNDEFINED;
    i->globals = JS_UNDEFINED;

    JS_SetOpaque(obj, i);
    return obj;
}

static TJSWasmInstance *tjs_wasm_instance_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_wasm_instance_class_id);
}

JSValue tjs_throw_wasm_error(JSContext *ctx, const char *name, M3Result r) {
    CHECK_NOT_NULL(r);
    JSValue obj = JS_NewError(ctx);
    JS_DefinePropertyValueStr(ctx, obj, "message", JS_NewString(ctx, r), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, obj, "wasmError", JS_NewString(ctx, name), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    if (JS_IsException(obj)) {
        obj = JS_NULL;
    }
    return JS_Throw(ctx, obj);
}

static JSValue tjs__wasm_result(JSContext *ctx, M3ValueType type, const void *stack) {
    switch (type) {
        case c_m3Type_i32: {
            int32_t val = *(int32_t *) stack;
            return JS_NewInt32(ctx, val);
        }
        case c_m3Type_i64: {
            int64_t val = *(int64_t *) stack;
            if (val == (int32_t) val) {
                return JS_NewInt32(ctx, (int32_t) val);
            } else {
                return JS_NewBigInt64(ctx, val);
            }
        }
        case c_m3Type_f32: {
            float val = *(float *) stack;
            return JS_NewFloat64(ctx, (double) val);
        }
        case c_m3Type_f64: {
            double val = *(double *) stack;
            return JS_NewFloat64(ctx, val);
        }
        default:
            return JS_UNDEFINED;
    }
}

static JSValue tjs_wasm_callfunction(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i) {
        return JS_EXCEPTION;
    }

    const char *fname = JS_ToCString(ctx, argv[0]);
    if (!fname) {
        return JS_EXCEPTION;
    }

    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    IM3Function func;
    M3Result r = m3_FindFunction(&func, i->runtime, fname);
    if (r) {
        JS_FreeCString(ctx, fname);
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    JS_FreeCString(ctx, fname);

    int nargs = argc - 1;
    if (nargs == 0) {
        r = m3_Call(func, 0, NULL);
    } else {
        const char *m3_argv[nargs + 1];
        for (int i = 0; i < nargs; i++) {
            m3_argv[i] = JS_ToCString(ctx, argv[i + 1]);
        }
        m3_argv[nargs] = NULL;
        r = m3_CallArgv(func, nargs, m3_argv);
        for (int i = 0; i < nargs; i++) {
            JS_FreeCString(ctx, m3_argv[i]);
        }
    }

    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    // https://webassembly.org/docs/js/ See "ToJSValue"
    // NOTE: here we support returning BigInt, because we can.

    int ret_count = m3_GetRetCount(func);

    if (ret_count > TJS__WASM_MAX_ARGS) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", "Too many return values");
    }

    uint64_t valbuff[TJS__WASM_MAX_ARGS];
    const void *valptrs[TJS__WASM_MAX_ARGS];
    memset(valbuff, 0, sizeof(valbuff));
    for (int i = 0; i < ret_count; i++) {
        valptrs[i] = &valbuff[i];
    }

    r = m3_GetResults(func, ret_count, valptrs);
    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    if (ret_count == 1) {
        return tjs__wasm_result(ctx, m3_GetRetType(func, 0), valptrs[0]);
    } else {
        JSValue rets = JS_NewArray(ctx);
        for (int i = 0; i < ret_count; i++) {
            JS_SetPropertyUint32(ctx, rets, i, tjs__wasm_result(ctx, m3_GetRetType(func, i), valptrs[i]));
        }
        return rets;
    }
}

static JSValue tjs_wasm_linkwasi(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i) {
        return JS_EXCEPTION;
    }

    M3Result r = m3_LinkWASI(i->module);
    if (r) {
        return tjs_throw_wasm_error(ctx, "LinkError", r);
    }

    return JS_UNDEFINED;
}

// Memory API functions
static JSValue tjs_wasm_memory_buffer(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmMemory *m = tjs_wasm_memory_get(ctx, this_val);
    if (!m) {
        return JS_EXCEPTION;
    }

    if (!m->buffer) {
        return JS_NULL;
    }

    return JS_NewArrayBuffer(ctx, m->buffer, m->size, NULL, NULL, false);
}

static JSValue tjs_wasm_memory_grow(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmMemory *m = tjs_wasm_memory_get(ctx, this_val);
    if (!m) {
        return JS_EXCEPTION;
    }

    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[0])) {
        return JS_EXCEPTION;
    }

    if (!m->memory) {
        return JS_ThrowTypeError(ctx, "Memory not initialized");
    }

    uint32_t old_pages = m3_GetMemorySize(m->memory);
    M3Result r = m3_GrowMemory(m->memory, delta);
    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    return JS_NewUint32(ctx, old_pages);
}

// Table API functions
static JSValue tjs_wasm_table_get(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmTable *t = tjs_wasm_table_get(ctx, this_val);
    if (!t) {
        return JS_EXCEPTION;
    }

    uint32_t index;
    if (JS_ToUint32(ctx, &index, argv[0])) {
        return JS_EXCEPTION;
    }

    if (!t->table) {
        return JS_ThrowTypeError(ctx, "Table not initialized");
    }

    if (index >= t->size) {
        return JS_ThrowRangeError(ctx, "Index out of bounds");
    }

    void *ptr;
    M3Result r = m3_GetTableElement(t->table, index, &ptr);
    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    // Convert function pointer to JS value
    return JS_NewInt64(ctx, (int64_t)ptr);
}

static JSValue tjs_wasm_table_set(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmTable *t = tjs_wasm_table_get(ctx, this_val);
    if (!t) {
        return JS_EXCEPTION;
    }

    uint32_t index;
    if (JS_ToUint32(ctx, &index, argv[0])) {
        return JS_EXCEPTION;
    }

    int64_t ptr;
    if (JS_ToInt64(ctx, &ptr, argv[1])) {
        return JS_EXCEPTION;
    }

    if (!t->table) {
        return JS_ThrowTypeError(ctx, "Table not initialized");
    }

    if (index >= t->size) {
        return JS_ThrowRangeError(ctx, "Index out of bounds");
    }

    M3Result r = m3_SetTableElement(t->table, index, (void*)ptr);
    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    return JS_UNDEFINED;
}

static JSValue tjs_wasm_table_size(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmTable *t = tjs_wasm_table_get(ctx, this_val);
    if (!t) {
        return JS_EXCEPTION;
    }

    if (!t->table) {
        return JS_ThrowTypeError(ctx, "Table not initialized");
    }

    return JS_NewUint32(ctx, t->size);
}

// Global API functions
static JSValue tjs_wasm_global_value(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmGlobal *g = tjs_wasm_global_get(ctx, this_val);
    if (!g) {
        return JS_EXCEPTION;
    }

    if (!g->global) {
        return JS_ThrowTypeError(ctx, "Global not initialized");
    }

    uint64_t value;
    M3Result r = m3_GetGlobal(g->global, &value);
    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    return tjs__wasm_result(ctx, g->type, &value);
}

static JSValue tjs_wasm_global_set_value(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmGlobal *g = tjs_wasm_global_get(ctx, this_val);
    if (!g) {
        return JS_EXCEPTION;
    }

    if (!g->mutable_) {
        return JS_ThrowTypeError(ctx, "Cannot set immutable global");
    }

    if (!g->global) {
        return JS_ThrowTypeError(ctx, "Global not initialized");
    }

    uint64_t value;
    int32_t i32;
    int64_t i64;
    double f64;

    switch (g->type) {
        case c_m3Type_i32:
            if (JS_ToInt32(ctx, &i32, argv[0])) {
                return JS_EXCEPTION;
            }
            value = (uint64_t)i32;
            break;
        case c_m3Type_i64:
            if (JS_ToInt64(ctx, &i64, argv[0])) {
                return JS_EXCEPTION;
            }
            value = (uint64_t)i64;
            break;
        case c_m3Type_f32:
        case c_m3Type_f64:
            if (JS_ToFloat64(ctx, &f64, argv[0])) {
                return JS_EXCEPTION;
            }
            value = *(uint64_t*)&f64;
            break;
        default:
            return JS_ThrowTypeError(ctx, "Unsupported global type");
    }

    M3Result r = m3_SetGlobal(g->global, value);
    if (r) {
        return tjs_throw_wasm_error(ctx, "RuntimeError", r);
    }

    return JS_UNDEFINED;
}

// Instance API functions
static JSValue tjs_wasm_instance_memory(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i) {
        return JS_EXCEPTION;
    }

    return JS_DupValue(ctx, i->memory);
}

static JSValue tjs_wasm_instance_table(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i) {
        return JS_EXCEPTION;
    }

    return JS_DupValue(ctx, i->table);
}

static JSValue tjs_wasm_instance_globals(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, this_val);
    if (!i) {
        return JS_EXCEPTION;
    }

    return JS_DupValue(ctx, i->globals);
}

static JSValue tjs_wasm_buildinstance(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSWasmModule *m = tjs_wasm_module_get(ctx, argv[0]);
    if (!m) {
        return JS_EXCEPTION;
    }

    JSValue obj = tjs_new_wasm_instance(ctx);
    if (JS_IsException(obj)) {
        return obj;
    }

    TJSWasmInstance *i = tjs_wasm_instance_get(ctx, obj);

    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    // We need to parse the module again for each instance to ensure
    // each instance has its own copy of the module data. This is necessary
    // because instances may modify module state.
    M3Result r = m3_ParseModule(qrt->wasm_ctx.env, &i->module, m->data.bytes, m->data.size);
    CHECK_NULL(r);  // Should never fail because we already parsed it. TODO: clone it?

    /* Create a runtime per module to avoid symbol clash. 
     * The stack size is set to 64KB which should be sufficient for most WASM modules.
     * This can be adjusted if needed for specific modules with deeper call stacks. */
    i->runtime = m3_NewRuntime(qrt->wasm_ctx.env, 64 * 1024, NULL);
    if (!i->runtime) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    r = m3_LoadModule(i->runtime, i->module);
    if (r) {
        JS_FreeValue(ctx, obj);
        return tjs_throw_wasm_error(ctx, "LinkError", r);
    }

    i->loaded = true;

    // Initialize memory, table, and globals if they exist
    // Note: This is a simplified implementation. A full implementation would need
    // to properly extract and initialize these from the module.
    
    // For now, we'll create empty objects that can be filled later
    i->memory = JS_NULL;
    i->table = JS_NULL;
    i->globals = JS_NewArray(ctx);

    return obj;
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

    // Add memory exports
    for (size_t i = 0, j = 0; i < m->module->numFunctions; ++i) {
        IM3Function f = &m->module->functions[i];
        const char *name = m3_GetFunctionName(f);
        if (name) {
            JSValue item = JS_NewObjectProto(ctx, JS_NULL);
            JS_DefinePropertyValueStr(ctx, item, "name", JS_NewString(ctx, name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind", JS_NewString(ctx, "function"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, exports, j, item, JS_PROP_C_W_E);
            j++;
        }
    }

    // Add memory exports
    for (u32 i = 0; i < m->module->numMemories; ++i) {
        IM3Memory mem = &m->module->memories[i];
        if (mem->name) {
            JSValue item = JS_NewObjectProto(ctx, JS_NULL);
            JS_DefinePropertyValueStr(ctx, item, "name", JS_NewString(ctx, mem->name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind", JS_NewString(ctx, "memory"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, exports, j, item, JS_PROP_C_W_E);
            j++;
        }
    }

    // Add table exports
    for (u32 i = 0; i < m->module->numTables; ++i) {
        IM3Table table = &m->module->tables[i];
        if (table->name) {
            JSValue item = JS_NewObjectProto(ctx, JS_NULL);
            JS_DefinePropertyValueStr(ctx, item, "name", JS_NewString(ctx, table->name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind", JS_NewString(ctx, "table"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, exports, j, item, JS_PROP_C_W_E);
            j++;
        }
    }

    // Add global exports
    for (u32 i = 0; i < m->module->numGlobals; ++i) {
        IM3Global global = &m->module->globals[i];
        if (global->name) {
            JSValue item = JS_NewObjectProto(ctx, JS_NULL);
            JS_DefinePropertyValueStr(ctx, item, "name", JS_NewString(ctx, global->name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind", JS_NewString(ctx, "global"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, exports, j, item, JS_PROP_C_W_E);
            j++;
        }
    }

    return exports;
}

static JSValue tjs_wasm_parsemodule(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    size_t size;
    uint8_t *buf = JS_GetArrayBuffer(ctx, &size, argv[0]);

    if (!buf) {
        /* Reset the exception. */
        JS_FreeValue(ctx, JS_GetException(ctx));

        /* Check if it's a typed array. */
        size_t aoffset, asize;
        JSValue abuf = JS_GetTypedArrayBuffer(ctx, argv[0], &aoffset, &asize, NULL);
        if (JS_IsException(abuf)) {
            return abuf;
        }
        buf = JS_GetArrayBuffer(ctx, &size, abuf);
        JS_FreeValue(ctx, abuf);
        if (!buf) {
            // It's possible the buffer is NULL and there is no exception, in case of
            // an array buffer of size 0.
            JS_FreeValue(ctx, JS_GetException(ctx));
            JS_ThrowTypeError(ctx, "invalid buffer");
            return JS_EXCEPTION;
        }
        buf += aoffset;
        size = asize;
    }

    JSValue obj = tjs_new_wasm_module(ctx);
    TJSWasmModule *m = tjs_wasm_module_get(ctx, obj);
    m->data.bytes = js_malloc(ctx, size);
    if (!m->data.bytes) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    memcpy(m->data.bytes, buf, size);
    m->data.size = size;

    M3Result r = m3_ParseModule(qrt->wasm_ctx.env, &m->module, m->data.bytes, m->data.size);
    if (r) {
        JS_FreeValue(ctx, obj);
        return tjs_throw_wasm_error(ctx, "CompileError", r);
    }

    return obj;
}

// Memory constructor
static JSValue tjs_wasm_creatememory(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    // Parse descriptor object { initial: number, maximum?: number }
    uint32_t initial = 0;
    uint32_t maximum = 0;
    bool has_maximum = false;

    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue initial_val = JS_GetPropertyStr(ctx, argv[0], "initial");
        if (!JS_IsException(initial_val) && !JS_IsUndefined(initial_val)) {
            if (JS_ToUint32(ctx, &initial, initial_val)) {
                JS_FreeValue(ctx, initial_val);
                return JS_EXCEPTION;
            }
        }
        JS_FreeValue(ctx, initial_val);

        JSValue maximum_val = JS_GetPropertyStr(ctx, argv[0], "maximum");
        if (!JS_IsException(maximum_val) && !JS_IsUndefined(maximum_val)) {
            if (JS_ToUint32(ctx, &maximum, maximum_val)) {
                JS_FreeValue(ctx, maximum_val);
                return JS_EXCEPTION;
            }
            has_maximum = true;
        }
        JS_FreeValue(ctx, maximum_val);
    }

    JSValue obj = tjs_new_wasm_memory(ctx);
    TJSWasmMemory *m = tjs_wasm_memory_get(ctx, obj);

    m->runtime = m3_NewRuntime(qrt->wasm_ctx.env, initial * 65536, NULL);
    if (!m->runtime) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    m->memory = m3_NewMemory(m->runtime, initial, has_maximum ? maximum : 0);
    if (!m->memory) {
        m3_FreeRuntime(m->runtime);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    m->size = initial * 65536;
    m->buffer = js_malloc(ctx, m->size);
    if (!m->buffer) {
        m3_FreeMemory(m->memory);
        m3_FreeRuntime(m->runtime);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    return obj;
}

// Table constructor
static JSValue tjs_wasm_createtable(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    // Parse descriptor object { element: string, initial: number, maximum?: number }
    const char *element = "anyfunc";
    uint32_t initial = 0;
    uint32_t maximum = 0;
    bool has_maximum = false;

    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue element_val = JS_GetPropertyStr(ctx, argv[0], "element");
        if (!JS_IsException(element_val) && !JS_IsUndefined(element_val)) {
            element = JS_ToCString(ctx, element_val);
            if (!element) {
                JS_FreeValue(ctx, element_val);
                return JS_EXCEPTION;
            }
        }
        JS_FreeValue(ctx, element_val);

        JSValue initial_val = JS_GetPropertyStr(ctx, argv[0], "initial");
        if (!JS_IsException(initial_val) && !JS_IsUndefined(initial_val)) {
            if (JS_ToUint32(ctx, &initial, initial_val)) {
                JS_FreeCString(ctx, element);
                JS_FreeValue(ctx, initial_val);
                return JS_EXCEPTION;
            }
        }
        JS_FreeValue(ctx, initial_val);

        JSValue maximum_val = JS_GetPropertyStr(ctx, argv[0], "maximum");
        if (!JS_IsException(maximum_val) && !JS_IsUndefined(maximum_val)) {
            if (JS_ToUint32(ctx, &maximum, maximum_val)) {
                JS_FreeCString(ctx, element);
                JS_FreeValue(ctx, maximum_val);
                return JS_EXCEPTION;
            }
            has_maximum = true;
        }
        JS_FreeValue(ctx, maximum_val);
    }

    JSValue obj = tjs_new_wasm_table(ctx);
    TJSWasmTable *t = tjs_wasm_table_get(ctx, obj);

    t->runtime = m3_NewRuntime(qrt->wasm_ctx.env, 1024, NULL);
    if (!t->runtime) {
        JS_FreeCString(ctx, element);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    t->table = m3_NewTable(t->runtime, initial, has_maximum ? maximum : 0);
    if (!t->table) {
        m3_FreeRuntime(t->runtime);
        JS_FreeCString(ctx, element);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    t->size = initial;
    JS_FreeCString(ctx, element);

    return obj;
}

// Global constructor
static JSValue tjs_wasm_createglobal(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);

    // Parse descriptor object { value: string, mutable?: boolean }
    const char *value_type = "i32";
    bool mutable_ = false;

    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue value_val = JS_GetPropertyStr(ctx, argv[0], "value");
        if (!JS_IsException(value_val) && !JS_IsUndefined(value_val)) {
            value_type = JS_ToCString(ctx, value_val);
            if (!value_type) {
                JS_FreeValue(ctx, value_val);
                return JS_EXCEPTION;
            }
        }
        JS_FreeValue(ctx, value_val);

        JSValue mutable_val = JS_GetPropertyStr(ctx, argv[0], "mutable");
        if (!JS_IsException(mutable_val) && !JS_IsUndefined(mutable_val)) {
            mutable_ = JS_ToBool(ctx, mutable_val);
        }
        JS_FreeValue(ctx, mutable_val);
    }

    JSValue obj = tjs_new_wasm_global(ctx);
    TJSWasmGlobal *g = tjs_wasm_global_get(ctx, obj);

    g->runtime = m3_NewRuntime(qrt->wasm_ctx.env, 1024, NULL);
    if (!g->runtime) {
        JS_FreeCString(ctx, value_type);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    // Convert string type to M3ValueType
    if (strcmp(value_type, "i32") == 0) {
        g->type = c_m3Type_i32;
    } else if (strcmp(value_type, "i64") == 0) {
        g->type = c_m3Type_i64;
    } else if (strcmp(value_type, "f32") == 0) {
        g->type = c_m3Type_f32;
    } else if (strcmp(value_type, "f64") == 0) {
        g->type = c_m3Type_f64;
    } else {
        m3_FreeRuntime(g->runtime);
        JS_FreeCString(ctx, value_type);
        JS_FreeValue(ctx, obj);
        return JS_ThrowTypeError(ctx, "Invalid global value type");
    }

    g->mutable_ = mutable_;
    g->global = m3_NewGlobal(g->runtime, g->type, mutable_, 0);
    if (!g->global) {
        m3_FreeRuntime(g->runtime);
        JS_FreeCString(ctx, value_type);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    JS_FreeCString(ctx, value_type);

    // Set initial value if provided
    if (argc > 1) {
        uint64_t value;
        int32_t i32;
        int64_t i64;
        double f64;

        switch (g->type) {
            case c_m3Type_i32:
                if (JS_ToInt32(ctx, &i32, argv[1])) {
                    JS_FreeValue(ctx, obj);
                    return JS_EXCEPTION;
                }
                value = (uint64_t)i32;
                break;
            case c_m3Type_i64:
                if (JS_ToInt64(ctx, &i64, argv[1])) {
                    JS_FreeValue(ctx, obj);
                    return JS_EXCEPTION;
                }
                value = (uint64_t)i64;
                break;
            case c_m3Type_f32:
            case c_m3Type_f64:
                if (JS_ToFloat64(ctx, &f64, argv[1])) {
                    JS_FreeValue(ctx, obj);
                    return JS_EXCEPTION;
                }
                value = *(uint64_t*)&f64;
                break;
            default:
                JS_FreeValue(ctx, obj);
                return JS_ThrowTypeError(ctx, "Unsupported global type");
        }

        M3Result r = m3_SetGlobal(g->global, value);
        if (r) {
            JS_FreeValue(ctx, obj);
            return tjs_throw_wasm_error(ctx, "RuntimeError", r);
        }
    }

    return obj;
}

static const JSCFunctionListEntry tjs_wasm_funcs[] = {
    TJS_CFUNC_DEF("buildInstance", 1, tjs_wasm_buildinstance),
    TJS_CFUNC_DEF("moduleExports", 1, tjs_wasm_moduleexports),
    TJS_CFUNC_DEF("parseModule", 1, tjs_wasm_parsemodule),
    TJS_CFUNC_DEF("createMemory", 1, tjs_wasm_creatememory),
    TJS_CFUNC_DEF("createTable", 1, tjs_wasm_createtable),
    TJS_CFUNC_DEF("createGlobal", 2, tjs_wasm_createglobal),
};

static const JSCFunctionListEntry tjs_wasm_instance_funcs[] = {
    TJS_CFUNC_DEF("callFunction", 1, tjs_wasm_callfunction),
    TJS_CFUNC_DEF("linkWasi", 0, tjs_wasm_linkwasi),
    TJS_CFUNC_DEF("memory", 0, tjs_wasm_instance_memory),
    TJS_CFUNC_DEF("table", 0, tjs_wasm_instance_table),
    TJS_CFUNC_DEF("globals", 0, tjs_wasm_instance_globals),
};

static const JSCFunctionListEntry tjs_wasm_memory_funcs[] = {
    TJS_CFUNC_DEF("buffer", 0, tjs_wasm_memory_buffer),
    TJS_CFUNC_DEF("grow", 1, tjs_wasm_memory_grow),
};

static const JSCFunctionListEntry tjs_wasm_table_funcs[] = {
    TJS_CFUNC_DEF("get", 1, tjs_wasm_table_get),
    TJS_CFUNC_DEF("set", 2, tjs_wasm_table_set),
    TJS_CFUNC_DEF("size", 0, tjs_wasm_table_size),
};

static const JSCFunctionListEntry tjs_wasm_global_funcs[] = {
    TJS_CFUNC_DEF("value", 0, tjs_wasm_global_value),
    TJS_CFUNC_DEF("setValue", 1, tjs_wasm_global_set_value),
};

void tjs__mod_wasm_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    /* Module object */
    JS_NewClassID(rt, &tjs_wasm_module_class_id);
    JS_NewClass(rt, tjs_wasm_module_class_id, &tjs_wasm_module_class);
    JS_SetClassProto(ctx, tjs_wasm_module_class_id, JS_NULL);

    /* Memory object */
    JS_NewClassID(rt, &tjs_wasm_memory_class_id);
    JS_NewClass(rt, tjs_wasm_memory_class_id, &tjs_wasm_memory_class);
    JSValue memory_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, memory_proto, tjs_wasm_memory_funcs, countof(tjs_wasm_memory_funcs));
    JS_SetClassProto(ctx, tjs_wasm_memory_class_id, memory_proto);

    /* Table object */
    JS_NewClassID(rt, &tjs_wasm_table_class_id);
    JS_NewClass(rt, tjs_wasm_table_class_id, &tjs_wasm_table_class);
    JSValue table_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, table_proto, tjs_wasm_table_funcs, countof(tjs_wasm_table_funcs));
    JS_SetClassProto(ctx, tjs_wasm_table_class_id, table_proto);

    /* Global object */
    JS_NewClassID(rt, &tjs_wasm_global_class_id);
    JS_NewClass(rt, tjs_wasm_global_class_id, &tjs_wasm_global_class);
    JSValue global_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, global_proto, tjs_wasm_global_funcs, countof(tjs_wasm_global_funcs));
    JS_SetClassProto(ctx, tjs_wasm_global_class_id, global_proto);

    /* Instance object */
    JS_NewClassID(rt, &tjs_wasm_instance_class_id);
    JS_NewClass(rt, tjs_wasm_instance_class_id, &tjs_wasm_instance_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_wasm_instance_funcs, countof(tjs_wasm_instance_funcs));
    JS_SetClassProto(ctx, tjs_wasm_instance_class_id, proto);

    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    JS_SetPropertyFunctionList(ctx, obj, tjs_wasm_funcs, countof(tjs_wasm_funcs));

    JS_DefinePropertyValueStr(ctx, ns, "wasm", obj, JS_PROP_C_W_E);
}

#endif