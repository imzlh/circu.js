/*
 * txiki.js - WebAssembly module implementation using wasm3
 * 
 * Exports directly to namespace:
 *   - WasmModule, WasmInstance, WasmMemory, WasmTable, WasmGlobal
 *   - wasmCompile, wasmInstantiate, wasmValidate
 */

#include "private.h"

#ifdef CJS__HAS_WASM

#include <string.h>
#include "wasm3.h"
#include "m3_env.h"

/* ============================================================================
 * Constants and Macros
 * ============================================================================ */

#define WASM_STACK_SIZE     (64 * 1024)
#define WASM_MAX_ARGS       32
#define WASM_PAGE_SIZE      65536

/* ============================================================================
 * Class IDs
 * ============================================================================ */

static JSClassID js_wasm_module_class_id;
static JSClassID js_wasm_instance_class_id;
static JSClassID js_wasm_memory_class_id;
static JSClassID js_wasm_table_class_id;
static JSClassID js_wasm_global_class_id;
static JSClassID js_wasm_func_class_id;

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef struct {
    uint8_t *bytes;
    size_t size;
} JSWasmData;

typedef struct {
    IM3Module module;
    JSWasmData data;
    bool linked;
} JSWasmModule;

typedef struct {
    IM3Runtime runtime;
    IM3Module module;
    JSContext *ctx;
} JSWasmInstance;

typedef struct {
    IM3Runtime runtime;
    uint32_t initial;
    uint32_t maximum;
    bool has_max;
    bool owned;  /* true if we own the runtime */
} JSWasmMemory;

typedef struct {
    JSValue *elements;
    uint32_t size;
    uint32_t maximum;
    bool has_max;
} JSWasmTable;

typedef struct {
    M3ValueType type;
    uint64_t value;
    bool mutable_;
} JSWasmGlobal;

typedef struct {
    IM3Function func;
} JSWasmFunc;

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static JSValue js_wasm_throw(JSContext *ctx, const char *name, const char *msg);
static JSValue js_wasm_build_exports(JSContext *ctx, JSWasmInstance *inst, JSValue instance_obj);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

static IM3Environment js_wasm_get_env(JSContext *ctx) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    CHECK_NOT_NULL(qrt);
    return qrt->wasm_ctx.env;
}

static JSValue js_wasm_throw(JSContext *ctx, const char *name, const char *msg) {
    JSValue err = JS_NewError(ctx);
    JS_DefinePropertyValueStr(ctx, err, "message",
        JS_NewString(ctx, msg ? msg : "Unknown error"),
        JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, err, "name",
        JS_NewString(ctx, name),
        JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    return JS_Throw(ctx, err);
}

static M3ValueType js_wasm_parse_valtype(const char *str) {
    if (!str) return c_m3Type_none;
    if (strcmp(str, "i32") == 0) return c_m3Type_i32;
    if (strcmp(str, "i64") == 0) return c_m3Type_i64;
    if (strcmp(str, "f32") == 0) return c_m3Type_f32;
    if (strcmp(str, "f64") == 0) return c_m3Type_f64;
    return c_m3Type_none;
}

static JSValue js_wasm_value_to_js(JSContext *ctx, M3ValueType type, const void *ptr) {
    switch (type) {
        case c_m3Type_i32:
            return JS_NewInt32(ctx, *(int32_t *)ptr);
        case c_m3Type_i64: {
            int64_t v = *(int64_t *)ptr;
            if (v >= INT32_MIN && v <= INT32_MAX)
                return JS_NewInt32(ctx, (int32_t)v);
            return JS_NewBigInt64(ctx, v);
        }
        case c_m3Type_f32:
            return JS_NewFloat64(ctx, *(float *)ptr);
        case c_m3Type_f64:
            return JS_NewFloat64(ctx, *(double *)ptr);
        default:
            return JS_UNDEFINED;
    }
}

static int js_wasm_js_to_value(JSContext *ctx, JSValue val, M3ValueType type, void *ptr) {
    switch (type) {
        case c_m3Type_i32: {
            int32_t v;
            if (JS_ToInt32(ctx, &v, val)) return -1;
            *(int32_t *)ptr = v;
            return 0;
        }
        case c_m3Type_i64: {
            int64_t v;
            if (JS_ToInt64(ctx, &v, val)) return -1;
            *(int64_t *)ptr = v;
            return 0;
        }
        case c_m3Type_f32: {
            double v;
            if (JS_ToFloat64(ctx, &v, val)) return -1;
            *(float *)ptr = (float)v;
            return 0;
        }
        case c_m3Type_f64: {
            double v;
            if (JS_ToFloat64(ctx, &v, val)) return -1;
            *(double *)ptr = v;
            return 0;
        }
        default:
            return -1;
    }
}

static uint8_t *js_wasm_get_buffer(JSContext *ctx, JSValue val, size_t *psize) {
    uint8_t *buf;
    size_t size;
    
    /* Try ArrayBuffer first */
    buf = JS_GetArrayBuffer(ctx, &size, val);
    if (buf) {
        *psize = size;
        return buf;
    }
    
    /* Clear exception from failed GetArrayBuffer */
    JSValue ex = JS_GetException(ctx);
    JS_FreeValue(ctx, ex);
    
    /* Try TypedArray */
    size_t offset, len;
    JSValue abuf = JS_GetTypedArrayBuffer(ctx, val, &offset, &len, NULL);
    if (JS_IsException(abuf))
        return NULL;
    
    buf = JS_GetArrayBuffer(ctx, &size, abuf);
    JS_FreeValue(ctx, abuf);
    
    if (!buf) {
        ex = JS_GetException(ctx);
        JS_FreeValue(ctx, ex);
        return NULL;
    }
    
    *psize = len;
    return buf + offset;
}

/* ============================================================================
 * WasmModule Class
 * ============================================================================ */

static void js_wasm_module_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmModule *m = JS_GetOpaque(val, js_wasm_module_class_id);
    if (m) {
        if (m->module && !m->linked)
            m3_FreeModule(m->module);
        js_free_rt(rt, m->data.bytes);
        js_free_rt(rt, m);
    }
}

static JSClassDef js_wasm_module_class = {
    "Module",
    .finalizer = js_wasm_module_finalizer,
};

static JSValue js_wasm_module_ctor(JSContext *ctx, JSValue new_target,
                                   int argc, JSValue *argv) {
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing buffer argument");
    
    size_t size;
    uint8_t *buf = js_wasm_get_buffer(ctx, argv[0], &size);
    if (!buf)
        return js_wasm_throw(ctx, "TypeError", "Invalid buffer source");
    
    /* Validate magic number */
    if (size < 8 || buf[0] != 0x00 || buf[1] != 0x61 || 
        buf[2] != 0x73 || buf[3] != 0x6d)
        return js_wasm_throw(ctx, "CompileError", "Invalid WASM magic number");
    
    JSValue obj = JS_NewObjectClass(ctx, js_wasm_module_class_id);
    if (JS_IsException(obj))
        return obj;
    
    JSWasmModule *m = js_mallocz(ctx, sizeof(*m));
    if (!m) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_SetOpaque(obj, m);
    
    /* Copy buffer data */
    m->data.bytes = js_malloc(ctx, size);
    if (!m->data.bytes) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    memcpy(m->data.bytes, buf, size);
    m->data.size = size;
    m->linked = false;
    
    /* Parse module */
    M3Result r = m3_ParseModule(js_wasm_get_env(ctx), &m->module, 
                                m->data.bytes, m->data.size);
    if (r) {
        JS_FreeValue(ctx, obj);
        return js_wasm_throw(ctx, "CompileError", r);
    }
    
    return obj;
}

static JSValue js_wasm_module_exports(JSContext *ctx, JSValue this_val,
                                      int argc, JSValue *argv) {
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing module argument");
    
    JSWasmModule *m = JS_GetOpaque2(ctx, argv[0], js_wasm_module_class_id);
    if (!m || !m->module)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmModule");
    
    JSValue arr = JS_NewArray(ctx);
    if (JS_IsException(arr))
        return arr;
    
    uint32_t idx = 0;
    IM3Module mod = m->module;
    
    /* Export functions */
    for (uint32_t i = 0; i < mod->numFunctions; i++) {
        IM3Function f = &mod->functions[i];
        if (f->export_name) {
            JSValue item = JS_NewObject(ctx);
            JS_DefinePropertyValueStr(ctx, item, "name",
                JS_NewString(ctx, f->export_name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind",
                JS_NewString(ctx, "function"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, arr, idx++, item, JS_PROP_C_W_E);
        }
    }
    
    /* Export memory */
    if (mod->memoryExportName) {
        JSValue item = JS_NewObject(ctx);
        JS_DefinePropertyValueStr(ctx, item, "name",
            JS_NewString(ctx, mod->memoryExportName), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, item, "kind",
            JS_NewString(ctx, "memory"), JS_PROP_C_W_E);
        JS_DefinePropertyValueUint32(ctx, arr, idx++, item, JS_PROP_C_W_E);
    }
    
    /* Export globals */
    for (uint32_t i = 0; i < mod->numGlobals; i++) {
        IM3Global g = &mod->globals[i];
        if (g->name) {
            JSValue item = JS_NewObject(ctx);
            JS_DefinePropertyValueStr(ctx, item, "name",
                JS_NewString(ctx, g->name), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind",
                JS_NewString(ctx, "global"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, arr, idx++, item, JS_PROP_C_W_E);
        }
    }
    
    return arr;
}

static JSValue js_wasm_module_imports(JSContext *ctx, JSValue this_val,
                                      int argc, JSValue *argv) {
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing module argument");
    
    JSWasmModule *m = JS_GetOpaque2(ctx, argv[0], js_wasm_module_class_id);
    if (!m || !m->module)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmModule");
    
    JSValue arr = JS_NewArray(ctx);
    if (JS_IsException(arr))
        return arr;
    
    uint32_t idx = 0;
    IM3Module mod = m->module;
    
    /* Import functions */
    for (uint32_t i = 0; i < mod->numFunctions; i++) {
        IM3Function f = &mod->functions[i];
        if (f->import.moduleUtf8 && f->import.fieldUtf8) {
            JSValue item = JS_NewObject(ctx);
            JS_DefinePropertyValueStr(ctx, item, "module",
                JS_NewString(ctx, f->import.moduleUtf8), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "name",
                JS_NewString(ctx, f->import.fieldUtf8), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, item, "kind",
                JS_NewString(ctx, "function"), JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(ctx, arr, idx++, item, JS_PROP_C_W_E);
        }
    }
    
    /* Import memory */
	JSValue item = JS_NewObject(ctx);
	JS_DefinePropertyValueStr(ctx, item, "module",
		JS_NewString(ctx, mod->memoryImport.moduleUtf8), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, item, "name",
		JS_NewString(ctx, mod->memoryImport.fieldUtf8), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, item, "kind",
		JS_NewString(ctx, "memory"), JS_PROP_C_W_E);
	JS_DefinePropertyValueUint32(ctx, arr, idx++, item, JS_PROP_C_W_E);
    
    return arr;
}

/* ============================================================================
 * WasmMemory Class
 * ============================================================================ */

static void js_wasm_memory_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmMemory *m = JS_GetOpaque(val, js_wasm_memory_class_id);
    if (m) {
        if (m->runtime && m->owned)
            m3_FreeRuntime(m->runtime);
        js_free_rt(rt, m);
    }
}

static JSClassDef js_wasm_memory_class = {
    "Memory",
    .finalizer = js_wasm_memory_finalizer,
};

static JSValue js_wasm_memory_ctor(JSContext *ctx, JSValue new_target,
                                   int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0]))
        return js_wasm_throw(ctx, "TypeError", "Descriptor must be an object");
    
    JSValue desc = argv[0];
    
    /* Get initial */
    JSValue initial_val = JS_GetPropertyStr(ctx, desc, "initial");
    uint32_t initial = 0;
    if (JS_ToUint32(ctx, &initial, initial_val)) {
        JS_FreeValue(ctx, initial_val);
        return js_wasm_throw(ctx, "TypeError", "Invalid initial pages");
    }
    JS_FreeValue(ctx, initial_val);
    
    /* Get maximum */
    uint32_t maximum = 65536;
    bool has_max = false;
    JSValue max_val = JS_GetPropertyStr(ctx, desc, "maximum");
    if (!JS_IsUndefined(max_val)) {
        has_max = true;
        if (JS_ToUint32(ctx, &maximum, max_val)) {
            JS_FreeValue(ctx, max_val);
            return js_wasm_throw(ctx, "TypeError", "Invalid maximum pages");
        }
    }
    JS_FreeValue(ctx, max_val);
    
    if (initial > maximum)
        return js_wasm_throw(ctx, "RangeError", "Initial exceeds maximum");
    
    JSValue obj = JS_NewObjectClass(ctx, js_wasm_memory_class_id);
    if (JS_IsException(obj))
        return obj;
    
    JSWasmMemory *m = js_mallocz(ctx, sizeof(*m));
    if (!m) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_SetOpaque(obj, m);
    
    m->initial = initial;
    m->maximum = maximum;
    m->has_max = has_max;
    m->owned = true;
    
    m->runtime = m3_NewRuntime(js_wasm_get_env(ctx), initial * WASM_PAGE_SIZE, NULL);
    if (!m->runtime) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    return obj;
}

static JSValue js_wasm_memory_buffer_get(JSContext *ctx, JSValue this_val) {
    JSWasmMemory *m = JS_GetOpaque2(ctx, this_val, js_wasm_memory_class_id);
    if (!m)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmMemory");
    
    if (!m->runtime)
        return JS_NewArrayBuffer(ctx, NULL, 0, NULL, NULL, false);
    
    uint32_t size = 0;
    uint8_t *data = m3_GetMemory(m->runtime, &size, 0);
    if (!data || size == 0)
        return JS_NewArrayBuffer(ctx, NULL, 0, NULL, NULL, false);
    
    return JS_NewArrayBuffer(ctx, data, size, NULL, NULL, false);
}

static JSValue js_wasm_memory_grow(JSContext *ctx, JSValue this_val,
                                   int argc, JSValue *argv) {
    JSWasmMemory *m = JS_GetOpaque2(ctx, this_val, js_wasm_memory_class_id);
    if (!m)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmMemory");
    
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing delta argument");
    
    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[0]))
        return JS_EXCEPTION;
    
    if (!m->runtime)
        return JS_NewInt32(ctx, -1);
    
    uint32_t old_size = 0;
    m3_GetMemory(m->runtime, &old_size, 0);
    uint32_t old_pages = old_size / WASM_PAGE_SIZE;
    uint32_t new_pages = old_pages + delta;
    
    if (m->has_max && new_pages > m->maximum)
        return JS_NewInt32(ctx, -1);
    
    M3Result r = ResizeMemory(m->runtime, new_pages);
    if (r)
        return JS_NewInt32(ctx, -1);
    
    return JS_NewInt32(ctx, old_pages);
}

/* ============================================================================
 * WasmTable Class
 * ============================================================================ */

static void js_wasm_table_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmTable *t = JS_GetOpaque(val, js_wasm_table_class_id);
    if (t) {
        if (t->elements) {
            for (uint32_t i = 0; i < t->size; i++)
                JS_FreeValueRT(rt, t->elements[i]);
            js_free_rt(rt, t->elements);
        }
        js_free_rt(rt, t);
    }
}

static void js_wasm_table_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    JSWasmTable *t = JS_GetOpaque(val, js_wasm_table_class_id);
    if (t && t->elements) {
        for (uint32_t i = 0; i < t->size; i++)
            JS_MarkValue(rt, t->elements[i], mark_func);
    }
}

static JSClassDef js_wasm_table_class = {
    "Table",
    .finalizer = js_wasm_table_finalizer,
    .gc_mark = js_wasm_table_mark,
};

static JSValue js_wasm_table_ctor(JSContext *ctx, JSValue new_target,
                                  int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0]))
        return js_wasm_throw(ctx, "TypeError", "Descriptor must be an object");
    
    JSValue desc = argv[0];
    
    /* Get element type */
    JSValue elem_val = JS_GetPropertyStr(ctx, desc, "element");
    const char *elem_str = JS_ToCString(ctx, elem_val);
    JS_FreeValue(ctx, elem_val);
    
    if (!elem_str)
        return js_wasm_throw(ctx, "TypeError", "Missing element type");
    
    bool valid = (strcmp(elem_str, "anyfunc") == 0 ||
                  strcmp(elem_str, "funcref") == 0 ||
                  strcmp(elem_str, "externref") == 0);
    JS_FreeCString(ctx, elem_str);
    
    if (!valid)
        return js_wasm_throw(ctx, "TypeError", "Invalid element type");
    
    /* Get initial */
    JSValue initial_val = JS_GetPropertyStr(ctx, desc, "initial");
    uint32_t initial = 0;
    if (JS_ToUint32(ctx, &initial, initial_val)) {
        JS_FreeValue(ctx, initial_val);
        return js_wasm_throw(ctx, "TypeError", "Invalid initial size");
    }
    JS_FreeValue(ctx, initial_val);
    
    /* Get maximum */
    uint32_t maximum = UINT32_MAX;
    bool has_max = false;
    JSValue max_val = JS_GetPropertyStr(ctx, desc, "maximum");
    if (!JS_IsUndefined(max_val)) {
        has_max = true;
        if (JS_ToUint32(ctx, &maximum, max_val)) {
            JS_FreeValue(ctx, max_val);
            return js_wasm_throw(ctx, "TypeError", "Invalid maximum size");
        }
    }
    JS_FreeValue(ctx, max_val);
    
    if (initial > maximum)
        return js_wasm_throw(ctx, "RangeError", "Initial exceeds maximum");
    
    JSValue obj = JS_NewObjectClass(ctx, js_wasm_table_class_id);
    if (JS_IsException(obj))
        return obj;
    
    JSWasmTable *t = js_mallocz(ctx, sizeof(*t));
    if (!t) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_SetOpaque(obj, t);
    
    t->size = initial;
    t->maximum = maximum;
    t->has_max = has_max;
    
    if (initial > 0) {
        t->elements = js_mallocz(ctx, initial * sizeof(JSValue));
        if (!t->elements) {
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
        for (uint32_t i = 0; i < initial; i++)
            t->elements[i] = JS_NULL;
    }
    
    return obj;
}

static JSValue js_wasm_table_length_get(JSContext *ctx, JSValue this_val) {
    JSWasmTable *t = JS_GetOpaque2(ctx, this_val, js_wasm_table_class_id);
    if (!t)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmTable");
    return JS_NewUint32(ctx, t->size);
}

static JSValue js_wasm_table_get(JSContext *ctx, JSValue this_val,
                                 int argc, JSValue *argv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, this_val, js_wasm_table_class_id);
    if (!t)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmTable");
    
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing index argument");
    
    uint32_t idx;
    if (JS_ToUint32(ctx, &idx, argv[0]))
        return JS_EXCEPTION;
    
    if (idx >= t->size)
        return js_wasm_throw(ctx, "RangeError", "Index out of bounds");
    
    return JS_DupValue(ctx, t->elements[idx]);
}

static JSValue js_wasm_table_set(JSContext *ctx, JSValue this_val,
                                 int argc, JSValue *argv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, this_val, js_wasm_table_class_id);
    if (!t)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmTable");
    
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing index argument");
    
    uint32_t idx;
    if (JS_ToUint32(ctx, &idx, argv[0]))
        return JS_EXCEPTION;
    
    if (idx >= t->size)
        return js_wasm_throw(ctx, "RangeError", "Index out of bounds");
    
    JS_FreeValue(ctx, t->elements[idx]);
    t->elements[idx] = JS_DupValue(ctx, argc > 1 ? argv[1] : JS_NULL);
    
    return JS_UNDEFINED;
}

static JSValue js_wasm_table_grow(JSContext *ctx, JSValue this_val,
                                  int argc, JSValue *argv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, this_val, js_wasm_table_class_id);
    if (!t)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmTable");
    
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing delta argument");
    
    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[0]))
        return JS_EXCEPTION;
    
    uint32_t old_size = t->size;
    uint64_t new_size64 = (uint64_t)old_size + delta;
    
    if (new_size64 > t->maximum || new_size64 > UINT32_MAX)
        return JS_NewInt32(ctx, -1);
    
    uint32_t new_size = (uint32_t)new_size64;
    
    if (new_size > 0) {
        JSValue *new_elements = js_realloc(ctx, t->elements, new_size * sizeof(JSValue));
        if (!new_elements)
            return JS_NewInt32(ctx, -1);
        
        JSValue init_val = argc > 1 ? argv[1] : JS_NULL;
        for (uint32_t i = old_size; i < new_size; i++)
            new_elements[i] = JS_DupValue(ctx, init_val);
        
        t->elements = new_elements;
    }
    
    t->size = new_size;
    return JS_NewUint32(ctx, old_size);
}

/* ============================================================================
 * WasmGlobal Class
 * ============================================================================ */

static void js_wasm_global_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmGlobal *g = JS_GetOpaque(val, js_wasm_global_class_id);
    if (g)
        js_free_rt(rt, g);
}

static JSClassDef js_wasm_global_class = {
    "Global",
    .finalizer = js_wasm_global_finalizer,
};

static JSValue js_wasm_global_ctor(JSContext *ctx, JSValue new_target,
                                   int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0]))
        return js_wasm_throw(ctx, "TypeError", "Descriptor must be an object");
    
    JSValue desc = argv[0];
    
    /* Get value type */
    JSValue type_val = JS_GetPropertyStr(ctx, desc, "value");
    const char *type_str = JS_ToCString(ctx, type_val);
    JS_FreeValue(ctx, type_val);
    
    if (!type_str)
        return js_wasm_throw(ctx, "TypeError", "Missing value type");
    
    M3ValueType type = js_wasm_parse_valtype(type_str);
    JS_FreeCString(ctx, type_str);
    
    if (type == c_m3Type_none)
        return js_wasm_throw(ctx, "TypeError", "Invalid value type");
    
    /* Get mutable */
    JSValue mutable_val = JS_GetPropertyStr(ctx, desc, "mutable");
    bool mutable_ = JS_ToBool(ctx, mutable_val);
    JS_FreeValue(ctx, mutable_val);
    
    JSValue obj = JS_NewObjectClass(ctx, js_wasm_global_class_id);
    if (JS_IsException(obj))
        return obj;
    
    JSWasmGlobal *g = js_mallocz(ctx, sizeof(*g));
    if (!g) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_SetOpaque(obj, g);
    
    g->type = type;
    g->mutable_ = mutable_;
    g->value = 0;
    
    /* Set initial value */
    if (argc > 1) {
        if (js_wasm_js_to_value(ctx, argv[1], type, &g->value)) {
            JS_FreeValue(ctx, obj);
            return js_wasm_throw(ctx, "TypeError", "Invalid initial value");
        }
    }
    
    return obj;
}

static JSValue js_wasm_global_value_get(JSContext *ctx, JSValue this_val) {
    JSWasmGlobal *g = JS_GetOpaque2(ctx, this_val, js_wasm_global_class_id);
    if (!g)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmGlobal");
    return js_wasm_value_to_js(ctx, g->type, &g->value);
}

static JSValue js_wasm_global_value_set(JSContext *ctx, JSValue this_val, JSValue val) {
    JSWasmGlobal *g = JS_GetOpaque2(ctx, this_val, js_wasm_global_class_id);
    if (!g)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmGlobal");
    
    if (!g->mutable_)
        return js_wasm_throw(ctx, "TypeError", "Cannot set immutable global");
    
    if (js_wasm_js_to_value(ctx, val, g->type, &g->value))
        return js_wasm_throw(ctx, "TypeError", "Invalid value type");
    
    return JS_UNDEFINED;
}

static JSValue js_wasm_global_valueof(JSContext *ctx, JSValue this_val,
                                      int argc, JSValue *argv) {
    return js_wasm_global_value_get(ctx, this_val);
}

/* ============================================================================
 * WasmFunc Class (Internal - for wrapped exported functions)
 * ============================================================================ */

static void js_wasm_func_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmFunc *f = JS_GetOpaque(val, js_wasm_func_class_id);
    if (f)
        js_free_rt(rt, f);
}

static JSClassDef js_wasm_func_class = {
    "Func",
    .finalizer = js_wasm_func_finalizer,
};

/*
 * Function call handler
 * func_data[0] = JSWasmFunc object (contains IM3Function pointer)
 * func_data[1] = WasmInstance object (prevents GC, provides runtime)
 */
static JSValue js_wasm_func_call(JSContext *ctx, JSValue this_val,
                                 int argc, JSValue *argv, int magic, 
                                 JSValue *func_data) {
    /* Get function data */
    JSWasmFunc *f = JS_GetOpaque(func_data[0], js_wasm_func_class_id);
    if (!f || !f->func)
        return js_wasm_throw(ctx, "RuntimeError", "Invalid function reference");
    
    /* Get instance to verify runtime is still valid */
    JSWasmInstance *inst = JS_GetOpaque(func_data[1], js_wasm_instance_class_id);
    if (!inst || !inst->runtime)
        return js_wasm_throw(ctx, "RuntimeError", "Instance has been destroyed");
    
    IM3Function func = f->func;
    int arg_count = m3_GetArgCount(func);
    
    if (argc < arg_count)
        return js_wasm_throw(ctx, "TypeError", "Not enough arguments");
    
    if (arg_count > WASM_MAX_ARGS)
        return js_wasm_throw(ctx, "RangeError", "Too many arguments");
    
    /* Convert arguments */
    uint64_t arg_values[WASM_MAX_ARGS];
    const void *arg_ptrs[WASM_MAX_ARGS];
    
    for (int i = 0; i < arg_count; i++) {
        M3ValueType type = m3_GetArgType(func, i);
        if (js_wasm_js_to_value(ctx, argv[i], type, &arg_values[i]))
            return js_wasm_throw(ctx, "TypeError", "Invalid argument type");
        arg_ptrs[i] = &arg_values[i];
    }
    
    /* Call function */
    M3Result r = m3_Call(func, arg_count, arg_ptrs);
    if (r)
        return js_wasm_throw(ctx, "RuntimeError", r);
    
    /* Get return values */
    int ret_count = m3_GetRetCount(func);
    if (ret_count == 0)
        return JS_UNDEFINED;
    
    if (ret_count > WASM_MAX_ARGS)
        return js_wasm_throw(ctx, "RangeError", "Too many return values");
    
    uint64_t ret_values[WASM_MAX_ARGS];
    const void *ret_ptrs[WASM_MAX_ARGS];
    
    for (int i = 0; i < ret_count; i++)
        ret_ptrs[i] = &ret_values[i];
    
    r = m3_GetResults(func, ret_count, ret_ptrs);
    if (r)
        return js_wasm_throw(ctx, "RuntimeError", r);
    
    /* Return single value or array */
    if (ret_count == 1)
        return js_wasm_value_to_js(ctx, m3_GetRetType(func, 0), ret_ptrs[0]);
    
    JSValue arr = JS_NewArray(ctx);
    for (int i = 0; i < ret_count; i++) {
        JS_SetPropertyUint32(ctx, arr, i,
            js_wasm_value_to_js(ctx, m3_GetRetType(func, i), ret_ptrs[i]));
    }
    return arr;
}

static JSValue js_wasm_wrap_func(JSContext *ctx, IM3Function func, JSValue instance_obj) {
    JSWasmFunc *f = js_mallocz(ctx, sizeof(*f));
    if (!f)
        return JS_EXCEPTION;
    
    f->func = func;
    
    JSValue func_obj = JS_NewObjectClass(ctx, js_wasm_func_class_id);
    if (JS_IsException(func_obj)) {
        js_free(ctx, f);
        return JS_EXCEPTION;
    }
    JS_SetOpaque(func_obj, f);
    
    /* Create function with two data values:
     * [0] = JSWasmFunc object
     * [1] = Instance object (prevents GC of instance while function exists)
     */
    JSValue func_data[2] = { func_obj, instance_obj };
    JSValue wrapper = JS_NewCFunctionData(ctx, js_wasm_func_call, 0, 0, 2, func_data);
    
    JS_FreeValue(ctx, func_obj);
    return wrapper;
}

/* ============================================================================
 * WasmInstance Class
 * ============================================================================ */

static void js_wasm_instance_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmInstance *i = JS_GetOpaque(val, js_wasm_instance_class_id);
    if (i) {
        if (i->runtime)
            m3_FreeRuntime(i->runtime);
        js_free_rt(rt, i);
    }
}

static JSClassDef js_wasm_instance_class = {
    "Instance",
    .finalizer = js_wasm_instance_finalizer,
};

/* ============================================================================
 * Import Linking
 * ============================================================================ */

typedef struct {
    JSContext *ctx;
    JSValue func;
    M3ValueType *arg_types;
    int arg_count;
    M3ValueType ret_type;
} JSWasmImport;

static m3ApiRawFunction(js_wasm_import_trampoline) {
    JSWasmImport *imp = (JSWasmImport *)_ctx;
    if (!imp || JS_IsUndefined(imp->func))
        m3ApiTrap("Invalid import function");
    
    JSContext *ctx = imp->ctx;
    int arg_count = imp->arg_count;
    
    /* Allocate JS arguments */
    JSValue *js_args = NULL;
    if (arg_count > 0) {
        js_args = js_malloc(ctx, arg_count * sizeof(JSValue));
        if (!js_args)
            m3ApiTrap("Out of memory");
    }
    
    /* Convert WASM args to JS */
    uint64_t *raw_args = (uint64_t *)_sp;
    for (int i = 0; i < arg_count; i++) {
        js_args[i] = js_wasm_value_to_js(ctx, imp->arg_types[i], &raw_args[i]);
    }
    
    /* Call JS function */
    JSValue result = JS_Call(ctx, imp->func, JS_UNDEFINED, arg_count, js_args);
    
    /* Free JS arguments */
    for (int i = 0; i < arg_count; i++)
        JS_FreeValue(ctx, js_args[i]);
    js_free(ctx, js_args);
    
    /* Handle exception */
    if (JS_IsException(result)) {
        JS_FreeValue(ctx, result);
        m3ApiTrap("JS function threw exception");
    }
    
    /* Convert return value */
    if (imp->ret_type != c_m3Type_none) {
        uint64_t ret_val = 0;
        if (js_wasm_js_to_value(ctx, result, imp->ret_type, &ret_val)) {
            JS_FreeValue(ctx, result);
            m3ApiTrap("Failed to convert return value");
        }
        raw_args[arg_count] = ret_val;
    }
    
    JS_FreeValue(ctx, result);
    m3ApiSuccess();
}

static int js_wasm_link_imports(JSContext *ctx, JSWasmInstance *inst, JSValue imports) {
    if (JS_IsUndefined(imports) || JS_IsNull(imports))
        return 0;
    
    IM3Module module = inst->module;
    
    for (uint32_t i = 0; i < module->numFunctions; i++) {
        IM3Function f = &module->functions[i];
        
        /* Skip non-imports */
        if (!f->import.moduleUtf8 || !f->import.fieldUtf8)
            continue;
        
        /* Get module object */
        JSValue mod_obj = JS_GetPropertyStr(ctx, imports, f->import.moduleUtf8);
        if (JS_IsException(mod_obj))
            return -1;
        if (JS_IsUndefined(mod_obj))
            continue;
        
        /* Get function */
        JSValue fn = JS_GetPropertyStr(ctx, mod_obj, f->import.fieldUtf8);
        JS_FreeValue(ctx, mod_obj);
        
        if (JS_IsException(fn))
            return -1;
        if (JS_IsUndefined(fn))
            continue;
        
        if (!JS_IsFunction(ctx, fn)) {
            JS_FreeValue(ctx, fn);
            continue;
        }
        
        /* Create import data */
        JSWasmImport *imp = js_mallocz(ctx, sizeof(*imp));
        if (!imp) {
            JS_FreeValue(ctx, fn);
            return -1;
        }
        
        imp->ctx = ctx;
        imp->func = JS_DupValue(ctx, fn);
        imp->arg_count = m3_GetArgCount(f);
        imp->ret_type = m3_GetRetCount(f) > 0 ? m3_GetRetType(f, 0) : c_m3Type_none;
        
        if (imp->arg_count > 0) {
            imp->arg_types = js_malloc(ctx, imp->arg_count * sizeof(M3ValueType));
            if (!imp->arg_types) {
                JS_FreeValue(ctx, imp->func);
                js_free(ctx, imp);
                JS_FreeValue(ctx, fn);
                return -1;
            }
            for (int j = 0; j < imp->arg_count; j++)
                imp->arg_types[j] = m3_GetArgType(f, j);
        }
        
        /* Link function */
        M3Result r = m3_LinkRawFunctionEx(module,
            f->import.moduleUtf8, f->import.fieldUtf8,
            NULL, js_wasm_import_trampoline, (void *)imp);
        
        if (r) {
            JS_FreeValue(ctx, imp->func);
            js_free(ctx, imp->arg_types);
            js_free(ctx, imp);
        }
        
        JS_FreeValue(ctx, fn);
    }
    
    return 0;
}

/* ============================================================================
 * Instance Exports Builder
 * ============================================================================ */

static JSValue js_wasm_build_exports(JSContext *ctx, JSWasmInstance *inst, 
                                     JSValue instance_obj) {
    JSValue exports = JS_NewObject(ctx);
    if (JS_IsException(exports))
        return exports;
    
    IM3Module module = inst->module;
    
    /* Export functions */
    for (uint32_t i = 0; i < module->numFunctions; i++) {
        IM3Function f = &module->functions[i];
        if (!f->export_name)
            continue;
        
        IM3Function func;
        M3Result r = m3_FindFunction(&func, inst->runtime, f->export_name);
        if (r)
            continue;
        
        JSValue fn = js_wasm_wrap_func(ctx, func, instance_obj);
        if (JS_IsException(fn)) {
            JS_FreeValue(ctx, exports);
            return fn;
        }
        
        JS_DefinePropertyValueStr(ctx, exports, f->export_name, fn, JS_PROP_C_W_E);
    }
    
    /* Export memory */
    uint32_t mem_size = 0;
    uint8_t *mem = m3_GetMemory(inst->runtime, &mem_size, 0);
    if (mem && mem_size > 0) {
        JSValue mem_obj = JS_NewObjectClass(ctx, js_wasm_memory_class_id);
        if (!JS_IsException(mem_obj)) {
            JSWasmMemory *m = js_mallocz(ctx, sizeof(*m));
            if (m) {
                m->runtime = inst->runtime;
                m->owned = false;  /* Instance owns the runtime */
                m->initial = mem_size / WASM_PAGE_SIZE;
                m->maximum = 65536;
                m->has_max = false;
                JS_SetOpaque(mem_obj, m);
                
                const char *name = module->memoryExportName ? 
                                   module->memoryExportName : "memory";
                JS_DefinePropertyValueStr(ctx, exports, name, mem_obj, JS_PROP_C_W_E);
            } else {
                JS_FreeValue(ctx, mem_obj);
            }
        }
    }
    
    return exports;
}

/* ============================================================================
 * Instance Constructor and Exports Getter
 * ============================================================================ */

static JSValue js_wasm_instance_ctor(JSContext *ctx, JSValue new_target,
                                     int argc, JSValue *argv) {
    if (argc < 1)
        return js_wasm_throw(ctx, "TypeError", "Missing module argument");
    
    JSWasmModule *m = JS_GetOpaque2(ctx, argv[0], js_wasm_module_class_id);
    if (!m || !m->module)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmModule");
    
    JSValue obj = JS_NewObjectClass(ctx, js_wasm_instance_class_id);
    if (JS_IsException(obj))
        return obj;
    
    JSWasmInstance *inst = js_mallocz(ctx, sizeof(*inst));
    if (!inst) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_SetOpaque(obj, inst);
    inst->ctx = ctx;
    
    /* Parse module (creates a new copy) */
    M3Result r = m3_ParseModule(js_wasm_get_env(ctx), &inst->module,
                                m->data.bytes, m->data.size);
    if (r) {
        JS_FreeValue(ctx, obj);
        return js_wasm_throw(ctx, "CompileError", r);
    }
    
    /* Create runtime */
    inst->runtime = m3_NewRuntime(js_wasm_get_env(ctx), WASM_STACK_SIZE, NULL);
    if (!inst->runtime) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    /* Link imports */
    if (argc > 1 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        if (js_wasm_link_imports(ctx, inst, argv[1])) {
            JS_FreeValue(ctx, obj);
            return js_wasm_throw(ctx, "LinkError", "Failed to link imports");
        }
    }
    
    /* Load module into runtime */
    r = m3_LoadModule(inst->runtime, inst->module);
    if (r) {
        JS_FreeValue(ctx, obj);
        return js_wasm_throw(ctx, "LinkError", r);
    }
    
    /* Compile module */
    r = m3_CompileModule(inst->module);
    if (r) {
        JS_FreeValue(ctx, obj);
        return js_wasm_throw(ctx, "CompileError", r);
    }
    
    return obj;
}

static JSValue js_wasm_instance_exports_get(JSContext *ctx, JSValue this_val) {
    JSWasmInstance *inst = JS_GetOpaque2(ctx, this_val, js_wasm_instance_class_id);
    if (!inst)
        return js_wasm_throw(ctx, "TypeError", "Invalid WasmInstance");
    
    /* Build exports each time - functions hold reference to instance_obj (this_val)
     * which prevents GC of instance while any exported function exists */
    return js_wasm_build_exports(ctx, inst, this_val);
}

/* ============================================================================
 * Top-level Functions
 * ============================================================================ */

static JSValue js_wasm_compile(JSContext *ctx, JSValue this_val,
                               int argc, JSValue *argv) {
    JSValue resolving_funcs[2];
    JSValue promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise))
        return promise;
    
    JSValue module = js_wasm_module_ctor(ctx, JS_UNDEFINED, argc, argv);
    
    if (JS_IsException(module)) {
        JSValue err = JS_GetException(ctx);
        JS_Call(ctx, resolving_funcs[1], JS_UNDEFINED, 1, &err);
        JS_FreeValue(ctx, err);
    } else {
        JS_Call(ctx, resolving_funcs[0], JS_UNDEFINED, 1, &module);
        JS_FreeValue(ctx, module);
    }
    
    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);
    
    return promise;
}

static JSValue js_wasm_instantiate(JSContext *ctx, JSValue this_val,
                                   int argc, JSValue *argv) {
    JSValue resolving_funcs[2];
    JSValue promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise))
        return promise;
    
    JSValue module = JS_UNDEFINED;
    bool from_buffer = true;
    
    /* Check if first arg is already a module */
    if (JS_GetOpaque(argv[0], js_wasm_module_class_id)) {
        module = JS_DupValue(ctx, argv[0]);
        from_buffer = false;
    } else {
        module = js_wasm_module_ctor(ctx, JS_UNDEFINED, 1, argv);
    }
    
    if (JS_IsException(module)) {
        JSValue err = JS_GetException(ctx);
        JS_Call(ctx, resolving_funcs[1], JS_UNDEFINED, 1, &err);
        JS_FreeValue(ctx, err);
        goto done;
    }
    
    /* Create instance */
    JSValue inst_args[2] = { module, argc > 1 ? argv[1] : JS_UNDEFINED };
    JSValue instance = js_wasm_instance_ctor(ctx, JS_UNDEFINED, 2, inst_args);
    
    if (JS_IsException(instance)) {
        JSValue err = JS_GetException(ctx);
        JS_Call(ctx, resolving_funcs[1], JS_UNDEFINED, 1, &err);
        JS_FreeValue(ctx, err);
    } else {
        JSValue result;
        if (from_buffer) {
            /* Return { module, instance } */
            result = JS_NewObject(ctx);
            JS_DefinePropertyValueStr(ctx, result, "module", module, JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, result, "instance", instance, JS_PROP_C_W_E);
            module = JS_UNDEFINED;  /* Ownership transferred */
        } else {
            result = instance;
        }
        JS_Call(ctx, resolving_funcs[0], JS_UNDEFINED, 1, &result);
        JS_FreeValue(ctx, result);
    }
    
done:
    JS_FreeValue(ctx, module);
    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);
    
    return promise;
}

static JSValue js_wasm_validate(JSContext *ctx, JSValue this_val,
                                int argc, JSValue *argv) {
    if (argc < 1)
        return JS_FALSE;
    
    size_t size;
    uint8_t *buf = js_wasm_get_buffer(ctx, argv[0], &size);
    if (!buf)
        return JS_FALSE;
    
    /* Check magic number */
    if (size < 8)
        return JS_FALSE;
    if (buf[0] != 0x00 || buf[1] != 0x61 || buf[2] != 0x73 || buf[3] != 0x6d)
        return JS_FALSE;
    
    /* Try to parse */
    IM3Module module;
    M3Result r = m3_ParseModule(js_wasm_get_env(ctx), &module, buf, size);
    if (r)
        return JS_FALSE;
    
    m3_FreeModule(module);
    return JS_TRUE;
}

/* ============================================================================
 * Property Lists
 * ============================================================================ */

static const JSCFunctionListEntry js_wasm_module_static_funcs[] = {
    TJS_CFUNC_DEF("exports", 1, js_wasm_module_exports),
    TJS_CFUNC_DEF("imports", 1, js_wasm_module_imports),
};

static const JSCFunctionListEntry js_wasm_instance_proto_funcs[] = {
    TJS_CGETSET_DEF("exports", js_wasm_instance_exports_get, NULL),
};

static const JSCFunctionListEntry js_wasm_memory_proto_funcs[] = {
    TJS_CGETSET_DEF("buffer", js_wasm_memory_buffer_get, NULL),
    TJS_CFUNC_DEF("grow", 1, js_wasm_memory_grow),
};

static const JSCFunctionListEntry js_wasm_table_proto_funcs[] = {
    TJS_CGETSET_DEF("length", js_wasm_table_length_get, NULL),
    TJS_CFUNC_DEF("get", 1, js_wasm_table_get),
    TJS_CFUNC_DEF("set", 2, js_wasm_table_set),
    TJS_CFUNC_DEF("grow", 1, js_wasm_table_grow),
};

static const JSCFunctionListEntry js_wasm_global_proto_funcs[] = {
    TJS_CGETSET_DEF("value", js_wasm_global_value_get, js_wasm_global_value_set),
    TJS_CFUNC_DEF("valueOf", 0, js_wasm_global_valueof),
};

/* ============================================================================
 * Initialization
 * ============================================================================ */

void tjs__mod_wasm_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    
    /* Initialize wasm3 environment */
    if (!qrt->wasm_ctx.env)
        qrt->wasm_ctx.env = m3_NewEnvironment();
    
    /* WasmModule class */
    JS_NewClassID(rt, &js_wasm_module_class_id);
    JS_NewClass(rt, js_wasm_module_class_id, &js_wasm_module_class);
    JSValue module_proto = JS_NewObject(ctx);
    JS_SetClassProto(ctx, js_wasm_module_class_id, module_proto);
    JSValue module_ctor = JS_NewCFunction2(ctx, js_wasm_module_ctor, 
                                           "Module", 1, JS_CFUNC_constructor, 0);
    JS_SetPropertyFunctionList(ctx, module_ctor, 
                               js_wasm_module_static_funcs, 
                               countof(js_wasm_module_static_funcs));
    JS_DefinePropertyValueStr(ctx, ns, "Module", module_ctor, JS_PROP_C_W_E);
    
    /* WasmInstance class */
    JS_NewClassID(rt, &js_wasm_instance_class_id);
    JS_NewClass(rt, js_wasm_instance_class_id, &js_wasm_instance_class);
    JSValue instance_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, instance_proto, 
                               js_wasm_instance_proto_funcs, 
                               countof(js_wasm_instance_proto_funcs));
    JS_SetClassProto(ctx, js_wasm_instance_class_id, instance_proto);
    JSValue instance_ctor = JS_NewCFunction2(ctx, js_wasm_instance_ctor, 
                                             "Instance", 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "Instance", instance_ctor, JS_PROP_C_W_E);
    
    /* WasmMemory class */
    JS_NewClassID(rt, &js_wasm_memory_class_id);
    JS_NewClass(rt, js_wasm_memory_class_id, &js_wasm_memory_class);
    JSValue memory_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, memory_proto, 
                               js_wasm_memory_proto_funcs, 
                               countof(js_wasm_memory_proto_funcs));
    JS_SetClassProto(ctx, js_wasm_memory_class_id, memory_proto);
    JSValue memory_ctor = JS_NewCFunction2(ctx, js_wasm_memory_ctor, 
                                           "Memory", 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "Memory", memory_ctor, JS_PROP_C_W_E);
    
    /* WasmTable class */
    JS_NewClassID(rt, &js_wasm_table_class_id);
    JS_NewClass(rt, js_wasm_table_class_id, &js_wasm_table_class);
    JSValue table_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, table_proto, 
                               js_wasm_table_proto_funcs, 
                               countof(js_wasm_table_proto_funcs));
    JS_SetClassProto(ctx, js_wasm_table_class_id, table_proto);
    JSValue table_ctor = JS_NewCFunction2(ctx, js_wasm_table_ctor, 
                                          "Table", 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "Table", table_ctor, JS_PROP_C_W_E);
    
    /* WasmGlobal class */
    JS_NewClassID(rt, &js_wasm_global_class_id);
    JS_NewClass(rt, js_wasm_global_class_id, &js_wasm_global_class);
    JSValue global_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, global_proto, 
                               js_wasm_global_proto_funcs, 
                               countof(js_wasm_global_proto_funcs));
    JS_SetClassProto(ctx, js_wasm_global_class_id, global_proto);
    JSValue global_ctor = JS_NewCFunction2(ctx, js_wasm_global_ctor, 
                                           "Global", 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, ns, "Global", global_ctor, JS_PROP_C_W_E);
    
    /* WasmFunc class (internal, no constructor exposed) */
    JS_NewClassID(rt, &js_wasm_func_class_id);
    JS_NewClass(rt, js_wasm_func_class_id, &js_wasm_func_class);
    
    /* Top-level functions */
    JS_DefinePropertyValueStr(ctx, ns, "Compile",
        JS_NewCFunction(ctx, js_wasm_compile, "Compile", 1), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, ns, "Instantiate",
        JS_NewCFunction(ctx, js_wasm_instantiate, "Instantiate", 1), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, ns, "Validate",
        JS_NewCFunction(ctx, js_wasm_validate, "Validate", 1), JS_PROP_C_W_E);
}

void tjs__mod_wasm_cleanup(TJSRuntime *qrt) {
    if (qrt->wasm_ctx.env) {
        m3_FreeEnvironment(qrt->wasm_ctx.env);
        qrt->wasm_ctx.env = NULL;
    }
}

#else /* !CJS__HAS_WASM */

/* Stub implementations when WASM is not available */

void tjs__mod_wasm_init(JSContext *ctx, JSValue ns) {
    (void)ctx;
    (void)ns;
}

void tjs__mod_wasm_cleanup(TJSRuntime *qrt) {
    (void)qrt;
}

#warning "WASM is not available"

#endif /* CJS__HAS_WASM */
