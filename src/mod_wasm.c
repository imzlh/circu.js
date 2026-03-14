/*
 * mod_wasm.c  –  WebAssembly via WAMR (wasm-micro-runtime >= 2.4)
 *
 * Copyright (c) 2025-2026 iz
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
#include <string.h>
#include <wasm_export.h>

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define WASM_STACK_SIZE  (64  * 1024)
#define WASM_HEAP_SIZE   (256 * 1024)
#define WASM_MAX_VALS    32
#define WASM_MAX_IMP     128
#define WASM_PAGE_SIZE   65536
#define WASM_ERR_SZ      256
#define IMP_MAX_ARGS     16

/* export kinds (matches WAMR wasm_import_export_kind_t) */
#define WEXT_FUNC   0
#define WEXT_TABLE  1
#define WEXT_MEM    2
#define WEXT_GLOBAL 3

/* ------------------------------------------------------------------ */
/* Class IDs                                                            */
/* ------------------------------------------------------------------ */

static JSClassID js_mod_cls;
static JSClassID js_inst_cls;
static JSClassID js_mem_cls;
static JSClassID js_tbl_cls;
static JSClassID js_glb_cls;
static JSClassID js_fn_cls;

/* ------------------------------------------------------------------ */
/* Import dispatch table                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    char           mod[64];
    char           name[64];
    wasm_valkind_t arg_types[IMP_MAX_ARGS];
    wasm_valkind_t ret_types[IMP_MAX_ARGS];
    uint32_t       n_args;
    uint32_t       n_rets;
    JSValue        js_fn;
    JSContext     *ctx;
} ImportEntry;

typedef struct {
    ImportEntry  entries[WASM_MAX_IMP];
    NativeSymbol syms[WASM_MAX_IMP];
    uint32_t     count;
} ImportTable;

/* ------------------------------------------------------------------ */
/* Object types                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    wasm_module_t mod;    /* owned */
    uint8_t      *bytes;  /* owned; needed for wasm_runtime_load lifetime */
    size_t        size;
} JSWasmModule;

/* Forward declaration needed for trampoline */
typedef struct JSWasmInstance JSWasmInstance;
/* g_link_inst unused: symbol resolution now done via load_ex(no_resolve)+resolve_symbols */
static JSWasmInstance *g_link_inst = NULL;

struct JSWasmInstance {
    JSValue              mod_ref;   /* dup of Module JSValue → prevents early GC */
    wasm_module_t        mod;       /* borrowed from mod_ref */
    wasm_module_inst_t   inst;
    wasm_exec_env_t      exec_env;
    JSContext           *ctx;
    ImportTable          imp;
};

typedef struct {
    wasm_module_inst_t  inst;
    bool                owned;  /* false when borrowed from an Instance export */
} JSWasmMemory;

typedef struct {
    JSValue          *elems;       /* NULL for wasm-backed tables */
    uint32_t          size;
    uint32_t          max;
    bool              has_max;
    /* wasm-exported table fields (from_wasm=true) */
    bool              from_wasm;
    wasm_table_inst_t wasm_ti;
    JSValue           inst_ref;
} JSWasmTable;

typedef struct {
    wasm_valkind_t  type;
    bool            mutable_;
    void           *data_ptr;  /* points into wasm instance memory, always live */
    JSValue         inst_ref;  /* dup of Instance JSValue to prevent early GC */
} JSWasmGlobal;

typedef struct {
    wasm_function_inst_t fn;
    wasm_module_inst_t   inst;
} JSWasmFunc;

/* ------------------------------------------------------------------ */
/* Small helpers                                                        */
/* ------------------------------------------------------------------ */

#define get_buf(ctx, buf, len) JS_GetAnyBuffer(ctx, len, buf)

static JSValue wasm_err(JSContext *ctx, const char *name, const char *msg) {
    JSValue e = JS_NewError(ctx);
    JS_DefinePropertyValueStr(ctx, e, "message",
        JS_NewString(ctx, msg ? msg : "unknown error"),
        JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_DefinePropertyValueStr(ctx, e, "name",
        JS_NewString(ctx, name),
        JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    return JS_Throw(ctx, e);
}

static JSValue val_to_js(JSContext *ctx, wasm_valkind_t k, const wasm_val_t *v) {
    switch (k) {
    case WASM_I32: return JS_NewInt32(ctx, v->of.i32);
    case WASM_I64:
        if (v->of.i64 >= INT32_MIN && v->of.i64 <= INT32_MAX)
            return JS_NewInt32(ctx, (int32_t)v->of.i64);
        return JS_NewBigInt64(ctx, v->of.i64);
    case WASM_F32: return JS_NewFloat64(ctx, (double)v->of.f32);
    case WASM_F64: return JS_NewFloat64(ctx, v->of.f64);
    default:       return JS_UNDEFINED;
    }
}

static int js_to_val(JSContext *ctx, JSValue jsv, wasm_valkind_t k, wasm_val_t *out) {
    out->kind = k;
    switch (k) {
    case WASM_I32: return JS_ToInt32(ctx, &out->of.i32, jsv);
    case WASM_I64: return JS_ToInt64(ctx, &out->of.i64, jsv);
    case WASM_F32: {
        double d; int r = JS_ToFloat64(ctx, &d, jsv);
        out->of.f32 = (float)d; return r;
    }
    case WASM_F64: return JS_ToFloat64(ctx, &out->of.f64, jsv);
    default: return -1;
    }
}

/* Get default memory instance base address and page count */
static uint8_t *mem_base(wasm_module_inst_t inst, uint32_t *out_pages) {
    wasm_memory_inst_t mi = wasm_runtime_get_default_memory(inst);
    if (!mi) { if (out_pages) *out_pages = 0; return NULL; }
    if (out_pages) *out_pages = (uint32_t)wasm_memory_get_cur_page_count(mi);
    return (uint8_t *)wasm_memory_get_base_address(mi);
}

/* LEB128 encode, returns bytes written */
static int leb_u32(uint8_t *p, uint32_t v) {
    int n = 0;
    do { p[n] = v & 0x7f; v >>= 7; if (v) p[n] |= 0x80; n++; } while (v);
    return n;
}

/* ------------------------------------------------------------------ */
/* Import parsing (Module → ImportTable)                               */
/* ------------------------------------------------------------------ */

static void parse_imports(wasm_module_t mod, ImportTable *t) {
    uint32_t total = wasm_runtime_get_import_count(mod);
    t->count = 0;
    for (uint32_t i = 0; i < total && t->count < WASM_MAX_IMP; i++) {
        wasm_import_t imp;
        wasm_runtime_get_import_type(mod, i, &imp);
        if (imp.kind != WASM_IMPORT_EXPORT_KIND_FUNC) continue;

        ImportEntry *e = &t->entries[t->count++];
        snprintf(e->mod,  sizeof(e->mod),  "%s", imp.module_name);
        snprintf(e->name, sizeof(e->name), "%s", imp.name);
        e->n_args = wasm_func_type_get_param_count(imp.u.func_type);
        e->n_rets = wasm_func_type_get_result_count(imp.u.func_type);
        for (uint32_t j = 0; j < e->n_args && j < IMP_MAX_ARGS; j++)
            e->arg_types[j] = wasm_func_type_get_param_valkind(imp.u.func_type, j);
        for (uint32_t j = 0; j < e->n_rets && j < IMP_MAX_ARGS; j++)
            e->ret_types[j] = wasm_func_type_get_result_valkind(imp.u.func_type, j);
        e->js_fn = JS_UNDEFINED;
        e->ctx   = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Trampoline dispatch                                                  */
/*                                                                      */
/* wasm_runtime_register_natives_raw convention:                        */
/*   void f(wasm_exec_env_t, uint64_t *args)                            */
/* Each arg slot is one uint64_t regardless of wasm type.               */
/* Return value written back to args[0].                                */
/* ------------------------------------------------------------------ */

static void tramp_dispatch(wasm_exec_env_t env, uint32_t slot, uint64_t *args) {
    JSWasmInstance *inst = (JSWasmInstance *)wasm_runtime_get_user_data(env);
    if (!inst) inst = g_link_inst;
    if (!inst) return;

    ImportEntry *e   = &inst->imp.entries[slot];
    JSContext   *ctx = e->ctx ? e->ctx : inst->ctx;

    /* Decode args: each slot is uint64_t, cast per type */
    JSValue js_args[IMP_MAX_ARGS];
    for (uint32_t i = 0; i < e->n_args; i++) {
        switch (e->arg_types[i]) {
        case WASM_I32:
            js_args[i] = JS_NewInt32(ctx, (int32_t)(uint32_t)args[i]); break;
        case WASM_I64:
            js_args[i] = JS_NewBigInt64(ctx, (int64_t)args[i]); break;
        case WASM_F32: {
            float f; memcpy(&f, &args[i], 4);
            js_args[i] = JS_NewFloat64(ctx, (double)f); break;
        }
        case WASM_F64: {
            double d; memcpy(&d, &args[i], 8);
            js_args[i] = JS_NewFloat64(ctx, d); break;
        }
        default:
            js_args[i] = JS_UNDEFINED; break;
        }
    }

    JSValue ret = JS_IsUndefined(e->js_fn)
        ? JS_UNDEFINED
        : JS_Call(ctx, e->js_fn, JS_UNDEFINED, (int)e->n_args, js_args);

    for (uint32_t i = 0; i < e->n_args; i++)
        JS_FreeValue(ctx, js_args[i]);

    if (JS_IsException(ret)) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        return;
    }

    /* Write return value to args[0] */
    if (e->n_rets > 0) {
        switch (e->ret_types[0]) {
        case WASM_I32: {
            int32_t v = 0; JS_ToInt32(ctx, &v, ret);
            args[0] = (uint64_t)(uint32_t)v; break;
        }
        case WASM_I64: {
            int64_t v = 0; JS_ToInt64(ctx, &v, ret);
            args[0] = (uint64_t)v; break;
        }
        case WASM_F32: {
            double v = 0; JS_ToFloat64(ctx, &v, ret);
            float f = (float)v; memcpy(&args[0], &f, 4); break;
        }
        case WASM_F64: {
            double v = 0; JS_ToFloat64(ctx, &v, ret);
            memcpy(&args[0], &v, 8); break;
        }
        default: break;
        }
    }
    JS_FreeValue(ctx, ret);
}

/* 128 per-slot trampoline stubs via X-macro */
#define TRAMP_LIST \
    X(0)   X(1)   X(2)   X(3)   X(4)   X(5)   X(6)   X(7)   \
    X(8)   X(9)   X(10)  X(11)  X(12)  X(13)  X(14)  X(15)  \
    X(16)  X(17)  X(18)  X(19)  X(20)  X(21)  X(22)  X(23)  \
    X(24)  X(25)  X(26)  X(27)  X(28)  X(29)  X(30)  X(31)  \
    X(32)  X(33)  X(34)  X(35)  X(36)  X(37)  X(38)  X(39)  \
    X(40)  X(41)  X(42)  X(43)  X(44)  X(45)  X(46)  X(47)  \
    X(48)  X(49)  X(50)  X(51)  X(52)  X(53)  X(54)  X(55)  \
    X(56)  X(57)  X(58)  X(59)  X(60)  X(61)  X(62)  X(63)  \
    X(64)  X(65)  X(66)  X(67)  X(68)  X(69)  X(70)  X(71)  \
    X(72)  X(73)  X(74)  X(75)  X(76)  X(77)  X(78)  X(79)  \
    X(80)  X(81)  X(82)  X(83)  X(84)  X(85)  X(86)  X(87)  \
    X(88)  X(89)  X(90)  X(91)  X(92)  X(93)  X(94)  X(95)  \
    X(96)  X(97)  X(98)  X(99)  X(100) X(101) X(102) X(103) \
    X(104) X(105) X(106) X(107) X(108) X(109) X(110) X(111) \
    X(112) X(113) X(114) X(115) X(116) X(117) X(118) X(119) \
    X(120) X(121) X(122) X(123) X(124) X(125) X(126) X(127)

#define X(N) \
    static void js_tramp_##N(wasm_exec_env_t e, uint64_t *args) \
    { tramp_dispatch(e, N, args); }
TRAMP_LIST
#undef X

typedef void (*TrFn)(wasm_exec_env_t, uint64_t *);
#define X(N) js_tramp_##N,
static const TrFn g_tramps[WASM_MAX_IMP] = { TRAMP_LIST };
#undef X

/* Fill NativeSymbol array; signature=NULL required for register_natives_raw */
static void build_syms(ImportTable *t) {
    for (uint32_t i = 0; i < t->count; i++) {
        t->syms[i].symbol     = t->entries[i].name;
        t->syms[i].func_ptr   = (void*)g_tramps[i];
        t->syms[i].signature  = NULL;
        t->syms[i].attachment = NULL;
    }
}

/*
 * Register natives grouped by module name using register_natives_raw.
 * Must be called BEFORE wasm_runtime_resolve_symbols / instantiate.
 * Returns true if all groups registered successfully.
 */
static bool register_natives(ImportTable *t) {
    const char *mods[WASM_MAX_IMP];
    uint32_t    n_mods = 0;
    for (uint32_t i = 0; i < t->count; i++) {
        bool dup = false;
        for (uint32_t j = 0; j < n_mods; j++)
            if (!strcmp(mods[j], t->entries[i].mod)) { dup = true; break; }
        if (!dup) mods[n_mods++] = t->entries[i].mod;
    }
    for (uint32_t mi = 0; mi < n_mods; mi++) {
        /* build per-module slice directly from t->syms (stable pointers) */
        NativeSymbol *start = NULL;
        uint32_t      cnt   = 0;
        for (uint32_t i = 0; i < t->count; i++) {
            if (!strcmp(t->entries[i].mod, mods[mi])) {
                if (!start) start = &t->syms[i];
                cnt++;
            }
        }
        if (cnt && !wasm_runtime_register_natives_raw(mods[mi], start, cnt))
            return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* WasmModule                                                           */
/* ------------------------------------------------------------------ */

static void mod_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmModule *m = JS_GetOpaque(val, js_mod_cls);
    if (!m) return;
    if (m->mod)   wasm_runtime_unload(m->mod);
    if (m->bytes) js_free_rt(rt, m->bytes);
    js_free_rt(rt, m);
}

static JSClassDef js_mod_classdef = { "Module", .finalizer = mod_finalizer };

static JSValue mod_ctor(JSContext *ctx, JSValue nt, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing buffer");
    size_t   size;
    uint8_t *src = get_buf(ctx, argv[0], &size);
    if (!src || size < 8 || src[0] != 0x00 || src[1] != 0x61 ||
        src[2] != 0x73 || src[3] != 0x6d)
        return wasm_err(ctx, "CompileError", "Not a wasm binary");

    JSValue obj = JS_NewObjectClass(ctx, js_mod_cls);
    if (JS_IsException(obj)) return obj;

    JSWasmModule *m = js_mallocz(ctx, sizeof(*m));
    if (!m) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    JS_SetOpaque(obj, m);

    m->bytes = js_malloc(ctx, size);
    if (!m->bytes) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    memcpy(m->bytes, src, size);
    m->size = size;

    char err[WASM_ERR_SZ];
    /* no_resolve: defer symbol resolution until Instance ctor registers natives.
     * wasm_binary_freeable: WAMR copies what it needs, so we can free bytes
     * immediately after load if the runtime supports it. */
    LoadArgs la = { .no_resolve = true, .wasm_binary_freeable = true };
    m->mod = wasm_runtime_load_ex(m->bytes, (uint32_t)size, &la, err, sizeof(err));
    if (!m->mod) { JS_FreeValue(ctx, obj); return wasm_err(ctx, "CompileError", err); }

    if (wasm_runtime_is_underlying_binary_freeable(m->mod)) {
        js_free(ctx, m->bytes);
        m->bytes = NULL;
    }

    return obj;
}

static JSValue mod_exports(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    (void)tv;
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing module");
    JSWasmModule *m = JS_GetOpaque2(ctx, argv[0], js_mod_cls);
    if (!m || !m->mod) return JS_ThrowTypeError(ctx, "Invalid Module");

    uint32_t total = wasm_runtime_get_export_count(m->mod);
    JSValue  arr   = JS_NewArray(ctx);
    static const char *kinds[] = { "function", "table", "memory", "global" };

    for (uint32_t i = 0; i < total; i++) {
        wasm_export_t exp;
        wasm_runtime_get_export_type(m->mod, i, &exp);
        JSValue item = JS_NewObject(ctx);
        JS_DefinePropertyValueStr(ctx, item, "name",
            JS_NewString(ctx, exp.name), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, item, "kind",
            JS_NewString(ctx, exp.kind < 4 ? kinds[exp.kind] : "unknown"),
            JS_PROP_C_W_E);
        JS_DefinePropertyValueUint32(ctx, arr, i, item, JS_PROP_C_W_E);
    }
    return arr;
}

static JSValue mod_imports(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    (void)tv;
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing module");
    JSWasmModule *m = JS_GetOpaque2(ctx, argv[0], js_mod_cls);
    if (!m || !m->mod) return JS_ThrowTypeError(ctx, "Invalid Module");

    ImportTable t;
    parse_imports(m->mod, &t);
    JSValue arr = JS_NewArray(ctx);
    for (uint32_t i = 0; i < t.count; i++) {
        JSValue item = JS_NewObject(ctx);
        JS_DefinePropertyValueStr(ctx, item, "module",
            JS_NewString(ctx, t.entries[i].mod),  JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, item, "name",
            JS_NewString(ctx, t.entries[i].name), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, item, "kind",
            JS_NewString(ctx, "function"),         JS_PROP_C_W_E);
        JS_DefinePropertyValueUint32(ctx, arr, i, item, JS_PROP_C_W_E);
    }
    return arr;
}

/* ------------------------------------------------------------------ */
/* WasmMemory                                                           */
/* ------------------------------------------------------------------ */

static void mem_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmMemory *m = JS_GetOpaque(val, js_mem_cls);
    if (!m) return;
    if (m->owned && m->inst) wasm_runtime_deinstantiate(m->inst);
    js_free_rt(rt, m);
}
static JSClassDef js_mem_classdef = { "Memory", .finalizer = mem_finalizer };

/* Build a minimal wasm binary containing only a memory section */
static int build_mem_wasm(uint8_t *out, size_t cap,
                           uint32_t init, uint32_t max, bool has_max) {
    if (cap < 32) return -1;
    uint8_t *p = out;
	static uint8_t wasm_header[8] = {
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 
	};

    memcpy(p, wasm_header, 8); p += 8;

    uint8_t limits[12]; int ll = 0;
    if (has_max) {
        limits[ll++] = 0x01;
        ll += leb_u32(limits + ll, init);
        ll += leb_u32(limits + ll, max);
    } else {
        limits[ll++] = 0x00;
        ll += leb_u32(limits + ll, init);
    }
    *p++ = 5;                               /* section id: memory */
    p   += leb_u32(p, 1 + (uint32_t)ll);    /* section size       */
    *p++ = 1;                               /* count              */
    memcpy(p, limits, (size_t)ll); p += ll;
    return (int)(p - out);
}

static JSValue mem_ctor(JSContext *ctx, JSValue nt, int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0]))
        return JS_ThrowTypeError(ctx, "Descriptor must be an object");

    JSValue iv = JS_GetPropertyStr(ctx, argv[0], "initial");
    uint32_t init;
    if (JS_ToUint32(ctx, &init, iv)) { JS_FreeValue(ctx, iv); return JS_EXCEPTION; }
    JS_FreeValue(ctx, iv);

    uint32_t max = 0; bool has_max = false;
    JSValue  mv  = JS_GetPropertyStr(ctx, argv[0], "maximum");
    if (!JS_IsUndefined(mv)) {
        if (JS_ToUint32(ctx, &max, mv) || max < init) {
            JS_FreeValue(ctx, mv);
            return wasm_err(ctx, "RangeError", "Invalid maximum");
        }
        has_max = true;
    }
    JS_FreeValue(ctx, mv);

    JSValue obj = JS_NewObjectClass(ctx, js_mem_cls);
    if (JS_IsException(obj)) return obj;
    JSWasmMemory *m = js_mallocz(ctx, sizeof(*m));
    if (!m) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    JS_SetOpaque(obj, m);

    /* buf must stay alive until unload; use heap + wasm_binary_freeable so
     * WAMR copies what it needs internally, then we can free immediately */
    uint8_t *buf = js_malloc(ctx, 64);
    if (!buf) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    int sz = build_mem_wasm(buf, 64, init, max, has_max);
    if (sz < 0) {
        js_free(ctx, buf); JS_FreeValue(ctx, obj);
        return wasm_err(ctx, "RangeError", "Bad descriptor");
    }
    char          err[WASM_ERR_SZ];
    LoadArgs      la  = { .wasm_binary_freeable = true };
    wasm_module_t mod = wasm_runtime_load_ex(buf, (uint32_t)sz, &la, err, sizeof(err));
    js_free(ctx, buf);
    if (!mod) { JS_FreeValue(ctx, obj); return wasm_err(ctx, "CompileError", err); }
    m->inst = wasm_runtime_instantiate(mod, WASM_STACK_SIZE, WASM_HEAP_SIZE, err, sizeof(err));
    wasm_runtime_unload(mod);
    if (!m->inst) { JS_FreeValue(ctx, obj); return wasm_err(ctx, "LinkError", err); }

    m->owned = true;
    return obj;
}

static JSValue mem_shared_get(JSContext *ctx, JSValue tv) {
    JSWasmMemory *m = JS_GetOpaque2(ctx, tv, js_mem_cls);
    if (!m) return JS_ThrowTypeError(ctx, "Invalid Memory");
    wasm_memory_inst_t mi = wasm_runtime_get_default_memory(m->inst);
    return mi ? JS_NewBool(ctx, wasm_memory_get_shared(mi)) : JS_FALSE;
}

static JSValue mem_buffer_get(JSContext *ctx, JSValue tv) {
    JSWasmMemory *m = JS_GetOpaque2(ctx, tv, js_mem_cls);
    if (!m) return JS_ThrowTypeError(ctx, "Invalid Memory");
    uint32_t pages = 0;
    uint8_t *base  = mem_base(m->inst, &pages);
    if (!base) return JS_NewArrayBuffer(ctx, NULL, 0, NULL, NULL, false);
    return JS_NewArrayBufferCopy(ctx, base, (size_t)pages * WASM_PAGE_SIZE);
}

static JSValue mem_grow(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    JSWasmMemory *m = JS_GetOpaque2(ctx, tv, js_mem_cls);
    if (!m) return JS_ThrowTypeError(ctx, "Invalid Memory");
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing delta");

    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[0])) return JS_EXCEPTION;

    wasm_memory_inst_t mi = wasm_runtime_get_default_memory(m->inst);
    if (!mi) return JS_NewInt32(ctx, -1);

    uint32_t old = (uint32_t)wasm_memory_get_cur_page_count(mi);
    if (!wasm_memory_enlarge(mi, delta))
        return JS_NewInt32(ctx, -1);
    return JS_NewUint32(ctx, old);
}

/* ------------------------------------------------------------------ */
/* WasmTable  (pure JS, no WAMR)                                       */
/* ------------------------------------------------------------------ */


static JSValue fn_call(JSContext *ctx, JSValue tv, int argc, JSValue *argv,
                        int magic, JSValue *data) {
    (void)magic;
    JSWasmFunc *f = JS_GetOpaque(data[0], js_fn_cls);
    if (!f || !f->fn) return wasm_err(ctx, "RuntimeError", "Invalid function");

    JSWasmInstance *inst = JS_GetOpaque(data[1], js_inst_cls);
    if (!inst || !inst->inst) return wasm_err(ctx, "RuntimeError", "Instance destroyed");

    uint32_t np = wasm_func_get_param_count(f->fn, f->inst);
    uint32_t nr = wasm_func_get_result_count(f->fn, f->inst);
    if ((uint32_t)argc < np) return JS_ThrowTypeError(ctx, "Not enough arguments");
    if (np > WASM_MAX_VALS || nr > WASM_MAX_VALS)
        return wasm_err(ctx, "RangeError", "Too many params/results");

    wasm_valkind_t ptypes[WASM_MAX_VALS], rtypes[WASM_MAX_VALS];
    wasm_func_get_param_types(f->fn, f->inst, ptypes);
    wasm_func_get_result_types(f->fn, f->inst, rtypes);

    wasm_val_t params[WASM_MAX_VALS], results[WASM_MAX_VALS];
    for (uint32_t i = 0; i < np; i++)
        if (js_to_val(ctx, argv[i], ptypes[i], &params[i]))
            return JS_ThrowTypeError(ctx, "Invalid argument");

    if (!wasm_runtime_call_wasm_a(inst->exec_env, f->fn, nr, results, np, params)) {
        const char *ex = wasm_runtime_get_exception(inst->inst);
        return wasm_err(ctx, "RuntimeError", ex ? ex : "wasm trap");
    }

    if (nr == 0) return JS_UNDEFINED;
    if (nr == 1) return val_to_js(ctx, rtypes[0], &results[0]);

    JSValue arr = JS_NewArray(ctx);
    for (uint32_t i = 0; i < nr; i++)
        JS_SetPropertyUint32(ctx, arr, i, val_to_js(ctx, rtypes[i], &results[i]));
    return arr;
}

static JSValue wrap_func(JSContext *ctx, wasm_function_inst_t fn,
                          wasm_module_inst_t mi, JSValue iobj) {
    JSWasmFunc *f = js_mallocz(ctx, sizeof(*f));
    if (!f) return JS_EXCEPTION;
    f->fn = fn; f->inst = mi;

    JSValue fo = JS_NewObjectClass(ctx, js_fn_cls);
    if (JS_IsException(fo)) { js_free(ctx, f); return fo; }
    JS_SetOpaque(fo, f);

    JSValue data[2] = { fo, iobj };
    JSValue w = JS_NewCFunctionData(ctx, fn_call, 0, 0, 2, data);
    JS_FreeValue(ctx, fo);
    return w;
}

static void tbl_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmTable *t = JS_GetOpaque(val, js_tbl_cls);
    if (!t) return;
    if (t->elems) {
        for (uint32_t i = 0; i < t->size; i++) JS_FreeValueRT(rt, t->elems[i]);
        js_free_rt(rt, t->elems);
    }
    if (t->from_wasm)
        JS_FreeValueRT(rt, t->inst_ref);
    js_free_rt(rt, t);
}

static void tbl_gc_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mf) {
    JSWasmTable *t = JS_GetOpaque(val, js_tbl_cls);
    if (t && t->from_wasm && !JS_IsUndefined(t->inst_ref))
        JS_MarkValue(rt, t->inst_ref, mf);
}

static JSClassDef js_tbl_classdef = {
    "Table",
    .finalizer = tbl_finalizer,
    .gc_mark   = tbl_gc_mark,
};

static JSValue tbl_ctor(JSContext *ctx, JSValue nt, int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0]))
        return JS_ThrowTypeError(ctx, "Descriptor must be an object");

    JSValue etv = JS_GetPropertyStr(ctx, argv[0], "element");
    const char *ets = JS_ToCString(ctx, etv);
    JS_FreeValue(ctx, etv);
    if (!ets || strcmp(ets, "anyfunc")) {
        JS_FreeCString(ctx, ets);
        return JS_ThrowTypeError(ctx, "element must be \"anyfunc\"");
    }
    JS_FreeCString(ctx, ets);

    JSValue iv = JS_GetPropertyStr(ctx, argv[0], "initial");
    uint32_t init;
    if (JS_ToUint32(ctx, &init, iv)) { JS_FreeValue(ctx, iv); return JS_EXCEPTION; }
    JS_FreeValue(ctx, iv);

    uint32_t max = UINT32_MAX; bool has_max = false;
    JSValue  mv  = JS_GetPropertyStr(ctx, argv[0], "maximum");
    if (!JS_IsUndefined(mv)) {
        if (JS_ToUint32(ctx, &max, mv) || max < init) {
            JS_FreeValue(ctx, mv); return wasm_err(ctx, "RangeError", "Invalid maximum");
        }
        has_max = true;
    }
    JS_FreeValue(ctx, mv);

    JSValue      obj = JS_NewObjectClass(ctx, js_tbl_cls);
    if (JS_IsException(obj)) return obj;
    JSWasmTable *t = js_mallocz(ctx, sizeof(*t));
    if (!t) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    JS_SetOpaque(obj, t);

    t->max     = max;
    t->has_max = has_max;
    t->size    = init;
    if (init > 0) {
        t->elems = js_mallocz(ctx, init * sizeof(JSValue));
        if (!t->elems) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
        JSValue fill = argc > 1 ? argv[1] : JS_NULL;
        for (uint32_t i = 0; i < init; i++) t->elems[i] = JS_DupValue(ctx, fill);
    }
    return obj;
}

static JSValue tbl_length_get(JSContext *ctx, JSValue tv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, tv, js_tbl_cls);
    return t ? JS_NewUint32(ctx, t->size) : JS_ThrowTypeError(ctx, "Invalid Table");
}

static JSValue tbl_get(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, tv, js_tbl_cls);
    if (!t) return JS_ThrowTypeError(ctx, "Invalid Table");
    uint32_t idx;
    if (JS_ToUint32(ctx, &idx, argv[0]) || idx >= t->size)
        return wasm_err(ctx, "RangeError", "Index out of bounds");

    if (t->from_wasm) {
        JSWasmInstance *inst = JS_GetOpaque(t->inst_ref, js_inst_cls);
        if (!inst) return JS_NULL;
        wasm_function_inst_t fn =
            wasm_table_get_func_inst(inst->inst, &t->wasm_ti, idx);
        if (!fn) return JS_NULL;
        return wrap_func(ctx, fn, inst->inst, t->inst_ref);
    }
    return JS_DupValue(ctx, t->elems[idx]);
}

static JSValue tbl_set(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, tv, js_tbl_cls);
    if (!t) return JS_ThrowTypeError(ctx, "Invalid Table");
    if (t->from_wasm)
        return JS_ThrowTypeError(ctx, "Cannot set on wasm-exported Table");
    uint32_t idx;
    if (JS_ToUint32(ctx, &idx, argv[0]) || idx >= t->size)
        return wasm_err(ctx, "RangeError", "Index out of bounds");
    JS_FreeValue(ctx, t->elems[idx]);
    t->elems[idx] = JS_DupValue(ctx, argc > 1 ? argv[1] : JS_NULL);
    return JS_UNDEFINED;
}

static JSValue tbl_grow(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    JSWasmTable *t = JS_GetOpaque2(ctx, tv, js_tbl_cls);
    if (!t) return JS_ThrowTypeError(ctx, "Invalid Table");
    if (t->from_wasm)
        return JS_ThrowTypeError(ctx, "Cannot grow wasm-exported Table");
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing delta");
    uint32_t delta;
    if (JS_ToUint32(ctx, &delta, argv[0])) return JS_EXCEPTION;

    uint32_t old  = t->size;
    uint64_t newn = (uint64_t)old + delta;
    if (newn > t->max || newn > UINT32_MAX) return JS_NewInt32(ctx, -1);

    uint32_t nsz  = (uint32_t)newn;
    JSValue *ne   = js_realloc(ctx, t->elems, nsz * sizeof(JSValue));
    if (!ne && nsz > 0) return JS_NewInt32(ctx, -1);
    JSValue fill  = argc > 1 ? argv[1] : JS_NULL;
    for (uint32_t i = old; i < nsz; i++) ne[i] = JS_DupValue(ctx, fill);
    t->elems = ne;
    t->size  = nsz;
    return JS_NewUint32(ctx, old);
}

/* ------------------------------------------------------------------ */
/* WasmGlobal                                                              */
/* ------------------------------------------------------------------ */

static void glb_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmGlobal *g = JS_GetOpaque(val, js_glb_cls);
    if (!g) return;
    if (JS_IsUndefined(g->inst_ref))
        js_free_rt(rt, g->data_ptr);   /* standalone: we own the storage */
    JS_FreeValueRT(rt, g->inst_ref);
    js_free_rt(rt, g);
}

static void glb_gc_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mf) {
    JSWasmGlobal *g = JS_GetOpaque(val, js_glb_cls);
    if (g && !JS_IsUndefined(g->inst_ref))
        JS_MarkValue(rt, g->inst_ref, mf);
}

static JSClassDef js_glb_classdef = {
    "Global",
    .finalizer = glb_finalizer,
    .gc_mark   = glb_gc_mark,
};

static wasm_valkind_t parse_valtype(const char *s) {
    if (!s)              return 255;
    if (!strcmp(s, "i32")) return WASM_I32;
    if (!strcmp(s, "i64")) return WASM_I64;
    if (!strcmp(s, "f32")) return WASM_F32;
    if (!strcmp(s, "f64")) return WASM_F64;
    return 255;
}

static JSValue glb_ctor(JSContext *ctx, JSValue nt, int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0]))
        return JS_ThrowTypeError(ctx, "Descriptor must be an object");

    JSValue     tv  = JS_GetPropertyStr(ctx, argv[0], "value");
    const char *ts  = JS_ToCString(ctx, tv);
    JS_FreeValue(ctx, tv);
    wasm_valkind_t type = parse_valtype(ts);
    JS_FreeCString(ctx, ts);
    if (type == 255) return JS_ThrowTypeError(ctx, "Invalid value type");

    JSValue muv = JS_GetPropertyStr(ctx, argv[0], "mutable");
    bool mutable_ = JS_ToBool(ctx, muv);
    JS_FreeValue(ctx, muv);

    JSValue      obj = JS_NewObjectClass(ctx, js_glb_cls);
    if (JS_IsException(obj)) return obj;
    JSWasmGlobal *g  = js_mallocz(ctx, sizeof(*g));
    if (!g) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    JS_SetOpaque(obj, g);

    g->type     = type;
    g->mutable_ = mutable_;
    g->inst_ref = JS_UNDEFINED;
    /* standalone Global: allocate 8-byte storage for the value */
    g->data_ptr = js_mallocz(ctx, 8);
    if (!g->data_ptr) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    if (argc > 1) {
        wasm_val_t v = {0};
        if (js_to_val(ctx, argv[1], type, &v)) {
            JS_FreeValue(ctx, obj);
            return JS_ThrowTypeError(ctx, "Invalid initial value");
        }
        memcpy(g->data_ptr, &v.of, 8);
    }
    return obj;
}

static JSValue glb_value_get(JSContext *ctx, JSValue tv) {
    JSWasmGlobal *g = JS_GetOpaque2(ctx, tv, js_glb_cls);
    if (!g) return JS_ThrowTypeError(ctx, "Invalid Global");
    wasm_val_t v = { .kind = g->type };
    memcpy(&v.of, g->data_ptr, 8);   /* live read from data_ptr */
    return val_to_js(ctx, g->type, &v);
}

static JSValue glb_value_set(JSContext *ctx, JSValue tv, JSValue val) {
    JSWasmGlobal *g = JS_GetOpaque2(ctx, tv, js_glb_cls);
    if (!g) return JS_ThrowTypeError(ctx, "Invalid Global");
    if (!g->mutable_) return JS_ThrowTypeError(ctx, "Immutable global");
    wasm_val_t v = {0};
    if (js_to_val(ctx, val, g->type, &v)) return JS_EXCEPTION;
    memcpy(g->data_ptr, &v.of, 8);   /* live write to data_ptr */
    return JS_UNDEFINED;
}

static JSValue glb_valueof(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    (void)argc; (void)argv;
    return glb_value_get(ctx, tv);
}

/* ------------------------------------------------------------------ */
/* WasmFunc                                                             */
/* ------------------------------------------------------------------ */

static void fn_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmFunc *f = JS_GetOpaque(val, js_fn_cls);
    if (f) js_free_rt(rt, f);
}
static JSClassDef js_fn_classdef = { "Func", .finalizer = fn_finalizer };

/* ------------------------------------------------------------------ */
/* WasmInstance                                                         */
/* ------------------------------------------------------------------ */

static void inst_finalizer(JSRuntime *rt, JSValue val) {
    JSWasmInstance *i = JS_GetOpaque(val, js_inst_cls);
    if (!i) return;
    for (uint32_t j = 0; j < i->imp.count; j++)
        if (!JS_IsUndefined(i->imp.entries[j].js_fn))
            JS_FreeValueRT(rt, i->imp.entries[j].js_fn);
    if (i->exec_env) wasm_runtime_destroy_exec_env(i->exec_env);
    if (i->inst)     wasm_runtime_deinstantiate(i->inst);
    JS_FreeValueRT(rt, i->mod_ref);
    js_free_rt(rt, i);
}

static void inst_gc_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mf) {
    JSWasmInstance *i = JS_GetOpaque(val, js_inst_cls);
    if (!i) return;
    JS_MarkValue(rt, i->mod_ref, mf);
    for (uint32_t j = 0; j < i->imp.count; j++)
        if (!JS_IsUndefined(i->imp.entries[j].js_fn))
            JS_MarkValue(rt, i->imp.entries[j].js_fn, mf);
}

static JSClassDef js_inst_classdef = {
    "Instance",
    .finalizer = inst_finalizer,
    .gc_mark   = inst_gc_mark,
};

static JSValue build_exports(JSContext *ctx, JSWasmInstance *inst, JSValue iobj) {
    JSValue exports = JS_NewObject(ctx);
    if (JS_IsException(exports)) return exports;

    uint32_t total = wasm_runtime_get_export_count(inst->mod);
    for (uint32_t i = 0; i < total; i++) {
        wasm_export_t exp;
        wasm_runtime_get_export_type(inst->mod, i, &exp);

        if (exp.kind == WEXT_FUNC) {
            wasm_function_inst_t fn =
                wasm_runtime_lookup_function(inst->inst, exp.name);
            if (!fn) continue;
            JSValue w = wrap_func(ctx, fn, inst->inst, iobj);
            if (JS_IsException(w)) { JS_FreeValue(ctx, exports); return w; }
            JS_DefinePropertyValueStr(ctx, exports, exp.name, w, JS_PROP_C_W_E);

        } else if (exp.kind == WEXT_MEM) {
            JSValue mo = JS_NewObjectClass(ctx, js_mem_cls);
            if (JS_IsException(mo)) continue;
            JSWasmMemory *mem = js_mallocz(ctx, sizeof(*mem));
            if (!mem) { JS_FreeValue(ctx, mo); continue; }
            mem->inst  = inst->inst;
            mem->owned = false;
            JS_SetOpaque(mo, mem);
            JS_DefinePropertyValueStr(ctx, exports, exp.name, mo, JS_PROP_C_W_E);

        } else if (exp.kind == WEXT_GLOBAL) {
            wasm_global_inst_t gi;
            if (!wasm_runtime_get_export_global_inst(inst->inst, exp.name, &gi))
                continue;
            JSValue go = JS_NewObjectClass(ctx, js_glb_cls);
            if (JS_IsException(go)) continue;
            JSWasmGlobal *g = js_mallocz(ctx, sizeof(*g));
            if (!g) { JS_FreeValue(ctx, go); continue; }
            g->type     = gi.kind;
            g->mutable_ = gi.is_mutable;
            g->data_ptr = gi.global_data;    /* live pointer into wasm instance */
            g->inst_ref = JS_DupValue(ctx, iobj); /* keep instance alive */
            JS_SetOpaque(go, g);
            JS_DefinePropertyValueStr(ctx, exports, exp.name, go, JS_PROP_C_W_E);

        } else if (exp.kind == WEXT_TABLE) {
            wasm_table_inst_t ti;
            if (!wasm_runtime_get_export_table_inst(inst->inst, exp.name, &ti))
                continue;
            JSValue to = JS_NewObjectClass(ctx, js_tbl_cls);
            if (JS_IsException(to)) continue;
            /* Exported table: read-only wrapper around WAMR table.
             * set/grow are not supported (no WAMR write API). */
            JSWasmTable *t = js_mallocz(ctx, sizeof(*t));
            if (!t) { JS_FreeValue(ctx, to); continue; }
            t->size    = ti.cur_size;
            t->max     = ti.max_size;
            t->has_max = (ti.max_size != UINT32_MAX);
            /* elems: wrap each wasm func as JSWasmFunc on demand in tbl_get */
            t->wasm_ti   = ti;           /* store snapshot of table inst */
            t->inst_ref  = JS_DupValue(ctx, iobj);
            t->from_wasm = true;
            JS_SetOpaque(to, t);
            JS_DefinePropertyValueStr(ctx, exports, exp.name, to, JS_PROP_C_W_E);
        }
    }
    return exports;
}

static JSValue inst_ctor(JSContext *ctx, JSValue nt, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing module");
    JSWasmModule *m = JS_GetOpaque2(ctx, argv[0], js_mod_cls);
    if (!m || !m->mod) return JS_ThrowTypeError(ctx, "Invalid Module");

    JSValue obj = JS_NewObjectClass(ctx, js_inst_cls);
    if (JS_IsException(obj)) return obj;

    JSWasmInstance *inst = js_mallocz(ctx, sizeof(*inst));
    if (!inst) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    JS_SetOpaque(obj, inst);

    inst->mod_ref = JS_DupValue(ctx, argv[0]);  /* keep Module alive */
    inst->mod     = m->mod;
    inst->ctx     = ctx;

    /* Parse imports and resolve JS callbacks */
    parse_imports(m->mod, &inst->imp);
    for (uint32_t i = 0; i < inst->imp.count; i++) {
        ImportEntry *e = &inst->imp.entries[i];
        e->ctx    = ctx;
        e->js_fn  = JS_UNDEFINED;
        if (argc > 1 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
            JSValue mo = JS_GetPropertyStr(ctx, argv[1], e->mod);
            if (!JS_IsUndefined(mo) && !JS_IsNull(mo)) {
                JSValue fn = JS_GetPropertyStr(ctx, mo, e->name);
                if (JS_IsFunction(ctx, fn)) e->js_fn = fn;
                else JS_FreeValue(ctx, fn);
            }
            JS_FreeValue(ctx, mo);
        }
    }

    /* Register raw natives, resolve symbols, then instantiate.
     * Order matters: register_natives_raw must precede resolve_symbols. */
    build_syms(&inst->imp);
    if (!register_natives(&inst->imp)) {
        JS_FreeValue(ctx, obj);
        return wasm_err(ctx, "LinkError", "Failed to register native symbols");
    }
    if (!wasm_runtime_resolve_symbols(m->mod)) {
        JS_FreeValue(ctx, obj);
        return wasm_err(ctx, "LinkError", "Symbol resolution failed");
    }
    char err[WASM_ERR_SZ];
    inst->inst = wasm_runtime_instantiate(m->mod, WASM_STACK_SIZE, WASM_HEAP_SIZE,
                                          err, sizeof(err));
    if (!inst->inst) { JS_FreeValue(ctx, obj); return wasm_err(ctx, "LinkError", err); }
    if (!inst->inst) { JS_FreeValue(ctx, obj); return wasm_err(ctx, "LinkError", err); }

    inst->exec_env = wasm_runtime_create_exec_env(inst->inst, WASM_STACK_SIZE);
    if (!inst->exec_env) {
        JS_FreeValue(ctx, obj);
        return wasm_err(ctx, "RuntimeError", "create_exec_env failed");
    }
    wasm_runtime_set_user_data(inst->exec_env, inst);
    return obj;
}

static JSValue inst_exports_get(JSContext *ctx, JSValue tv) {
    JSWasmInstance *inst = JS_GetOpaque2(ctx, tv, js_inst_cls);
    if (!inst) return JS_ThrowTypeError(ctx, "Invalid Instance");
    return build_exports(ctx, inst, tv);
}

/* ------------------------------------------------------------------ */
/* Top-level WebAssembly.compile / instantiate / validate              */
/* ------------------------------------------------------------------ */

static JSValue wasm_compile(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    (void)tv;
    return mod_ctor(ctx, JS_UNDEFINED, argc, argv);
}

static JSValue wasm_instantiate(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    (void)tv;
    if (argc < 1) return JS_ThrowTypeError(ctx, "Missing argument");

    bool from_buf  = !JS_GetOpaque(argv[0], js_mod_cls);
    JSValue module = from_buf ? mod_ctor(ctx, JS_UNDEFINED, 1, argv)
                              : JS_DupValue(ctx, argv[0]);
    if (JS_IsException(module)) return module;

    JSValue ia[2]  = { module, argc > 1 ? argv[1] : JS_UNDEFINED };
    JSValue inst   = inst_ctor(ctx, JS_UNDEFINED, 2, ia);
    JS_FreeValue(ctx, module);

    if (JS_IsException(inst)) return inst;

    if (from_buf) {
        /* Re-dup module for the result object (we freed it above) */
        JSValue rmod = mod_ctor(ctx, JS_UNDEFINED, 1, argv);
        JSValue res  = JS_NewObject(ctx);
        JS_DefinePropertyValueStr(ctx, res, "module",   rmod, JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, res, "instance", inst, JS_PROP_C_W_E);
        return res;
    }
    return inst;
}

static JSValue wasm_validate(JSContext *ctx, JSValue tv, int argc, JSValue *argv) {
    (void)tv;
    if (argc < 1) return JS_FALSE;
    size_t   size;
    uint8_t *buf = get_buf(ctx, argv[0], &size);
    if (!buf || size < 8 || buf[0] != 0x00 || buf[1] != 0x61 ||
        buf[2] != 0x73 || buf[3] != 0x6d) return JS_FALSE;
    char          err[WASM_ERR_SZ];
    wasm_module_t mod = wasm_runtime_load(buf, (uint32_t)size, err, sizeof(err));
    if (!mod) return JS_FALSE;
    wasm_runtime_unload(mod);
    return JS_TRUE;
}

/* ------------------------------------------------------------------ */
/* Proto / function tables and init                                     */
/* ------------------------------------------------------------------ */

static const JSCFunctionListEntry js_mod_statics[] = {
    TJS_CFUNC_DEF("exports", 1, mod_exports),
    TJS_CFUNC_DEF("imports", 1, mod_imports),
};
static const JSCFunctionListEntry js_inst_proto[] = {
    TJS_CGETSET_DEF("exports", inst_exports_get, NULL),
};
static const JSCFunctionListEntry js_mem_proto[] = {
    TJS_CGETSET_DEF("buffer", mem_buffer_get, NULL),
    TJS_CGETSET_DEF("shared", mem_shared_get, NULL),
    TJS_CFUNC_DEF("grow", 1, mem_grow),
};
static const JSCFunctionListEntry js_tbl_proto[] = {
    TJS_CGETSET_DEF("length", tbl_length_get, NULL),
    TJS_CFUNC_DEF("get",  1, tbl_get),
    TJS_CFUNC_DEF("set",  2, tbl_set),
    TJS_CFUNC_DEF("grow", 1, tbl_grow),
};
static const JSCFunctionListEntry js_glb_proto[] = {
    TJS_CGETSET_DEF("value", glb_value_get, glb_value_set),
    TJS_CFUNC_DEF("valueOf", 0, glb_valueof),
};

/* Register a class with prototype functions */
#define REGCLS(cname, cvar, cdef, protos, ctor, argc) do {              \
    JS_NewClassID(rt, &(cvar));                                          \
    JS_NewClass(rt, (cvar), &(cdef));                                   \
    JSValue _p = JS_NewObject(ctx);                                     \
    JS_SetPropertyFunctionList(ctx, _p, protos, countof(protos));       \
    JS_SetClassProto(ctx, (cvar), _p);                                  \
    JSValue _c = JS_NewCFunction2(ctx, ctor, cname, argc,               \
                                  JS_CFUNC_constructor, 0);             \
    JS_DefinePropertyValueStr(ctx, ns, cname, _c, JS_PROP_C_W_E);      \
} while (0)

/* Register a class without prototype functions */
#define REGCLS_BARE(cname, cvar, cdef, ctor, argc) do {                 \
    JS_NewClassID(rt, &(cvar));                                          \
    JS_NewClass(rt, (cvar), &(cdef));                                   \
    JSValue _p = JS_NewObject(ctx);                                     \
    JS_SetClassProto(ctx, (cvar), _p);                                  \
    JSValue _c = JS_NewCFunction2(ctx, ctor, cname, argc,               \
                                  JS_CFUNC_constructor, 0);             \
    JS_DefinePropertyValueStr(ctx, ns, cname, _c, JS_PROP_C_W_E);      \
} while (0)

void tjs__mod_wasm_init(JSContext *ctx, JSValue ns) {
    JSRuntime  *rt  = JS_GetRuntime(ctx);

    REGCLS_BARE("Module",   js_mod_cls,  js_mod_classdef,  mod_ctor,  1);
    REGCLS("Instance", js_inst_cls, js_inst_classdef, js_inst_proto, inst_ctor, 1);
    REGCLS("Memory",   js_mem_cls,  js_mem_classdef,  js_mem_proto,  mem_ctor,  1);
    REGCLS("Table",    js_tbl_cls,  js_tbl_classdef,  js_tbl_proto,  tbl_ctor,  1);
    REGCLS("Global",   js_glb_cls,  js_glb_classdef,  js_glb_proto,  glb_ctor,  1);

    /* Module static methods */
    JSValue mc = JS_GetPropertyStr(ctx, ns, "Module");
    JS_SetPropertyFunctionList(ctx, mc, js_mod_statics, countof(js_mod_statics));
    JS_FreeValue(ctx, mc);

    /* Func is internal only (not a constructor exposed to JS) */
    JS_NewClassID(rt, &js_fn_cls);
    JS_NewClass(rt, js_fn_cls, &js_fn_classdef);

    #define DEF_FN(name, fn, n) \
        JS_DefinePropertyValueStr(ctx, ns, name, \
            JS_NewCFunction(ctx, fn, name, n), JS_PROP_C_W_E)
    DEF_FN("compile",     wasm_compile,     1);
    DEF_FN("instantiate", wasm_instantiate, 1);
    DEF_FN("validate",    wasm_validate,    1);
    #undef DEF_FN
}