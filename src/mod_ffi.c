/*
 * circu.js
 *
 * Copyright (c) 2024-present Saúl Ibarra Corretgé <s@saghul.net>
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

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "private.h"
#include "mem.h"
#include "capability.h"
#include <errno.h>
#include <ffi.h>
#include <limits.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(__linux__)
#include <dlfcn.h>
#endif

typedef struct FfiType FfiType;
typedef struct FfiLibrary FfiLibrary;
typedef struct FfiLibraryState FfiLibraryState;
typedef struct FfiCallback FfiCallback;
typedef struct FfiBound FfiBound;
typedef struct FfiBindCache FfiBindCache;
typedef struct FfiCleanupNode FfiCleanupNode;

static thread_local JSClassID type_class, pointer_class, owned_class;
static thread_local JSClassID library_class, bound_class, callback_class;
static thread_local int last_errno;

typedef enum { CLEANUP_STATE_UNREF, CLEANUP_DISPOSE } CleanupKind;

struct FfiCleanupNode {
    FfiCleanupNode *next;
    CleanupKind kind;
};

typedef enum {
    K_VOID, K_BOOL, K_I8, K_U8, K_I16, K_U16, K_I32, K_U32, K_I64, K_U64,
    K_F32, K_F64, K_LONG_DOUBLE, K_POINTER, K_BUFFER, K_FUNCTION, K_AGGREGATE,
} TypeKind;

struct FfiType {
    ffi_type *ffi;
    TypeKind kind;
    bool dynamic, array;
    size_t count, *offsets;
    JSValue *deps;
};

typedef struct {
    void *addr;
    JSValue owner;
    /* Weak back-ref: owner chain gc_marked; GC frees after all finalizers. */
    JSValue pinned_backing;
    FfiLibraryState *state;
    FfiCallback *callback;
    bool valid;
} FfiPointer;

struct FfiLibraryState {
    FfiCleanupNode cleanup;
    uv_lib_t handle;
    int *(*errno_location)(void);
    size_t refs, pending_unrefs;
    size_t owned_holds;
    size_t active_calls;
    bool handle_open, closed, cleanup_queued;
};

struct FfiLibrary {
    FfiLibraryState *state;
    FfiBindCache *cache;
    bool closed;
};

typedef struct {
    ffi_cif cif;
    ffi_type **arg_types;
    FfiType **types;
    JSValue *type_values;
    size_t *offsets, frame_offset, frame_size;
    unsigned nargs;
    int fixed;
} FfiSignature;

struct FfiBound {
    FfiSignature sig;
    void *addr;
    void *call_storage;
    uint8_t *result_storage;
    size_t call_storage_size, result_storage_size, pin_values_offset;
    size_t callback_values_offset, callback_counts_offset;
    JSValue owner;
    FfiLibraryState *state;
    FfiCallback *callback;
    bool in_call;
};

struct FfiBindCache {
    FfiBindCache *next;
    char *symbol;
    JSValue bound;
};

struct FfiCallback {
    FfiSignature sig;
    ffi_closure *closure;
    void *code;
    JSValue function;
    JSContext *ctx;
    uv_thread_t thread;
    atomic_uint_fast64_t foreign_calls;
    atomic_bool foreign_reported;
    bool closed;
};

typedef struct {
    FfiCleanupNode cleanup;
    void *resource_addr, *disposer_addr;
    ffi_cif cif;
    ffi_type *arg_types[1];
    FfiLibraryState *state, *resource_state;
} FfiDisposeJob;

typedef struct {
    FfiPointer pointer;
    FfiDisposeJob *job;
    bool armed;
} OwnedPointer;

typedef struct CallFrame {
    struct CallFrame *previous;
    JSValue exception;
} CallFrame;
static thread_local CallFrame *active_call;

static const char *status_name(ffi_status status) {
    switch (status) {
        case FFI_OK: return "FFI_OK";
        case FFI_BAD_TYPEDEF: return "FFI_BAD_TYPEDEF";
        case FFI_BAD_ABI: return "FFI_BAD_ABI";
        case FFI_BAD_ARGTYPE: return "FFI_BAD_ARGTYPE";
        default: return "unknown libffi error";
    }
}
static size_t type_size(FfiType *t) {
    return t->kind == K_VOID ? 0 : t->ffi->size;
}
static bool pointer_kind(FfiType *t) {
    return t->kind == K_POINTER || t->kind == K_BUFFER || t->kind == K_FUNCTION;
}
static bool narrow_kind(FfiType *t) {
    return t->ffi->size < sizeof(ffi_arg) && t->kind >= K_BOOL && t->kind <= K_U32;
}
static bool size_add(size_t *value, size_t addend) {
    if (*value > SIZE_MAX - addend) return false;
    *value += addend;
    return true;
}
static bool size_mul(size_t left, size_t right, size_t *result) {
    if (left != 0 && right > SIZE_MAX / left) return false;
    *result = left * right;
    return true;
}
static bool size_align(size_t *value, size_t alignment) {
    size_t remainder = alignment > 1 ? *value % alignment : 0;
    return !remainder || size_add(value, alignment - remainder);
}
static void capture_errno(FfiLibraryState *state) {
    last_errno = state && state->errno_location ? *state->errno_location() : errno;
}
static int strict_integer(JSContext *ctx, JSValueConst value, int64_t *result, const char *name) {
    double number;
    if (!JS_IsNumber(value) || JS_ToFloat64(ctx, &number, value) < 0)
        return JS_ThrowTypeError(ctx, "%s must be an integer", name), -1;
    if (!isfinite(number) || trunc(number) != number ||
        number < -9007199254740991.0 || number > 9007199254740991.0) {
        return JS_ThrowRangeError(ctx, "%s must be a safe integer", name), -1;
    }
    *result = (int64_t) number;
    return 0;
}

/* Preserve the original glibc dlmopen namespace, with ordinary libuv loading
 * on musl, macOS and Windows. */
#if defined(__linux__) && defined(__GLIBC__)
static uv_once_t loader_once = UV_ONCE_INIT;
static uv_mutex_t loader_mutex;
static bool loader_has_lmid;
static Lmid_t loader_lmid;
static size_t loader_refs;
static void loader_init(void) {
    uv_mutex_init(&loader_mutex);
}
static int ffi_dlopen(const char *name, uv_lib_t *lib, const char **error) {
    uv_once(&loader_once, loader_init);
    uv_mutex_lock(&loader_mutex);
    dlerror();
    lib->errmsg = NULL;
    Lmid_t lmid = loader_has_lmid ? loader_lmid : LM_ID_NEWLM;
    lib->handle = dlmopen(lmid, name, RTLD_LAZY | RTLD_LOCAL);
    if (!lib->handle) {
        *error = dlerror();
        uv_mutex_unlock(&loader_mutex);
        return -1;
    }
    if (loader_has_lmid) {
        loader_refs++;
    } else if (dlinfo(lib->handle, RTLD_DI_LMID, &loader_lmid) != 0) {
        *error = dlerror();
        dlclose(lib->handle);
        lib->handle = NULL;
        uv_mutex_unlock(&loader_mutex);
        return -1;
    } else {
        loader_has_lmid = true;
        loader_refs = 1;
    }
    uv_mutex_unlock(&loader_mutex);
    return 0;
}
static void ffi_dlclose(uv_lib_t *lib) {
    uv_once(&loader_once, loader_init);
    uv_mutex_lock(&loader_mutex);
    uv_dlclose(lib);
    if (loader_refs) loader_refs--;
    if (!loader_refs) {
        loader_has_lmid = false;
        loader_lmid = LM_ID_BASE;
    }
    uv_mutex_unlock(&loader_mutex);
}
#else
static int ffi_dlopen(const char *name, uv_lib_t *lib, const char **error) {
    int result = uv_dlopen(name, lib);
    *error = result ? uv_dlerror(lib) : NULL;
    return result;
}
static void ffi_dlclose(uv_lib_t *lib) {
    uv_dlclose(lib);
}
#endif

static void state_maybe_unload(FfiLibraryState *state) {
    if (state && state->handle_open && state->closed && state->owned_holds == 0 && state->active_calls == 0) {
        ffi_dlclose(&state->handle);
        state->handle_open = false;
    }
}
static void state_ref(FfiLibraryState *state) {
    if (state) state->refs++;
}
static void state_unref(FfiLibraryState *state) {
    if (!state) return;
    assert(state->refs > 0);
    state->refs--;
    if (!state->refs) state->closed = true;
    state_maybe_unload(state);
    if (!state->refs) {
        assert(!state->handle_open);
        tjs__free(state);
    }
}
static void state_owned_ref(FfiLibraryState *state) {
    if (!state) return;
    state_ref(state);
    state->owned_holds++;
}
static void state_owned_unref(FfiLibraryState *state) {
    if (!state) return;
    assert(state->owned_holds > 0);
    state->owned_holds--;
    state_unref(state);
}
static void cleanup_enqueue(TJSRuntime *trt, FfiCleanupNode *node) {
    node->next = trt->ffi_cleanup;
    trt->ffi_cleanup = node;
}
static void state_defer_unref(JSRuntime *rt, FfiLibraryState *state) {
    if (!state) return;
    state->pending_unrefs++;
    if (!state->cleanup_queued) {
        state->cleanup_queued = true;
        cleanup_enqueue(JS_GetRuntimeOpaque(rt), &state->cleanup);
    }
}
static void dispose_job_run(FfiDisposeJob *job, bool capture) {
    void *resource = job->resource_addr;
    void *args[] = { &resource };
    if (job->state) job->state->active_calls++;
    ffi_call(&job->cif, FFI_FN(job->disposer_addr), NULL, args);
    if (capture) capture_errno(job->state);
    if (job->state) {
        assert(job->state->active_calls > 0);
        job->state->active_calls--;
    }
    state_owned_unref(job->resource_state);
    state_owned_unref(job->state);
    tjs__free(job);
}
static thread_local bool cleanup_draining;
void tjs__mod_ffi_drain_runtime(TJSRuntime *trt) {
    if (!trt || cleanup_draining) return;
    cleanup_draining = true;
    FfiCleanupNode *node;
    while ((node = trt->ffi_cleanup) != NULL) {
        trt->ffi_cleanup = node->next;
        if (node->kind == CLEANUP_DISPOSE) {
            dispose_job_run((FfiDisposeJob *)node, false);
        } else {
            FfiLibraryState *state = (FfiLibraryState *)node;
            state->cleanup_queued = false;
            size_t count = state->pending_unrefs;
            state->pending_unrefs = 0;
            while (count--) state_unref(state);
        }
    }
    cleanup_draining = false;
}

/* Pointer objects */
static FfiPointer *get_pointer(JSValueConst value);
static int pointer_check(JSContext *ctx, FfiPointer *p) {
    if (!p || !p->valid)
        return JS_ThrowTypeError(ctx, "pointer is closed or released"), -1;
    if (p->state && p->state->closed)
        return JS_ThrowTypeError(ctx, "pointer belongs to a closed library"), -1;
    if (p->callback && p->callback->closed)
        return JS_ThrowTypeError(ctx, "pointer belongs to a closed callback"), -1;
    /* Derived ptrs chain to their source: close/release invalidates them. */
    if (!JS_IsUndefined(p->owner)) {
        FfiPointer *owner = get_pointer(p->owner);
        if (owner && pointer_check(ctx, owner) < 0) return -1;
    }
    return 0;
}
static FfiPointer *get_pointer(JSValueConst value) {
    FfiPointer *p = JS_GetOpaque(value, pointer_class);
    if (p) return p;
    OwnedPointer *owned = JS_GetOpaque(value, owned_class);
    return owned ? &owned->pointer : NULL;
}
static FfiPointer *require_pointer(JSContext *ctx, JSValueConst value) {
    FfiPointer *p = get_pointer(value);
    if (!p) return JS_ThrowTypeError(ctx, "expected an FFI Pointer"), NULL;
    return pointer_check(ctx, p) < 0 ? NULL : p;
}
static JSValue new_pointer(JSContext *ctx, void *addr, JSValueConst owner,
                           FfiLibraryState *state, FfiCallback *callback) {
    if (!addr) return JS_NULL;
    JSValue obj = JS_NewObjectClass(ctx, pointer_class);
    if (JS_IsException(obj)) return obj;
    FfiPointer *p = js_mallocz(ctx, sizeof(*p));
    if (!p) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    p->addr = addr;
    p->owner = JS_IsUndefined(owner) ? JS_UNDEFINED : JS_DupValue(ctx, owner);
    p->pinned_backing = JS_UNDEFINED;
    p->state = state;
    state_ref(state);
    p->callback = callback;
    p->valid = true;
    JS_SetOpaque(obj, p);
    return obj;
}
static void pointer_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    FfiPointer *p = JS_GetOpaque(value, pointer_class);
    if (p && !JS_IsUndefined(p->owner)) JS_MarkValue(rt, p->owner, mark);
}
static void pointer_finalizer(JSRuntime *rt, JSValueConst value) {
    FfiPointer *p = JS_GetOpaque(value, pointer_class);
    if (!p) return;
    if (JS_IsLiveObject(rt, p->pinned_backing))
        JS_UnpinArrayBuffer(p->pinned_backing);
    state_defer_unref(rt, p->state);
    JS_FreeValueRT(rt, p->owner);
    js_free_rt(rt, p);
}
static JSClassDef pointer_def = {
    "Pointer",
    .finalizer = pointer_finalizer,
    .gc_mark = pointer_mark,
};

/* Scalar and aggregate conversion */
static int pointer_native(JSContext *ctx, JSValueConst value, void **out) {
    if (JS_IsNull(value)) {
        *out = NULL;
        return 0;
    }
    FfiPointer *p = require_pointer(ctx, value);
    if (!p) return -1;
    *out = p->addr;
    return 0;
}
static int exact_number(JSContext *ctx, JSValueConst value, double minimum,
                        double maximum, double *out) {
    double v;
    if (!JS_IsNumber(value) || JS_ToFloat64(ctx, &v, value) < 0)
        return JS_ThrowTypeError(ctx, "expected number"), -1;
    if (!isfinite(v) || trunc(v) != v || v < minimum || v > maximum)
        return JS_ThrowRangeError(ctx, "integer is outside the C type range"), -1;
    *out = v;
    return 0;
}
static int exact_bigint(JSContext *ctx, JSValueConst value, bool is_signed,
                        unsigned bits, uint64_t *out) {
    if (!JS_IsBigInt(value)) return JS_ThrowTypeError(ctx, "expected bigint"), -1;
    int negative = 0;
    size_t count = 2;
    uint64_t words[2] = { 0, 0 };
    if (JS_GetBigIntWords(ctx, value, &negative, &count, words) < 0) return -1;
    if (count > 2 || (count == 2 && words[1] != 0))
        return JS_ThrowRangeError(ctx, "bigint is outside the C type range"), -1;
    uint64_t word = words[0];
    uint64_t limit = bits == 64 ? UINT64_MAX : ((UINT64_C(1) << bits) - 1);
    if (!is_signed && negative)
        return JS_ThrowRangeError(ctx, "bigint is outside the C type range"), -1;
    if (is_signed) {
        uint64_t positive_max = bits == 64
            ? INT64_MAX
            : ((UINT64_C(1) << (bits - 1)) - 1);
        uint64_t negative_max = UINT64_C(1) << (bits - 1);
        if ((!negative && word > positive_max) || (negative && word > negative_max))
            return JS_ThrowRangeError(ctx, "bigint is outside the C type range"), -1;
        *out = negative ? (uint64_t)(0 - word) : word;
    } else {
        if (word > limit) return JS_ThrowRangeError(ctx, "bigint is outside the C type range"), -1;
        *out = word;
    }
    return 0;
}
static int pack_value(JSContext *ctx, FfiType *t, JSValueConst value, uint8_t *out) {
    switch (t->kind) {
        case K_VOID:
            return JS_ThrowTypeError(ctx, "void is not a value"), -1;
        case K_BOOL: {
            if (!JS_IsBool(value))
                return JS_ThrowTypeError(ctx, "expected boolean"), -1;
            uint8_t converted = (uint8_t)JS_ToBool(ctx, value);
            memcpy(out, &converted, sizeof(converted));
            return 0;
        }
#define PACK_NUMBER(kind, c_type, minimum, maximum) \
        case kind: { \
            double number; \
            if (exact_number(ctx, value, minimum, maximum, &number) < 0) return -1; \
            c_type converted = (c_type)number; \
            memcpy(out, &converted, sizeof(converted)); \
            return 0; \
        }
        PACK_NUMBER(K_I8, int8_t, INT8_MIN, INT8_MAX)
        PACK_NUMBER(K_U8, uint8_t, 0, UINT8_MAX)
        PACK_NUMBER(K_I16, int16_t, INT16_MIN, INT16_MAX)
        PACK_NUMBER(K_U16, uint16_t, 0, UINT16_MAX)
        PACK_NUMBER(K_I32, int32_t, INT32_MIN, INT32_MAX)
        PACK_NUMBER(K_U32, uint32_t, 0, UINT32_MAX)
#undef PACK_NUMBER
        case K_I64:
        case K_U64: {
            uint64_t raw;
            if (exact_bigint(ctx, value, t->kind == K_I64,
                             (unsigned)(t->ffi->size * CHAR_BIT), &raw) < 0)
                return -1;
            if (t->ffi->size == 4) {
                uint32_t converted = (uint32_t)raw;
                memcpy(out, &converted, sizeof(converted));
            } else {
                memcpy(out, &raw, sizeof(raw));
            }
            return 0;
        }
        case K_F32: {
            double value64;
            if (!JS_IsNumber(value)) goto number;
            if (JS_ToFloat64(ctx, &value64, value) < 0) return -1;
            float converted = (float)value64;
            memcpy(out, &converted, sizeof(converted));
            return 0;
        }
        case K_F64: {
            double converted;
            if (!JS_IsNumber(value)) goto number;
            if (JS_ToFloat64(ctx, &converted, value) < 0) return -1;
            memcpy(out, &converted, sizeof(converted));
            return 0;
        }
        case K_LONG_DOUBLE: {
            double value64;
            if (!JS_IsNumber(value)) goto number;
            if (JS_ToFloat64(ctx, &value64, value) < 0) return -1;
            long double converted = (long double)value64;
            memcpy(out, &converted, sizeof(converted));
            return 0;
        }
        case K_POINTER:
        case K_FUNCTION: {
            void *pointer;
            if (pointer_native(ctx, value, &pointer) < 0) return -1;
            memcpy(out, &pointer, sizeof(pointer));
            return 0;
        }
        case K_BUFFER:
            return JS_ThrowTypeError(
                ctx, "buffer is only valid as a function argument"), -1;
        case K_AGGREGATE: {
            if (!JS_IsArray(value))
                return JS_ThrowTypeError(
                    ctx, "expected an array with %zu values", t->count), -1;
            JSValue length_value = JS_GetPropertyStr(ctx, value, "length");
            uint64_t length;
            if (JS_IsException(length_value)) return -1;
            int result = JS_ToIndex(ctx, &length, length_value);
            JS_FreeValue(ctx, length_value);
            if (result < 0) return -1;
            if (length != t->count)
                return JS_ThrowRangeError(
                    ctx, "expected exactly %zu aggregate values", t->count), -1;
            memset(out, 0, type_size(t));
            for (size_t i = 0; i < t->count; i++) {
                JSValue item = JS_GetPropertyUint32(ctx, value, (uint32_t)i);
                if (JS_IsException(item)) return -1;
                result = pack_value(ctx, JS_GetOpaque(t->deps[i], type_class),
                                    item, out + t->offsets[i]);
                JS_FreeValue(ctx, item);
                if (result < 0) return -1;
            }
            return 0;
        }
    }
number:
    return JS_ThrowTypeError(ctx, "expected number"), -1;
}
static JSValue read_value(JSContext *ctx, FfiType *type, const uint8_t *source,
                          JSValueConst owner, FfiLibraryState *state,
                          FfiCallback *callback, bool structured) {
    switch (type->kind) {
        case K_VOID:
            return JS_UNDEFINED;
        case K_BOOL: {
            uint8_t value;
            memcpy(&value, source, sizeof(value));
            return JS_NewBool(ctx, value != 0);
        }
#define READ_INT(kind, c_type, constructor) \
        case kind: { \
            c_type value; \
            memcpy(&value, source, sizeof(value)); \
            return constructor(ctx, value); \
        }
        READ_INT(K_I8, int8_t, JS_NewInt32)
        READ_INT(K_U8, uint8_t, JS_NewInt32)
        READ_INT(K_I16, int16_t, JS_NewInt32)
        READ_INT(K_U16, uint16_t, JS_NewInt32)
        READ_INT(K_I32, int32_t, JS_NewInt32)
        READ_INT(K_U32, uint32_t, JS_NewUint32)
#undef READ_INT
        case K_I64: {
            int64_t value = 0;
            if (type->ffi->size == 4) {
                int32_t narrow;
                memcpy(&narrow, source, sizeof(narrow));
                value = narrow;
            } else {
                memcpy(&value, source, sizeof(value));
            }
            return JS_NewBigInt64(ctx, value);
        }
        case K_U64: {
            uint64_t value = 0;
            if (type->ffi->size == 4) {
                uint32_t narrow;
                memcpy(&narrow, source, sizeof(narrow));
                value = narrow;
            } else {
                memcpy(&value, source, sizeof(value));
            }
            return JS_NewBigUint64(ctx, value);
        }
        case K_F32: {
            float value;
            memcpy(&value, source, sizeof(value));
            return JS_NewFloat64(ctx, value);
        }
        case K_F64: {
            double value;
            memcpy(&value, source, sizeof(value));
            return JS_NewFloat64(ctx, value);
        }
        case K_LONG_DOUBLE: {
            long double value;
            memcpy(&value, source, sizeof(value));
            return JS_NewFloat64(ctx, (double)value);
        }
        case K_POINTER:
        case K_BUFFER:
        case K_FUNCTION: {
            void *pointer;
            memcpy(&pointer, source, sizeof(pointer));
            return new_pointer(ctx, pointer, owner, state, callback);
        }
        case K_AGGREGATE: {
            if (!structured)
                return JS_NewUint8ArrayCopy(ctx, source, type_size(type));
            JSValue array = JS_NewArray(ctx);
            if (JS_IsException(array)) return array;
            for (size_t i = 0; i < type->count; i++) {
                FfiType *element = JS_GetOpaque(type->deps[i], type_class);
                JSValue value = read_value(
                    ctx, element, source + type->offsets[i],
                    JS_UNDEFINED, NULL, NULL, true);
                if (JS_IsException(value) ||
                    JS_SetPropertyUint32(ctx, array, (uint32_t)i, value) < 0) {
                    JS_FreeValue(ctx, array);
                    return JS_EXCEPTION;
                }
            }
            return array;
        }
    }
    return tjs_throw_plain_error(ctx, "unknown FFI type");
}

static JSValue type_pack(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){
    FfiType*t=JS_GetOpaque2(ctx,self,type_class);if(!t)return JS_EXCEPTION;
    if(t->kind!=K_AGGREGATE||argc!=1)return JS_ThrowTypeError(ctx,"pack expects one aggregate value");
    size_t n=type_size(t);uint8_t*b=js_mallocz(ctx,n);if(!b&&n)return JS_EXCEPTION;
    if(pack_value(ctx,t,argv[0],b)<0){js_free(ctx,b);return JS_EXCEPTION;}return TJS_NewUint8Array(ctx,b,n);
}
static JSValue type_unpack(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){
    FfiType*t=JS_GetOpaque2(ctx,self,type_class);if(!t)return JS_EXCEPTION;
    if(t->kind!=K_AGGREGATE||argc!=1)return JS_ThrowTypeError(ctx,"unpack expects one Uint8Array");
    size_t n;
    uint8_t*b=JS_GetUint8Array(ctx,&n,argv[0]);
    if(!b)return JS_ThrowTypeError(ctx,"unpack expects a Uint8Array");
    if(n!=type_size(t))return JS_ThrowRangeError(ctx,"buffer size must be exactly %zu bytes",type_size(t));
    return read_value(ctx,t,b,JS_UNDEFINED,NULL,NULL,true);
}
static void type_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    FfiType *type = JS_GetOpaque(value, type_class);
    if (type && type->dynamic) {
        for (size_t i = 0; i < type->count; i++)
            JS_MarkValue(rt, type->deps[i], mark);
    }
}
static void type_finalizer(JSRuntime *rt, JSValueConst value) {
    FfiType *type = JS_GetOpaque(value, type_class);
    if (!type) return;
    if (type->dynamic) {
        for (size_t i = 0; i < type->count; i++)
            JS_FreeValueRT(rt, type->deps[i]);
        js_free_rt(rt, type->deps);
        js_free_rt(rt, type->offsets);
        js_free_rt(rt, type->ffi->elements);
        js_free_rt(rt, type->ffi);
    }
    js_free_rt(rt, type);
}
static JSClassDef type_def = {
    "FfiTypeToken",
    .finalizer = type_finalizer,
    .gc_mark = type_mark,
};
static int const_prop(JSContext *ctx, JSValueConst obj, const char *name,
                      JSValue value) {
    return JS_DefinePropertyValueStr(ctx, obj, name, value, JS_PROP_ENUMERABLE);
}
static JSValue new_type(JSContext *ctx, ffi_type *native, TypeKind kind,
                        const char *name) {
    JSValue obj = JS_NewObjectClass(ctx, type_class);
    if (JS_IsException(obj)) return obj;
    FfiType *type = js_mallocz(ctx, sizeof(*type));
    if (!type) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    type->ffi = native;
    type->kind = kind;
    JS_SetOpaque(obj, type);
    if (const_prop(ctx, obj, "name", JS_NewString(ctx, name)) < 0 ||
        const_prop(ctx, obj, "size", JS_NewInt64(
            ctx, kind == K_VOID ? 0 : (int64_t)native->size)) < 0 ||
        const_prop(ctx, obj, "alignment",
                   JS_NewInt32(ctx, native->alignment)) < 0 ||
        JS_FreezeObject(ctx, obj) < 0) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    return obj;
}
static JSValue new_aggregate(JSContext *ctx, JSValueConst fields, bool array,
                             size_t count) {
    JSValue repeated = JS_UNDEFINED;
    if (array) {
        repeated = JS_DupValue(ctx, fields);
    } else {
        if (!JS_IsArray(fields)) return JS_ThrowTypeError(ctx, "types.struct expects an array");
        JSValue lv = JS_GetPropertyStr(ctx, fields, "length");
        uint64_t n;
        if (JS_IsException(lv)) return JS_EXCEPTION;
        int r = JS_ToIndex(ctx, &n, lv);
        JS_FreeValue(ctx, lv);
        if (r < 0) return JS_EXCEPTION;
        if (!n || n > UINT32_MAX) return JS_ThrowRangeError(ctx, "struct requires at least one field");
        count = (size_t) n;
    }
    size_t element_count = count;
    size_t elements_size, deps_size, offsets_size;
    if (!size_add(&element_count, 1) ||
        !size_mul(element_count, sizeof(ffi_type *), &elements_size) ||
        !size_mul(count, sizeof(JSValue), &deps_size) ||
        !size_mul(count, sizeof(size_t), &offsets_size)) {
        JS_FreeValue(ctx, repeated);
        return JS_ThrowRangeError(ctx, "aggregate is too large");
    }
    JSValue obj = JS_NewObjectClass(ctx, type_class);
    if (JS_IsException(obj)) {
        JS_FreeValue(ctx, repeated);
        return obj;
    }
    FfiType *type = js_mallocz(ctx, sizeof(*type));
    ffi_type *native = js_mallocz(ctx, sizeof(*native));
    ffi_type **elements = js_mallocz(ctx, elements_size);
    JSValue *deps = js_mallocz(ctx, deps_size);
    size_t *offsets = js_mallocz(ctx, offsets_size);
    if (!type || !native || !elements || !deps || !offsets) goto fail;
    for (size_t i = 0; i < count; i++) {
        JSValue token = array
            ? JS_DupValue(ctx, repeated)
            : JS_GetPropertyUint32(ctx, fields, (uint32_t)i);
        if (JS_IsException(token)) goto fail;
        FfiType *element = JS_GetOpaque(token, type_class);
        if (!element || element->kind == K_VOID || element->kind == K_BUFFER) {
            JS_FreeValue(ctx, token);
            JS_ThrowTypeError(ctx, "invalid aggregate field %zu", i + 1);
            goto fail;
        }
        deps[i] = token;
        elements[i] = element->ffi;
    }
    JS_FreeValue(ctx, repeated);
    repeated = JS_UNDEFINED;
    native->type = FFI_TYPE_STRUCT;
    native->elements = elements;
    ffi_status status = ffi_get_struct_offsets(FFI_DEFAULT_ABI, native, offsets);
    if (status != FFI_OK) {
        JS_ThrowTypeError(ctx, "cannot create aggregate: %s", status_name(status));
        goto fail;
    }
    type->ffi = native;
    type->kind = K_AGGREGATE;
    type->dynamic = true;
    type->array = array;
    type->count = count;
    type->deps = deps;
    type->offsets = offsets;
    JS_SetOpaque(obj, type);
    if (const_prop(ctx, obj, "name",
                   JS_NewString(ctx, array ? "array" : "struct")) < 0 ||
        const_prop(ctx, obj, "size",
                   JS_NewInt64(ctx, (int64_t)native->size)) < 0 ||
        const_prop(ctx, obj, "alignment",
                   JS_NewInt32(ctx, native->alignment)) < 0 ||
        const_prop(ctx, obj, "pack",
                   JS_NewCFunction(ctx, type_pack, "pack", 1)) < 0 ||
        const_prop(ctx, obj, "unpack",
                   JS_NewCFunction(ctx, type_unpack, "unpack", 1)) < 0) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JSValue offset_array = JS_NewArray(ctx);
    if (JS_IsException(offset_array)) {
        JS_FreeValue(ctx, obj);
        return offset_array;
    }
    for (size_t i = 0; i < count; i++) {
        if (JS_SetPropertyUint32(ctx, offset_array, (uint32_t)i,
                                 JS_NewInt64(ctx, (int64_t)offsets[i])) < 0) {
            JS_FreeValue(ctx, offset_array);
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
    }
    if (JS_FreezeObject(ctx, offset_array) < 0 ||
        const_prop(ctx, obj, "offsets", offset_array) < 0) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    if (JS_FreezeObject(ctx, obj) < 0) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    return obj;
fail:
    JS_FreeValue(ctx, repeated);
    if (deps) {
        for (size_t i = 0; i < count; i++) JS_FreeValue(ctx, deps[i]);
    }
    js_free(ctx, deps);
    js_free(ctx, offsets);
    js_free(ctx, elements);
    js_free(ctx, native);
    js_free(ctx, type);
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}
static JSValue types_struct(JSContext *ctx, JSValueConst self, int argc,
                            JSValueConst *argv) {
    (void)self;
    if (argc != 1)
        return JS_ThrowTypeError(ctx, "types.struct expects one argument");
    return new_aggregate(ctx, argv[0], false, 0);
}
static JSValue types_array(JSContext *ctx, JSValueConst self, int argc,
                           JSValueConst *argv) {
    (void)self;
    if (argc != 2)
        return JS_ThrowTypeError(ctx, "types.array expects type and count");
    FfiType *t = JS_GetOpaque(argv[0], type_class);
    if (!t || t->kind == K_VOID || t->kind == K_BUFFER) return JS_ThrowTypeError(ctx, "invalid array element type");
    int64_t n;
    if (strict_integer(ctx, argv[1], &n, "array count") < 0) return JS_EXCEPTION;
    if (n <= 0 || n > UINT32_MAX) return JS_ThrowRangeError(ctx, "array count must be positive");
    return new_aggregate(ctx, argv[0], true, (size_t) n);
}

/* Prepared signatures and bound calls */
static void signature_clear(JSRuntime *rt, FfiSignature *signature) {
    if (signature->type_values) {
        for (unsigned i = 0; i <= signature->nargs; i++)
            JS_FreeValueRT(rt, signature->type_values[i]);
    }
    js_free_rt(rt, signature->type_values);
    js_free_rt(rt, signature->types);
    js_free_rt(rt, signature->arg_types);
    js_free_rt(rt, signature->offsets);
    memset(signature, 0, sizeof(*signature));
}
static void signature_mark(JSRuntime *rt, FfiSignature *signature,
                           JS_MarkFunc *mark) {
    for (unsigned i = 0; i <= signature->nargs; i++)
        JS_MarkValue(rt, signature->type_values[i], mark);
}
static int parse_fixed(JSContext *ctx, JSValueConst options, unsigned nargs,
                       int *result) {
    *result = -1;
    if (JS_IsUndefined(options)) return 0;
    if (!JS_IsObject(options))
        return JS_ThrowTypeError(ctx, "options must be an object"), -1;
    JSValue value = JS_GetPropertyStr(ctx, options, "fixed");
    if (JS_IsException(value)) return -1;
    if (JS_IsUndefined(value)) {
        JS_FreeValue(ctx, value);
        return 0;
    }
    int64_t fixed;
    if (strict_integer(ctx, value, &fixed, "fixed") < 0) {
        JS_FreeValue(ctx, value);
        return -1;
    }
    JS_FreeValue(ctx, value);
    if (fixed <= 0 || (uint64_t)fixed >= nargs) {
        return JS_ThrowRangeError(
            ctx, "fixed must be greater than zero and less than parameter count"), -1;
    }
    *result = (int)fixed;
    return 0;
}
static int signature_prepare(JSContext *ctx, JSValueConst array, unsigned skip,
                             JSValueConst options, FfiSignature *signature) {
    memset(signature, 0, sizeof(*signature));
    if (!JS_IsArray(array))
        return JS_ThrowTypeError(ctx, "signature must be an array"), -1;
    JSValue length_value = JS_GetPropertyStr(ctx, array, "length");
    uint64_t length;
    if (JS_IsException(length_value)) return -1;
    int result = JS_ToIndex(ctx, &length, length_value);
    JS_FreeValue(ctx, length_value);
    if (result < 0) return -1;
    if (length <= skip || length - skip - 1 > UINT_MAX)
        return JS_ThrowTypeError(ctx, "signature requires a result type"), -1;

    signature->nargs = (unsigned)(length - skip - 1);
    if (parse_fixed(ctx, options, signature->nargs, &signature->fixed) < 0)
        return -1;

    size_t count = (size_t)signature->nargs + 1;
    size_t type_values_size, types_size, arg_types_size, offsets_size;
    if (!size_mul(count, sizeof(JSValue), &type_values_size) ||
        !size_mul(count, sizeof(FfiType *), &types_size) ||
        !size_mul((size_t)signature->nargs, sizeof(ffi_type *),
                  &arg_types_size) ||
        !size_mul((size_t)signature->nargs, sizeof(size_t), &offsets_size)) {
        return JS_ThrowRangeError(ctx, "signature is too large"), -1;
    }
    signature->type_values = js_mallocz(ctx, type_values_size);
    signature->types = js_mallocz(ctx, types_size);
    if (signature->nargs)
        signature->arg_types = js_mallocz(ctx, arg_types_size);
    if (!signature->type_values || !signature->types ||
        (signature->nargs && !signature->arg_types))
        goto fail;

    for (unsigned i = 0; i <= signature->nargs; i++) {
        uint32_t at = i ? skip + i : 0;
        JSValue token = JS_GetPropertyUint32(ctx, array, at);
        if (JS_IsException(token)) goto fail;
        FfiType *type = JS_GetOpaque(token, type_class);
        if (!type) {
            JS_FreeValue(ctx, token);
            JS_ThrowTypeError(ctx, "signature item %u is not a type token", at + 1);
            goto fail;
        }
        if (type->array) {
            JS_FreeValue(ctx, token);
            JS_ThrowTypeError(ctx,
                              "array types cannot be used in callable signatures");
            goto fail;
        }
        if ((!i && type->kind == K_BUFFER) || (i && type->kind == K_VOID)) {
            JS_FreeValue(ctx, token);
            JS_ThrowTypeError(ctx, "invalid type in callable signature");
            goto fail;
        }
        signature->type_values[i] = token;
        signature->types[i] = type;
        if (i) signature->arg_types[i - 1] = type->ffi;
    }
    if (signature->fixed >= 0) {
        for (unsigned i = (unsigned)signature->fixed;
             i < signature->nargs; i++) {
            TypeKind kind = signature->types[i + 1]->kind;
            if (kind == K_BOOL || kind == K_I8 || kind == K_U8 ||
                kind == K_I16 || kind == K_U16 || kind == K_F32) {
                JS_ThrowTypeError(
                    ctx, "variadic argument %u requires an explicitly promoted C type",
                    i + 1);
                goto fail;
            }
        }
    }
    ffi_status status = signature->fixed >= 0
        ? ffi_prep_cif_var(&signature->cif, FFI_DEFAULT_ABI,
                           (unsigned)signature->fixed, signature->nargs,
                           signature->types[0]->ffi, signature->arg_types)
        : ffi_prep_cif(&signature->cif, FFI_DEFAULT_ABI, signature->nargs,
                       signature->types[0]->ffi, signature->arg_types);
    if (status != FFI_OK) {
        JS_ThrowTypeError(ctx, "cannot prepare signature: %s", status_name(status));
        goto fail;
    }
    if (signature->nargs)
        signature->offsets = js_mallocz(ctx, offsets_size);
    if (signature->nargs && !signature->offsets) goto fail;

    size_t frame = 0;
    size_t max_alignment = 1;
    for (unsigned i = 0; i < signature->nargs; i++) {
        FfiType *type = signature->types[i + 1];
        size_t alignment = pointer_kind(type)
            ? _Alignof(void *)
            : type->ffi->alignment;
        size_t size = pointer_kind(type) ? sizeof(void *) : type_size(type);
        if (alignment > max_alignment) max_alignment = alignment;
        if (!size_align(&frame, alignment ? alignment : 1)) {
            JS_ThrowRangeError(ctx, "call frame too large");
            goto fail;
        }
        signature->offsets[i] = frame;
        if (!size_add(&frame, size)) {
            JS_ThrowRangeError(ctx, "call frame too large");
            goto fail;
        }
    }
    if (!size_mul((size_t)signature->nargs, sizeof(void *),
                  &signature->frame_offset) ||
        !size_align(&signature->frame_offset, max_alignment)) {
        JS_ThrowRangeError(ctx, "call frame too large");
        goto fail;
    }
    signature->frame_size = frame;
    return 0;

fail:
    signature_clear(JS_GetRuntime(ctx), signature);
    return -1;
}
static int validate_buffer(JSContext *ctx, JSValueConst value) {
    if (JS_IsNull(value) || JS_IsDataView(value) ||
        JS_GetTypedArrayType(value) >= 0)
        return 0;
    if (JS_PinArrayBuffer(ctx, value) < 0) return -1;
    JS_UnpinArrayBuffer(value);
    return 0;
}

static int acquire_buffer(JSContext *ctx, JSValueConst value, void **pointer, JSValue *backing) {
    size_t offset = 0, length = 0, element_size = 0, backing_size = 0;
    JSValue buffer;
    bool pinned = false, direct = false;
    if (JS_IsDataView(value)) {
        buffer = JS_GetDataViewBuffer(ctx, value, &offset, &length);
        if (JS_IsException(buffer)) return -1;
    } else if (JS_GetTypedArrayType(value) >= 0) {
        buffer = JS_GetTypedArrayBuffer(ctx, value, &offset, &length, &element_size);
        if (JS_IsException(buffer)) return -1;
    } else {
        buffer = JS_DupValue(ctx, value);
        direct = true;
        if (JS_PinArrayBuffer(ctx, buffer) < 0) {
            JS_FreeValue(ctx, buffer);
            return -1;
        }
        pinned = true;
    }
    if (!pinned && JS_PinArrayBuffer(ctx, buffer) < 0) {
        JS_FreeValue(ctx, buffer);
        return -1;
    }
    uint8_t *base = JS_GetArrayBuffer(ctx, &backing_size, buffer);
    if (!base && JS_HasException(ctx)) {
        JS_UnpinArrayBuffer(buffer);
        JS_FreeValue(ctx, buffer);
        return -1;
    }
    if (direct) length = backing_size;
    if (offset > backing_size || length > backing_size - offset) {
        JS_UnpinArrayBuffer(buffer);
        JS_FreeValue(ctx, buffer);
        return JS_ThrowRangeError(ctx, "BufferSource is outside its backing store"), -1;
    }
    static uint8_t empty_buffer_sentinel;
    *pointer = base ? base + offset : &empty_buffer_sentinel;
    *backing = buffer;
    return 0;
}

static void release_pins(JSContext *ctx, FfiSignature *signature, JSValue *values) {
    for (unsigned i = signature->nargs; i-- > 0;) {
        if (!JS_IsUndefined(values[i])) {
            JS_UnpinArrayBuffer(values[i]);
            JS_FreeValue(ctx, values[i]);
            values[i] = JS_UNDEFINED;
        }
    }
}

static int prepare_call_values(JSContext *ctx,
                               FfiSignature *signature,
                               JSValueConst *argv,
                               void **args,
                               uint8_t *frame,
                               FfiCallback **callbacks,
                               uint_fast64_t *callback_counts) {
    for (unsigned i = 0; i < signature->nargs; i++) {
        FfiType *type = signature->types[i + 1];
        uint8_t *slot = frame + signature->offsets[i];
        args[i] = slot;
        callbacks[i] = NULL;
        callback_counts[i] = 0;
        if (type->kind == K_BUFFER) {
            if (validate_buffer(ctx, argv[i]) < 0) return -1;
        } else if (type->kind == K_AGGREGATE) {
            if (JS_GetTypedArrayType(argv[i]) != JS_TYPED_ARRAY_UINT8) {
                JS_ThrowTypeError(ctx, "argument %u must be a Uint8Array", i + 1);
                return -1;
            }
        } else if (pack_value(ctx, type, argv[i], slot) < 0) {
            return -1;
        }
        if ((type->kind == K_POINTER || type->kind == K_FUNCTION) &&
            !JS_IsNull(argv[i])) {
            FfiPointer *pointer = get_pointer(argv[i]);
            callbacks[i] = pointer ? pointer->callback : NULL;
            if (callbacks[i]) {
                callback_counts[i] = atomic_load_explicit(
                    &callbacks[i]->foreign_calls, memory_order_acquire);
            }
        }
    }
    return 0;
}

static void cancel_bound_call(JSContext *ctx,
                              FfiBound *bound,
                              bool temporary,
                              void *allocation,
                              uint8_t *result) {
    bound->in_call = temporary;
    if (temporary) {
        js_free(ctx, result);
        js_free(ctx, allocation);
    }
}

static JSValue call_bound(JSContext *ctx, JSValueConst func, FfiBound *bound,
                          int argc, JSValueConst *argv, bool ignore_closed) {
    FfiSignature *signature = &bound->sig;
    if (!ignore_closed &&
        ((bound->state && bound->state->closed) ||
         (bound->callback && bound->callback->closed)))
        return JS_ThrowTypeError(ctx, "FFI owner is closed");
    if ((unsigned)argc != signature->nargs)
        return JS_ThrowTypeError(
            ctx, "expected %u FFI arguments but received %d",
            signature->nargs, argc);
    bool temporary = bound->in_call;
    void *allocation = bound->call_storage;
    uint8_t *result = bound->result_storage;
    if (temporary) {
        allocation = js_mallocz(
            ctx, bound->call_storage_size ? bound->call_storage_size : 1);
        if (!allocation) return JS_EXCEPTION;
        result = js_mallocz(
            ctx, bound->result_storage_size ? bound->result_storage_size : 1);
        if (!result) {
            js_free(ctx, allocation);
            return JS_EXCEPTION;
        }
    }
    bound->in_call = true;
    memset(allocation, 0, bound->call_storage_size);
    memset(result, 0, bound->result_storage_size);
    void **args = allocation;
    uint8_t *frame = (uint8_t *)allocation + signature->frame_offset;
    JSValue *pin_values = (JSValue *)(
        (uint8_t *)allocation + bound->pin_values_offset);
    FfiCallback **callbacks = (FfiCallback **)(
        (uint8_t *)allocation + bound->callback_values_offset);
    uint_fast64_t *callback_counts = (uint_fast64_t *)(
        (uint8_t *)allocation + bound->callback_counts_offset);
    for (unsigned i = 0; i < signature->nargs; i++)
        pin_values[i] = JS_UNDEFINED;
    /* Aggregate packing can execute getters. Recheck the owner afterwards even
     * without a capability hook; a getter can synchronously close it. */
    if (prepare_call_values(ctx, signature, argv, args, frame,
                            callbacks, callback_counts) < 0)
        goto fail;
    if (!ignore_closed &&
        ((bound->state && bound->state->closed) ||
         (bound->callback && bound->callback->closed))) {
        JS_ThrowTypeError(ctx, "FFI owner is closed");
        goto fail;
    }
    TJS_CAPABILITY_REVALIDATE(
        tjs__capability(ctx, TJS_CAP_DYNLIB | TJS_CAP_IO_CONTROL,
                        TJS_CAP_FLAG_REPLACEABLE, "ffi.call"),
        cancel_bound_call(ctx, bound, temporary, allocation, result),
        do {
            if (!ignore_closed &&
                ((bound->state && bound->state->closed) ||
                 (bound->callback && bound->callback->closed))) {
                JS_ThrowTypeError(ctx, "FFI owner is closed");
                goto fail;
            }
            if (prepare_call_values(ctx, signature, argv, args, frame,
                                    callbacks, callback_counts) < 0)
                goto fail;
        } while (0));
    /* Phase 2 acquires all raw buffer/aggregate addresses only after validation completed. */
    for (unsigned i = 0; i < signature->nargs; i++) {
        FfiType *type = signature->types[i + 1];
        if (type->kind == K_BUFFER) {
            void *pointer = NULL;
            if (!JS_IsNull(argv[i]) &&
                acquire_buffer(ctx, argv[i], &pointer, &pin_values[i]) < 0)
                goto fail;
            memcpy(frame + signature->offsets[i], &pointer, sizeof(pointer));
        } else if (type->kind == K_AGGREGATE) {
            size_t bytes;
            uint8_t *pointer = JS_GetUint8Array(ctx, &bytes, argv[i]);
            if (!pointer && JS_HasException(ctx)) goto fail;
            if (bytes != type_size(type)) {
                JS_ThrowRangeError(
                    ctx, "argument %u must contain exactly %zu bytes",
                    i + 1, type_size(type));
                goto fail;
            }
            memcpy(frame + signature->offsets[i], pointer, bytes);
        }
    }
    FfiType *return_type = signature->types[0];
    size_t result_size = type_size(return_type);
    CallFrame call_frame = {
        .previous = active_call,
        .exception = JS_UNDEFINED,
    };
    active_call = &call_frame;
    if (bound->state) bound->state->active_calls++;
    ffi_call(&signature->cif, FFI_FN(bound->addr),
             result_size ? result : NULL, args);
    capture_errno(bound->state);
    if (bound->state) {
        assert(bound->state->active_calls > 0);
        bound->state->active_calls--;
        state_maybe_unload(bound->state);
    }
    bool bad_thread = false;
    for (unsigned i = 0; i < signature->nargs; i++) {
        if (callbacks[i] &&
            callback_counts[i] != atomic_load_explicit(
                &callbacks[i]->foreign_calls, memory_order_acquire)) {
            bad_thread = true;
            break;
        }
    }
    active_call = call_frame.previous;
    bound->in_call = temporary;
    release_pins(ctx, signature, pin_values);
    if (temporary) js_free(ctx, allocation);
    if (!JS_IsUndefined(call_frame.exception)) {
        if (temporary) js_free(ctx, result);
        return JS_Throw(ctx, call_frame.exception);
    }
    if (bad_thread) {
        if (temporary) js_free(ctx, result);
        return JS_ThrowTypeError(
            ctx, "FFI callback invoked from an unsupported native thread");
    }
    JSValue out;
    if (return_type->kind == K_AGGREGATE) {
        out = JS_NewUint8ArrayCopy(ctx, result, result_size);
    } else if (narrow_kind(return_type)) {
        ffi_arg word = 0;
        memcpy(&word, result, sizeof(word));
        uint8_t narrow_bytes[sizeof(ffi_arg)] = { 0 };
#define COPY_NARROW(kind, c_type) \
        case kind: { \
            c_type value = (c_type)word; \
            memcpy(narrow_bytes, &value, sizeof(value)); \
            break; \
        }
        switch (return_type->kind) {
            case K_BOOL:
            COPY_NARROW(K_U8, uint8_t)
            COPY_NARROW(K_I8, int8_t)
            COPY_NARROW(K_U16, uint16_t)
            COPY_NARROW(K_I16, int16_t)
            COPY_NARROW(K_U32, uint32_t)
            COPY_NARROW(K_I32, int32_t)
            default: break;
        }
#undef COPY_NARROW
        out = read_value(ctx, return_type, narrow_bytes, func,
                         bound->state, bound->callback, false);
    } else {
        out = read_value(ctx, return_type, result, func,
                         bound->state, bound->callback, false);
    }
    if (temporary) js_free(ctx, result);
    return out;

fail:
    release_pins(ctx, signature, pin_values);
    bound->in_call = temporary;
    if (temporary) {
        js_free(ctx, result);
        js_free(ctx, allocation);
    }
    return JS_EXCEPTION;
}
static JSValue bound_call(JSContext *ctx, JSValueConst func,
                          JSValueConst self, int argc,
                          JSValueConst *argv, int flags) {
    (void)self;
    if (flags & JS_CALL_FLAG_CONSTRUCTOR)
        return JS_ThrowTypeError(ctx, "FFI functions are not constructors");
    FfiBound *bound = JS_GetOpaque2(ctx, func, bound_class);
    return bound ? call_bound(ctx, func, bound, argc, argv, false) : JS_EXCEPTION;
}
static JSValue bound_pointer(JSContext *ctx, JSValueConst self) {
    FfiBound *bound = JS_GetOpaque2(ctx, self, bound_class);
    if (!bound) return JS_EXCEPTION;
    if ((bound->state && bound->state->closed) ||
        (bound->callback && bound->callback->closed))
        return JS_ThrowTypeError(ctx, "FFI owner is closed");
    return new_pointer(ctx, bound->addr, self, bound->state, bound->callback);
}
static void bound_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    FfiBound *bound = JS_GetOpaque(value, bound_class);
    if (bound) {
        signature_mark(rt, &bound->sig, mark);
        JS_MarkValue(rt, bound->owner, mark);
    }
}
static void bound_finalizer(JSRuntime *rt, JSValueConst value) {
    FfiBound *bound = JS_GetOpaque(value, bound_class);
    if (!bound) return;
    state_defer_unref(rt, bound->state);
    signature_clear(rt, &bound->sig);
    JS_FreeValueRT(rt, bound->owner);
    js_free_rt(rt, bound->call_storage);
    js_free_rt(rt, bound->result_storage);
    js_free_rt(rt, bound);
}
static JSClassDef bound_def = {
    "BoundFfiFunction",
    .finalizer = bound_finalizer,
    .gc_mark = bound_mark,
    .call = bound_call,
};
static JSValue new_bound(JSContext *ctx, void *addr, JSValueConst owner,
                         FfiLibraryState *state, FfiCallback *callback,
                         JSValueConst signature_value, unsigned skip,
                         JSValueConst options) {
    JSValue obj = JS_NewObjectClass(ctx, bound_class);
    if (JS_IsException(obj)) return obj;
    FfiBound *bound = js_mallocz(ctx, sizeof(*bound));
    if (!bound) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    bound->owner = JS_DupValue(ctx, owner);
    bound->addr = addr;
    bound->state = state;
    bound->callback = callback;
    if (signature_prepare(ctx, signature_value, skip, options, &bound->sig) < 0)
        goto fail;

    size_t total = bound->sig.frame_offset;
    if (!size_add(&total, bound->sig.frame_size) ||
        !size_align(&total, _Alignof(JSValue)))
        goto too_large;
    bound->pin_values_offset = total;
    size_t section_size;
    if (!size_mul((size_t)bound->sig.nargs, sizeof(JSValue), &section_size) ||
        !size_add(&total, section_size) ||
        !size_align(&total, _Alignof(FfiCallback *)))
        goto too_large;
    bound->callback_values_offset = total;
    if (!size_mul((size_t)bound->sig.nargs, sizeof(FfiCallback *),
                  &section_size) ||
        !size_add(&total, section_size) ||
        !size_align(&total, _Alignof(uint_fast64_t)))
        goto too_large;
    bound->callback_counts_offset = total;
    if (!size_mul((size_t)bound->sig.nargs, sizeof(uint_fast64_t),
                  &section_size) ||
        !size_add(&total, section_size))
        goto too_large;
    bound->call_storage_size = total;
    bound->result_storage_size = narrow_kind(bound->sig.types[0])
        ? sizeof(ffi_arg)
        : type_size(bound->sig.types[0]);
    bound->call_storage = js_mallocz(ctx, total ? total : 1);
    bound->result_storage = js_mallocz(
        ctx, bound->result_storage_size ? bound->result_storage_size : 1);
    if (!bound->call_storage || !bound->result_storage) goto fail;
    state_ref(state);
    JS_SetOpaque(obj, bound);
    return obj;

too_large:
    JS_ThrowRangeError(ctx, "call frame too large");
fail:
    signature_clear(JS_GetRuntime(ctx), &bound->sig);
    JS_FreeValue(ctx, bound->owner);
    js_free(ctx, bound->call_storage);
    js_free(ctx, bound->result_storage);
    js_free(ctx, bound);
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}

/* Libraries */
static FfiLibrary *require_library(JSContext *ctx, JSValueConst value,
                                   bool closed_ok) {
    FfiLibrary *library = JS_GetOpaque2(ctx, value, library_class);
    if (!library) return NULL;
    if (!closed_ok && library->closed) {
        JS_ThrowTypeError(ctx, "FFI library is closed");
        return NULL;
    }
    return library;
}
static int resolve(JSContext *ctx, FfiLibrary *library, JSValueConst value,
                   void **addr) {
    if (!JS_IsString(value))
        return JS_ThrowTypeError(ctx, "symbol name must be a string"), -1;
    const char *name = JS_ToCString(ctx, value);
    if (!name) return -1;
    int result = uv_dlsym(&library->state->handle, name, addr);
    if (result) {
        JS_ThrowReferenceError(ctx, "cannot resolve FFI symbol '%s': %s",
                               name, uv_dlerror(&library->state->handle));
    }
    JS_FreeCString(ctx, name);
    return result ? -1 : 0;
}
static JSValue ffi_open_js(JSContext *ctx, JSValueConst self, int argc,
                           JSValueConst *argv) {
    (void)self;
    if (argc != 1 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "ffi.open expects a path string");
    const char *path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;
    TJS_CAPABILITY(
        tjs__capability_resource(
            ctx, TJS_CAP_DYNLIB | TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ,
            TJS_CAP_FLAG_REPLACEABLE, "ffi.open", path),
        JS_FreeCString(ctx, path));
    JSValue obj = JS_NewObjectClass(ctx, library_class);
    if (JS_IsException(obj)) {
        JS_FreeCString(ctx, path);
        return obj;
    }
    FfiLibrary *library = js_mallocz(ctx, sizeof(*library));
    FfiLibraryState *state = tjs__mallocz(sizeof(*state));
    if (!library || !state) {
        JS_FreeCString(ctx, path);
        js_free(ctx, library);
        tjs__free(state);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    const char *error = NULL;
    int result = ffi_dlopen(path, &state->handle, &error);
    if (result) {
        JSValue exception = JS_ThrowReferenceError(
            ctx, "cannot open FFI library '%s': %s",
            path, error ? error : "loader error");
        JS_FreeCString(ctx, path);
        if (state->handle.handle) uv_dlclose(&state->handle);
        tjs__free(state);
        js_free(ctx, library);
        JS_FreeValue(ctx, obj);
        return exception;
    }
    JS_FreeCString(ctx, path);
    state->handle_open = true;
    state->refs = 1;
    library->state = state;
#if defined(_WIN32)
    void *errno_symbol = NULL;
    if (uv_dlsym(&state->handle, "_errno", &errno_symbol) == 0)
        state->errno_location = (int *(*)(void))errno_symbol;
#elif defined(__APPLE__)
    void *errno_symbol = NULL;
    if (uv_dlsym(&state->handle, "__error", &errno_symbol) == 0)
        state->errno_location = (int *(*)(void))errno_symbol;
#else
    void *errno_symbol = NULL;
    if (uv_dlsym(&state->handle, "__errno_location", &errno_symbol) == 0)
        state->errno_location = (int *(*)(void))errno_symbol;
#endif
    JS_SetOpaque(obj, library);
    return obj;
}
static JSValue library_symbol(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv) {
    FfiLibrary *library = require_library(ctx, self, false);
    if (!library) return JS_EXCEPTION;
    if (argc != 1) return JS_ThrowTypeError(ctx, "symbol expects one name");
    void *addr;
    if (resolve(ctx, library, argv[0], &addr) < 0) return JS_EXCEPTION;
    return new_pointer(ctx, addr, self, library->state, NULL);
}
static JSValue library_bind(JSContext *ctx, JSValueConst self, int argc,
                            JSValueConst *argv) {
    FfiLibrary *library = require_library(ctx, self, false);
    if (!library) return JS_EXCEPTION;
    if (argc < 1 || argc > 2 || !JS_IsArray(argv[0]))
        return JS_ThrowTypeError(ctx, "bind expects a signature");
    JSValue length_value = JS_GetPropertyStr(ctx, argv[0], "length");
    uint64_t length;
    if (JS_IsException(length_value)) return JS_EXCEPTION;
    int converted = JS_ToIndex(ctx, &length, length_value);
    JS_FreeValue(ctx, length_value);
    if (converted < 0) return JS_EXCEPTION;
    if (length < 2 || length - 2 > UINT_MAX)
        return JS_ThrowTypeError(
            ctx, "library signature requires result type and symbol");
    int fixed;
    if (parse_fixed(ctx, argc == 2 ? argv[1] : JS_UNDEFINED,
                    (unsigned)(length - 2), &fixed) < 0)
        return JS_EXCEPTION;
    JSValue name = JS_GetPropertyUint32(ctx, argv[0], 1);
    if (JS_IsException(name)) return JS_EXCEPTION;
    if (!JS_IsString(name)) {
        JS_FreeValue(ctx, name);
        return JS_ThrowTypeError(ctx, "symbol name must be a string");
    }
    const char *symbol = JS_ToCString(ctx, name);
    if (!symbol) {
        JS_FreeValue(ctx, name);
        return JS_EXCEPTION;
    }
    for (FfiBindCache *entry = library->cache; entry; entry = entry->next) {
        if (strcmp(entry->symbol, symbol) != 0) continue;
        FfiBound *cached = JS_GetOpaque(entry->bound, bound_class);
        if (!cached || cached->sig.nargs != (unsigned)(length - 2) ||
            cached->sig.fixed != fixed)
            continue;
        bool match = true;
        for (unsigned i = 0; i <= cached->sig.nargs; i++) {
            uint32_t at = i ? i + 1 : 0;
            JSValue token = JS_GetPropertyUint32(ctx, argv[0], at);
            if (JS_IsException(token)) {
                JS_FreeCString(ctx, symbol);
                JS_FreeValue(ctx, name);
                return JS_EXCEPTION;
            }
            int equal = JS_IsStrictEqual(ctx, token, cached->sig.type_values[i]);
            JS_FreeValue(ctx, token);
            if (equal < 0) {
                JS_FreeCString(ctx, symbol);
                JS_FreeValue(ctx, name);
                return JS_EXCEPTION;
            }
            match = equal != 0;
            if (!match) break;
        }
        if (match) {
            JSValue result = JS_DupValue(ctx, entry->bound);
            JS_FreeCString(ctx, symbol);
            JS_FreeValue(ctx, name);
            return result;
        }
    }
    void *addr;
    int result_code = resolve(ctx, library, name, &addr);
    JS_FreeValue(ctx, name);
    if (result_code < 0) {
        JS_FreeCString(ctx, symbol);
        return JS_EXCEPTION;
    }
    JSValue result = new_bound(
        ctx, addr, JS_UNDEFINED, library->state, NULL, argv[0], 1,
        argc == 2 ? argv[1] : JS_UNDEFINED);
    if (JS_IsException(result)) {
        JS_FreeCString(ctx, symbol);
        return result;
    }
    FfiBindCache *entry = js_mallocz(ctx, sizeof(*entry));
    char *symbol_copy = entry ? js_strdup(ctx, symbol) : NULL;
    JS_FreeCString(ctx, symbol);
    if (!entry || !symbol_copy) {
        js_free(ctx, entry);
        JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    entry->symbol = symbol_copy;
    entry->bound = JS_DupValue(ctx, result);
    entry->next = library->cache;
    library->cache = entry;
    return result;
}
static JSValue library_read(JSContext *ctx, JSValueConst self, int argc,
                            JSValueConst *argv) {
    FfiLibrary *library = require_library(ctx, self, false);
    if (!library) return JS_EXCEPTION;
    if (argc != 1 || !JS_IsArray(argv[0]))
        return JS_ThrowTypeError(ctx, "read expects [type, symbol]");
    JSValue type_value = JS_GetPropertyUint32(ctx, argv[0], 0);
    if (JS_IsException(type_value)) return JS_EXCEPTION;
    FfiType *type = JS_GetOpaque(type_value, type_class);
    if (!type || type->kind == K_VOID || type->kind == K_BUFFER) {
        JS_FreeValue(ctx, type_value);
        return JS_ThrowTypeError(ctx, "read requires a readable type");
    }
    JSValue name = JS_GetPropertyUint32(ctx, argv[0], 1);
    void *addr;
    if (JS_IsException(name)) {
        JS_FreeValue(ctx, type_value);
        return JS_EXCEPTION;
    }
    int result_code = resolve(ctx, library, name, &addr);
    JS_FreeValue(ctx, name);
    if (result_code < 0) {
        JS_FreeValue(ctx, type_value);
        return JS_EXCEPTION;
    }
    JSValue out = read_value(
        ctx, type, addr, self, library->state, NULL, false);
    JS_FreeValue(ctx, type_value);
    return out;
}
static JSValue library_close(JSContext *ctx, JSValueConst self, int argc,
                             JSValueConst *argv) {
    (void)argc;
    (void)argv;
    FfiLibrary *library = require_library(ctx, self, true);
    if (!library) return JS_EXCEPTION;
    if (!library->closed) {
        library->closed = true;
        library->state->closed = true;
        state_maybe_unload(library->state);
    }
    return JS_UNDEFINED;
}
static void library_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    FfiLibrary *library = JS_GetOpaque(value, library_class);
    if (library) {
        for (FfiBindCache *entry = library->cache;
             entry; entry = entry->next)
            JS_MarkValue(rt, entry->bound, mark);
    }
}
static void library_finalizer(JSRuntime *rt, JSValueConst value) {
    FfiLibrary *library = JS_GetOpaque(value, library_class);
    if (!library) return;
    FfiBindCache *entry = library->cache;
    while (entry) {
        FfiBindCache *next = entry->next;
        JS_FreeValueRT(rt, entry->bound);
        js_free_rt(rt, entry->symbol);
        js_free_rt(rt, entry);
        entry = next;
    }
    state_defer_unref(rt, library->state);
    js_free_rt(rt, library);
}
static JSClassDef library_def = {
    "FfiLibrary",
    .finalizer = library_finalizer,
    .gc_mark = library_mark,
};

/* Callbacks */
static void callback_zero(FfiCallback *callback, void *result) {
    size_t size = type_size(callback->sig.types[0]);
    if (result && size) memset(result, 0, size);
}
static int callback_result(JSContext *ctx, FfiType *type, JSValueConst value,
                           void *out) {
    if (type->kind == K_VOID) return 0;
    if (type->kind == K_AGGREGATE) {
        size_t size;
        uint8_t *pointer = JS_GetUint8Array(ctx, &size, value);
        if (!pointer)
            return JS_ThrowTypeError(ctx, "callback must return Uint8Array"), -1;
        if (size != type_size(type))
            return JS_ThrowRangeError(
                ctx, "callback result size must be %zu", type_size(type)), -1;
        memcpy(out, pointer, size);
        return 0;
    }
    return pack_value(ctx, type, value, out);
}
static void latch_exception(FfiCallback *callback) {
    JSContext *ctx = callback->ctx;
    JSValue exception = JS_GetException(ctx);
    if (active_call) {
        if (JS_IsUndefined(active_call->exception))
            active_call->exception = exception;
        else
            JS_FreeValue(ctx, exception);
        return;
    }
    if (JS_IsUncatchableError(exception)) {
        tjs__stop_uncatchable_error(ctx, exception);
        JS_FreeValue(ctx, exception);
        return;
    }
    JSValue handled = tjs__dispatch_event(ctx, EV_JOB_EXCEPTION, exception);
    if (JS_IsException(handled)) TJS_DumpException(ctx);
    if (JS_IsException(handled) ||
        (JS_IsBool(handled) && !JS_VALUE_GET_BOOL(handled)))
        TJS_Stop(TJS_GetRuntime(ctx));
    JS_FreeValue(ctx, exception);
    JS_FreeValue(ctx, handled);
}
static void callback_invoke(ffi_cif *cif, void *result, void **args,
                            void *opaque) {
    (void)cif;
    FfiCallback *callback = opaque;
    uv_thread_t current = uv_thread_self();
    if (!uv_thread_equal(&current, &callback->thread)) {
        callback_zero(callback, result);
        atomic_fetch_add_explicit(
            &callback->foreign_calls, 1, memory_order_release);
        if (!atomic_exchange_explicit(
                &callback->foreign_reported, true, memory_order_relaxed)) {
            fputs("circu.js FFI: callback invoked from an unsupported native "
                  "thread; returned ABI zero without entering JavaScript\n",
                  stderr);
            fflush(stderr);
        }
        return;
    }
    if (callback->closed) {
        callback_zero(callback, result);
        return;
    }
    JSContext *ctx = callback->ctx;
    unsigned nargs = callback->sig.nargs;
    size_t values_size;
    if (!size_mul((size_t)nargs, sizeof(JSValue), &values_size)) {
        JS_ThrowRangeError(ctx, "callback argument array is too large");
        callback_zero(callback, result);
        latch_exception(callback);
        return;
    }
    JSValue *values = nargs ? js_malloc(ctx, values_size) : NULL;
    if (nargs && !values) {
        callback_zero(callback, result);
        latch_exception(callback);
        return;
    }
    unsigned made = 0;
    for (; made < nargs; made++) {
        FfiType *type = callback->sig.types[made + 1];
        values[made] = read_value(
            ctx, type, args[made], JS_UNDEFINED, NULL, NULL, false);
        if (JS_IsException(values[made])) break;
    }
    JSValue return_value = JS_EXCEPTION;
    if (made == nargs)
        return_value = JS_Call(
            ctx, callback->function, JS_UNDEFINED, nargs, values);
    for (unsigned i = 0; i < made; i++) JS_FreeValue(ctx, values[i]);
    js_free(ctx, values);
    if (JS_IsException(return_value)) {
        callback_zero(callback, result);
        latch_exception(callback);
    } else {
        if (callback_result(
                ctx, callback->sig.types[0], return_value, result) < 0) {
            callback_zero(callback, result);
            latch_exception(callback);
        }
        JS_FreeValue(ctx, return_value);
    }
}
static JSValue callback_create(JSContext *ctx, JSValueConst self, int argc,
                               JSValueConst *argv) {
    (void)self;
    if (argc != 2 || !JS_IsArray(argv[0]) ||
        !JS_IsFunction(ctx, argv[1]))
        return JS_ThrowTypeError(ctx, "callback expects signature and function");
    JSValue obj = JS_NewObjectClass(ctx, callback_class);
    if (JS_IsException(obj)) return obj;
    FfiCallback *callback = js_mallocz(ctx, sizeof(*callback));
    if (!callback) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    atomic_init(&callback->foreign_calls, 0);
    atomic_init(&callback->foreign_reported, false);
    if (signature_prepare(
            ctx, argv[0], 0, JS_UNDEFINED, &callback->sig) < 0) {
        js_free(ctx, callback);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    callback->closure = ffi_closure_alloc(
        sizeof(ffi_closure), &callback->code);
    if (!callback->closure) {
        signature_clear(JS_GetRuntime(ctx), &callback->sig);
        js_free(ctx, callback);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    ffi_status status = ffi_prep_closure_loc(
        callback->closure, &callback->sig.cif, callback_invoke,
        callback, callback->code);
    if (status != FFI_OK) {
        ffi_closure_free(callback->closure);
        signature_clear(JS_GetRuntime(ctx), &callback->sig);
        js_free(ctx, callback);
        JS_FreeValue(ctx, obj);
        return JS_ThrowTypeError(
            ctx, "cannot prepare callback: %s", status_name(status));
    }
    callback->function = JS_DupValue(ctx, argv[1]);
    callback->ctx = ctx;
    callback->thread = uv_thread_self();
    JS_SetOpaque(obj, callback);
    return obj;
}
static JSValue callback_pointer(JSContext *ctx, JSValueConst self) {
    FfiCallback *callback = JS_GetOpaque2(ctx, self, callback_class);
    if (!callback) return JS_EXCEPTION;
    if (callback->closed)
        return JS_ThrowTypeError(ctx, "FFI callback is closed");
    return new_pointer(ctx, callback->code, self, NULL, callback);
}
static JSValue callback_close(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv) {
    (void)argc;
    (void)argv;
    FfiCallback *callback = JS_GetOpaque2(ctx, self, callback_class);
    if (!callback) return JS_EXCEPTION;
    callback->closed = true;
    return JS_UNDEFINED;
}
static void callback_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    FfiCallback *callback = JS_GetOpaque(value, callback_class);
    if (callback) {
        signature_mark(rt, &callback->sig, mark);
        JS_MarkValue(rt, callback->function, mark);
    }
}
static void callback_finalizer(JSRuntime *rt, JSValueConst value) {
    FfiCallback *callback = JS_GetOpaque(value, callback_class);
    if (!callback) return;
    if (callback->closure) ffi_closure_free(callback->closure);
    signature_clear(rt, &callback->sig);
    JS_FreeValueRT(rt, callback->function);
    js_free_rt(rt, callback);
}
static JSClassDef callback_def = {
    "FfiCallback",
    .finalizer = callback_finalizer,
    .gc_mark = callback_mark,
};

/* Owned pointers copy the disposer address/CIF and pin the relevant library
 * states until disposal completes outside the GC finalizer. */
static void owned_dispose(OwnedPointer *owned) {
    if (!owned->armed || !owned->pointer.valid) return;
    owned->armed = false;
    owned->pointer.addr = NULL;
    owned->pointer.valid = false;
    FfiDisposeJob *job = owned->job;
    owned->job = NULL;
    dispose_job_run(job, true);
}
static JSValue owned_close(JSContext *ctx, JSValueConst self, int argc,
                           JSValueConst *argv) {
    (void)argc;
    (void)argv;
    OwnedPointer *owned = JS_GetOpaque2(ctx, self, owned_class);
    if (!owned) return JS_EXCEPTION;
    owned_dispose(owned);
    return JS_UNDEFINED;
}
static JSValue owned_release(JSContext *ctx, JSValueConst self, int argc,
                             JSValueConst *argv) {
    (void)argc;
    (void)argv;
    OwnedPointer *owned = JS_GetOpaque2(ctx, self, owned_class);
    if (!owned) return JS_EXCEPTION;
    if (!owned->armed || !owned->pointer.valid)
        return JS_ThrowTypeError(ctx, "owned pointer is closed or released");
    JSValue pointer = new_pointer(
        ctx, owned->pointer.addr, owned->pointer.owner,
        owned->pointer.state, owned->pointer.callback);
    if (JS_IsException(pointer)) return pointer;
    owned->armed = false;
    owned->pointer.valid = false;
    owned->pointer.addr = NULL;
    FfiDisposeJob *job = owned->job;
    owned->job = NULL;
    state_owned_unref(job->resource_state);
    state_owned_unref(job->state);
    tjs__free(job);
    return pointer;
}
static void owned_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    OwnedPointer *owned = JS_GetOpaque(value, owned_class);
    if (owned && !JS_IsUndefined(owned->pointer.owner))
        JS_MarkValue(rt, owned->pointer.owner, mark);
}
static void owned_finalizer(JSRuntime *rt, JSValueConst value) {
    OwnedPointer *owned = JS_GetOpaque(value, owned_class);
    if (!owned) return;
    if (owned->job) {
        FfiDisposeJob *job = owned->job;
        owned->job = NULL;
        if (owned->armed && owned->pointer.valid) {
            job->cleanup.kind = CLEANUP_DISPOSE;
            cleanup_enqueue(JS_GetRuntimeOpaque(rt), &job->cleanup);
        } else {
            state_owned_unref(job->resource_state);
            state_owned_unref(job->state);
            tjs__free(job);
        }
    }
    JS_FreeValueRT(rt, owned->pointer.owner);
    js_free_rt(rt, owned);
}
static JSClassDef owned_def = {
    "OwnedPointer",
    .finalizer = owned_finalizer,
    .gc_mark = owned_mark,
};

/* Public function() and unsafe namespace */
static JSValue ffi_function_js(JSContext *ctx, JSValueConst self, int argc,
                               JSValueConst *argv) {
    (void)self;
    if (argc < 2 || argc > 3)
        return JS_ThrowTypeError(
            ctx, "function expects pointer and signature");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    if (!pointer) return JS_EXCEPTION;
    return new_bound(
        ctx, pointer->addr, argv[0], pointer->state, pointer->callback,
        argv[1], 0, argc == 3 ? argv[2] : JS_UNDEFINED);
}
static JSValue unsafe_address(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv) {
    (void)self;
    if (argc != 1)
        return JS_ThrowTypeError(ctx, "address expects Pointer");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    return pointer
        ? JS_NewBigUint64(ctx, (uint64_t)(uintptr_t)pointer->addr)
        : JS_EXCEPTION;
}
static JSValue unsafe_from_address(JSContext *ctx, JSValueConst self, int argc,
                                   JSValueConst *argv) {
    (void)self;
    if (argc != 1 || !JS_IsBigInt(argv[0]))
        return JS_ThrowTypeError(ctx, "fromAddress expects bigint");
    uint64_t address;
    if (exact_bigint(
            ctx, argv[0], false, (unsigned)(sizeof(uintptr_t) * CHAR_BIT),
            &address) < 0)
        return JS_EXCEPTION;
    return new_pointer(
        ctx, (void *)(uintptr_t)address, JS_UNDEFINED, NULL, NULL);
}
static JSValue unsafe_pointer_of(JSContext *ctx, JSValueConst self, int argc,
                                 JSValueConst *argv) {
    (void)self;
    if (argc != 1)
        return JS_ThrowTypeError(ctx, "pointerOf expects BufferSource");
    if (validate_buffer(ctx, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_IsNull(argv[0])) return JS_NULL;
    void *address = NULL;
    JSValue backing = JS_UNDEFINED;
    if (acquire_buffer(ctx, argv[0], &address, &backing) < 0)
        return JS_EXCEPTION;
    JSValue result = new_pointer(ctx, address, argv[0], NULL, NULL);
    if (JS_IsException(result)) {
        JS_UnpinArrayBuffer(backing);
        JS_FreeValue(ctx, backing);
        return result;
    }
    FfiPointer *pointer = JS_GetOpaque(result, pointer_class);
    assert(pointer);
    pointer->pinned_backing = backing;
    JS_FreeValue(ctx, backing);
    return result;
}
static JSValue unsafe_offset(JSContext *ctx, JSValueConst self, int argc,
                             JSValueConst *argv) {
    (void)self;
    if (argc != 2)
        return JS_ThrowTypeError(ctx, "offset expects Pointer and number");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    if (!pointer) return JS_EXCEPTION;
    int64_t offset;
    if (strict_integer(ctx, argv[1], &offset, "offset") < 0)
        return JS_EXCEPTION;
    uintptr_t address = (uintptr_t)pointer->addr;
    if ((offset > 0 && address > UINTPTR_MAX - (uintptr_t)offset) ||
        (offset < 0 && address < (uintptr_t)(-(offset + 1)) + 1))
        return JS_ThrowRangeError(ctx, "pointer offset overflow");
    address = offset >= 0
        ? address + (uintptr_t)offset
        : address - ((uintptr_t)(-(offset + 1)) + 1);
    return new_pointer(
        ctx, (void *)address, argv[0], pointer->state, pointer->callback);
}
static JSValue unsafe_deref(JSContext *ctx, JSValueConst self, int argc,
                            JSValueConst *argv) {
    (void)self;
    if (argc < 1 || argc > 2)
        return JS_ThrowTypeError(ctx, "deref expects Pointer");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    if (!pointer) return JS_EXCEPTION;
    int64_t count = 1;
    if (argc == 2 && strict_integer(ctx, argv[1], &count, "count") < 0)
        return JS_EXCEPTION;
    if (count < 0)
        return JS_ThrowRangeError(ctx, "count must be non-negative");
    void *address = pointer->addr;
    for (int64_t i = 0; i < count && address; i++)
        memcpy(&address, address, sizeof(address));
    return new_pointer(
        ctx, address, argv[0], pointer->state, pointer->callback);
}
static JSValue unsafe_view(JSContext *ctx, JSValueConst self, int argc,
                           JSValueConst *argv) {
    (void)self;
    if (argc != 2)
        return JS_ThrowTypeError(ctx, "view expects Pointer and length");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    if (!pointer) return JS_EXCEPTION;
    int64_t length;
    if (strict_integer(ctx, argv[1], &length, "length") < 0)
        return JS_EXCEPTION;
    if (length < 0 || (uint64_t)length > SIZE_MAX)
        return JS_ThrowRangeError(ctx, "invalid view length");
    JSValue view = JS_NewUint8Array(
        ctx, pointer->addr, (size_t)length, NULL, NULL, false);
    if (JS_IsException(view)) return view;
    if (JS_DefinePropertyValueStr(
            ctx, view, "_ffiOwner", JS_DupValue(ctx, argv[0]), 0) < 0) {
        JS_FreeValue(ctx, view);
        return JS_EXCEPTION;
    }
    return view;
}
static JSValue unsafe_cstring(JSContext *ctx, JSValueConst self, int argc,
                              JSValueConst *argv) {
    (void)self;
    if (argc < 1 || argc > 2)
        return JS_ThrowTypeError(ctx, "readCString expects Pointer");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    if (!pointer) return JS_EXCEPTION;
    if (argc == 1) return JS_NewString(ctx, pointer->addr);
    int64_t maximum;
    if (strict_integer(ctx, argv[1], &maximum, "maximum length") < 0)
        return JS_EXCEPTION;
    if (maximum < 0 || (uint64_t)maximum > SIZE_MAX)
        return JS_ThrowRangeError(ctx, "invalid maximum length");
    return JS_NewStringLen(
        ctx, pointer->addr, strnlen(pointer->addr, (size_t)maximum));
}
static JSValue unsafe_loop(JSContext *ctx, JSValueConst self, int argc,
                           JSValueConst *argv) {
    (void)self;
    (void)argc;
    (void)argv;
    return new_pointer(
        ctx, tjs_get_loop(ctx), JS_UNDEFINED, NULL, NULL);
}
static JSValue unsafe_adopt(JSContext *ctx, JSValueConst self, int argc,
                            JSValueConst *argv) {
    (void)self;
    if (argc != 2)
        return JS_ThrowTypeError(ctx, "adopt expects pointer and disposer");
    if (JS_GetOpaque(argv[0], owned_class))
        return JS_ThrowTypeError(
            ctx, "cannot adopt an owned pointer; release it instead");
    FfiPointer *pointer = require_pointer(ctx, argv[0]);
    if (!pointer) return JS_EXCEPTION;
    /* Borrowed ptrs can't be owned: GC fallback runs after owner is freed. */
    if (pointer->callback ||
        (!pointer->state && !JS_IsUndefined(pointer->owner)))
        return JS_ThrowTypeError(
            ctx, "cannot adopt a borrowed buffer or callback pointer");
    FfiBound *bound = JS_GetOpaque(argv[1], bound_class);
    if (!bound || bound->sig.fixed >= 0 || bound->sig.nargs != 1 ||
        bound->sig.types[0]->kind != K_VOID ||
        bound->sig.types[1]->kind != K_POINTER || bound->callback)
        return JS_ThrowTypeError(
            ctx, "disposer must be a native bound void(pointer) function");
    if (bound->state && bound->state->closed)
        return JS_ThrowTypeError(
            ctx, "disposer belongs to a closed FFI owner");
    JSValue obj = JS_NewObjectClass(ctx, owned_class);
    if (JS_IsException(obj)) return obj;
    OwnedPointer *owned = js_mallocz(ctx, sizeof(*owned));
    FfiDisposeJob *job = tjs__mallocz(sizeof(*job));
    if (!owned || !job) {
        js_free(ctx, owned);
        tjs__free(job);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    job->resource_addr = pointer->addr;
    job->disposer_addr = bound->addr;
    job->arg_types[0] = &ffi_type_pointer;
    job->state = bound->state;
    job->resource_state = pointer->state != bound->state
        ? pointer->state
        : NULL;
    ffi_status status = ffi_prep_cif(
        &job->cif, bound->sig.cif.abi, 1, &ffi_type_void, job->arg_types);
    if (status != FFI_OK) {
        js_free(ctx, owned);
        tjs__free(job);
        JS_FreeValue(ctx, obj);
        return JS_ThrowTypeError(
            ctx, "cannot prepare disposer: %s", status_name(status));
    }
    state_owned_ref(job->state);
    state_owned_ref(job->resource_state);
    owned->pointer.addr = pointer->addr;
    owned->pointer.owner = JS_DupValue(ctx, argv[0]);
    owned->pointer.state = pointer->state;
    owned->pointer.callback = pointer->callback;
    owned->pointer.valid = true;
    owned->job = job;
    owned->armed = true;
    JS_SetOpaque(obj, owned);
    return obj;
}

static JSValue ffi_errno_js(JSContext *ctx, JSValueConst self, int argc,
                            JSValueConst *argv) {
    (void)self;
    (void)argv;
    if (argc)
        return JS_ThrowTypeError(ctx, "errno expects no arguments");
    return JS_NewInt32(ctx, last_errno);
}
#ifndef _WIN32
static const char *strerror_gnu(char *result, char *buffer, size_t size,
                                int error) {
    (void)buffer;
    (void)size;
    (void)error;
    return result ? result : "Unknown error";
}
static const char *strerror_xsi(int result, char *buffer, size_t size,
                                int error) {
    if (result) snprintf(buffer, size, "Unknown error %d", error);
    return buffer;
}
#define STRERROR_RESULT(call, buffer, size, error) \
    _Generic((call), \
        char *: strerror_gnu, \
        default: strerror_xsi \
    )((call), (buffer), (size), (error))
#endif
static JSValue ffi_strerror_js(JSContext *ctx, JSValueConst self, int argc,
                               JSValueConst *argv) {
    (void)self;
    if (argc != 1 || !JS_IsNumber(argv[0]))
        return JS_ThrowTypeError(ctx, "strerror expects number");
    int32_t error;
    if (JS_ToInt32(ctx, &error, argv[0]) < 0) return JS_EXCEPTION;
    char buffer[256] = { 0 };
#ifdef _WIN32
    if (strerror_s(buffer, sizeof(buffer), error))
        snprintf(buffer, sizeof(buffer), "Unknown error %d", error);
    return JS_NewString(ctx, buffer);
#else
    return JS_NewString(
        ctx, STRERROR_RESULT(
            strerror_r(error, buffer, sizeof(buffer)),
            buffer, sizeof(buffer), error));
#endif
}

#if defined(_WIN32)
#define FFI_C_LIBRARY_NAME "msvcrt.dll"
#define FFI_M_LIBRARY_NAME "msvcrt.dll"
#elif defined(__APPLE__)
#define FFI_C_LIBRARY_NAME "libSystem.dylib"
#define FFI_M_LIBRARY_NAME "libSystem.dylib"
#elif defined(__GLIBC__)
#include <gnu/lib-names.h>
#define FFI_C_LIBRARY_NAME LIBC_SO
#define FFI_M_LIBRARY_NAME LIBM_SO
#elif defined(__linux__)
#define FFI_C_LIBRARY_NAME "libc.so"
#define FFI_M_LIBRARY_NAME "libm.so"
#else
#error unsupported platform
#endif

static const JSCFunctionListEntry library_proto[] = {
    JS_CFUNC_DEF("bind", 2, library_bind),
    JS_CFUNC_DEF("symbol", 1, library_symbol),
    JS_CFUNC_DEF("read", 1, library_read),
    JS_CFUNC_DEF("close", 0, library_close),
};
static const JSCFunctionListEntry bound_proto[] = {
    JS_CGETSET_DEF("pointer", bound_pointer, NULL),
};
static const JSCFunctionListEntry callback_proto[] = {
    JS_CGETSET_DEF("pointer", callback_pointer, NULL),
    JS_CFUNC_DEF("close", 0, callback_close),
};
static const JSCFunctionListEntry owned_proto[] = {
    JS_CFUNC_DEF("close", 0, owned_close),
    JS_CFUNC_DEF("release", 0, owned_release),
};
static int register_class(JSContext *ctx, JSClassID *id, JSClassDef *def,
                          const JSCFunctionListEntry *props, size_t count,
                          JSCFunction *dispose) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, id);
    if (JS_NewClass(rt, *id, def) < 0) return -1;
    JSValue proto = JS_NewObject(ctx);
    if (JS_IsException(proto)) return -1;
    if (props &&
        JS_SetPropertyFunctionList(ctx, proto, props, (int)count) < 0) {
        JS_FreeValue(ctx, proto);
        return -1;
    }
    if (dispose) {
        JSValue function = JS_NewCFunction(
            ctx, dispose, "[Symbol.dispose]", 0);
        if (JS_IsException(function) ||
            JS_DefinePropertyValue(
                ctx, proto, JS_ATOM_Symbol_dispose, function,
                JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE) < 0) {
            JS_FreeValue(ctx, proto);
            return -1;
        }
    }
    JS_SetClassProto(ctx, *id, proto);
    return 0;
}
static int add_type(JSContext *ctx, JSValueConst types, const char *name,
                    ffi_type *ffi, TypeKind kind) {
    JSValue token = new_type(ctx, ffi, kind, name);
    return JS_IsException(token)
        ? -1
        : JS_SetPropertyStr(ctx, types, name, token);
}

void tjs__mod_ffi_init(JSContext *ctx, JSValue ffi_object) {
    if (register_class(
            ctx, &type_class, &type_def, NULL, 0, NULL) < 0 ||
        register_class(
            ctx, &pointer_class, &pointer_def, NULL, 0, NULL) < 0 ||
        register_class(
            ctx, &owned_class, &owned_def, owned_proto,
            countof(owned_proto), owned_close) < 0 ||
        register_class(
            ctx, &library_class, &library_def, library_proto,
            countof(library_proto), library_close) < 0 ||
        register_class(
            ctx, &bound_class, &bound_def, bound_proto,
            countof(bound_proto), NULL) < 0 ||
        register_class(
            ctx, &callback_class, &callback_def, callback_proto,
            countof(callback_proto), callback_close) < 0)
        return;
    JSValue types = JS_NewObject(ctx);
    if (JS_IsException(types)) return;
#define ADD(name, ffi, kind) \
    do { \
        if (add_type(ctx, types, name, &ffi, kind) < 0) { \
            JS_FreeValue(ctx, types); \
            return; \
        } \
    } while (0)
    ADD("void", ffi_type_void, K_VOID);
    ADD("bool", ffi_type_uint8, K_BOOL);
    ADD("i8", ffi_type_sint8, K_I8);
    ADD("u8", ffi_type_uint8, K_U8);
    ADD("i16", ffi_type_sint16, K_I16);
    ADD("u16", ffi_type_uint16, K_U16);
    ADD("i32", ffi_type_sint32, K_I32);
    ADD("u32", ffi_type_uint32, K_U32);
    ADD("i64", ffi_type_sint64, K_I64);
    ADD("u64", ffi_type_uint64, K_U64);
    ADD("f32", ffi_type_float, K_F32);
    ADD("f64", ffi_type_double, K_F64);
    ADD("pointer", ffi_type_pointer, K_POINTER);
    ADD("buffer", ffi_type_pointer, K_BUFFER);
    ADD("function", ffi_type_pointer, K_FUNCTION);
    ADD("schar", ffi_type_schar, K_I8);
    ADD("uchar", ffi_type_uchar, K_U8);
    ADD("short", ffi_type_sshort, K_I16);
    ADD("ushort", ffi_type_ushort, K_U16);
    ADD("int", ffi_type_sint, K_I32);
    ADD("uint", ffi_type_uint, K_U32);
#if LONG_MAX == INT32_MAX
    ADD("long", ffi_type_slong, K_I32);
    ADD("ulong", ffi_type_ulong, K_U32);
#elif LONG_MAX == INT64_MAX
    ADD("long", ffi_type_slong, K_I64);
    ADD("ulong", ffi_type_ulong, K_U64);
#else
#error unsupported long width
#endif
    ADD("longLong", ffi_type_sint64, K_I64);
    ADD("ulongLong", ffi_type_uint64, K_U64);
#if SIZE_MAX == UINT32_MAX
    ADD("usize", ffi_type_uint32, K_U64);
    ADD("isize", ffi_type_sint32, K_I64);
#else
    ADD("usize", ffi_type_uint64, K_U64);
    ADD("isize", ffi_type_sint64, K_I64);
#endif
    ADD("longDouble", ffi_type_longdouble, K_LONG_DOUBLE);
#undef ADD
    JS_SetPropertyStr(
        ctx, types, "struct", JS_NewCFunction(ctx, types_struct, "struct", 1));
    JS_SetPropertyStr(
        ctx, types, "array", JS_NewCFunction(ctx, types_array, "array", 2));
    if (JS_FreezeObject(ctx, types) < 0) {
        JS_FreeValue(ctx, types);
        return;
    }

    JSValue libraries = JS_NewObject(ctx);
    JS_SetPropertyStr(
        ctx, libraries, "c", JS_NewString(ctx, FFI_C_LIBRARY_NAME));
    JS_SetPropertyStr(
        ctx, libraries, "m", JS_NewString(ctx, FFI_M_LIBRARY_NAME));
    if (JS_FreezeObject(ctx, libraries) < 0) {
        JS_FreeValue(ctx, types);
        JS_FreeValue(ctx, libraries);
        return;
    }

    JSValue unsafe = JS_NewObject(ctx);
    static const JSCFunctionListEntry unsafe_functions[] = {
        JS_CFUNC_DEF("address", 1, unsafe_address),
        JS_CFUNC_DEF("fromAddress", 1, unsafe_from_address),
        JS_CFUNC_DEF("pointerOf", 1, unsafe_pointer_of),
        JS_CFUNC_DEF("offset", 2, unsafe_offset),
        JS_CFUNC_DEF("deref", 1, unsafe_deref),
        JS_CFUNC_DEF("view", 2, unsafe_view),
        JS_CFUNC_DEF("readCString", 2, unsafe_cstring),
        JS_CFUNC_DEF("currentEventLoop", 0, unsafe_loop),
        JS_CFUNC_DEF("adopt", 2, unsafe_adopt),
    };
    JS_SetPropertyFunctionList(
        ctx, unsafe, unsafe_functions, countof(unsafe_functions));

    static const JSCFunctionListEntry functions[] = {
        JS_CFUNC_DEF("open", 1, ffi_open_js),
        JS_CFUNC_DEF("function", 2, ffi_function_js),
        JS_CFUNC_DEF("callback", 2, callback_create),
        JS_CFUNC_DEF("errno", 0, ffi_errno_js),
        JS_CFUNC_DEF("strerror", 1, ffi_strerror_js),
    };
    JS_SetPropertyFunctionList(
        ctx, ffi_object, functions, countof(functions));
    JS_SetPropertyStr(ctx, ffi_object, "types", types);
    JS_SetPropertyStr(ctx, ffi_object, "libraries", libraries);
    JS_SetPropertyStr(ctx, ffi_object, "unsafe", unsafe);
}
