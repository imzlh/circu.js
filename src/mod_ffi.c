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

static thread_local JSClassID type_class, pointer_class, owned_class, library_class, bound_class, callback_class;
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
    /* Non-owning identity for a backing store pinned by pointerOf(). Safe as a
     * weak back-reference under two invariants: the owner chain is strongly
     * gc_marked so the backing object outlives this pointer, and the fork GC
     * runs every finalizer before freeing any object, so JS_IsLiveObject in
     * the finalizer never reads freed memory. Never store a pinned pointer
     * without an owner. */
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
static size_t type_size(FfiType *t) { return t->kind == K_VOID ? 0 : t->ffi->size; }
static bool pointer_kind(FfiType *t) { return t->kind == K_POINTER || t->kind == K_BUFFER || t->kind == K_FUNCTION; }
static bool narrow_kind(FfiType *t) {
    return t->ffi->size < sizeof(ffi_arg) && t->kind >= K_BOOL && t->kind <= K_U32;
}
static bool size_add(size_t *v, size_t n) { if (*v > SIZE_MAX - n) return false; *v += n; return true; }
static bool size_align(size_t *v, size_t a) { size_t r = a > 1 ? *v % a : 0; return !r || size_add(v, a-r); }
static void capture_errno(FfiLibraryState *state) {
    last_errno = state && state->errno_location ? *state->errno_location() : errno;
}
static int strict_integer(JSContext *ctx, JSValueConst value, int64_t *result, const char *name) {
    double number;
    if (!JS_IsNumber(value) || JS_ToFloat64(ctx, &number, value) < 0)
        return JS_ThrowTypeError(ctx, "%s must be an integer", name), -1;
    if (!isfinite(number) || trunc(number) != number || number < -9007199254740991.0 || number > 9007199254740991.0)
        return JS_ThrowRangeError(ctx, "%s must be a safe integer", name), -1;
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
static void loader_init(void) { uv_mutex_init(&loader_mutex); }
static int ffi_dlopen(const char *name, uv_lib_t *lib, const char **error) {
    uv_once(&loader_once, loader_init); uv_mutex_lock(&loader_mutex);
    dlerror(); lib->errmsg = NULL;
    Lmid_t lmid = loader_has_lmid ? loader_lmid : LM_ID_NEWLM;
    lib->handle = dlmopen(lmid, name, RTLD_LAZY | RTLD_LOCAL);
    if (!lib->handle) { *error = dlerror(); uv_mutex_unlock(&loader_mutex); return -1; }
    if (loader_has_lmid) loader_refs++;
    else if (dlinfo(lib->handle, RTLD_DI_LMID, &loader_lmid) != 0) {
        *error = dlerror(); dlclose(lib->handle); lib->handle = NULL;
        uv_mutex_unlock(&loader_mutex); return -1;
    } else { loader_has_lmid = true; loader_refs = 1; }
    uv_mutex_unlock(&loader_mutex); return 0;
}
static void ffi_dlclose(uv_lib_t *lib) {
    uv_once(&loader_once, loader_init); uv_mutex_lock(&loader_mutex);
    uv_dlclose(lib); if (loader_refs) loader_refs--;
    if (!loader_refs) { loader_has_lmid = false; loader_lmid = LM_ID_BASE; }
    uv_mutex_unlock(&loader_mutex);
}
#else
static int ffi_dlopen(const char *name, uv_lib_t *lib, const char **error) {
    int r = uv_dlopen(name, lib); *error = r ? uv_dlerror(lib) : NULL; return r;
}
static void ffi_dlclose(uv_lib_t *lib) { uv_dlclose(lib); }
#endif

static void state_maybe_unload(FfiLibraryState *state) {
    if (state && state->handle_open && state->closed && state->owned_holds == 0 && state->active_calls == 0) {
        ffi_dlclose(&state->handle);
        state->handle_open = false;
    }
}
static void state_ref(FfiLibraryState *state) { if (state) state->refs++; }
static void state_unref(FfiLibraryState *state) {
    if (!state) return;
    assert(state->refs > 0);
    state->refs--;
    if (!state->refs) state->closed = true;
    state_maybe_unload(state);
    if (!state->refs) { assert(!state->handle_open); tjs__free(state); }
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
    if (!p || !p->valid) return JS_ThrowTypeError(ctx, "pointer is closed or released"), -1;
    if (p->state && p->state->closed) return JS_ThrowTypeError(ctx, "pointer belongs to a closed library"), -1;
    if (p->callback && p->callback->closed) return JS_ThrowTypeError(ctx, "pointer belongs to a closed callback"), -1;
    /* Native-derived pointers keep their source Pointer as owner. Follow that
     * chain so close/release invalidation propagates to every later offset or
     * dereference instead of leaving a usable address into freed storage. */
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
static JSValue new_pointer(JSContext *ctx, void *addr, JSValueConst owner, FfiLibraryState *state, FfiCallback *callback) {
    if (!addr) return JS_NULL;
    JSValue obj = JS_NewObjectClass(ctx, pointer_class);
    if (JS_IsException(obj)) return obj;
    FfiPointer *p = js_mallocz(ctx, sizeof(*p));
    if (!p) { JS_FreeValue(ctx, obj); return JS_EXCEPTION; }
    p->addr = addr; p->owner = JS_IsUndefined(owner) ? JS_UNDEFINED : JS_DupValue(ctx, owner);
    p->pinned_backing = JS_UNDEFINED; p->state = state; state_ref(state);
    p->callback = callback; p->valid = true; JS_SetOpaque(obj, p); return obj;
}
static void pointer_mark(JSRuntime *rt, JSValueConst value, JS_MarkFunc *mark) {
    FfiPointer *p = JS_GetOpaque(value, pointer_class);
    if (p && !JS_IsUndefined(p->owner)) JS_MarkValue(rt, p->owner, mark);
}
static void pointer_finalizer(JSRuntime *rt, JSValueConst value) {
    FfiPointer *p = JS_GetOpaque(value, pointer_class); if (!p) return;
    if (JS_IsLiveObject(rt, p->pinned_backing)) JS_UnpinArrayBuffer(p->pinned_backing);
    state_defer_unref(rt, p->state);
    JS_FreeValueRT(rt, p->owner); js_free_rt(rt, p);
}
static JSClassDef pointer_def = { "Pointer", .finalizer = pointer_finalizer, .gc_mark = pointer_mark };

/* Scalar and aggregate conversion */
static int pointer_native(JSContext *ctx, JSValueConst value, void **out) {
    if (JS_IsNull(value)) { *out = NULL; return 0; }
    FfiPointer *p = require_pointer(ctx, value); if (!p) return -1; *out = p->addr; return 0;
}
static int exact_number(JSContext *ctx, JSValueConst value, double minimum, double maximum, double *out) {
    double v;
    if (!JS_IsNumber(value) || JS_ToFloat64(ctx, &v, value) < 0)
        return JS_ThrowTypeError(ctx, "expected number"), -1;
    if (!isfinite(v) || trunc(v) != v || v < minimum || v > maximum)
        return JS_ThrowRangeError(ctx, "integer is outside the C type range"), -1;
    *out = v;
    return 0;
}
static int exact_bigint(JSContext *ctx, JSValueConst value, bool is_signed, unsigned bits, uint64_t *out) {
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
        uint64_t positive_max = bits == 64 ? INT64_MAX : ((UINT64_C(1) << (bits - 1)) - 1);
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
        case K_VOID: return JS_ThrowTypeError(ctx, "void is not a value"), -1;
        case K_BOOL: { if (!JS_IsBool(value)) return JS_ThrowTypeError(ctx, "expected boolean"), -1;
            uint8_t v=(uint8_t)JS_ToBool(ctx,value); memcpy(out,&v,sizeof(v)); return 0; }
        case K_I8: { double n;if(exact_number(ctx,value,INT8_MIN,INT8_MAX,&n)<0)return -1;int8_t v=(int8_t)n;memcpy(out,&v,sizeof(v));return 0; }
        case K_U8: { double n;if(exact_number(ctx,value,0,UINT8_MAX,&n)<0)return -1;uint8_t v=(uint8_t)n;memcpy(out,&v,sizeof(v));return 0; }
        case K_I16:{ double n;if(exact_number(ctx,value,INT16_MIN,INT16_MAX,&n)<0)return -1;int16_t v=(int16_t)n;memcpy(out,&v,sizeof(v));return 0; }
        case K_U16:{ double n;if(exact_number(ctx,value,0,UINT16_MAX,&n)<0)return -1;uint16_t v=(uint16_t)n;memcpy(out,&v,sizeof(v));return 0; }
        case K_I32:{ double n;if(exact_number(ctx,value,INT32_MIN,INT32_MAX,&n)<0)return -1;int32_t v=(int32_t)n;memcpy(out,&v,sizeof(v));return 0; }
        case K_U32:{ double n;if(exact_number(ctx,value,0,UINT32_MAX,&n)<0)return -1;uint32_t v=(uint32_t)n;memcpy(out,&v,sizeof(v));return 0; }
        case K_I64:{ uint64_t raw;if(exact_bigint(ctx,value,true,(unsigned)(t->ffi->size*CHAR_BIT),&raw)<0)return -1;if(t->ffi->size==4){uint32_t v=(uint32_t)raw;memcpy(out,&v,4);}else memcpy(out,&raw,8);return 0; }
        case K_U64:{ uint64_t raw;if(exact_bigint(ctx,value,false,(unsigned)(t->ffi->size*CHAR_BIT),&raw)<0)return -1;if(t->ffi->size==4){uint32_t v=(uint32_t)raw;memcpy(out,&v,4);}else memcpy(out,&raw,8);return 0; }
        case K_F32:{ double v;if(!JS_IsNumber(value))goto number;if(JS_ToFloat64(ctx,&v,value)<0)return -1;float n=(float)v;memcpy(out,&n,sizeof(n));return 0; }
        case K_F64:{ double v; if(!JS_IsNumber(value))goto number; if(JS_ToFloat64(ctx,&v,value)<0)return -1; memcpy(out,&v,8);return 0; }
        case K_LONG_DOUBLE:{ double v;if(!JS_IsNumber(value))goto number;if(JS_ToFloat64(ctx,&v,value)<0)return -1;long double n=(long double)v;memcpy(out,&n,sizeof(n));return 0; }
        case K_POINTER: case K_FUNCTION:{ void *p; if(pointer_native(ctx,value,&p)<0)return -1;memcpy(out,&p,sizeof(p));return 0; }
        case K_BUFFER: return JS_ThrowTypeError(ctx,"buffer is only valid as a function argument"),-1;
        case K_AGGREGATE: {
            if(!JS_IsArray(value))return JS_ThrowTypeError(ctx,"expected an array with %zu values",t->count),-1;
            JSValue lv=JS_GetPropertyStr(ctx,value,"length"); uint64_t len;
            if (JS_IsException(lv)) return -1;
            int r = JS_ToIndex(ctx, &len, lv);
            JS_FreeValue(ctx, lv);
            if (r < 0) return -1;
            if(len!=t->count)return JS_ThrowRangeError(ctx,"expected exactly %zu aggregate values",t->count),-1;
            memset(out,0,type_size(t));
            for(size_t i=0;i<t->count;i++){JSValue item=JS_GetPropertyUint32(ctx,value,(uint32_t)i);if(JS_IsException(item))return -1;
                r=pack_value(ctx,JS_GetOpaque(t->deps[i],type_class),item,out+t->offsets[i]);JS_FreeValue(ctx,item);if(r<0)return -1;}
            return 0;
        }
    }
number:return JS_ThrowTypeError(ctx,"expected number"),-1;
}
static JSValue read_value(JSContext *ctx,FfiType*t,const uint8_t*src,JSValueConst owner,FfiLibraryState*state,FfiCallback*cb,bool structured){
    switch(t->kind){
        case K_VOID:return JS_UNDEFINED;
        case K_BOOL:{uint8_t v;memcpy(&v,src,1);return JS_NewBool(ctx,v!=0);}
        case K_I8:{int8_t v;memcpy(&v,src,1);return JS_NewInt32(ctx,v);}case K_U8:{uint8_t v;memcpy(&v,src,1);return JS_NewInt32(ctx,v);}
        case K_I16:{int16_t v;memcpy(&v,src,2);return JS_NewInt32(ctx,v);}case K_U16:{uint16_t v;memcpy(&v,src,2);return JS_NewInt32(ctx,v);}
        case K_I32:{int32_t v;memcpy(&v,src,4);return JS_NewInt32(ctx,v);}case K_U32:{uint32_t v;memcpy(&v,src,4);return JS_NewUint32(ctx,v);}
        case K_I64:{int64_t v=0;if(t->ffi->size==4){int32_t n;memcpy(&n,src,4);v=n;}else memcpy(&v,src,8);return JS_NewBigInt64(ctx,v);}
        case K_U64:{uint64_t v=0;if(t->ffi->size==4){uint32_t n;memcpy(&n,src,4);v=n;}else memcpy(&v,src,8);return JS_NewBigUint64(ctx,v);}
        case K_F32:{float v;memcpy(&v,src,sizeof(v));return JS_NewFloat64(ctx,v);}case K_F64:{double v;memcpy(&v,src,sizeof(v));return JS_NewFloat64(ctx,v);}
        case K_LONG_DOUBLE:{long double v;memcpy(&v,src,sizeof(v));return JS_NewFloat64(ctx,(double)v);}
        case K_POINTER:case K_BUFFER:case K_FUNCTION:{void*p;memcpy(&p,src,sizeof(p));return new_pointer(ctx,p,owner,state,cb);}
        case K_AGGREGATE:{
            if(!structured)return JS_NewUint8ArrayCopy(ctx,src,type_size(t));
            JSValue a=JS_NewArray(ctx);if(JS_IsException(a))return a;
            for(size_t i=0;i<t->count;i++){FfiType*e=JS_GetOpaque(t->deps[i],type_class);
                JSValue v=read_value(ctx,e,src+t->offsets[i],JS_UNDEFINED,NULL,NULL,true);
                if(JS_IsException(v)||JS_SetPropertyUint32(ctx,a,(uint32_t)i,v)<0){JS_FreeValue(ctx,a);return JS_EXCEPTION;}}
            return a;
        }
    } return JS_ThrowInternalError(ctx,"unknown FFI type");
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
    size_t n;uint8_t*b=JS_GetUint8Array(ctx,&n,argv[0]);if(!b)return JS_ThrowTypeError(ctx,"unpack expects a Uint8Array");
    if(n!=type_size(t))return JS_ThrowRangeError(ctx,"buffer size must be exactly %zu bytes",type_size(t));
    return read_value(ctx,t,b,JS_UNDEFINED,NULL,NULL,true);
}
static void type_mark(JSRuntime*rt,JSValueConst value,JS_MarkFunc*mark){FfiType*t=JS_GetOpaque(value,type_class);if(t&&t->dynamic)for(size_t i=0;i<t->count;i++)JS_MarkValue(rt,t->deps[i],mark);}
static void type_finalizer(JSRuntime*rt,JSValueConst value){FfiType*t=JS_GetOpaque(value,type_class);if(!t)return;if(t->dynamic){for(size_t i=0;i<t->count;i++)JS_FreeValueRT(rt,t->deps[i]);js_free_rt(rt,t->deps);js_free_rt(rt,t->offsets);js_free_rt(rt,t->ffi->elements);js_free_rt(rt,t->ffi);}js_free_rt(rt,t);}
static JSClassDef type_def={"FfiTypeToken",.finalizer=type_finalizer,.gc_mark=type_mark};
static int const_prop(JSContext*ctx,JSValueConst obj,const char*name,JSValue value){return JS_DefinePropertyValueStr(ctx,obj,name,value,JS_PROP_ENUMERABLE);}
static JSValue new_type(JSContext*ctx,ffi_type*native,TypeKind kind,const char*name){
    JSValue obj=JS_NewObjectClass(ctx,type_class);if(JS_IsException(obj))return obj;FfiType*t=js_mallocz(ctx,sizeof(*t));
    if(!t){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}t->ffi=native;t->kind=kind;JS_SetOpaque(obj,t);
    if(const_prop(ctx,obj,"name",JS_NewString(ctx,name))<0||const_prop(ctx,obj,"size",JS_NewInt64(ctx,kind==K_VOID?0:(int64_t)native->size))<0||
       const_prop(ctx,obj,"alignment",JS_NewInt32(ctx,native->alignment))<0||JS_FreezeObject(ctx,obj)<0){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}return obj;
}
static JSValue new_aggregate(JSContext*ctx,JSValueConst fields,bool array,size_t count){
    JSValue repeated=JS_UNDEFINED;if(array)repeated=JS_DupValue(ctx,fields);else{
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
    if(count>(SIZE_MAX/sizeof(ffi_type*))-1||count>SIZE_MAX/sizeof(JSValue)||count>SIZE_MAX/sizeof(size_t)){JS_FreeValue(ctx,repeated);return JS_ThrowRangeError(ctx,"aggregate is too large");}
    JSValue obj=JS_NewObjectClass(ctx,type_class);if(JS_IsException(obj)){JS_FreeValue(ctx,repeated);return obj;}
    FfiType*t=js_mallocz(ctx,sizeof(*t));ffi_type*f=js_mallocz(ctx,sizeof(*f));ffi_type**elements=js_mallocz(ctx,sizeof(*elements)*(count+1));
    JSValue*deps=js_mallocz(ctx,sizeof(*deps)*count);size_t*offsets=js_mallocz(ctx,sizeof(*offsets)*count);
    if(!t||!f||!elements||!deps||!offsets)goto fail;
    for(size_t i=0;i<count;i++){JSValue token=array?JS_DupValue(ctx,repeated):JS_GetPropertyUint32(ctx,fields,(uint32_t)i);if(JS_IsException(token))goto fail;
        FfiType*e=JS_GetOpaque(token,type_class);if(!e||e->kind==K_VOID||e->kind==K_BUFFER){JS_FreeValue(ctx,token);JS_ThrowTypeError(ctx,"invalid aggregate field %zu",i+1);goto fail;}deps[i]=token;elements[i]=e->ffi;}
    JS_FreeValue(ctx,repeated);repeated=JS_UNDEFINED;f->type=FFI_TYPE_STRUCT;f->elements=elements;ffi_status st=ffi_get_struct_offsets(FFI_DEFAULT_ABI,f,offsets);
    if(st!=FFI_OK){JS_ThrowTypeError(ctx,"cannot create aggregate: %s",status_name(st));goto fail;}
    t->ffi=f;t->kind=K_AGGREGATE;t->dynamic=true;t->array=array;t->count=count;t->deps=deps;t->offsets=offsets;JS_SetOpaque(obj,t);
    if(const_prop(ctx,obj,"name",JS_NewString(ctx,array?"array":"struct"))<0||const_prop(ctx,obj,"size",JS_NewInt64(ctx,(int64_t)f->size))<0||
       const_prop(ctx,obj,"alignment",JS_NewInt32(ctx,f->alignment))<0||const_prop(ctx,obj,"pack",JS_NewCFunction(ctx,type_pack,"pack",1))<0||
       const_prop(ctx,obj,"unpack",JS_NewCFunction(ctx,type_unpack,"unpack",1))<0){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}
    {JSValue a=JS_NewArray(ctx);if(JS_IsException(a)){JS_FreeValue(ctx,obj);return a;}for(size_t i=0;i<count;i++)if(JS_SetPropertyUint32(ctx,a,(uint32_t)i,JS_NewInt64(ctx,(int64_t)offsets[i]))<0){JS_FreeValue(ctx,a);JS_FreeValue(ctx,obj);return JS_EXCEPTION;}
        if(JS_FreezeObject(ctx,a)<0||const_prop(ctx,obj,"offsets",a)<0){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}}
    if(JS_FreezeObject(ctx,obj)<0){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}return obj;
fail:JS_FreeValue(ctx,repeated);if(deps)for(size_t i=0;i<count;i++)JS_FreeValue(ctx,deps[i]);js_free(ctx,deps);js_free(ctx,offsets);js_free(ctx,elements);js_free(ctx,f);js_free(ctx,t);JS_FreeValue(ctx,obj);return JS_EXCEPTION;
}
static JSValue types_struct(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=1)return JS_ThrowTypeError(ctx,"types.struct expects one argument");return new_aggregate(ctx,argv[0],false,0);}
static JSValue types_array(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=2)return JS_ThrowTypeError(ctx,"types.array expects type and count");FfiType*t=JS_GetOpaque(argv[0],type_class);
    if (!t || t->kind == K_VOID || t->kind == K_BUFFER) return JS_ThrowTypeError(ctx, "invalid array element type");
    int64_t n;
    if (strict_integer(ctx, argv[1], &n, "array count") < 0) return JS_EXCEPTION;
    if (n <= 0 || n > UINT32_MAX) return JS_ThrowRangeError(ctx, "array count must be positive");
    return new_aggregate(ctx, argv[0], true, (size_t) n);
}

/* Prepared signatures and bound calls */
static void signature_clear(JSRuntime*rt,FfiSignature*s){if(s->type_values)for(unsigned i=0;i<=s->nargs;i++)JS_FreeValueRT(rt,s->type_values[i]);js_free_rt(rt,s->type_values);js_free_rt(rt,s->types);js_free_rt(rt,s->arg_types);js_free_rt(rt,s->offsets);memset(s,0,sizeof(*s));}
static void signature_mark(JSRuntime*rt,FfiSignature*s,JS_MarkFunc*mark){for(unsigned i=0;i<=s->nargs;i++)JS_MarkValue(rt,s->type_values[i],mark);}
static int parse_fixed(JSContext*ctx,JSValueConst options,unsigned nargs,int*out){*out=-1;if(JS_IsUndefined(options))return 0;if(!JS_IsObject(options))return JS_ThrowTypeError(ctx,"options must be an object"),-1;
    JSValue v=JS_GetPropertyStr(ctx,options,"fixed");if(JS_IsException(v))return -1;if(JS_IsUndefined(v)){JS_FreeValue(ctx,v);return 0;}int64_t n;
    if(strict_integer(ctx,v,&n,"fixed")<0){JS_FreeValue(ctx,v);return -1;}JS_FreeValue(ctx,v);
    if(n<=0||(uint64_t)n>=nargs)return JS_ThrowRangeError(ctx,"fixed must be greater than zero and less than parameter count"),-1;
    *out=(int)n;return 0;}
static int signature_prepare(JSContext*ctx,JSValueConst array,unsigned skip,JSValueConst options,FfiSignature*s){
    memset(s,0,sizeof(*s));if(!JS_IsArray(array))return JS_ThrowTypeError(ctx,"signature must be an array"),-1;JSValue lv=JS_GetPropertyStr(ctx,array,"length");uint64_t len;
    if (JS_IsException(lv)) return -1;
    int r = JS_ToIndex(ctx, &len, lv);
    JS_FreeValue(ctx, lv);
    if (r < 0) return -1;
    if(len<=skip||len-skip-1>UINT_MAX)return JS_ThrowTypeError(ctx,"signature requires a result type"),-1;
    s->nargs=(unsigned)(len-skip-1);if(parse_fixed(ctx,options,s->nargs,&s->fixed)<0)return -1;size_t count=(size_t)s->nargs+1;
    if(count>SIZE_MAX/sizeof(JSValue)||count>SIZE_MAX/sizeof(FfiType*)||s->nargs>SIZE_MAX/sizeof(ffi_type*)||s->nargs>SIZE_MAX/sizeof(size_t))return JS_ThrowRangeError(ctx,"signature is too large"),-1;
    s->type_values=js_mallocz(ctx,sizeof(JSValue)*count);s->types=js_mallocz(ctx,sizeof(FfiType*)*count);if(s->nargs)s->arg_types=js_mallocz(ctx,sizeof(ffi_type*)*s->nargs);
    if(!s->type_values||!s->types||(s->nargs&&!s->arg_types))goto fail;
    for(unsigned i=0;i<=s->nargs;i++){uint32_t at=i?skip+i:0;JSValue token=JS_GetPropertyUint32(ctx,array,at);if(JS_IsException(token))goto fail;FfiType*t=JS_GetOpaque(token,type_class);
        if(!t){JS_FreeValue(ctx,token);JS_ThrowTypeError(ctx,"signature item %u is not a type token",at+1);goto fail;}
        if(t->array){JS_FreeValue(ctx,token);JS_ThrowTypeError(ctx,"array types cannot be used in callable signatures");goto fail;}
        if((!i&&t->kind==K_BUFFER)||(i&&t->kind==K_VOID)){JS_FreeValue(ctx,token);JS_ThrowTypeError(ctx,"invalid type in callable signature");goto fail;}
        s->type_values[i]=token;s->types[i]=t;if(i)s->arg_types[i-1]=t->ffi;}
    if(s->fixed>=0)for(unsigned i=(unsigned)s->fixed;i<s->nargs;i++){TypeKind kind=s->types[i+1]->kind;if(kind==K_BOOL||kind==K_I8||kind==K_U8||kind==K_I16||kind==K_U16||kind==K_F32){JS_ThrowTypeError(ctx,"variadic argument %u requires an explicitly promoted C type",i+1);goto fail;}}
    ffi_status st=s->fixed>=0?ffi_prep_cif_var(&s->cif,FFI_DEFAULT_ABI,(unsigned)s->fixed,s->nargs,s->types[0]->ffi,s->arg_types):ffi_prep_cif(&s->cif,FFI_DEFAULT_ABI,s->nargs,s->types[0]->ffi,s->arg_types);
    if(st!=FFI_OK){JS_ThrowTypeError(ctx,"cannot prepare signature: %s",status_name(st));goto fail;}if(s->nargs)s->offsets=js_mallocz(ctx,sizeof(size_t)*s->nargs);if(s->nargs&&!s->offsets)goto fail;
    size_t frame=0,max_alignment=1;for(unsigned i=0;i<s->nargs;i++){FfiType*t=s->types[i+1];size_t a=pointer_kind(t)?_Alignof(void*):t->ffi->alignment,n=pointer_kind(t)?sizeof(void*):type_size(t);if(a>max_alignment)max_alignment=a;if(!size_align(&frame,a?a:1)){JS_ThrowRangeError(ctx,"call frame too large");goto fail;}s->offsets[i]=frame;if(!size_add(&frame,n)){JS_ThrowRangeError(ctx,"call frame too large");goto fail;}}size_t table;if(s->nargs>SIZE_MAX/sizeof(void*)){JS_ThrowRangeError(ctx,"call frame too large");goto fail;}table=sizeof(void*)*s->nargs;s->frame_offset=table;if(!size_align(&s->frame_offset,max_alignment)){JS_ThrowRangeError(ctx,"call frame too large");goto fail;}s->frame_size=frame;return 0;
fail:signature_clear(JS_GetRuntime(ctx),s);return -1;}
static int validate_buffer(JSContext*ctx,JSValueConst v){if(JS_IsNull(v)||JS_IsDataView(v)||JS_GetTypedArrayType(v)>=0)return 0;if(JS_PinArrayBuffer(ctx,v)<0)return -1;JS_UnpinArrayBuffer(v);return 0;}

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

static JSValue call_bound(JSContext*ctx,JSValueConst func,FfiBound*b,int argc,JSValueConst*argv,bool ignore_closed){
    FfiSignature*s=&b->sig;if(!ignore_closed&&((b->state&&b->state->closed)||(b->callback&&b->callback->closed)))return JS_ThrowTypeError(ctx,"FFI owner is closed");
    if((unsigned)argc!=s->nargs)return JS_ThrowTypeError(ctx,"expected %u FFI arguments but received %d",s->nargs,argc);
    bool temporary=b->in_call;void*allocation=b->call_storage;uint8_t*result=b->result_storage;
    if(temporary){allocation=js_mallocz(ctx,b->call_storage_size?b->call_storage_size:1);if(!allocation)return JS_EXCEPTION;result=js_mallocz(ctx,b->result_storage_size?b->result_storage_size:1);if(!result){js_free(ctx,allocation);return JS_EXCEPTION;}}
    b->in_call=true;memset(allocation,0,b->call_storage_size);memset(result,0,b->result_storage_size);
    void**args=allocation;uint8_t*frame=(uint8_t*)allocation+s->frame_offset;
    JSValue *pin_values=(JSValue*)((uint8_t*)allocation+b->pin_values_offset);
    FfiCallback **callbacks=(FfiCallback**)((uint8_t*)allocation+b->callback_values_offset);uint_fast64_t *callback_counts=(uint_fast64_t*)((uint8_t*)allocation+b->callback_counts_offset);
    for(unsigned i=0;i<s->nargs;i++)pin_values[i]=JS_UNDEFINED;
    /* Aggregate packing can execute getters. Recheck the owner afterwards even
     * without a capability hook; a getter can synchronously close it. */
    if(prepare_call_values(ctx,s,argv,args,frame,callbacks,callback_counts)<0)goto fail;
    if(!ignore_closed&&((b->state&&b->state->closed)||(b->callback&&b->callback->closed))){JS_ThrowTypeError(ctx,"FFI owner is closed");goto fail;}
    TJS_CAPABILITY_REVALIDATE(tjs__capability(ctx, TJS_CAP_DYNLIB | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "ffi.call"), cancel_bound_call(ctx, b, temporary, allocation, result), do { if(!ignore_closed&&((b->state&&b->state->closed)||(b->callback&&b->callback->closed))){JS_ThrowTypeError(ctx,"FFI owner is closed");goto fail;} if(prepare_call_values(ctx,s,argv,args,frame,callbacks,callback_counts)<0)goto fail; } while (0));
    /* Phase 2 acquires all raw buffer/aggregate addresses only after validation completed. */
    for(unsigned i=0;i<s->nargs;i++){FfiType*t=s->types[i+1];if(t->kind==K_BUFFER){void*p=NULL;if(!JS_IsNull(argv[i])&&acquire_buffer(ctx,argv[i],&p,&pin_values[i])<0)goto fail;memcpy(frame+s->offsets[i],&p,sizeof(p));}
        else if(t->kind==K_AGGREGATE){size_t bytes;uint8_t*p=JS_GetUint8Array(ctx,&bytes,argv[i]);if(!p&&JS_HasException(ctx))goto fail;if(bytes!=type_size(t)){JS_ThrowRangeError(ctx,"argument %u must contain exactly %zu bytes",i+1,type_size(t));goto fail;}memcpy(frame+s->offsets[i],p,bytes);}}
    FfiType*rt=s->types[0];size_t n=type_size(rt);CallFrame cf={.previous=active_call,.exception=JS_UNDEFINED};active_call=&cf;if(b->state)b->state->active_calls++;
    ffi_call(&s->cif,FFI_FN(b->addr),n?result:NULL,args);capture_errno(b->state);if(b->state){assert(b->state->active_calls>0);b->state->active_calls--;state_maybe_unload(b->state);}bool bad_thread=false;for(unsigned i=0;i<s->nargs;i++)if(callbacks[i]&&callback_counts[i]!=atomic_load_explicit(&callbacks[i]->foreign_calls,memory_order_acquire)){bad_thread=true;break;}active_call=cf.previous;b->in_call=temporary;release_pins(ctx,s,pin_values);
    if(temporary)js_free(ctx,allocation);
    if(!JS_IsUndefined(cf.exception)){if(temporary)js_free(ctx,result);return JS_Throw(ctx,cf.exception);}if(bad_thread){if(temporary)js_free(ctx,result);return JS_ThrowTypeError(ctx,"FFI callback invoked from an unsupported native thread");}
    JSValue out;if(rt->kind==K_AGGREGATE)out=JS_NewUint8ArrayCopy(ctx,result,n);else if(narrow_kind(rt)){ffi_arg word=0;memcpy(&word,result,sizeof(word));uint8_t small[sizeof(ffi_arg)]={0};
        switch(rt->kind){case K_BOOL:case K_U8:{uint8_t v=(uint8_t)word;memcpy(small,&v,1);break;}case K_I8:{int8_t v=(int8_t)word;memcpy(small,&v,1);break;}case K_U16:{uint16_t v=(uint16_t)word;memcpy(small,&v,2);break;}case K_I16:{int16_t v=(int16_t)word;memcpy(small,&v,2);break;}case K_U32:{uint32_t v=(uint32_t)word;memcpy(small,&v,4);break;}case K_I32:{int32_t v=(int32_t)word;memcpy(small,&v,4);break;}default:break;}out=read_value(ctx,rt,small,func,b->state,b->callback,false);
    }else out=read_value(ctx,rt,result,func,b->state,b->callback,false);if(temporary)js_free(ctx,result);return out;
fail:release_pins(ctx,s,pin_values);b->in_call=temporary;if(temporary){js_free(ctx,result);js_free(ctx,allocation);}return JS_EXCEPTION;}
static JSValue bound_call(JSContext*ctx,JSValueConst func,JSValueConst self,int argc,JSValueConst*argv,int flags){(void)self;if(flags&JS_CALL_FLAG_CONSTRUCTOR)return JS_ThrowTypeError(ctx,"FFI functions are not constructors");FfiBound*b=JS_GetOpaque2(ctx,func,bound_class);return b?call_bound(ctx,func,b,argc,argv,false):JS_EXCEPTION;}
static JSValue bound_pointer(JSContext*ctx,JSValueConst self){FfiBound*b=JS_GetOpaque2(ctx,self,bound_class);if(!b)return JS_EXCEPTION;if((b->state&&b->state->closed)||(b->callback&&b->callback->closed))return JS_ThrowTypeError(ctx,"FFI owner is closed");return new_pointer(ctx,b->addr,self,b->state,b->callback);}
static void bound_mark(JSRuntime*rt,JSValueConst value,JS_MarkFunc*mark){FfiBound*b=JS_GetOpaque(value,bound_class);if(b){signature_mark(rt,&b->sig,mark);JS_MarkValue(rt,b->owner,mark);}}
static void bound_finalizer(JSRuntime*rt,JSValueConst value){FfiBound*b=JS_GetOpaque(value,bound_class);if(!b)return;state_defer_unref(rt,b->state);signature_clear(rt,&b->sig);JS_FreeValueRT(rt,b->owner);js_free_rt(rt,b->call_storage);js_free_rt(rt,b->result_storage);js_free_rt(rt,b);}
static JSClassDef bound_def={"BoundFfiFunction",.finalizer=bound_finalizer,.gc_mark=bound_mark,.call=bound_call};
static JSValue new_bound(JSContext*ctx,void*addr,JSValueConst owner,FfiLibraryState*state,FfiCallback*cb,JSValueConst sig,unsigned skip,JSValueConst options){JSValue obj=JS_NewObjectClass(ctx,bound_class);if(JS_IsException(obj))return obj;FfiBound*b=js_mallocz(ctx,sizeof(*b));if(!b){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}b->owner=JS_DupValue(ctx,owner);b->addr=addr;b->state=state;b->callback=cb;if(signature_prepare(ctx,sig,skip,options,&b->sig)<0)goto fail;size_t total=b->sig.frame_offset;if(!size_add(&total,b->sig.frame_size)||!size_align(&total,_Alignof(JSValue)))goto too_large;b->pin_values_offset=total;if(b->sig.nargs>SIZE_MAX/sizeof(JSValue)||!size_add(&total,sizeof(JSValue)*b->sig.nargs)||!size_align(&total,_Alignof(FfiCallback*)))goto too_large;b->callback_values_offset=total;if(b->sig.nargs>SIZE_MAX/sizeof(FfiCallback*)||!size_add(&total,sizeof(FfiCallback*)*b->sig.nargs)||!size_align(&total,_Alignof(uint_fast64_t)))goto too_large;b->callback_counts_offset=total;if(b->sig.nargs>SIZE_MAX/sizeof(uint_fast64_t)||!size_add(&total,sizeof(uint_fast64_t)*b->sig.nargs))goto too_large;b->call_storage_size=total;b->result_storage_size=narrow_kind(b->sig.types[0])?sizeof(ffi_arg):type_size(b->sig.types[0]);b->call_storage=js_mallocz(ctx,total?total:1);b->result_storage=js_mallocz(ctx,b->result_storage_size?b->result_storage_size:1);if(!b->call_storage||!b->result_storage)goto fail;state_ref(state);JS_SetOpaque(obj,b);return obj;
too_large:JS_ThrowRangeError(ctx,"call frame too large");
fail:signature_clear(JS_GetRuntime(ctx),&b->sig);JS_FreeValue(ctx,b->owner);js_free(ctx,b->call_storage);js_free(ctx,b->result_storage);js_free(ctx,b);JS_FreeValue(ctx,obj);return JS_EXCEPTION;}

/* Libraries */
static FfiLibrary*require_library(JSContext*ctx,JSValueConst value,bool closed_ok){FfiLibrary*l=JS_GetOpaque2(ctx,value,library_class);if(!l)return NULL;if(!closed_ok&&l->closed){JS_ThrowTypeError(ctx,"FFI library is closed");return NULL;}return l;}
static int resolve(JSContext*ctx,FfiLibrary*l,JSValueConst value,void**addr){if(!JS_IsString(value))return JS_ThrowTypeError(ctx,"symbol name must be a string"),-1;const char*name=JS_ToCString(ctx,value);if(!name)return -1;int r=uv_dlsym(&l->state->handle,name,addr);if(r)JS_ThrowReferenceError(ctx,"cannot resolve FFI symbol '%s': %s",name,uv_dlerror(&l->state->handle));JS_FreeCString(ctx,name);return r?-1:0;}
static JSValue ffi_open_js(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){
    (void)self;
    if(argc!=1||!JS_IsString(argv[0]))return JS_ThrowTypeError(ctx,"ffi.open expects a path string");
    const char*path=JS_ToCString(ctx,argv[0]);
    if(!path)return JS_EXCEPTION;
    TJS_CAPABILITY(tjs__capability_resource(ctx, TJS_CAP_DYNLIB | TJS_CAP_IO_ACCESS | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "ffi.open", path), JS_FreeCString(ctx, path));
    JSValue obj=JS_NewObjectClass(ctx,library_class);
    if(JS_IsException(obj)){JS_FreeCString(ctx,path);return obj;}
    FfiLibrary*l=js_mallocz(ctx,sizeof(*l));
    FfiLibraryState*state=tjs__mallocz(sizeof(*state));
    if(!l||!state){JS_FreeCString(ctx,path);js_free(ctx,l);tjs__free(state);JS_FreeValue(ctx,obj);return JS_EXCEPTION;}
    const char*error=NULL;
    int r=ffi_dlopen(path,&state->handle,&error);
    if(r){JSValue e=JS_ThrowReferenceError(ctx,"cannot open FFI library '%s': %s",path,error?error:"loader error");JS_FreeCString(ctx,path);if(state->handle.handle)uv_dlclose(&state->handle);tjs__free(state);js_free(ctx,l);JS_FreeValue(ctx,obj);return e;}
    JS_FreeCString(ctx,path);
    state->handle_open=true;state->refs=1;l->state=state;
#if defined(_WIN32)
    void *errno_symbol = NULL;
    if (uv_dlsym(&state->handle, "_errno", &errno_symbol) == 0) state->errno_location = (int *(*)(void)) errno_symbol;
#elif defined(__APPLE__)
    void *errno_symbol = NULL;
    if (uv_dlsym(&state->handle, "__error", &errno_symbol) == 0) state->errno_location = (int *(*)(void)) errno_symbol;
#else
    void *errno_symbol = NULL;
    if (uv_dlsym(&state->handle, "__errno_location", &errno_symbol) == 0) state->errno_location = (int *(*)(void)) errno_symbol;
#endif
    JS_SetOpaque(obj,l);return obj;}
static JSValue library_symbol(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){FfiLibrary*l=require_library(ctx,self,false);if(!l)return JS_EXCEPTION;if(argc!=1)return JS_ThrowTypeError(ctx,"symbol expects one name");void*addr;if(resolve(ctx,l,argv[0],&addr)<0)return JS_EXCEPTION;return new_pointer(ctx,addr,self,l->state,NULL);}
static JSValue library_bind(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){
    FfiLibrary*l=require_library(ctx,self,false);if(!l)return JS_EXCEPTION;if(argc<1||argc>2||!JS_IsArray(argv[0]))return JS_ThrowTypeError(ctx,"bind expects a signature");
    JSValue length_value=JS_GetPropertyStr(ctx,argv[0],"length");uint64_t length;if(JS_IsException(length_value))return JS_EXCEPTION;int converted=JS_ToIndex(ctx,&length,length_value);JS_FreeValue(ctx,length_value);if(converted<0)return JS_EXCEPTION;if(length<2||length-2>UINT_MAX)return JS_ThrowTypeError(ctx,"library signature requires result type and symbol");
    int fixed;if(parse_fixed(ctx,argc==2?argv[1]:JS_UNDEFINED,(unsigned)(length-2),&fixed)<0)return JS_EXCEPTION;
    JSValue name=JS_GetPropertyUint32(ctx,argv[0],1);if(JS_IsException(name))return JS_EXCEPTION;if(!JS_IsString(name)){JS_FreeValue(ctx,name);return JS_ThrowTypeError(ctx,"symbol name must be a string");}const char*symbol=JS_ToCString(ctx,name);if(!symbol){JS_FreeValue(ctx,name);return JS_EXCEPTION;}
    for(FfiBindCache*entry=l->cache;entry;entry=entry->next){if(strcmp(entry->symbol,symbol)!=0)continue;FfiBound*cached=JS_GetOpaque(entry->bound,bound_class);if(!cached||cached->sig.nargs!=(unsigned)(length-2)||cached->sig.fixed!=fixed)continue;bool match=true;for(unsigned i=0;i<=cached->sig.nargs;i++){uint32_t at=i?i+1:0;JSValue token=JS_GetPropertyUint32(ctx,argv[0],at);if(JS_IsException(token)){JS_FreeCString(ctx,symbol);JS_FreeValue(ctx,name);return JS_EXCEPTION;}int equal=JS_IsStrictEqual(ctx,token,cached->sig.type_values[i]);JS_FreeValue(ctx,token);if(equal<0){JS_FreeCString(ctx,symbol);JS_FreeValue(ctx,name);return JS_EXCEPTION;}match=equal!=0;if(!match)break;}if(match){JSValue result=JS_DupValue(ctx,entry->bound);JS_FreeCString(ctx,symbol);JS_FreeValue(ctx,name);return result;}}
    void*addr;int r=resolve(ctx,l,name,&addr);JS_FreeValue(ctx,name);if(r<0){JS_FreeCString(ctx,symbol);return JS_EXCEPTION;}JSValue result=new_bound(ctx,addr,JS_UNDEFINED,l->state,NULL,argv[0],1,argc==2?argv[1]:JS_UNDEFINED);if(JS_IsException(result)){JS_FreeCString(ctx,symbol);return result;}
    FfiBindCache*entry=js_mallocz(ctx,sizeof(*entry));char*symbol_copy=entry?js_strdup(ctx,symbol):NULL;JS_FreeCString(ctx,symbol);if(!entry||!symbol_copy){js_free(ctx,entry);JS_FreeValue(ctx,result);return JS_EXCEPTION;}entry->symbol=symbol_copy;entry->bound=JS_DupValue(ctx,result);entry->next=l->cache;l->cache=entry;return result;
}
static JSValue library_read(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){FfiLibrary*l=require_library(ctx,self,false);if(!l)return JS_EXCEPTION;if(argc!=1||!JS_IsArray(argv[0]))return JS_ThrowTypeError(ctx,"read expects [type, symbol]");JSValue tv=JS_GetPropertyUint32(ctx,argv[0],0);if(JS_IsException(tv))return JS_EXCEPTION;FfiType*t=JS_GetOpaque(tv,type_class);if(!t||t->kind==K_VOID||t->kind==K_BUFFER){JS_FreeValue(ctx,tv);return JS_ThrowTypeError(ctx,"read requires a readable type");}JSValue name=JS_GetPropertyUint32(ctx,argv[0],1);void*addr;if(JS_IsException(name)){JS_FreeValue(ctx,tv);return JS_EXCEPTION;}int r=resolve(ctx,l,name,&addr);JS_FreeValue(ctx,name);if(r<0){JS_FreeValue(ctx,tv);return JS_EXCEPTION;}JSValue out=read_value(ctx,t,addr,self,l->state,NULL,false);JS_FreeValue(ctx,tv);return out;}
static JSValue library_close(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)argc;(void)argv;FfiLibrary*l=require_library(ctx,self,true);if(!l)return JS_EXCEPTION;if(!l->closed){l->closed=true;l->state->closed=true;state_maybe_unload(l->state);}return JS_UNDEFINED;}
static void library_mark(JSRuntime*rt,JSValueConst value,JS_MarkFunc*mark){FfiLibrary*l=JS_GetOpaque(value,library_class);if(l)for(FfiBindCache*entry=l->cache;entry;entry=entry->next)JS_MarkValue(rt,entry->bound,mark);}
static void library_finalizer(JSRuntime*rt,JSValueConst value){FfiLibrary*l=JS_GetOpaque(value,library_class);if(l){FfiBindCache*entry=l->cache;while(entry){FfiBindCache*next=entry->next;JS_FreeValueRT(rt,entry->bound);js_free_rt(rt,entry->symbol);js_free_rt(rt,entry);entry=next;}state_defer_unref(rt,l->state);js_free_rt(rt,l);}}
static JSClassDef library_def={"FfiLibrary",.finalizer=library_finalizer,.gc_mark=library_mark};

/* Callbacks */
static void callback_zero(FfiCallback*cb,void*result){size_t n=type_size(cb->sig.types[0]);if(result&&n)memset(result,0,n);}
static int callback_result(JSContext*ctx,FfiType*t,JSValueConst value,void*out){if(t->kind==K_VOID)return 0;if(t->kind==K_AGGREGATE){size_t n;uint8_t*p=JS_GetUint8Array(ctx,&n,value);if(!p)return JS_ThrowTypeError(ctx,"callback must return Uint8Array"),-1;if(n!=type_size(t))return JS_ThrowRangeError(ctx,"callback result size must be %zu",type_size(t)),-1;memcpy(out,p,n);return 0;}return pack_value(ctx,t,value,out);}
static void latch_exception(FfiCallback*cb){JSContext*ctx=cb->ctx;JSValue e=JS_GetException(ctx);if(active_call){if(JS_IsUndefined(active_call->exception))active_call->exception=e;else JS_FreeValue(ctx,e);return;}if(JS_IsUncatchableError(e)){tjs__stop_uncatchable_error(ctx,e);JS_FreeValue(ctx,e);return;}JSValue handled=tjs__dispatch_event(ctx,EV_JOB_EXCEPTION,e);if(JS_IsException(handled))TJS_DumpException(ctx);if(JS_IsException(handled)||(JS_IsBool(handled)&&!JS_VALUE_GET_BOOL(handled)))TJS_Stop(TJS_GetRuntime(ctx));JS_FreeValue(ctx,e);JS_FreeValue(ctx,handled);}
static void callback_invoke(ffi_cif*cif,void*result,void**args,void*opaque){(void)cif;FfiCallback*cb=opaque;uv_thread_t current=uv_thread_self();if(!uv_thread_equal(&current,&cb->thread)){callback_zero(cb,result);atomic_fetch_add_explicit(&cb->foreign_calls,1,memory_order_release);if(!atomic_exchange_explicit(&cb->foreign_reported,true,memory_order_relaxed)){fputs("circu.js FFI: callback invoked from an unsupported native thread; returned ABI zero without entering JavaScript\n",stderr);fflush(stderr);}return;}if(cb->closed){callback_zero(cb,result);return;}JSContext*ctx=cb->ctx;unsigned n=cb->sig.nargs;JSValue*values=n?js_malloc(ctx,sizeof(JSValue)*n):NULL;if(n&&!values){callback_zero(cb,result);latch_exception(cb);return;}unsigned made=0;for(;made<n;made++){FfiType*t=cb->sig.types[made+1];values[made]=read_value(ctx,t,args[made],JS_UNDEFINED,NULL,NULL,false);if(JS_IsException(values[made]))break;}JSValue ret=JS_EXCEPTION;if(made==n)ret=JS_Call(ctx,cb->function,JS_UNDEFINED,n,values);for(unsigned i=0;i<made;i++)JS_FreeValue(ctx,values[i]);js_free(ctx,values);if(JS_IsException(ret)){callback_zero(cb,result);latch_exception(cb);}else{if(callback_result(ctx,cb->sig.types[0],ret,result)<0){callback_zero(cb,result);latch_exception(cb);}JS_FreeValue(ctx,ret);}}
static JSValue callback_create(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=2||!JS_IsArray(argv[0])||!JS_IsFunction(ctx,argv[1]))return JS_ThrowTypeError(ctx,"callback expects signature and function");JSValue obj=JS_NewObjectClass(ctx,callback_class);if(JS_IsException(obj))return obj;FfiCallback*cb=js_mallocz(ctx,sizeof(*cb));if(!cb){JS_FreeValue(ctx,obj);return JS_EXCEPTION;}atomic_init(&cb->foreign_calls,0);atomic_init(&cb->foreign_reported,false);if(signature_prepare(ctx,argv[0],0,JS_UNDEFINED,&cb->sig)<0){js_free(ctx,cb);JS_FreeValue(ctx,obj);return JS_EXCEPTION;}cb->closure=ffi_closure_alloc(sizeof(ffi_closure),&cb->code);if(!cb->closure){signature_clear(JS_GetRuntime(ctx),&cb->sig);js_free(ctx,cb);JS_FreeValue(ctx,obj);return JS_ThrowOutOfMemory(ctx);}ffi_status st=ffi_prep_closure_loc(cb->closure,&cb->sig.cif,callback_invoke,cb,cb->code);if(st!=FFI_OK){ffi_closure_free(cb->closure);signature_clear(JS_GetRuntime(ctx),&cb->sig);js_free(ctx,cb);JS_FreeValue(ctx,obj);return JS_ThrowTypeError(ctx,"cannot prepare callback: %s",status_name(st));}cb->function=JS_DupValue(ctx,argv[1]);cb->ctx=ctx;cb->thread=uv_thread_self();JS_SetOpaque(obj,cb);return obj;}
static JSValue callback_pointer(JSContext*ctx,JSValueConst self){FfiCallback*cb=JS_GetOpaque2(ctx,self,callback_class);if(!cb)return JS_EXCEPTION;if(cb->closed)return JS_ThrowTypeError(ctx,"FFI callback is closed");return new_pointer(ctx,cb->code,self,NULL,cb);}
static JSValue callback_close(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)argc;(void)argv;FfiCallback*cb=JS_GetOpaque2(ctx,self,callback_class);if(!cb)return JS_EXCEPTION;cb->closed=true;return JS_UNDEFINED;}
static void callback_mark(JSRuntime*rt,JSValueConst value,JS_MarkFunc*mark){FfiCallback*cb=JS_GetOpaque(value,callback_class);if(cb){signature_mark(rt,&cb->sig,mark);JS_MarkValue(rt,cb->function,mark);}}
static void callback_finalizer(JSRuntime*rt,JSValueConst value){FfiCallback*cb=JS_GetOpaque(value,callback_class);if(!cb)return;if(cb->closure)ffi_closure_free(cb->closure);signature_clear(rt,&cb->sig);JS_FreeValueRT(rt,cb->function);js_free_rt(rt,cb);}
static JSClassDef callback_def={"FfiCallback",.finalizer=callback_finalizer,.gc_mark=callback_mark};

/* Owned pointers copy the disposer address/CIF and pin the relevant library
 * states until disposal completes outside the GC finalizer. */
static void owned_dispose(OwnedPointer*o){if(!o->armed||!o->pointer.valid)return;o->armed=false;o->pointer.addr=NULL;o->pointer.valid=false;FfiDisposeJob*job=o->job;o->job=NULL;dispose_job_run(job,true);}
static JSValue owned_close(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)argc;(void)argv;OwnedPointer*o=JS_GetOpaque2(ctx,self,owned_class);if(!o)return JS_EXCEPTION;owned_dispose(o);return JS_UNDEFINED;}
static JSValue owned_release(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)argc;(void)argv;OwnedPointer*o=JS_GetOpaque2(ctx,self,owned_class);if(!o)return JS_EXCEPTION;if(!o->armed||!o->pointer.valid)return JS_ThrowTypeError(ctx,"owned pointer is closed or released");JSValue p=new_pointer(ctx,o->pointer.addr,o->pointer.owner,o->pointer.state,o->pointer.callback);if(JS_IsException(p))return p;o->armed=false;o->pointer.valid=false;o->pointer.addr=NULL;FfiDisposeJob*job=o->job;o->job=NULL;state_owned_unref(job->resource_state);state_owned_unref(job->state);tjs__free(job);return p;}
static void owned_mark(JSRuntime*rt,JSValueConst value,JS_MarkFunc*mark){OwnedPointer*o=JS_GetOpaque(value,owned_class);if(o&&!JS_IsUndefined(o->pointer.owner))JS_MarkValue(rt,o->pointer.owner,mark);}
static void owned_finalizer(JSRuntime*rt,JSValueConst value){OwnedPointer*o=JS_GetOpaque(value,owned_class);if(!o)return;if(o->job){FfiDisposeJob*job=o->job;o->job=NULL;if(o->armed&&o->pointer.valid){job->cleanup.kind=CLEANUP_DISPOSE;cleanup_enqueue(JS_GetRuntimeOpaque(rt),&job->cleanup);}else{state_owned_unref(job->resource_state);state_owned_unref(job->state);tjs__free(job);}}JS_FreeValueRT(rt,o->pointer.owner);js_free_rt(rt,o);}
static JSClassDef owned_def={"OwnedPointer",.finalizer=owned_finalizer,.gc_mark=owned_mark};

/* Public function() and unsafe namespace */
static JSValue ffi_function_js(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc<2||argc>3)return JS_ThrowTypeError(ctx,"function expects pointer and signature");FfiPointer*p=require_pointer(ctx,argv[0]);if(!p)return JS_EXCEPTION;return new_bound(ctx,p->addr,argv[0],p->state,p->callback,argv[1],0,argc==3?argv[2]:JS_UNDEFINED);}
static JSValue unsafe_address(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=1)return JS_ThrowTypeError(ctx,"address expects Pointer");FfiPointer*p=require_pointer(ctx,argv[0]);return p?JS_NewBigUint64(ctx,(uint64_t)(uintptr_t)p->addr):JS_EXCEPTION;}
static JSValue unsafe_from_address(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=1||!JS_IsBigInt(argv[0]))return JS_ThrowTypeError(ctx,"fromAddress expects bigint");uint64_t a;if(exact_bigint(ctx,argv[0],false,(unsigned)(sizeof(uintptr_t)*CHAR_BIT),&a)<0)return JS_EXCEPTION;
    return new_pointer(ctx,(void*)(uintptr_t)a,JS_UNDEFINED,NULL,NULL);}
static JSValue unsafe_pointer_of(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=1)return JS_ThrowTypeError(ctx,"pointerOf expects BufferSource");if(validate_buffer(ctx,argv[0])<0)return JS_EXCEPTION;if(JS_IsNull(argv[0]))return JS_NULL;void*p=NULL;JSValue backing=JS_UNDEFINED;if(acquire_buffer(ctx,argv[0],&p,&backing)<0)return JS_EXCEPTION;JSValue result=new_pointer(ctx,p,argv[0],NULL,NULL);if(JS_IsException(result)){JS_UnpinArrayBuffer(backing);JS_FreeValue(ctx,backing);return result;}FfiPointer*pointer=JS_GetOpaque(result,pointer_class);assert(pointer);pointer->pinned_backing=backing;JS_FreeValue(ctx,backing);return result;}
static JSValue unsafe_offset(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=2)return JS_ThrowTypeError(ctx,"offset expects Pointer and number");FfiPointer*p=require_pointer(ctx,argv[0]);if(!p)return JS_EXCEPTION;int64_t off;if(strict_integer(ctx,argv[1],&off,"offset")<0)return JS_EXCEPTION;uintptr_t a=(uintptr_t)p->addr;if((off>0&&a>UINTPTR_MAX-(uintptr_t)off)||(off<0&&a<(uintptr_t)(-(off+1))+1))return JS_ThrowRangeError(ctx,"pointer offset overflow");a=off>=0?a+(uintptr_t)off:a-((uintptr_t)(-(off+1))+1);return new_pointer(ctx,(void*)a,argv[0],p->state,p->callback);}
static JSValue unsafe_deref(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc<1||argc>2)return JS_ThrowTypeError(ctx,"deref expects Pointer");FfiPointer*p=require_pointer(ctx,argv[0]);if(!p)return JS_EXCEPTION;int64_t count=1;if(argc==2&&strict_integer(ctx,argv[1],&count,"count")<0)return JS_EXCEPTION;if(count<0)return JS_ThrowRangeError(ctx,"count must be non-negative");void*a=p->addr;for(int64_t i=0;i<count&&a;i++)memcpy(&a,a,sizeof(a));return new_pointer(ctx,a,argv[0],p->state,p->callback);}
static JSValue unsafe_view(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=2)return JS_ThrowTypeError(ctx,"view expects Pointer and length");FfiPointer*p=require_pointer(ctx,argv[0]);if(!p)return JS_EXCEPTION;int64_t n;if(strict_integer(ctx,argv[1],&n,"length")<0)return JS_EXCEPTION;if(n<0||(uint64_t)n>SIZE_MAX)return JS_ThrowRangeError(ctx,"invalid view length");JSValue view=JS_NewUint8Array(ctx,p->addr,(size_t)n,NULL,NULL,false);if(JS_IsException(view))return view;if(JS_DefinePropertyValueStr(ctx,view,"_ffiOwner",JS_DupValue(ctx,argv[0]),0)<0){JS_FreeValue(ctx,view);return JS_EXCEPTION;}return view;}
static JSValue unsafe_cstring(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc<1||argc>2)return JS_ThrowTypeError(ctx,"readCString expects Pointer");FfiPointer*p=require_pointer(ctx,argv[0]);if(!p)return JS_EXCEPTION;if(argc==1)return JS_NewString(ctx,p->addr);int64_t n;if(strict_integer(ctx,argv[1],&n,"maximum length")<0)return JS_EXCEPTION;if(n<0||(uint64_t)n>SIZE_MAX)return JS_ThrowRangeError(ctx,"invalid maximum length");return JS_NewStringLen(ctx,p->addr,strnlen(p->addr,(size_t)n));}
static JSValue unsafe_loop(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;(void)argc;(void)argv;return new_pointer(ctx,tjs_get_loop(ctx),JS_UNDEFINED,NULL,NULL);}
static JSValue unsafe_adopt(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=2)return JS_ThrowTypeError(ctx,"adopt expects pointer and disposer");if(JS_GetOpaque(argv[0],owned_class))return JS_ThrowTypeError(ctx,"cannot adopt an owned pointer; release it instead");FfiPointer*p=require_pointer(ctx,argv[0]);if(!p)return JS_EXCEPTION;
    /* GC fallback runs from a native cleanup queue after the JS owner may have
     * been finalized. Borrowed buffer and callback addresses therefore cannot
     * safely become owned resources; adopt is for independent native storage. */
    if(p->callback||(!p->state&&!JS_IsUndefined(p->owner)))return JS_ThrowTypeError(ctx,"cannot adopt a borrowed buffer or callback pointer");
    FfiBound*b=JS_GetOpaque(argv[1],bound_class);if(!b||b->sig.fixed>=0||b->sig.nargs!=1||b->sig.types[0]->kind!=K_VOID||b->sig.types[1]->kind!=K_POINTER||b->callback)return JS_ThrowTypeError(ctx,"disposer must be a native bound void(pointer) function");if(b->state&&b->state->closed)return JS_ThrowTypeError(ctx,"disposer belongs to a closed FFI owner");JSValue obj=JS_NewObjectClass(ctx,owned_class);if(JS_IsException(obj))return obj;OwnedPointer*o=js_mallocz(ctx,sizeof(*o));FfiDisposeJob*job=tjs__mallocz(sizeof(*job));if(!o||!job){js_free(ctx,o);tjs__free(job);JS_FreeValue(ctx,obj);return JS_EXCEPTION;}job->resource_addr=p->addr;job->disposer_addr=b->addr;job->arg_types[0]=&ffi_type_pointer;job->state=b->state;job->resource_state=p->state!=b->state?p->state:NULL;ffi_status st=ffi_prep_cif(&job->cif,b->sig.cif.abi,1,&ffi_type_void,job->arg_types);if(st!=FFI_OK){js_free(ctx,o);tjs__free(job);JS_FreeValue(ctx,obj);return JS_ThrowTypeError(ctx,"cannot prepare disposer: %s",status_name(st));}state_owned_ref(job->state);state_owned_ref(job->resource_state);o->pointer.addr=p->addr;o->pointer.owner=JS_DupValue(ctx,argv[0]);o->pointer.state=p->state;o->pointer.callback=p->callback;o->pointer.valid=true;o->job=job;o->armed=true;JS_SetOpaque(obj,o);return obj;}

static JSValue ffi_errno_js(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;(void)argv;if(argc)return JS_ThrowTypeError(ctx,"errno expects no arguments");return JS_NewInt32(ctx,last_errno);}
#ifndef _WIN32
static const char*strerror_gnu(char*r,char*b,size_t n,int e){(void)b;(void)n;(void)e;return r?r:"Unknown error";}static const char*strerror_xsi(int r,char*b,size_t n,int e){if(r)snprintf(b,n,"Unknown error %d",e);return b;}
#define STRERROR_RESULT(call,b,n,e) _Generic((call),char*:strerror_gnu,default:strerror_xsi)((call),(b),(n),(e))
#endif
static JSValue ffi_strerror_js(JSContext*ctx,JSValueConst self,int argc,JSValueConst*argv){(void)self;if(argc!=1||!JS_IsNumber(argv[0]))return JS_ThrowTypeError(ctx,"strerror expects number");int32_t e;if(JS_ToInt32(ctx,&e,argv[0])<0)return JS_EXCEPTION;char b[256]={0};
#ifdef _WIN32
    if(strerror_s(b,sizeof(b),e))snprintf(b,sizeof(b),"Unknown error %d",e);return JS_NewString(ctx,b);
#else
    return JS_NewString(ctx,STRERROR_RESULT(strerror_r(e,b,sizeof(b)),b,sizeof(b),e));
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

static const JSCFunctionListEntry library_proto[]={JS_CFUNC_DEF("bind",2,library_bind),JS_CFUNC_DEF("symbol",1,library_symbol),JS_CFUNC_DEF("read",1,library_read),JS_CFUNC_DEF("close",0,library_close)};
static const JSCFunctionListEntry bound_proto[]={JS_CGETSET_DEF("pointer",bound_pointer,NULL)};
static const JSCFunctionListEntry callback_proto[]={JS_CGETSET_DEF("pointer",callback_pointer,NULL),JS_CFUNC_DEF("close",0,callback_close)};
static const JSCFunctionListEntry owned_proto[]={JS_CFUNC_DEF("close",0,owned_close),JS_CFUNC_DEF("release",0,owned_release)};
static int register_class(JSContext*ctx,JSClassID*id,JSClassDef*def,const JSCFunctionListEntry*props,size_t count,JSCFunction*dispose){JSRuntime*rt=JS_GetRuntime(ctx);JS_NewClassID(rt,id);if(JS_NewClass(rt,*id,def)<0)return -1;JSValue proto=JS_NewObject(ctx);if(JS_IsException(proto))return -1;if(props&&JS_SetPropertyFunctionList(ctx,proto,props,(int)count)<0){JS_FreeValue(ctx,proto);return -1;}if(dispose){JSValue f=JS_NewCFunction(ctx,dispose,"[Symbol.dispose]",0);if(JS_IsException(f)||JS_DefinePropertyValue(ctx,proto,JS_ATOM_Symbol_dispose,f,JS_PROP_CONFIGURABLE|JS_PROP_WRITABLE)<0){JS_FreeValue(ctx,proto);return -1;}}JS_SetClassProto(ctx,*id,proto);return 0;}
static int add_type(JSContext*ctx,JSValueConst types,const char*name,ffi_type*ffi,TypeKind kind){JSValue token=new_type(ctx,ffi,kind,name);return JS_IsException(token)?-1:JS_SetPropertyStr(ctx,types,name,token);}

void tjs__mod_ffi_init(JSContext *ctx, JSValue ffi_object) {
    if(register_class(ctx,&type_class,&type_def,NULL,0,NULL)<0||register_class(ctx,&pointer_class,&pointer_def,NULL,0,NULL)<0||
       register_class(ctx,&owned_class,&owned_def,owned_proto,countof(owned_proto),owned_close)<0||register_class(ctx,&library_class,&library_def,library_proto,countof(library_proto),library_close)<0||
       register_class(ctx,&bound_class,&bound_def,bound_proto,countof(bound_proto),NULL)<0||register_class(ctx,&callback_class,&callback_def,callback_proto,countof(callback_proto),callback_close)<0)return;
    JSValue types=JS_NewObject(ctx);if(JS_IsException(types))return;
#define ADD(n,f,k) if(add_type(ctx,types,n,&f,k)<0){JS_FreeValue(ctx,types);return;}
    ADD("void",ffi_type_void,K_VOID);ADD("bool",ffi_type_uint8,K_BOOL);ADD("i8",ffi_type_sint8,K_I8);ADD("u8",ffi_type_uint8,K_U8);
    ADD("i16",ffi_type_sint16,K_I16);ADD("u16",ffi_type_uint16,K_U16);ADD("i32",ffi_type_sint32,K_I32);ADD("u32",ffi_type_uint32,K_U32);
    ADD("i64",ffi_type_sint64,K_I64);ADD("u64",ffi_type_uint64,K_U64);ADD("f32",ffi_type_float,K_F32);ADD("f64",ffi_type_double,K_F64);
    ADD("pointer",ffi_type_pointer,K_POINTER);ADD("buffer",ffi_type_pointer,K_BUFFER);ADD("function",ffi_type_pointer,K_FUNCTION);
    ADD("schar",ffi_type_schar,K_I8);ADD("uchar",ffi_type_uchar,K_U8);ADD("short",ffi_type_sshort,K_I16);ADD("ushort",ffi_type_ushort,K_U16);
    ADD("int",ffi_type_sint,K_I32);ADD("uint",ffi_type_uint,K_U32);
#if LONG_MAX == INT32_MAX
    ADD("long",ffi_type_slong,K_I32);ADD("ulong",ffi_type_ulong,K_U32);
#elif LONG_MAX == INT64_MAX
    ADD("long",ffi_type_slong,K_I64);ADD("ulong",ffi_type_ulong,K_U64);
#else
#error unsupported long width
#endif
    ADD("longLong",ffi_type_sint64,K_I64);ADD("ulongLong",ffi_type_uint64,K_U64);
#if SIZE_MAX == UINT32_MAX
    ADD("usize",ffi_type_uint32,K_U64);ADD("isize",ffi_type_sint32,K_I64);
#else
    ADD("usize",ffi_type_uint64,K_U64);ADD("isize",ffi_type_sint64,K_I64);
#endif
    ADD("longDouble",ffi_type_longdouble,K_LONG_DOUBLE);
#undef ADD
    JS_SetPropertyStr(ctx,types,"struct",JS_NewCFunction(ctx,types_struct,"struct",1));JS_SetPropertyStr(ctx,types,"array",JS_NewCFunction(ctx,types_array,"array",2));if(JS_FreezeObject(ctx,types)<0){JS_FreeValue(ctx,types);return;}
    JSValue libraries=JS_NewObject(ctx);JS_SetPropertyStr(ctx,libraries,"c",JS_NewString(ctx,FFI_C_LIBRARY_NAME));JS_SetPropertyStr(ctx,libraries,"m",JS_NewString(ctx,FFI_M_LIBRARY_NAME));if(JS_FreezeObject(ctx,libraries)<0){JS_FreeValue(ctx,types);JS_FreeValue(ctx,libraries);return;}
    JSValue unsafe=JS_NewObject(ctx);static const JSCFunctionListEntry uf[]={JS_CFUNC_DEF("address",1,unsafe_address),JS_CFUNC_DEF("fromAddress",1,unsafe_from_address),JS_CFUNC_DEF("pointerOf",1,unsafe_pointer_of),JS_CFUNC_DEF("offset",2,unsafe_offset),JS_CFUNC_DEF("deref",1,unsafe_deref),JS_CFUNC_DEF("view",2,unsafe_view),JS_CFUNC_DEF("readCString",2,unsafe_cstring),JS_CFUNC_DEF("currentEventLoop",0,unsafe_loop),JS_CFUNC_DEF("adopt",2,unsafe_adopt)};JS_SetPropertyFunctionList(ctx,unsafe,uf,countof(uf));
    static const JSCFunctionListEntry funcs[]={JS_CFUNC_DEF("open",1,ffi_open_js),JS_CFUNC_DEF("function",2,ffi_function_js),JS_CFUNC_DEF("callback",2,callback_create),JS_CFUNC_DEF("errno",0,ffi_errno_js),JS_CFUNC_DEF("strerror",1,ffi_strerror_js)};JS_SetPropertyFunctionList(ctx,ffi_object,funcs,countof(funcs));JS_SetPropertyStr(ctx,ffi_object,"types",types);JS_SetPropertyStr(ctx,ffi_object,"libraries",libraries);JS_SetPropertyStr(ctx,ffi_object,"unsafe",unsafe);
}
