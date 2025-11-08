/**
 * LightJS cFFI support(linux only)
 * dangerous: this is a low-level interface, it's easy to cause memory leaks and crashes.
 *
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

#include "private.h"
#include "utils.h"

#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <errno.h>

#ifndef L_NO_THREADS_H
#include <threads.h>
#endif

#include <ffi.h>

#if defined(DEBUG) && defined(HAS_EXECINFO)
// warn: not available in Alpine(musl)
#include <execinfo.h>
#endif

#define DEF(name, flag) JS_PROP_INT32_DEF(#name, flag, JS_PROP_CONFIGURABLE)
#define RB_MALLOC 1 << 9
#define RB_FROM_ARG 2 << 9
static JSValue js_ffi_type_helper_ptr(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);
const JSCFunctionListEntry js_ffi_types[] = {
    DEF(AUTO, -1),
    DEF(VOID, FFI_TYPE_VOID),
    DEF(INT, FFI_TYPE_INT),
    DEF(FLOAT, FFI_TYPE_FLOAT),
    DEF(DOUBLE, FFI_TYPE_DOUBLE),
    DEF(LONGDOUBLE, FFI_TYPE_LONGDOUBLE),
    DEF(UINT8, FFI_TYPE_UINT8),
    DEF(SINT8, FFI_TYPE_SINT8),
    DEF(UINT16, FFI_TYPE_UINT16),
    DEF(SINT16, FFI_TYPE_SINT16),
    DEF(UINT32, FFI_TYPE_UINT32),
    DEF(SINT32, FFI_TYPE_SINT32),
    DEF(UINT64, FFI_TYPE_UINT64),
    DEF(SINT64, FFI_TYPE_SINT64),
    DEF(POINTER, FFI_TYPE_POINTER),

    // return PTR type mask
    DEF(R_STRING, 1 << 8),  // \0 terminated string
    DEF(R_BUFFER_MALLOC, RB_MALLOC),     // malloced buffer
    DEF(R_BUFFER_FROM_ARG, RB_FROM_ARG), // from JSValue TypedArray

    JS_CFUNC_DEF("PTR", 1, js_ffi_type_helper_ptr)
};

enum ARG_GCFLAG {
    GC_JSSTRING,    // from JS_ToCString
    GC_JSALLOC,     // from js_malloc
    GC_TYPEDARRAY   // from JS_GetArrayBuffer
};

// for safety , capture SIGSEGV and SIGBUS to prevent crash
#ifdef DEBUG
pthread_mutex_t ffi_mutex;
pthread_t running_thread;
char* info;
char* bt_msg = NULL;
static thread_local jmp_buf jump_buf;
static void sig_handler(int sig, siginfo_t *_info, void *ucontext){
    // generate error message
    info = malloc(
#ifdef HAS_EXECINFO
        1024 * 64
#else
        1024
#endif
    );
    void *fault_addr = _info -> si_addr;
    switch(sig){
        case SIGSEGV: snprintf(info, 128, "Segmentation fault at %p", fault_addr); break;
        case SIGBUS: snprintf(info, 128, "Bus error at %p", fault_addr); break;
        case SIGFPE: snprintf(info, 128, "Floating point exception at %p", fault_addr); break;
        case SIGILL: snprintf(info, 128, "Illegal instruction at %p", fault_addr); break;
        case SIGABRT: snprintf(info, 128, "Aborted at %p", fault_addr); break;
        default: snprintf(info, 128, "Unknown signal %d", sig); break;
    }
    
#ifdef HAS_EXECINFO
    void* bt_buff[60];
    int bt_len = backtrace(bt_buff, 60);
    char** bt_str = backtrace_symbols(bt_buff, bt_len);
    bt_msg = malloc(1024);
    strcat(bt_msg, "Backtrace(if available):\n");
    for(int i = 0; i < bt_len; i++){
        strcat(bt_msg, bt_str[i]);
        strcat(bt_msg, "\n");
    }
    free(bt_str);
#endif

    if(running_thread){
        pthread_mutex_unlock(&ffi_mutex);
        pthread_kill(running_thread, SIGUSR2);
        running_thread = 0;
    }else{
        // Not in FFI thread
        printf("program received unhandled %s\n", info);
        free(info);
        if(bt_msg) free(bt_msg);
        info = bt_msg = NULL;
        raise(SIGTRAP);
        exit(1);
    }
}

static void inthread_sighandler(int sig, siginfo_t *_info, void *ucontext){
    longjmp(jump_buf, 1);    // jump to handle ffi error
}
#endif

static inline int32_t guess_type(JSContext *ctx, JSValueConst val){
    if(JS_IsUndefined(val) || JS_IsNull(val)){
        return FFI_TYPE_VOID;
    }else if(JS_IsNumber(val)){
        if(JS_IsBigInt(ctx, val)){
            return FFI_TYPE_SINT64;
        }
        double num;
        if(JS_ToFloat64(ctx, &num, val) == -1){
            return -1;
        }
        if(num == (int32_t)num){
            return FFI_TYPE_SINT32;
        }else{
            return FFI_TYPE_DOUBLE;
        }
    }else if(JS_IsString(val) || JS_GetTypedArrayType(val) != -1){
        return FFI_TYPE_POINTER;
    }else if(JS_IsBool(val)){
        return FFI_TYPE_UINT8;
    }else if(JS_IsArray(val)){
        return FFI_TYPE_POINTER;
    }else{
        return -1;
    }
}

void free_malloc(JSRuntime *rt, void *opaque, void *ptr){
	free(opaque);
}

void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr){
	js_free_rt(rt, ptr);
}

static JSValue js_ffi_get_buffer_from_ptr(JSContext *ctx, JSValue this_val, int argc, JSValueConst *argv, int magic, JSValue *func_data){
    uint8_t* ptr = JS_VALUE_GET_PTR(func_data[0]);

    int64_t len;
    if(argc == 0 || -1 == JS_ToInt64Ext(ctx, &len, argv[0])){
        return JS_ThrowTypeError(ctx, "The buffer size is required");
    }
    
    bool share = false;
    if(argc >= 2) share = JS_ToBool(ctx, argv[1]);

    JSFreeArrayBufferDataFunc* free_func = NULL;
    if(magic & RB_MALLOC) free_func = free_malloc;
    else if(magic & RB_FROM_ARG) free_func = free_js_malloc;

    return JS_NewArrayBuffer(ctx, ptr, len, free_func, NULL, share);
}

static JSValue js_ffi_type_helper_ptr(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0) return JS_NewInt32(ctx, FFI_TYPE_POINTER);
    const char* name = JS_ToCString(ctx, argv[0]);
    int ret;
    if(!name) ret = FFI_TYPE_POINTER;
    else if(strcmp(name, "free") == 0) ret = FFI_TYPE_POINTER | RB_MALLOC;
    else if(strcmp(name, "jsfree") == 0) ret = FFI_TYPE_POINTER | RB_FROM_ARG;
    else return JS_ThrowTypeError(ctx, "Invalid type name");
	return JS_NewInt32(ctx, ret);
}

// this_val: type, args: to ffi func
static JSValue js_ffi_handle(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic, JSValue *func_data) {
    if(argc == 0 || !JS_IsArray(this_val)) {
helpmsg:
		return JS_ThrowTypeError(ctx, "This arg is invalid. Expect a Array containing at least 2 types");
    }

    // help message
    int64_t len;
    if(-1 == JS_GetLength(ctx, this_val, &len) || len < 2){
		goto helpmsg;
    }

    // return type
    JSValue ret_type = JS_GetPropertyUint32(ctx, this_val, 0);
    int32_t ret_type_num;
    if(JS_ToInt32(ctx, &ret_type_num, ret_type) == -1){
        JS_FreeValue(ctx, ret_type);
		return JS_ThrowTypeError(ctx, "The return type(this[0]) is invalid. Expect a number(type.XXX)");
    }
    JS_FreeValue(ctx, ret_type);

    // function name and find the function
    JSValue func_name = JS_GetPropertyUint32(ctx, this_val, 1);
    const char *func_name_str = JS_ToCString(ctx, func_name);
    if(!func_name_str){
        JS_FreeValue(ctx, func_name);
        return JS_ThrowTypeError(ctx, "The function name(this[1]) is invalid. Expect a string");
    }
    void* func = dlsym(JS_VALUE_GET_PTR(func_data[0]), func_name_str);
    JS_FreeCString(ctx, func_name_str);
    JS_FreeValue(ctx, func_name);
    if(!func){
		return JS_ThrowReferenceError(ctx, "Failed to find function: %s", func_name_str);
    }

    // init
    volatile JSValue ret_val = JS_EXCEPTION;
    uint32_t args_len = MAX(argc, len-2);
    ffi_type **arg_types = js_malloc(ctx, args_len * sizeof(ffi_type*));
    void **args = js_malloc(ctx, args_len * sizeof(void*));
    enum ARG_GCFLAG* gc_flags = js_malloc(ctx, args_len * sizeof(enum ARG_GCFLAG));
    if(!arg_types || !args || !gc_flags)
        return JS_ThrowOutOfMemory(ctx);

    for(int64_t i = 0; i < len; i++){
        JSValue val = JS_GetPropertyUint32(ctx, this_val, i+2);
        int32_t type;
        if(JS_ToInt32(ctx, &type, val) == -1){
            JS_FreeValue(ctx, val);
            return JS_ThrowTypeError(ctx, "The type of this arg is invalid. Expect a number(type.XXX)");
        }
        JS_FreeValue(ctx, val);

        // typecheck
        if(argc -1 >= i){
            gc_flags[i] = GC_JSALLOC;   // default from js_malloc
restart_typecheck:
            switch(type){
                case -1: // AUTO
                    type = guess_type(ctx, argv[i]);
                    if(type == -1){
                        return JS_ThrowTypeError(ctx, "Could not infer type from given value(at index: %ld)", i);
                        goto _continue;
                    }
                    goto restart_typecheck;

                case FFI_TYPE_VOID:
                    arg_types[i] = &ffi_type_void;
                    args[i] = NULL;
                break;

                // 32-bit integer types
                case FFI_TYPE_INT:
                case FFI_TYPE_UINT8:
                case FFI_TYPE_SINT8:
                case FFI_TYPE_UINT16:
                case FFI_TYPE_SINT16:
                case FFI_TYPE_SINT32:
                    arg_types[i] = &ffi_type_sint;
                    int32_t num32;
                    if(JS_ToInt32(ctx, &num32, argv[i]) == -1)
                        goto error;
                    void *p32 = js_malloc(ctx, sizeof(uint32_t));
                    if(!p32) return JS_ThrowOutOfMemory(ctx);

                    if(type == FFI_TYPE_INT){
                        arg_types[i] = &ffi_type_sint;
                        *(int*)p32 = num32;
                    }else if(type == FFI_TYPE_UINT8){
                        arg_types[i] = &ffi_type_uint8;
                        *(uint8_t*)p32 = num32;
                    }else if(type == FFI_TYPE_SINT8){
                        arg_types[i] = &ffi_type_sint8;
                        *(int8_t*)p32 = num32;
                    }else if(type == FFI_TYPE_UINT16){
                        arg_types[i] = &ffi_type_uint16;
                        *(uint16_t*)p32 = num32;
                    }else if(type == FFI_TYPE_SINT16){
                        arg_types[i] = &ffi_type_sint16;
                        *(int16_t*)p32 = num32;
                    }else if(type == FFI_TYPE_SINT32){
                        arg_types[i] = &ffi_type_sint32;
                        *(int32_t*)p32 = num32;
                    }
                    
                    args[i] = p32;
                break; 

                // 64-bit integer types
                case FFI_TYPE_SINT64:
                case FFI_TYPE_UINT32:
                    int64_t num64;
                    if(JS_ToInt64(ctx, &num64, argv[i]) == -1)
                        goto error;
                    int64_t *p64 = js_malloc(ctx, sizeof(int64_t));
                    if(!p64) return JS_ThrowOutOfMemory(ctx);

                    if(type == FFI_TYPE_SINT64){
                        arg_types[i] = &ffi_type_sint64;
                        *(int64_t*)p64 = num64;
                    }else if(type == FFI_TYPE_UINT32){
                        arg_types[i] = &ffi_type_uint32;
                        *(uint32_t*)p64 = num64;
                    }
                    
                    args[i] = p64;
                break; 

                // 64-bit biginteger types
                case FFI_TYPE_UINT64:
                    uint64_t numu64;
                    if(JS_ToBigUint64(ctx, &numu64, argv[i]) == -1)
                        goto error;
                    uint64_t *pu64 = js_malloc(ctx, sizeof(uint64_t));
                    if(!pu64) return JS_ThrowOutOfMemory(ctx);

                    arg_types[i] = &ffi_type_uint64;
                    *(uint64_t*)pu64 = numu64;
                    args[i] = pu64;
                break; 

                case FFI_TYPE_DOUBLE:
                case FFI_TYPE_LONGDOUBLE:
                case FFI_TYPE_FLOAT:
                    double numfl;
                    if(JS_ToFloat64(ctx, &numfl, argv[i]) == -1)
                        goto error;
                    void *pfl = js_malloc(ctx, MAX(sizeof (float), sizeof(long double)));
                    if(!pfl) return JS_ThrowOutOfMemory(ctx);

                    if(type == FFI_TYPE_DOUBLE){
                        arg_types[i] = &ffi_type_double;
                        *(double*)pfl = numfl;
                    }else if(type == FFI_TYPE_FLOAT){
                        arg_types[i] = &ffi_type_float;
                        *(float*)pfl = numfl;
                    }else if(type == FFI_TYPE_LONGDOUBLE){
                        arg_types[i] = &ffi_type_longdouble;
                        *(long double*)pfl = numfl;
                    }
                    
                    args[i] = pfl;
                break; 

                case FFI_TYPE_POINTER:
                    arg_types[i] = &ffi_type_pointer;
                    // str
                    if(JS_IsString(argv[i])){
                        const char *str = JS_ToCString(ctx, argv[i]);
                        if(!str) goto error;
                        gc_flags[i] = GC_JSSTRING;
                        args[i] = (void*)str;
                    }else{
                        size_t len;
                        uint8_t* buf = JS_GetArrayBuffer(ctx, &len, argv[i]);
                        if(!buf) goto error;
                        JS_DupValue(ctx, argv[i]);
                        gc_flags[i] = GC_TYPEDARRAY;
                        args[i] = buf;
                    }
                break; 

                default:
                    goto error;
            }
        }

_continue: continue;
error: 
        JS_ThrowTypeError(ctx, "Failed to parse args(at index: %ld): invalid type", i);
        goto cleanup;
    }

    // guess return type
    ffi_type *rtype = &ffi_type_void;
    switch (ret_type_num){
        case FFI_TYPE_VOID: rtype = &ffi_type_void; break;
        case -1: // AUTO: C default return type
        case FFI_TYPE_INT: rtype = &ffi_type_sint; break;
        case FFI_TYPE_UINT8: rtype = &ffi_type_uint8; break;
        case FFI_TYPE_SINT8: rtype = &ffi_type_sint8; break;
        case FFI_TYPE_UINT16: rtype = &ffi_type_uint16; break;
        case FFI_TYPE_SINT16: rtype = &ffi_type_sint16; break;
        case FFI_TYPE_SINT32: rtype = &ffi_type_sint32; break;
        case FFI_TYPE_SINT64: rtype = &ffi_type_sint64; break;
        case FFI_TYPE_UINT32: rtype = &ffi_type_uint32; break;
        case FFI_TYPE_UINT64: rtype = &ffi_type_uint64; break;
        case FFI_TYPE_DOUBLE: rtype = &ffi_type_double; break;
        case FFI_TYPE_FLOAT: rtype = &ffi_type_float; break;
        case FFI_TYPE_LONGDOUBLE: rtype = &ffi_type_longdouble; break;
        default: if(ret_type_num & FFI_TYPE_POINTER){
            rtype = &ffi_type_pointer;
        }else{
            JS_ThrowTypeError(ctx, "Invalid return type: %d", ret_type_num);
            goto cleanup;
        }
    }
    void* ret_value = js_malloc(ctx, rtype -> size);

    // start call
    ffi_cif cif;
    if(ffi_prep_cif(&cif, FFI_DEFAULT_ABI, args_len, rtype, arg_types) != FFI_OK){
		return JS_ThrowPlainError(ctx, "Failed to prepare cif");
        goto cleanup;
    }

    // jump 
#ifdef DEBUG
    if(setjmp(jump_buf)){
		ret_val = JS_ThrowTypeError(ctx, "FFI Error: %s", bt_msg);
        free(info);
        free(bt_msg);
        info = bt_msg = NULL;
        goto cleanup;
    }else{
        // dangerous! start ffi call
        pthread_mutex_lock(&ffi_mutex);
        running_thread = pthread_self();
#endif
        ffi_call(&cif, func, ret_value, (void**)args);
#ifdef DEBUG
    }
#endif

    // return value
    switch(ret_type_num){
        case FFI_TYPE_VOID: ret_val = JS_UNDEFINED; break;
        case FFI_TYPE_INT: ret_val = JS_NewInt32(ctx, *(int*)ret_value); break;
        case FFI_TYPE_UINT8: ret_val = JS_NewUint32(ctx, *(uint8_t*)ret_value); break;
        case FFI_TYPE_SINT8: ret_val = JS_NewInt32(ctx, *(int8_t*)ret_value); break;
        case FFI_TYPE_UINT16: ret_val = JS_NewUint32(ctx, *(uint16_t*)ret_value); break;
        case FFI_TYPE_SINT16: ret_val = JS_NewInt32(ctx, *(int16_t*)ret_value); break;
        case FFI_TYPE_SINT32: ret_val = JS_NewInt32(ctx, *(int32_t*)ret_value); break;
        case FFI_TYPE_SINT64: ret_val = JS_NewInt64(ctx, *(int64_t*)ret_value); break;
        case FFI_TYPE_UINT32: ret_val = JS_NewUint32(ctx, *(uint32_t*)ret_value); break;
        case FFI_TYPE_UINT64: ret_val = JS_NewBigUint64(ctx, *(uint64_t*)ret_value); break;
        case FFI_TYPE_DOUBLE: ret_val = JS_NewFloat64(ctx, *(double*)ret_value); break;
        case FFI_TYPE_FLOAT: ret_val = JS_NewFloat64(ctx, *(float*)ret_value); break;
        case FFI_TYPE_LONGDOUBLE: ret_val = JS_NewFloat64(ctx, *(long double*)ret_value); break;
        default: if(ret_type_num & FFI_TYPE_POINTER){
            ret_val = JS_NewCFunctionData(ctx, js_ffi_get_buffer_from_ptr, 1, ret_type_num, 1, (JSValueConst[]){
                JS_MKPTR(JS_TAG_INT, ret_value)
            });
        }else abort();  // unreachable
    }

cleanup:
    for(int64_t i = 0; i < args_len; i++){
        if(gc_flags[i] == GC_JSSTRING){
            JS_FreeCString(ctx, (char*)args[i]);
        }else if(gc_flags[i] == GC_TYPEDARRAY){
            JS_FreeValue(ctx, argv[i]);
        }else if(gc_flags[i] == GC_JSALLOC){
            js_free(ctx, (void*)args[i]);
        }
    }
    js_free(ctx, arg_types);
    js_free(ctx, args);
    js_free(ctx, gc_flags);
    return ret_val;
}

void free_dl_handler(JSRuntime *rt, void *opaque, void *ptr) {
    dlclose(ptr);
}

static JSValue js_dlopen(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0){
		return JS_ThrowTypeError(ctx, "dlopen() requires at least one argument");
    }

    const char *path = JS_ToCString(ctx, argv[0]);
    if(!path) {
        return JS_EXCEPTION;
    }

    // realpath
    char rpath[PATH_MAX];
    if(realpath(path, rpath) == NULL) {
		return tjs_throw_errno(ctx, errno);
    }

    void *handle = dlopen(rpath, RTLD_LAZY | RTLD_GLOBAL);
    if(!handle) {
		return JS_ThrowTypeError(ctx, "Failed to load library: %s", dlerror());
    }

    JSValue ret = JS_NewCFunctionData(ctx, js_ffi_handle, 0, 0, 1, (JSValueConst[]){
        JS_NewArrayBuffer(ctx, (void*)handle, SIZE_MAX, free_dl_handler, NULL, false)
    });
    return ret;
}

const JSCFunctionListEntry js_ffi_funcs[] = {
    JS_CFUNC_DEF("dlopen", 0, js_dlopen),
    JS_OBJECT_DEF("types", js_ffi_types, countof(js_ffi_types), JS_PROP_CONFIGURABLE)
};

#ifdef DEBUG
__attribute__((constructor)) void ffi_init(void) {
    pthread_mutex_init(&ffi_mutex, NULL);
    struct sigaction sa = {
        .sa_flags = SA_SIGINFO,
        .sa_sigaction = sig_handler,
        .sa_restorer = NULL
    };
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}
#endif

int init_ffi(JSContext *ctx, JSModuleDef *m) {
#if defined(DEBUG) && !defined(__CYGWIN__)
    // signal(SIGUSR1, inthread_sighandler);
    struct sigaction sa = {
        .sa_flags = SA_SIGINFO,
        .sa_sigaction = inthread_sighandler,
        .sa_restorer = NULL
    };
    sigaction(SIGUSR2, &sa, NULL);
#endif
    return JS_SetModuleExportList(ctx, m, js_ffi_funcs, countof(js_ffi_funcs));
}

void tjs__mod_posix_ffi_init(JSContext *ctx, JSValue ns){
	JS_SetPropertyFunctionList(ctx, ns, js_ffi_funcs, countof(js_ffi_funcs));
}