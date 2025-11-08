/**
 * Circu.js Console
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

#include "mem.h"
#include "private.h"
#include "tjs.h"
#include "binary.h"


#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#ifndef L_NO_THREADS_H
#include <threads.h>
#endif
#include <assert.h>

#define MAX_DEPTH 64
#define MAX_OUTPUT_LEN 1024
#define MAX_OBJECT_PROP_LEN 16
#define MAX_OBJEXT_INLINE_PROP_LEN 4

// ANSI 颜色代码
#define ANSI_RESET   "\x1b[0m"
#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_WHITE   "\x1b[37m"
#define ANSI_BOLD    "\x1b[1m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_ITALIC "\x1b[3m"

static const char* getClassName(JSContext *ctx, JSValue prototype) {
    JSValue constructor, name;

    constructor = JS_GetProperty(ctx, prototype, JS_ATOM_constructor);
    if (JS_IsException(constructor))
        return NULL;
    name = JS_GetProperty(ctx, constructor, JS_ATOM_name);
    if (JS_IsException(name))
        return NULL;

    JS_FreeValue(ctx, constructor);
    JS_FreeValue(ctx, name);
    return JS_ToCString(ctx, name);
}

void* dalloc(void *opaque, void *ptr, size_t size){
    return js_realloc_rt((JSRuntime*)opaque, ptr, size);
}

#define PRINT_INDENT(depth) fputs(output, getBlank(depth))

#define BLANK_64 "                                                                "
static const char* blank = BLANK_64 BLANK_64 BLANK_64 BLANK_64; // max depth 64
static size_t blank_len = 64;

static inline const char* getBlank(int depth) {
    assert(depth <= blank_len);
    size_t offset = (blank_len - depth) * 4;
    return blank + offset;
}

// forward declaration
static inline void print_jsvalue(JSContext *ctx, JSValueConst val, JSValueConst prototype_of, int depth, JSValue visited[], DynBuf* dbuf);

static inline bool check_circular(JSContext *ctx, JSValue val, JSValue visited[], int depth) {
    if(depth == 64) return true; // max depth
    for(int i = 0; i < depth; i++){
        if(JS_IsSameValue(ctx, val, visited[i])) return true;
    }
    return false;
}

static inline JSValue JS_GetPropertyNoDup(JSContext *ctx, JSValueConst obj, JSAtom atom){
    JSValue ret = JS_GetProperty(ctx, obj, atom);
    JS_FreeValue(ctx, ret);
    return ret;
}

static inline JSValue JS_GetWeakRefValue(JSContext *ctx, JSValue val){
	JSValue ret = JS_GetProperty(ctx, val, JS_ATOM_value);
	return ret;
}

static inline const char* LJS_ToCString(JSContext *ctx, JSValueConst val, size_t* psize){
    if(!JS_IsString(val)) return NULL;  // different from JS_ToCString
    return JS_ToCStringLen(ctx, psize, val);
}

static inline bool JS_IsTypedArray(JSContext* ctx, JSValueConst val){
    return JS_GetTypedArrayType(val) != -1;
}


static inline int JS_GetEnumerableLength(JSContext* ctx, JSValueConst obj, int64_t* plen){
    JSValue jsobj;
    int ret = -1;
    if(JS_IsNumber(jsobj = JS_GetProperty(ctx, obj, JS_ATOM_length))){
        ret = JS_ToInt64(ctx, plen, jsobj);
        goto end;
    }
    JS_FreeValue(ctx, jsobj);
    
    if(JS_IsNumber(jsobj = JS_GetProperty(ctx, obj, JS_ATOM_size))){
        ret = JS_ToInt64(ctx, plen, jsobj);
        goto end;
    }

end:
    JS_FreeValue(ctx, jsobj);
    return ret;
}

// measure whether to wrap display into multiple lines
// useful for Array and Object with many properties
static bool measure_wrap_display(JSContext *ctx, JSValue val, JSValue visited[MAX_OBJEXT_INLINE_PROP_LEN], int depth, 
    bool also_proto, bool getset_only) {
#define MEASURE_SUBELEMENT(el) JSValue value = el; \
    if(measure_wrap_display(ctx, value, visited, depth + 1, also_proto, false)){ \
        JS_FreeValue(ctx, value); \
        return true; \
    }\
    JS_FreeValue(ctx, value);

    // Too deep?
    if(depth == MAX_OBJEXT_INLINE_PROP_LEN) return true;

    // check circular reference
    if(check_circular(ctx, val, visited, depth)) return false;

    // add to visited
    visited[depth] = val;

    int64_t plen;
    // if(JS_IsProxy(val) || JS_IsError(ctx, val)) return false;
    if(also_proto && JS_HasProperty(ctx, val, JS_ATOM_prototype)){
        MEASURE_SUBELEMENT(JS_GetProperty(ctx, val, JS_ATOM_prototype));
    }

    // string
    if(JS_IsString(val)) return false;
    
    // some special objects
    if(JS_IsWeakMap(val) || JS_IsWeakSet(val)) return false;
    // weakref?
    if (JS_IsWeakRef(val)) {
        MEASURE_SUBELEMENT(JS_GetWeakRefValue(ctx, val));
        return false;
    }

    // NULL and many special objects
    if (JS_IsNull(val) || JS_IsSymbol(val) || JS_IsRegExp(val) || JS_IsDate(val))
        return false;
    if (JS_IsPromise(val)) {
        MEASURE_SUBELEMENT(JS_PromiseResult(ctx, val));
        return false;
    }

    if(JS_GetEnumerableLength(ctx, val, &plen) != -1){
        if(plen > MAX_OBJEXT_INLINE_PROP_LEN) return true;
        for(int64_t i = 0; i < plen; i++){
            MEASURE_SUBELEMENT(JS_GetPropertyUint32(ctx, val, i));
        }
    }else if(JS_IsObject(val)){
        // display prototype?
        // JSValue prototype = JS_GetProperty(ctx, val, JS_ATOM_prototype);
        // if(!JS_IsException(prototype) ) return true;
        if(!also_proto){
            JSValue proto = JS_GetPrototype(ctx, val);
            if(JS_IsObject(proto) && measure_wrap_display(ctx, proto, visited, depth + 1, false, true)){
                JS_FreeValue(ctx, proto);
                return true;                
            }
            JS_FreeValue(ctx, proto);
        }

        JSPropertyEnum *props;
        uint32_t prop_count;
        if(-1 == JS_GetOwnPropertyNames(ctx, &props, &prop_count, val, JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_PRIVATE_MASK)) return false;
        if(prop_count > MAX_OBJEXT_INLINE_PROP_LEN){
            JS_FreePropertyEnum(ctx, props, prop_count);
            return true;
        }
        for(uint32_t i = 0; i < prop_count; i++){
            JSAtom atom = props[i].atom;
            if(atom == JS_ATOM_prototype || atom == JS_ATOM_Symbol_species || atom == JS_ATOM___proto__)
                continue;
            if(getset_only){
                JSPropertyDescriptor desc;
                bool wrap_res = false;
                if(-1 == JS_GetOwnProperty(ctx, &desc, val, props[i].atom))
                    continue;
                if(JS_IsFunction(ctx, desc.getter)){
                    JSValue desc_val = JS_Call(ctx, desc.getter, val, 0, NULL);
                    if(measure_wrap_display(ctx, desc_val, visited, depth + 1, false, true)){
                        wrap_res = true;
                    }
                    JS_FreeValue(ctx, desc_val);
                }
                JS_FreeValue(ctx, desc.value);
                JS_FreeValue(ctx, desc.getter);
                JS_FreeValue(ctx, desc.setter);
                if(wrap_res) return true;
            }else{
                JSValue prop = JS_GetProperty(ctx, val, atom);
                if(measure_wrap_display(ctx, prop, visited, depth + 1, also_proto, false)){
                    JS_FreeValue(ctx, prop);
                    JS_FreePropertyEnum(ctx, props, prop_count);
                    return true;
                }
                JS_FreeValue(ctx, prop);
            }
        }
        JS_FreePropertyEnum(ctx, props, prop_count);
    }
    return false;
}

static inline bool measure_wrap_disp2(JSContext *ctx, JSValue val, bool also_proto){
    JSValue visited[MAX_OBJEXT_INLINE_PROP_LEN];
    return measure_wrap_display(ctx, val, visited, 0, also_proto, false);
}

static void __print_stack(JSContext* ctx, JSValueConst stack, int depth, DynBuf* output) {
    const char* indent = getBlank(depth);
    const char* stack_str = LJS_ToCString(ctx, stack, NULL);

    if(!stack_str) return;
    char* wrap_pos = strchr(stack_str, '\n');
    while (wrap_pos != NULL) {
        *wrap_pos = '\0';
        dbuf_printf(output, "%s%s\n", indent, stack_str);
        stack_str = wrap_pos + 1;
        wrap_pos = strchr(stack_str, '\n');
    }
    // dbuf_printf(output, "%s%s\n", indent, stack_str);
    JS_FreeCString(ctx, stack_str);
}

static void print_jserror(JSContext* ctx, JSValue val, int depth, DynBuf* output) {
    const char* indent = getBlank(depth);

    JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
    JSValue message = JS_GetProperty(ctx, val, JS_ATOM_message);
    JSValue help = JS_GetPropertyStr(ctx, val, "help");
    JSValue stack = JS_GetProperty(ctx, val, JS_ATOM_stack);
    const char* name_str = JS_ToCString(ctx, name);
    const char* message_str = LJS_ToCString(ctx, message, NULL);
    
    if (JS_IsString(help)) {
        const char* help_str = JS_ToCString(ctx, help);
        dbuf_printf(output,
            ANSI_RED "%s%s" ANSI_RESET ": %s\n" \
            ANSI_GREEN "%s help: " ANSI_RESET "%s\n",
            indent ,name_str, message_str, indent, help_str);
        JS_FreeCString(ctx, help_str);
    } else {
        dbuf_printf(output, ANSI_RED "%s%s" ANSI_RESET ": %s\n", indent, name_str, message_str);
    }

    // print stack
    if (JS_IsString(stack)) __print_stack(ctx, stack, depth, output);

    JS_FreeCString(ctx, name_str);
    JS_FreeCString(ctx, message_str);
    JS_FreeValue(ctx, name);
    JS_FreeValue(ctx, message);
    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, help);
}

static void print_jspromise(JSContext* ctx, JSValue val, int depth, JSValue visited[], DynBuf* output) {
    JSPromiseStateEnum state = JS_PromiseState(ctx, val);
    char* state_str = "unknown";
    switch (state) {
    case JS_PROMISE_PENDING:
        state_str = "pending";
        break;
    case JS_PROMISE_FULFILLED:
        state_str = "fulfilled";
        break;
    case JS_PROMISE_REJECTED:
        state_str = "rejected";
        break;
    }
    dbuf_printf(output, ANSI_MAGENTA "Promise" ANSI_YELLOW "<%s>" ANSI_RESET, state_str);

    if (state != JS_PROMISE_PENDING) {
        JSValue res = JS_PromiseResult(ctx, val);
        print_jsvalue(ctx, res, JS_UNDEFINED, depth + 1, visited, output);
        JS_FreeValue(ctx, res);
    }
}

static void print_jsbuffer(JSContext* ctx, JSValue val, int depth, DynBuf* output) {
    size_t psize;
    uint8_t* buf;
    if (JS_IsArrayBuffer(val)) {
        buf = JS_GetArrayBuffer(ctx, &psize, val);
        dbuf_printf(output, ANSI_MAGENTA "ArrayBuffer(" ANSI_BLUE "%zu" ANSI_MAGENTA ") {" ANSI_RESET, psize);

        goto print_buffer;
    }

    if (JS_IsTypedArray(ctx, val)) {
        buf = JS_GetUint8Array(ctx, &psize, val);

        dbuf_printf(output, ANSI_MAGENTA "TypedArray(" ANSI_BLUE "%zu" ANSI_MAGENTA ")" ANSI_RESET " {", psize);

print_buffer:
        if (buf == NULL) {
            dbuf_putstr(output, ANSI_RED "NULL" ANSI_RESET);
            return;
        }
        const char* indent = getBlank(depth + 1);
        size_t iend = MIN(psize, 128);
        for (size_t i = 0; i < iend; i += 16) {
            dbuf_printf(output, "\n%s", indent);
            for (int j = 0; j < MIN(psize - i, 16); j++) {
                dbuf_printf(output, ANSI_BLUE "%02x" ANSI_RESET, buf[i + j]);
                if(i + j != iend -1) dbuf_putstr(output, ", ");
            }
        }

        dbuf_printf(output, "\n%s}", indent + 4);

        return;
    }
}

// print JSValue like node.js/deno
static void print_jsvalue(JSContext *ctx, JSValueConst val, JSValueConst prototype_of, int depth, JSValue visited[], DynBuf* output) {
    if(depth == 64){        // max depth
        dbuf_putstr(output, ANSI_RED "..." ANSI_RESET);
        return;
    }

    // uninitialed?
    if (JS_VALUE_GET_TAG(val) == JS_TAG_UNINITIALIZED){
        dbuf_putstr(output, ANSI_RED "[val: NULL]" ANSI_RESET);
        return;
    }

    // weakref?
    if(JS_IsWeakRef(val)){
        JSValue value = JS_GetWeakRefValue(ctx, val);
        if(JS_IsUndefined(value)){
            dbuf_putstr(output, ANSI_RED "WeakRef<destroyed>" ANSI_RESET);
            return;
        }else{
            dbuf_putstr(output, ANSI_MAGENTA "WeakRef" ANSI_RESET " -> ");
            val = value;
			JS_FreeValue(ctx, value);	// will dup value after this
            goto main;
        }
    }
    // weakset and weakmap is not enumerable
    if(JS_IsWeakSet(val) || JS_IsWeakMap(val)){
        dbuf_putstr(output, JS_IsWeakMap(val) ? "WeakMap {}" : "WeakSet []");
        return;
    }
    JS_DupValue(ctx, val); // dup value to avoid GC(eg. 0-ref String)

main:
    visited[depth] = val;   // record visited value
    bool obj_showproto = true;

    if (JS_IsUndefined(val)) {
        dbuf_putstr(output, ANSI_BLUE "undefined" ANSI_RESET);
    } else if (JS_IsNull(val)) {
        dbuf_putstr(output, ANSI_BLUE "null" ANSI_RESET);
    } else if (JS_IsBool(val)) {
        dbuf_printf(output, ANSI_BOLD "%s" ANSI_RESET, JS_ToBool(ctx, val) ? "true" : "false");
    } else if (JS_IsNumber(val)) {
        double num;
        if(-1 == JS_ToFloat64(ctx, &num, val))
        dbuf_putstr(output, ANSI_CYAN "NaN" ANSI_RESET);
        else
            dbuf_printf(output, ANSI_CYAN "%g" ANSI_RESET, num);
    } else if (JS_IsBigInt(ctx, val)) {
        const char *str = JS_ToCString(ctx, val);
        if(str){
            dbuf_printf(output, ANSI_CYAN "%s" ANSI_RESET ANSI_GREEN "n" ANSI_RESET, str);
            JS_FreeCString(ctx, str);
        }else{
            dbuf_putstr(output, ANSI_RED "BigInt" ANSI_RESET);
        }
    } else if (JS_IsString(val)) {
        const char *str = JS_ToCString(ctx, val);
        if(str){
            if(depth == 0)
                dbuf_putstr(output, str);
            else
                dbuf_printf(output, ANSI_GREEN "\"%s\"" ANSI_RESET, str);
            JS_FreeCString(ctx, str);
        }else{
            dbuf_putstr(output, ANSI_RED "String" ANSI_RESET);
        }
    } else if (JS_IsFunction(ctx, val)) {
        // constructor?
        JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
        const char *name_str = LJS_ToCString(ctx, name, NULL);
        if(name_str){
            if (JS_IsConstructor(ctx, val)){
                dbuf_printf(output, ANSI_RED ANSI_ITALIC "f" ANSI_RESET ANSI_MAGENTA " class(" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, name_str);
                obj_showproto = false;
            } else {
                dbuf_printf(output, ANSI_RED ANSI_ITALIC "f" ANSI_RESET ANSI_MAGENTA " (" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, name_str);
            }
            JS_FreeCString(ctx, name_str);
        }else{
            dbuf_putstr(output, ANSI_RED "Function" ANSI_RESET);
        }
        JS_FreeValue(ctx, name);

        // Properites
        JSPropertyEnum *props;
        uint32_t prop_count;
        if(-1 != JS_GetOwnPropertyNames(ctx, &props, &prop_count, val, JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK)){
        //     dbuf_putstr(output, " {");
        //     // meraure wrap first
        //     bool wrap = false;
        //     if(prop_count >= MAX_OBJECT_PROP_LEN) wrap = true;
        //     else
        //         for(uint32_t i = 0; i < prop_count; i++)
        //             if(measure_wrap_disp2(ctx, JS_GetPropertyNoDup(ctx, val, props[i].atom), false))
        //                 wrap = true;

        //     const char* indent = getBlank(depth + 1);
        //     if(wrap) dbuf_printf(output, "\n%s", indent);
        //     for(uint32_t i = 0; i < MIN(prop_count, MAX_OBJECT_PROP_LEN); i++){
        //         print_jsvalue(ctx, JS_GetPropertyNoDup(ctx, val, props[i].atom), val, depth + 1, visited, output);
        //         if(i != prop_count - 1) dbuf_putstr(output, ", ");
        //         if(i == MAX_OBJECT_PROP_LEN){
        //             dbuf_printf(output, "\n%s...\n%s", indent, indent + 4);
        //             break;
        //         }else if(wrap){
        //             if(i == MAX_OBJECT_PROP_LEN - 1) dbuf_printf(output, "\n%s", indent + 4);
        //             else dbuf_printf(output, "\n%s", indent);
        //         }
        //     }
            uint32_t pcount = 0;
            static const JSAtom ignore_atom_list[] = {
                JS_ATOM_length,
                JS_ATOM_name,
                JS_ATOM_prototype,
                JS_ATOM_Symbol_species,
                JS_ATOM_Symbol_toStringTag,
                JS_ATOM_Symbol_toPrimitive,
            };
            for(uint32_t i = 0; i < prop_count; i++){
                for(int j = 0; j < countof(ignore_atom_list); j++){
                    if(props[i].atom == ignore_atom_list[j]) goto __function_break;
                }
                pcount++;
__function_break:
                continue;
            }
            JS_FreePropertyEnum(ctx, props, prop_count);
            if(pcount > 0) goto obj_restart;
        //     dbuf_printf(output, "%s}", indent - 4);
        }
    } else if (JS_IsSymbol(val)) {
        JSAtom atom = JS_ValueToAtom(ctx, val);
        const char* str = JS_AtomToCString(ctx, atom);
        if(str && *str){
            dbuf_printf(output, ANSI_MAGENTA "Symbol(" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, str);
            JS_FreeCString(ctx, str);
        }else{
            dbuf_putstr(output, ANSI_RED "Symbol" ANSI_RESET);
        }
        JS_FreeAtom(ctx, atom);
    } else if (JS_IsArray(val) || JS_IsSet(val)) {
        int64_t length;
        if(-1 == JS_GetEnumerableLength(ctx, val, &length)){
                dbuf_putstr(output, ANSI_RED "[]" ANSI_RESET);
            goto end;
        }

        if(depth >= MAX_DEPTH || check_circular(ctx, val, visited, depth)){
            dbuf_printf(output, ANSI_RED "ArrayLike(%ld)" ANSI_RESET, (long int)length); // 保留格式化输出
            goto end;
        }
        
        dbuf_putstr(output, ANSI_GREEN "[ " ANSI_RESET);
        const char* indent = getBlank(depth + 1);
        bool wrap_display = measure_wrap_disp2(ctx, val, false);
        for (uint32_t i = 0; i < length; i++) {
            if(i != 0) dbuf_putstr(output, ", ");
            if(wrap_display)
                dbuf_printf(output, "\n%s", indent);
            
            JSValue element = JS_GetPropertyUint32(ctx, val, i);
            print_jsvalue(ctx, element, JS_UNDEFINED, depth + 1, visited, output);
            JS_FreeValue(ctx, element);

            if(i == MAX_OBJECT_PROP_LEN){
                dbuf_printf(output, "\n%s...", indent);
                break;
            }
        }
        if(wrap_display) dbuf_printf(output, "\n%s", getBlank(depth));
        dbuf_putstr(output, ANSI_GREEN " ]" ANSI_RESET);

    end:
        visited[depth] = JS_NULL;
    } else if (JS_IsObject(val)) {
        // Error
        if(JS_IsError(ctx, val) && depth == 0){
            print_jserror(ctx, val, depth, output);
            goto end;
        }

        // Promise
        if(JS_IsPromise(val)){
            print_jspromise(ctx, val, depth, visited, output);
            goto end;
        }

        // TypedArray or ArrayBuffer
        if(JS_IsArrayBuffer(val) || JS_IsTypedArray(ctx, val)){
            print_jsbuffer(ctx, val, depth, output);
            goto end;
        }

        // cached_object
        if(check_circular(ctx, val, visited, depth)){
            dbuf_putstr(output, ANSI_RED "Object<CIRCULAR>" ANSI_RESET);
            goto end;
        }

        // print class name
        JSClassID class_id = JS_GetClassID(val);
        if(JS_IsRegisteredClass(JS_GetRuntime(ctx), class_id)){
            const char* class_name = getClassName(ctx, val);
            if(NULL == class_name){
                // toStringTag
                JSValue tag = JS_GetProperty(ctx, val, JS_ATOM_Symbol_toStringTag);
                if(JS_IsString(tag)){
                    const char* tag_str = JS_ToCString(ctx, tag);
                    if(tag_str){
                        dbuf_printf(output, ANSI_MAGENTA "%s" ANSI_RESET, tag_str);
                        JS_FreeCString(ctx, tag_str);
                        JS_FreeValue(ctx, tag);
                        goto show_content;
                    }
                }
                JS_FreeValue(ctx, tag);
                dbuf_putstr(output, ANSI_MAGENTA "Object" ANSI_RESET);
            }else{
                dbuf_printf(output, ANSI_MAGENTA "%s" ANSI_RESET, class_name);
                JS_FreeCString(ctx, class_name);
            }
            obj_showproto = false;
        }

show_content:;
        JSValue proto_str;
        // Symbol.toPrimitive
        JSValue valtmp;
        if(JS_IsFunction(ctx, valtmp = JS_GetPropertyNoDup(ctx, val, JS_ATOM_Symbol_toPrimitive))){
            JSValue str = JS_NewString(ctx, "string");
            proto_str = JS_Call(ctx, valtmp, val, 1, (JSValueConst[]){ str });
            JS_FreeValue(ctx, str);
        }

        // toString?
        else if(JS_IsFunction(ctx, valtmp = JS_GetPropertyNoDup(ctx, val, JS_ATOM_toString))){
            proto_str = JS_Call(ctx, valtmp, val, 0, NULL);
        }

        // normal
        else {
            goto obj_restart;
        }

        if (JS_IsException(proto_str)) {
            JS_ResetUncatchableError(ctx);
        } else {
            const char* proto_str_str = JS_ToCString(ctx, proto_str);
            if (proto_str_str) {
                if (memcmp("[object ", proto_str_str, 8) == 0) {
                    JS_FreeCString(ctx, proto_str_str);
                    JS_FreeValue(ctx, proto_str);
                    goto obj_restart;
                }
                if (strlen(proto_str_str) > 100 || strchr(proto_str_str, '\n')) {
                    dbuf_printf(output, "<<< \n%s\n<<<", proto_str_str);
                }
                else {
                    dbuf_printf(output, "(" ANSI_GREEN " %s " ANSI_RESET ")", proto_str_str);
                }
                JS_FreeCString(ctx, proto_str_str);
            }
            else {
                JS_FreeValue(ctx, proto_str);
                goto obj_restart;
            }

            goto end1;
        }
        JS_FreeValue(ctx, proto_str);

obj_restart:;
        bool wrap_display = measure_wrap_disp2(ctx, val, obj_showproto);
        // 读取对象键名
        JSPropertyEnum *props;
        uint32_t len;
        if (-1 == JS_GetOwnPropertyNames(ctx, &props, &len, val, JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_PRIVATE_MASK)) {
            dbuf_putstr(output, ANSI_MAGENTA "Object()" ANSI_RESET);
            goto end1;
        }
        
        dbuf_putstr(output, ANSI_GREEN " { " ANSI_RESET);
        const char* indent = getBlank(depth + 1);

        JSValue getter_this = JS_IsUndefined(prototype_of) ? val : prototype_of;
        for (int i = 0; i < len; i++) {
            JSPropertyDescriptor desc;

            if(props[i].atom == JS_ATOM_prototype || props[i].atom == JS_ATOM_Symbol_toStringTag){
                continue;
            }else if(props[i].atom == JS_ATOM_Symbol_species){
                const char* cname = getClassName(ctx, val);
                if(cname){
                    if(wrap_display)
                        dbuf_printf(output, ",\n%s" ANSI_RED ANSI_BOLD "[species]" ANSI_RESET ": " ANSI_MAGENTA "%s" ANSI_RESET, indent, cname);
                    else
                        dbuf_printf(output, ANSI_RED ", [species]" ANSI_RESET ": " ANSI_MAGENTA "%s" ANSI_RESET, cname);
                    JS_FreeCString(ctx, cname);
                }
                continue;
            }

            if (-1 == JS_GetOwnProperty(ctx, &desc, val, props[i].atom)) {
                continue;
            }
            
            if(wrap_display) {
                dbuf_printf(output, "\n%s", indent);
            }

            JSValue atom_val = JS_AtomToValue(ctx, props[i].atom);
            const char *key_str = JS_AtomToCString(ctx, props[i].atom);
            if(props[i].is_enumerable || !JS_IsSymbol(atom_val))
                dbuf_printf(output, ANSI_YELLOW "%s" ANSI_RESET ": ", key_str);
            else if(*key_str)
                dbuf_printf(output, ANSI_RED "[" ANSI_RESET "%s" ANSI_RED "] " ANSI_RESET ": ", key_str);
            else
                dbuf_putstr(output, ANSI_RED "Symbol" ANSI_RESET ": ");
            JS_FreeCString(ctx, key_str);
            JS_FreeValue(ctx, atom_val);

            if(desc.flags & JS_PROP_GETSET){
                if(!JS_IsUndefined(desc.setter)){
                    dbuf_putstr(output, ANSI_GREEN "set " ANSI_RESET);
                    JS_FreeValue(ctx, desc.setter);
                }
                if(!JS_IsUndefined(desc.getter)){
                    dbuf_putstr(output, ANSI_GREEN "get" ANSI_RESET);
                    JSValue getres = JS_Call(ctx, desc.getter, getter_this, 0, NULL);

                    if(JS_IsException(getres)){
                        JS_ResetUncatchableError(ctx);
                    }else{
                        dbuf_putstr(output, "() => ");
                        print_jsvalue(ctx, getres, JS_UNDEFINED, depth + 1, visited, output);
                        JS_FreeValue(ctx, getres);
                    }
                    JS_FreeValue(ctx, desc.getter);
                }
            }else{
                print_jsvalue(ctx, desc.value, JS_UNDEFINED, depth + 1, visited, output);
                JS_FreeValue(ctx, desc.value);
            }
            
            if ( i != len - 1 && !(i == len -2 && props[i+1].atom == JS_ATOM_prototype) ) dbuf_putstr(output, ", ");
            if ( i == MAX_OBJECT_PROP_LEN ){
                dbuf_printf(output, "\n%s...", indent);
                break;
            }
        }

        if (obj_showproto) {
			JSClassID class_id = JS_GetClassID(val);

			// Object id=1
			// fixme: more stable way to judge invisible object?
			if (class_id == 1){
				goto shallow_show_proto;
			}

            JSValue proto = JS_GetPrototype(ctx, val);
            // Not globalThis.Object and globalThis.Map
            if (!JS_IsUndefined(proto) && !JS_IsNull(proto) && !JS_IsException(proto)) {
                dbuf_printf(output, ",\n%s" ANSI_MAGENTA ANSI_BOLD "__proto__" ANSI_RESET ": ", indent);
                print_jsvalue(ctx, proto, val, depth + 1, visited, output);
            }
            JS_FreeValue(ctx, proto);
        } else {
shallow_show_proto:;
            // show get/set properties
            JSPropertyEnum* prop;
            uint32_t prop_count;
            JSValue proto = JS_GetPrototype(ctx, val);
            if (-1 != JS_GetOwnPropertyNames(ctx, &prop, &prop_count, proto, JS_GPN_STRING_MASK)) {
                for (int j = 0; j < prop_count; j++) {
                    if (prop[j].atom == JS_ATOM_constructor || prop[j].atom == JS_ATOM___proto__) continue;
                    JSPropertyDescriptor desc;
                    if (-1 != JS_GetOwnProperty(ctx, &desc, proto, prop[j].atom)) {
                        if (desc.flags & JS_PROP_GETSET) {
                            if (JS_IsFunction(ctx, desc.getter)) {
                                // call getter
                                JSValue getres = JS_Call(ctx, desc.getter, getter_this, 0, NULL);
                                const char* key_str = JS_AtomToCString(ctx, prop[j].atom);
                                if (!JS_IsException(getres)) {
                                    if (wrap_display)
                                        dbuf_printf(output, ",\n%s" ANSI_MAGENTA "%s" ANSI_RESET ": ", indent, key_str ? key_str : "");
                                    else
                                        dbuf_printf(output, ANSI_MAGENTA ", %s" ANSI_RESET ": ", key_str ? key_str : "");
                                    print_jsvalue(ctx, getres, JS_UNDEFINED, depth + 1, visited, output);
                                }
                                if (key_str) JS_FreeCString(ctx, key_str);
                                JS_FreeValue(ctx, getres);
                            }
                            JS_FreeValue(ctx, desc.getter);
                            JS_FreeValue(ctx, desc.setter);
                        } else {
                            JS_FreeValue(ctx, desc.value);
                        }
                    }
                }
                JS_FreePropertyEnum(ctx, prop, prop_count);
            }
            JS_FreeValue(ctx, proto);
        }

// skip_proto:
        if(wrap_display) {
            dbuf_printf(output, "\n%s", indent + 4);
        } else {
            dbuf_putstr(output, " ");
        }

        dbuf_putstr(output, ANSI_GREEN "}" ANSI_RESET);
        JS_FreePropertyEnum(ctx, props, len);

end1:
        visited[depth] = JS_NULL;
    } else {
        dbuf_printf(output, ANSI_RED "[value: %d]" ANSI_RESET, JS_VALUE_GET_TAG(val));
    }

    JS_FreeValue(ctx, val);
}

static inline void printval_internal(JSContext *ctx, int argc, JSValueConst *argv, FILE *target_fd) {
    static JSValue visited[64];
    bool wrap = false;

	if(feof(target_fd)) return;

    for(int i = 0; i < argc; i++){
        if(measure_wrap_disp2(ctx, argv[i], true)){
            wrap = true;
            break;
        }
    }
    DynBuf output;
    dbuf_init2(&output, JS_GetRuntime(ctx), dalloc);
    for(int i = 0; i < argc; i++){
        JSValue val = argv[i];    
        print_jsvalue(ctx, val, JS_UNDEFINED, 0, visited, &output);
        if(JS_IsObject(val)) dbuf_putc(&output, ' ');
        if(wrap) dbuf_putc(&output, '\n');
        else dbuf_putc(&output, ' ');
    }
    dbuf_putc(&output, '\n');
	fwrite(output.buf, 1, output.size, target_fd);
    dbuf_free(&output);
}

// console.log 实现
static JSValue js_console_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printval_internal(ctx, argc, argv, stdout);
    return JS_UNDEFINED;
}

// // console.error 实现
// static JSValue js_console_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     fwrite(pstderr, ANSI_RED " error " ANSI_RESET);
//     printval_internal(ctx, argc, argv, pstderr);
//     return JS_UNDEFINED;
// }

// // console.info 实现
// static JSValue js_console_info(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     print2(pstdout, ANSI_BLUE " info " ANSI_RESET);
//     printval_internal(ctx, argc, argv, pstdout);
//     return JS_UNDEFINED;
// }

// // console.debug 实现
// static JSValue js_console_debug(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     if(getenv("DEBUG") == NULL){
//         return JS_UNDEFINED;
//     }
    
//     ev_printf(pstdout, ANSI_WHITE " debug " ANSI_RESET);
//     printval_internal(ctx, argc, argv, pstdout);
//     return JS_UNDEFINED;
// }

// // console.assert 实现
// static JSValue js_console_assert(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     if(argc < 2){
//         return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Assertion failed: at least 2 arguments required, but only %d present", 
//             "console.assert(condition: any, ...)" , argc);
//     }

//     if (!JS_ToBool(ctx, argv[0])) {
//         ev_printf(pstderr, ANSI_RED " assert " ANSI_RESET);
//         printval_internal(ctx, argc - 1, argv + 1, pstderr);
//     }
//     return JS_UNDEFINED;
// }

// // console.warn 实现
// static JSValue js_console_warn(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     ev_printf(pstdout, ANSI_YELLOW " warn " ANSI_RESET);
//     printval_internal(ctx, argc, argv, pstdout);
//     return JS_UNDEFINED;
// }

// // console.clear 实现
// static JSValue js_console_clear(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     ev_printf(pstdout, "\033[2J\033[1;1H");
//     return JS_UNDEFINED;
// }

// static const JSCFunctionListEntry console_funcs[] = {
//     JS_CFUNC_DEF("log", 1, js_console_log),
//     JS_CFUNC_DEF("error", 1, js_console_error),
//     JS_CFUNC_DEF("info", 1, js_console_info),
//     JS_CFUNC_DEF("debug", 1, js_console_debug),
//     JS_CFUNC_DEF("assert", 2, js_console_assert),
//     JS_CFUNC_DEF("warn", 1, js_console_warn),
//     JS_CFUNC_DEF("clear", 0, js_console_clear),
// };

void tjs__mod_console_init(JSContext *ctx) {
    // JSValue console = JS_NewObject(ctx);
    JSValue global = JS_GetGlobalObject(ctx);
    // JS_SetPropertyFunctionList(ctx, console, console_funcs, countof(console_funcs));
    // JS_DefinePropertyValueStr(ctx, global, "console", console, JS_PROP_C_W_E);
    // JS_FreeValue(ctx, global);
	JSValue jsprint = JS_NewCFunction(ctx, js_console_log, "print", 1);
	JS_SetPropertyStr(ctx, global, "print", jsprint);
	JS_FreeValue(ctx, global);
}