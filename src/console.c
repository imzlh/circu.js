/**
 * Circu.js Console - Revised Version
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
#include <time.h>
#ifndef L_NO_THREADS_H
#include <threads.h>
#endif
#include <assert.h>
#include <wchar.h>
#include <locale.h>

/* Constants */
#define MAX_DEPTH 64
#define MAX_INLINE_PROPS 4
#define MAX_DISPLAY_PROPS 16
#define MAX_DISPLAY_ARRAY 32
#define MAX_BUFFER_DISPLAY 128
#define MAX_TABLE_ROWS 100
#define MAX_TABLE_COLS 20
#define MAX_STRING_LEN 1000

/* ANSI Color Codes */
#define ANSI_RESET     "\x1b[0m"
#define ANSI_BOLD      "\x1b[1m"
#define ANSI_DIM       "\x1b[2m"
#define ANSI_ITALIC    "\x1b[3m"
#define ANSI_RED       "\x1b[31m"
#define ANSI_GREEN     "\x1b[32m"
#define ANSI_YELLOW    "\x1b[33m"
#define ANSI_BLUE      "\x1b[34m"
#define ANSI_MAGENTA   "\x1b[35m"
#define ANSI_CYAN      "\x1b[36m"
#define ANSI_GRAY      "\x1b[90m"

/* Indentation Helper */
#define INDENT_SIZE 4
#define BLK_SIZE (INDENT_SIZE * MAX_DEPTH)
static char* blk = NULL;
static inline const char* get_indent(int depth) {
    assert(depth <= MAX_DEPTH);
    size_t offset = (MAX_DEPTH - depth) * INDENT_SIZE;
    return offset + blk;
}

__attribute__((constructor)) static void init_blk() {
	blk = malloc(BLK_SIZE + 1);
	memset(blk, ' ', BLK_SIZE);
	blk[BLK_SIZE] = '\0';
}

__attribute__((destructor)) static void free_blk() {
	free(blk);
}

/* Memory Allocator */
static void* console_realloc(void* opaque, void* ptr, size_t size) {
    return js_realloc_rt((JSRuntime*)opaque, ptr, size);
}

/* Helper Functions */
// JS_CallMethod(ctx, val, "entries", 0, NULL);
static JSValue JS_CallMethod(JSContext* ctx, JSValue val, const char* method, int argc, JSValue* argv) {
    JSValue func = JS_GetPropertyStr(ctx, val, method);
    if (JS_IsException(func)) return JS_EXCEPTION;
    JSValue ret = JS_Call(ctx, func, val, argc, argv);
    JS_FreeValue(ctx, func);
	return ret;
}

static JSValue JS_CallMethodAtom(JSContext* ctx, JSValue val, JSAtom atom, int argc, JSValue* argv) {
    JSValue func = JS_GetProperty(ctx, val, atom);
    if (JS_IsException(func)) return JS_EXCEPTION;
    JSValue ret = JS_Call(ctx, func, val, argc, argv);
    JS_FreeValue(ctx, func);
	return ret;
}

/* calculate the width of a string in a terminal */
static size_t wchar_width(const char* str) {
    if (!str) return 0;
    
    size_t width = 0;
    size_t len = strlen(str);
    size_t i = 0;
    
    while (i < len) {
        unsigned char c = str[i];
        
        /* ASCII */
        if ((c & 0x80) == 0) {
            if (c == '\x1b') {
                while (i < len && str[i] != 'm') i++;
                i++;
                continue;
            }
            width++;
            i++;
        }
        /* multibyte characters */
        else if ((c & 0xE0) == 0xC0) {
            width += 2;
            i += 2;
        }
        else if ((c & 0xF0) == 0xE0) {
            width += 2;
            i += 3;
        }
        else if ((c & 0xF8) == 0xF0) {
            width += 2;
            i += 4;
        }
        else {
            width++;
            i++;
        }
    }
    return width;
}

static size_t safe_truncate(const char* str, size_t max_width) {
    if (!str) return 0;
    
    size_t width = 0;
    size_t len = strlen(str);
    size_t i = 0;
    
    while (i < len && width < max_width) {
        unsigned char c = str[i];
        
        if ((c & 0x80) == 0) {
            if (c == '\x1b') {
                while (i < len && str[i] != 'm') i++;
                i++;
                continue;
            }
            width++;
            i++;
        }
        else if ((c & 0xE0) == 0xC0) {
            if (width + 2 > max_width) break;
            width += 2;
            i += 2;
        }
        else if ((c & 0xF0) == 0xE0) {
            if (width + 2 > max_width) break;
            width += 2;
            i += 3;
        }
        else if ((c & 0xF8) == 0xF0) {
            if (width + 2 > max_width) break;
            width += 2;
            i += 4;
        }
        else {
            width++;
            i++;
        }
    }
    
    return i;
}

/* Enhanced circular reference tracking */
typedef struct {
    JSValue refs[MAX_DEPTH];
    int count;
} VisitStack;

static inline bool is_circular(VisitStack* stack, JSValue val) {
    for (int i = 0; i < stack->count; i++) {
        if (JS_VALUE_HAS_REF_COUNT(val) && JS_VALUE_GET_OBJ(val) == JS_VALUE_GET_OBJ(stack->refs[i])) {
            return true;
        }
    }
    return false;
}

static inline void visit_push(VisitStack* stack, JSValue val) {
    if (stack->count < MAX_DEPTH) {
        stack->refs[stack->count++] = val;
    }
}

static inline void visit_pop(VisitStack* stack) {
    if (stack->count > 0) {
        stack->count--;
    }
}

/* Utility Functions */
static inline const char* try_get_string(JSContext* ctx, JSValueConst val) {
    return JS_IsString(val) ? JS_ToCString(ctx, val) : NULL;
}

static inline const char* get_class_name(JSContext* ctx, JSValue obj) {
    JSValue constructor = JS_GetProperty(ctx, obj, JS_ATOM_constructor);
    if (JS_IsException(constructor)) return NULL;
    
    JSValue name = JS_GetProperty(ctx, constructor, JS_ATOM_name);
    JS_FreeValue(ctx, constructor);
    
    if (JS_IsException(name)) return NULL;
    
    const char* result = JS_ToCString(ctx, name);
    JS_FreeValue(ctx, name);
    return result;
}

/* Forward declarations */
static void format_value(JSContext* ctx, JSValueConst val, int depth, 
                        VisitStack* stack, DynBuf* buf, bool in_container);

/* Check if value should be displayed inline */
static bool should_inline(JSContext* ctx, JSValueConst val, VisitStack* stack, int depth) {
    if (depth >= MAX_INLINE_PROPS) return false;
	if (is_circular(stack, val)) return false;
    if (!JS_IsObject(val)) return true;
    if (JS_IsNull(val)) return true;
    if (JS_IsSymbol(val) || JS_IsRegExp(val) || JS_IsDate(val)) return true;
    if (JS_IsWeakMap(val) || JS_IsWeakSet(val)) return true;
    
    /* Check container size - more accurate than original */
    int64_t len = 0;
    JSValue len_val = JS_GetProperty(ctx, val, JS_ATOM_length);
    if (JS_IsNumber(len_val)) {
        JS_ToInt64(ctx, &len, len_val);
        JS_FreeValue(ctx, len_val);
        if (len > MAX_INLINE_PROPS) return false;
        
        /* Check element complexity */
        for (int64_t i = 0; i < len && i < MAX_INLINE_PROPS; i++) {
            JSValue elem = JS_GetPropertyUint32(ctx, val, i);
            if (JS_IsException(elem)) {
                JS_FreeValue(ctx, elem);
                return false;
            }
            bool inline_elem = should_inline(ctx, elem, stack, depth + 1);
            JS_FreeValue(ctx, elem);
            if (!inline_elem) return false;
        }
        return true;
    }
    JS_FreeValue(ctx, len_val);
    
    /* For objects, check property count */
    JSPropertyEnum* props = NULL;
    uint32_t prop_count = 0;
    int err = JS_GetOwnPropertyNames(ctx, &props, &prop_count, val, 
                                     JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK);
    if (err == 0) {
        bool result = prop_count <= MAX_INLINE_PROPS;
        JS_FreePropertyEnum(ctx, props, prop_count);
        return result;
    }
    
    return true;
}

/* Format Functions */
static void format_string(JSContext* ctx, JSValueConst val, DynBuf* buf, bool in_container) {
    const char* str = JS_ToCString(ctx, val);
    if (!str) {
        dbuf_putstr(buf, ANSI_RED "[String]" ANSI_RESET);
        return;
    }
    
    size_t len = mblen(str, MB_CUR_MAX);
    if (in_container) {
        if (len > MAX_STRING_LEN) {
            dbuf_printf(buf, ANSI_GREEN "'%.1000s...'" ANSI_RESET, str);
        } else {
            dbuf_printf(buf, ANSI_GREEN "'%s'" ANSI_RESET, str);
        }
    } else {
        if (len > MAX_STRING_LEN) {
            dbuf_printf(buf, "%.1000s...", str);
        } else {
            dbuf_putstr(buf, str);
        }
    }
    JS_FreeCString(ctx, str);
}

static void format_number(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    double num;
    if (JS_ToFloat64(ctx, &num, val) < 0) {
        dbuf_putstr(buf, ANSI_YELLOW "NaN" ANSI_RESET);
    } else {
        /* Handle special values */
        if (isnan(num)) {
            dbuf_putstr(buf, ANSI_YELLOW "NaN" ANSI_RESET);
        } else if (isinf(num)) {
            dbuf_printf(buf, ANSI_YELLOW "%cInfinity" ANSI_RESET, num < 0 ? '-' : '+');
        } else {
            dbuf_printf(buf, ANSI_YELLOW "%g" ANSI_RESET, num);
        }
    }
}

static void format_function(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
    const char* name_str = try_get_string(ctx, name);
    
    if (JS_IsConstructor(ctx, val)) {
        dbuf_printf(buf, ANSI_CYAN "[class %s]" ANSI_RESET, 
                   name_str ? name_str : "anonymous");
    } else {
        dbuf_printf(buf, ANSI_CYAN "[Function: %s]" ANSI_RESET, 
                   name_str ? name_str : "anonymous");
    }
    
    if (name_str) JS_FreeCString(ctx, name_str);
    JS_FreeValue(ctx, name);
}

static void format_symbol(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    JSAtom atom = JS_ValueToAtom(ctx, val);
    const char* desc = JS_AtomToCString(ctx, atom);
    
    if (desc && *desc) {
        dbuf_printf(buf, ANSI_GREEN "Symbol(%s)" ANSI_RESET, desc);
        JS_FreeCString(ctx, desc);
    } else {
        dbuf_putstr(buf, ANSI_GREEN "Symbol()" ANSI_RESET);
    }
    JS_FreeAtom(ctx, atom);
}

static void format_array(JSContext* ctx, JSValueConst val, int depth, 
                        VisitStack* stack, DynBuf* buf) {
    int64_t len = 0;
    JSValue len_val = JS_GetProperty(ctx, val, JS_ATOM_length);
    if (JS_IsException(len_val)) {
        dbuf_putstr(buf, ANSI_RED "[Invalid Array]" ANSI_RESET);
        return;
    }
    JS_ToInt64(ctx, &len, len_val);
    JS_FreeValue(ctx, len_val);
    
    /* Check circular reference */
    if (is_circular(stack, val)) {
        dbuf_putstr(buf, ANSI_CYAN "[Circular Array]" ANSI_RESET);
        return;
    }
    
    visit_push(stack, (JSValue)val);
    
    bool inline_display = should_inline(ctx, val, stack, depth);
    
    dbuf_putstr(buf, ANSI_CYAN "[" ANSI_RESET);
    
    int64_t display_count = (len > MAX_DISPLAY_ARRAY) ? MAX_DISPLAY_ARRAY : len;
    for (int64_t i = 0; i < display_count; i++) {
        // if (i > 0) {
            dbuf_putstr(buf, inline_display ? ", " : ",\n");
            if (!inline_display) {
                dbuf_printf(buf, "%s", get_indent(depth + 1));
            }
        // }
        
        JSValue elem = JS_GetPropertyUint32(ctx, val, i);
        if (JS_IsException(elem)) {
            dbuf_putstr(buf, ANSI_RED "[Exception]" ANSI_RESET);
        } else {
            format_value(ctx, elem, depth + 1, stack, buf, true);
        }
        JS_FreeValue(ctx, elem);
    }
    
    if (len > display_count) {
        if (display_count > 0) {
            dbuf_putstr(buf, inline_display ? ", " : ",\n");
            if (!inline_display) {
                dbuf_printf(buf, "%s", get_indent(depth + 1));
            }
        }
        dbuf_printf(buf, ANSI_GRAY "... %lld more items" ANSI_RESET, (long long)(len - display_count));
    }
    
    if (!inline_display && len > 0) {
        dbuf_printf(buf, "\n%s", get_indent(depth));
    }
    
    dbuf_putstr(buf, ANSI_CYAN "]" ANSI_RESET);
    visit_pop(stack);
}

static void format_object(JSContext* ctx, JSValueConst val, int depth, 
                         VisitStack* stack, DynBuf* buf) {
    /* Check circular reference */
    if (is_circular(stack, val)) {
        dbuf_putstr(buf, ANSI_CYAN "[Circular Object]" ANSI_RESET);
        return;
    }
    
    visit_push(stack, (JSValue)val);
    
    /* Get class/constructor name */
    const char* class_name = get_class_name(ctx, val);
    if (class_name) {
		dbuf_printf(buf, ANSI_BOLD "%s" ANSI_RESET, class_name);
		JS_FreeCString(ctx, class_name);
	} else {
		// Not required to print classname for Object
		// as it will mess up the output
		// dbuf_putstr(buf, "Object");
	}
    
    /* Get all properties (including non-enumerable) */
    JSPropertyEnum* props = NULL;
    uint32_t prop_count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, val,
                               JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK) < 0) {
        dbuf_putstr(buf, ANSI_RED "[Cannot access object]" ANSI_RESET);
        visit_pop(stack);
        return;
    }
    
    /* Count valid properties (skip prototype) */
    uint32_t valid_count = 0;
    for (uint32_t i = 0; i < prop_count; i++) {
        if (props[i].atom != JS_ATOM_prototype) {
            valid_count++;
        }
    }
    
    if (valid_count == 0) {
        dbuf_putstr(buf, "{ }");
        JS_FreePropertyEnum(ctx, props, prop_count);
        visit_pop(stack);
        return;
    }
    
    bool inline_display = should_inline(ctx, val, stack, depth);
    dbuf_putstr(buf, inline_display ? " { " : " {\n");

    uint32_t display_count = (valid_count > MAX_DISPLAY_PROPS) ? MAX_DISPLAY_PROPS : valid_count;
    uint32_t shown = 0;

    for (uint32_t i = 0; i < prop_count && shown < display_count; i++) {
        if (props[i].atom == JS_ATOM_prototype) continue;

        if (shown > 0) {
            dbuf_putstr(buf, inline_display ? ", " : ",\n");
        }
        if (!inline_display) {
            dbuf_printf(buf, "%s", get_indent(depth + 1));
        }

		// FIXME: whether is Symbol or not?
        const char* key = JS_AtomToCString(ctx, props[i].atom);
        dbuf_printf(buf, ANSI_MAGENTA "%s" ANSI_RESET ": ", key ? key : "Symbol");
        if (key) JS_FreeCString(ctx, key);

        JSValue prop_val = JS_GetProperty(ctx, val, props[i].atom);
        if (JS_IsException(prop_val)) {
            dbuf_putstr(buf, ANSI_RED "[Getter Exception]" ANSI_RESET);
        } else {
            format_value(ctx, prop_val, depth + 1, stack, buf, true);
        }
        JS_FreeValue(ctx, prop_val);
        shown++;
    }

    if (valid_count > display_count) {
        if (shown > 0) {
            dbuf_putstr(buf, inline_display ? ", " : ",\n");
            if (!inline_display) {
                dbuf_printf(buf, "%s", get_indent(depth + 1));
            }
        }
        dbuf_printf(buf, ANSI_GRAY "... %u more properties" ANSI_RESET, valid_count - display_count);
    }

    if (!inline_display && shown > 0) {
        dbuf_putstr(buf, "\n");
        dbuf_printf(buf, "%s", get_indent(depth));
    }
    dbuf_putstr(buf, " }");
    
    JS_FreePropertyEnum(ctx, props, prop_count);
    visit_pop(stack);
}

static void format_error(JSContext* ctx, JSValueConst val, int depth, DynBuf* buf) {
    JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
    JSValue message = JS_GetProperty(ctx, val, JS_ATOM_message);
    JSValue stack = JS_GetProperty(ctx, val, JS_ATOM_stack);
    
    const char* name_str = JS_ToCString(ctx, name);
    const char* msg_str = try_get_string(ctx, message);
    
    dbuf_printf(buf, ANSI_RED "%s" ANSI_RESET, name_str ? name_str : "Error");
    if (msg_str) {
        dbuf_printf(buf, ": %s", msg_str);
    }
    
    if (JS_IsString(stack)) {
        const char* stack_str = JS_ToCString(ctx, stack);
        if (stack_str) {
			// FIXME: indent stack output
            dbuf_printf(buf, "\n%s", stack_str);
            JS_FreeCString(ctx, stack_str);
        }
    }
    
    if (name_str) JS_FreeCString(ctx, name_str);
    if (msg_str) JS_FreeCString(ctx, msg_str);
    JS_FreeValue(ctx, name);
    JS_FreeValue(ctx, message);
    JS_FreeValue(ctx, stack);
}

static void format_promise(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    JSPromiseStateEnum state = JS_PromiseState(ctx, val);
    const char* state_str = "pending";
    
    switch (state) {
        case JS_PROMISE_FULFILLED: state_str = "fulfilled"; break;
        case JS_PROMISE_REJECTED: state_str = "rejected"; break;
        default: break;
    }
    
    dbuf_printf(buf, ANSI_CYAN "Promise" ANSI_RESET " { " ANSI_YELLOW "<%s>" ANSI_RESET " }", state_str);
}

static void format_array_buffer(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    size_t size = 0;
    uint8_t* data = JS_GetArrayBuffer(ctx, &size, val);
    
    if (!data) {
        dbuf_putstr(buf, ANSI_RED "[Invalid ArrayBuffer]" ANSI_RESET);
        return;
    }
    
    dbuf_printf(buf, ANSI_MAGENTA "ArrayBuffer" ANSI_RESET "(%zu) [[ ", size);
    
    size_t display_size = (size > MAX_BUFFER_DISPLAY) ? MAX_BUFFER_DISPLAY : size;
    for (size_t i = 0; i < display_size; i++) {
        if (i > 0) dbuf_putstr(buf, " ");
        dbuf_printf(buf, "%02x", data[i]);
    }
    
    if (size > display_size) {
        dbuf_printf(buf, " ... %zu more bytes", size - display_size);
    }
    
    dbuf_putstr(buf, " ]]");
}

static void format_typed_array(JSContext* ctx, JSValueConst val, int depth, 
                              VisitStack* stack, DynBuf* buf) {
    const char* type_name = "TypedArray";
    JSTypedArrayEnum type = JS_GetTypedArrayType(val);
    
    switch (type) {
        case JS_TYPED_ARRAY_INT8: type_name = "Int8Array"; break;
        case JS_TYPED_ARRAY_UINT8: type_name = "Uint8Array"; break;
        case JS_TYPED_ARRAY_UINT8C: type_name = "Uint8ClampedArray"; break;
        case JS_TYPED_ARRAY_INT16: type_name = "Int16Array"; break;
        case JS_TYPED_ARRAY_UINT16: type_name = "Uint16Array"; break;
        case JS_TYPED_ARRAY_INT32: type_name = "Int32Array"; break;
        case JS_TYPED_ARRAY_UINT32: type_name = "Uint32Array"; break;
        case JS_TYPED_ARRAY_FLOAT32: type_name = "Float32Array"; break;
        case JS_TYPED_ARRAY_FLOAT64: type_name = "Float64Array"; break;
        case JS_TYPED_ARRAY_BIG_INT64: type_name = "BigInt64Array"; break;
        case JS_TYPED_ARRAY_BIG_UINT64: type_name = "BigUint64Array"; break;
        default: break;
    }
    
    size_t size = 0;
    size_t offset = 0;
    size_t byte_length = 0;
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, val, &offset, &size, &byte_length);
    
    dbuf_printf(buf, ANSI_MAGENTA "%s" ANSI_RESET "(%zu) [ ", type_name, size);
    
    /* Show a few elements */
    size_t display_count = (size > 8) ? 8 : size;
    for (size_t i = 0; i < display_count; i++) {
        if (i > 0) dbuf_putstr(buf, ", ");
        JSValue elem = JS_GetPropertyUint32(ctx, val, i);
        format_value(ctx, elem, depth + 1, stack, buf, true);
        JS_FreeValue(ctx, elem);
    }
    
    if (size > display_count) {
        dbuf_printf(buf, ", ... %zu more items", size - display_count);
    }
    
    dbuf_putstr(buf, " ]");
    JS_FreeValue(ctx, buffer);
}

static void format_map(JSContext* ctx, JSValueConst val, int depth, 
                      VisitStack* stack, DynBuf* buf) {
    if (is_circular(stack, val)) {
        dbuf_putstr(buf, ANSI_CYAN "[Circular Map]" ANSI_RESET);
        return;
    }
    
    visit_push(stack, (JSValue)val);
    
    JSValue size_val = JS_GetProperty(ctx, val, JS_ATOM_size);
    int64_t size = 0;
    if (JS_IsNumber(size_val)) {
        JS_ToInt64(ctx, &size, size_val);
    }
    JS_FreeValue(ctx, size_val);
    
    dbuf_printf(buf, ANSI_MAGENTA "Map" ANSI_RESET "(%lld) { ", (long long)size);
    
    /* Get entries */
    JSValue entries = JS_CallMethod(ctx, val, "entries", 0, NULL);
    if (!JS_IsException(entries)) {
        JSValue array = JS_CallMethodAtom(ctx, entries, JS_ATOM_next, 0, NULL);
        int count = 0;
        int max_show = 4;
        
        while (!JS_IsException(array) && count < max_show) {
            JSValue done = JS_GetProperty(ctx, array, JS_ATOM_done);
            bool is_done = JS_ToBool(ctx, done);
            JS_FreeValue(ctx, done);
            
            if (is_done) break;
            
            if (count > 0) dbuf_putstr(buf, ", ");
            
            JSValue value = JS_GetProperty(ctx, array, JS_ATOM_value);
            if (!JS_IsException(value)) {
                JSValue key = JS_GetPropertyUint32(ctx, value, 0);
                JSValue val_entry = JS_GetPropertyUint32(ctx, value, 1);
                
                format_value(ctx, key, depth + 1, stack, buf, true);
                dbuf_putstr(buf, " => ");
                format_value(ctx, val_entry, depth + 1, stack, buf, true);
                
                JS_FreeValue(ctx, key);
                JS_FreeValue(ctx, val_entry);
                JS_FreeValue(ctx, value);
            }
            
            JS_FreeValue(ctx, array);
            array = JS_CallMethodAtom(ctx, entries, JS_ATOM_next, 0, NULL);
            count++;
        }
        
        if (size > max_show) {
            dbuf_printf(buf, ", ... %lld more entries", (long long)(size - max_show));
        }
        
        JS_FreeValue(ctx, array);
        JS_FreeValue(ctx, entries);
    }
    
    dbuf_putstr(buf, " }");
    visit_pop(stack);
}

static void format_set(JSContext* ctx, JSValueConst val, int depth, 
                      VisitStack* stack, DynBuf* buf) {
    if (is_circular(stack, val)) {
        dbuf_putstr(buf, ANSI_CYAN "[Circular Set]" ANSI_RESET);
        return;
    }
    
    visit_push(stack, (JSValue)val);
    
    JSValue size_val = JS_GetProperty(ctx, val, JS_ATOM_size);
    int64_t size = 0;
    if (JS_IsNumber(size_val)) {
        JS_ToInt64(ctx, &size, size_val);
    }
    JS_FreeValue(ctx, size_val);
    
    dbuf_printf(buf, ANSI_MAGENTA "Set" ANSI_RESET "(%lld) { ", (long long)size);
    
    /* Get values */
    JSValue values = JS_CallMethodAtom(ctx, val, JS_ATOM_values, 0, NULL);
    if (!JS_IsException(values)) {
        JSValue array = JS_CallMethodAtom(ctx, values, JS_ATOM_next, 0, NULL);
        int count = 0;
        int max_show = 8;
        
        while (!JS_IsException(array) && count < max_show) {
            JSValue done = JS_GetProperty(ctx, array, JS_ATOM_done);
            bool is_done = JS_ToBool(ctx, done);
            JS_FreeValue(ctx, done);
            
            if (is_done) break;
            
            if (count > 0) dbuf_putstr(buf, ", ");
            
            JSValue value = JS_GetProperty(ctx, array, JS_ATOM_value);
            if (!JS_IsException(value)) {
                format_value(ctx, value, depth + 1, stack, buf, true);
                JS_FreeValue(ctx, value);
            }
            
            JS_FreeValue(ctx, array);
            array = JS_CallMethodAtom(ctx, values, JS_ATOM_next, 0, NULL);
            count++;
        }
        
        if (size > max_show) {
            dbuf_printf(buf, ", ... %lld more items", (long long)(size - max_show));
        }
        
        JS_FreeValue(ctx, array);
        JS_FreeValue(ctx, values);
    }
    
    dbuf_putstr(buf, " }");
    visit_pop(stack);
}

/* Main formatting function */
static void format_value(JSContext* ctx, JSValueConst val, int depth, 
                        VisitStack* stack, DynBuf* buf, bool in_container) {
    if (depth >= MAX_DEPTH) {
        dbuf_putstr(buf, ANSI_RED "[Max depth exceeded]" ANSI_RESET);
        return;
    }
    
    /* Primitives */
    if (JS_IsUndefined(val)) {
        dbuf_putstr(buf, ANSI_GRAY "undefined" ANSI_RESET);
    } else if (JS_IsNull(val)) {
        dbuf_putstr(buf, ANSI_DIM "null" ANSI_RESET);
    } else if (JS_IsBool(val)) {
        dbuf_printf(buf, ANSI_YELLOW "%s" ANSI_RESET, JS_ToBool(ctx, val) ? "true" : "false");
    } else if (JS_IsNumber(val)) {
        format_number(ctx, val, buf);
    } else if (JS_IsBigInt(val)) {
        const char* str = JS_ToCString(ctx, val);
        dbuf_printf(buf, ANSI_YELLOW "%sn" ANSI_RESET, str ? str : "0");
        if (str) JS_FreeCString(ctx, str);
    } else if (JS_IsString(val)) {
        format_string(ctx, val, buf, in_container);
    } else if (JS_IsSymbol(val)) {
        format_symbol(ctx, val, buf);
    } else if (JS_IsFunction(ctx, val)) {
        format_function(ctx, val, buf);
    } 
    /* Special objects - check BEFORE generic object */
    else if (JS_IsError(val)) {
        format_error(ctx, val, depth, buf);
    } else if (JS_IsPromise(val)) {
        format_promise(ctx, val, buf);
    } else if (JS_IsArrayBuffer(val)) {
        format_array_buffer(ctx, val, buf);
    } else if (JS_GetTypedArrayType(val) != -1) {
        format_typed_array(ctx, val, depth, stack, buf);
    } else if (JS_IsArray(val)) {
        format_array(ctx, val, depth, stack, buf);
    } else if (JS_IsMap(val)) {
        format_map(ctx, val, depth, stack, buf);
    } else if (JS_IsSet(val)) {
        format_set(ctx, val, depth, stack, buf);
    } else if (JS_IsObject(val)) {
        format_object(ctx, val, depth, stack, buf);
    } else {
        dbuf_putstr(buf, ANSI_RED "[Unknown type]" ANSI_RESET);
    }
}

static JSValue js_console_inspect(JSContext* ctx, JSValueConst this_val, 
								 int argc, JSValueConst* argv) {
	if (argc == 0) {
        return JS_UNDEFINED;
    }

    VisitStack stack = { .count = 0 };
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, &stack, &buf, false);
    }
    
    dbuf_putc(&buf, '\n');
    JSValue ret = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
    dbuf_free(&buf);
    return ret;
}

/* Console API implementations */
static JSValue js_console_log(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv) {
    if (argc == 0) {
        printf("\n");
        fflush(stdout);
        return JS_UNDEFINED;
    }
    
    VisitStack stack = { .count = 0 };
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, &stack, &buf, false);
    }
    
    dbuf_putc(&buf, '\n');
    fwrite(buf.buf, 1, buf.size, stdout);
    fflush(stdout);
    
    dbuf_free(&buf);
    return JS_UNDEFINED;
}

static JSValue js_console_error(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    if (argc == 0) {
        fprintf(stderr, "\n");
        fflush(stderr);
        return JS_UNDEFINED;
    }
    
    VisitStack stack = { .count = 0 };
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, &stack, &buf, false);
    }
    
    dbuf_putc(&buf, '\n');
    fwrite(buf.buf, 1, buf.size, stderr);
    fflush(stderr);
    
    dbuf_free(&buf);
    return JS_UNDEFINED;
}

static JSValue js_console_warn(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    if (argc == 0) {
        printf(ANSI_YELLOW "Warning\n" ANSI_RESET);
        fflush(stdout);
        return JS_UNDEFINED;
    }
    
    VisitStack stack = { .count = 0 };
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    dbuf_putstr(&buf, ANSI_YELLOW);
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, &stack, &buf, false);
    }
    dbuf_putstr(&buf, ANSI_RESET);
    
    dbuf_putc(&buf, '\n');
    fwrite(buf.buf, 1, buf.size, stdout);
    fflush(stdout);
    
    dbuf_free(&buf);
    return JS_UNDEFINED;
}

static JSValue js_console_info(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    return js_console_log(ctx, this_val, argc, argv);
}

static JSValue js_console_debug(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    if (getenv("DEBUG") == NULL) {
        return JS_UNDEFINED;
    }
    return js_console_log(ctx, this_val, argc, argv);
}

static JSValue js_console_clear(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    printf("\033[2J\033[H");
    fflush(stdout);
    return JS_UNDEFINED;
}

static JSValue js_console_dir(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv) {
    if (argc == 0) return JS_UNDEFINED;
    
    VisitStack stack = { .count = 0 };
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    /* Always show full object structure */
    format_value(ctx, argv[0], 0, &stack, &buf, false);
    
    dbuf_putc(&buf, '\n');
    fwrite(buf.buf, 1, buf.size, stdout);
    fflush(stdout);
    
    dbuf_free(&buf);
    return JS_UNDEFINED;
}

static JSValue js_console_trace(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    printf(ANSI_GRAY "Trace" ANSI_RESET);
    
    if (argc > 0) {
        printf(": ");
        js_console_log(ctx, this_val, argc, argv);
    } else {
        printf("\n");
    }
    
    /* Print stack trace */
    JSValue error = JS_NewError(ctx);
    JSValue stack = JS_GetProperty(ctx, error, JS_ATOM_stack);
    
    if (JS_IsString(stack)) {
        const char* stack_str = JS_ToCString(ctx, stack);
        if (stack_str) {
            printf("%s\n", stack_str);
            JS_FreeCString(ctx, stack_str);
        }
    }
    
    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, error);
    
    return JS_UNDEFINED;
}

static JSValue js_console_assert(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    if (argc == 0 || !JS_ToBool(ctx, argv[0])) {
        fprintf(stderr, ANSI_RED "Assertion failed" ANSI_RESET);
        if (argc > 1) {
            fprintf(stderr, ": ");
            js_console_error(ctx, this_val, argc - 1, argv + 1);
        } else {
            fprintf(stderr, "\n");
            fflush(stderr);
        }
    }
    return JS_UNDEFINED;
}

/* Timer and counter functions */
static JSValue js_console_time(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
    const char* label = "default";
    
    if (argc > 0) {
        label = JS_ToCString(ctx, argv[0]);
        if (label) {
            atom = JS_ValueToAtom(ctx, argv[0]);
        }
    }
    
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    uv_timeval64_t tv;
    uv_gettimeofday(&tv);
    uint64_t now_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    
    JSValue time_val = JS_NewBigUint64(ctx, now_ms);
    JS_SetProperty(ctx, trt->builtins.contime, atom, time_val);
    
    printf(ANSI_GRAY "Timer '%s' started" ANSI_RESET "\n", label);
    
    if (label && argc > 0) JS_FreeCString(ctx, label);
    if (argc > 0) JS_FreeAtom(ctx, atom);
    
    return JS_UNDEFINED;
}

static JSValue js_console_timeEnd(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
    const char* label = "default";
    
    if (argc > 0) {
        label = JS_ToCString(ctx, argv[0]);
        if (label) {
            atom = JS_ValueToAtom(ctx, argv[0]);
        }
    }
    
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    JSValue time_val = JS_GetProperty(ctx, trt->builtins.contime, atom);
    
    uint64_t start_ms = 0;
    if (JS_IsBigInt(time_val)) {
        JS_ToBigUint64(ctx, &start_ms, time_val);
    } else {
        fprintf(stderr, ANSI_RED "Timer '%s' does not exist\n" ANSI_RESET, label);
        if (label && argc > 0) JS_FreeCString(ctx, label);
        if (argc > 0) JS_FreeAtom(ctx, atom);
        JS_FreeValue(ctx, time_val);
        return JS_UNDEFINED;
    }
    
    JS_FreeValue(ctx, time_val);
    JS_SetProperty(ctx, trt->builtins.contime, atom, JS_UNDEFINED);
    
    uv_timeval64_t tv;
    uv_gettimeofday(&tv);
    uint64_t end_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    uint64_t diff_ms = end_ms - start_ms;
    
    printf(ANSI_GRAY "Timer '%s' " ANSI_BLUE "%llu ms" ANSI_RESET "\n", 
           label, (unsigned long long)diff_ms);
    
    if (label && argc > 0) JS_FreeCString(ctx, label);
    if (argc > 0) JS_FreeAtom(ctx, atom);
    
    return JS_UNDEFINED;
}

static JSValue js_console_timeLog(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
    const char* label = "default";
    
    if (argc > 0) {
        label = JS_ToCString(ctx, argv[0]);
        if (label) {
            atom = JS_ValueToAtom(ctx, argv[0]);
        }
    }
    
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    JSValue time_val = JS_GetProperty(ctx, trt->builtins.contime, atom);
    
    uint64_t start_ms = 0;
    if (JS_IsBigInt(time_val)) {
        JS_ToBigUint64(ctx, &start_ms, time_val);
    } else {
        fprintf(stderr, ANSI_RED "Timer '%s' does not exist\n" ANSI_RESET, label);
        if (label && argc > 0) JS_FreeCString(ctx, label);
        if (argc > 0) JS_FreeAtom(ctx, atom);
        JS_FreeValue(ctx, time_val);
        return JS_UNDEFINED;
    }
    
    uv_timeval64_t tv;
    uv_gettimeofday(&tv);
    uint64_t now_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    uint64_t diff_ms = now_ms - start_ms;
    
    printf(ANSI_GRAY "Timer '%s' " ANSI_BLUE "%llu ms" ANSI_RESET, 
           label, (unsigned long long)diff_ms);
    
    if (argc > 1) {
        printf(": ");
        js_console_log(ctx, this_val, argc - 1, argv + 1);
    } else {
        printf("\n");
    }
    
    if (label && argc > 0) JS_FreeCString(ctx, label);
    if (argc > 0) JS_FreeAtom(ctx, atom);
    JS_FreeValue(ctx, time_val);
    
    return JS_UNDEFINED;
}

static JSValue js_console_timeStamp(JSContext* ctx, JSValueConst this_val,
                                   int argc, JSValueConst* argv) {
    const char* label = "default";
    
    if (argc > 0) {
        label = JS_ToCString(ctx, argv[0]);
    }
    
    uv_timeval64_t tv;
    uv_gettimeofday(&tv);
    time_t now = tv.tv_sec;
    struct tm* tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf(ANSI_GRAY "Timestamp '%s' " ANSI_BLUE "%s.%03d" ANSI_RESET "\n",
           label, time_str, tv.tv_usec / 1000);

    if (label && argc > 0) JS_FreeCString(ctx, label);
    
    return JS_UNDEFINED;
}

static JSValue js_console_count(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
    const char* label = "default";
    
    if (argc > 0) {
        label = JS_ToCString(ctx, argv[0]);
        if (label) {
            atom = JS_ValueToAtom(ctx, argv[0]);
        }
    }
    
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    JSValue count_val = JS_GetProperty(ctx, trt->builtins.concount, atom);
    
    int count = 1;
    if (JS_IsNumber(count_val)) {
        JS_ToInt32(ctx, &count, count_val);
        count++;
    }
    
    JSValue new_count = JS_NewInt32(ctx, count);
    JS_SetProperty(ctx, trt->builtins.concount, atom, new_count);
    JS_FreeValue(ctx, new_count);
    
    printf(ANSI_GRAY "count '%s' " ANSI_BLUE "%d\n" ANSI_RESET, label, count);
    
    if (label && argc > 0) JS_FreeCString(ctx, label);
    if (argc > 0) JS_FreeAtom(ctx, atom);
    JS_FreeValue(ctx, count_val);
    
    return JS_UNDEFINED;
}

static JSValue js_console_countReset(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
    const char* label = "default";
    
    if (argc > 0) {
        label = JS_ToCString(ctx, argv[0]);
        if (label) {
            atom = JS_ValueToAtom(ctx, argv[0]);
        }
    }
    
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    JS_SetProperty(ctx, trt->builtins.concount, atom, JS_NewInt32(ctx, 0));
    
    printf(ANSI_GRAY "countReset '%s'\n" ANSI_RESET, label);
    
    if (label && argc > 0) JS_FreeCString(ctx, label);
    if (argc > 0) JS_FreeAtom(ctx, atom);
    
    return JS_UNDEFINED;
}

/* Console.table implementation */
static JSValue js_console_table(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    if (argc == 0) {
        return JS_UNDEFINED;
    }
    
    JSValueConst data = argv[0];
    
    /* Only handle arrays and objects */
    if (!JS_IsArray(data) && !JS_IsObject(data)) {
        return js_console_log(ctx, this_val, argc, argv);
    }
    
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    /* Get columns to display */
    JSPropertyEnum* cols = NULL;
    uint32_t col_count = 0;
    const char** col_names = NULL;
    size_t* col_widths = NULL;
    
    if (JS_IsArray(data)) {
        /* Array of objects */
        int64_t len = 0;
        JSValue len_val = JS_GetProperty(ctx, data, JS_ATOM_length);
        JS_ToInt64(ctx, &len, len_val);
        JS_FreeValue(ctx, len_val);
        
        if (len == 0 || len > MAX_TABLE_ROWS) {
            dbuf_putstr(&buf, "Table too large or empty\n");
            goto end;
        }
        
        /* Get columns from first object */
        JSValue first = JS_GetPropertyUint32(ctx, data, 0);
        if (JS_IsObject(first)) {
            JS_GetOwnPropertyNames(ctx, &cols, &col_count, first,
                                  JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK);
            if (col_count > MAX_TABLE_COLS) col_count = MAX_TABLE_COLS;
        }
        JS_FreeValue(ctx, first);
        
        if (col_count == 0) {
            dbuf_putstr(&buf, "No columns found\n");
            goto end;
        }
        
        /* Allocate column info */
        col_names = js_malloc(ctx, sizeof(char*) * (col_count + 1));
        col_widths = js_malloc(ctx, sizeof(size_t) * (col_count + 1));
        
        /* Index column */
        col_names[0] = "(index)";
        col_widths[0] = wchar_width(col_names[0]);
        
        /* Data columns */
        for (uint32_t i = 0; i < col_count; i++) {
            col_names[i + 1] = JS_AtomToCString(ctx, cols[i].atom);
            col_widths[i + 1] = wchar_width(col_names[i + 1]);
        }
        
        /* Calculate column widths by checking all rows */
        for (int64_t row = 0; row < len; row++) {
            JSValue row_obj = JS_GetPropertyUint32(ctx, data, row);
            if (!JS_IsObject(row_obj)) {
                JS_FreeValue(ctx, row_obj);
                continue;
            }
            
            /* Index column width */
            char idx_buf[32];
            snprintf(idx_buf, sizeof(idx_buf), "%lld", (long long)row);
            size_t idx_width = wchar_width(idx_buf);
            if (idx_width > col_widths[0]) col_widths[0] = idx_width;
            
            /* Data columns */
            for (uint32_t col = 0; col < col_count; col++) {
                JSValue cell = JS_GetProperty(ctx, row_obj, cols[col].atom);
                
                DynBuf cell_buf;
                dbuf_init2(&cell_buf, JS_GetRuntime(ctx), console_realloc);
                VisitStack temp_stack = { .count = 0 };
                format_value(ctx, cell, 0, &temp_stack, &cell_buf, true);
                
                size_t cell_width = wchar_width((const char*)cell_buf.buf);
                if (cell_width > col_widths[col + 1]) {
                    col_widths[col + 1] = cell_width;
                    if (col_widths[col + 1] > 50) col_widths[col + 1] = 50;
                }
                
                dbuf_free(&cell_buf);
                JS_FreeValue(ctx, cell);
            }
            JS_FreeValue(ctx, row_obj);
        }
        
        /* Build table */
        /* Top border */
        dbuf_putstr(&buf, "┌─");
        for (uint32_t i = 0; i <= col_count; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < col_count) dbuf_putstr(&buf, "─┬─");
        }
        dbuf_putstr(&buf, "─┐\n");
        
        /* Header */
        dbuf_putstr(&buf, "│ ");
        for (uint32_t i = 0; i <= col_count; i++) {
            dbuf_printf(&buf, ANSI_BOLD "%s" ANSI_RESET, col_names[i]);
            size_t name_width = wchar_width(col_names[i]);
            for (size_t j = name_width; j < col_widths[i]; j++) dbuf_putc(&buf, ' ');
            if (i < col_count) dbuf_putstr(&buf, " │ ");
        }
        dbuf_putstr(&buf, " │\n");
        
        /* Header separator */
        dbuf_putstr(&buf, "├─");
        for (uint32_t i = 0; i <= col_count; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < col_count) dbuf_putstr(&buf, "─┼─");
        }
        dbuf_putstr(&buf, "─┤\n");
        
        /* Rows */
        for (int64_t row = 0; row < len && row < MAX_TABLE_ROWS; row++) {
            dbuf_putstr(&buf, "│ ");
            
            /* Index column */
            char idx_buf[32];
            snprintf(idx_buf, sizeof(idx_buf), "%lld", (long long)row);
            dbuf_printf(&buf, ANSI_GRAY "%s" ANSI_RESET, idx_buf);
            size_t idx_width = wchar_width(idx_buf);
            for (size_t j = idx_width; j < col_widths[0]; j++) dbuf_putc(&buf, ' ');
            dbuf_putstr(&buf, " │ ");
            
            /* Data columns */
            JSValue row_obj = JS_GetPropertyUint32(ctx, data, row);
            for (uint32_t col = 0; col < col_count; col++) {
                JSValue cell = JS_GetProperty(ctx, row_obj, cols[col].atom);
                
                DynBuf cell_buf;
                dbuf_init2(&cell_buf, JS_GetRuntime(ctx), console_realloc);
                VisitStack temp_stack = { .count = 0 };
                format_value(ctx, cell, 0, &temp_stack, &cell_buf, true);
                
                size_t cell_width = wchar_width((const char*)cell_buf.buf);
                if (cell_width > col_widths[col + 1]) {
                    size_t truncate_pos = safe_truncate((const char*)cell_buf.buf, col_widths[col + 1] - 3);
                    dbuf_put(&buf, cell_buf.buf, truncate_pos);
                    dbuf_putstr(&buf, "...");
                } else {
                    dbuf_put(&buf, cell_buf.buf, cell_buf.size);
                    for (size_t j = cell_width; j < col_widths[col + 1]; j++) {
                        dbuf_putc(&buf, ' ');
                    }
                }
                
                dbuf_free(&cell_buf);
                JS_FreeValue(ctx, cell);
                
                if (col < col_count - 1) dbuf_putstr(&buf, " │ ");
            }
            JS_FreeValue(ctx, row_obj);
            
            dbuf_putstr(&buf, " │\n");
        }
        
        /* Bottom border */
        dbuf_putstr(&buf, "└─");
        for (uint32_t i = 0; i <= col_count; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < col_count) dbuf_putstr(&buf, "─┴─");
        }
        dbuf_putstr(&buf, "─┘\n");
        
    } else {
        /* Single object */
        JS_GetOwnPropertyNames(ctx, &cols, &col_count, data,
                              JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK);
        
        if (col_count == 0 || col_count > MAX_TABLE_ROWS) {
            dbuf_putstr(&buf, "Table too large or empty\n");
            goto end;
        }
        
        col_names = js_malloc(ctx, sizeof(char*) * 2);
        col_widths = js_malloc(ctx, sizeof(size_t) * 2);
        
        col_names[0] = "(index)";
        col_names[1] = NULL;
        col_widths[0] = wchar_width(col_names[0]);
        col_widths[1] = 0;
        
        /* Calculate widths */
        for (uint32_t i = 0; i < col_count; i++) {
            const char* key = JS_AtomToCString(ctx, cols[i].atom);
            size_t key_width = wchar_width(key);
            if (key_width > col_widths[0]) col_widths[0] = key_width;
            JS_FreeCString(ctx, key);
            
            JSValue val = JS_GetProperty(ctx, data, cols[i].atom);
            DynBuf val_buf;
            dbuf_init2(&val_buf, JS_GetRuntime(ctx), console_realloc);
            VisitStack temp_stack = { .count = 0 };
            format_value(ctx, val, 0, &temp_stack, &val_buf, true);
            
            size_t val_width = wchar_width((const char*)val_buf.buf);
            if (val_width > col_widths[1]) {
                col_widths[1] = val_width;
                if (col_widths[1] > 50) col_widths[1] = 50;
            }
            
            dbuf_free(&val_buf);
            JS_FreeValue(ctx, val);
        }
        
        /* Build table */
        dbuf_putstr(&buf, "┌─");
        for (int i = 0; i < 2; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < 1) dbuf_putstr(&buf, "─┬─");
        }
        dbuf_putstr(&buf, "─┐\n");
        
        dbuf_putstr(&buf, "│ ");
        for (int i = 0; i < 2; i++) {
			if (col_names[i])
            	dbuf_printf(&buf, ANSI_BOLD "%s" ANSI_RESET, col_names[i]);
            size_t name_width = wchar_width(col_names[i]);
            for (size_t j = name_width; j < col_widths[i]; j++) dbuf_putc(&buf, ' ');
            if (i < 1) dbuf_putstr(&buf, " │ ");
        }
        dbuf_putstr(&buf, " │\n");
        
        dbuf_putstr(&buf, "├─");
        for (int i = 0; i < 2; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < 1) dbuf_putstr(&buf, "─┼─");
        }
        dbuf_putstr(&buf, "─┤\n");
        
        for (uint32_t i = 0; i < col_count; i++) {
            dbuf_putstr(&buf, "│ ");
            
            const char* key = JS_AtomToCString(ctx, cols[i].atom);
            dbuf_printf(&buf, ANSI_CYAN "%s" ANSI_RESET, key);
            size_t key_width = wchar_width(key);
            for (size_t j = key_width; j < col_widths[0]; j++) dbuf_putc(&buf, ' ');
            JS_FreeCString(ctx, key);
            
            dbuf_putstr(&buf, " │ ");
            
            JSValue val = JS_GetProperty(ctx, data, cols[i].atom);
            DynBuf val_buf;
            dbuf_init2(&val_buf, JS_GetRuntime(ctx), console_realloc);
            VisitStack temp_stack = { .count = 0 };
            format_value(ctx, val, 0, &temp_stack, &val_buf, true);
            
            size_t val_width = wchar_width((const char*)val_buf.buf);
            if (val_width > col_widths[1]) {
                size_t truncate_pos = safe_truncate((const char*)val_buf.buf, col_widths[1] - 3);
                dbuf_put(&buf, val_buf.buf, truncate_pos);
                dbuf_putstr(&buf, "...");
            } else {
                dbuf_put(&buf, val_buf.buf, val_buf.size);
                for (size_t j = val_width; j < col_widths[1]; j++) {
                    dbuf_putc(&buf, ' ');
                }
            }
            
            dbuf_free(&val_buf);
            JS_FreeValue(ctx, val);
            
            dbuf_putstr(&buf, " │\n");
        }
        
        dbuf_putstr(&buf, "└─");
        for (int i = 0; i < 2; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < 1) dbuf_putstr(&buf, "─┴─");
        }
        dbuf_putstr(&buf, "─┘\n");
    }
    
end:
    if (cols) JS_FreePropertyEnum(ctx, cols, col_count);
    if (col_names) {
        for (uint32_t i = 1; i < col_count + 1 && col_names[i]; i++) {
            if(col_names[i]) JS_FreeCString(ctx, col_names[i]);
        }
        js_free(ctx, col_names);
    }
    if (col_widths) js_free(ctx, col_widths);
    
    fwrite(buf.buf, 1, buf.size, stdout);
    fflush(stdout);
    dbuf_free(&buf);
    
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry console_funcs[] = {
    JS_CFUNC_DEF("log", 1, js_console_log),
    JS_CFUNC_DEF("error", 1, js_console_error),
    JS_CFUNC_DEF("warn", 1, js_console_warn),
    JS_CFUNC_DEF("info", 1, js_console_info),
    JS_CFUNC_DEF("debug", 1, js_console_debug),
    JS_CFUNC_DEF("assert", 2, js_console_assert),
    JS_CFUNC_DEF("clear", 0, js_console_clear),
    JS_CFUNC_DEF("dir", 1, js_console_dir),
    JS_CFUNC_DEF("table", 1, js_console_table),
    JS_CFUNC_DEF("trace", 0, js_console_trace),
    JS_CFUNC_DEF("count", 0, js_console_count),
    JS_CFUNC_DEF("countReset", 0, js_console_countReset),
    JS_CFUNC_DEF("time", 0, js_console_time),
    JS_CFUNC_DEF("timeEnd", 0, js_console_timeEnd),
    JS_CFUNC_DEF("timeLog", 0, js_console_timeLog),
    JS_CFUNC_DEF("timeStamp", 0, js_console_timeStamp),
    // non-standard: inspect()
    JS_CFUNC_DEF("inspect", 1, js_console_inspect),
};

/* Module initialization */
void tjs__mod_console_init(JSContext* ctx, JSValue ns) {
    /* Create console object */
    JS_SetPropertyFunctionList(ctx, ns, console_funcs, countof(console_funcs));
}