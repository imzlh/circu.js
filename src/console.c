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
#include <time.h>
#ifndef L_NO_THREADS_H
#include <threads.h>
#endif
#include <assert.h>

/* Constants */
#define MAX_DEPTH 64
#define MAX_INLINE_PROPS 4
#define MAX_DISPLAY_PROPS 16
#define MAX_BUFFER_DISPLAY 128
#define MAX_TABLE_ROWS 100
#define MAX_TABLE_COLS 20

/* ANSI Color Codes */
#define ANSI_RESET     "\x1b[0m"
#define ANSI_BOLD      "\x1b[1m"
#define ANSI_ITALIC    "\x1b[3m"
#define ANSI_RED       "\x1b[31m"
#define ANSI_GREEN     "\x1b[32m"
#define ANSI_YELLOW    "\x1b[33m"
#define ANSI_BLUE      "\x1b[34m"
#define ANSI_MAGENTA   "\x1b[35m"
#define ANSI_CYAN      "\x1b[36m"
#define ANSI_GRAY      "\x1b[90m"

/* Indentation Helper */
#define INDENT_SIZE 2
#define BLANK_BUFFER "                                                                " \
                     "                                                                " \
                     "                                                                " \
                     "                                                                "

static const char* s_blank = BLANK_BUFFER;
static const size_t s_blank_len = 64;

static inline const char* get_indent(int depth) {
    assert(depth <= (int)s_blank_len);
    size_t offset = (s_blank_len - depth) * INDENT_SIZE;
    return s_blank + offset;
}

/* Memory Allocator */
static void* console_realloc(void* opaque, void* ptr, size_t size) {
    return js_realloc_rt((JSRuntime*)opaque, ptr, size);
}

/* Utility Functions */
static inline bool is_circular(JSContext* ctx, JSValue val, JSValue visited[], int depth) {
    if (depth >= MAX_DEPTH) return true;
    for (int i = 0; i < depth; i++) {
        if (JS_IsSameValue(ctx, val, visited[i])) return true;
    }
    return false;
}

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
                        JSValue visited[], DynBuf* buf, bool in_container);

/* Check if value should be displayed inline */
static bool should_inline(JSContext* ctx, JSValueConst val, JSValue visited[], int depth) {
    if (depth >= MAX_INLINE_PROPS) return false;
    if (is_circular(ctx, val, visited, depth)) return true;
    
    /* Simple types always inline */
    if (!JS_IsObject(val)) return true;
    if (JS_IsNull(val)) return true;
    
    /* Special objects */
    if (JS_IsSymbol(val) || JS_IsRegExp(val) || JS_IsDate(val)) return true;
    if (JS_IsWeakMap(val) || JS_IsWeakSet(val)) return true;
    
    /* Check container size */
    int64_t len = 0;
    JSValue len_val = JS_GetProperty(ctx, val, JS_ATOM_length);
    if (JS_IsNumber(len_val)) {
        JS_ToInt64(ctx, &len, len_val);
        JS_FreeValue(ctx, len_val);
        if (len > MAX_INLINE_PROPS) return false;
        
        /* Check element complexity */
        visited[depth] = val;
        for (int64_t i = 0; i < len; i++) {
            JSValue elem = JS_GetPropertyUint32(ctx, val, i);
            bool inline_elem = should_inline(ctx, elem, visited, depth + 1);
            JS_FreeValue(ctx, elem);
            if (!inline_elem) return false;
        }
        return true;
    }
    JS_FreeValue(ctx, len_val);
    
    /* Check object properties */
    JSPropertyEnum* props = NULL;
    uint32_t prop_count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, val, 
                               JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK) == 0) {
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
        dbuf_putstr(buf, ANSI_RED "String" ANSI_RESET);
        return;
    }
    
    if (in_container) {
        dbuf_printf(buf, ANSI_GREEN "'%s'" ANSI_RESET, str);
    } else {
        dbuf_putstr(buf, str);
    }
    JS_FreeCString(ctx, str);
}

static void format_number(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    double num;
    if (JS_ToFloat64(ctx, &num, val) < 0) {
        dbuf_putstr(buf, ANSI_YELLOW "NaN" ANSI_RESET);
    } else {
        dbuf_printf(buf, ANSI_YELLOW "%g" ANSI_RESET, num);
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
                        JSValue visited[], DynBuf* buf) {
    int64_t len = 0;
    JSValue len_val = JS_GetProperty(ctx, val, JS_ATOM_length);
    JS_ToInt64(ctx, &len, len_val);
    JS_FreeValue(ctx, len_val);
    
    if (is_circular(ctx, val, visited, depth)) {
        dbuf_putstr(buf, ANSI_CYAN "[Circular]" ANSI_RESET);
        return;
    }
    
    visited[depth] = val;
    bool inline_display = should_inline(ctx, val, visited, depth);
    
    dbuf_putstr(buf, "[ ");
    
    int64_t display_count = len > MAX_DISPLAY_PROPS ? MAX_DISPLAY_PROPS : len;
    for (int64_t i = 0; i < display_count; i++) {
        if (i > 0) dbuf_putstr(buf, ", ");
        
        if (!inline_display && i > 0) {
            dbuf_printf(buf, "\n%s", get_indent(depth + 1));
        }
        
        JSValue elem = JS_GetPropertyUint32(ctx, val, i);
        format_value(ctx, elem, depth + 1, visited, buf, true);
        JS_FreeValue(ctx, elem);
    }
    
    if (len > MAX_DISPLAY_PROPS) {
        dbuf_printf(buf, ", ... %lld more items", (long long)(len - MAX_DISPLAY_PROPS));
    }
    
    if (!inline_display && display_count > 0) {
        dbuf_printf(buf, "\n%s", get_indent(depth));
    }
    
    dbuf_putstr(buf, " ]");
    visited[depth] = JS_NULL;
}

static void format_object(JSContext* ctx, JSValueConst val, int depth, 
                         JSValue visited[], DynBuf* buf) {
    if (is_circular(ctx, val, visited, depth)) {
        dbuf_putstr(buf, ANSI_CYAN "[Circular]" ANSI_RESET);
        return;
    }
    
    visited[depth] = val;
    
    /* Get class name */
    const char* class_name = get_class_name(ctx, val);
    if (class_name) {
        dbuf_printf(buf, "%s ", class_name);
        JS_FreeCString(ctx, class_name);
    }
    
    /* Get properties */
    JSPropertyEnum* props = NULL;
    uint32_t prop_count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, val,
                               JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK) < 0) {
        dbuf_putstr(buf, "{}");
        visited[depth] = JS_NULL;
        return;
    }
    
    bool inline_display = should_inline(ctx, val, visited, depth);
    dbuf_putstr(buf, "{ ");
    
    uint32_t display_count = prop_count > MAX_DISPLAY_PROPS ? MAX_DISPLAY_PROPS : prop_count;
    uint32_t shown = 0;
    
    for (uint32_t i = 0; i < display_count; i++) {
        if (props[i].atom == JS_ATOM_prototype) continue;
        
        if (shown > 0) dbuf_putstr(buf, ", ");
        
        if (!inline_display && shown > 0) {
            dbuf_printf(buf, "\n%s", get_indent(depth + 1));
        }
        
        /* Property key */
        const char* key = JS_AtomToCString(ctx, props[i].atom);
        dbuf_printf(buf, ANSI_CYAN "%s" ANSI_RESET ": ", key ? key : "");
        if (key) JS_FreeCString(ctx, key);
        
        /* Property value */
        JSValue prop_val = JS_GetProperty(ctx, val, props[i].atom);
        format_value(ctx, prop_val, depth + 1, visited, buf, true);
        JS_FreeValue(ctx, prop_val);
        
        shown++;
    }
    
    if (prop_count > MAX_DISPLAY_PROPS) {
        dbuf_printf(buf, ", ... %u more properties", prop_count - MAX_DISPLAY_PROPS);
    }
    
    if (!inline_display && shown > 0) {
        dbuf_printf(buf, "\n%s", get_indent(depth));
    }
    
    dbuf_putstr(buf, " }");
    
    JS_FreePropertyEnum(ctx, props, prop_count);
    visited[depth] = JS_NULL;
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

static void format_typed_array(JSContext* ctx, JSValueConst val, int depth, DynBuf* buf) {
    size_t size = 0;
    uint8_t* data = NULL;
    const char* type_name = "TypedArray";
    
    if (JS_IsArrayBuffer(val)) {
        data = JS_GetArrayBuffer(ctx, &size, val);
        type_name = "ArrayBuffer";
    } else {
        data = JS_GetUint8Array(ctx, &size, val);
    }
    
    dbuf_printf(buf, ANSI_MAGENTA "%s" ANSI_RESET "(%zu) [", type_name, size);
    
    size_t display_size = size > MAX_BUFFER_DISPLAY ? MAX_BUFFER_DISPLAY : size;
    for (size_t i = 0; i < display_size; i++) {
        if (i > 0) dbuf_putstr(buf, " ");
        dbuf_printf(buf, "%02x", data[i]);
    }
    
    if (size > MAX_BUFFER_DISPLAY) {
        dbuf_printf(buf, " ... %zu more bytes", size - MAX_BUFFER_DISPLAY);
    }
    
    dbuf_putstr(buf, " ]");
}

/* Main formatting function */
static void format_value(JSContext* ctx, JSValueConst val, int depth, 
                        JSValue visited[], DynBuf* buf, bool in_container) {
    if (depth >= MAX_DEPTH) {
        dbuf_putstr(buf, ANSI_RED "[Max depth]" ANSI_RESET);
        return;
    }
    
    /* Primitives */
    if (JS_IsUndefined(val)) {
        dbuf_putstr(buf, ANSI_GRAY "undefined" ANSI_RESET);
    } else if (JS_IsNull(val)) {
        dbuf_putstr(buf, ANSI_BOLD "null" ANSI_RESET);
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
    /* Special objects */
    else if (JS_IsError(val)) {
        format_error(ctx, val, depth, buf);
    } else if (JS_IsPromise(val)) {
        format_promise(ctx, val, buf);
    } else if (JS_IsArrayBuffer(val) || JS_GetTypedArrayType(val) != -1) {
        format_typed_array(ctx, val, depth, buf);
    } else if (JS_IsArray(val)) {
        format_array(ctx, val, depth, visited, buf);
    } else if (JS_IsObject(val)) {
        format_object(ctx, val, depth, visited, buf);
    } else {
        dbuf_putstr(buf, ANSI_RED "[Unknown]" ANSI_RESET);
    }
}

/* Table formatting helper */
static void format_table_value(JSContext* ctx, JSValueConst val, DynBuf* buf, size_t max_width) {
    JSValue visited[MAX_DEPTH];
    DynBuf temp;
    dbuf_init2(&temp, JS_GetRuntime(ctx), console_realloc);
    
    format_value(ctx, val, 0, visited, &temp, true);
    
    /* Truncate if too long */
    size_t len = temp.size;
    if (len > max_width) {
        len = max_width - 3;
        dbuf_put(buf, temp.buf, len);
        dbuf_putstr(buf, "...");
    } else {
        dbuf_put(buf, temp.buf, len);
        /* Pad with spaces */
        for (size_t i = len; i < max_width; i++) {
            dbuf_putc(buf, ' ');
        }
    }
    
    dbuf_free(&temp);
}

/* Console API implementations */
static JSValue js_console_log(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv) {
    if (argc == 0) {
        printf("\n");
        return JS_UNDEFINED;
    }
    
    JSValue visited[MAX_DEPTH];
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, visited, &buf, false);
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
        return JS_UNDEFINED;
    }
    
    JSValue visited[MAX_DEPTH];
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, visited, &buf, false);
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
        return JS_UNDEFINED;
    }
    
    JSValue visited[MAX_DEPTH];
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    dbuf_putstr(&buf, ANSI_YELLOW);
    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, visited, &buf, false);
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
        col_widths[0] = strlen(col_names[0]);
        
        /* Data columns */
        for (uint32_t i = 0; i < col_count; i++) {
            col_names[i + 1] = JS_AtomToCString(ctx, cols[i].atom);
            col_widths[i + 1] = strlen(col_names[i + 1]);
        }
        
        /* Calculate column widths */
        for (int64_t row = 0; row < len; row++) {
            JSValue row_obj = JS_GetPropertyUint32(ctx, data, row);
            if (!JS_IsObject(row_obj)) {
                JS_FreeValue(ctx, row_obj);
                continue;
            }
            
            for (uint32_t col = 0; col < col_count; col++) {
                JSValue cell = JS_GetProperty(ctx, row_obj, cols[col].atom);
                
                DynBuf cell_buf;
                dbuf_init2(&cell_buf, JS_GetRuntime(ctx), console_realloc);
                JSValue visited[MAX_DEPTH];
                format_value(ctx, cell, 0, visited, &cell_buf, true);
                
                if (cell_buf.size > col_widths[col + 1]) {
                    col_widths[col + 1] = cell_buf.size;
                    if (col_widths[col + 1] > 50) col_widths[col + 1] = 50;
                }
                
                dbuf_free(&cell_buf);
                JS_FreeValue(ctx, cell);
            }
            JS_FreeValue(ctx, row_obj);
        }
        
        /* Print header separator */
        dbuf_putstr(&buf, "┌─");
        for (uint32_t i = 0; i <= col_count; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < col_count) dbuf_putstr(&buf, "─┬─");
        }
        dbuf_putstr(&buf, "─┐\n");
        
        /* Print header */
        dbuf_putstr(&buf, "│ ");
        for (uint32_t i = 0; i <= col_count; i++) {
            dbuf_printf(&buf, ANSI_BOLD "%s" ANSI_RESET, col_names[i]);
            size_t name_len = strlen(col_names[i]);
            for (size_t j = name_len; j < col_widths[i]; j++) dbuf_putc(&buf, ' ');
            if (i < col_count) dbuf_putstr(&buf, " │ ");
        }
        dbuf_putstr(&buf, " │\n");
        
        /* Print separator */
        dbuf_putstr(&buf, "├─");
        for (uint32_t i = 0; i <= col_count; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < col_count) dbuf_putstr(&buf, "─┼─");
        }
        dbuf_putstr(&buf, "─┤\n");
        
        /* Print rows */
        for (int64_t row = 0; row < len && row < MAX_TABLE_ROWS; row++) {
            dbuf_putstr(&buf, "│ ");
            
            /* Index column */
            dbuf_printf(&buf, ANSI_GRAY "%lld" ANSI_RESET, (long long)row);
            size_t idx_len = snprintf(NULL, 0, "%lld", (long long)row);
            for (size_t j = idx_len; j < col_widths[0]; j++) dbuf_putc(&buf, ' ');
            dbuf_putstr(&buf, " │ ");
            
            /* Data columns */
            JSValue row_obj = JS_GetPropertyUint32(ctx, data, row);
            for (uint32_t col = 0; col < col_count; col++) {
                JSValue cell = JS_GetProperty(ctx, row_obj, cols[col].atom);
                format_table_value(ctx, cell, &buf, col_widths[col + 1]);
                JS_FreeValue(ctx, cell);
                if (col < col_count - 1) dbuf_putstr(&buf, " │ ");
            }
            JS_FreeValue(ctx, row_obj);
            
            dbuf_putstr(&buf, " │\n");
        }
        
        /* Print footer */
        dbuf_putstr(&buf, "└─");
        for (uint32_t i = 0; i <= col_count; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < col_count) dbuf_putstr(&buf, "─┴─");
        }
        dbuf_putstr(&buf, "─┘\n");
        
    } else {
        /* Single object - show key-value pairs */
        JS_GetOwnPropertyNames(ctx, &cols, &col_count, data,
                              JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK);
        
        if (col_count == 0 || col_count > MAX_TABLE_ROWS) {
            dbuf_putstr(&buf, "Table too large or empty\n");
            goto end;
        }
        
        col_names = js_malloc(ctx, sizeof(char*) * 2);
        col_widths = js_malloc(ctx, sizeof(size_t) * 2);
        
        col_names[0] = "(index)";
        col_names[1] = "Values";
        col_widths[0] = strlen(col_names[0]);
        col_widths[1] = strlen(col_names[1]);
        
        /* Calculate widths */
        for (uint32_t i = 0; i < col_count; i++) {
            const char* key = JS_AtomToCString(ctx, cols[i].atom);
            size_t key_len = strlen(key);
            if (key_len > col_widths[0]) col_widths[0] = key_len;
            JS_FreeCString(ctx, key);
            
            JSValue val = JS_GetProperty(ctx, data, cols[i].atom);
            DynBuf val_buf;
            dbuf_init2(&val_buf, JS_GetRuntime(ctx), console_realloc);
            JSValue visited[MAX_DEPTH];
            format_value(ctx, val, 0, visited, &val_buf, true);
            if (val_buf.size > col_widths[1]) {
                col_widths[1] = val_buf.size;
                if (col_widths[1] > 50) col_widths[1] = 50;
            }
            dbuf_free(&val_buf);
            JS_FreeValue(ctx, val);
        }
        
        /* Print table */
        dbuf_putstr(&buf, "┌─");
        for (int i = 0; i < 2; i++) {
            for (size_t j = 0; j < col_widths[i]; j++) dbuf_putstr(&buf, "─");
            if (i < 1) dbuf_putstr(&buf, "─┬─");
        }
        dbuf_putstr(&buf, "─┐\n");
        
        dbuf_putstr(&buf, "│ ");
        for (int i = 0; i < 2; i++) {
            dbuf_printf(&buf, ANSI_BOLD "%s" ANSI_RESET, col_names[i]);
            size_t name_len = strlen(col_names[i]);
            for (size_t j = name_len; j < col_widths[i]; j++) dbuf_putc(&buf, ' ');
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
            size_t key_len = strlen(key);
            for (size_t j = key_len; j < col_widths[0]; j++) dbuf_putc(&buf, ' ');
            JS_FreeCString(ctx, key);
            
            dbuf_putstr(&buf, " │ ");
            
            JSValue val = JS_GetProperty(ctx, data, cols[i].atom);
            format_table_value(ctx, val, &buf, col_widths[1]);
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
            JS_FreeCString(ctx, col_names[i]);
        }
        js_free(ctx, col_names);
    }
    if (col_widths) js_free(ctx, col_widths);
    
    fwrite(buf.buf, 1, buf.size, stdout);
    fflush(stdout);
    dbuf_free(&buf);
    
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
        }
    }
    return JS_UNDEFINED;
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
    
    JSValue visited[MAX_DEPTH];
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    
    /* Always show full object structure */
    format_value(ctx, argv[0], 0, visited, &buf, false);
    
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

static inline JSValue tjs_get_t_cache(JSContext* ctx, JSValue symbol, JSAtom* atom){
	TJSRuntime* trt = TJS_GetRuntime(ctx);
    
    *atom = JS_ATOM_default;
    if (JS_IsString(symbol)) {
        *atom = JS_ValueToAtom(ctx, symbol);
    }
    
	JSValue val = JS_GetProperty(ctx, trt->builtins.contime, *atom);
	if (JS_IsUndefined(val)){
		val = JS_NewInt32(ctx, 0);
	}

	return val;
}

static inline void tjs_set_t_cache(JSContext* ctx, JSAtom atom, JSValue val){
	JS_SetProperty(ctx, TJS_GetRuntime(ctx)->builtins.contime, atom, val);
}

static JSValue js_console_count(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {

	TJSRuntime* trt = TJS_GetRuntime(ctx);
    JSAtom atom = JS_ATOM_default;
	JSValue symbol = argc == 0 ? JS_UNDEFINED : argv[0];

    if (JS_IsString(symbol)) {
        atom = JS_ValueToAtom(ctx, symbol);
    }
    
	JSValue val = JS_GetProperty(ctx, trt->builtins.concount, atom);
	if (JS_IsUndefined(val)) val = JS_MKVAL(JS_TAG_INT, 1);
	else val.u.int32++;
	JS_SetProperty(ctx, trt->builtins.concount, atom, val);

	const char* label = JS_AtomToCString(ctx, atom);
	printf(ANSI_GRAY "count '%s'" ANSI_BLUE " %d\n", label ? label : "default", val.u.int32);
	if(label) JS_FreeCString(ctx, label);

	JS_FreeAtom(ctx, atom);
	JS_FreeValue(ctx, val);	// maybe not necessary
    return JS_UNDEFINED;
}

static JSValue js_console_countReset(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    TJSRuntime* trt = TJS_GetRuntime(ctx);
    JSAtom atom = JS_ATOM_default;
    JSValue symbol = argc == 0 ? JS_UNDEFINED : argv[0];

    if (JS_IsString(symbol)) {
        atom = JS_ValueToAtom(ctx, symbol);
    }

    JSValue val = JS_NewInt32(ctx, 0);
    JS_SetProperty(ctx, trt->builtins.concount, atom, val);

    const char* label = JS_AtomToCString(ctx, atom);
    printf(ANSI_GRAY "countReset '%s'" ANSI_BLUE " %d\n", 
           label ? label : "default", val.u.int32);
    
    if (label) {
        JS_FreeCString(ctx, label);
    }
    JS_FreeAtom(ctx, atom);
    JS_FreeValue(ctx, val);

    return JS_UNDEFINED;
}


static JSValue js_console_time(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
	JSValue symbol = argc == 0 ? JS_UNDEFINED : argv[0];
	const char* label = NULL;

    if (JS_IsString(symbol)) {
        atom = JS_ValueToAtom(ctx, symbol);
		label = JS_ToCString(ctx, symbol);
    }

	JSValue val = tjs_get_t_cache(ctx, symbol, &atom);
	size_t prevclk;
	size_t clk = clock();
	if (-1 == JS_ToBigUint64(ctx, &prevclk, val)){
		prevclk = clock();
		tjs_set_t_cache(ctx, atom, JS_NewBigUint64(ctx, prevclk));
	}
    
	size_t diff_ms = (clk - prevclk) * 1000 / CLOCKS_PER_SEC;
    printf(ANSI_GRAY "Timer '%s' " ANSI_BLUE " %ldms" ANSI_RESET "\n", label ? label : "default", diff_ms);
    
	if (label) {
		JS_FreeCString(ctx, label);
		JS_FreeAtom(ctx, atom);
	}
    JS_FreeValue(ctx, val);
    return JS_UNDEFINED;
}

static JSValue js_console_timeEnd(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv) {
    JSAtom atom = JS_ATOM_default;
    JSValue symbol = argc == 0 ? JS_UNDEFINED : argv[0];
    const char* label = NULL;

    if (JS_IsString(symbol)) {
        atom = JS_ValueToAtom(ctx, symbol);
        label = JS_ToCString(ctx, symbol);
    }
    JSValue val = tjs_get_t_cache(ctx, symbol, &atom);
    size_t start_clk;
    if (-1 == JS_ToBigUint64(ctx, &start_clk, val)) {
        if (label) {
            JS_FreeCString(ctx, label);
            JS_FreeAtom(ctx, atom);
        }
        return JS_UNDEFINED;
    }

    size_t end_clk = clock();
    size_t diff_ms = (end_clk - start_clk) * 1000 / CLOCKS_PER_SEC;
    printf(ANSI_GRAY "Timer '%s' " ANSI_BLUE " %ldms" ANSI_RESET "\n", 
           label ? label : "default", diff_ms);

    tjs_set_t_cache(ctx, atom, JS_UNDEFINED);

    if (label) {
        JS_FreeCString(ctx, label);
        JS_FreeAtom(ctx, atom);
    }
    JS_FreeValue(ctx, val);
    
    return JS_UNDEFINED;
}

static JSValue js_console_timeLog(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    // TJSRuntime* trt = TJS_GetRuntime(ctx);
    JSAtom atom = JS_ATOM_default;
    JSValue symbol = argc == 0 ? JS_UNDEFINED : argv[0];
    const char* label = NULL;

    if (JS_IsString(symbol)) {
        atom = JS_ValueToAtom(ctx, symbol);
        label = JS_ToCString(ctx, symbol);
    }

    JSValue val = tjs_get_t_cache(ctx, symbol, &atom);
    size_t start_clk;
    if (-1 == JS_ToBigUint64(ctx, &start_clk, val)) {
        if (label) {
            JS_FreeCString(ctx, label);
            JS_FreeAtom(ctx, atom);
        }
        return JS_UNDEFINED;
    }

    size_t current_clk = clock();
    size_t diff_ms = (current_clk - start_clk) * 1000 / CLOCKS_PER_SEC;
    printf(ANSI_GRAY "Timer '%s' " ANSI_BLUE " %ldms  " ANSI_RESET, 
           label ? label : "default", diff_ms);
    
    if (argc > 1) {
        printf(":");
		js_console_log(ctx, this_val, argc - 1, argv + 1);
    }
    printf("\n");

    if (label) {
        JS_FreeCString(ctx, label);
        JS_FreeAtom(ctx, atom);
    }
    JS_FreeValue(ctx, val);
    
    return JS_UNDEFINED;
}
static JSValue js_console_timeStamp(JSContext* ctx, JSValueConst this_val,
                                   int argc, JSValueConst* argv) {
    const char* label = NULL;
    JSValue symbol = argc == 0 ? JS_UNDEFINED : argv[0];

    if (JS_IsString(symbol)) {
        label = JS_ToCString(ctx, symbol);
    }

    uv_timeval64_t tv;
    uv_gettimeofday(&tv);
    time_t now = tv.tv_sec;
    struct tm* tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf(ANSI_GRAY "Timestamp '%s' " ANSI_BLUE " %s.%03ld" ANSI_RESET "\n",
           label ? label : "default", time_str, tv.tv_sec * 1000 + tv.tv_usec / 1000);

    if (label) {
        JS_FreeCString(ctx, label);
    }
    
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
};

/* Module initialization */
void tjs__mod_console_init(JSContext* ctx, JSValue ns) {
    /* Create console object */
    JS_SetPropertyFunctionList(ctx, ns, console_funcs, countof(console_funcs));
}