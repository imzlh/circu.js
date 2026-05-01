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
#include <stdlib.h>
#include <math.h>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif
#else
#include <unistd.h>
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX_DEPTH 64
#define DEFAULT_BREAK_LENGTH 80
#define MAX_ARRAY_LENGTH 100
#define MAX_STRING_LENGTH 10000

/* ANSI Colors */
#define ANSI_RESET     "\x1b[0m"
#define ANSI_BOLD      "\x1b[1m"
#define ANSI_DIM       "\x1b[2m"
#define ANSI_RED       "\x1b[31m"
#define ANSI_GREEN     "\x1b[32m"
#define ANSI_YELLOW    "\x1b[33m"
#define ANSI_BLUE      "\x1b[34m"
#define ANSI_MAGENTA   "\x1b[35m"
#define ANSI_CYAN      "\x1b[36m"
#define ANSI_GRAY      "\x1b[90m"

/* Memory */
static void* console_realloc(void* opaque, void* ptr, size_t size) {
    return js_realloc_rt((JSRuntime*)opaque, ptr, size);
}

/* STDOUT lock */
static uv_mutex_t stdout_mutex;
static int stdout_mutex_initialized = 0;

static void ensure_stdout_mutex_init(void) {
    if (!stdout_mutex_initialized) {
        uv_mutex_init(&stdout_mutex);
        stdout_mutex_initialized = 1;
    }
}

#define __mutex(op) ensure_stdout_mutex_init(); uv_mutex_lock(&stdout_mutex); op; uv_mutex_unlock(&stdout_mutex);
#define fwrite2(...) __mutex(fwrite(__VA_ARGS__))
#define fprintf2(...) __mutex(fprintf(__VA_ARGS__))

/* Indentation - Fixed: properly initialized */
static const char* get_indent(int depth) {
    static const char spaces[] = "                                                                ";
    int offset = depth * 2;
    if (offset > 60) offset = 60;
    return &spaces[sizeof(spaces) - 1 - offset];  // Return pointer to the spaces
}

/* Circular reference tracking */
typedef struct {
    JSValue refs[MAX_DEPTH];
    int count;
} VisitStack;

static bool is_circular(VisitStack* stack, JSValue val) {
    if (!stack || !JS_VALUE_HAS_REF_COUNT(val)) return false;
    void* ptr = JS_VALUE_GET_PTR(val);
    for (int i = 0; i < stack->count; i++) {
        if (JS_VALUE_GET_PTR(stack->refs[i]) == ptr) return true;
    }
    return false;
}

static void visit_push(VisitStack* stack, JSValue val) {
    if (stack && stack->count < MAX_DEPTH) {
        stack->refs[stack->count++] = val;
    }
}

static void visit_pop(VisitStack* stack) {
    if (stack && stack->count > 0) stack->count--;
}

/* Options */
typedef struct {
    int depth;
    int break_length;
    bool colors;
    bool show_hidden;
    int max_array_length;
    int max_string_length;
    bool compact;
} InspectOptions;

static void parse_inspect_options(JSContext* ctx, JSValue opts_val, InspectOptions* opts) {
    opts->depth = 2;
    opts->break_length = DEFAULT_BREAK_LENGTH;
    opts->colors = isatty(STDOUT_FILENO);
    opts->show_hidden = false;
    opts->max_array_length = MAX_ARRAY_LENGTH;
    opts->max_string_length = MAX_STRING_LENGTH;
    opts->compact = true;

    if (!JS_IsObject(opts_val)) return;

    JSValue v;
    v = JS_GetPropertyStr(ctx, opts_val, "depth");
    if (JS_IsNumber(v)) {
        JS_ToInt32(ctx, &opts->depth, v);
        if (opts->depth < 0) opts->depth = 0;
    }
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opts_val, "breakLength");
    if (JS_IsNumber(v)) JS_ToInt32(ctx, &opts->break_length, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opts_val, "colors");
    if (JS_IsBool(v)) opts->colors = JS_ToBool(ctx, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opts_val, "showHidden");
    if (JS_IsBool(v)) opts->show_hidden = JS_ToBool(ctx, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opts_val, "maxArrayLength");
    if (JS_IsNumber(v)) JS_ToInt32(ctx, &opts->max_array_length, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opts_val, "maxStringLength");
    if (JS_IsNumber(v)) JS_ToInt32(ctx, &opts->max_string_length, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opts_val, "compact");
    if (JS_IsBool(v)) opts->compact = JS_ToBool(ctx, v);
    JS_FreeValue(ctx, v);
}

/* Forward declaration */
static void format_value(JSContext* ctx, JSValue val, int depth, VisitStack* stack, 
                        DynBuf* buf, bool quoted, const InspectOptions* opts);

/* Utility: Get class name including Symbol.toStringTag */
static char* get_class_name(JSContext* ctx, JSValue obj) {
    // Try Symbol.toStringTag first (for fs.Stats, etc.)
    JSAtom tag_atom = JS_NewAtom(ctx, "Symbol.toStringTag");
    JSValue tag = JS_GetProperty(ctx, obj, tag_atom);
    JS_FreeAtom(ctx, tag_atom);
    
    if (!JS_IsException(tag) && JS_IsString(tag)) {
        const char* str = JS_ToCString(ctx, tag);
        JS_FreeValue(ctx, tag);
        if (str && str[0]) {
            char* dup = js_strdup(ctx, str);
            JS_FreeCString(ctx, str);  /* fix: str leaked before return */
            return dup;
        }
        if (str) JS_FreeCString(ctx, str);
    }
    JS_FreeValue(ctx, tag);

    // Fallback to constructor.name
    JSValue ctor = JS_GetPropertyStr(ctx, obj, "constructor");
    if (JS_IsException(ctor) || JS_IsUndefined(ctor) || JS_IsNull(ctor)) {
        JS_FreeValue(ctx, ctor);
        return NULL;
    }

    JSValue name = JS_GetPropertyStr(ctx, ctor, "name");
    JS_FreeValue(ctx, ctor);
    
    if (JS_IsException(name) || !JS_IsString(name)) {
        JS_FreeValue(ctx, name);
        return NULL;
    }

    const char* str = JS_ToCString(ctx, name);
    JS_FreeValue(ctx, name);
    
    if (str && str[0] && strcmp(str, "Object") != 0) {
        char* dup = js_strdup(ctx, str);
        JS_FreeCString(ctx, str);  /* fix: str leaked before return */
        return dup;
    }
    if (str) JS_FreeCString(ctx, str);
    return NULL;
}

/* Color helpers */
static void put_color(DynBuf* buf, const InspectOptions* opts, const char* color) {
    if (opts->colors) dbuf_putstr(buf, color);
}

static void put_reset(DynBuf* buf, const InspectOptions* opts) {
    if (opts->colors) dbuf_putstr(buf, ANSI_RESET);
}

/* Format primitives */
static void format_string(JSContext* ctx, JSValue val, DynBuf* buf, bool quoted, 
                         const InspectOptions* opts) {
    const char* str = JS_ToCString(ctx, val);
    if (!str) {
        put_color(buf, opts, ANSI_RED);
        dbuf_putstr(buf, "[String]");
        put_reset(buf, opts);
        return;
    }

    size_t len = strlen(str);
    if (!quoted) {
        dbuf_printf(buf, "%.*s%s", opts->max_string_length, str, 
                   len > (size_t)opts->max_string_length ? "..." : "");
    } else {
        put_color(buf, opts, ANSI_GREEN);
        dbuf_putc(buf, '\'');
        for (size_t i = 0; i < len && i < (size_t)opts->max_string_length; i++) {
            unsigned char c = str[i];
            if (c == '\n') dbuf_putstr(buf, "\\n");
            else if (c == '\r') dbuf_putstr(buf, "\\r");
            else if (c == '\t') dbuf_putstr(buf, "\\t");
            else if (c == '\\') dbuf_putstr(buf, "\\\\");
            else if (c == '\'') dbuf_putstr(buf, "\\'");
            else if (c < 32 || c == 127) dbuf_printf(buf, "\\x%02x", c);
            else dbuf_putc(buf, c);
        }
        if (len > (size_t)opts->max_string_length) dbuf_putstr(buf, "...");
        dbuf_putc(buf, '\'');
        put_reset(buf, opts);
    }
    JS_FreeCString(ctx, str);
}

static void format_number(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    double num;
    if (JS_ToFloat64(ctx, &num, val) < 0) {
        put_color(buf, opts, ANSI_YELLOW);
        dbuf_putstr(buf, "NaN");
        put_reset(buf, opts);
        return;
    }

    put_color(buf, opts, ANSI_YELLOW);
    if (isnan(num)) {
        dbuf_putstr(buf, "NaN");
    } else if (isinf(num)) {
        dbuf_printf(buf, "%cInfinity", num < 0 ? '-' : '+');
    } else if (floor(num) == num && fabs(num) < 1e21) {
        dbuf_printf(buf, "%.0f", num);
    } else {
        dbuf_printf(buf, "%g", num);
    }
    put_reset(buf, opts);
}

static void format_bigint(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    const char* str = JS_ToCString(ctx, val);
    put_color(buf, opts, ANSI_YELLOW);
    dbuf_printf(buf, "%sn", str ? str : "0");
    put_reset(buf, opts);
    if (str) JS_FreeCString(ctx, str);
}

static void format_function(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    JSValue name = JS_GetPropertyStr(ctx, val, "name");
    const char* name_str = JS_IsString(name) ? JS_ToCString(ctx, name) : NULL;
    
    put_color(buf, opts, ANSI_CYAN);
    if (JS_IsConstructor(ctx, val)) {
        dbuf_printf(buf, "[class %s]", name_str && name_str[0] ? name_str : "anonymous");
    } else {
        dbuf_printf(buf, "[Function: %s]", name_str && name_str[0] ? name_str : "anonymous");
    }
    put_reset(buf, opts);
    
    if (name_str) JS_FreeCString(ctx, name_str);
    JS_FreeValue(ctx, name);
}

static void format_symbol(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    // Get description via Symbol.prototype.toString or description property
    JSValue desc = JS_GetPropertyStr(ctx, val, "description");
    const char* desc_str = JS_IsString(desc) ? JS_ToCString(ctx, desc) : NULL;
    
    put_color(buf, opts, ANSI_GREEN);
    dbuf_printf(buf, "Symbol(%s)", desc_str ? desc_str : "");
    put_reset(buf, opts);
    
    if (desc_str) JS_FreeCString(ctx, desc_str);
    JS_FreeValue(ctx, desc);
}

static void format_date(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {

	const char* str = JS_ToCString(ctx, val);
	put_color(buf, opts, ANSI_MAGENTA);
	dbuf_printf(buf, "%s", str ? str : "Invalid Date");
	put_reset(buf, opts);
	if (str) JS_FreeCString(ctx, str);
}

static void format_regexp(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    JSValue src = JS_GetPropertyStr(ctx, val, "source");
    JSValue flags = JS_GetPropertyStr(ctx, val, "flags");
    const char* src_str = JS_IsString(src) ? JS_ToCString(ctx, src) : NULL;
    const char* flags_str = JS_IsString(flags) ? JS_ToCString(ctx, flags) : NULL;
    
    put_color(buf, opts, ANSI_RED);
    dbuf_printf(buf, "/%s/%s", src_str ? src_str : "", flags_str ? flags_str : "");
    put_reset(buf, opts);
    
    if (src_str) JS_FreeCString(ctx, src_str);
    if (flags_str) JS_FreeCString(ctx, flags_str);
    JS_FreeValue(ctx, src);
    JS_FreeValue(ctx, flags);
}

static void format_error(JSContext* ctx, JSValue val, int depth, DynBuf* buf, 
                        const InspectOptions* opts) {
    JSValue name = JS_GetPropertyStr(ctx, val, "name");
    JSValue msg = JS_GetPropertyStr(ctx, val, "message");
    JSValue stack = JS_GetPropertyStr(ctx, val, "stack");
    
    const char* name_str = JS_IsString(name) ? JS_ToCString(ctx, name) : NULL;
    const char* msg_str = JS_IsString(msg) ? JS_ToCString(ctx, msg) : NULL;
    
    put_color(buf, opts, ANSI_RED);
    dbuf_printf(buf, "%s", name_str ? name_str : "Error");
    if (msg_str && msg_str[0]) dbuf_printf(buf, ": %s", msg_str);
    put_reset(buf, opts);
    
    if (JS_IsString(stack)) {
        const char* stack_str = JS_ToCString(ctx, stack);
        if (stack_str) {
            // Print stack with indentation
            const char* p = stack_str;
            while (*p) {
                const char* end = strchr(p, '\n');
                if (!end) end = p + strlen(p);
                dbuf_putc(buf, '\n');
                dbuf_putstr(buf, get_indent(depth + 1));
                dbuf_put(buf, p, end - p);
                if (*end == '\0') break;
                p = end + 1;
            }
            JS_FreeCString(ctx, stack_str);
        }
    }
    
    if (name_str) JS_FreeCString(ctx, name_str);
    if (msg_str) JS_FreeCString(ctx, msg_str);
    JS_FreeValue(ctx, name);
    JS_FreeValue(ctx, msg);
    JS_FreeValue(ctx, stack);
}

/* Estimate width for breakLength calculation - Fixed: no NULL stack access */
static int estimate_width(JSContext* ctx, JSValue val, int depth) {
    if (depth > 2) return 15;
    
    switch (JS_VALUE_GET_TAG(val)) {
		case JS_TAG_INT:
		case JS_TAG_FLOAT64: return 10;
		case JS_TAG_BOOL: return 5;
		case JS_TAG_NULL:
		case JS_TAG_UNDEFINED: return 9;
		case JS_TAG_STRING: {
			const char* s = JS_ToCString(ctx, val);
			int len = s ? (int)strlen(s) : 0;
			if (s) JS_FreeCString(ctx, s);
			return (len > 20 ? 20 : len) + 2;
		}
		case JS_TAG_OBJECT: {
			if (JS_IsFunction(ctx, val)) return 20;
			// Simple estimate for objects
			int64_t len = 0;
			JSValue len_val = JS_GetPropertyStr(ctx, val, "length");
			if (JS_IsNumber(len_val)) JS_ToInt64(ctx, &len, len_val);
			JS_FreeValue(ctx, len_val);
			
			if (len > 0 && len <= 4) return (int)len * 5 + 4;
			return 15;
		}
		default: return 10;
    }
}

static void format_array(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                        DynBuf* buf, const InspectOptions* opts) {
    int64_t len = 0;
    JSValue len_val = JS_GetPropertyStr(ctx, val, "length");
    if (!JS_IsException(len_val)) JS_ToInt64(ctx, &len, len_val);
    JS_FreeValue(ctx, len_val);

    if (is_circular(stack, val)) {
        put_color(buf, opts, ANSI_CYAN);
        dbuf_putstr(buf, "[Circular]");
        put_reset(buf, opts);
        return;
    }

    if (len == 0) {
        put_color(buf, opts, ANSI_CYAN);
        dbuf_putstr(buf, "[]");
        put_reset(buf, opts);
        return;
    }

    visit_push(stack, val);

    // Calculate estimated width
    int est_width = 2; // []
    uint32_t len_u32 = len;
    for (uint32_t i = 0; i < len_u32 && i < 6; i++) {
        JSValue elem = JS_GetPropertyUint32(ctx, val, i);
        est_width += estimate_width(ctx, elem, depth);
        JS_FreeValue(ctx, elem);
        if (i < len_u32 - 1) est_width += 2; // ", "
        if (est_width > opts->break_length) break;
    }
    bool inline_disp = opts->compact && est_width <= opts->break_length && len <= 6;

    put_color(buf, opts, ANSI_CYAN);
    dbuf_putstr(buf, "[");
    put_reset(buf, opts);

    int64_t show = len < opts->max_array_length ? len : opts->max_array_length;
    for (int64_t i = 0; i < show; i++) {
        if (i > 0) {
            dbuf_putstr(buf, inline_disp ? ", " : ",\n");
            if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        } else if (!inline_disp) {
            dbuf_putstr(buf, "\n");
            dbuf_putstr(buf, get_indent(depth + 1));
        }

        JSValue elem = JS_GetPropertyUint32(ctx, val, i);
        format_value(ctx, elem, depth + 1, stack, buf, true, opts);
        JS_FreeValue(ctx, elem);
    }

    if (len > show) {
        if (show > 0) {
            dbuf_putstr(buf, inline_disp ? ", " : ",\n");
            if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        }
        put_color(buf, opts, ANSI_GRAY);
        dbuf_printf(buf, "... %lld more items", (long long)(len - show));
        put_reset(buf, opts);
    }

    if (!inline_disp && len > 0) {
        dbuf_putstr(buf, "\n");
        dbuf_putstr(buf, get_indent(depth));
    }

    put_color(buf, opts, ANSI_CYAN);
    dbuf_putstr(buf, "]");
    put_reset(buf, opts);

    visit_pop(stack);
}

static void format_object(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                         DynBuf* buf, const InspectOptions* opts) {
    if (is_circular(stack, val)) {
        put_color(buf, opts, ANSI_CYAN);
        dbuf_putstr(buf, "[Circular]");
        put_reset(buf, opts);
        return;
    }

    visit_push(stack, val);

    // Get class name
    char* cls = get_class_name(ctx, val);
    if (cls) {
        put_color(buf, opts, ANSI_BOLD);
        dbuf_printf(buf, "%s ", cls);
        put_reset(buf, opts);
        js_free(ctx, cls);
    }

    // Get properties
    int flags = JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK;
    if (!opts->show_hidden) flags |= JS_GPN_ENUM_ONLY;

    JSPropertyEnum* props = NULL;
    uint32_t count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &count, val, flags) < 0) {
        dbuf_putstr(buf, "{ ... }");
        visit_pop(stack);
        return;
    }

    // Count valid props (exclude prototype)
    uint32_t valid = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (props[i].atom != JS_ATOM_prototype) valid++;
    }

    if (valid == 0) {
        dbuf_putstr(buf, "{}");
        JS_FreePropertyEnum(ctx, props, count);
        visit_pop(stack);
        return;
    }

    // Estimate width
    int est_width = 2; // {}
    for (uint32_t i = 0; i < count && i < 6; i++) {
        const char* k = JS_AtomToCString(ctx, props[i].atom);
        if (k) {
            est_width += (int)strlen(k) + 4;
            JS_FreeCString(ctx, k);
        }
        JSValue v = JS_GetProperty(ctx, val, props[i].atom);
        est_width += estimate_width(ctx, v, depth);
        JS_FreeValue(ctx, v);
        if (i < count - 1) est_width += 2;
        if (est_width > opts->break_length) break;
    }
    bool inline_disp = opts->compact && est_width <= opts->break_length && valid <= 4;

    dbuf_putstr(buf, inline_disp ? "{ " : "{\n");

    uint32_t shown = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (props[i].atom == JS_ATOM_prototype) continue;

        if (shown > 0) {
            dbuf_putstr(buf, inline_disp ? ", " : ",\n");
        }
        if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));

        // Key
        JSValue key_val = JS_AtomToValue(ctx, props[i].atom);
        if (JS_IsSymbol(key_val)) {
            dbuf_putstr(buf, "[");
            format_symbol(ctx, key_val, buf, opts);
            dbuf_putstr(buf, "]: ");
        } else {
            const char* k = JS_ToCString(ctx, key_val);
            bool need_quote = false;
            if (!k || !k[0]) {
                need_quote = true;
            } else {
                for (const char* p = k; *p; p++) {
                    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || 
                          (*p >= '0' && *p <= '9') || *p == '_' || *p == '$')) {
                        need_quote = true;
                        break;
                    }
                    if (p == k && (*p >= '0' && *p <= '9')) {
                        need_quote = true;
                        break;
                    }
                }
            }

            put_color(buf, opts, ANSI_GREEN);
            if (need_quote) dbuf_printf(buf, "'%s': ", k ? k : "");
            else dbuf_printf(buf, "%s: ", k ? k : "");
            put_reset(buf, opts);
            if (k) JS_FreeCString(ctx, k);
        }
        JS_FreeValue(ctx, key_val);

        // Value
        JSValue v = JS_GetProperty(ctx, val, props[i].atom);
        format_value(ctx, v, depth + 1, stack, buf, true, opts);
        JS_FreeValue(ctx, v);
        shown++;
    }

    if (!inline_disp && shown > 0) {
        dbuf_putstr(buf, "\n");
        dbuf_putstr(buf, get_indent(depth));
    } else if (inline_disp) {
        dbuf_putstr(buf, " ");
    }
    dbuf_putstr(buf, "}");

    JS_FreePropertyEnum(ctx, props, count);
    visit_pop(stack);
}

static void format_typed_array(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                              DynBuf* buf, const InspectOptions* opts) {
    const char* name = "TypedArray";
    switch (JS_GetTypedArrayType(val)) {
    case JS_TYPED_ARRAY_INT8: name = "Int8Array"; break;
    case JS_TYPED_ARRAY_UINT8: name = "Uint8Array"; break;
    case JS_TYPED_ARRAY_UINT8C: name = "Uint8ClampedArray"; break;
    case JS_TYPED_ARRAY_INT16: name = "Int16Array"; break;
    case JS_TYPED_ARRAY_UINT16: name = "Uint16Array"; break;
    case JS_TYPED_ARRAY_INT32: name = "Int32Array"; break;
    case JS_TYPED_ARRAY_UINT32: name = "Uint32Array"; break;
    case JS_TYPED_ARRAY_FLOAT32: name = "Float32Array"; break;
    case JS_TYPED_ARRAY_FLOAT64: name = "Float64Array"; break;
    case JS_TYPED_ARRAY_BIG_INT64: name = "BigInt64Array"; break;
    case JS_TYPED_ARRAY_BIG_UINT64: name = "BigUint64Array"; break;
    default: break;
    }

	size_t offset, len, per;
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, val, &offset, &len, &per);

    put_color(buf, opts, ANSI_MAGENTA);
    dbuf_printf(buf, "%s(%zu) [ ", name, len);
    put_reset(buf, opts);
    size_t show = MIN(len, opts->max_array_length);
    for (uint32_t i = 0; i < show; i++) {
        if (i > 0) dbuf_putstr(buf, ", ");
        JSValue elem = JS_GetPropertyUint32(ctx, val, i + offset);
        format_number(ctx, elem, buf, opts);
        JS_FreeValue(ctx, elem);
    }
    if (len > show) {
        put_color(buf, opts, ANSI_GRAY);
        dbuf_printf(buf, ", ... %zu more items", len - show);
        put_reset(buf, opts);
    }

    put_color(buf, opts, ANSI_MAGENTA);
    dbuf_putstr(buf, " ]");
    put_reset(buf, opts);

    JS_FreeValue(ctx, buffer);
}

static void format_array_buffer(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    size_t size = 0;
    uint8_t* data = JS_GetArrayBuffer(ctx, &size, val);

    put_color(buf, opts, ANSI_MAGENTA);
    dbuf_printf(buf, "ArrayBuffer(%zu) {", size);
    if (size > 0 && data) {
        size_t show = size < 32 ? size : 32;
        for (size_t i = 0; i < show; i++) {
            if (i > 0) dbuf_putc(buf, ' ');
            dbuf_printf(buf, "%02x", data[i]);
        }
        if (size > show) dbuf_printf(buf, " ... %zu more bytes", size - show);
    }
    dbuf_putstr(buf, " }");
    put_reset(buf, opts);
}

static void format_promise(JSContext* ctx, JSValue val, int depth, VisitStack* stack, DynBuf* buf, const InspectOptions* opts) {
    put_color(buf, opts, ANSI_CYAN);
	dbuf_printf(buf, "Promise<");

	if (JS_PromiseState(ctx, val) == JS_PROMISE_PENDING) {
		put_color(buf, opts, ANSI_GRAY);
		dbuf_printf(buf, "%s", "pending");
	} else {
		JSValue result = JS_PromiseResult(ctx, val);
		format_value(ctx, result, depth + 1, stack, buf, true, opts);
	}
	
	put_color(buf, opts, ANSI_CYAN);
	dbuf_putc(buf, '>');
		put_reset(buf, opts);
}

/* Main dispatch - Fixed: Symbol must be checked first in JS_TAG_OBJECT */
static void format_value(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                        DynBuf* buf, bool quoted, const InspectOptions* opts) {
    if (depth > opts->depth) {
        put_color(buf, opts, ANSI_GRAY);
        dbuf_putstr(buf, "[Object]");
        put_reset(buf, opts);
        return;
    }

    switch (JS_VALUE_GET_TAG(val)) {
		case JS_TAG_BIG_INT:
		case JS_TAG_SHORT_BIG_INT:
			format_bigint(ctx, val, buf, opts);
			break;
		case JS_TAG_UNDEFINED:
			put_color(buf, opts, ANSI_GRAY);
			dbuf_putstr(buf, "undefined");
			put_reset(buf, opts);
			break;
		case JS_TAG_BOOL:
			put_color(buf, opts, ANSI_YELLOW);
			dbuf_putstr(buf, JS_ToBool(ctx, val) ? "true" : "false");
			put_reset(buf, opts);
			break;
		case JS_TAG_NULL:
			put_color(buf, opts, ANSI_DIM);
			dbuf_putstr(buf, "null");
			put_reset(buf, opts);
			break;
		case JS_TAG_INT:
		case JS_TAG_FLOAT64:
			format_number(ctx, val, buf, opts);
			break;
		case JS_TAG_STRING:
			format_string(ctx, val, buf, quoted, opts);
			break;
		case JS_TAG_OBJECT:
			if (JS_IsPromise(val)) {
				format_promise(ctx, val, depth, stack, buf, opts);
			} else if (JS_IsDate(val)) {
				format_date(ctx, val, buf, opts);
			} else if (JS_IsRegExp(val)) {
				format_regexp(ctx, val, buf, opts);
			} else if (JS_IsFunction(ctx, val)) {
				format_function(ctx, val, buf, opts);
			} else if (JS_IsError(val)) {
				format_error(ctx, val, depth, buf, opts);
			} else if (JS_IsArrayBuffer(val)) {
				format_array_buffer(ctx, val, buf, opts);
			} else if (JS_GetTypedArrayType(val) != -1) {
				format_typed_array(ctx, val, depth, stack, buf, opts);
			} else if (JS_IsArray(val)) {
				format_array(ctx, val, depth, stack, buf, opts);
			} else {
				format_object(ctx, val, depth, stack, buf, opts);
			}
			break;
		case JS_TAG_EXCEPTION:
			put_color(buf, opts, ANSI_RED);
			dbuf_putstr(buf, "[Exception]");
			put_reset(buf, opts);
			break;
		case JS_TAG_SYMBOL:
			format_symbol(ctx, val, buf, opts);
			break;
		case JS_TAG_MODULE:
			put_color(buf, opts, ANSI_GRAY);
			JSAtom module_atom = JS_GetModuleName(ctx, JS_VALUE_GET_PTR(val));
			const char* module_name = JS_AtomToCString(ctx, module_atom);
			dbuf_printf(buf, "Module %s", module_name);
			JS_FreeCString(ctx, module_name);
			JS_FreeAtom(ctx, module_atom);
			put_reset(buf, opts);
		default:
			put_color(buf, opts, ANSI_RED);
			dbuf_printf(buf, "[Unknown:%d]", JS_VALUE_GET_TAG(val));
			put_reset(buf, opts);
			break;
    }

    // Clear any pending exception from property access
    JSValue exc = JS_GetException(ctx);
    if (!JS_IsUndefined(exc)) JS_FreeValue(ctx, exc);
}

/* Public APIs */
static JSValue js_console_inspect(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc == 0) return JS_NewString(ctx, "undefined");

    InspectOptions opts;
    parse_inspect_options(ctx, argc > 1 ? argv[1] : JS_UNDEFINED, &opts);

    VisitStack stack = {0};
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);

    format_value(ctx, argv[0], 0, &stack, &buf, false, &opts);

    JSValue ret = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
    dbuf_free(&buf);
    return ret;
}

static void console_log_internal(JSContext* ctx, int argc, JSValueConst* argv,
                                FILE* stream, int default_depth, bool show_hidden) {
    if (argc == 0) {
        fwrite2("\n", 1, 1, stream);
        return;
    }

    InspectOptions opts = {
        .depth = default_depth,
        .break_length = 80,
        .colors = isatty(_fileno(stream)),
        .show_hidden = show_hidden,
        .max_array_length = 100,
        .max_string_length = 10000,
        .compact = true
    };

    VisitStack stack = {0};
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);

    for (int i = 0; i < argc; i++) {
        if (i > 0) dbuf_putc(&buf, ' ');
        format_value(ctx, argv[i], 0, &stack, &buf, false, &opts);
    }

    dbuf_putc(&buf, '\n');
    fwrite2(buf.buf, 1, buf.size, stream);
    fflush(stream);
    dbuf_free(&buf);
}

static JSValue js_console_log(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    console_log_internal(ctx, argc, argv, stdout, 2, false);
    return JS_UNDEFINED;
}

static JSValue js_console_error(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
	fprintf2(stderr, ANSI_RED "error " ANSI_RESET);
    console_log_internal(ctx, argc, argv, stderr, 2, false);
    return JS_UNDEFINED;
}

static JSValue js_console_warn(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    fprintf2(stderr, ANSI_YELLOW "warn " ANSI_RESET);
	console_log_internal(ctx, argc, argv, stdout, 2, false);
    return JS_UNDEFINED;
}

static JSValue js_console_info(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    fprintf2(stdout, ANSI_CYAN "info " ANSI_RESET);
	console_log_internal(ctx, argc, argv, stdout, 2, false);
	return JS_UNDEFINED;
}

static JSValue js_console_debug(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (!getenv("DEBUG")) return JS_UNDEFINED;
    console_log_internal(ctx, argc, argv, stdout, 2, false);
	return JS_UNDEFINED;
}

static JSValue js_console_dir(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc == 0) return JS_UNDEFINED;
    
    InspectOptions opts;
    parse_inspect_options(ctx, argc > 1 ? argv[1] : JS_UNDEFINED, &opts);
    opts.depth = 100;
    opts.show_hidden = true;
    opts.compact = false;

    VisitStack stack = {0};
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);

    format_value(ctx, argv[0], 0, &stack, &buf, false, &opts);
    dbuf_putc(&buf, '\n');
    fwrite2(buf.buf, 1, buf.size, stdout);
    fflush(stdout);
    dbuf_free(&buf);
    return JS_UNDEFINED;
}

static JSValue js_console_clear(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    printf("\033[2J\033[H");
    fflush(stdout);
    return JS_UNDEFINED;
}

static JSValue js_console_trace(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    js_console_log(ctx, this_val, argc, argv);

	fprintf2(stderr, ANSI_MAGENTA "trace " ANSI_RESET);
    
    JSValue err = JS_NewError(ctx);
    JSValue stack = JS_GetPropertyStr(ctx, err, "stack");
    if (JS_IsString(stack)) {
        const char* s = JS_ToCString(ctx, stack);
        if (s) {
            printf("%s\n", s);
            JS_FreeCString(ctx, s);
        }
    }
    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, err);
    return JS_UNDEFINED;
}

static JSValue js_console_assert(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc == 0 || !JS_ToBool(ctx, argv[0])) {
        fprintf2(stderr, ANSI_RED "Assertion failed " ANSI_RESET);
        if (argc > 1) {
            fprintf2(stderr, ": ");
            InspectOptions opts = {0};
            opts.depth = 2;
            opts.colors = isatty(STDERR_FILENO);
            VisitStack stack = {0};
            DynBuf buf;
            dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
            for (int i = 1; i < argc; i++) {
                if (i > 1) dbuf_putc(&buf, ' ');
                format_value(ctx, argv[i], 0, &stack, &buf, false, &opts);
            }
            fwrite2(buf.buf, 1, buf.size, stderr);
            dbuf_free(&buf);
        }
        fwrite2("\n", 1, 1, stderr);
        fflush(stderr);
    }
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry console_funcs[] = {
    JS_CFUNC_DEF("log", 0, js_console_log),
    JS_CFUNC_DEF("error", 0, js_console_error),
    JS_CFUNC_DEF("warn", 0, js_console_warn),
    JS_CFUNC_DEF("info", 0, js_console_info),
    JS_CFUNC_DEF("debug", 0, js_console_debug),
    JS_CFUNC_DEF("dir", 1, js_console_dir),
    JS_CFUNC_DEF("trace", 0, js_console_trace),
    JS_CFUNC_DEF("clear", 0, js_console_clear),
    JS_CFUNC_DEF("assert", 1, js_console_assert),
    JS_CFUNC_DEF("inspect", 1, js_console_inspect),
};

void tjs__mod_console_init(JSContext* ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, console_funcs, countof(console_funcs));
}

// # C apis
static void tjs_dump_obj(JSContext *ctx, FILE *f, JSValue val) {
	VisitStack st;
	InspectOptions io = {0};
	DynBuf buf;

	dbuf_init(&buf);
	format_value(ctx, val, 0, &st, &buf, false, &io);
	fwrite(buf.buf, buf.size, 1, f);
	dbuf_free(&buf);
}

void tjs_dump_error(JSContext *ctx) {
    JSValue exception_val = JS_GetException(ctx);
    tjs_dump_error1(ctx, exception_val);
    JS_FreeValue(ctx, exception_val);
}

void tjs_dump_error1(JSContext *ctx, JSValue exception_val) {
    tjs_dump_obj(ctx, stderr, exception_val);
    fflush(stderr);
}