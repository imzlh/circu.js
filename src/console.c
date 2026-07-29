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

#define MAX_DEPTH 64
#define DEFAULT_BREAK_LENGTH 80
#define MAX_ARRAY_LENGTH 100
#define MAX_STRING_LENGTH 10000

// not defined in MSVC
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

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
static uv_once_t stdout_mutex_once = UV_ONCE_INIT;
static thread_local int console_group_indent = 0;

typedef struct ConsoleCounter {
    char* label;
    int count;
    struct ConsoleCounter* next;
} ConsoleCounter;

typedef struct ConsoleTimer {
    char* label;
    uint64_t start;
    struct ConsoleTimer* next;
} ConsoleTimer;

/* Per-thread: each worker runtime has its own console state; sharing these
 * across threads without locks would race. */
static thread_local ConsoleCounter* console_counters = NULL;
static thread_local ConsoleTimer* console_timers = NULL;

#define __mutex(op) do { uv_mutex_lock(&stdout_mutex); op; uv_mutex_unlock(&stdout_mutex); } while(0)
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
    JSValue tag = JS_GetProperty(ctx, obj, JS_ATOM_Symbol_toStringTag);
    if (!JS_IsException(tag) && JS_IsString(tag)) {
        const char* str = JS_ToCString(ctx, tag);
        JS_FreeValue(ctx, tag);
        if (str && str[0]) {
            char* dup = js_strdup(ctx, str);
            JS_FreeCString(ctx, str);
            return dup;
        }
        if (str) JS_FreeCString(ctx, str);
    }
    JS_FreeValue(ctx, tag);

    // Fallback to constructor.name
    JSValue ctor = JS_GetProperty(ctx, obj, JS_ATOM_constructor);
    if (JS_IsException(ctor) || JS_IsUndefined(ctor) || JS_IsNull(ctor)) {
        JS_FreeValue(ctx, ctor);
        return NULL;
    }

    JSValue name = JS_GetProperty(ctx, ctor, JS_ATOM_name);
    JS_FreeValue(ctx, ctor);
    
    if (JS_IsException(name) || !JS_IsString(name)) {
        JS_FreeValue(ctx, name);
        return NULL;
    }

    const char* str = JS_ToCString(ctx, name);
    JS_FreeValue(ctx, name);
    
    if (str && str[0] && strcmp(str, "Object") != 0) {
        char* dup = js_strdup(ctx, str);
        JS_FreeCString(ctx, str);
        return dup;
    }
    if (str) JS_FreeCString(ctx, str);
    return NULL;
}

/* Color helpers */
static inline void put_color(DynBuf* buf, const InspectOptions* opts, const char* color) {
    if (opts->colors) dbuf_putstr(buf, color);
}

static inline void put_reset(DynBuf* buf, const InspectOptions* opts) {
    if (opts->colors) dbuf_putstr(buf, ANSI_RESET);
}

static void put_group_indent(DynBuf* buf) {
    for (int i = 0; i < console_group_indent; i++) dbuf_putc(buf, ' ');
}

static void format_value_with_depth(JSContext* ctx, JSValueConst val, DynBuf* buf, int depth,
                                    bool quoted, FILE* stream) {
    InspectOptions opts = {
        .depth = depth,
        .break_length = DEFAULT_BREAK_LENGTH,
        .colors = stream && isatty(fileno(stream)),
        .show_hidden = false,
        .max_array_length = MAX_ARRAY_LENGTH,
        .max_string_length = MAX_STRING_LENGTH,
        .compact = true,
    };
    VisitStack stack = {0};
    format_value(ctx, val, 0, &stack, buf, quoted, &opts);
}

static void format_to_string(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    if (JS_IsSymbol(val)) {
        format_value_with_depth(ctx, val, buf, 2, false, NULL);
        return;
    }
    const char* str = JS_ToCString(ctx, val);
    dbuf_putstr(buf, str ? str : "");
    if (str) JS_FreeCString(ctx, str);
}

static void format_to_number(JSContext* ctx, JSValueConst val, DynBuf* buf, bool integer) {
    double num = 0;
    if (JS_VALUE_GET_TAG(val) == JS_TAG_BIG_INT || JS_VALUE_GET_TAG(val) == JS_TAG_SHORT_BIG_INT) {
        format_to_string(ctx, val, buf);
        return;
    }
    if (JS_ToFloat64(ctx, &num, val) < 0 || isnan(num)) {
        dbuf_putstr(buf, "NaN");
    } else if (integer) {
        double truncated = trunc(num);
        if (truncated == 0) truncated = 0;
        dbuf_printf(buf, "%.0f", truncated);
    } else if (isinf(num)) {
        dbuf_printf(buf, "%cInfinity", num < 0 ? '-' : '+');
    } else {
        dbuf_printf(buf, "%g", num);
    }
}

static void format_json(JSContext* ctx, JSValueConst val, DynBuf* buf) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue json = JS_GetPropertyStr(ctx, global, "JSON");
    JSValue stringify = JS_GetPropertyStr(ctx, json, "stringify");
    JSValue ret = JS_UNDEFINED;

    if (JS_IsFunction(ctx, stringify)) {
        JSValueConst args[1] = { val };
        ret = JS_Call(ctx, stringify, json, 1, args);
    }

    if (JS_IsException(ret)) {
        JSValue exc = JS_GetException(ctx);
        JS_FreeValue(ctx, exc);
        dbuf_putstr(buf, "[Circular]");
    } else if (JS_IsUndefined(ret)) {
        dbuf_putstr(buf, "undefined");
    } else {
        format_to_string(ctx, ret, buf);
    }

    JS_FreeValue(ctx, ret);
    JS_FreeValue(ctx, stringify);
    JS_FreeValue(ctx, json);
    JS_FreeValue(ctx, global);
}

static bool format_args_node(JSContext* ctx, int argc, JSValueConst* argv, DynBuf* buf, FILE* stream) {
    if (argc <= 0) return false;

    bool used_format = false;
    bool wrote = false;
    int consumed = 0;

    if (JS_IsString(argv[0])) {
        const char* fmt = JS_ToCString(ctx, argv[0]);
        if (!fmt) return false;

        DynBuf fmt_buf;
        dbuf_init2(&fmt_buf, JS_GetRuntime(ctx), console_realloc);

        for (const char* p = fmt; *p; p++) {
            if (*p != '%' || p[1] == '\0') {
                dbuf_putc(&fmt_buf, *p);
                continue;
            }

            char spec = p[1];
            if (spec == '%') {
                dbuf_putc(&fmt_buf, '%');
                p++;
                used_format = true;
                continue;
            }

            if (spec == 's' || spec == 'd' || spec == 'i' || spec == 'f' ||
                spec == 'j' || spec == 'o' || spec == 'O' || spec == 'c') {
                used_format = true;
                if (consumed + 1 >= argc) {
                    dbuf_putc(&fmt_buf, '%');
                    dbuf_putc(&fmt_buf, spec);
                    p++;
                    continue;
                }

                JSValueConst arg = argv[++consumed];
                switch (spec) {
                    case 's':
                        format_to_string(ctx, arg, &fmt_buf);
                        break;
                    case 'd':
                    case 'i':
                        format_to_number(ctx, arg, &fmt_buf, true);
                        break;
                    case 'f':
                        format_to_number(ctx, arg, &fmt_buf, false);
                        break;
                    case 'j':
                        format_json(ctx, arg, &fmt_buf);
                        break;
                    case 'o':
                        format_value_with_depth(ctx, arg, &fmt_buf, 4, false, stream);
                        break;
                    case 'O':
                        format_value_with_depth(ctx, arg, &fmt_buf, 100, false, stream);
                        break;
                    case 'c':
                        /* Node ignores CSS in non-browser terminals. */
                        break;
                }
                p++;
                continue;
            }

            dbuf_putc(&fmt_buf, *p);
        }

        if (used_format) {
            dbuf_put(buf, fmt_buf.buf, fmt_buf.size);
            wrote = fmt_buf.size > 0;
        }

        dbuf_free(&fmt_buf);
        JS_FreeCString(ctx, fmt);
    }

    int start = used_format ? consumed + 1 : 0;
    for (int i = start; i < argc; i++) {
        if (wrote) dbuf_putc(buf, ' ');
        if (JS_IsString(argv[i])) format_to_string(ctx, argv[i], buf);
        else format_value_with_depth(ctx, argv[i], buf, 3, false, stream);
        wrote = true;
    }
    return true;
}

static void console_write_args(JSContext* ctx, int argc, JSValueConst* argv, FILE* stream) {
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    put_group_indent(&buf);
    format_args_node(ctx, argc, argv, &buf, stream);
    dbuf_putc(&buf, '\n');
    fwrite2(buf.buf, 1, buf.size, stream);
    fflush(stream);
    dbuf_free(&buf);
}

static char* console_label(JSContext* ctx, JSValueConst val, const char* fallback) {
    if (JS_IsUndefined(val)) return js_strdup(ctx, fallback);
    const char* str = JS_ToCString(ctx, val);
    char* label = js_strdup(ctx, str ? str : fallback);
    if (str) JS_FreeCString(ctx, str);
    return label;
}

static ConsoleCounter* find_counter(const char* label) {
    for (ConsoleCounter* c = console_counters; c; c = c->next)
        if (strcmp(c->label, label) == 0) return c;
    return NULL;
}

static ConsoleTimer* find_timer(const char* label) {
    for (ConsoleTimer* t = console_timers; t; t = t->next)
        if (strcmp(t->label, label) == 0) return t;
    return NULL;
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

static void format_function(JSContext* ctx, JSValue val, VisitStack* stack, DynBuf* buf, const InspectOptions* opts) {
    JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
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

    /* Show own enumerable properties attached to the function */
    JSPropertyEnum* props = NULL;
    uint32_t count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &count, val,
                               JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
        uint32_t extra = 0;
        for (uint32_t i = 0; i < count; i++) {
            const char* k = JS_AtomToCString(ctx, props[i].atom);
            bool skip = k && (strcmp(k, "length") == 0 || strcmp(k, "name") == 0 ||
                              strcmp(k, "prototype") == 0 || strcmp(k, "arguments") == 0 ||
                              strcmp(k, "caller") == 0);
            if (k) JS_FreeCString(ctx, k);
            if (!skip) extra++;
        }
        if (extra > 0) {
            dbuf_putstr(buf, " {");
            uint32_t shown = 0;
            for (uint32_t i = 0; i < count; i++) {
                const char* k = JS_AtomToCString(ctx, props[i].atom);
                bool skip = k && (strcmp(k, "length") == 0 || strcmp(k, "name") == 0 ||
                                  strcmp(k, "prototype") == 0 || strcmp(k, "arguments") == 0 ||
                                  strcmp(k, "caller") == 0);
                if (skip) { if (k) JS_FreeCString(ctx, k); continue; }
                dbuf_putstr(buf, shown == 0 ? " " : ", ");
                put_color(buf, opts, ANSI_GREEN);
                dbuf_printf(buf, "%s", k ? k : "");
                put_reset(buf, opts);
                dbuf_putstr(buf, ": ");
                if (k) JS_FreeCString(ctx, k);
                JSValue v = JS_GetProperty(ctx, val, props[i].atom);
                if (JS_IsException(v)) {
                    JSValue exc = JS_GetException(ctx); JS_FreeValue(ctx, exc);
                    shown++;
                    dbuf_putstr(buf, "[Exception]");
                    continue;
                }
                format_value(ctx, v, 1, stack, buf, true, opts);
                JS_FreeValue(ctx, v);
                shown++;
            }
            dbuf_putstr(buf, " }");
        }
        JS_FreePropertyEnum(ctx, props, count);
    }
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
    JSValue src = JS_GetProperty(ctx, val, JS_ATOM_source);
    JSValue flags = JS_GetProperty(ctx, val, JS_ATOM_flags);
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
    JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
    JSValue msg = JS_GetProperty(ctx, val, JS_ATOM_message);
    JSValue stack = JS_GetProperty(ctx, val, JS_ATOM_stack);

    const char* name_str = JS_IsString(name) ? JS_ToCString(ctx, name) : NULL;
    const char* msg_str = JS_IsString(msg) ? JS_ToCString(ctx, msg) : NULL;

    put_color(buf, opts, ANSI_RED);
    dbuf_printf(buf, "%s", name_str ? name_str : "Error");
    if (msg_str && msg_str[0]) dbuf_printf(buf, ": %s", msg_str);
    put_reset(buf, opts);

    /* Show extra own enumerable properties (e.g. err.code, err.errno) */
    JSPropertyEnum* props = NULL;
    uint32_t count = 0;
    if (JS_GetOwnPropertyNames(ctx, &props, &count, val,
                               JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
        uint32_t extra = 0;
        for (uint32_t i = 0; i < count; i++) {
            const char* k = JS_AtomToCString(ctx, props[i].atom);
            bool skip = k && (strcmp(k, "name") == 0 || strcmp(k, "message") == 0 ||
                              strcmp(k, "stack") == 0);
            if (k) JS_FreeCString(ctx, k);
            if (!skip) extra++;
        }
        if (extra > 0) {
            dbuf_putstr(buf, " {");
            uint32_t shown = 0;
            for (uint32_t i = 0; i < count; i++) {
                const char* k = JS_AtomToCString(ctx, props[i].atom);
                bool skip = k && (strcmp(k, "name") == 0 || strcmp(k, "message") == 0 ||
                                  strcmp(k, "stack") == 0);
                if (skip) { if (k) JS_FreeCString(ctx, k); continue; }
                if (shown > 0) dbuf_putstr(buf, ", ");
                else dbuf_putstr(buf, " ");
                put_color(buf, opts, ANSI_GREEN);
                dbuf_printf(buf, "%s", k ? k : "");
                put_reset(buf, opts);
                dbuf_putstr(buf, ": ");
                if (k) JS_FreeCString(ctx, k);
                JSValue v = JS_GetProperty(ctx, val, props[i].atom);
                if (JS_IsException(v)) {
                    JSValue exc = JS_GetException(ctx); JS_FreeValue(ctx, exc);
                    shown++;
                    dbuf_putstr(buf, "[Exception]");
                    continue;
                }
                VisitStack err_stack = {0};
                format_value(ctx, v, depth + 1, &err_stack, buf, true, opts);
                JS_FreeValue(ctx, v);
                shown++;
            }
            dbuf_putstr(buf, " }");
        }
        JS_FreePropertyEnum(ctx, props, count);
    }

    if (JS_IsString(stack)) {
        const char* stack_str = JS_ToCString(ctx, stack);
        if (stack_str && stack_str[0]) {
            const char* p = stack_str;
            while (*p) {
                const char* end = strchr(p, '\n');
                if (!end) end = p + strlen(p);
                dbuf_putc(buf, '\n');
                dbuf_putstr(buf, get_indent(depth + 1));
                dbuf_put(buf, p, end - p);
                if (*end == '\0') {
                    dbuf_putc(buf, '\n');
                    break;
                }
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
        case JS_TAG_SHORT_BIG_INT:
        case JS_TAG_BIG_INT:
		case JS_TAG_FLOAT64: return 10;
		case JS_TAG_BOOL: return 5;
		case JS_TAG_NULL:
		case JS_TAG_UNDEFINED: return 9;
		case JS_TAG_STRING:
        case JS_TAG_STRING_ROPE: {
			const char* s = JS_ToCString(ctx, val);
			int len = s ? (int)strlen(s) : 0;
			if (s) JS_FreeCString(ctx, s);
			return (len > 20 ? 20 : len) + 2;
		}
		case JS_TAG_OBJECT: {
			if (JS_IsFunction(ctx, val)) return 20;
			// Simple estimate for objects
			int64_t len = 0;
			JS_GetLength(ctx, val, &len);
			
			if (len > 0 && len <= 4) return (int)len * 5 + 4;
			return 15;
		}
		default: return 10;
    }
}

static void format_array(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                        DynBuf* buf, const InspectOptions* opts) {
    int64_t len = 0;
    JSValue len_val = JS_GetProperty(ctx, val, JS_ATOM_length);
    if (!JS_IsException(len_val)) JS_ToInt64(ctx, &len, len_val);
    JS_FreeValue(ctx, len_val);

    if (is_circular(stack, val)) {
        put_color(buf, opts, ANSI_CYAN);
        dbuf_putstr(buf, "[Circular]");
        put_reset(buf, opts);
        return;
    }

    if (len == 0 && !opts->show_hidden) {
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
    if (inline_disp && opts->show_hidden) dbuf_putstr(buf, " ");

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

    bool has_hidden_length = opts->show_hidden;

    if (len > show) {
        if (show > 0) {
            dbuf_putstr(buf, inline_disp ? ", " : ",\n");
            if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        }
        put_color(buf, opts, ANSI_GRAY);
        dbuf_printf(buf, "... %lld more items", (long long)(len - show));
        put_reset(buf, opts);
    }

    if (has_hidden_length) {
        if (show > 0 || len > show) {
            dbuf_putstr(buf, inline_disp ? ", " : ",\n");
            if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        }
        put_color(buf, opts, ANSI_GRAY);
        dbuf_printf(buf, "[length]: %lld", (long long)len);
        put_reset(buf, opts);
    }

    if (!inline_disp && (len > 0 || has_hidden_length)) {
        dbuf_putstr(buf, "\n");
        dbuf_putstr(buf, get_indent(depth));
    }

    put_color(buf, opts, ANSI_CYAN);
    if (inline_disp && opts->show_hidden) dbuf_putstr(buf, " ");
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
        JS_FreePropertyEnum(ctx, props, count);

        /* No own enumerable props: fall back to prototype getters (e.g. TS class with only get accessors).
         * Only one level up — avoids showing every Object.prototype method. */
        JSValue proto = JS_GetPrototype(ctx, val);
        if (!JS_IsNull(proto) && !JS_IsException(proto)) {
            JSPropertyEnum* pprops = NULL;
            uint32_t pcount = 0;
            if (JS_GetOwnPropertyNames(ctx, &pprops, &pcount, proto, JS_GPN_STRING_MASK) == 0) {
                uint32_t gshown = 0;
                for (uint32_t i = 0; i < pcount; i++) {
                    const char* k = JS_AtomToCString(ctx, pprops[i].atom);
                    if (!k || strcmp(k, "constructor") == 0) { if (k) JS_FreeCString(ctx, k); continue; }

                    JSPropertyDescriptor desc;
                    int res = JS_GetOwnProperty(ctx, &desc, proto, pprops[i].atom);
                    if (res <= 0) {
                        JS_FreeCString(ctx, k);
                        if (res < 0) { JSValue exc = JS_GetException(ctx); JS_FreeValue(ctx, exc); }
                        continue;
                    }

                    if (desc.flags & JS_PROP_GETSET) {
                        /* Free both unconditionally — QuickJS sets unused half to JS_UNDEFINED */
                        JSValue getter = desc.getter;
                        JSValue setter = desc.setter;
                        if (!JS_IsUndefined(getter) && !JS_IsException(getter)) {
                            JSValue result = JS_Call(ctx, getter, val, 0, NULL);
                            if (JS_IsException(result)) {
                                JSValue exc = JS_GetException(ctx);
                                JS_FreeValue(ctx, exc);
                            } else if (!JS_IsFunction(ctx, result)) {
                                if (gshown == 0) dbuf_putstr(buf, "{\n");
                                else dbuf_putstr(buf, ",\n");
                                dbuf_putstr(buf, get_indent(depth + 1));
                                put_color(buf, opts, ANSI_GREEN);
                                dbuf_printf(buf, "%s", k);
                                put_reset(buf, opts);
                                dbuf_putstr(buf, ": ");
                                format_value(ctx, result, depth + 1, stack, buf, true, opts);
                                gshown++;
                            }
                            JS_FreeValue(ctx, result);
                        }
                        JS_FreeValue(ctx, getter);
                        JS_FreeValue(ctx, setter);
                    } else {
                        /* JS_PROP_NORMAL: desc.value is set, getter/setter are NOT initialized */
                        JS_FreeValue(ctx, desc.value);
                    }
                    JS_FreeCString(ctx, k);
                }
                JS_FreePropertyEnum(ctx, pprops, pcount);

                if (gshown > 0) {
                    dbuf_putstr(buf, "\n");
                    dbuf_putstr(buf, get_indent(depth));
                    dbuf_putstr(buf, "}");
                    JS_FreeValue(ctx, proto);
                    visit_pop(stack);
                    return;
                }
            }
        }
        JS_FreeValue(ctx, proto);

        dbuf_putstr(buf, "{}");
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

	size_t offset = 0, len = 0, per = 0;
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, val, &offset, &len, &per);
    if (JS_IsException(buffer)) {
        /* Detached buffer — fall back to generic object display */
        put_color(buf, opts, ANSI_MAGENTA);
        dbuf_printf(buf, "%s(%zu) [ <detached> ]", name, len);
        put_reset(buf, opts);
        JS_FreeValue(ctx, buffer);
        return;
    }

    put_color(buf, opts, ANSI_MAGENTA);
    dbuf_printf(buf, "%s(%zu) [ ", name, len);
    put_reset(buf, opts);
    size_t show = MIN(len, opts->max_array_length);
    for (size_t i = 0; i < show; i++) {
        if (i > 0) dbuf_putstr(buf, ", ");
        JSValue elem = JS_GetPropertyUint32(ctx, val, (uint32_t)i);
        format_value(ctx, elem, depth + 1, stack, buf, false, opts);
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

static void format_dataview(JSContext* ctx, JSValue val, DynBuf* buf, const InspectOptions* opts) {
    JSValue buffer = JS_GetPropertyStr(ctx, val, "buffer");
    size_t size = 0;
    uint8_t* data = NULL;
    if (!JS_IsException(buffer) && JS_IsArrayBuffer(buffer)) {
        data = JS_GetArrayBuffer(ctx, &size, buffer);
    }
    JS_FreeValue(ctx, buffer);

    put_color(buf, opts, ANSI_MAGENTA);
    dbuf_printf(buf, "DataView(%zu) {", size);
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

static void format_map(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                       DynBuf* buf, const InspectOptions* opts) {
    JSValue size_val = JS_GetPropertyStr(ctx, val, "size");
    int32_t size = 0;
    if (!JS_IsException(size_val)) JS_ToInt32(ctx, &size, size_val);
    JS_FreeValue(ctx, size_val);

    put_color(buf, opts, ANSI_CYAN);
    dbuf_printf(buf, "Map(%d) ", size);
    put_reset(buf, opts);

    if (is_circular(stack, val)) {
        put_color(buf, opts, ANSI_CYAN);
        dbuf_putstr(buf, "[Circular]");
        put_reset(buf, opts);
        return;
    }
    if (size == 0) { dbuf_putstr(buf, "{}"); return; }

    visit_push(stack, val);

    JSValue entries_fn = JS_GetPropertyStr(ctx, val, "entries");
    JSValue iterator = JS_Call(ctx, entries_fn, val, 0, NULL);
    JS_FreeValue(ctx, entries_fn);
    if (JS_IsException(iterator)) {
        JS_FreeValue(ctx, iterator);
        visit_pop(stack);
        dbuf_putstr(buf, "{ ... }");
        return;
    }

    JSValue next_fn = JS_GetPropertyStr(ctx, iterator, "next");
    int32_t max_show = size < opts->max_array_length ? size : opts->max_array_length;
    bool inline_disp = opts->compact && size <= 4;
    dbuf_putstr(buf, inline_disp ? "{ " : "{\n");

    int shown = 0;
    while (shown < max_show) {
        JSValue step = JS_Call(ctx, next_fn, iterator, 0, NULL);
        if (JS_IsException(step)) { JS_FreeValue(ctx, step); break; }
        JSValue done_val = JS_GetPropertyStr(ctx, step, "done");
        bool done = JS_ToBool(ctx, done_val);
        JS_FreeValue(ctx, done_val);
        if (done) { JS_FreeValue(ctx, step); break; }

        JSValue entry = JS_GetPropertyStr(ctx, step, "value");
        JS_FreeValue(ctx, step);
        JSValue key   = JS_GetPropertyUint32(ctx, entry, 0);
        JSValue value = JS_GetPropertyUint32(ctx, entry, 1);
        JS_FreeValue(ctx, entry);

        if (shown > 0) dbuf_putstr(buf, inline_disp ? ", " : ",\n");
        if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        format_value(ctx, key,   depth + 1, stack, buf, true, opts);
        dbuf_putstr(buf, " => ");
        format_value(ctx, value, depth + 1, stack, buf, true, opts);
        JS_FreeValue(ctx, key);
        JS_FreeValue(ctx, value);
        shown++;
    }

    JS_FreeValue(ctx, next_fn);
    JS_FreeValue(ctx, iterator);

    if (size > max_show) {
        dbuf_putstr(buf, inline_disp ? ", " : ",\n");
        if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        put_color(buf, opts, ANSI_GRAY);
        dbuf_printf(buf, "... %d more items", size - max_show);
        put_reset(buf, opts);
    }
    if (!inline_disp) { dbuf_putstr(buf, "\n"); dbuf_putstr(buf, get_indent(depth)); }
    else dbuf_putstr(buf, " ");
    dbuf_putstr(buf, "}");
    visit_pop(stack);
}

static void format_set(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                       DynBuf* buf, const InspectOptions* opts) {
    JSValue size_val = JS_GetPropertyStr(ctx, val, "size");
    int32_t size = 0;
    if (!JS_IsException(size_val)) JS_ToInt32(ctx, &size, size_val);
    JS_FreeValue(ctx, size_val);

    put_color(buf, opts, ANSI_CYAN);
    dbuf_printf(buf, "Set(%d) ", size);
    put_reset(buf, opts);

    if (is_circular(stack, val)) {
        put_color(buf, opts, ANSI_CYAN);
        dbuf_putstr(buf, "[Circular]");
        put_reset(buf, opts);
        return;
    }
    if (size == 0) { dbuf_putstr(buf, "{}"); return; }

    visit_push(stack, val);

    JSValue values_fn = JS_GetPropertyStr(ctx, val, "values");
    JSValue iterator  = JS_Call(ctx, values_fn, val, 0, NULL);
    JS_FreeValue(ctx, values_fn);
    if (JS_IsException(iterator)) {
        JS_FreeValue(ctx, iterator);
        visit_pop(stack);
        dbuf_putstr(buf, "{ ... }");
        return;
    }

    JSValue next_fn = JS_GetPropertyStr(ctx, iterator, "next");
    int32_t max_show = size < opts->max_array_length ? size : opts->max_array_length;
    bool inline_disp = opts->compact && size <= 4;
    dbuf_putstr(buf, inline_disp ? "{ " : "{\n");

    int shown = 0;
    while (shown < max_show) {
        JSValue step = JS_Call(ctx, next_fn, iterator, 0, NULL);
        if (JS_IsException(step)) { JS_FreeValue(ctx, step); break; }
        JSValue done_val = JS_GetPropertyStr(ctx, step, "done");
        bool done = JS_ToBool(ctx, done_val);
        JS_FreeValue(ctx, done_val);
        if (done) { JS_FreeValue(ctx, step); break; }

        JSValue item = JS_GetPropertyStr(ctx, step, "value");
        JS_FreeValue(ctx, step);
        if (shown > 0) dbuf_putstr(buf, inline_disp ? ", " : ",\n");
        if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        format_value(ctx, item, depth + 1, stack, buf, true, opts);
        JS_FreeValue(ctx, item);
        shown++;
    }

    JS_FreeValue(ctx, next_fn);
    JS_FreeValue(ctx, iterator);

    if (size > max_show) {
        dbuf_putstr(buf, inline_disp ? ", " : ",\n");
        if (!inline_disp) dbuf_putstr(buf, get_indent(depth + 1));
        put_color(buf, opts, ANSI_GRAY);
        dbuf_printf(buf, "... %d more items", size - max_show);
        put_reset(buf, opts);
    }
    if (!inline_disp) { dbuf_putstr(buf, "\n"); dbuf_putstr(buf, get_indent(depth)); }
    else dbuf_putstr(buf, " ");
    dbuf_putstr(buf, "}");
    visit_pop(stack);
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
		JS_FreeValue(ctx, result);
	}

	put_color(buf, opts, ANSI_CYAN);
	dbuf_putc(buf, '>');
		put_reset(buf, opts);
}

/* Main dispatch */
static void format_value(JSContext* ctx, JSValue val, int depth, VisitStack* stack,
                        DynBuf* buf, bool quoted, const InspectOptions* opts) {
    if (depth > opts->depth && JS_VALUE_GET_TAG(val) == JS_TAG_OBJECT) {
        /* Primitives (string, number, bool, null, undefined, symbol, bigint) always
         * pass through regardless of depth — only objects are collapsed. */
        put_color(buf, opts, ANSI_GRAY);
        if (JS_IsArray(val)) {
            int64_t alen = 0;
            JSValue lv = JS_GetProperty(ctx, val, JS_ATOM_length);
            if (!JS_IsException(lv)) JS_ToInt64(ctx, &alen, lv);
            JS_FreeValue(ctx, lv);
            dbuf_printf(buf, "[Array(%lld)]", (long long)alen);
        } else if (JS_IsFunction(ctx, val)) {
            JSValue nm = JS_GetProperty(ctx, val, JS_ATOM_name);
            const char* ns = JS_IsString(nm) ? JS_ToCString(ctx, nm) : NULL;
            if (ns && ns[0]) dbuf_printf(buf, "[Function: %s]", ns);
            else              dbuf_putstr(buf, "[Function]");
            if (ns) JS_FreeCString(ctx, ns);
            JS_FreeValue(ctx, nm);
        } else {
            /* Map / Set / named class — give a hint */
            JSValue tag = JS_GetProperty(ctx, val, JS_ATOM_Symbol_toStringTag);
            const char* ts = JS_IsString(tag) ? JS_ToCString(ctx, tag) : NULL;
            if (ts && strcmp(ts, "Map") == 0) {
                JSValue sv = JS_GetPropertyStr(ctx, val, "size");
                int32_t sz = 0;
                if (!JS_IsException(sv)) JS_ToInt32(ctx, &sz, sv);
                JS_FreeValue(ctx, sv);
                dbuf_printf(buf, "[Map(%d)]", sz);
            } else if (ts && strcmp(ts, "Set") == 0) {
                JSValue sv = JS_GetPropertyStr(ctx, val, "size");
                int32_t sz = 0;
                if (!JS_IsException(sv)) JS_ToInt32(ctx, &sz, sv);
                JS_FreeValue(ctx, sv);
                dbuf_printf(buf, "[Set(%d)]", sz);
            } else {
                char* cls = get_class_name(ctx, val);
                if (cls) { dbuf_printf(buf, "[%s]", cls); js_free(ctx, cls); }
                else        dbuf_putstr(buf, "[Object]");
            }
            if (ts) JS_FreeCString(ctx, ts);
            JS_FreeValue(ctx, tag);
        }
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
        case JS_TAG_STRING_ROPE:
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
				format_function(ctx, val, stack, buf, opts);
			} else if (JS_IsError(val)) {
				format_error(ctx, val, depth, buf, opts);
			} else if (JS_IsArrayBuffer(val)) {
				format_array_buffer(ctx, val, buf, opts);
			} else if (JS_IsDataView(val)) {
				format_dataview(ctx, val, buf, opts);
			} else if (JS_GetTypedArrayType(val) != -1) {
				format_typed_array(ctx, val, depth, stack, buf, opts);
			} else if (JS_IsArray(val)) {
				format_array(ctx, val, depth, stack, buf, opts);
			} else {
				/* Detect Map/Set via Symbol.toStringTag before generic object path */
				JSValue tag = JS_GetProperty(ctx, val, JS_ATOM_Symbol_toStringTag);
				const char* tag_str = JS_IsString(tag) ? JS_ToCString(ctx, tag) : NULL;
				bool handled = false;
				if (tag_str && strcmp(tag_str, "Map") == 0) {
					format_map(ctx, val, depth, stack, buf, opts);
					handled = true;
				} else if (tag_str && strcmp(tag_str, "Set") == 0) {
					format_set(ctx, val, depth, stack, buf, opts);
					handled = true;
				}
				if (tag_str) JS_FreeCString(ctx, tag_str);
				JS_FreeValue(ctx, tag);
				if (!handled) format_object(ctx, val, depth, stack, buf, opts);
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
		case JS_TAG_MODULE: {
			put_color(buf, opts, ANSI_GRAY);
			JSAtom module_atom = JS_GetModuleName(ctx, JS_VALUE_GET_PTR(val));
			const char* module_name = JS_AtomToCString(ctx, module_atom);
			dbuf_printf(buf, "Module %s", module_name);
			JS_FreeCString(ctx, module_name);
			JS_FreeAtom(ctx, module_atom);
			put_reset(buf, opts);
			break;
		}
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

static JSValue js_console_format(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc == 0) return JS_NewString(ctx, "undefined");
    
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);

    if (!format_args_node(ctx, argc, argv, &buf, NULL)) {
        dbuf_free(&buf);
        return JS_ThrowPlainError(ctx, "Failed to format arguments");
    }

    JSValue ret = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
    dbuf_free(&buf);
    return ret;
}

static void console_log_internal(JSContext* ctx, int argc, JSValueConst* argv,
                                FILE* stream, int default_depth, bool show_hidden) {
    (void)default_depth;
    (void)show_hidden;
    console_write_args(ctx, argc, argv, stream);
}

static JSValue js_console_log(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    console_log_internal(ctx, argc, argv, stdout, 2, false);
    return JS_UNDEFINED;
}

static JSValue js_console_error(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    console_log_internal(ctx, argc, argv, stderr, 2, false);
    return JS_UNDEFINED;
}

static JSValue js_console_warn(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
	console_log_internal(ctx, argc, argv, stderr, 2, false);
    return JS_UNDEFINED;
}

static JSValue js_console_info(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
	console_log_internal(ctx, argc, argv, stdout, 2, false);
	return JS_UNDEFINED;
}

static JSValue js_console_debug(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
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
    if (argc > 0) console_log_internal(ctx, argc, argv, stderr, 2, false);
    else console_log_internal(ctx, 0, argv, stderr, 2, false);
    
    JSValue err = JS_NewError(ctx);
    JSValue stack = JS_GetProperty(ctx, err, JS_ATOM_stack);
    if (JS_IsString(stack)) {
        const char* s = JS_ToCString(ctx, stack);
        if (s) {
            fprintf2(stderr, "Trace\n%s\n", s);
            JS_FreeCString(ctx, s);
        }
    }
    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, err);
    return JS_UNDEFINED;
}

static JSValue js_console_assert(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc == 0 || !JS_ToBool(ctx, argv[0])) {
        DynBuf buf;
        dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
        dbuf_putstr(&buf, "Assertion failed");
        if (argc > 1) {
            DynBuf msg;
            dbuf_init2(&msg, JS_GetRuntime(ctx), console_realloc);
            format_args_node(ctx, argc - 1, argv + 1, &msg, stderr);
            if (msg.size > 0) {
                dbuf_putstr(&buf, ": ");
                dbuf_put(&buf, msg.buf, msg.size);
            }
            dbuf_free(&msg);
        }
        dbuf_putc(&buf, '\n');
        fwrite2(buf.buf, 1, buf.size, stderr);
        fflush(stderr);
        dbuf_free(&buf);
    }
    return JS_UNDEFINED;
}

static JSValue js_console_count(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    char* label = console_label(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, "default");
    ConsoleCounter* counter = find_counter(label);
    if (!counter) {
        counter = js_mallocz(ctx, sizeof(*counter));
        if (!counter) {
            js_free(ctx, label);
            return JS_EXCEPTION;
        }
        counter->label = label;
        counter->next = console_counters;
        console_counters = counter;
    } else {
        js_free(ctx, label);
    }
    counter->count++;

    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    dbuf_printf(&buf, "%s: %d", counter->label, counter->count);
    JSValue msg = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
    dbuf_free(&buf);
    JSValueConst args[1] = { msg };
    console_log_internal(ctx, 1, args, stdout, 2, false);
    JS_FreeValue(ctx, msg);
    return JS_UNDEFINED;
}

static JSValue js_console_count_reset(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    char* label = console_label(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, "default");
    ConsoleCounter* prev = NULL;
    ConsoleCounter* cur = console_counters;
    while (cur) {
        if (strcmp(cur->label, label) == 0) {
            if (prev) prev->next = cur->next;
            else console_counters = cur->next;
            js_free(ctx, cur->label);
            js_free(ctx, cur);
            js_free(ctx, label);
            return JS_UNDEFINED;
        }
        prev = cur;
        cur = cur->next;
    }
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    dbuf_printf(&buf, "Count for '%s' does not exist", label);
    JSValue msg = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
    dbuf_free(&buf);
    JSValueConst args[1] = { msg };
    console_log_internal(ctx, 1, args, stderr, 2, false);
    JS_FreeValue(ctx, msg);
    js_free(ctx, label);
    return JS_UNDEFINED;
}

static JSValue js_console_time(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    char* label = console_label(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, "default");
    ConsoleTimer* timer = find_timer(label);
    if (!timer) {
        timer = js_mallocz(ctx, sizeof(*timer));
        if (!timer) {
            js_free(ctx, label);
            return JS_EXCEPTION;
        }
        timer->label = label;
        timer->next = console_timers;
        console_timers = timer;
    } else {
        js_free(ctx, label);
    }
    timer->start = uv_hrtime();
    return JS_UNDEFINED;
}

static void console_time_log(JSContext* ctx, ConsoleTimer* timer, int argc, JSValueConst* argv, bool remove_timer) {
    double ms = (double)(uv_hrtime() - timer->start) / 1000000.0;
    DynBuf buf;
    dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
    dbuf_printf(&buf, "%s: %.3fms", timer->label, ms);

    if (argc > 1) {
        DynBuf extra;
        dbuf_init2(&extra, JS_GetRuntime(ctx), console_realloc);
        format_args_node(ctx, argc - 1, argv + 1, &extra, stdout);
        if (extra.size > 0) {
            dbuf_putc(&buf, ' ');
            dbuf_put(&buf, extra.buf, extra.size);
        }
        dbuf_free(&extra);
    }

    JSValue msg = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
    dbuf_free(&buf);
    JSValueConst args[1] = { msg };
    console_log_internal(ctx, 1, args, stdout, 2, false);
    JS_FreeValue(ctx, msg);

    if (remove_timer) {
        ConsoleTimer* prev = NULL;
        ConsoleTimer* cur = console_timers;
        while (cur) {
            if (cur == timer) {
                if (prev) prev->next = cur->next;
                else console_timers = cur->next;
                js_free(ctx, cur->label);
                js_free(ctx, cur);
                break;
            }
            prev = cur;
            cur = cur->next;
        }
    }
}

static JSValue js_console_time_log(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    char* label = console_label(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, "default");
    ConsoleTimer* timer = find_timer(label);
    if (!timer) {
        DynBuf buf;
        dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
        dbuf_printf(&buf, "Timer '%s' does not exist", label);
        JSValue msg = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
        dbuf_free(&buf);
        JSValueConst args[1] = { msg };
        console_log_internal(ctx, 1, args, stderr, 2, false);
        JS_FreeValue(ctx, msg);
        js_free(ctx, label);
        return JS_UNDEFINED;
    }
    js_free(ctx, label);
    console_time_log(ctx, timer, argc, argv, false);
    return JS_UNDEFINED;
}

static JSValue js_console_time_end(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    char* label = console_label(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, "default");
    ConsoleTimer* timer = find_timer(label);
    if (!timer) {
        DynBuf buf;
        dbuf_init2(&buf, JS_GetRuntime(ctx), console_realloc);
        dbuf_printf(&buf, "Timer '%s' does not exist", label);
        JSValue msg = JS_NewStringLen(ctx, (char*)buf.buf, buf.size);
        dbuf_free(&buf);
        JSValueConst args[1] = { msg };
        console_log_internal(ctx, 1, args, stderr, 2, false);
        JS_FreeValue(ctx, msg);
        js_free(ctx, label);
        return JS_UNDEFINED;
    }
    js_free(ctx, label);
    console_time_log(ctx, timer, argc, argv, true);
    return JS_UNDEFINED;
}

static JSValue js_console_time_stamp(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    (void)ctx;
    (void)this_val;
    (void)argc;
    (void)argv;
    return JS_UNDEFINED;
}

static JSValue js_console_group(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc > 0) console_log_internal(ctx, argc, argv, stdout, 2, false);
    console_group_indent += 2;
    return JS_UNDEFINED;
}

static JSValue js_console_group_end(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    (void)ctx;
    (void)this_val;
    (void)argc;
    (void)argv;
    if (console_group_indent >= 2) console_group_indent -= 2;
    return JS_UNDEFINED;
}

static JSValue js_console_dirxml(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return js_console_log(ctx, this_val, argc, argv);
}

static JSValue js_console_table(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc == 0 || JS_IsUndefined(argv[0]) || JS_IsNull(argv[0])) {
        console_log_internal(ctx, argc, argv, stdout, 2, false);
        return JS_UNDEFINED;
    }

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue array_ctor = JS_GetPropertyStr(ctx, global, "Array");
    JSValue is_array_fn = JS_GetPropertyStr(ctx, array_ctor, "isArray");
    JSValue is_arr_val = JS_IsFunction(ctx, is_array_fn) ? JS_Call(ctx, is_array_fn, array_ctor, 1, argv) : JS_FALSE;
    bool is_arr = JS_ToBool(ctx, is_arr_val);
    JS_FreeValue(ctx, is_arr_val);
    JS_FreeValue(ctx, is_array_fn);
    JS_FreeValue(ctx, array_ctor);
    JS_FreeValue(ctx, global);

    DynBuf out;
    dbuf_init2(&out, JS_GetRuntime(ctx), console_realloc);

    if (is_arr) {
        int64_t len = 0;
        JSValue len_val = JS_GetProperty(ctx, argv[0], JS_ATOM_length);
        JS_ToInt64(ctx, &len, len_val);
        JS_FreeValue(ctx, len_val);
        dbuf_putstr(&out, "(index)  Value\n");
        int64_t show = len < 100 ? len : 100;
        for (int64_t i = 0; i < show; i++) {
            JSValue elem = JS_GetPropertyUint32(ctx, argv[0], (uint32_t)i);
            dbuf_printf(&out, "%lld        ", (long long)i);
            format_value_with_depth(ctx, elem, &out, 1, false, stdout);
            dbuf_putc(&out, '\n');
            JS_FreeValue(ctx, elem);
        }
        if (len > show) dbuf_printf(&out, "... %lld more items\n", (long long)(len - show));
    } else if (JS_IsObject(argv[0])) {
        JSPropertyEnum* props = NULL;
        uint32_t count = 0;
        if (JS_GetOwnPropertyNames(ctx, &props, &count, argv[0], JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
            dbuf_putstr(&out, "(index)  Value\n");
            for (uint32_t i = 0; i < count && i < 100; i++) {
                const char* key = JS_AtomToCString(ctx, props[i].atom);
                JSValue val = JS_GetProperty(ctx, argv[0], props[i].atom);
                dbuf_printf(&out, "%s        ", key ? key : "");
                format_value_with_depth(ctx, val, &out, 1, false, stdout);
                dbuf_putc(&out, '\n');
                if (key) JS_FreeCString(ctx, key);
                JS_FreeValue(ctx, val);
            }
            JS_FreePropertyEnum(ctx, props, count);
        }
    }

    if (out.size == 0) {
        format_value_with_depth(ctx, argv[0], &out, 2, false, stdout);
        dbuf_putc(&out, '\n');
    }
    fwrite2(out.buf, 1, out.size, stdout);
    fflush(stdout);
    dbuf_free(&out);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry console_funcs[] = {
    JS_CFUNC_DEF("log", 0, js_console_log),
    JS_CFUNC_DEF("error", 0, js_console_error),
    JS_CFUNC_DEF("warn", 0, js_console_warn),
    JS_CFUNC_DEF("info", 0, js_console_info),
    JS_CFUNC_DEF("debug", 0, js_console_debug),
    JS_CFUNC_DEF("dir", 1, js_console_dir),
    JS_CFUNC_DEF("dirxml", 0, js_console_dirxml),
    JS_CFUNC_DEF("table", 1, js_console_table),
    JS_CFUNC_DEF("trace", 0, js_console_trace),
    JS_CFUNC_DEF("clear", 0, js_console_clear),
    JS_CFUNC_DEF("assert", 1, js_console_assert),
    JS_CFUNC_DEF("count", 1, js_console_count),
    JS_CFUNC_DEF("countReset", 1, js_console_count_reset),
    JS_CFUNC_DEF("time", 1, js_console_time),
    JS_CFUNC_DEF("timeLog", 1, js_console_time_log),
    JS_CFUNC_DEF("timeEnd", 1, js_console_time_end),
    JS_CFUNC_DEF("timeStamp", 1, js_console_time_stamp),
    JS_CFUNC_DEF("group", 0, js_console_group),
    JS_CFUNC_DEF("groupCollapsed", 0, js_console_group),
    JS_CFUNC_DEF("groupEnd", 0, js_console_group_end),
    JS_CFUNC_DEF("inspect", 1, js_console_inspect),
    JS_CFUNC_DEF("format", 0, js_console_format)
};

static void stdout_mutex_init_once(void) {
    uv_mutex_init(&stdout_mutex);
}

void tjs__mod_console_init(JSContext* ctx, JSValue ns) {
    /* Racy under worker threads with a plain static flag; uv_once is safe. */
    uv_once(&stdout_mutex_once, stdout_mutex_init_once);
#ifdef _WIN32
    // use utf-8 to display correctly in Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // ANSI color
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif

    JS_SetPropertyFunctionList(ctx, ns, console_funcs, countof(console_funcs));
}

// # C apis
void TJS_DumpValue(JSContext *ctx, FILE *f, JSValue val) {
	VisitStack st = {0};
	InspectOptions io = {
		.depth = 2,
		.break_length = DEFAULT_BREAK_LENGTH,
		.colors = isatty(fileno(f)),
		.show_hidden = false,
		.max_array_length = MAX_ARRAY_LENGTH,
		.max_string_length = MAX_STRING_LENGTH,
		.compact = true,
	};
	DynBuf buf;

	dbuf_init(&buf);
	format_value(ctx, val, 0, &st, &buf, false, &io);
	fwrite(buf.buf, buf.size, 1, f);
	dbuf_free(&buf);
}

void TJS_DumpException(JSContext *ctx) {
    JSValue exception_val = JS_GetException(ctx);
    tjs_dump_error(ctx, exception_val);
    JS_FreeValue(ctx, exception_val);
}

void tjs_dump_error(JSContext *ctx, JSValue exception_val) {
    TJS_DumpValue(ctx, stderr, exception_val);
    fflush(stderr);
}
