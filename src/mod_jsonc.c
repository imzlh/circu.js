/*
 * circu.js - JSONC Parser Module
 *
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
#include "tjs.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

typedef struct {
    const char* str;
    size_t len;
    size_t pos;
    JSContext* ctx;
    int line;
    int column;
} JsoncParser;

#pragma region Macros

#define CURRENT_CHAR(p) ((p)->pos < (p)->len ? (p)->str[(p)->pos] : '\0')
#define PEEK_CHAR(p, offset) ((p)->pos + (offset) < (p)->len ? (p)->str[(p)->pos + (offset)] : '\0')
#define IS_AT_END(p) ((p)->pos >= (p)->len)
#define MATCHES(p, s, n) ((p)->pos + (n) <= (p)->len && memcmp((p)->str + (p)->pos, (s), (n)) == 0)

#define THROW_SYNTAX_ERROR(ctx, ...) JS_ThrowSyntaxError(ctx, __VA_ARGS__)
#define THROW_OOM(ctx) JS_ThrowOutOfMemory(ctx)

#define CHECK_EXCEPTION(val) if (JS_IsException(val)) return -1

#pragma endregion

#pragma region Helper Functions

static int parse_value(JsoncParser* p, JSValue* result);

static inline void advance(JsoncParser* p) {
    if (!IS_AT_END(p)) {
        if (p->str[p->pos] == '\n') {
            p->line++;
            p->column = 1;
        } else {
            p->column++;
        }
        p->pos++;
    }
}

static void get_context(JsoncParser* p, char* buf, size_t size) {
    if (size < 2) return;
    
    size_t start = p->pos > 20 ? p->pos - 20 : 0;
    size_t end = p->pos + 20 < p->len ? p->pos + 20 : p->len;
    size_t len = end - start;
    
    if (len >= size - 1) len = size - 1;
    
    memcpy(buf, p->str + start, len);
    buf[len] = '\0';
    
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
    }
}

static void skip_whitespace(JsoncParser* p) {
    while (!IS_AT_END(p) && isspace((unsigned char)CURRENT_CHAR(p))) {
        advance(p);
    }
}

static void skip_line_comment(JsoncParser* p) {
    advance(p); // '/'
    advance(p); // '/'
    
    while (!IS_AT_END(p) && CURRENT_CHAR(p) != '\n') {
        advance(p);
    }
    
    if (!IS_AT_END(p)) advance(p); // skip '\n'
}

static int skip_block_comment(JsoncParser* p) {
    int start_line = p->line;
    int start_col = p->column;
    
    advance(p); // '/'
    advance(p); // '*'
    
    while (!IS_AT_END(p)) {
        if (CURRENT_CHAR(p) == '*' && PEEK_CHAR(p, 1) == '/') {
            advance(p); // '*'
            advance(p); // '/'
            return 0;
        }
        advance(p);
    }
    
    char ctx[64];
    get_context(p, ctx, sizeof(ctx));
    THROW_SYNTAX_ERROR(p->ctx, 
        "Unclosed block comment at line %d, column %d. Context: '%s'",
        start_line, start_col, ctx);
    return -1;
}

static int skip_whitespace_and_comments(JsoncParser* p) {
    while (1) {
        skip_whitespace(p);
        
        if (IS_AT_END(p)) break;
        
        if (CURRENT_CHAR(p) == '/' && PEEK_CHAR(p, 1) == '/') {
            skip_line_comment(p);
        } else if (CURRENT_CHAR(p) == '/' && PEEK_CHAR(p, 1) == '*') {
            if (skip_block_comment(p) < 0) return -1;
        } else {
            break;
        }
    }
    
    return 0;
}

#pragma endregion

#pragma region String Parsing

static int parse_string(JsoncParser* p, JSValue* result) {
    if (CURRENT_CHAR(p) != '"') {
        char ctx[64];
        get_context(p, ctx, sizeof(ctx));
        THROW_SYNTAX_ERROR(p->ctx, "Expected '\"' at line %d, column %d. Context: '%s'",
            p->line, p->column, ctx);
        return -1;
    }
    
    int start_line = p->line;
    int start_col = p->column;
    size_t str_start = p->pos;
    
    advance(p); // skip opening '"'
    
    int has_escape = 0;
    
    while (!IS_AT_END(p)) {
        char c = CURRENT_CHAR(p);
        
        if (c == '\\') {
            has_escape = 1;
            advance(p);
            if (!IS_AT_END(p)) advance(p);
            continue;
        }
        
        if (c == '"') {
            size_t str_end = p->pos;
            advance(p); // skip closing '"'
            
            if (has_escape) {
                size_t json_len = str_end - str_start + 1;
                *result = JS_ParseJSON(p->ctx, p->str + str_start, json_len, "<string>");
                CHECK_EXCEPTION(*result);
            } else {
                size_t content_len = str_end - str_start - 1;
                *result = JS_NewStringLen(p->ctx, p->str + str_start + 1, content_len);
                CHECK_EXCEPTION(*result);
            }
            
            return 0;
        }
        
        if ((unsigned char)c < 0x20 && c != '\t') {
            THROW_SYNTAX_ERROR(p->ctx, "Unescaped control character (0x%02X) at line %d, column %d",
                (unsigned char)c, p->line, p->column);
            return -1;
        }
        
        advance(p);
    }
    
    char ctx[64];
    get_context(p, ctx, sizeof(ctx));
    THROW_SYNTAX_ERROR(p->ctx, "Unclosed string at line %d, column %d. Context: '%s'",
        start_line, start_col, ctx);
    return -1;
}

#pragma endregion

#pragma region Number Parsing

static int parse_number(JsoncParser* p, JSValue* result) {
    size_t start = p->pos;
    int start_line = p->line;
    int start_col = p->column;
    
    if (CURRENT_CHAR(p) == '-') advance(p);
    
    if (!isdigit((unsigned char)CURRENT_CHAR(p))) {
        char ctx[64];
        get_context(p, ctx, sizeof(ctx));
        THROW_SYNTAX_ERROR(p->ctx, "Invalid number at line %d, column %d. Context: '%s'",
            start_line, start_col, ctx);
        return -1;
    }
    
    while (isdigit((unsigned char)CURRENT_CHAR(p))) advance(p);
    
    if (CURRENT_CHAR(p) == '.') {
        advance(p);
        
        if (!isdigit((unsigned char)CURRENT_CHAR(p))) {
            char ctx[64];
            get_context(p, ctx, sizeof(ctx));
            THROW_SYNTAX_ERROR(p->ctx, "Invalid number: expected digit after '.' at line %d, column %d. Context: '%s'",
                p->line, p->column, ctx);
            return -1;
        }
        
        while (isdigit((unsigned char)CURRENT_CHAR(p))) advance(p);
    }
    
    if (CURRENT_CHAR(p) == 'e' || CURRENT_CHAR(p) == 'E') {
        advance(p);
        
        if (CURRENT_CHAR(p) == '+' || CURRENT_CHAR(p) == '-') advance(p);
        
        if (!isdigit((unsigned char)CURRENT_CHAR(p))) {
            char ctx[64];
            get_context(p, ctx, sizeof(ctx));
            THROW_SYNTAX_ERROR(p->ctx, "Invalid number: expected digit in exponent at line %d, column %d. Context: '%s'",
                p->line, p->column, ctx);
            return -1;
        }
        
        while (isdigit((unsigned char)CURRENT_CHAR(p))) advance(p);
    }
    
    size_t len = p->pos - start;
    if (len >= 64) {
        THROW_SYNTAX_ERROR(p->ctx, "Number too long at line %d, column %d", start_line, start_col);
        return -1;
    }
    
    char buf[64];
    memcpy(buf, p->str + start, len);
    buf[len] = '\0';
    
    double val;
    if (sscanf(buf, "%lf", &val) != 1) {
        char ctx[64];
        get_context(p, ctx, sizeof(ctx));
        THROW_SYNTAX_ERROR(p->ctx, "Invalid number '%s' at line %d, column %d. Context: '%s'",
            buf, start_line, start_col, ctx);
        return -1;
    }
    
    *result = JS_NewFloat64(p->ctx, val);
    return 0;
}

#pragma endregion

#pragma region Array Parsing

static int parse_array(JsoncParser* p, JSValue* result) {
    int start_line = p->line;
    int start_col = p->column;
    
    advance(p); // skip '['
    
    JSValue arr = JS_NewArray(p->ctx);
    CHECK_EXCEPTION(arr);
    
    uint32_t idx = 0;
    int need_value = 1;
    
    while (1) {
        if (skip_whitespace_and_comments(p) < 0) {
            JS_FreeValue(p->ctx, arr);
            return -1;
        }
        
        if (IS_AT_END(p)) {
            JS_FreeValue(p->ctx, arr);
            char ctx[64];
            get_context(p, ctx, sizeof(ctx));
            THROW_SYNTAX_ERROR(p->ctx, "Unclosed array at line %d, column %d. Context: '%s'",
                start_line, start_col, ctx);
            return -1;
        }
        
        if (CURRENT_CHAR(p) == ']') {
            advance(p);
            *result = arr;
            return 0;
        }
        
        if (!need_value) {
            if (CURRENT_CHAR(p) == ',') {
                advance(p);
                need_value = 1;
                continue;
            } else {
                JS_FreeValue(p->ctx, arr);
                char ctx[64];
                get_context(p, ctx, sizeof(ctx));
                THROW_SYNTAX_ERROR(p->ctx, "Expected ',' or ']' at line %d, column %d. Context: '%s'",
                    p->line, p->column, ctx);
                return -1;
            }
        }
        
        JSValue elem;
        if (parse_value(p, &elem) < 0) {
            JS_FreeValue(p->ctx, arr);
            return -1;
        }
        
        if (JS_SetPropertyUint32(p->ctx, arr, idx++, elem) < 0) {
            JS_FreeValue(p->ctx, arr);
            return -1;
        }
        
        need_value = 0;
    }
}

#pragma endregion

#pragma region Object Parsing

static int parse_object(JsoncParser* p, JSValue* result) {
    int start_line = p->line;
    int start_col = p->column;
    
    advance(p); // skip '{'
    
    JSValue obj = JS_NewObject(p->ctx);
    CHECK_EXCEPTION(obj);
    
    int need_key = 1;
    
    while (1) {
        if (skip_whitespace_and_comments(p) < 0) {
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        if (IS_AT_END(p)) {
            JS_FreeValue(p->ctx, obj);
            char ctx[64];
            get_context(p, ctx, sizeof(ctx));
            THROW_SYNTAX_ERROR(p->ctx, "Unclosed object at line %d, column %d. Context: '%s'",
                start_line, start_col, ctx);
            return -1;
        }
        
        if (CURRENT_CHAR(p) == '}') {
            advance(p);
            *result = obj;
            return 0;
        }
        
        if (!need_key) {
            if (CURRENT_CHAR(p) == ',') {
                advance(p);
                need_key = 1;
                continue;
            } else {
                JS_FreeValue(p->ctx, obj);
                char ctx[64];
                get_context(p, ctx, sizeof(ctx));
                THROW_SYNTAX_ERROR(p->ctx, "Expected ',' or '}' at line %d, column %d. Context: '%s'",
                    p->line, p->column, ctx);
                return -1;
            }
        }
        
        JSValue key;
        if (parse_string(p, &key) < 0) {
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        if (skip_whitespace_and_comments(p) < 0) {
            JS_FreeValue(p->ctx, key);
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        if (CURRENT_CHAR(p) != ':') {
            JS_FreeValue(p->ctx, key);
            JS_FreeValue(p->ctx, obj);
            char ctx[64];
            get_context(p, ctx, sizeof(ctx));
            THROW_SYNTAX_ERROR(p->ctx, "Expected ':' at line %d, column %d. Context: '%s'",
                p->line, p->column, ctx);
            return -1;
        }
        
        advance(p); // skip ':'
        
        if (skip_whitespace_and_comments(p) < 0) {
            JS_FreeValue(p->ctx, key);
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        JSValue val;
        if (parse_value(p, &val) < 0) {
            JS_FreeValue(p->ctx, key);
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        const char* key_str = JS_ToCString(p->ctx, key);
        if (!key_str) {
            JS_FreeValue(p->ctx, val);
            JS_FreeValue(p->ctx, key);
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        int ret = JS_SetPropertyStr(p->ctx, obj, key_str, val);
        JS_FreeCString(p->ctx, key_str);
        JS_FreeValue(p->ctx, key);
        
        if (ret < 0) {
            JS_FreeValue(p->ctx, obj);
            return -1;
        }
        
        need_key = 0;
    }
}

#pragma endregion

#pragma region Value Parsing

static int parse_value(JsoncParser* p, JSValue* result) {
    if (skip_whitespace_and_comments(p) < 0) return -1;
    
    if (IS_AT_END(p)) {
        char ctx[64];
        get_context(p, ctx, sizeof(ctx));
        THROW_SYNTAX_ERROR(p->ctx, "Unexpected end at line %d, column %d. Context: '%s'",
            p->line, p->column, ctx);
        return -1;
    }
    
    char c = CURRENT_CHAR(p);
    
    switch (c) {
        case '"':
            return parse_string(p, result);
        case '[':
            return parse_array(p, result);
        case '{':
            return parse_object(p, result);
        case 't':
            if (MATCHES(p, "true", 4) && !isalnum((unsigned char)PEEK_CHAR(p, 4))) {
                p->pos += 4;
                p->column += 4;
                *result = JS_TRUE;
                return 0;
            }
            break;
        case 'f':
            if (MATCHES(p, "false", 5) && !isalnum((unsigned char)PEEK_CHAR(p, 5))) {
                p->pos += 5;
                p->column += 5;
                *result = JS_FALSE;
                return 0;
            }
            break;
        case 'n':
            if (MATCHES(p, "null", 4) && !isalnum((unsigned char)PEEK_CHAR(p, 4))) {
                p->pos += 4;
                p->column += 4;
                *result = JS_NULL;
                return 0;
            }
            break;
        case '-':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return parse_number(p, result);
    }
    
    char ctx[64];
    get_context(p, ctx, sizeof(ctx));
    if (isprint((unsigned char)c)) {
        THROW_SYNTAX_ERROR(p->ctx, "Unexpected character '%c' at line %d, column %d. Context: '%s'",
            c, p->line, p->column, ctx);
    } else {
        THROW_SYNTAX_ERROR(p->ctx, "Unexpected character (0x%02X) at line %d, column %d. Context: '%s'",
            (unsigned char)c, p->line, p->column, ctx);
    }
    return -1;
}

#pragma endregion

#pragma region Public API

static JSValue jsonc_parse(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc != 1) {
        return JS_ThrowTypeError(ctx, "Expected 1 argument");
    }
    
    if (!JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "Expected string argument");
    }
    
    const char* str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_EXCEPTION;
    
    JsoncParser parser = {
        .str = str,
        .len = strlen(str),
        .pos = 0,
        .ctx = ctx,
        .line = 1,
        .column = 1
    };
    
    JSValue result = JS_UNDEFINED;
    
    if (parse_value(&parser, &result) < 0) {
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    if (skip_whitespace_and_comments(&parser) < 0) {
        JS_FreeValue(ctx, result);
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    if (!IS_AT_END(&parser)) {
        char ctx_buf[64];
        get_context(&parser, ctx_buf, sizeof(ctx_buf));
        JS_FreeValue(ctx, result);
        JS_FreeCString(ctx, str);
        return THROW_SYNTAX_ERROR(ctx, "Trailing content at line %d, column %d. Context: '%s'",
            parser.line, parser.column, ctx_buf);
    }
    
    JS_FreeCString(ctx, str);
    return result;
}

static const JSCFunctionListEntry js_jsonc_funcs[] = {
    JS_CFUNC_DEF("parse", 1, jsonc_parse),
};

void tjs__mod_jsonc_init(JSContext* ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, js_jsonc_funcs, countof(js_jsonc_funcs));
}

#pragma endregion