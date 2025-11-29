/*
 * circu.js
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

typedef struct {
	const char* str;
	size_t len;
	size_t pos;
	JSContext* ctx;
} JsoncParser;

static void skip_whitespace(JsoncParser* parser) {
	while (parser->pos < parser->len && isspace(parser->str[parser->pos])) {
		parser->pos++;
	}
}

static int skip_comment(JsoncParser* parser) {
	if (parser->pos + 1 >= parser->len) return -1;

	if (parser->str[parser->pos] == '/' && parser->str[parser->pos + 1] == '/') {
		// Single line comment
		parser->pos += 2;
		while (parser->pos < parser->len && parser->str[parser->pos] != '\n') {
			parser->pos++;
		}
		if (parser->pos < parser->len) parser->pos++; // Skip newline
		return 0;
	}

	if (parser->str[parser->pos] == '/' && parser->str[parser->pos + 1] == '*') {
		// Multi-line comment
		parser->pos += 2;
		while (parser->pos + 1 < parser->len) {
			if (parser->str[parser->pos] == '*' && parser->str[parser->pos + 1] == '/') {
				parser->pos += 2;
				return 0;
			}
			parser->pos++;
		}
		return -1; // Unclosed comment
	}

	return 1; // Not a comment
}

static void skip_comments_and_whitespace(JsoncParser* parser) {
	int result;
	do {
		skip_whitespace(parser);
		result = skip_comment(parser);
	} while (result == 0);
}

static int parse_value(JsoncParser* parser, JSValue* result);

static int parse_string(JsoncParser* parser, JSValue* result) {
	if (parser->pos >= parser->len || parser->str[parser->pos] != '"') return -1;

	parser->pos++; // Skip opening quote
	const char* start = parser->str + parser->pos;
	size_t length = 0;
	int escaped = 0;

	while (parser->pos < parser->len) {
		char c = parser->str[parser->pos];

		if (escaped) {
			escaped = 0;
			parser->pos++;
			length++;
			continue;
		}

		if (c == '\\') {
			escaped = 1;
			parser->pos++;
			length++;
			continue;
		}

		if (c == '"') {
			// Found closing quote
			*result = JS_NewStringLen(parser->ctx, start, length);
			parser->pos++; // Skip closing quote
			return 0;
		}

		parser->pos++;
		length++;
	}

	return -1; // Unclosed string
}

static int parse_number(JsoncParser* parser, JSValue* result) {
	const char* start = parser->str + parser->pos;
	size_t length = 0;

	// Optional minus sign
	if (parser->pos < parser->len && parser->str[parser->pos] == '-') {
		parser->pos++;
		length++;
	}

	// Integer part
	while (parser->pos < parser->len && isdigit(parser->str[parser->pos])) {
		parser->pos++;
		length++;
	}

	// Decimal part
	if (parser->pos < parser->len && parser->str[parser->pos] == '.') {
		parser->pos++;
		length++;
		while (parser->pos < parser->len && isdigit(parser->str[parser->pos])) {
			parser->pos++;
			length++;
		}
	}

	// Exponent part
	if (parser->pos < parser->len && (parser->str[parser->pos] == 'e' || parser->str[parser->pos] == 'E')) {
		parser->pos++;
		length++;
		if (parser->pos < parser->len && (parser->str[parser->pos] == '+' || parser->str[parser->pos] == '-')) {
			parser->pos++;
			length++;
		}
		while (parser->pos < parser->len && isdigit(parser->str[parser->pos])) {
			parser->pos++;
			length++;
		}
	}

	if (length == 0) return -1;

	// Use QuickJS's number parsing for better performance
	double val;
	if (sscanf(start, "%lf", &val) == 1) {
		*result = JS_NewFloat64(parser->ctx, val);
		return 0;
	}

	return -1;
}

static int parse_array(JsoncParser* parser, JSValue* result) {
	if (parser->pos >= parser->len || parser->str[parser->pos] != '[') return -1;

	parser->pos++; // Skip '['
	JSValue array = JS_NewArray(parser->ctx);
	uint32_t index = 0;
	int first = 1;

	while (parser->pos < parser->len) {
		skip_comments_and_whitespace(parser);

		if (parser->pos < parser->len && parser->str[parser->pos] == ']') {
			parser->pos++; // Skip ']'
			*result = array;
			return 0;
		}

		if (!first) {
			skip_comments_and_whitespace(parser);
			if (parser->pos < parser->len && parser->str[parser->pos] == ',') {
				parser->pos++; // Skip comma
				skip_comments_and_whitespace(parser);
			}
		}

		JSValue element;
		if (parse_value(parser, &element) == 0) {
			JS_SetPropertyUint32(parser->ctx, array, index++, element);
			JS_FreeValue(parser->ctx, element);
		}
		else {
			JS_FreeValue(parser->ctx, array);
			return -1;
		}

		first = 0;
	}

	JS_FreeValue(parser->ctx, array);
	return -1; // Unclosed array
}

static int parse_object(JsoncParser* parser, JSValue* result) {
	if (parser->pos >= parser->len || parser->str[parser->pos] != '{') return -1;

	parser->pos++; // Skip '{'
	JSValue obj = JS_NewObject(parser->ctx);
	int first = 1;

	while (parser->pos < parser->len) {
		skip_comments_and_whitespace(parser);

		if (parser->pos < parser->len && parser->str[parser->pos] == '}') {
			parser->pos++; // Skip '}'
			*result = obj;
			return 0;
		}

		if (!first) {
			skip_comments_and_whitespace(parser);
			if (parser->pos < parser->len && parser->str[parser->pos] == ',') {
				parser->pos++; // Skip comma
				skip_comments_and_whitespace(parser);
			}
		}

		// Parse key
		JSValue key;
		if (parse_string(parser, &key) != 0) {
			JS_FreeValue(parser->ctx, obj);
			return -1;
		}

		skip_comments_and_whitespace(parser);

		// Check for colon
		if (parser->pos >= parser->len || parser->str[parser->pos] != ':') {
			JS_FreeValue(parser->ctx, key);
			JS_FreeValue(parser->ctx, obj);
			return -1;
		}
		parser->pos++; // Skip ':'
		skip_comments_and_whitespace(parser);

		// Parse value
		JSValue value;
		if (parse_value(parser, &value) == 0) {
			const char* key_str = JS_ToCString(parser->ctx, key);
			JS_SetPropertyStr(parser->ctx, obj, key_str, value);
			JS_FreeCString(parser->ctx, key_str);
			JS_FreeValue(parser->ctx, key);
		}
		else {
			JS_FreeValue(parser->ctx, key);
			JS_FreeValue(parser->ctx, obj);
			return -1;
		}

		first = 0;
	}

	JS_FreeValue(parser->ctx, obj);
	return -1; // Unclosed object
}

static int parse_value(JsoncParser* parser, JSValue* result) {
	skip_comments_and_whitespace(parser);

	if (parser->pos >= parser->len) return -1;

	char c = parser->str[parser->pos];

	switch (c) {
	case '"': return parse_string(parser, result);
	case '[': return parse_array(parser, result);
	case '{': return parse_object(parser, result);
	case 't': // true
		if (parser->pos + 3 < parser->len && memcmp(parser->str + parser->pos, "true", 4) == 0) {
			parser->pos += 4;
			*result = JS_TRUE;
			return 0;
		}
		break;
	case 'f': // false
		if (parser->pos + 4 < parser->len && memcmp(parser->str + parser->pos, "false", 5) == 0) {
			parser->pos += 5;
			*result = JS_FALSE;
			return 0;
		}
		break;
	case 'n': // null
		if (parser->pos + 3 < parser->len && memcmp(parser->str + parser->pos, "null", 4) == 0) {
			parser->pos += 4;
			*result = JS_NULL;
			return 0;
		}
		break;
	default:
		if (c == '-' || isdigit(c)) {
			return parse_number(parser, result);
		}
		break;
	}

	return -1;
}

static JSValue jsonc_parse(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
	if (argc != 1) {
		return JS_ThrowTypeError(ctx, "expected one argument");
	}

	const char* str = JS_ToCString(ctx, argv[0]);
	if (!str) return JS_EXCEPTION;

	size_t len = strlen(str);
	JsoncParser parser = {
		.str = str,
		.len = len,
		.pos = 0,
		.ctx = ctx
	};

	JSValue result;
	if (parse_value(&parser, &result) == 0) {
		skip_comments_and_whitespace(&parser);
		if (parser.pos < parser.len) {
			JS_FreeValue(ctx, result);
			JS_FreeCString(ctx, str);
			return JS_ThrowSyntaxError(ctx, "trailing garbage after JSON");
		}
	}
	else {
		JS_FreeCString(ctx, str);
		return JS_ThrowSyntaxError(ctx, "invalid JSONC format");
	}

	JS_FreeCString(ctx, str);
	return result;
}

static const JSCFunctionListEntry js_jsonc_funcs[] = {
	JS_CFUNC_DEF("parse", 1, jsonc_parse),
};

static int tjs__mod_jsonc_init(JSContext* ctx, JSValue ns) {
	return JS_SetPropertyFunctionList(ctx, ns, js_jsonc_funcs, countof(js_jsonc_funcs));
}
