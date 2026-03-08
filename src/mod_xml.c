/**
 * Circu.js expat XML parser module
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
#include <expat.h>
#include <string.h>

/* Parser state structure */
typedef struct {
    JSContext *ctx;
    XML_Parser parser;
    JSValue handlers;
    JSValue current_data;
    bool stopped;
} TJSXMLParser;

/* Macro for creating callback wrapper */
#define XML_CALLBACK(name, ...) \
    static void xml_##name##_cb(void *userData, ##__VA_ARGS__)

/* Macro for invoking JS handler */
#define INVOKE_HANDLER(state, handler_name, argc, ...) do { \
    JSValue handler = JS_GetPropertyStr((state)->ctx, (state)->handlers, handler_name); \
    if (JS_IsFunction((state)->ctx, handler)) { \
        JSValue args[] = { __VA_ARGS__ }; \
        JSValue ret = JS_Call((state)->ctx, handler, JS_UNDEFINED, argc, args); \
        if (JS_IsException(ret)) { \
            (state)->stopped = true; \
        } \
        JS_FreeValue((state)->ctx, ret); \
        for (int i = 0; i < argc; i++) JS_FreeValue((state)->ctx, args[i]); \
    } \
    JS_FreeValue((state)->ctx, handler); \
} while(0)

/* Helper: Convert attributes array to JS object */
static JSValue xml_attrs_to_obj(JSContext *ctx, const XML_Char **attrs) {
    JSValue obj = JS_NewObject(ctx);
    if (attrs) {
        for (int i = 0; attrs[i]; i += 2) {
            JS_SetPropertyStr(ctx, obj, attrs[i], JS_NewString(ctx, attrs[i + 1]));
        }
    }
    return obj;
}

/* Expat callbacks */
XML_CALLBACK(element_start, const XML_Char *name, const XML_Char **attrs) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue name_val = JS_NewString(state->ctx, name);
    JSValue attrs_val = xml_attrs_to_obj(state->ctx, attrs);
    INVOKE_HANDLER(state, "startElement", 2, name_val, attrs_val);
}

XML_CALLBACK(element_end, const XML_Char *name) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue name_val = JS_NewString(state->ctx, name);
    INVOKE_HANDLER(state, "endElement", 1, name_val);
}

XML_CALLBACK(character_data, const XML_Char *s, int len) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue data_val = JS_NewStringLen(state->ctx, s, len);
    INVOKE_HANDLER(state, "characterData", 1, data_val);
}

XML_CALLBACK(comment, const XML_Char *data) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue data_val = JS_NewString(state->ctx, data);
    INVOKE_HANDLER(state, "comment", 1, data_val);
}

XML_CALLBACK(start_cdata) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    INVOKE_HANDLER(state, "startCDATA", 0);
}

XML_CALLBACK(end_cdata) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    INVOKE_HANDLER(state, "endCDATA", 0);
}

XML_CALLBACK(processing_instruction, const XML_Char *target, const XML_Char *data) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue target_val = JS_NewString(state->ctx, target);
    JSValue data_val = JS_NewString(state->ctx, data ? data : "");
    INVOKE_HANDLER(state, "processingInstruction", 2, target_val, data_val);
}

XML_CALLBACK(namespace_start, const XML_Char *prefix, const XML_Char *uri) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue prefix_val = prefix ? JS_NewString(state->ctx, prefix) : JS_NULL;
    JSValue uri_val = JS_NewString(state->ctx, uri);
    INVOKE_HANDLER(state, "startNamespace", 2, prefix_val, uri_val);
}

XML_CALLBACK(namespace_end, const XML_Char *prefix) {
    TJSXMLParser *state = (TJSXMLParser *)userData;
    if (state->stopped) return;
    
    JSValue prefix_val = prefix ? JS_NewString(state->ctx, prefix) : JS_NULL;
    INVOKE_HANDLER(state, "endNamespace", 1, prefix_val);
}

/* Class ID */
static JSClassID tjs_xml_parser_class_id;

/* Finalizer */
static void tjs_xml_parser_finalizer(JSRuntime *rt, JSValue val) {
    TJSXMLParser *state = JS_GetOpaque(val, tjs_xml_parser_class_id);
    if (state) {
        if (state->parser) {
            XML_ParserFree(state->parser);
        }
        JS_FreeValueRT(rt, state->handlers);
        JS_FreeValueRT(rt, state->current_data);
        js_free_rt(rt, state);
    }
}

static void tjs_xml_parser_mark(JSRuntime *rt, JSValue val,
                                JS_MarkFunc *mark_func)
{
    TJSXMLParser *p = JS_GetOpaque(val, tjs_xml_parser_class_id);
    if (!p) return;

    JS_MarkValue(rt, p->handlers,    mark_func);
    JS_MarkValue(rt, p->current_data, mark_func);
}



static JSClassDef tjs_xml_parser_class = {
    "XMLParser",
    .finalizer = tjs_xml_parser_finalizer,
	.gc_mark = tjs_xml_parser_mark,
};

/* Constructor: new XMLParser(options) */
static JSValue tjs_xml_parser_constructor(JSContext *ctx, JSValueConst new_target,
                                           int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_xml_parser_class_id);
    if (JS_IsException(obj)) return obj;
    
    TJSXMLParser *state = js_mallocz(ctx, sizeof(*state));
    if (!state) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    state->ctx = ctx;
    state->handlers = JS_NewObject(ctx);
    state->current_data = JS_UNDEFINED;
    state->stopped = false;
    
    /* Parse options */
    JSValue options = argc > 0 ? argv[0] : JS_UNDEFINED;
    JSValue ns_val = JS_GetPropertyStr(ctx, options, "namespace");
    JSValue separator_val = JS_GetPropertyStr(ctx, options, "namespaceSeparator");
    
    const char *separator = NULL;
    if (JS_IsString(separator_val)) {
        separator = JS_ToCString(ctx, separator_val);
    }
    
    /* Create parser with namespace support */
    if (JS_ToBool(ctx, ns_val)) {
        state->parser = XML_ParserCreateNS(NULL, separator ? separator[0] : '|');
    } else {
        state->parser = XML_ParserCreate(NULL);
    }
    
    if (separator) JS_FreeCString(ctx, separator);
    JS_FreeValue(ctx, ns_val);
    JS_FreeValue(ctx, separator_val);
    
    if (!state->parser) {
        JS_FreeValue(ctx, state->handlers);
        js_free(ctx, state);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    /* Setup callbacks */
    XML_SetUserData(state->parser, state);
    XML_SetElementHandler(state->parser, xml_element_start_cb, xml_element_end_cb);
    XML_SetCharacterDataHandler(state->parser, xml_character_data_cb);
    XML_SetCommentHandler(state->parser, xml_comment_cb);
    XML_SetCdataSectionHandler(state->parser, xml_start_cdata_cb, xml_end_cdata_cb);
    XML_SetProcessingInstructionHandler(state->parser, xml_processing_instruction_cb);
    XML_SetNamespaceDeclHandler(state->parser, xml_namespace_start_cb, xml_namespace_end_cb);
    
    JS_SetOpaque(obj, state);
    return obj;
}

/* parser.on(event, handler) */
static JSValue tjs_xml_parser_on(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSXMLParser *state = JS_GetOpaque2(ctx, this_val, tjs_xml_parser_class_id);
    if (!state) return JS_EXCEPTION;
    
    const char *event = JS_ToCString(ctx, argv[0]);
    if (!event) return JS_EXCEPTION;
    
    JS_SetPropertyStr(ctx, state->handlers, event, JS_DupValue(ctx, argv[1]));
    JS_FreeCString(ctx, event);
    
    return JS_DupValue(ctx, this_val);
}

/* parser.parse(data, isFinal) */
static JSValue tjs_xml_parser_parse(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    TJSXMLParser *state = JS_GetOpaque2(ctx, this_val, tjs_xml_parser_class_id);
    if (!state) return JS_EXCEPTION;
    
    size_t len;
    const char *data = JS_ToCStringLen(ctx, &len, argv[0]);
    if (!data) return JS_EXCEPTION;
    
    int is_final = argc > 1 ? JS_ToBool(ctx, argv[1]) : 1;
    
    state->stopped = false;
    int status = XML_Parse(state->parser, data, len, is_final);
    JS_FreeCString(ctx, data);
    
    if (!status && !state->stopped) {
        enum XML_Error error = XML_GetErrorCode(state->parser);
        return JS_ThrowTypeError(ctx, "XML parse error: %s at line %lu",
                                XML_ErrorString(error),
                                XML_GetCurrentLineNumber(state->parser));
    }
    
    return JS_NewBool(ctx, status);
}

/* parser.stop() */
static JSValue tjs_xml_parser_stop(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    TJSXMLParser *state = JS_GetOpaque2(ctx, this_val, tjs_xml_parser_class_id);
    if (!state) return JS_EXCEPTION;
    
    XML_StopParser(state->parser, XML_TRUE);
    state->stopped = true;
    
    return JS_UNDEFINED;
}

/* parser.reset() */
static JSValue tjs_xml_parser_reset(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv) {
    TJSXMLParser *state = JS_GetOpaque2(ctx, this_val, tjs_xml_parser_class_id);
    if (!state) return JS_EXCEPTION;
    
    const char *encoding = argc > 0 ? JS_ToCString(ctx, argv[0]) : NULL;
    int status = XML_ParserReset(state->parser, encoding);
    if (encoding) JS_FreeCString(ctx, encoding);
    
    if (status) {
        XML_SetUserData(state->parser, state);
        state->stopped = false;
    }
    
    return JS_NewBool(ctx, status);
}

/* Getter: parser.line */
static JSValue tjs_xml_parser_get_line(JSContext *ctx, JSValueConst this_val) {
    TJSXMLParser *state = JS_GetOpaque2(ctx, this_val, tjs_xml_parser_class_id);
    if (!state) return JS_EXCEPTION;
    return JS_NewInt64(ctx, XML_GetCurrentLineNumber(state->parser));
}

/* Getter: parser.column */
static JSValue tjs_xml_parser_get_column(JSContext *ctx, JSValueConst this_val) {
    TJSXMLParser *state = JS_GetOpaque2(ctx, this_val, tjs_xml_parser_class_id);
    if (!state) return JS_EXCEPTION;
    return JS_NewInt64(ctx, XML_GetCurrentColumnNumber(state->parser));
}

/* Utility: XML.escape(str) */
static JSValue tjs_xml_escape(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
    const char *str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_EXCEPTION;
    
    size_t len = strlen(str);
    size_t new_len = len;
    
    /* Calculate new length */
    for (size_t i = 0; i < len; i++) {
        switch (str[i]) {
            case '&': new_len += 4; break;  /* &amp; */
            case '<': case '>': new_len += 3; break;  /* &lt; &gt; */
            case '"': new_len += 5; break;  /* &quot; */
            case '\'': new_len += 5; break;  /* &apos; */
        }
    }
    
    char *escaped = js_malloc(ctx, new_len + 1);
    if (!escaped) {
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        switch (str[i]) {
            case '&': memcpy(escaped + j, "&amp;", 5); j += 5; break;
            case '<': memcpy(escaped + j, "&lt;", 4); j += 4; break;
            case '>': memcpy(escaped + j, "&gt;", 4); j += 4; break;
            case '"': memcpy(escaped + j, "&quot;", 6); j += 6; break;
            case '\'': memcpy(escaped + j, "&apos;", 6); j += 6; break;
            default: escaped[j++] = str[i]; break;
        }
    }
    escaped[j] = '\0';
    
    JS_FreeCString(ctx, str);
    JSValue result = JS_NewString(ctx, escaped);
    js_free(ctx, escaped);
    return result;
}

/* Method definitions */
static const JSCFunctionListEntry tjs_xml_parser_proto_funcs[] = {
    JS_CFUNC_DEF("on", 2, tjs_xml_parser_on),
    JS_CFUNC_DEF("parse", 2, tjs_xml_parser_parse),
    JS_CFUNC_DEF("stop", 0, tjs_xml_parser_stop),
    JS_CFUNC_DEF("reset", 1, tjs_xml_parser_reset),
    JS_CGETSET_DEF("line", tjs_xml_parser_get_line, NULL),
    JS_CGETSET_DEF("column", tjs_xml_parser_get_column, NULL),
};

static const JSCFunctionListEntry tjs_xml_funcs[] = {
    JS_CFUNC_DEF("escape", 1, tjs_xml_escape),
};

/* Module initialization */
void tjs__mod_xml_init(JSContext *ctx, JSValue ns) {
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_xml_parser_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_xml_parser_class_id, &tjs_xml_parser_class);
    
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_xml_parser_proto_funcs,
                              countof(tjs_xml_parser_proto_funcs));
    JS_SetClassProto(ctx, tjs_xml_parser_class_id, proto);
    
    JSValue constructor = JS_NewCFunction2(ctx, tjs_xml_parser_constructor,
                                          "XMLParser", 1,
                                          JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, constructor, proto);
    JS_SetPropertyStr(ctx, ns, "XMLParser", constructor);
    JS_SetPropertyFunctionList(ctx, ns, tjs_xml_funcs, countof(tjs_xml_funcs));
}