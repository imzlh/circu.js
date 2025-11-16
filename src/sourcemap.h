/**
 * circu.js SourceMap Extension 
 * 
 * Copyright (c) 2025 iz
 * MIT License
 */

#ifndef SOURCEMAP_H
#define SOURCEMAP_H

#include "tjs.h"

typedef struct MappingContext MappingContext;
typedef struct MappingResult {
    const char *original_file;
    int original_line;
    int original_column;
    const char *function_name;
    int found;
} MappingResult;

/* Context management */
MappingContext *js_create_mapping_context(void);
void js_destroy_mapping_context(MappingContext *ctx);

/* Source map operations */
bool js_has_sourcemap(MappingContext *ctx, const char *file_path);
int js_load_sourcemap(MappingContext *ctx, JSContext *js_ctx, const char *file_path, JSValue sourcemap_obj);
int js_load_sourcemap_cjson(MappingContext *ctx, JSContext *js_ctx, const char *file_path, const char *json_str);
MappingResult js_get_source_mapping(MappingContext *ctx, const char *file_path, int line, int col);
bool js_remove_sourcemap(MappingContext *ctx, const char *file_path);

#endif