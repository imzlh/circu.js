/**
 * circu.js SourceMap Extension 
 * 
 * Copyright (c) 2025 iz
 * MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../deps/quickjs/list.h"

#include "private.h"
#include "sourcemap.h"

#pragma region Macros and Constants
/* ---------- Macros ---------- */

#define HASH_INIT_SIZE 1024
#define FILE_INIT_CAPACITY 16

#define CALC_HASH(line, col, size) (hash_position((line), (col)) % (size))
#define MAKE_KEY(line, col) (((uint64_t)(line) << 32) | (uint32_t)(col))

#define FREE_STR_ARRAY(arr, cnt) \
    do { \
        if (arr) { \
            for (int i = 0; i < (cnt); i++) free((arr)[i]); \
            free(arr); \
        } \
    } while (0)

/* ---------- Structures ---------- */

typedef struct {
    int generated_line;
    int generated_column;
    int original_line;
    int original_column;
    char *original_file;
    char *name;
} SourceMapping;

/* Node in hash bucket and global list */
typedef struct MappingNode {
    uint64_t key;
    SourceMapping mapping;
    struct list_head hash_link;  /* Hash bucket chain */
    struct list_head list_link;  /* Global ordered list */
} MappingNode;

/* Hash bucket head */
typedef struct {
    struct list_head head;
} HashBucket;

/* Per-file source map */
typedef struct FileSourceMap {
    char *file_path;
    char **sources;
    int sources_count;
    char **names;
    int names_count;
    HashBucket *hash_table;
    int hash_size;
    struct list_head mappings_list;  /* All mappings in order */
    int mappings_count;
    int ref_count;
} FileSourceMap;

/* Context replacing global manager */
struct MappingContext {
    FileSourceMap **files;
    int files_count;
    int files_capacity;
};

#pragma region Static Functions
/* ---------- Static Functions ---------- */

static uint32_t hash_position(int line, int column) {
    uint64_t key = MAKE_KEY(line, column);
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;
    return (uint32_t)key;
}

static inline int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int decode_vlq(const char **input, int *value) {
    int result = 0, shift = 0, digit;
    
    while (**input) {
        digit = base64_decode_char(**input);
        if (digit == -1) return 0;
        
        (*input)++;
        result |= (digit & 31) << shift;
        if (!(digit & 32)) break;
        shift += 5;
    }
    
    *value = (result & 1) ? -(result >> 1) : (result >> 1);
    return 1;
}

static char **parse_json_array(JSContext *ctx, JSValue array, int *count) {
    *count = 0;
    if (!JS_IsArray(array)) return NULL;
    
    JSValue len_val = JS_GetPropertyStr(ctx, array, "length");
    int32_t len;
    if (JS_ToInt32(ctx, &len, len_val) < 0) {
        JS_FreeValue(ctx, len_val);
        return NULL;
    }
    JS_FreeValue(ctx, len_val);
    
    if (len <= 0) return NULL;
    
    char **result = malloc(len * sizeof(char*));
    if (!result) return NULL;
    
    int actual = 0;
    for (int i = 0; i < len; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, array, i);
        if (JS_IsString(item)) {
            const char *str = JS_ToCString(ctx, item);
            if (str) {
                result[actual++] = strdup(str);
                JS_FreeCString(ctx, str);
            }
        }
        JS_FreeValue(ctx, item);
    }
    
    *count = actual;
    return result;
}

static FileSourceMap *create_file_map(const char *file_path) {
    FileSourceMap *map = calloc(1, sizeof(FileSourceMap));
    if (!map) return NULL;
    
    map->file_path = strdup(file_path);
    map->hash_size = HASH_INIT_SIZE;
    map->hash_table = calloc(map->hash_size, sizeof(HashBucket));
    init_list_head(&map->mappings_list);
    map->ref_count = 1;
    
    if (!map->file_path || !map->hash_table) {
        free(map->file_path);
        free(map->hash_table);
        free(map);
        return NULL;
    }
    
    for (int i = 0; i < map->hash_size; i++) {
        init_list_head(&map->hash_table[i].head);
    }
    
    return map;
}

static void free_file_map(FileSourceMap *map) {
    if (!map) return;
    
    /* Free all mappings */
	struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &map->mappings_list) {
		struct MappingNode *node = list_entry(cur, MappingNode, list_link);
        list_del(&node->hash_link);
        list_del(&node->list_link);
        free(node->mapping.original_file);
        free(node->mapping.name);
        free(node);
    }
    
    free(map->hash_table);
    FREE_STR_ARRAY(map->sources, map->sources_count);
    FREE_STR_ARRAY(map->names, map->names_count);
    free(map->file_path);
    free(map);
}

static FileSourceMap *find_file_map(MappingContext *ctx, const char *path) {
    for (int i = 0; i < ctx->files_count; i++) {
        if (ctx->files[i] && strcmp(ctx->files[i]->file_path, path) == 0) {
            return ctx->files[i];
        }
    }
    return NULL;
}

static FileSourceMap *get_or_create_file_map(MappingContext *ctx, const char *path) {
    FileSourceMap *map = find_file_map(ctx, path);
    if (map) {
        map->ref_count++;
        return map;
    }
    
    map = create_file_map(path);
    if (!map) return NULL;
    
    /* Resize file array if needed */
    if (ctx->files_count >= ctx->files_capacity) {
        int new_cap = ctx->files_capacity ? ctx->files_capacity * 2 : FILE_INIT_CAPACITY;
        FileSourceMap **new_files = realloc(ctx->files, new_cap * sizeof(FileSourceMap*));
        if (!new_files) {
            free_file_map(map);
            return NULL;
        }
        ctx->files = new_files;
        ctx->files_capacity = new_cap;
    }
    
    ctx->files[ctx->files_count++] = map;
    return map;
}

static void insert_mapping(FileSourceMap *map, int gen_line, int gen_col,
                          int orig_line, int orig_col, const char *orig_file, const char *name) {
    MappingNode *node = malloc(sizeof(MappingNode));
    if (!node) return;
    
    node->key = MAKE_KEY(gen_line, gen_col);
    node->mapping = (SourceMapping){
        .generated_line = gen_line,
        .generated_column = gen_col,
        .original_line = orig_line,
        .original_column = orig_col,
        .original_file = orig_file ? strdup(orig_file) : NULL,
        .name = name ? strdup(name) : NULL
    };
    
    uint32_t hash = CALC_HASH(gen_line, gen_col, map->hash_size);
    list_add_tail(&node->list_link, &map->mappings_list);
    list_add(&node->hash_link, &map->hash_table[hash].head);
    map->mappings_count++;
}

static SourceMapping *find_exact_mapping(FileSourceMap *map, int line, int column) {
    uint32_t hash = CALC_HASH(line, column, map->hash_size);
    uint64_t key = MAKE_KEY(line, column);
    
    struct list_head *cur;
    list_for_each(cur, &map->hash_table[hash].head) {
		struct MappingNode* node = list_entry(cur, MappingNode, hash_link);
        if (node->key == key) return &node->mapping;
    }
    return NULL;
}

static SourceMapping *find_nearest_mapping(FileSourceMap *map, int line, int column) {
    struct list_head *cur;
    SourceMapping *best = NULL;
    
    /* List is in insertion order (sorted by generated position) */
    list_for_each(cur, &map->mappings_list) {
		struct MappingNode *node = list_entry(cur, MappingNode, list_link);
        if (node->mapping.generated_line < line ||
            (node->mapping.generated_line == line && node->mapping.generated_column <= column)) {
            if (!best || node->mapping.generated_line > best->generated_line ||
                (node->mapping.generated_line == best->generated_line && 
                 node->mapping.generated_column > best->generated_column)) {
                best = &node->mapping;
            }
        }
    }
    
    return best;
}

static int parse_mappings(FileSourceMap *map, const char *mappings_str) {
    if (!mappings_str) return 0;
    
    const char *p = mappings_str;
    int gen_line = 0, gen_col = 0;
    int src_idx = 0, orig_line = 0, orig_col = 0, name_idx = 0;
    
    while (*p) {
        if (*p == ';') {
            gen_line++;
            gen_col = 0;
            p++;
            continue;
        }
        
        if (*p == ',') {
            p++;
            continue;
        }
        
        int values[5] = {0}, cnt = 0;
        while (*p && *p != ',' && *p != ';' && cnt < 5) {
            if (!decode_vlq(&p, &values[cnt++])) break;
        }
        
        if (cnt >= 1) {
            gen_col += values[0];
            if (cnt >= 4) {
                src_idx += values[1];
                orig_line += values[2];
                orig_col += values[3];
                
                const char *orig_file = NULL;
                if (src_idx >= 0 && src_idx < map->sources_count) {
                    orig_file = map->sources[src_idx];
                }
                
                const char *name = NULL;
                if (cnt >= 5) {
                    name_idx += values[4];
                    if (name_idx >= 0 && name_idx < map->names_count) {
                        name = map->names[name_idx];
                    }
                }
                
                insert_mapping(map, gen_line, gen_col, orig_line, orig_col, orig_file, name);
            }
        }
    }
    
    return 1;
}

#pragma region JS Public API

MappingContext *js_create_mapping_context(void) {
    MappingContext *ctx = calloc(1, sizeof(MappingContext));
    if (!ctx) return NULL;
    
    ctx->files_capacity = FILE_INIT_CAPACITY;
    ctx->files = calloc(ctx->files_capacity, sizeof(FileSourceMap*));
    if (!ctx->files) {
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void js_destroy_mapping_context(MappingContext *ctx) {
    if (!ctx) return;
    
    for (int i = 0; i < ctx->files_count; i++) {
        if (ctx->files[i]) free_file_map(ctx->files[i]);
    }
    
    free(ctx->files);
    free(ctx);
}

bool js_has_sourcemap(MappingContext *ctx, const char *file_path) {
    return file_path && find_file_map(ctx, file_path) != NULL;
}

int js_load_sourcemap(MappingContext *ctx, JSContext *js_ctx, 
                     const char *file_path, JSValue sm_obj) {
    if (!ctx || !file_path || !JS_IsObject(sm_obj)) return 0;
    
    FileSourceMap *map = get_or_create_file_map(ctx, file_path);
    if (!map) return 0;
    
    /* Clear existing mappings */
	struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &map->mappings_list) {
		struct MappingNode *node = list_entry(cur, MappingNode, list_link);
        list_del(&node->hash_link);
        list_del(&node->list_link);
        free(node->mapping.original_file);
        free(node->mapping.name);
        free(node);
    }
    init_list_head(&map->mappings_list);
    map->mappings_count = 0;
    
    FREE_STR_ARRAY(map->sources, map->sources_count);
    FREE_STR_ARRAY(map->names, map->names_count);
    map->sources = map->names = NULL;
    map->sources_count = map->names_count = 0;
    
    /* Parse JSON */
    JSValue sources = JS_GetPropertyStr(js_ctx, sm_obj, "sources");
    if (JS_IsArray(sources)) {
        map->sources = parse_json_array(js_ctx, sources, &map->sources_count);
    }
    JS_FreeValue(js_ctx, sources);
    
    JSValue names = JS_GetPropertyStr(js_ctx, sm_obj, "names");
    if (JS_IsArray(names)) {
        map->names = parse_json_array(js_ctx, names, &map->names_count);
    }
    JS_FreeValue(js_ctx, names);
    
    int success = 0;
    JSValue mappings_val = JS_GetPropertyStr(js_ctx, sm_obj, "mappings");
    const char *mappings_str = JS_ToCString(js_ctx, mappings_val);
    if (mappings_str) {
        success = parse_mappings(map, mappings_str);
        JS_FreeCString(js_ctx, mappings_str);
    }
    JS_FreeValue(js_ctx, mappings_val);
    
    return success;
}

int js_load_sourcemap_cjson(MappingContext *ctx, JSContext *js_ctx, 
                           const char *file_path, const char *json_str) {
    if (!ctx || !file_path || !json_str) return 0;
    
    JSValue json_obj = JS_ParseJSON(js_ctx, json_str, strlen(json_str), "<sourcemap>");
    if (JS_IsException(json_obj)) return 0;
    
    int result = js_load_sourcemap(ctx, js_ctx, file_path, json_obj);
    JS_FreeValue(js_ctx, json_obj);
    return result;
}

MappingResult js_get_source_mapping(MappingContext *ctx, const char *file_path, 
                                   int gen_line, int gen_col) {
    MappingResult result = {0};
    
    if (!ctx || !file_path) return result;
    
    FileSourceMap *map = find_file_map(ctx, file_path);
    if (!map) return result;
    
    SourceMapping *mapping = find_exact_mapping(map, gen_line - 1, gen_col);
    if (!mapping) mapping = find_nearest_mapping(map, gen_line - 1, gen_col);
    
    if (mapping && mapping->original_file) {
        result.original_file = mapping->original_file;
        result.original_line = mapping->original_line + 1;
        result.original_column = mapping->original_column;
        result.function_name = mapping->name;
        result.found = 1;
    } else {
        result.original_line = gen_line;
        result.original_column = gen_col;
        result.found = 0;
    }
    
    return result;
}

bool js_remove_sourcemap(MappingContext *ctx, const char *file_path) {
    if (!ctx || !file_path) return false;
    
    for (int i = 0; i < ctx->files_count; i++) {
        if (ctx->files[i] && strcmp(ctx->files[i]->file_path, file_path) == 0) {
            free_file_map(ctx->files[i]);
            /* Swap with last element for O(1) removal */
            if (i < ctx->files_count - 1) {
                ctx->files[i] = ctx->files[ctx->files_count - 1];
            }
            ctx->files_count--;
            return true;
        }
    }
    
    return false;
}

static JSValue tjs__has_sourcemap(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_EXCEPTION;
    
    const char *file_path = JS_ToCString(ctx, argv[0]);
    if (!file_path) return JS_EXCEPTION;

    TJSRuntime *rt = TJS_GetRuntime(ctx);
    bool has = js_has_sourcemap(rt->module.mapctx, file_path);

    JS_FreeCString(ctx, file_path);
    return JS_NewBool(ctx, has);
}

static JSValue tjs__load_sourcemap(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 2) return JS_EXCEPTION;
    
    const char *file_path = JS_ToCString(ctx, argv[0]);
    if (!file_path) return JS_EXCEPTION;

    TJSRuntime *rt = TJS_GetRuntime(ctx);
    int ret = js_load_sourcemap(rt->module.mapctx, ctx, file_path, argv[1]);

    JS_FreeCString(ctx, file_path);
    return JS_NewInt32(ctx, ret);
}

static JSValue tjs__load_sourcemap_cjson(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 2) return JS_EXCEPTION;
    
    const char *file_path = JS_ToCString(ctx, argv[0]);
    const char *json_str = JS_ToCString(ctx, argv[1]);
    if (!file_path || !json_str) {
        if (file_path) JS_FreeCString(ctx, file_path);
        if (json_str) JS_FreeCString(ctx, json_str);
        return JS_EXCEPTION;
    }

    TJSRuntime *rt = TJS_GetRuntime(ctx);
    int ret = js_load_sourcemap_cjson(rt->module.mapctx, ctx, file_path, json_str);

    JS_FreeCString(ctx, file_path);
    JS_FreeCString(ctx, json_str);
    return JS_NewInt32(ctx, ret);
}

static JSValue tjs__get_source_mapping(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 3) return JS_EXCEPTION;
    
    const char *file_path = JS_ToCString(ctx, argv[0]);
    int line, col;
    if (!file_path || JS_ToInt32(ctx, &line, argv[1]) || JS_ToInt32(ctx, &col, argv[2])) {
        if (file_path) JS_FreeCString(ctx, file_path);
        return JS_EXCEPTION;
    }

    TJSRuntime *rt = TJS_GetRuntime(ctx);
    MappingResult res = js_get_source_mapping(rt->module.mapctx, file_path, line, col);

    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "original_file", JS_NewString(ctx, res.original_file ? res.original_file : ""));
    JS_SetPropertyStr(ctx, obj, "original_line", JS_NewInt32(ctx, res.original_line));
    JS_SetPropertyStr(ctx, obj, "original_column", JS_NewInt32(ctx, res.original_column));
    JS_SetPropertyStr(ctx, obj, "function_name", JS_NewString(ctx, res.function_name ? res.function_name : ""));
    JS_SetPropertyStr(ctx, obj, "found", JS_NewBool(ctx, res.found));

    JS_FreeCString(ctx, file_path);
    return obj;
}

static JSValue tjs__remove_sourcemap(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_EXCEPTION;
    
    const char *file_path = JS_ToCString(ctx, argv[0]);
    if (!file_path) return JS_EXCEPTION;

    TJSRuntime *rt = TJS_GetRuntime(ctx);
    bool removed = js_remove_sourcemap(rt->module.mapctx, file_path);

    JS_FreeCString(ctx, file_path);
    return JS_NewBool(ctx, removed);
}

static const JSCFunctionListEntry js_sourcemap_funcs[] = {
    JS_CFUNC_DEF("has", 1, tjs__has_sourcemap),
    JS_CFUNC_DEF("load", 2, tjs__load_sourcemap),
    JS_CFUNC_DEF("loadJSON", 2, tjs__load_sourcemap_cjson),
    JS_CFUNC_DEF("getMapping", 3, tjs__get_source_mapping),
    JS_CFUNC_DEF("remove", 1, tjs__remove_sourcemap),
};

void tjs__mod_sourcemap_init(JSContext *ctx, JSValue ns) {
	JS_SetPropertyFunctionList(ctx, ns, js_sourcemap_funcs, countof(js_sourcemap_funcs));
}