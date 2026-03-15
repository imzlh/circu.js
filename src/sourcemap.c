/**
 * circu.js SourceMap Extension
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../deps/quickjs/list.h"

#include "private.h"
#include "sourcemap.h"

/* ---------- Constants ---------- */

#define HASH_INIT_SIZE     1024
#define FILE_INIT_CAPACITY 16
#define SORTED_INIT_CAP    256

#define CALC_HASH(line, col, size) (hash_position((line), (col)) % (size))
#define MAKE_KEY(line, col)        (((uint64_t)(uint32_t)(line) << 32) | (uint32_t)(col))

#define FREE_STR_ARRAY(arr, cnt) \
    do { \
        if (arr) { \
            for (int _i = 0; _i < (cnt); _i++) free((arr)[_i]); \
            free(arr); \
            (arr) = NULL; \
        } \
    } while (0)

/* ---------- Structures ---------- */

/*
 * Compact mapping: stores source/name as indices into the FileSourceMap arrays
 * rather than duplicating the strings per node.  A typical source map has
 * thousands of mappings all pointing to the same handful of source files, so
 * this eliminates O(n) strdup calls and the matching O(n) free calls.
 */
typedef struct {
    int generated_line;
    int generated_column;
    int original_line;
    int original_column;
    int source_idx;   /* into FileSourceMap.sources; -1 = unknown */
    int name_idx;     /* into FileSourceMap.names;   -1 = unknown */
} SourceMapping;

typedef struct MappingNode {
    uint64_t key;
    SourceMapping mapping;
    struct list_head hash_link;
    struct list_head list_link;
} MappingNode;

typedef struct {
    struct list_head head;
} HashBucket;

typedef struct FileSourceMap {
    char *file_path;
    char **sources;
    int   sources_count;
    char **names;
    int   names_count;

    HashBucket *hash_table;
    int         hash_size;
    struct list_head mappings_list;
    int              mappings_count;
    int              ref_count;

    /*
     * Flat sorted array of node pointers, used for O(log n) nearest-mapping
     * binary search.  Rebuilt lazily (sorted_dirty flag) after any insert.
     */
    MappingNode **sorted;
    int           sorted_count;
    int           sorted_cap;
    int           sorted_dirty;
} FileSourceMap;

struct MappingContext {
    FileSourceMap **files;
    int files_count;
    int files_capacity;
};

/* ---------- Internal helpers ---------- */

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
        if (shift > 30) return 0;  /* guard malformed input */
    }
    *value = (result & 1) ? -(result >> 1) : (result >> 1);
    return 1;
}

static char **parse_json_array(JSContext *ctx, JSValue array, int *count) {
    *count = 0;
    if (!JS_IsArray(array)) return NULL;

    JSValue len_val = JS_GetPropertyStr(ctx, array, "length");
    int32_t len = 0;
    if (JS_ToInt32(ctx, &len, len_val) < 0 || len <= 0) {
        JS_FreeValue(ctx, len_val);
        return NULL;
    }
    JS_FreeValue(ctx, len_val);

    char **result = malloc(len * sizeof(char *));
    if (!result) return NULL;

    int actual = 0;
    for (int i = 0; i < len; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, array, i);
        if (JS_IsString(item)) {
            const char *str = JS_ToCString(ctx, item);
            if (str) {
                char *dup = strdup(str);
                JS_FreeCString(ctx, str);
                if (dup) result[actual++] = dup;
                /* OOM: skip entry; index gaps are handled by range checks */
            }
        }
        JS_FreeValue(ctx, item);
    }

    *count = actual;
    return result;
}

/* ---------- FileSourceMap lifecycle ---------- */

static FileSourceMap *create_file_map(const char *file_path) {
    FileSourceMap *map = calloc(1, sizeof(FileSourceMap));
    if (!map) return NULL;

    map->file_path  = strdup(file_path);
    map->hash_size  = HASH_INIT_SIZE;
    map->hash_table = calloc(map->hash_size, sizeof(HashBucket));
    map->ref_count  = 1;
    map->sorted_dirty = 1;

    if (!map->file_path || !map->hash_table) {
        free(map->file_path);
        free(map->hash_table);
        free(map);
        return NULL;
    }

    init_list_head(&map->mappings_list);
    for (int i = 0; i < map->hash_size; i++)
        init_list_head(&map->hash_table[i].head);

    return map;
}

/* Free all mapping nodes and reset hash buckets.  Does NOT free sources/names. */
static void clear_mappings(FileSourceMap *map) {
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &map->mappings_list) {
        MappingNode *node = list_entry(cur, MappingNode, list_link);
        list_del(&node->hash_link);
        list_del(&node->list_link);
        free(node);   /* no per-node strings any more */
    }
    init_list_head(&map->mappings_list);

    /* Re-init every bucket so no stale list_head pointers remain */
    for (int i = 0; i < map->hash_size; i++)
        init_list_head(&map->hash_table[i].head);

    map->mappings_count = 0;

    free(map->sorted);
    map->sorted       = NULL;
    map->sorted_count = 0;
    map->sorted_cap   = 0;
    map->sorted_dirty = 1;
}

static void free_file_map(FileSourceMap *map) {
    if (!map) return;
    clear_mappings(map);
    free(map->hash_table);
    FREE_STR_ARRAY(map->sources, map->sources_count);
    FREE_STR_ARRAY(map->names,   map->names_count);
    free(map->file_path);
    free(map);
}

/* ---------- Context helpers ---------- */

static FileSourceMap *find_file_map(MappingContext *ctx, const char *path) {
    for (int i = 0; i < ctx->files_count; i++)
        if (ctx->files[i] && strcmp(ctx->files[i]->file_path, path) == 0)
            return ctx->files[i];
    return NULL;
}

static FileSourceMap *get_or_create_file_map(MappingContext *ctx, const char *path) {
    FileSourceMap *map = find_file_map(ctx, path);
    if (map) { map->ref_count++; return map; }

    map = create_file_map(path);
    if (!map) return NULL;

    if (ctx->files_count >= ctx->files_capacity) {
        int nc = ctx->files_capacity ? ctx->files_capacity * 2 : FILE_INIT_CAPACITY;
        FileSourceMap **nf = realloc(ctx->files, nc * sizeof(FileSourceMap *));
        if (!nf) { free_file_map(map); return NULL; }
        ctx->files = nf;
        ctx->files_capacity = nc;
    }
    ctx->files[ctx->files_count++] = map;
    return map;
}

/* ---------- Insert / lookup ---------- */

static void insert_mapping(FileSourceMap *map, int gl, int gc,
                            int ol, int oc, int sidx, int nidx) {
    MappingNode *node = malloc(sizeof(MappingNode));
    if (!node) return;

    node->key = MAKE_KEY(gl, gc);
    node->mapping = (SourceMapping){
        .generated_line   = gl,
        .generated_column = gc,
        .original_line    = ol,
        .original_column  = oc,
        .source_idx       = sidx,
        .name_idx         = nidx,
    };

    uint32_t h = CALC_HASH(gl, gc, map->hash_size);
    list_add_tail(&node->list_link, &map->mappings_list);
    list_add(&node->hash_link, &map->hash_table[h].head);
    map->mappings_count++;
    map->sorted_dirty = 1;
}

/* O(1) exact lookup via hash */
static SourceMapping *find_exact_mapping(FileSourceMap *map, int line, int col) {
    uint32_t h   = CALC_HASH(line, col, map->hash_size);
    uint64_t key = MAKE_KEY(line, col);
    struct list_head *cur;
    list_for_each(cur, &map->hash_table[h].head) {
        MappingNode *node = list_entry(cur, MappingNode, hash_link);
        if (node->key == key) return &node->mapping;
    }
    return NULL;
}

static int cmp_node_ptr(const void *a, const void *b) {
    const MappingNode *na = *(const MappingNode *const *)a;
    const MappingNode *nb = *(const MappingNode *const *)b;
    if (na->mapping.generated_line != nb->mapping.generated_line)
        return na->mapping.generated_line - nb->mapping.generated_line;
    return na->mapping.generated_column - nb->mapping.generated_column;
}

/* Rebuild sorted[] from the linked list.  O(n log n), called once per batch. */
static void rebuild_sorted(FileSourceMap *map) {
    if (!map->sorted_dirty) return;

    int n = map->mappings_count;
    if (n == 0) { map->sorted_count = 0; map->sorted_dirty = 0; return; }

    if (n > map->sorted_cap) {
        int nc = map->sorted_cap ? map->sorted_cap : SORTED_INIT_CAP;
        while (nc < n) nc *= 2;
        MappingNode **ns = realloc(map->sorted, nc * sizeof(MappingNode *));
        if (!ns) return;  /* stay dirty; retry next call */
        map->sorted     = ns;
        map->sorted_cap = nc;
    }

    int idx = 0;
    struct list_head *cur;
    list_for_each(cur, &map->mappings_list)
        map->sorted[idx++] = list_entry(cur, MappingNode, list_link);

    qsort(map->sorted, n, sizeof(MappingNode *), cmp_node_ptr);
    map->sorted_count = n;
    map->sorted_dirty = 0;
}

/*
 * O(log n) nearest-mapping: find the largest (line,col) <= (target_line, target_col).
 * This replaces the original O(n) linear scan.
 */
static SourceMapping *find_nearest_mapping(FileSourceMap *map, int line, int col) {
    rebuild_sorted(map);
    if (map->sorted_count == 0) return NULL;

    int lo = 0, hi = map->sorted_count - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        MappingNode *n = map->sorted[mid];
        int dl = n->mapping.generated_line - line;
        int dc = n->mapping.generated_column - col;

        if (dl < 0 || (dl == 0 && dc <= 0)) {
            best = mid;
            lo   = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return best >= 0 ? &map->sorted[best]->mapping : NULL;
}

/* ---------- Mapping string parser ---------- */

static int parse_mappings(FileSourceMap *map, const char *mappings_str) {
    if (!mappings_str) return 0;

    const char *p = mappings_str;
    int gen_line = 0, gen_col = 0;
    int src_idx  = 0, orig_line = 0, orig_col = 0, name_idx = 0;

    while (*p) {
        if (*p == ';') { gen_line++; gen_col = 0; p++; continue; }
        if (*p == ',') { p++; continue; }

        int values[5] = {0}, cnt = 0;
        while (*p && *p != ',' && *p != ';' && cnt < 5)
            if (!decode_vlq(&p, &values[cnt++])) break;

        if (cnt >= 4) {
            gen_col   += values[0];
            src_idx   += values[1];
            orig_line += values[2];
            orig_col  += values[3];

            int sidx = (src_idx  >= 0 && src_idx  < map->sources_count) ? src_idx  : -1;
            int nidx = -1;
            if (cnt >= 5) {
                name_idx += values[4];
                nidx = (name_idx >= 0 && name_idx < map->names_count) ? name_idx : -1;
            }
            insert_mapping(map, gen_line, gen_col, orig_line, orig_col, sidx, nidx);
        } else if (cnt == 1) {
            gen_col += values[0];
        }
    }
    return 1;
}

/* ---------- Public C API ---------- */

MappingContext *js_create_mapping_context(void) {
    MappingContext *ctx = calloc(1, sizeof(MappingContext));
    if (!ctx) return NULL;
    ctx->files_capacity = FILE_INIT_CAPACITY;
    ctx->files = calloc(ctx->files_capacity, sizeof(FileSourceMap *));
    if (!ctx->files) { free(ctx); return NULL; }
    return ctx;
}

void js_destroy_mapping_context(MappingContext *ctx) {
    if (!ctx) return;
    for (int i = 0; i < ctx->files_count; i++)
        if (ctx->files[i]) free_file_map(ctx->files[i]);
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

    clear_mappings(map);
    FREE_STR_ARRAY(map->sources, map->sources_count);
    FREE_STR_ARRAY(map->names,   map->names_count);

    JSValue sources = JS_GetPropertyStr(js_ctx, sm_obj, "sources");
    if (JS_IsArray(sources))
        map->sources = parse_json_array(js_ctx, sources, &map->sources_count);
    JS_FreeValue(js_ctx, sources);

    JSValue names = JS_GetPropertyStr(js_ctx, sm_obj, "names");
    if (JS_IsArray(names))
        map->names = parse_json_array(js_ctx, names, &map->names_count);
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

    /* QJS line numbers are 1-based; mappings are 0-based */
    int line0 = gen_line - 1;
    SourceMapping *mapping = find_exact_mapping(map, line0, gen_col);
    if (!mapping) mapping = find_nearest_mapping(map, line0, gen_col);

    if (mapping && mapping->source_idx >= 0) {
        result.original_file   = map->sources[mapping->source_idx];
        result.original_line   = mapping->original_line + 1;
        result.original_column = mapping->original_column;
        result.function_name   = (mapping->name_idx >= 0)
                                   ? map->names[mapping->name_idx] : NULL;
        result.found = 1;
    } else {
        result.original_line   = gen_line;
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
            if (i < ctx->files_count - 1)
                ctx->files[i] = ctx->files[ctx->files_count - 1];
            ctx->files_count--;
            return true;
        }
    }
    return false;
}

/* ---------- JS bindings ---------- */

static JSValue tjs__has_sourcemap(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    if (argc < 1) return JS_EXCEPTION;
    const char *fp = JS_ToCString(ctx, argv[0]);
    if (!fp) return JS_EXCEPTION;
    TJSRuntime *rt = TJS_GetRuntime(ctx);
    bool has = js_has_sourcemap(rt->module.mapctx, fp);
    JS_FreeCString(ctx, fp);
    return JS_NewBool(ctx, has);
}

static JSValue tjs__load_sourcemap(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
    if (argc < 2) return JS_EXCEPTION;
    const char *fp = JS_ToCString(ctx, argv[0]);
    if (!fp) return JS_EXCEPTION;
    TJSRuntime *rt = TJS_GetRuntime(ctx);
    int ret = js_load_sourcemap(rt->module.mapctx, ctx, fp, argv[1]);
    JS_FreeCString(ctx, fp);
    return JS_NewInt32(ctx, ret);
}

static JSValue tjs__load_sourcemap_cjson(JSContext *ctx, JSValueConst this_val,
                                          int argc, JSValueConst *argv) {
    if (argc < 2) return JS_EXCEPTION;
    const char *fp = JS_ToCString(ctx, argv[0]);
    const char *js = JS_ToCString(ctx, argv[1]);
    if (!fp || !js) {
        JS_FreeCString(ctx, fp);
        JS_FreeCString(ctx, js);
        return JS_EXCEPTION;
    }
    TJSRuntime *rt = TJS_GetRuntime(ctx);
    int ret = js_load_sourcemap_cjson(rt->module.mapctx, ctx, fp, js);
    JS_FreeCString(ctx, fp);
    JS_FreeCString(ctx, js);
    return JS_NewInt32(ctx, ret);
}

static JSValue tjs__get_source_mapping(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    if (argc < 3) return JS_EXCEPTION;
    const char *fp = JS_ToCString(ctx, argv[0]);
    int line, col;
    if (!fp || JS_ToInt32(ctx, &line, argv[1]) || JS_ToInt32(ctx, &col, argv[2])) {
        JS_FreeCString(ctx, fp);
        return JS_EXCEPTION;
    }
    TJSRuntime *rt = TJS_GetRuntime(ctx);
    MappingResult res = js_get_source_mapping(rt->module.mapctx, fp, line, col);
    JS_FreeCString(ctx, fp);

    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "original_file",
        JS_NewString(ctx, res.original_file   ? res.original_file   : ""));
    JS_SetPropertyStr(ctx, obj, "original_line",   JS_NewInt32(ctx, res.original_line));
    JS_SetPropertyStr(ctx, obj, "original_column", JS_NewInt32(ctx, res.original_column));
    JS_SetPropertyStr(ctx, obj, "function_name",
        JS_NewString(ctx, res.function_name   ? res.function_name   : ""));
    JS_SetPropertyStr(ctx, obj, "found", JS_NewBool(ctx, res.found));
    return obj;
}

static JSValue tjs__remove_sourcemap(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    if (argc < 1) return JS_EXCEPTION;
    const char *fp = JS_ToCString(ctx, argv[0]);
    if (!fp) return JS_EXCEPTION;
    TJSRuntime *rt = TJS_GetRuntime(ctx);
    bool removed = js_remove_sourcemap(rt->module.mapctx, fp);
    JS_FreeCString(ctx, fp);
    return JS_NewBool(ctx, removed);
}

static const JSCFunctionListEntry js_sourcemap_funcs[] = {
    JS_CFUNC_DEF("has",        1, tjs__has_sourcemap),
    JS_CFUNC_DEF("load",       2, tjs__load_sourcemap),
    JS_CFUNC_DEF("loadJSON",   2, tjs__load_sourcemap_cjson),
    JS_CFUNC_DEF("getMapping", 3, tjs__get_source_mapping),
    JS_CFUNC_DEF("remove",     1, tjs__remove_sourcemap),
};

void tjs__mod_sourcemap_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, js_sourcemap_funcs, countof(js_sourcemap_funcs));
}
