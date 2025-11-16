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
#include <pthread.h>
#include <stdint.h>

#include "private.h"
#include "sourcemap.h"

typedef struct {
    int generated_line;
    int generated_column;
    int original_line;
    int original_column;
    char *original_file;
    char *name;
} SourceMapping;

// mapping node using hash table
typedef struct MappingNode {
    uint64_t key;               // (line << 32) | column
    SourceMapping mapping;
    struct MappingNode *next;
} MappingNode;

// 单个文件的SourceMap
typedef struct {
    char *file_path;            // file path
    char **sources;             // sources
    int sources_count;
    char **names;               // name
    int names_count;
    MappingNode **hash_table;   // hash table
    int hash_size;
    pthread_rwlock_t rwlock;    // rwlock
    int ref_count;              // refcount
} FileSourceMap;

// global source map manager
typedef struct {
    FileSourceMap **files;      // file array
    int files_count;
    int files_capacity;
    pthread_rwlock_t global_rwlock;  // global rwlock
} SourceMapManager;

static SourceMapManager g_manager = {0};
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

// initialize source map manager
__attribute__((constructor)) static void init_manager() {
    memset(&g_manager, 0, sizeof(g_manager));
    pthread_rwlock_init(&g_manager.global_rwlock, NULL);
    g_manager.files_capacity = 16;
    g_manager.files = calloc(g_manager.files_capacity, sizeof(FileSourceMap*));
}

// hash function for mapping node
static uint32_t hash_position(int line, int column) {
    uint64_t key = ((uint64_t)line << 32) | (uint32_t)column;
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccd;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53;
    key ^= key >> 33;
    return (uint32_t)key;
}

// position key
static uint64_t make_position_key(int line, int column) {
    return ((uint64_t)line << 32) | (uint32_t)column;
}

static inline int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// VLQ decode
static int decode_vlq(const char **input, int *value) {
    int result = 0;
    int shift = 0;
    int continuation = 1;
    
    while (continuation && **input) {
        int digit = base64_decode_char(**input);
        if (digit == -1) return 0;
        
        continuation = digit & 1;
        digit >>= 1;
        
        result += digit << shift;
        shift += 5;
        (*input)++;
    }
    
    if (result & 1) {
        *value = -(result >> 1);
    } else {
        *value = result >> 1;
    }
    
    return 1;
}

// parse source map array
static char **parse_json_array(JSContext *ctx, JSValue array, int *count) {
    *count = 0;
    
    if (!JS_IsArray(array)) return NULL;
    
    JSValue length_val = JS_GetPropertyStr(ctx, array, "length");
    int32_t length;
    if (JS_ToInt32(ctx, &length, length_val) < 0) {
        JS_FreeValue(ctx, length_val);
        return NULL;
    }
    JS_FreeValue(ctx, length_val);
    
    if (length <= 0) return NULL;
    
    char **result = malloc(length * sizeof(char*));
    if (!result) return NULL;
    
    int actual_count = 0;
    for (int i = 0; i < length; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, array, i);
        if (JS_IsString(item)) {
            const char *str = JS_ToCString(ctx, item);
            if (str) {
                result[actual_count] = strdup(str);
                JS_FreeCString(ctx, str);
                actual_count++;
            }
        }
        JS_FreeValue(ctx, item);
    }
    
    *count = actual_count;
    return result;
}

// release string array
static void free_string_array(char **array, int count) {
    if (!array) return;
    for (int i = 0; i < count; i++) {
        free(array[i]);
    }
    free(array);
}

// insert into hash table
static void insert_mapping(FileSourceMap *file_map, int gen_line, int gen_col,
                          int orig_line, int orig_col, const char *orig_file, const char *name) {
    uint64_t key = make_position_key(gen_line, gen_col);
    uint32_t hash = hash_position(gen_line, gen_col) % file_map -> hash_size;
    
    MappingNode *node = malloc(sizeof(MappingNode));
    if (!node) return;
    
    node -> key = key;
    node -> mapping.generated_line = gen_line;
    node -> mapping.generated_column = gen_col;
    node -> mapping.original_line = orig_line;
    node -> mapping.original_column = orig_col;
    node -> mapping.original_file = orig_file ? strdup(orig_file) : NULL;
    node -> mapping.name = name ? strdup(name) : NULL;
    
    node -> next = file_map -> hash_table[hash];
    file_map -> hash_table[hash] = node;
}

// find mapping in hash table
static SourceMapping *find_mapping(FileSourceMap *file_map, int line, int column) {
    if (!file_map || !file_map -> hash_table) return NULL;
    
    uint64_t key = make_position_key(line, column);
    uint32_t hash = hash_position(line, column) % file_map -> hash_size;
    
    MappingNode *node = file_map -> hash_table[hash];
    while (node) {
        if (node -> key == key) {
            return &node -> mapping;
        }
        node = node -> next;
    }
    
    // no exact match, find the nearest match
    SourceMapping *best_match = NULL;
    for (int i = 0; i < file_map -> hash_size; i++) {
        node = file_map -> hash_table[i];
        while (node) {
            if (node -> mapping.generated_line < line || 
                (node -> mapping.generated_line == line && node -> mapping.generated_column <= column)) {
                if (!best_match || 
                    node -> mapping.generated_line > best_match -> generated_line ||
                    (node -> mapping.generated_line == best_match -> generated_line && 
                     node -> mapping.generated_column > best_match -> generated_column)) {
                    best_match = &node -> mapping;
                }
            }
            node = node -> next;
        }
    }
    
    return best_match;
}

// parse source map
static int parse_mappings(FileSourceMap *file_map, const char *mappings_str) {
    if (!mappings_str) return 0;
    
    const char *p = mappings_str;
    int generated_line = 0;
    int generated_column = 0;
    int source_index = 0;
    int original_line = 0;
    int original_column = 0;
    int name_index = 0;
    
    while (*p) {
        if (*p == ';') {
            generated_line++;
            generated_column = 0;
            p++;
            continue;
        }
        
        if (*p == ',') {
            p++;
            continue;
        }
        
        int values[5];
        int value_count = 0;
        
        while (*p && *p != ',' && *p != ';' && value_count < 5) {
            int value;
            if (!decode_vlq(&p, &value)) break;
            values[value_count++] = value;
        }
        
        if (value_count >= 1) {
            generated_column += values[0];
            
            if (value_count >= 4) {
                source_index += values[1];
                original_line += values[2];
                original_column += values[3];
                
                const char *orig_file = NULL;
                if (source_index >= 0 && source_index < file_map -> sources_count) {
                    orig_file = file_map -> sources[source_index];
                }
                
                const char *name = NULL;
                if (value_count >= 5) {
                    name_index += values[4];
                    if (name_index >= 0 && name_index < file_map -> names_count) {
                        name = file_map -> names[name_index];
                    }
                }
                
                insert_mapping(file_map, generated_line, generated_column,
                             original_line, original_column, orig_file, name);
            }
        }
    }
    
    return 1;
}

// create file source map
static FileSourceMap *create_file_sourcemap(const char *file_path) {
    FileSourceMap *file_map = calloc(1, sizeof(FileSourceMap));
    if (!file_map) return NULL;
    
    file_map -> file_path = strdup(file_path);
    file_map -> hash_size = 1024;
    file_map -> hash_table = calloc(file_map -> hash_size, sizeof(MappingNode*));
    file_map -> ref_count = 1;
    
    if (pthread_rwlock_init(&file_map -> rwlock, NULL) != 0) {
        free(file_map -> file_path);
        free(file_map -> hash_table);
        free(file_map);
        return NULL;
    }
    
    return file_map;
}

// release file source map
static void free_file_sourcemap(FileSourceMap *file_map) {
    if (!file_map) return;
    
    if (file_map -> hash_table) {
        for (int i = 0; i < file_map -> hash_size; i++) {
            MappingNode *node = file_map -> hash_table[i];
            while (node) {
                MappingNode *next = node -> next;
                free(node -> mapping.original_file);
                free(node -> mapping.name);
                free(node);
                node = next;
            }
        }
        free(file_map -> hash_table);
    }
    
    free_string_array(file_map -> sources, file_map -> sources_count);
    free_string_array(file_map -> names, file_map -> names_count);
    free(file_map -> file_path);
    pthread_rwlock_destroy(&file_map -> rwlock);
    free(file_map);
}

// find or create file source map
static FileSourceMap *get_or_create_file_map(const char *file_path) {
    pthread_once(&g_init_once, init_manager);
    
    pthread_rwlock_rdlock(&g_manager.global_rwlock);
    
    FileSourceMap *found = NULL;
    for (int i = 0; i < g_manager.files_count; i++) {
        if (g_manager.files[i] && strcmp(g_manager.files[i] -> file_path, file_path) == 0) {
            found = g_manager.files[i];
            found -> ref_count++;
            break;
        }
    }
    
    pthread_rwlock_unlock(&g_manager.global_rwlock);
    
    if (found) return found;
    
    // not found, create a new one
    FileSourceMap *new_map = create_file_sourcemap(file_path);
    if (!new_map) return NULL;
    
    pthread_rwlock_wrlock(&g_manager.global_rwlock);
    
    if (g_manager.files_count >= g_manager.files_capacity) {
        g_manager.files_capacity *= 2;
        FileSourceMap **new_files = realloc(g_manager.files, 
            g_manager.files_capacity * sizeof(FileSourceMap*));
        if (!new_files) {
            pthread_rwlock_unlock(&g_manager.global_rwlock);
            free_file_sourcemap(new_map);
            return NULL;
        }
        g_manager.files = new_files;
    }
    
    g_manager.files[g_manager.files_count++] = new_map;
    
    pthread_rwlock_unlock(&g_manager.global_rwlock);
    
    return new_map;
}

// load global source map
int js_load_sourcemap(JSContext *ctx, const char *file_path, JSValue sourcemap_obj) {
    if (!file_path || !JS_IsObject(sourcemap_obj)) {
        return 0;
    }
    
    FileSourceMap *file_map = get_or_create_file_map(file_path);
    if (!file_map) return 0;
    
    pthread_rwlock_wrlock(&file_map -> rwlock);
    
    // 清除现有映射
    if (file_map -> hash_table) {
        for (int i = 0; i < file_map -> hash_size; i++) {
            MappingNode *node = file_map -> hash_table[i];
            while (node) {
                MappingNode *next = node -> next;
                free(node -> mapping.original_file);
                free(node -> mapping.name);
                free(node);
                node = next;
            }
            file_map -> hash_table[i] = NULL;
        }
    }
    
    free_string_array(file_map -> sources, file_map -> sources_count);
    free_string_array(file_map -> names, file_map -> names_count);
    file_map -> sources = NULL;
    file_map -> names = NULL;
    file_map -> sources_count = 0;
    file_map -> names_count = 0;
    
    int success = 0;
    
    // 解析sources
    JSValue sources = JS_GetPropertyStr(ctx, sourcemap_obj, "sources");
    if (JS_IsArray(sources)) {
        file_map -> sources = parse_json_array(ctx, sources, &file_map -> sources_count);
    }
    JS_FreeValue(ctx, sources);
    
    // 解析names
    JSValue names = JS_GetPropertyStr(ctx, sourcemap_obj, "names");
    if (JS_IsArray(names)) {
        file_map -> names = parse_json_array(ctx, names, &file_map -> names_count);
    }
    JS_FreeValue(ctx, names);
    
    // 解析mappings
    JSValue mappings_val = JS_GetPropertyStr(ctx, sourcemap_obj, "mappings");
    const char *mappings_str = JS_ToCString(ctx, mappings_val);
    if (mappings_str) {
        success = parse_mappings(file_map, mappings_str);
        JS_FreeCString(ctx, mappings_str);
    }
    JS_FreeValue(ctx, mappings_val);
    
    pthread_rwlock_unlock(&file_map -> rwlock);
    
    return success;
}

// 从JSON字符串加载
int js_load_sourcemap_cjson(JSContext *ctx, const char *file_path, const char *json_str) {
    JSValue json_obj = JS_ParseJSON(ctx, json_str, strlen(json_str), "<sourcemap>");
    if (JS_IsException(json_obj)) {
        return 0;
    }
    
    int result = js_load_sourcemap(ctx, file_path, json_obj);
    JS_FreeValue(ctx, json_obj);
    return result;
}

bool js_has_sourcemap(const char *file_path){
    if(!file_path) return false;

    pthread_once(&g_init_once, init_manager);

    pthread_rwlock_rdlock(&g_manager.global_rwlock);

    FileSourceMap *file_map = NULL;
    for (int i = 0; i < g_manager.files_count; i++) {
        if (g_manager.files[i] && strcmp(g_manager.files[i] -> file_path, file_path) == 0) {
            file_map = g_manager.files[i];
            break;
        }
    }

    pthread_rwlock_unlock(&g_manager.global_rwlock);

    if (file_map) return true;

    return false;
}

// Get mapping for a given position in a file
MappingResult js_get_source_mapping(const char *file_path, int generated_line, int generated_column) {
    MappingResult result = {0};
    
    if (!file_path) return result;
    
    pthread_once(&g_init_once, init_manager);
    
    pthread_rwlock_rdlock(&g_manager.global_rwlock);
    
    FileSourceMap *file_map = NULL;
    for (int i = 0; i < g_manager.files_count; i++) {
        if (g_manager.files[i] && strcmp(g_manager.files[i] -> file_path, file_path) == 0) {
            file_map = g_manager.files[i];
            break;
        }
    }
    
    if (!file_map) {
        pthread_rwlock_unlock(&g_manager.global_rwlock);
        return result;
    }
    
    pthread_rwlock_rdlock(&file_map -> rwlock);
    pthread_rwlock_unlock(&g_manager.global_rwlock);
    
    SourceMapping *mapping = find_mapping(file_map, generated_line - 1, generated_column);
    
    if (mapping && mapping -> original_file) {
        result.original_file = mapping -> original_file;
        result.original_line = mapping -> original_line + 1;
        result.original_column = mapping -> original_column;
        result.function_name = mapping -> name;
        result.found = 1;
    } else {
        result.original_line = generated_line;
        result.original_column = generated_column;
        result.found = 0;
    }
    
    pthread_rwlock_unlock(&file_map -> rwlock);
    
    return result;
}

// Cleanup mapping manager
__attribute__((destructor)) static void js_cleanup_mapping(void) {
    pthread_once(&g_init_once, init_manager);
    
    pthread_rwlock_wrlock(&g_manager.global_rwlock);
    
    for (int i = 0; i < g_manager.files_count; i++) {
        if (g_manager.files[i]) {
            free_file_sourcemap(g_manager.files[i]);
        }
    }
    
    free(g_manager.files);
    g_manager.files = NULL;
    g_manager.files_count = 0;
    g_manager.files_capacity = 0;
    
    pthread_rwlock_unlock(&g_manager.global_rwlock);
    pthread_rwlock_destroy(&g_manager.global_rwlock);
}