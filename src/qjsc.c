/* clang-format off */

/*
 * QuickJS command line compiler
 *
 * Copyright (c) 2018-2026 Fabrice Bellard
 * Copyright (c) 2023-2026 Ben Noordhuis
 * Copyright (c) 2023-2026 Saúl Ibarra Corretgé
 * Copyright (c) 2026 iz
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#ifdef _WIN32

#else
#include <unistd.h>
#endif

#include "../deps/quickjs/quickjs.h"
#include "../deps/quickjs/cutils.h"
#include "version.h"
#define STRINGIFY(x) #x
#define VERSION STRINGIFY(TJS_VERSION_MAJOR) "." STRINGIFY(TJS_VERSION_MINOR) "." STRINGIFY(TJS_VERSION_PATCH) TJS_VERSION_SUFFIX

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #define access _access
    #define F_OK 0
#else
    #include <limits.h>
#endif

/* Utility functions from qjsng */

uint8_t *js_load_file(JSContext *ctx, size_t *pbuf_len, const char *filename)
{
    FILE *f;
    size_t n, len;
    uint8_t *p, *buf, tmp[8192];

    f = fopen(filename, "rb");
    if (!f)
        return NULL;
    buf = NULL;
    len = 0;
    do {
        n = fread(tmp, 1, sizeof(tmp), f);
        if (ctx) {
            p = js_realloc(ctx, buf, len + n + 1);
        } else {
            p = realloc(buf, len + n + 1);
        }
        if (!p) {
            if (ctx) {
                js_free(ctx, buf);
            } else {
                free(buf);
            }
            fclose(f);
            return NULL;
        }
        memcpy(&p[len], tmp, n);
        buf = p;
        len += n;
        buf[len] = '\0';
    } while (n == sizeof(tmp));
    fclose(f);
    *pbuf_len = len;
    return buf;
}

static inline int js__is_digit(char c) {
    return c >= '0' && c <= '9';
}

static inline int js__is_ident_start(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$';
}

static inline int js__is_ident_char(char c) {
    return js__is_ident_start(c) || js__is_digit(c);
}

static int js__strcmp(const char *s1, const char *s2) {
    if (s1 == NULL || s2 == NULL) return s1 == s2 ? 0 : (s1 == NULL ? -1 : 1);
    return strcmp(s1, s2);
}

static void js_dump_exception(JSContext* ctx) {
	JSValue exception = JS_GetException(ctx);
    const char* e = JS_ToCString(ctx, exception);
	printf("Error: %s\n", e);
	JS_FreeCString(ctx, e);
	JS_FreeValue(ctx, exception);
}

/* Output type enumeration */
typedef enum {
    OUTPUT_C,           // Generate .h C array
    OUTPUT_C_MAIN,      // Generate .c with main()
    OUTPUT_RAW,         // Generate .jsc raw bytecode
    OUTPUT_ATTACH,      // Attach to executable (shebang/binary)
} OutputTypeEnum;

typedef struct {
    char *name;
    char *short_name;
    int flags;
} namelist_entry_t;

typedef struct namelist_t {
    namelist_entry_t *array;
    int count;
    int size;
} namelist_t;

static namelist_t cname_list;
static namelist_t cmodule_list;
static namelist_t init_module_list;
static OutputTypeEnum output_type = OUTPUT_C;  // Will be auto-detected
static FILE *outfile;
static const char *c_ident_prefix = "cjsc_";
static int strip;
static const char *output_filename = NULL;

/* Binary attachment utilities */

static uint8_t* read_file_into_buffer(FILE* file, size_t *file_size) {
    if (!file) return NULL;
    
    long current = ftell(file);
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, current, SEEK_SET);
    
    if (*file_size == 0) return NULL;
    
    uint8_t *buffer = malloc(*file_size);
    if (!buffer) return NULL;
    
    if (fread(buffer, 1, *file_size, file) != *file_size) {
        free(buffer);
        return NULL;
    }
    
    return buffer;
}

static uint8_t* extract_attached_data(uint8_t *file_data, size_t file_size, uint32_t *binary_length) {
    if (file_size < 4) return NULL;
    
    // Last 4 bytes contain the length of attached data
    *binary_length = *(uint32_t*)(file_data + file_size - 4);
    
    // Sanity check
    if (*binary_length > file_size - 4 || *binary_length == 0) return NULL;
    
    uint8_t *attach = malloc(*binary_length);
    if (!attach) return NULL;
    
    memcpy(attach, file_data + file_size - 4 - *binary_length, *binary_length);
    return attach;
}

/**
 * Build binary with auto-detection of existing attached data.
 * Automatically strips old bytecode before attaching new.
 * 
 * file: File opened in rb+ mode
 * binary: Bytecode to attach
 * size: Size of bytecode
 * 
 * Returns 0 on success, -1 on error
 */
int tjs__build_binary_auto(FILE* file, uint8_t *binary, uint32_t size) {
    size_t original_size;
    uint8_t *original_data = read_file_into_buffer(file, &original_size);
    if (!original_data) {
        // Empty or new file, just write binary + length at end
        fseek(file, 0, SEEK_END);
        if (fwrite(binary, 1, size, file) != size) return -1;
        if (fwrite(&size, 1, 4, file) != 4) return -1;
        return 0;
    }
    
    // Check if there's existing attached data
    uint32_t old_binary_length = 0;
    uint8_t *old_binary = extract_attached_data(original_data, original_size, &old_binary_length);
    
    size_t program_size;
    if (old_binary) {
        // Has old attached data, truncate to original program size
        program_size = original_size - old_binary_length - 4;
        free(old_binary);
        
        // Truncate file to program_size
        #ifdef _WIN32
        _chsize(fileno(file), program_size);
        #else
        ftruncate(fileno(file), program_size);
        #endif
    } else {
        // No attached data, use entire file as program
        program_size = original_size;
    }
    
    free(original_data);
    
    // Seek to end of program (after truncation or at original end)
    fseek(file, program_size, SEEK_SET);
    
    // Write new binary + length
    if (fwrite(binary, 1, size, file) != size) return -1;
    if (fwrite(&size, 1, 4, file) != 4) return -1;
    
    // Truncate again to remove any leftover data (if new binary is smaller than old)
    long final_pos = ftell(file);
    #ifdef _WIN32
    _chsize(fileno(file), final_pos);
    #else
    ftruncate(fileno(file), final_pos);
    #endif
    
    return 0;
}

/* Namelist management */

void namelist_add(namelist_t *lp, const char *name, const char *short_name, int flags) {
    namelist_entry_t *e;
    if (lp->count == lp->size) {
        size_t newsize = lp->size + (lp->size >> 1) + 4;
        namelist_entry_t *a = realloc(lp->array, sizeof(lp->array[0]) * newsize);
        if (!a) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }
        lp->array = a;
        lp->size = newsize;
    }
    e = &lp->array[lp->count++];
    e->name = strdup(name);
    e->short_name = short_name ? strdup(short_name) : NULL;
    e->flags = flags;
}

void namelist_free(namelist_t *lp) {
    while (lp->count > 0) {
        namelist_entry_t *e = &lp->array[--lp->count];
        free(e->name);
        free(e->short_name);
    }
    free(lp->array);
    lp->array = NULL;
    lp->size = 0;
}

namelist_entry_t *namelist_find(namelist_t *lp, const char *name) {
    int i;
    for (i = 0; i < lp->count; i++) {
        namelist_entry_t *e = &lp->array[i];
        if (!strcmp(e->name, name))
            return e;
    }
    return NULL;
}

static void get_c_name(char *buf, size_t buf_size, const char *file) {
    const char *p, *r;
    size_t len, i;
    int c;
    char *q;

    p = strrchr(file, '/');
    if (!p) p = file;
    else p++;
    
    r = strrchr(p, '.');
    if (!r) len = strlen(p);
    else len = r - p;
    
    js__pstrcpy(buf, buf_size, c_ident_prefix);
    q = buf + strlen(buf);
    
    for (i = 0; i < len && (q - buf) < buf_size - 1; i++) {
        c = p[i];
        if (!js__is_ident_char(c)) c = '_';
        *q++ = c;
    }
    *q = '\0';
}

static void find_unique_cname(char *cname, size_t cname_size) {
    char cname1[1024];
    int suffix_num;
    size_t len, max_len;
    
    if (cname_size < 32) return;
    
    len = strlen(cname);
    max_len = cname_size - 16;
    if (len > max_len) cname[max_len] = '\0';
    
    suffix_num = 1;
    for (;;) {
        snprintf(cname1, sizeof(cname1), "%s_%d", cname, suffix_num);
        if (!namelist_find(&cname_list, cname1)) break;
        suffix_num++;
    }
    js__pstrcpy(cname, cname_size, cname1);
}

static void dump_hex(FILE *f, const uint8_t *buf, size_t len) {
    size_t i, col = 0;
    for (i = 0; i < len; i++) {
        fprintf(f, " 0x%02x,", buf[i]);
        if (++col == 8) {
            fprintf(f, "\n");
            col = 0;
        }
    }
    if (col != 0) fprintf(f, "\n");
}

static void output_object_code(JSContext *ctx, const char *out_filename,
                               JSValue obj, const char *c_name, bool load_only) {
    uint8_t *out_buf;
    size_t out_buf_len;
    int flags = JS_WRITE_OBJ_BYTECODE;

    if (strip) {
        flags |= JS_WRITE_OBJ_STRIP_SOURCE;
        if (strip > 1) flags |= JS_WRITE_OBJ_STRIP_DEBUG;
    }

    out_buf = JS_WriteObject(ctx, &out_buf_len, obj, flags);
    if (!out_buf) {
		js_dump_exception(ctx);
        exit(1);
    }

    namelist_add(&cname_list, c_name, NULL, load_only);

    switch (output_type) {
        case OUTPUT_RAW: {
            // .jsc file - raw bytecode
            FILE *f = fopen(out_filename, "wb");
            if (!f) {
                perror(out_filename);
                exit(1);
            }
            fwrite(out_buf, 1, out_buf_len, f);
            fclose(f);
            printf("Written raw bytecode to %s (%zu bytes)\n", out_filename, out_buf_len);
            break;
        }
        
        case OUTPUT_ATTACH: {
            // Attach to executable
            FILE *f = fopen(out_filename, "rb+");
            if (!f) {
                // For attach mode, target must exist (it's the runtime)
                fprintf(stderr, "Error: Cannot open '%s' for attaching. Maybe under using or not exists?\n", out_filename);
                exit(1);
            }
            
            if (tjs__build_binary_auto(f, out_buf, out_buf_len) != 0) {
                fprintf(stderr, "Error: Failed to attach bytecode to %s\n", out_filename);
                fclose(f);
                exit(1);
            }
            fclose(f);
            printf("Attached bytecode to %s (%zu bytes)\n", out_filename, out_buf_len);
            break;
        }
        
        case OUTPUT_C:
        case OUTPUT_C_MAIN:
        default: {
            // C array output to FILE* (already opened)
            if (!outfile) {
                fprintf(stderr, "Error: No output file opened for C code generation\n");
                exit(1);
            }
            fprintf(outfile, "const uint32_t %s_size = %u;\n\n",
                    c_name, (unsigned int)out_buf_len);
            fprintf(outfile, "const uint8_t %s[%u] = {\n",
                    c_name, (unsigned int)out_buf_len);
            dump_hex(outfile, out_buf, out_buf_len);
            fprintf(outfile, "};\n\n");
            break;
        }
    }

    js_free(ctx, out_buf);
}

static int js_module_dummy_init(JSContext *ctx, JSModuleDef *m) {
    abort();
    return -1;
}

JSModuleDef *jsc_module_loader(JSContext *ctx, const char *module_name, void *opaque) {
    JSModuleDef *m;
    namelist_entry_t *e;

    // Check C modules first
    e = namelist_find(&cmodule_list, module_name);
    if (e) {
        namelist_add(&init_module_list, e->name, e->short_name, 0);
        m = JS_NewCModule(ctx, module_name, js_module_dummy_init);
        return m;
    }
    
    // Check for .so (not supported in compiler)
    if (js__has_suffix(module_name, ".so")) {
        JS_ThrowReferenceError(ctx, "%s: dynamically linking to shared libraries not supported", module_name);
        return NULL;
    }

    // Compile JS module
    size_t buf_len;
    uint8_t *buf = js_load_file(ctx, &buf_len, module_name);
    if (!buf) {
        JS_ThrowReferenceError(ctx, "could not load module filename '%s'", module_name);
        return NULL;
    }

    JSValue func_val = JS_Eval(ctx, (char *)buf, buf_len, module_name,
                               JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    js_free(ctx, buf);
    
    if (JS_IsException(func_val)) return NULL;

    char cname[1024];
    get_c_name(cname, sizeof(cname), module_name);
    if (namelist_find(&cname_list, cname)) {
        find_unique_cname(cname, sizeof(cname));
    }
    
    output_object_code(ctx, output_filename, func_val, cname, true);
    
    m = JS_VALUE_GET_PTR(func_val);
    JS_FreeValue(ctx, func_val);
    return m;
}

static void compile_file(JSContext *ctx, const char *filename,
                         const char *script_name, const char *c_name1, int module) {
    uint8_t *buf;
    char c_name[1024];
    int eval_flags;
    JSValue obj;
    size_t buf_len;

    buf = js_load_file(ctx, &buf_len, filename);
    if (!buf) {
        fprintf(stderr, "Could not load '%s'\n", filename);
        exit(1);
    }
    
    eval_flags = JS_EVAL_FLAG_COMPILE_ONLY;
    if (module < 0) {
        module = (js__has_suffix(filename, ".mjs") ||
                  JS_DetectModule((const char *)buf, buf_len));
    }
    if (module)
        eval_flags |= JS_EVAL_TYPE_MODULE;
    else
        eval_flags |= JS_EVAL_TYPE_GLOBAL;
        
    obj = JS_Eval(ctx, (const char *)buf, buf_len, script_name ? script_name : filename, eval_flags);
    if (JS_IsException(obj)) {
        js_dump_exception(ctx);
        exit(1);
    }
    js_free(ctx, buf);
    
    if (c_name1) {
        js__pstrcpy(c_name, sizeof(c_name), c_name1);
    } else {
        get_c_name(c_name, sizeof(c_name), filename);
    }
    
    output_object_code(ctx, output_filename, obj, c_name, false);
    JS_FreeValue(ctx, obj);
}

static const char main_c_template1[] =
    "int main(int argc, char **argv)\n"
    "{\n"
    "  int r;\n"
    "  JSRuntime *rt;\n"
    "  JSContext *ctx;\n"
    "  r = 0;\n"
    "  rt = JS_NewRuntime();\n"
    "  js_std_set_worker_new_context_func(JS_NewCustomContext);\n"
    "  js_std_init_handlers(rt);\n"
    ;

static const char main_c_template2[] =
    "  r = js_std_loop(ctx);\n"
    "  if (r) {\n"
    "    js_std_dump_error(ctx);\n"
    "  }\n"
    "  js_std_free_handlers(rt);\n"
    "  JS_FreeContext(ctx);\n"
    "  JS_FreeRuntime(rt);\n"
    "  return r;\n"
    "}\n";

#define PROG_NAME "cjsc"

void help(void) {
    printf("Circu.JS OpCode compiler V%s with QuickJS %s\n"
           "usage: " PROG_NAME " [options] [files]\n"
           "\n"
           "options are:\n"
           "  -o output   set the output filename (auto-detect format by extension:\n"
           "              .h/.c -> C source, .jsc -> raw bytecode, none/.exe -> self-attach)\n"
           "  -e          output main() and bytecode in a C file\n"
           "  -n name     set the script name (as used in stack traces)\n"
           "  -N cname    set the C name of the generated data\n"
           "  -C          compile as JS classic script (default=autodetect)\n"
           "  -m          compile as ES module (default=autodetect)\n"
           "  -D module   compile a dynamically loaded module or worker\n"
           "  -M module[,cname] add initialization code for an external C module\n"
           "  -p prefix   set the prefix of the generated C names (default: cjsc_)\n"
           "  -s          strip source code (-ss also strips debug info)\n"
           "  -S n        set the maximum stack size (e.g., -S 65536, -S 1m, -S 2g)\n"
           "  -h          show this help\n"
           "\n"
           "Examples:\n"
           "  " PROG_NAME " -o script.h script.js      # Generate C header\n"
           "  " PROG_NAME " -o script.jsc script.js    # Generate raw bytecode\n"
           "  " PROG_NAME " -o runtime script.js       # Attach to 'runtime' executable\n"
           "  " PROG_NAME " -e -o main.c script.js     # Generate standalone C program\n"
           "\n",
		   VERSION,
           JS_GetVersion());
    exit(1);
}

static int64_t parse_limit(const char *arg) {
    char *p;
    unsigned long unit = 1;
    double d = strtod(arg, &p);

    if (p == arg) {
        fprintf(stderr, PROG_NAME ": invalid limit: %s\n", arg);
        return -1;
    }

    if (*p) {
        switch (*p++) {
        case 'b': case 'B': unit = 1UL << 0; break;
        case 'k': case 'K': unit = 1UL << 10; break;
        case 'm': case 'M': unit = 1UL << 20; break;
        case 'g': case 'G': unit = 1UL << 30; break;
        default:
            fprintf(stderr, PROG_NAME ": invalid limit suffix: %s\n", arg);
            return -1;
        }
        if (*p) {
            fprintf(stderr, PROG_NAME ": invalid limit (multiple suffixes): %s\n", arg);
            return -1;
        }
    }

    return (int64_t)(d * unit);
}

static void check_hasarg(int optind, int argc, char opt) {
    if (optind >= argc) {
        fprintf(stderr, PROG_NAME ": missing argument for -%c\n", opt);
        exit(1);
    }
}

/* Auto-detect output type from filename extension */
static void detect_output_type(const char *filename) {
    if (!filename) return;
    
    // Check for .exe (Windows) or no extension -> ATTACH mode
    size_t len = strlen(filename);
    
    // Check if it's an executable file (no recognizable source extension)
    if (js__has_suffix(filename, ".jsc")) {
        output_type = OUTPUT_RAW;
        printf("Auto-detected: Raw bytecode mode (.jsc)\n");
    } else if (js__has_suffix(filename, ".h")) {
        output_type = OUTPUT_C;
        printf("Auto-detected: C header mode (.h)\n");
    } else if (js__has_suffix(filename, ".c")) {
        output_type = OUTPUT_C_MAIN;  // Default to main for .c, can be overridden by -e
        printf("Auto-detected: C source mode (.c)\n");
    } else if (js__has_suffix(filename, ".exe") || 
               !strchr(filename, '.')) {
        // No extension or .exe -> attach mode
        output_type = OUTPUT_ATTACH;
        printf("Auto-detected: Self-attach mode (no extension or .exe)\n");
    }
    // else keep default OUTPUT_C
}

int main(int argc, char **argv) {
    int optind = 1;
    int i;
    const char *out_filename = NULL;
    const char *cname = NULL;
    const char *script_name = NULL;
    int module = -1;
    size_t stack_size = 0;
    namelist_t dynamic_module_list;
    bool output_type_forced = false;

    memset(&dynamic_module_list, 0, sizeof(dynamic_module_list));

    while (optind < argc && *argv[optind] == '-') {
        char *arg = argv[optind] + 1;
        const char *longopt = "";
        char *optarg = NULL;
        
        if (!*arg) break;  // single - stops argument scanning
        
        optind++;
        if (*arg == '-') {
            longopt = arg + 1;
            optarg = strchr(longopt, '=');
            if (optarg) *optarg++ = '\0';
            arg += strlen(arg);
            if (!*longopt) break;  // -- stops scanning
        }
        
        for (; *arg || *longopt; longopt = "") {
            char opt = *arg;
            if (opt) {
                arg++;
                if (!optarg && *arg) optarg = arg;
            }
            
            if (opt == 'h' || opt == '?' || !strcmp(longopt, "help")) {
                help();
                continue;
            }
            if (opt == 'e') {
                output_type = OUTPUT_C_MAIN;
                output_type_forced = true;
                continue;
            }
            if (opt == 'o') {
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                out_filename = optarg;
                continue;
            }
            if (opt == 'n') {
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                script_name = optarg;
                continue;
            }
            if (opt == 'N') {
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                cname = optarg;
                continue;
            }
            if (opt == 'C') {
                module = 0;
                continue;
            }
            if (opt == 'm') {
                module = 1;
                continue;
            }
            if (opt == 'M') {
                char *p;
                char path[1024];
                char cname_buf[1024];
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                js__pstrcpy(path, sizeof(path), optarg);
                p = strchr(path, ',');
                if (p) {
                    *p = '\0';
                    js__pstrcpy(cname_buf, sizeof(cname_buf), p + 1);
                } else {
                    get_c_name(cname_buf, sizeof(cname_buf), path);
                }
                namelist_add(&cmodule_list, path, cname_buf, 0);
                continue;
            }
            if (opt == 'D') {
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                namelist_add(&dynamic_module_list, optarg, NULL, 0);
                continue;
            }
            if (opt == 's') {
                strip++;
                continue;
            }
            if (opt == 'p') {
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                c_ident_prefix = optarg;
                continue;
            }
            if (opt == 'S') {
                if (!optarg) {
                    check_hasarg(optind, argc, opt);
                    optarg = argv[optind++];
                }
                stack_size = parse_limit(optarg);
                continue;
            }
            help();
        }
    }

    // Auto-detect output type from filename if not forced by flags
    if (out_filename) {
        output_filename = out_filename;
        if (!output_type_forced) {
            detect_output_type(out_filename);
        }
    } else {
        output_filename = "out.c";
    }

    if (optind >= argc) help();

    // Open output file if needed for C generation
    if (output_type == OUTPUT_C || output_type == OUTPUT_C_MAIN) {
        const char *mode = (output_type == OUTPUT_RAW) ? "wb" : "w";
        outfile = fopen(output_filename, mode);
        if (!outfile) {
            perror(output_filename);
            exit(1);
        }
        
        fprintf(outfile, "/* Generated by Enhanced QuickJS Compiler */\n\n");
        if (output_type == OUTPUT_C_MAIN) {
            fprintf(outfile, "#include \"quickjs-libc.h\"\n\n");
        } else {
            fprintf(outfile, "#include <inttypes.h>\n\n");
        }
    }

    JSRuntime *rt = JS_NewRuntime();
    JSContext *ctx = JS_NewContext(rt);
    JS_SetModuleLoaderFunc(rt, NULL, jsc_module_loader, NULL);

    // Compile input files
    for (i = optind; i < argc; i++) {
        const char *filename = argv[i];
        compile_file(ctx, filename, script_name, cname, module);
        cname = NULL;  // Only use for first file
    }

    // Handle dynamic modules
    for (i = 0; i < dynamic_module_list.count; i++) {
        if (!jsc_module_loader(ctx, dynamic_module_list.array[i].name, NULL)) {
            fprintf(stderr, "Could not load dynamic module '%s'\n",
                    dynamic_module_list.array[i].name);
            exit(1);
        }
    }

    // Write main template for OUTPUT_C_MAIN
    if (output_type == OUTPUT_C_MAIN) {
        fprintf(outfile,
                "static JSContext *JS_NewCustomContext(JSRuntime *rt)\n"
                "{\n"
                "  JSContext *ctx = JS_NewContext(rt);\n"
                "  if (!ctx) return NULL;\n");
        
        for(i = 0; i < init_module_list.count; i++) {
            namelist_entry_t *e = &init_module_list.array[i];
            fprintf(outfile,
                    "  {\n"
                    "    extern JSModuleDef *js_init_module_%s(JSContext *ctx, const char *name);\n"
                    "    js_init_module_%s(ctx, \"%s\");\n"
                    "  }\n",
                    e->short_name, e->short_name, e->name);
        }
        
        for(i = 0; i < cname_list.count; i++) {
            namelist_entry_t *e = &cname_list.array[i];
            if (e->flags) {
                fprintf(outfile, "  js_std_eval_binary(ctx, %s, %s_size, 1);\n",
                        e->name, e->name);
            }
        }
        
        fprintf(outfile,
                "  return ctx;\n"
                "}\n\n");

        fputs(main_c_template1, outfile);
        
        if (stack_size != 0) {
            fprintf(outfile, "  JS_SetMaxStackSize(rt, %zu);\n", stack_size);
        }
        
        fprintf(outfile, "  JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);\n");
        fprintf(outfile,
                "  ctx = JS_NewCustomContext(rt);\n"
                "  js_std_add_helpers(ctx, argc, argv);\n");

        for(i = 0; i < cname_list.count; i++) {
            namelist_entry_t *e = &cname_list.array[i];
            if (!e->flags) {
                fprintf(outfile, "  js_std_eval_binary(ctx, %s, %s_size, 0);\n",
                        e->name, e->name);
            }
        }
        fputs(main_c_template2, outfile);
    }

    if (outfile) fclose(outfile);
    
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    namelist_free(&cname_list);
    namelist_free(&cmodule_list);
    namelist_free(&init_module_list);
    namelist_free(&dynamic_module_list);
    
    return 0;
}