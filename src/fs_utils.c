/*
 * circu.js filesystem utilities
 * Common filesystem functions shared between sync and async modules
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

#include "fs_utils.h"
#include "utils.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/* Helper: build flags from JS object */
int parse_open_flags(JSContext* ctx, JSValueConst flags_obj) {
    int flags = 0;
    
    if (JS_IsString(flags_obj)) {
        const char* str = JS_ToCString(ctx, flags_obj);
        if (!str) return -1;
        
        if (strcmp(str, "r") == 0) {
            flags = O_RDONLY;
        } else if (strcmp(str, "r+") == 0) {
            flags = O_RDWR;
        } else if (strcmp(str, "w") == 0) {
            flags = O_WRONLY | O_CREAT | O_TRUNC;
        } else if (strcmp(str, "w+") == 0) {
            flags = O_RDWR | O_CREAT | O_TRUNC;
        } else if (strcmp(str, "a") == 0) {
            flags = O_WRONLY | O_CREAT | O_APPEND;
        } else if (strcmp(str, "a+") == 0) {
            flags = O_RDWR | O_CREAT | O_APPEND;
        } else if (strcmp(str, "wx") == 0) {
            flags = O_WRONLY | O_CREAT | O_EXCL;
        } else if (strcmp(str, "wx+") == 0) {
            flags = O_RDWR | O_CREAT | O_EXCL;
        } else {
            JS_FreeCString(ctx, str);
            return -1;
        }
        JS_FreeCString(ctx, str);
    } else {
        if (JS_ToInt32(ctx, &flags, flags_obj) < 0) {
            return -1;
        }
    }
    
#ifdef _WIN32
    flags |= O_BINARY | O_NOINHERIT;  /* Always binary mode on Windows */
#endif
    
    return flags;
}

/* Helper: create stat object from stat structure */
JSValue create_stat_object(JSContext* ctx, const struct stat* st) {
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "dev", JS_NewInt64(ctx, st->st_dev));
    JS_SetPropertyStr(ctx, obj, "ino", JS_NewInt64(ctx, st->st_ino));
    JS_SetPropertyStr(ctx, obj, "mode", JS_NewUint32(ctx, st->st_mode));
    JS_SetPropertyStr(ctx, obj, "nlink", JS_NewInt64(ctx, st->st_nlink));
    JS_SetPropertyStr(ctx, obj, "uid", JS_NewUint32(ctx, st->st_uid));
    JS_SetPropertyStr(ctx, obj, "gid", JS_NewUint32(ctx, st->st_gid));
    JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st->st_rdev));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, st->st_size));
    JS_SetPropertyStr(ctx, obj, "blksize", JS_NewInt64(ctx, 4096));
    JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, (st->st_size + 511) / 512 < 0 ? 0 : (st->st_size + 511) / 512));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewInt64(ctx, (int64_t)st->st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewInt64(ctx, (int64_t)st->st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewInt64(ctx, (int64_t)st->st_ctime * 1000));
    
    /* Helper methods */
    JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, S_ISREG(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, S_ISDIR(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, S_ISLNK(st->st_mode)));
    
    return obj;
}

/* Helper: create stat object from uv_stat_t structure */
JSValue create_uv_stat_object(JSContext* ctx, const uv_stat_t* st) {
    JSValue obj = JS_NewObject(ctx);
    
#define SET_UINT64_FIELD(x)                                                                                            \
    JS_DefinePropertyValueStr(ctx, obj, STRINGIFY(x), JS_NewUint32(ctx, st->st_##x), JS_PROP_C_W_E);

    SET_UINT64_FIELD(dev);
    SET_UINT64_FIELD(mode);
    SET_UINT64_FIELD(nlink);
    SET_UINT64_FIELD(uid);
    SET_UINT64_FIELD(gid);
    SET_UINT64_FIELD(rdev);
    SET_UINT64_FIELD(ino);
    SET_UINT64_FIELD(size);
    SET_UINT64_FIELD(blksize);
    SET_UINT64_FIELD(blocks);
    SET_UINT64_FIELD(flags);
#undef SET_UINT64_FIELD

#define SET_TIMESPEC_FIELD(field, prop)                                                                                \
    JS_DefinePropertyValueStr(ctx,                                                                                     \
                              obj,                                                                                     \
                              prop,                                                                                    \
                              JS_NewDate(ctx, st->st_##field.tv_sec * 1e3 + st->st_##field.tv_nsec / 1e6),             \
                              JS_PROP_C_W_E);
    SET_TIMESPEC_FIELD(atim, "atime");
    SET_TIMESPEC_FIELD(mtim, "mtime");
    SET_TIMESPEC_FIELD(ctim, "ctime");
    SET_TIMESPEC_FIELD(birthtim, "birthtime");
#undef SET_TIMESPEC_FIELD
    
    return obj;
}

/* Helper: throw error based on errno */
JSValue throw_fs_error(JSContext* ctx, int err) {
    return tjs_throw_errno(ctx, uv_translate_sys_error(err));
}

/* Helper: check if path is valid */
bool is_valid_path(const char* path) {
    return path != NULL && strlen(path) > 0;
}
