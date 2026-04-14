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

#ifndef FS_UTILS_H
#define FS_UTILS_H

#include "private.h"

/* File mode flags */
enum {
    OPEN_RDONLY = O_RDONLY,
    OPEN_WRONLY = O_WRONLY,
    OPEN_RDWR = O_RDWR,
    OPEN_CREAT = O_CREAT,
    OPEN_EXCL = O_EXCL,
    OPEN_TRUNC = O_TRUNC,
    OPEN_APPEND = O_APPEND,
};

/* Helper: build flags from JS object */
int parse_open_flags(JSContext* ctx, JSValueConst flags_obj);

/* Helper: create stat object from stat structure */
JSValue create_stat_object(JSContext* ctx, const struct stat* st);

/* Helper: create stat object from uv_stat_t structure */
JSValue create_uv_stat_object(JSContext* ctx, const uv_stat_t* st);

/* Helper: throw error based on errno */
JSValue throw_fs_error(JSContext* ctx, int err);

/* Helper: check if path is valid */
bool is_valid_path(const char* path);

#endif /* FS_UTILS_H */
