/*
 * circu.js syncfs module
 * Synchronous filesystem operations for IO-intensive scripts and module loading
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
#include "utils.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#define stat _stat64
#define fstat _fstat64
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISLNK(m) (0)
#define open _open
#define close _close
#define read _read
#define write _write
#define lseek _lseeki64
#define mkdir(path, mode) _mkdir(path)
#define rmdir _rmdir
#define unlink _unlink
#else
#include <unistd.h>
#include <dirent.h>
#endif

/* File mode flags using magic */
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
static int parse_open_flags(JSContext* ctx, JSValueConst flags_obj) {
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
    flags |= O_BINARY;  /* Always binary mode on Windows */
#endif
    
    return flags;
}

/* stat() - get file status */
static JSValue tjs_syncfs_stat(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    struct stat st;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "stat() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    int ret = stat(path, &st);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "stat failed: %s", strerror(errno));
    }
    
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "dev", JS_NewInt64(ctx, st.st_dev));
    JS_SetPropertyStr(ctx, obj, "ino", JS_NewInt64(ctx, st.st_ino));
    JS_SetPropertyStr(ctx, obj, "mode", JS_NewUint32(ctx, st.st_mode));
    JS_SetPropertyStr(ctx, obj, "nlink", JS_NewInt64(ctx, st.st_nlink));
    JS_SetPropertyStr(ctx, obj, "uid", JS_NewUint32(ctx, st.st_uid));
    JS_SetPropertyStr(ctx, obj, "gid", JS_NewUint32(ctx, st.st_gid));
    JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st.st_rdev));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, st.st_size));
    JS_SetPropertyStr(ctx, obj, "blksize", JS_NewInt64(ctx, 4096));
    JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, (st.st_size + 511) / 512));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewInt64(ctx, st.st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewInt64(ctx, st.st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewInt64(ctx, st.st_ctime * 1000));
    
    /* Helper methods */
    JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, S_ISREG(st.st_mode)));
    JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, S_ISDIR(st.st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, S_ISLNK(st.st_mode)));
    
    return obj;
}

/* lstat() - like stat but doesn't follow symlinks */
static JSValue tjs_syncfs_lstat(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    struct stat st;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "lstat() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    int ret = stat(path, &st);  /* Windows doesn't have lstat */
#else
    int ret = lstat(path, &st);
#endif
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "lstat failed: %s", strerror(errno));
    }
    
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "dev", JS_NewInt64(ctx, st.st_dev));
    JS_SetPropertyStr(ctx, obj, "ino", JS_NewInt64(ctx, st.st_ino));
    JS_SetPropertyStr(ctx, obj, "mode", JS_NewUint32(ctx, st.st_mode));
    JS_SetPropertyStr(ctx, obj, "nlink", JS_NewInt64(ctx, st.st_nlink));
    JS_SetPropertyStr(ctx, obj, "uid", JS_NewUint32(ctx, st.st_uid));
    JS_SetPropertyStr(ctx, obj, "gid", JS_NewUint32(ctx, st.st_gid));
    JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st.st_rdev));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, st.st_size));
    JS_SetPropertyStr(ctx, obj, "blksize", JS_NewInt64(ctx, 4096));
    JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, (st.st_size + 511) / 512));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewInt64(ctx, st.st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewInt64(ctx, st.st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewInt64(ctx, st.st_ctime * 1000));
    
    JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, S_ISREG(st.st_mode)));
    JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, S_ISDIR(st.st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, S_ISLNK(st.st_mode)));
    
    return obj;
}

/* exists() - check if file exists */
static JSValue tjs_syncfs_exists(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    struct stat st;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "exists() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    int ret = stat(path, &st);
    JS_FreeCString(ctx, path);
    
    return JS_NewBool(ctx, ret == 0);
}

/* open() - open file and return fd */
static JSValue tjs_syncfs_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    int flags;
    int mode = 0666;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "open() requires 2 arguments: path and flags");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    flags = parse_open_flags(ctx, argv[1]);
    if (flags < 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Invalid flags");
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &mode, argv[2]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }
    }
    
    int fd = open(path, flags, mode);
    JS_FreeCString(ctx, path);
    
    if (fd < 0) {
        return JS_ThrowInternalError(ctx, "open failed: %s", strerror(errno));
    }
    
    return JS_NewInt32(ctx, fd);
}

/* close() - close file descriptor */
static JSValue tjs_syncfs_close(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "close() requires 1 argument: fd");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (close(fd) < 0) {
        return JS_ThrowInternalError(ctx, "close failed: %s", strerror(errno));
    }
    
    return JS_UNDEFINED;
}

/* read() - read from file descriptor */
static JSValue tjs_syncfs_read(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    size_t buf_size;
    uint8_t* buffer;
    int32_t length = -1;
    int32_t offset = 0;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "read() requires at least 2 arguments: fd and buffer");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    buffer = JS_GetArrayBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &offset, argv[2]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    if (argc >= 4 && !JS_IsUndefined(argv[3])) {
        if (JS_ToInt32(ctx, &length, argv[3]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    if (offset < 0 || offset > (int32_t)buf_size) {
        return JS_ThrowRangeError(ctx, "offset out of bounds");
    }
    
    if (length < 0) {
        length = buf_size - offset;
    }
    
    if (offset + length > (int32_t)buf_size) {
        return JS_ThrowRangeError(ctx, "length out of bounds");
    }
    
    ssize_t bytes_read = read(fd, buffer + offset, length);
    
    if (bytes_read < 0) {
        return JS_ThrowInternalError(ctx, "read failed: %s", strerror(errno));
    }
    
    return JS_NewInt32(ctx, bytes_read);
}

/* write() - write to file descriptor */
static JSValue tjs_syncfs_write(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    size_t buf_size;
    const uint8_t* buffer;
    int32_t length = -1;
    int32_t offset = 0;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "write() requires at least 2 arguments: fd and buffer");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    buffer = JS_GetArrayBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &offset, argv[2]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    if (argc >= 4 && !JS_IsUndefined(argv[3])) {
        if (JS_ToInt32(ctx, &length, argv[3]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    if (offset < 0 || offset > (int32_t)buf_size) {
        return JS_ThrowRangeError(ctx, "offset out of bounds");
    }
    
    if (length < 0) {
        length = buf_size - offset;
    }
    
    if (offset + length > (int32_t)buf_size) {
        return JS_ThrowRangeError(ctx, "length out of bounds");
    }
    
    ssize_t bytes_written = write(fd, buffer + offset, length);
    
    if (bytes_written < 0) {
        return JS_ThrowInternalError(ctx, "write failed: %s", strerror(errno));
    }
    
    return JS_NewInt32(ctx, bytes_written);
}

/* readFile() - read entire file */
static JSValue tjs_syncfs_read_file(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    struct stat st;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "readFile() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    int fd = open(path, O_RDONLY
#ifdef _WIN32
        | O_BINARY
#endif
    );
    if (fd < 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowInternalError(ctx, "open failed: %s", strerror(errno));
    }
    
    if (fstat(fd, &st) < 0) {
        close(fd);
        JS_FreeCString(ctx, path);
        return JS_ThrowInternalError(ctx, "fstat failed: %s", strerror(errno));
    }
    
    JS_FreeCString(ctx, path);
    
    size_t size = st.st_size;
    uint8_t* buf = js_malloc(ctx, size);
    if (!buf) {
        close(fd);
        return JS_EXCEPTION;
    }
    
    ssize_t total_read = 0;
    while (total_read < (ssize_t)size) {
        ssize_t n = read(fd, buf + total_read, size - total_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            js_free(ctx, buf);
            close(fd);
            return JS_ThrowInternalError(ctx, "read failed: %s", strerror(errno));
        }
        if (n == 0) break;
        total_read += n;
    }
    
    close(fd);
    
    JSValue result = JS_NewArrayBufferCopy(ctx, buf, total_read);
    js_free(ctx, buf);
    
    return result;
}

/* writeFile() - write entire file */
static JSValue tjs_syncfs_write_file(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    size_t data_len;
    const uint8_t* data;
    int mode = 0666;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "writeFile() requires 2 arguments: path and data");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &mode, argv[2]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }
    }
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC
#ifdef _WIN32
        | O_BINARY
#endif
    , mode);
    JS_FreeCString(ctx, path);
    
    if (fd < 0) {
        return JS_ThrowInternalError(ctx, "open failed: %s", strerror(errno));
    }
    
    ssize_t total_written = 0;
    while (total_written < (ssize_t)data_len) {
        ssize_t n = write(fd, data + total_written, data_len - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return JS_ThrowInternalError(ctx, "write failed: %s", strerror(errno));
        }
        total_written += n;
    }
    
    close(fd);
    
    return JS_UNDEFINED;
}

/* mkdir() - create directory */
static JSValue tjs_syncfs_mkdir(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    int mode = 0777;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "mkdir() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &mode, argv[1]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }
    }
    
    int ret = mkdir(path, mode);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "mkdir failed: %s", strerror(errno));
    }
    
    return JS_UNDEFINED;
}

/* rmdir() - remove directory */
static JSValue tjs_syncfs_rmdir(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "rmdir() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    int ret = rmdir(path);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "rmdir failed: %s", strerror(errno));
    }
    
    return JS_UNDEFINED;
}

/* unlink() - delete file */
static JSValue tjs_syncfs_unlink(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "unlink() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    int ret = unlink(path);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "unlink failed: %s", strerror(errno));
    }
    
    return JS_UNDEFINED;
}

/* rename() - rename/move file */
static JSValue tjs_syncfs_rename(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char *oldpath, *newpath;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "rename() requires 2 arguments: oldpath and newpath");
    }
    
    oldpath = JS_ToCString(ctx, argv[0]);
    if (!oldpath) {
        return JS_EXCEPTION;
    }
    
    newpath = JS_ToCString(ctx, argv[1]);
    if (!newpath) {
        JS_FreeCString(ctx, oldpath);
        return JS_EXCEPTION;
    }
    
    int ret = rename(oldpath, newpath);
    JS_FreeCString(ctx, oldpath);
    JS_FreeCString(ctx, newpath);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "rename failed: %s", strerror(errno));
    }
    
    return JS_UNDEFINED;
}

/* readdir() - read directory contents */
static JSValue tjs_syncfs_readdir(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "readdir() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    
    HANDLE handle = FindFirstFileA(search_path, &find_data);
    JS_FreeCString(ctx, path);
    
    if (handle == INVALID_HANDLE_VALUE) {
        return JS_ThrowInternalError(ctx, "opendir failed");
    }
    
    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    
    do {
        if (strcmp(find_data.cFileName, ".") != 0 && 
            strcmp(find_data.cFileName, "..") != 0) {
            JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, find_data.cFileName));
        }
    } while (FindNextFileA(handle, &find_data));
    
    FindClose(handle);
#else
    DIR* dir = opendir(path);
    JS_FreeCString(ctx, path);
    
    if (!dir) {
        return JS_ThrowInternalError(ctx, "opendir failed: %s", strerror(errno));
    }
    
    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    struct dirent* entry;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && 
            strcmp(entry->d_name, "..") != 0) {
            JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, entry->d_name));
        }
    }
    
    closedir(dir);
#endif
    
    return arr;
}

/* realpath() - resolve canonical path */
static JSValue tjs_syncfs_realpath(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "realpath() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    char resolved[MAX_PATH];
    DWORD ret = GetFullPathNameA(path, MAX_PATH, resolved, NULL);
    JS_FreeCString(ctx, path);
    
    if (ret == 0 || ret > MAX_PATH) {
        return JS_ThrowInternalError(ctx, "realpath failed");
    }
    
    return JS_NewString(ctx, resolved);
#else
    char resolved[PATH_MAX];
    char* result = realpath(path, resolved);
    JS_FreeCString(ctx, path);
    
    if (!result) {
        return JS_ThrowInternalError(ctx, "realpath failed: %s", strerror(errno));
    }
    
    return JS_NewString(ctx, resolved);
#endif
}

/* getcwd() - get current working directory */
static JSValue tjs_syncfs_getcwd(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    char buf[4096];
    
#ifdef _WIN32
    if (!_getcwd(buf, sizeof(buf))) {
        return JS_ThrowInternalError(ctx, "getcwd failed");
    }
#else
    if (!getcwd(buf, sizeof(buf))) {
        return JS_ThrowInternalError(ctx, "getcwd failed: %s", strerror(errno));
    }
#endif
    
    return JS_NewString(ctx, buf);
}

/* chdir() - change current working directory */
static JSValue tjs_syncfs_chdir(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "chdir() requires 1 argument: path");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    int ret = _chdir(path);
#else
    int ret = chdir(path);
#endif
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        return JS_ThrowInternalError(ctx, "chdir failed: %s", strerror(errno));
    }
    
    return JS_UNDEFINED;
}

/* Module function list */
static const JSCFunctionListEntry tjs_syncfs_funcs[] = {
    /* File status */
    JS_CFUNC_DEF("stat", 1, tjs_syncfs_stat),
    JS_CFUNC_DEF("lstat", 1, tjs_syncfs_lstat),
    JS_CFUNC_DEF("exists", 1, tjs_syncfs_exists),
    
    /* File operations */
    JS_CFUNC_DEF("open", 3, tjs_syncfs_open),
    JS_CFUNC_DEF("close", 1, tjs_syncfs_close),
    JS_CFUNC_DEF("read", 4, tjs_syncfs_read),
    JS_CFUNC_DEF("write", 4, tjs_syncfs_write),
    JS_CFUNC_DEF("readFile", 1, tjs_syncfs_read_file),
    JS_CFUNC_DEF("writeFile", 3, tjs_syncfs_write_file),
    
    /* Directory operations */
    JS_CFUNC_DEF("mkdir", 2, tjs_syncfs_mkdir),
    JS_CFUNC_DEF("rmdir", 1, tjs_syncfs_rmdir),
    JS_CFUNC_DEF("readdir", 1, tjs_syncfs_readdir),
    
    /* File management */
    JS_CFUNC_DEF("unlink", 1, tjs_syncfs_unlink),
    JS_CFUNC_DEF("rename", 2, tjs_syncfs_rename),
    
    /* Path operations */
    JS_CFUNC_DEF("realpath", 1, tjs_syncfs_realpath),
    JS_CFUNC_DEF("getcwd", 0, tjs_syncfs_getcwd),
    JS_CFUNC_DEF("chdir", 1, tjs_syncfs_chdir),
    
#define CCONST(val) JS_PROP_INT32_DEF(#val, val, JS_PROP_CONFIGURABLE)

    /* Constants - file open flags */
	CCONST(O_RDONLY),
	CCONST(O_WRONLY),
	CCONST(O_RDWR),
	CCONST(O_CREAT),
	CCONST(O_EXCL),
	CCONST(O_TRUNC),
	CCONST(O_APPEND),
    
    /* Constants - file modes */
	CCONST(S_IFMT),
	CCONST(S_IFREG),
	CCONST(S_IFDIR),
	CCONST(S_IRWXU),
	CCONST(S_IRUSR),
	CCONST(S_IWUSR),
	CCONST(S_IXUSR),
	CCONST(S_IRWXG),
	CCONST(S_IRGRP),
	CCONST(S_IWGRP),
	CCONST(S_IXGRP),
	CCONST(S_IRWXO),
	CCONST(S_IROTH),
	CCONST(S_IWOTH),
	CCONST(S_IXOTH),

#undef CCONST
};

void tjs__mod_fs_init(JSContext* ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_syncfs_funcs, countof(tjs_syncfs_funcs));
}