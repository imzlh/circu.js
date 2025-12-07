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
#include <winioctl.h>
#include <fileapi.h>
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
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
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
    
    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
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
    
    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
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
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
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

/* link() - create hard link */
static JSValue tjs_syncfs_link(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    const char *existing_path, *new_path;
    int result;
    
    if (argc < 2) {
        return JS_ThrowSyntaxError(ctx, "Missing string arguments: requires existingPath and newPath");
    }
    
    existing_path = JS_ToCString(ctx, argv[0]);
    if (!existing_path) return JS_EXCEPTION;
    
    new_path = JS_ToCString(ctx, argv[1]);
    if (!new_path) {
        JS_FreeCString(ctx, existing_path);
        return JS_EXCEPTION;
    }
    
    if (strlen(existing_path) == 0 || strlen(new_path) == 0) {
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return JS_ThrowRangeError(ctx, "Paths cannot be empty");
    }

    // Platform-specific link creation
#ifdef _WIN32
    // Windows implementation using CreateHardLink
    result = CreateHardLinkA(new_path, existing_path, NULL);
    if (!result) {
        DWORD error_code = GetLastError();
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to create hard link on Windows. Error code: %lu", error_code);
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
#else
    // Unix-like implementation using link()
    result = link(existing_path, new_path);
    if (result != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to create hard link. System error: %s", strerror(errno));
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
#endif

    // Clean up and return success
    JS_FreeCString(ctx, existing_path);
    JS_FreeCString(ctx, new_path);
    
    return JS_UNDEFINED;
}

/* symlink() - create symbolic link */
static JSValue tjs_syncfs_symlink(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
    const char *target, *path;
    
    // Validate argument count
    if (argc < 2) {
        return JS_ThrowSyntaxError(ctx, "Missing arguments: requires target and path");
    }
    
    // Extract arguments
    target = JS_ToCString(ctx, argv[0]);
    if (!target) {
        return JS_ThrowTypeError(ctx, "First argument (target) must be a string");
    }
    
    path = JS_ToCString(ctx, argv[1]);
    if (!path) {
        JS_FreeCString(ctx, target);
        return JS_ThrowTypeError(ctx, "Second argument (path) must be a string");
    }
    
    // Validate path lengths
    if (strlen(target) == 0 || strlen(path) == 0) {
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return JS_ThrowRangeError(ctx, "Target and path cannot be empty");
    }

#ifdef _WIN32
    // Windows implementation using CreateSymbolicLink
    DWORD flags = 0;
    BOOL is_directory = FALSE;
    
    // Check if we should treat as directory (third argument or auto-detect)
    if (argc >= 3) {
        JSValue type_val = argv[2];
        if (JS_IsString(type_val)) {
            const char *type_str = JS_ToCString(ctx, type_val);
            if (type_str) {
                if (strcmp(type_str, "dir") == 0 || strcmp(type_str, "directory") == 0) {
                    flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
                    is_directory = TRUE;
                } else if (strcmp(type_str, "file") == 0) {
                    flags = 0;
                    is_directory = FALSE;
                } else {
                    JS_FreeCString(ctx, target);
                    JS_FreeCString(ctx, path);
                    JS_FreeCString(ctx, type_str);
                    return JS_ThrowTypeError(ctx, "Link type must be 'file' or 'dir' on Windows");
                }
                JS_FreeCString(ctx, type_str);
            }
        }
    } else {
        // Auto-detect: try to determine if target is a directory
        DWORD attribs = GetFileAttributesA(target);
        if (attribs != INVALID_FILE_ATTRIBUTES) {
            if (attribs & FILE_ATTRIBUTE_DIRECTORY) {
                flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
                is_directory = TRUE;
            } else {
                flags = 0;
                is_directory = FALSE;
            }
        } else {
            // If target doesn't exist, use file extension heuristic
            const char *last_dot = strrchr(target, '.');
            const char *last_slash = strrchr(target, '/');
            if (!last_slash) last_slash = strrchr(target, '\\');
            
            if (last_dot && (!last_slash || last_dot > last_slash)) {
                // Has file extension, treat as file
                flags = 0;
                is_directory = FALSE;
            } else {
                // No extension or extension before slash, treat as directory
                flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
                is_directory = TRUE;
            }
        }
    }
    
    // Convert paths to wide strings for Windows API
    wchar_t *w_target = NULL;
    wchar_t *w_path = NULL;
    int w_target_len = 0, w_path_len = 0;
    BOOL success = FALSE;
    
    do {
        w_target_len = MultiByteToWideChar(CP_UTF8, 0, target, -1, NULL, 0);
        w_path_len = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
        
        if (w_target_len <= 0 || w_path_len <= 0) {
            break;
        }
        
        w_target = (wchar_t*)malloc(w_target_len * sizeof(wchar_t));
        w_path = (wchar_t*)malloc(w_path_len * sizeof(wchar_t));
        
        if (!w_target || !w_path) {
            break;
        }
        
        if (MultiByteToWideChar(CP_UTF8, 0, target, -1, w_target, w_target_len) == 0 ||
            MultiByteToWideChar(CP_UTF8, 0, path, -1, w_path, w_path_len) == 0) {
            break;
        }
        
        // Create the symbolic link
        success = CreateSymbolicLinkW(w_path, w_target, flags);
        
        if (!success) {
            DWORD error = GetLastError();
            // Check if we need administrator privileges
            if (error == ERROR_PRIVILEGE_NOT_HELD) {
                // Try without the flag (for older Windows versions)
                success = CreateSymbolicLinkW(w_path, w_target, 0);
            }
        }
    } while (0);
    
    // Clean up wide strings
    if (w_target) free(w_target);
    if (w_path) free(w_path);
    
    if (!success) {
        DWORD error_code = GetLastError();
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Failed to create symbolic link. %s", strerror(error_code));
    }
#else
    // Unix-like implementation using symlink
    int symlink_result;
    
    // For Unix, we can ignore the type parameter as symlink works for both files and directories
    symlink_result = symlink(target, path);
    
    if (symlink_result != 0) {
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return JS_ThrowPlainError(ctx, "Failed to create symlink. System error: %s", strerror(errno));
    }
#endif

    // Clean up and return success
    JS_FreeCString(ctx, target);
    JS_FreeCString(ctx, path);
    
    return JS_UNDEFINED;
}

/* readlink() - read symbolic link */
static JSValue tjs_syncfs_readlink(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    const char *path;
    char *link_path = NULL;
    JSValue result = JS_UNDEFINED;
    
    // Validate argument count
    if (argc < 1) {
        return JS_ThrowSyntaxError(ctx, "Missing argument: requires path");
    }
    
    // Extract path argument
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_ThrowTypeError(ctx, "First argument must be a string");
    }
    
    // Validate path length
    if (strlen(path) == 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowRangeError(ctx, "Path cannot be empty");
    }

#ifdef _WIN32
    // Windows implementation for reading symbolic links
    HANDLE hFile = NULL;
    DWORD buffer_size = 4096; // Initial buffer size
    
    // Open the symbolic link
    hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error_code = GetLastError();
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Cannot open symbolic link. Error code: %lu", error_code);
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
    
    // Allocate buffer for reparse point data
    BYTE *buffer = (BYTE*)malloc(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (!buffer) {
        CloseHandle(hFile);
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Memory allocation failed");
    }
    
    // Read the reparse point data
    DWORD bytes_returned;
    BOOL success = DeviceIoControl(
        hFile,
        FSCTL_GET_REPARSE_POINT,
        NULL,
        0,
        buffer,
        MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
        &bytes_returned,
        NULL
    );
    
    if (success) {
        PREPARSE_DATA_BUFFER reparse_data = (PREPARSE_DATA_BUFFER)buffer;
        
        // Check if it's a symbolic link reparse point
        if (reparse_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
            // Extract the target path from the reparse data
            WCHAR *substitute_name = reparse_data->SymbolicLinkReparseBuffer.PathBuffer + 
                                   reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
            DWORD substitute_name_length = reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR);
            
            // Convert wide char to UTF-8
            int utf8_size = WideCharToMultiByte(CP_UTF8, 0, substitute_name, substitute_name_length, 
                                              NULL, 0, NULL, NULL);
            if (utf8_size > 0) {
                link_path = (char*)malloc(utf8_size + 1);
                if (link_path) {
                    WideCharToMultiByte(CP_UTF8, 0, substitute_name, substitute_name_length, 
                                      link_path, utf8_size, NULL, NULL);
                    link_path[utf8_size] = '\0';
                    
                    // Remove the \\??\\ prefix if present (Windows symlink format)
                    if (strncmp(link_path, "\\??\\", 4) == 0) {
                        memmove(link_path, link_path + 4, strlen(link_path + 4) + 1);
                    }
                }
            }
        }
    }
    
    free(buffer);
    CloseHandle(hFile);
    
    if (!success || !link_path) {
        DWORD error_code = GetLastError();
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to read symbolic link. Error code: %lu", error_code);
        JS_FreeCString(ctx, path);
        if (link_path) free(link_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
#else
    // Unix-like implementation using readlink
    size_t buffer_size = 4096; // Initial buffer size
    ssize_t link_size;
    
    // Allocate buffer for the link path
    link_path = (char*)malloc(buffer_size);
    if (!link_path) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Memory allocation failed");
    }
    
    // Read the symbolic link
    link_size = readlink(path, link_path, buffer_size - 1);
    
    // Handle buffer too small case
    if (link_size == buffer_size - 1) {
        // Buffer might be too small, try with larger buffer
        free(link_path);
        buffer_size = 65536; // 64KB should be sufficient for most paths
        link_path = (char*)malloc(buffer_size);
        if (!link_path) {
            JS_FreeCString(ctx, path);
            return JS_ThrowTypeError(ctx, "Memory allocation failed");
        }
        link_size = readlink(path, link_path, buffer_size - 1);
    }
    
    if (link_size == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to read symbolic link: %s", strerror(errno));
        free(link_path);
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
    
    // Null-terminate the string
    link_path[link_size] = '\0';
#endif

    // Create JavaScript string from the link path
    if (link_path) {
        result = JS_NewString(ctx, link_path);
        free(link_path);
    } else {
        result = JS_NewString(ctx, "");
    }
    
    // Clean up and return result
    JS_FreeCString(ctx, path);
    return result;
}

/* copy(): high-performance file copy */
static JSValue tjs_syncfs_copy(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    const char *src_path, *dest_path;
    
    if (argc < 2) {
        return JS_ThrowSyntaxError(ctx, "Missing arguments: requires srcPath and destPath");
    }
    
    src_path = JS_ToCString(ctx, argv[0]);
    if (!src_path) {
        return JS_ThrowTypeError(ctx, "First argument must be a string");
    }
    
    dest_path = JS_ToCString(ctx, argv[1]);
    if (!dest_path) {
        JS_FreeCString(ctx, src_path);
        return JS_ThrowTypeError(ctx, "Second argument must be a string");
    }
    
    if (strlen(src_path) == 0 || strlen(dest_path) == 0) {
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowRangeError(ctx, "Paths cannot be empty");
    }
    
#ifdef _WIN32
    // Windows high-performance copy using CopyFileEx with progress callback (NULL for simple copy)
    result = CopyFileExA(src_path, dest_path, NULL, NULL, NULL, COPY_FILE_FAIL_IF_EXISTS);
    if (!result) {
        DWORD error_code = GetLastError();
        char error_msg[256];
        
        if (error_code == ERROR_FILE_EXISTS) {
            snprintf(error_msg, sizeof(error_msg), "Destination file already exists: %s", dest_path);
        } else {
            snprintf(error_msg, sizeof(error_msg), 
                     "Failed to copy file on Windows. Error code: %lu", error_code);
        }
        
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
#else
    // Unix high-performance copy using sendfile() for efficient kernel-space copying
    int src_fd = -1, dest_fd = -1;
    struct stat src_stat;
    ssize_t bytes_copied;
    off_t offset = 0;
    
    // Open source file (read-only)
    src_fd = open(src_path, O_RDONLY);
    if (src_fd == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Cannot open source file: %s", strerror(errno));
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
    
    // Get source file info
    if (fstat(src_fd, &src_stat) == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Cannot get source file info: %s", strerror(errno));
        close(src_fd);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
    
    // Open destination file (create, write-only, with same permissions as source)
    dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, src_stat.st_mode);
    if (dest_fd == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Cannot create destination file: %s", strerror(errno));
        close(src_fd);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
    
    // Use sendfile for efficient zero-copy file transfer (where available)
    #ifdef __linux__
        bytes_copied = sendfile(dest_fd, src_fd, &offset, src_stat.st_size);
    #else
        // Fallback to read/write for systems without sendfile
        char buffer[65536]; // 64KB buffer
        ssize_t bytes_read;
        bytes_copied = 0;
        
        while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
            ssize_t bytes_written = write(dest_fd, buffer, bytes_read);
            if (bytes_written != bytes_read) {
                // Write error
                bytes_copied = -1;
                break;
            }
            bytes_copied += bytes_written;
        }
        
        if (bytes_read == -1) {
            bytes_copied = -1;
        }
    #endif
    
    // Close file descriptors
    close(src_fd);
    close(dest_fd);
    
    // Check if copy was successful
    if (bytes_copied == -1 || bytes_copied != src_stat.st_size) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                 "Failed to copy file data: %s", strerror(errno));
        
        // Clean up partial destination file on error
        unlink(dest_path);
        
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, error_msg);
    }
#endif

    // Clean up and return success
    JS_FreeCString(ctx, src_path);
    JS_FreeCString(ctx, dest_path);
    
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
	JS_CFUNC_DEF("copy", 2, tjs_syncfs_copy),
    
    /* Directory operations */
    JS_CFUNC_DEF("mkdir", 2, tjs_syncfs_mkdir),
    JS_CFUNC_DEF("rmdir", 1, tjs_syncfs_rmdir),
    JS_CFUNC_DEF("readdir", 1, tjs_syncfs_readdir),
    
    /* File management */
    JS_CFUNC_DEF("unlink", 1, tjs_syncfs_unlink),
    JS_CFUNC_DEF("rename", 2, tjs_syncfs_rename),
	JS_CFUNC_DEF("link", 2, tjs_syncfs_link),
	JS_CFUNC_DEF("symlink", 2, tjs_syncfs_symlink),
    
    /* Path operations */
    JS_CFUNC_DEF("realpath", 1, tjs_syncfs_realpath),
    JS_CFUNC_DEF("getcwd", 0, tjs_syncfs_getcwd),
    JS_CFUNC_DEF("chdir", 1, tjs_syncfs_chdir),
	JS_CFUNC_DEF("readlink", 1, tjs_syncfs_readlink),
    
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