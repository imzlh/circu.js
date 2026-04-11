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
typedef int64_t fs_off_t;
static int64_t fs_pread(int fd, void *buf, int64_t len, int64_t off)
{
    OVERLAPPED ov = {0};
    ov.Offset     = (DWORD)(off & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD rd = 0;
    if (!ReadFile((HANDLE)_get_osfhandle(fd), buf, (DWORD)len, &rd, &ov))
        return -1;
    return rd;
}
static int64_t fs_pwrite(int fd, const void *buf, int64_t len, int64_t off)
{
    OVERLAPPED ov = {0};
    ov.Offset     = (DWORD)(off & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD wr = 0;
    if (!WriteFile((HANDLE)_get_osfhandle(fd), buf, (DWORD)len, &wr, &ov))
        return -1;
    return wr;
}
#else
typedef off_t fs_off_t;
#define fs_pread pread
#define fs_pwrite pwrite
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/file.h>
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
    flags |= O_BINARY | O_NOINHERIT;  /* Always binary mode on Windows */
#endif
    
    return flags;
}

#ifdef _WIN32
static int crt2uv(int crt_err) {
    switch (crt_err) {
#define UV(crt, uv) case crt: return uv;
        UV(ENOENT, UV_ENOENT)
        UV(EACCES, UV_EACCES)
        UV(EEXIST, UV_EEXIST)
        UV(ENOTDIR, UV_ENOTDIR)
        UV(EISDIR, UV_EISDIR)
        UV(EINVAL, UV_EINVAL)
        UV(ENOSPC, UV_ENOSPC)
        UV(EIO, UV_EIO)
        UV(EBUSY, UV_EBUSY)
        UV(ENOMEM, UV_ENOMEM)
        UV(EMFILE, UV_EMFILE)
        UV(ENFILE, UV_ENFILE)
        UV(EROFS, UV_EROFS)
        UV(EPIPE, UV_EPIPE)
        
        UV(EAGAIN, UV_EAGAIN)
        UV(EWOULDBLOCK, UV_EAGAIN)
        UV(EINTR, UV_EINTR)
        
        UV(ENOTSOCK, UV_ENOTSOCK)
        UV(EDESTADDRREQ, UV_EDESTADDRREQ)
        UV(EMSGSIZE, UV_EMSGSIZE)
        UV(EPROTOTYPE, UV_EPROTOTYPE)
        UV(ENOPROTOOPT, UV_ENOPROTOOPT)
        UV(EPROTONOSUPPORT, UV_EPROTONOSUPPORT)
        UV(ESOCKTNOSUPPORT, UV_ESOCKTNOSUPPORT)
        UV(EOPNOTSUPP, UV_EOPNOTSUPP)
        UV(EPFNOSUPPORT, UV_EPFNOSUPPORT)
        UV(EAFNOSUPPORT, UV_EAFNOSUPPORT)
        UV(EADDRINUSE, UV_EADDRINUSE)
        UV(EADDRNOTAVAIL, UV_EADDRNOTAVAIL)
        UV(ENETDOWN, UV_ENETDOWN)
        UV(ENETUNREACH, UV_ENETUNREACH)
        UV(ENETRESET, UV_ENETRESET)
        UV(ECONNABORTED, UV_ECONNABORTED)
        UV(ECONNRESET, UV_ECONNRESET)
        UV(ENOBUFS, UV_ENOBUFS)
        UV(EISCONN, UV_EISCONN)
        UV(ENOTCONN, UV_ENOTCONN)
        UV(ESHUTDOWN, UV_ESHUTDOWN)
        UV(ETIMEDOUT, UV_ETIMEDOUT)
        UV(ECONNREFUSED, UV_ECONNREFUSED)
        UV(EHOSTDOWN, UV_EHOSTDOWN)
        UV(EHOSTUNREACH, UV_EHOSTUNREACH)
        UV(EALREADY, UV_EALREADY)
        UV(EINPROGRESS, UV_EINPROGRESS)
        
        UV(ELOOP, UV_ELOOP)
        UV(ENAMETOOLONG, UV_ENAMETOOLONG)
        UV(ENOTEMPTY, UV_ENOTEMPTY)
        UV(EUSERS, UV_EUSERS)
        UV(EDQUOT, UV_EDQUOT)
        UV(ESTALE, UV_ESTALE)
        UV(EREMOTE, UV_EREMOTE)
        UV(EBADF, UV_EBADF)
        UV(EFAULT, UV_EFAULT)
        UV(ESPIPE, UV_ESPIPE)
        UV(E2BIG, UV_E2BIG)
        UV(ENXIO, UV_ENXIO)
        UV(ECHILD, UV_ECHILD)
        UV(EDEADLK, UV_EDEADLK)
        UV(ENOLCK, UV_ENOLCK)
        UV(ENOSYS, UV_ENOSYS)
        UV(ENOMSG, UV_ENOMSG)
        UV(EIDRM, UV_EIDRM)
        UV(EILSEQ, UV_EILSEQ)
        UV(EOVERFLOW, UV_EOVERFLOW)
        UV(ECANCELED, UV_ECANCELED)
        
        default:
            return uv_translate_sys_error(crt_err);
#undef UV
    }
}

#define THROW(msg) return tjs_throw_errno(ctx, crt2uv(errno));
#define THROW2(msg) return tjs_throw_errno(ctx, uv_translate_sys_error(GetLastError()));
#else
#define THROW(msg) return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
#define THROW2(msg) do { fprintf(stderr, "THROW2 called on non-Windows platform\n"); abort(); } while(0)	// windows only, should never happen
#endif


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
        THROW("stat");
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
    JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, (st.st_size + 511) / 512 < 0 ? 0 : (st.st_size + 511) / 512));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewInt64(ctx, (int64_t)st.st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewInt64(ctx, (int64_t)st.st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewInt64(ctx, (int64_t)st.st_ctime * 1000));
    
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
        THROW("lstat");
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
    JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, (st.st_size + 511) / 512 < 0 ? 0 : (st.st_size + 511) / 512));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewInt64(ctx, (int64_t)st.st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewInt64(ctx, (int64_t)st.st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewInt64(ctx, (int64_t)st.st_ctime * 1000));
    
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
        THROW("open");
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
        THROW("close");
    }
    
    return JS_UNDEFINED;
}

/* read() - read from file descriptor */
static JSValue tjs_syncfs_read(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    size_t buf_size;
    uint8_t* buffer;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "read() requires 2 arguments: fd and buffer");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
        return JS_EXCEPTION;
    }
    
    // Simple blocking read with EAGAIN/EINTR handling
    ssize_t bytes_read;
    while (1) {
        bytes_read = read(fd, buffer, buf_size);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
#ifndef _WIN32
                // Wait for data to be available
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(fd, &readfds);
                
                int ret = select(fd + 1, &readfds, NULL, NULL, NULL);
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    THROW("select");
                }
                continue;
#else
                THROW("read");
#endif
            }
            THROW("read");
        }
        break;
    }
    
    return JS_NewInt32(ctx, bytes_read);
}

/* write() - write to file descriptor */
static JSValue tjs_syncfs_write(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    size_t buf_size;
    const uint8_t* buffer;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "write() requires 2 arguments: fd and buffer");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
        return JS_EXCEPTION;
    }
    
    // Write all data, handling EINTR and EAGAIN
    ssize_t total_written = 0;
    while (total_written < (ssize_t)buf_size) {
        ssize_t n = write(fd, buffer + total_written, buf_size - total_written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
#ifndef _WIN32
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(fd, &writefds);
                
                int ret = select(fd + 1, NULL, &writefds, NULL, NULL);
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    THROW("select");
                }
                continue;
#else
                THROW("write");
#endif
            }
            THROW("write");
        }
        total_written += n;
    }
    
    return JS_NewInt32(ctx, total_written);
}

/* pread() - positional read */
static JSValue tjs_syncfs_pread(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    size_t buf_size;
    uint8_t* buffer;
    int64_t offset;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "pread() requires 3 arguments: fd, buffer, and offset");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt64(ctx, &offset, argv[2]) < 0) {
        return JS_EXCEPTION;
    }
    
    ssize_t bytes_read = fs_pread(fd, buffer, buf_size, offset);
    
    if (bytes_read < 0) {
        THROW("pread");
    }
    
    return JS_NewInt32(ctx, bytes_read);
}

/* pwrite() - positional write */
static JSValue tjs_syncfs_pwrite(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    size_t buf_size;
    const uint8_t* buffer;
    int64_t offset;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "pwrite() requires 3 arguments: fd, buffer, and offset");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt64(ctx, &offset, argv[2]) < 0) {
        return JS_EXCEPTION;
    }
    
    ssize_t bytes_written = fs_pwrite(fd, buffer, buf_size, offset);
    
    if (bytes_written < 0) {
        THROW("pwrite");
    }
    
    return JS_NewInt32(ctx, bytes_written);
}

/* setBlocking() - set fd to blocking/non-blocking mode */
static JSValue tjs_syncfs_set_blocking(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    int blocking = 1;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "setBlocking() requires 2 arguments: fd and blocking");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    blocking = JS_ToBool(ctx, argv[1]);
    
#ifndef _WIN32
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        THROW("fcntl");
    }
    
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    
    if (fcntl(fd, F_SETFL, flags) == -1) {
        THROW("fcntl");
    }
#endif
    
    return JS_UNDEFINED;
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
        THROW("open");
    }
    
    if (fstat(fd, &st) < 0) {
        close(fd);
        JS_FreeCString(ctx, path);
        THROW("fstat");
    }
    
    JS_FreeCString(ctx, path);
    
    size_t size = st.st_size;
    
    // For pseudo-files (like /proc/*, /sys/*), st_size may be 0 but content exists
    // Use dynamic buffer for such cases
    if (size == 0) {
        size_t capacity = 4096;
        size_t total_read = 0;
        uint8_t* buf = js_malloc(ctx, capacity);
        if (!buf) {
            close(fd);
            return JS_EXCEPTION;
        }
        
        ssize_t n;
        while ((n = read(fd, buf + total_read, capacity - total_read)) != 0) {
            if (n < 0) {
                if (errno == EINTR) continue;
                js_free(ctx, buf);
                close(fd);
                THROW("read");
            }
            total_read += n;
            if (total_read >= capacity) {
                // Grow buffer
                size_t new_capacity = capacity * 2;
                uint8_t* new_buf = js_realloc(ctx, buf, new_capacity);
                if (!new_buf) {
                    js_free(ctx, buf);
                    close(fd);
                    return JS_EXCEPTION;
                }
                buf = new_buf;
                capacity = new_capacity;
            }
        }
        
        close(fd);
        
        JSValue result = JS_NewArrayBufferCopy(ctx, buf, total_read);
        js_free(ctx, buf);
        return result;
    }

    uint8_t* buf = js_malloc(ctx, size);
    if (!buf) {
        close(fd);
        return JS_EXCEPTION;
    }
    
    ssize_t n, total_read = 0;
    while ((n = read(fd, buf + total_read, size - total_read)) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            js_free(ctx, buf);
            close(fd);
            THROW("read");
        }
        total_read += n;
        if (total_read == size) break;
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
        THROW("open");
    }
    
    ssize_t total_written = 0;
    while (total_written < (ssize_t)data_len) {
        ssize_t n = write(fd, data + total_written, data_len - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            THROW("write");
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
        THROW("mkdir");
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
        THROW("rmdir");
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
        THROW("unlink");
    }
    
    return JS_UNDEFINED;
}

/* link() - create hard link */
static JSValue tjs_syncfs_link(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    const char *existing_path, *new_path;
    
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
    BOOL result = CreateHardLinkA(new_path, existing_path, NULL);
    (void)result;  // Silence unused variable warning in case of macro weirdness
    if (!result) {
        DWORD error_code = GetLastError();
        LPSTR messageBuffer = NULL;
        JSValue error;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        if (messageBuffer) {
            error = JS_ThrowTypeError(ctx, "Failed to create hard link: %s", messageBuffer);
            LocalFree(messageBuffer);
        } else {
            error = JS_ThrowTypeError(ctx, "Failed to create hard link. Error code: %lu", error_code);
        }
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return error;
    }
#else
    // Unix-like implementation using link()
    int result = link(existing_path, new_path);
    (void)result;  // Silence unused variable warning in case of macro weirdness
    if (result != 0) {
        int saved_errno = errno;
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
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
        
        w_target = (wchar_t*)js_malloc(ctx, w_target_len * sizeof(wchar_t));
        w_path = (wchar_t*)js_malloc(ctx, w_path_len * sizeof(wchar_t));
        
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
    if (w_target) js_free(ctx, w_target);
    if (w_path) js_free(ctx, w_path);
    
    if (!success) {
        DWORD error_code = GetLastError();
        LPSTR messageBuffer = NULL;
        JSValue error;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        if (messageBuffer) {
            error = JS_ThrowTypeError(ctx, "Failed to create symbolic link: %s", messageBuffer);
            LocalFree(messageBuffer);
        } else {
            error = JS_ThrowTypeError(ctx, "Failed to create symbolic link. Error code: %lu", error_code);
        }
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return error;
    }
#else
    // Unix-like implementation using symlink
    // For Unix, we can ignore the type parameter as symlink works for both files and directories
    int symlink_result = symlink(target, path);
    
    if (symlink_result != 0) {
        int saved_errno = errno;
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
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
        LPSTR messageBuffer = NULL;
        JSValue error;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        if (messageBuffer) {
            error = JS_ThrowTypeError(ctx, "Cannot open symbolic link: %s", messageBuffer);
            LocalFree(messageBuffer);
        } else {
            error = JS_ThrowTypeError(ctx, "Cannot open symbolic link. Error code: %lu", error_code);
        }
        JS_FreeCString(ctx, path);
        return error;
    }
    
    // Allocate buffer for reparse point data
    BYTE *buffer = (BYTE*)js_malloc(ctx, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
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
                link_path = (char*)js_malloc(ctx, utf8_size + 1);
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
    
    js_free(ctx, buffer);
    CloseHandle(hFile);
    
    if (!success || !link_path) {
        DWORD error_code = GetLastError();
        LPSTR messageBuffer = NULL;
        JSValue error;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        if (messageBuffer) {
            error = JS_ThrowTypeError(ctx, "Failed to read symbolic link: %s", messageBuffer);
            LocalFree(messageBuffer);
        } else {
            error = JS_ThrowTypeError(ctx, "Failed to read symbolic link. Error code: %lu", error_code);
        }
        JS_FreeCString(ctx, path);
        if (link_path) js_free(ctx, link_path);
        return error;
    }
#else
    // Unix-like implementation using readlink
    size_t buffer_size = 4096; // Initial buffer size
    ssize_t link_size;
    
    // Allocate buffer for the link path
    link_path = (char*)js_malloc(ctx, buffer_size);
    if (!link_path) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Memory allocation failed");
    }
    
    // Read the symbolic link
    link_size = readlink(path, link_path, buffer_size);
    
    // Handle buffer too small case
    if (link_size == (ssize_t)buffer_size) {
        // Buffer might be too small (content was truncated), try with larger buffer
        js_free(ctx, link_path);
        buffer_size = 65536; // 64KB should be sufficient for most paths
        link_path = (char*)js_malloc(ctx, buffer_size);
        if (!link_path) {
            JS_FreeCString(ctx, path);
            return JS_ThrowTypeError(ctx, "Memory allocation failed");
        }
        link_size = readlink(path, link_path, buffer_size);
    }
    
    if (link_size == -1) {
        int saved_errno = errno;
        js_free(ctx, link_path);
        JS_FreeCString(ctx, path);
        return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
    }
    
    // Null-terminate the string
    link_path[link_size] = '\0';
#endif

    // Create JavaScript string from the link path
    if (link_path) {
        result = JS_NewString(ctx, link_path);
        js_free(ctx, link_path);
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
    // Check if source is a regular file (not a directory)
    DWORD src_attribs = GetFileAttributesA(src_path);
    if (src_attribs == INVALID_FILE_ATTRIBUTES) {
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        THROW2("copy: cannot access source file");
    }
    if (src_attribs & FILE_ATTRIBUTE_DIRECTORY) {
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, "Source is a directory, not a file");
    }
    
    // Windows high-performance copy using CopyFileEx with progress callback (NULL for simple copy)
    // Note: We use 0 flags (not COPY_FILE_FAIL_IF_EXISTS) to match Unix behavior (overwrite)
    BOOL result = CopyFileExA(src_path, dest_path, NULL, NULL, NULL, 0);
    if (!result) {
        DWORD error_code = GetLastError();
        char error_msg[256];
        
        LPSTR messageBuffer = NULL;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        if (messageBuffer) {
            snprintf(error_msg, sizeof(error_msg), "Failed to copy file: %s", messageBuffer);
            LocalFree(messageBuffer);
        } else {
            snprintf(error_msg, sizeof(error_msg), "Failed to copy file. Error code: %lu", error_code);
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
        int saved_errno = errno;
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
    }
    
    // Check if source is a regular file (don't copy directories or special files)
    if (fstat(src_fd, &src_stat) == -1) {
        int saved_errno = errno;
        close(src_fd);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
    }
    if (!S_ISREG(src_stat.st_mode)) {
        close(src_fd);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, "Source is not a regular file");
    }
    
    // Open destination file (create, write-only, with same permissions as source)
    dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, src_stat.st_mode);
    if (dest_fd == -1) {
        int saved_errno = errno;
        close(src_fd);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
    }
    
    // Use sendfile for efficient zero-copy file transfer (where available)
    #ifdef __linux__
        // Loop to handle partial writes and EINTR
        bytes_copied = 0;
        while (offset < src_stat.st_size) {
            size_t to_send = (size_t)(src_stat.st_size - offset);
            // Limit chunk size to avoid issues with large files on 32-bit systems
            if (to_send > 0x7ffff000) to_send = 0x7ffff000;
            ssize_t ret = sendfile(dest_fd, src_fd, &offset, to_send);
            if (ret < 0) {
                if (errno == EINTR) continue;
                bytes_copied = -1;
                break;
            }
            if (ret == 0) {
                // EOF reached before expected (file truncated during copy)
                break;
            }
            bytes_copied += ret;
        }
    #else
        // Fallback to read/write for systems without sendfile
        char buffer[65536]; // 64KB buffer
        ssize_t bytes_read;
        bytes_copied = 0;
        
        while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) != 0) {
            if (bytes_read < 0) {
                if (errno == EINTR) continue;
                bytes_copied = -1;
                break;
            }
            ssize_t total_written = 0;
            while (total_written < bytes_read) {
                ssize_t bytes_written = write(dest_fd, buffer + total_written, bytes_read - total_written);
                if (bytes_written < 0) {
                    if (errno == EINTR) continue;
                    bytes_copied = -1;
                    break;
                }
                total_written += bytes_written;
            }
            if (bytes_copied == -1) break;
            bytes_copied += bytes_read;
        }
    #endif
    
    // Close file descriptors
    int close_ret1 = close(src_fd);
    int close_ret2 = close(dest_fd);
    int saved_errno = 0;
    if (bytes_copied < 0) {
        saved_errno = errno;
    } else if (close_ret1 < 0 || close_ret2 < 0) {
        saved_errno = errno;
        bytes_copied = -1;
    }
    
    // Check if copy was successful (bytes_copied should match file size)
    if (bytes_copied < 0 || bytes_copied != src_stat.st_size) {
        // Clean up partial destination file on error
        int saved_errno2 = errno;
        unlink(dest_path);
        
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        if (saved_errno != 0) {
            return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno));
        }
        if (saved_errno2 != 0 && saved_errno2 != ENOENT) {
            return tjs_throw_errno(ctx, uv_translate_sys_error(saved_errno2));
        }
        return JS_ThrowTypeError(ctx, "Failed to copy file data (file may have been modified during copy)");
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
        THROW("rename");
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
        THROW2("opendir")
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
        THROW("opendir");
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
static JSValue tjs_syncfs_realpath(JSContext *ctx,
                                   JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    const char *path;

    if (argc < 1)
        return JS_ThrowTypeError(ctx, "realpath() requires 1 argument: path");

    path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;

#ifdef _WIN32
    HANDLE hFile = CreateFileA(path,
                               0,	// query only
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
    JS_FreeCString(ctx, path);
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("realpath");
    }

    /* 2. get final path (resolved symlinks, ., and ..) */
    char buf[MAX_PATH * 4];
    DWORD len = GetFinalPathNameByHandleA(hFile, buf, sizeof(buf),
                                          VOLUME_NAME_DOS);
    CloseHandle(hFile);
    if (len == 0 || len >= sizeof(buf)) {
        SetLastError(len == 0 ? ERROR_GEN_FAILURE : ERROR_INSUFFICIENT_BUFFER);
        THROW2("realpath");
    }

    const char *out = buf;
	// UNC path: \\?\UNC\server\share\file.txt -> \\server\share\file.txt
    if (strncmp(out, "\\\\?\\", 4) == 0) {
        out += 4;
        if (strncmp(out, "UNC\\", 4) == 0) {
            out += 2;
            *(--out) = '\\';
        }
    }
    return JS_NewString(ctx, out);
#else
    char resolved[PATH_MAX];
    char *ret = realpath(path, resolved);
    JS_FreeCString(ctx, path);
    if (!ret) {
        THROW("realpath");
    }
    return JS_NewString(ctx, resolved);
#endif
}

/* flock() - advisory file locking */
static JSValue tjs_syncfs_flock(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    int32_t operation;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "flock() requires 2 arguments: fd and operation");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &operation, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("flock")
    }
    
    OVERLAPPED overlapped = {0};
    DWORD flags = 0;
    
    // LOCK_SH = 1, LOCK_EX = 2, LOCK_UN = 8, LOCK_NB = 4
    if (operation & 8) { // LOCK_UN
        if (!UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &overlapped)) {
            THROW2("unlock")
        }
    } else {
        if (operation & 2) { // LOCK_EX
            flags = LOCKFILE_EXCLUSIVE_LOCK;
        }
        if (operation & 4) { // LOCK_NB
            flags |= LOCKFILE_FAIL_IMMEDIATELY;
        }
        
        if (!LockFileEx(hFile, flags, 0, MAXDWORD, MAXDWORD, &overlapped)) {
            if (GetLastError() == ERROR_LOCK_VIOLATION && (operation & 4)) {
                errno = EWOULDBLOCK;
            }
            THROW("lock")
        }
    }
#else
    if (flock(fd, operation) < 0) {
        THROW("flock");
    }
#endif
    
    return JS_UNDEFINED;
}

/* fsync() - synchronize file data to disk */
static JSValue tjs_syncfs_fsync(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "fsync() requires 1 argument: fd");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("fsync")
    }
    
    if (!FlushFileBuffers(hFile)) {
        THROW2("fsync")
    }
#else
    if (fsync(fd) < 0) {
        THROW("fsync");
    }
#endif
    
    return JS_UNDEFINED;
}

/* fdatasync() - synchronize file data (not metadata) to disk */
static JSValue tjs_syncfs_fdatasync(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "fdatasync() requires 1 argument: fd");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    // Windows doesn't distinguish between fsync and fdatasync
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("fdatasync")
    }
    
    if (!FlushFileBuffers(hFile)) {
        THROW2("fdatasync")
    }
#else
    #ifdef __APPLE__
        // macOS doesn't have fdatasync, use fcntl F_FULLFSYNC
        if (fcntl(fd, F_FULLFSYNC) < 0) {
            THROW("fdatasync");
        }
    #else
        if (fdatasync(fd) < 0) {
            THROW("fdatasync");
        }
    #endif
#endif
    
    return JS_UNDEFINED;
}

/* truncate() - truncate file to specified length */
static JSValue tjs_syncfs_truncate(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    int64_t length;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "truncate() requires 2 arguments: path and length");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt64(ctx, &length, argv[1]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, NULL);
    JS_FreeCString(ctx, path);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("truncate")
    }
    
    LARGE_INTEGER li;
    li.QuadPart = length;
    
    if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        CloseHandle(hFile);
        THROW2("truncate")
    }
    
    CloseHandle(hFile);
#else
    int ret = truncate(path, length);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        THROW("truncate");
    }
#endif
    
    return JS_UNDEFINED;
}

/* ftruncate() - truncate open file to specified length */
static JSValue tjs_syncfs_ftruncate(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    int64_t length;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "ftruncate() requires 2 arguments: fd and length");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt64(ctx, &length, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("ftruncate")
    }
    
    LARGE_INTEGER li;
    li.QuadPart = length;
    
    if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        THROW2("ftruncate")
    }
#else
    if (ftruncate(fd, length) < 0) {
        THROW("ftruncate");
    }
#endif
    
    return JS_UNDEFINED;
}

/* chmod() - change file permissions */
static JSValue tjs_syncfs_chmod(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    int32_t mode;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "chmod() requires 2 arguments: path and mode");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &mode, argv[1]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    int ret = _chmod(path, mode);
#else
    int ret = chmod(path, mode);
#endif
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        THROW("chmod");
    }
    
    return JS_UNDEFINED;
}

/* fchmod() - change permissions of open file */
static JSValue tjs_syncfs_fchmod(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    int32_t mode;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "fchmod() requires 2 arguments: fd and mode");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &mode, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    // Windows doesn't support fchmod directly, limited support
    return JS_ThrowInternalError(ctx, "fchmod not supported on Windows");
#else
    if (fchmod(fd, mode) < 0) {
        THROW("fchmod");
    }
#endif
    
    return JS_UNDEFINED;
}

/* chown() - change file owner and group */
static JSValue tjs_syncfs_chown(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    int32_t uid, gid;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "chown() requires 3 arguments: path, uid, gid");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &uid, argv[1]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &gid, argv[2]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    JS_FreeCString(ctx, path);
    return JS_ThrowInternalError(ctx, "chown not supported on Windows");
#else
    int ret = chown(path, uid, gid);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        THROW("chown");
    }
#endif
    
    return JS_UNDEFINED;
}

/* fchown() - change owner of open file */
static JSValue tjs_syncfs_fchown(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd, uid, gid;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "fchown() requires 3 arguments: fd, uid, gid");
    }
    
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &uid, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &gid, argv[2]) < 0) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    return JS_ThrowInternalError(ctx, "fchown not supported on Windows");
#else
    if (fchown(fd, uid, gid) < 0) {
        THROW("fchown");
    }
#endif
    
    return JS_UNDEFINED;
}

/* utimes() - change file access and modification times */
static JSValue tjs_syncfs_utimes(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    double atime, mtime;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "utimes() requires 3 arguments: path, atime, mtime");
    }
    
    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToFloat64(ctx, &atime, argv[1]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
    if (JS_ToFloat64(ctx, &mtime, argv[2]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    HANDLE hFile = CreateFileA(path, FILE_WRITE_ATTRIBUTES, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    JS_FreeCString(ctx, path);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("utimes failed: cannot open file");
    }
    
    FILETIME ft_atime, ft_mtime;
    ULARGE_INTEGER ul;
    
    // Convert Unix timestamp (seconds since 1970) to Windows FILETIME (100ns since 1601)
    ul.QuadPart = (ULONGLONG)((atime + 11644473600.0) * 10000000.0);
    ft_atime.dwLowDateTime = ul.LowPart;
    ft_atime.dwHighDateTime = ul.HighPart;
    
    ul.QuadPart = (ULONGLONG)((mtime + 11644473600.0) * 10000000.0);
    ft_mtime.dwLowDateTime = ul.LowPart;
    ft_mtime.dwHighDateTime = ul.HighPart;
    
    if (!SetFileTime(hFile, NULL, &ft_atime, &ft_mtime)) {
        CloseHandle(hFile);
        THROW2("utimes")
    }
    
    CloseHandle(hFile);
#else
    struct timeval times[2];
    times[0].tv_sec = (time_t)atime;
    times[0].tv_usec = (suseconds_t)((atime - times[0].tv_sec) * 1000000);
    times[1].tv_sec = (time_t)mtime;
    times[1].tv_usec = (suseconds_t)((mtime - times[1].tv_sec) * 1000000);
    
    int ret = utimes(path, times);
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        THROW("utimes");
    }
#endif
    
    return JS_UNDEFINED;
}

/* access() - check file accessibility */
static JSValue tjs_syncfs_access(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    int32_t mode = 0; // F_OK by default
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "access() requires at least 1 argument: path");
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
    
#ifdef _WIN32
    int ret = _access(path, mode);
#else
    int ret = access(path, mode);
#endif
    JS_FreeCString(ctx, path);
    
    if (ret < 0) {
        THROW("access");
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
    JS_CFUNC_DEF("read", 2, tjs_syncfs_read),
	JS_CFUNC_DEF("pread", 3, tjs_syncfs_pread),
    JS_CFUNC_DEF("write", 2, tjs_syncfs_write),
	JS_CFUNC_DEF("pwrite", 3, tjs_syncfs_pwrite),
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

	/* File locking and synchronization */
    JS_CFUNC_DEF("flock", 2, tjs_syncfs_flock),
    JS_CFUNC_DEF("fsync", 1, tjs_syncfs_fsync),
    JS_CFUNC_DEF("fdatasync", 1, tjs_syncfs_fdatasync),
    
    /* File size manipulation */
    JS_CFUNC_DEF("truncate", 2, tjs_syncfs_truncate),
    JS_CFUNC_DEF("ftruncate", 2, tjs_syncfs_ftruncate),
    
    /* Permissions and ownership */
    JS_CFUNC_DEF("chmod", 2, tjs_syncfs_chmod),
    JS_CFUNC_DEF("fchmod", 2, tjs_syncfs_fchmod),
    JS_CFUNC_DEF("chown", 3, tjs_syncfs_chown),
    JS_CFUNC_DEF("fchown", 3, tjs_syncfs_fchown),
    
    /* Time manipulation */
    JS_CFUNC_DEF("utimes", 3, tjs_syncfs_utimes),
    
    /* Access checks */
    JS_CFUNC_DEF("access", 2, tjs_syncfs_access),

	/* blocking mode operations */
    JS_CFUNC_DEF("setBlocking", 2, tjs_syncfs_set_blocking),
    
    /* Path operations */
    JS_CFUNC_DEF("realpath", 1, tjs_syncfs_realpath),
	JS_CFUNC_DEF("readlink", 1, tjs_syncfs_readlink),
    
#define CCONST(val) JS_PROP_INT32_DEF(#val, val, JS_PROP_CONFIGURABLE)

    /* Constants - file open flags */
	CCONST(OPEN_RDONLY),
	CCONST(OPEN_WRONLY),
	CCONST(OPEN_RDWR),
	CCONST(OPEN_CREAT),
	CCONST(OPEN_EXCL),
	CCONST(OPEN_TRUNC),
	CCONST(OPEN_APPEND),
    
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

	CCONST(LOCK_SH),  // Shared lock (1)
    CCONST(LOCK_EX),  // Exclusive lock (2)
    CCONST(LOCK_NB),  // Non-blocking (4)
    CCONST(LOCK_UN),  // Unlock (8)
    
    /* Access mode constants */
    CCONST(F_OK),     // File exists
    CCONST(R_OK),     // Read permission
    CCONST(W_OK),     // Write permission
    CCONST(X_OK),     // Execute permission

#undef CCONST
};

void tjs__mod_fs_init(JSContext* ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_syncfs_funcs, countof(tjs_syncfs_funcs));
}