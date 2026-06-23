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
#define close _close
#define read _read
#define write _write
#define lseek _lseeki64
#define mkdir(path, mode) _mkdir(path)
#define rmdir _rmdir
#define unlink _unlink
/* Use wide-char file open on Windows for Unicode path support */
#ifdef _WIN32
#define open _wopen

/* Format a Win32 error code as a UTF-8 string into buf (size bytes).
 * Always NUL-terminates. Returns buf. */
static char *win32_strerror_utf8(DWORD code, char *buf, int size) {
    WCHAR wbuf[512];
    if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            wbuf, (DWORD)(sizeof(wbuf)/sizeof(wbuf[0])), NULL)) {
        /* strip trailing whitespace / CR LF */
        int len = (int)wcslen(wbuf);
        while (len > 0 && (wbuf[len-1] == L'\r' || wbuf[len-1] == L'\n' || wbuf[len-1] == L' '))
            wbuf[--len] = L'\0';
        WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, size, NULL, NULL);
    } else {
        snprintf(buf, size, "error code %lu", (unsigned long)code);
    }
    buf[size-1] = '\0';
    return buf;
}
#endif
 /* flock constants - not defined in Windows headers */
#ifndef LOCK_SH
#define LOCK_SH 1   /* Shared lock */
#endif
#ifndef LOCK_EX
#define LOCK_EX 2   /* Exclusive lock */
#endif
#ifndef LOCK_NB
#define LOCK_NB 4   /* Non-blocking */
#endif
#ifndef LOCK_UN
#define LOCK_UN 8   /* Unlock */
#endif

/* UTF-8 ↔ wide-char helpers for proper Unicode file paths on Windows */
static WCHAR* utf8_to_wcs(const char* s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    WCHAR* w = (WCHAR*) malloc(n * sizeof(WCHAR));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static char* wcs_to_utf8(const WCHAR* w, int nchars) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, nchars, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char* s = (char*) malloc(n + 1);
    if (!s) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, w, nchars, s, n, NULL, NULL);
    s[n] = '\0';
    return s;
}
/* Reparse point buffer for symbolic links - may not be defined in older SDKs */
#ifndef MAXIMUM_REPARSE_DATA_BUFFER_SIZE
#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE 16384
#endif
#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000C
#endif
/* Define REPARSE_DATA_BUFFER if not available */
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
/* Permission constants - not defined in Windows headers */
#ifndef S_IRWXU
#define S_IRWXU 00700  /* Read, write, execute owner */
#endif
#ifndef S_IRUSR
#define S_IRUSR 00400  /* Read permission owner */
#endif
#ifndef S_IWUSR
#define S_IWUSR 00200  /* Write permission owner */
#endif
#ifndef S_IXUSR
#define S_IXUSR 00100  /* Execute permission owner */
#endif
#ifndef S_IRWXG
#define S_IRWXG 00070  /* Read, write, execute group */
#endif
#ifndef S_IRGRP
#define S_IRGRP 00040  /* Read permission group */
#endif
#ifndef S_IWGRP
#define S_IWGRP 00020  /* Write permission group */
#endif
#ifndef S_IXGRP
#define S_IXGRP 00010  /* Execute permission group */
#endif
#ifndef S_IRWXO
#define S_IRWXO 00007  /* Read, write, execute other */
#endif
#ifndef S_IROTH
#define S_IROTH 00004  /* Read permission other */
#endif
#ifndef S_IWOTH
#define S_IWOTH 00002  /* Write permission other */
#endif
#ifndef S_IXOTH
#define S_IXOTH 00001  /* Execute permission other */
#endif
typedef int64_t fs_off_t;
static int64_t fs_pread(int fd, void* buf, int64_t len, int64_t off)
{
    OVERLAPPED ov = { 0 };
    ov.Offset = (DWORD) (off & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD) (off >> 32);
    DWORD rd = 0;
    if (!ReadFile((HANDLE) _get_osfhandle(fd), buf, (DWORD) len, &rd, &ov))
        return -1;
    return rd;
}
static int64_t fs_pwrite(int fd, const void* buf, int64_t len, int64_t off)
{
    OVERLAPPED ov = { 0 };
    ov.Offset = (DWORD) (off & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD) (off >> 32);
    DWORD wr = 0;
    if (!WriteFile((HANDLE) _get_osfhandle(fd), buf, (DWORD) len, &wr, &ov))
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
#ifndef __APPLE__
#include <sys/sendfile.h>
#endif
#include <sys/stat.h>
#include <sys/file.h>
#endif

#ifndef S_ISBLK
#  define S_ISBLK(m) 0
#endif
#ifndef S_ISCHR
#  ifdef _S_IFCHR
#    define S_ISCHR(m) (((m) & _S_IFMT) == _S_IFCHR)
#  else
#    define S_ISCHR(m) 0
#  endif
#endif
#ifndef S_ISDIR
#  define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef S_ISFIFO
#  ifdef _S_IFIFO
#    define S_ISFIFO(m) (((m) & _S_IFMT) == _S_IFIFO)
#  else
#    define S_ISFIFO(m) 0
#  endif
#endif
#ifndef S_ISREG
#  define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#ifndef S_ISSOCK
#  ifdef _S_IFSOCK
#    define S_ISSOCK(m) (((m) & _S_IFMT) == _S_IFSOCK)
#  else
#    define S_ISSOCK(m) 0
#  endif
#endif
#ifndef S_ISLNK
#  ifdef _S_IFLNK
#    define S_ISLNK(m) (((m) & _S_IFMT) == _S_IFLNK)
#  else
#    define S_ISLNK(m) 0
#  endif
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
        size_t strlen;
        const char* str = JS_ToCStringLen(ctx, &strlen, flags_obj);
        if (!str) return -1;

        flags = TJS_ParseOpenFlags(str, strlen);
    }
    else {
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

#ifdef ENOTSOCK
            UV(ENOTSOCK, UV_ENOTSOCK)
#endif
#ifdef EDESTADDRREQ
            UV(EDESTADDRREQ, UV_EDESTADDRREQ)
#endif
#ifdef EMSGSIZE
            UV(EMSGSIZE, UV_EMSGSIZE)
#endif
#ifdef EPROTOTYPE
            UV(EPROTOTYPE, UV_EPROTOTYPE)
#endif
#ifdef ENOPROTOOPT
            UV(ENOPROTOOPT, UV_ENOPROTOOPT)
#endif
#ifdef EPROTONOSUPPORT
            UV(EPROTONOSUPPORT, UV_EPROTONOSUPPORT)
#endif
#ifdef ESOCKTNOSUPPORT
            UV(ESOCKTNOSUPPORT, UV_ESOCKTNOSUPPORT)
#endif
#ifdef EPFNOSUPPORT
            UV(EPFNOSUPPORT, UV_EPFNOSUPPORT)
#endif
#ifdef EAFNOSUPPORT
            UV(EAFNOSUPPORT, UV_EAFNOSUPPORT)
#endif
#ifdef EADDRINUSE
            UV(EADDRINUSE, UV_EADDRINUSE)
#endif
#ifdef EADDRNOTAVAIL
            UV(EADDRNOTAVAIL, UV_EADDRNOTAVAIL)
#endif
#ifdef ENETDOWN
            UV(ENETDOWN, UV_ENETDOWN)
#endif
#ifdef ENETUNREACH
            UV(ENETUNREACH, UV_ENETUNREACH)
#endif
#ifdef ECONNABORTED
            UV(ECONNABORTED, UV_ECONNABORTED)
#endif
#ifdef ECONNRESET
            UV(ECONNRESET, UV_ECONNRESET)
#endif
#ifdef ENOBUFS
            UV(ENOBUFS, UV_ENOBUFS)
#endif
#ifdef EISCONN
            UV(EISCONN, UV_EISCONN)
#endif
#ifdef ENOTCONN
            UV(ENOTCONN, UV_ENOTCONN)
#endif
#ifdef ESHUTDOWN
            UV(ESHUTDOWN, UV_ESHUTDOWN)
#endif
#ifdef ETIMEDOUT
            UV(ETIMEDOUT, UV_ETIMEDOUT)
#endif
#ifdef ECONNREFUSED
            UV(ECONNREFUSED, UV_ECONNREFUSED)
#endif
#ifdef EHOSTDOWN
            UV(EHOSTDOWN, UV_EHOSTDOWN)
#endif
#ifdef EHOSTUNREACH
            UV(EHOSTUNREACH, UV_EHOSTUNREACH)
#endif
#ifdef EALREADY
            UV(EALREADY, UV_EALREADY)
#endif
#ifdef ELOOP
            UV(ELOOP, UV_ELOOP)
#endif
#ifdef ENAMETOOLONG
            UV(ENAMETOOLONG, UV_ENAMETOOLONG)
#endif
#ifdef ENOTEMPTY
            UV(ENOTEMPTY, UV_ENOTEMPTY)
#endif
#ifdef EUSERS
            UV(EUSERS, UV_EUSERS)
#endif
#ifdef EDQUOT
            UV(EDQUOT, UV_EDQUOT)
#endif
#ifdef ESTALE
            UV(ESTALE, UV_ESTALE)
#endif
#ifdef EREMOTE
            UV(EREMOTE, UV_EREMOTE)
#endif
#ifdef EBADF
            UV(EBADF, UV_EBADF)
#endif
#ifdef EFAULT
            UV(EFAULT, UV_EFAULT)
#endif
#ifdef ESPIPE
            UV(ESPIPE, UV_ESPIPE)
#endif
#ifdef E2BIG
            UV(E2BIG, UV_E2BIG)
#endif
#ifdef ENXIO
            UV(ENXIO, UV_ENXIO)
#endif
#ifdef ENOSYS
            UV(ENOSYS, UV_ENOSYS)
#endif
#ifdef EILSEQ
            UV(EILSEQ, UV_EILSEQ)
#endif
#ifdef EOVERFLOW
            UV(EOVERFLOW, UV_EOVERFLOW)
#endif
#ifdef ECANCELED
            UV(ECANCELED, UV_ECANCELED)
#endif

    default:
        return uv_translate_sys_error(crt_err);
#undef UV
    }
}

#define THROW(msg) return tjs_throw_errno(ctx, crt2uv(errno));
#define THROW2(msg) return tjs_throw_errno(ctx, uv_translate_sys_error(GetLastError()));
#else
#define THROW(msg) return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
#define THROW2(msg) abort();    // windows only, should never happen
#endif

static inline JSValue build_stat_obj(JSContext* ctx, struct stat* st) {
    JSValue obj = JS_NewObject(ctx);

    // The struct is same as stat() in asyncfs
#define SET_UINT64_FIELD(x) \
    JS_DefinePropertyValueStr(ctx, obj, STRINGIFY(x), JS_NewInt64(ctx, st->st_##x), JS_PROP_C_W_E);
#define SET_UINT32_FIELD(x) \
    JS_DefinePropertyValueStr(ctx, obj, STRINGIFY(x), JS_NewUint32(ctx, st->st_##x), JS_PROP_C_W_E);

    SET_UINT32_FIELD(dev);
    SET_UINT32_FIELD(mode);
    SET_UINT32_FIELD(nlink);
    SET_UINT32_FIELD(uid);
    SET_UINT32_FIELD(gid);
    SET_UINT32_FIELD(rdev);
    SET_UINT64_FIELD(ino);      // 64-bit inode
    SET_UINT64_FIELD(size);     // 64-bit file size
#ifdef _WIN32
    // Windows doesn't have blksize and blocks, set to 0
    JS_DefinePropertyValueStr(ctx, obj, "blksize", JS_NewUint32(ctx, 0), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "blocks", JS_NewUint32(ctx, 0), JS_PROP_C_W_E);
#else
    SET_UINT32_FIELD(blksize);
    SET_UINT64_FIELD(blocks);   // 64-bit block count
#endif
#undef SET_UINT64_FIELD
#undef SET_UINT32_FIELD

#ifdef _WIN32
    // Windows uses st_atime, st_mtime, st_ctime (time_t, not timespec)
    JS_DefinePropertyValueStr(ctx, obj, "atim", JS_NewDate(ctx, (double) st->st_atime * 1000.0), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "mtim", JS_NewDate(ctx, (double) st->st_mtime * 1000.0), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "ctim", JS_NewDate(ctx, (double) st->st_ctime * 1000.0), JS_PROP_C_W_E);
#else
#ifdef __APPLE__
    // macOS uses timespec suffix instead of tim
#define SET_TIMESPEC_FIELD(x, rename)                                                                                          \
        JS_DefinePropertyValueStr(ctx,                                                                                     \
                                  obj,                                                                                     \
                                  STRINGIFY(rename),                                                                            \
                                  JS_NewDate(ctx, st->st_##x##timespec.tv_sec * 1e3 + st->st_##x##timespec.tv_nsec / 1e6),                     \
                                  JS_PROP_C_W_E);
#else
    // Linux and other Unix systems use tim suffix
#define SET_TIMESPEC_FIELD(x, rename)                                                                                          \
        JS_DefinePropertyValueStr(ctx,                                                                                     \
                                  obj,                                                                                     \
                                  STRINGIFY(rename),                                                                            \
                                  JS_NewDate(ctx, st->st_##x##tim.tv_sec * 1e3 + st->st_##x##tim.tv_nsec / 1e6),                     \
                                  JS_PROP_C_W_E);
#endif

    SET_TIMESPEC_FIELD(a, atim);
    SET_TIMESPEC_FIELD(m, mtim);
    SET_TIMESPEC_FIELD(c, ctim);

#ifdef __APPLE__
    // macOS has birthtime
    SET_TIMESPEC_FIELD(birth, birthtim);
#endif

#undef SET_TIMESPEC_FIELD
#endif

    /* Helper methods */
    JS_SetPropertyStr(ctx, obj, "isBlockDevice", JS_NewBool(ctx, S_ISBLK(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isCharacterDevice", JS_NewBool(ctx, S_ISCHR(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, S_ISDIR(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isFIFO", JS_NewBool(ctx, S_ISFIFO(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, S_ISREG(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSocket", JS_NewBool(ctx, S_ISSOCK(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, S_ISLNK(st->st_mode)));
    return obj;
}

static JSValue build_dirent_obj(JSContext* ctx, const char* name, int kind) {
    JSValue obj = JS_NewObject(ctx);
    if (JS_IsException(obj)) {
        return obj;
    }

    JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, name));
    JS_SetPropertyStr(ctx, obj, "isBlockDevice", JS_NewBool(ctx, kind == UV_DIRENT_BLOCK));
    JS_SetPropertyStr(ctx, obj, "isCharacterDevice", JS_NewBool(ctx, kind == UV_DIRENT_CHAR));
    JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, kind == UV_DIRENT_DIR));
    JS_SetPropertyStr(ctx, obj, "isFIFO", JS_NewBool(ctx, kind == UV_DIRENT_FIFO));
    JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, kind == UV_DIRENT_FILE));
    JS_SetPropertyStr(ctx, obj, "isSocket", JS_NewBool(ctx, kind == UV_DIRENT_SOCKET));
    JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, kind == UV_DIRENT_LINK));
    return obj;
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

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    int ret = _wstat64(wpath, &st);
    free(wpath);
#else
    int ret = stat(path, &st);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    return build_stat_obj(ctx, &st);
}

/* fstat() - get file status by fd */
static JSValue tjs_syncfs_fstat(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    struct stat st;
    int fd;

    if (argc < 1 || -1 == JS_ToInt32(ctx, &fd, argv[0])) {
        return JS_ThrowTypeError(ctx, "stat() requires 1 number argument: fd");
    }

    int ret = fstat(fd, &st);

    if (ret < 0) {
        JSValue err = tjs_throw_errno(ctx, uv_translate_sys_error(errno));
        return err;
    }

    return build_stat_obj(ctx, &st);
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
    /* Windows doesn't have lstat, use stat */
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    int ret = _wstat64(wpath, &st);
    free(wpath);
#else
    int ret = lstat(path, &st);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    return build_stat_obj(ctx, &st);
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

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    JS_FreeCString(ctx, path);
    if (!wpath) return JS_ThrowOutOfMemory(ctx);
    int ret = _wstat64(wpath, &st);
    free(wpath);
#else
    int ret = stat(path, &st);
    JS_FreeCString(ctx, path);
#endif

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

    int fd;
#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    fd = _wopen(wpath, flags, mode);
    free(wpath);
#else
    fd = open(path, flags, mode);
#endif

    if (fd < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

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
    while (total_written < (ssize_t) buf_size) {
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

    // Convert offset BEFORE getting buffer pointer (offset conversion can detach buffer)
    if (JS_ToInt64(ctx, &offset, argv[2]) < 0) {
        return JS_EXCEPTION;
    }

    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
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

    // Convert offset BEFORE getting buffer pointer (offset conversion can detach buffer)
    if (JS_ToInt64(ctx, &offset, argv[2]) < 0) {
        return JS_EXCEPTION;
    }

    buffer = JS_GetAnyBuffer(ctx, &buf_size, argv[1]);
    if (!buffer) {
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
    }
    else {
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

    int fd;
#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    fd = _wopen(wpath, O_RDONLY | O_BINARY);
    free(wpath);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    if (fstat(fd, &st) < 0) {
        close(fd);
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    size_t size = st.st_size;

    // For pseudo-files (like /proc/*, /sys/*), st_size may be 0 but content exists
    // Use dynamic buffer for such cases
    if (size == 0) {
        size_t capacity = 4096;
        size_t total_read = 0;
        uint8_t* buf = js_malloc(ctx, capacity);
        if (!buf) {
            close(fd);
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }

        ssize_t n;
        while ((n = read(fd, buf + total_read, capacity - total_read)) != 0) {
            if (n < 0) {
                if (errno == EINTR) continue;
                js_free(ctx, buf);
                close(fd);
                JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
                JS_FreeCString(ctx, path);
                return err;
            }
            total_read += n;
            if (total_read >= capacity) {
                // Grow buffer
                size_t new_capacity = capacity * 2;
                uint8_t* new_buf = js_realloc(ctx, buf, new_capacity);
                if (!new_buf) {
                    js_free(ctx, buf);
                    close(fd);
                    JS_FreeCString(ctx, path);
                    return JS_EXCEPTION;
                }
                buf = new_buf;
                capacity = new_capacity;
            }
        }

        close(fd);
        JS_FreeCString(ctx, path);

        JSValue result = JS_NewArrayBufferCopy(ctx, buf, total_read);
        js_free(ctx, buf);
        return result;
    }

    uint8_t* buf = js_malloc(ctx, size);
    if (!buf) {
        close(fd);
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }

    ssize_t n;
    size_t total_read = 0;
    while ((n = read(fd, buf + total_read, size - total_read)) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            js_free(ctx, buf);
            close(fd);
            JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
            JS_FreeCString(ctx, path);
            return err;
        }
        total_read += n;
        if (total_read == size) break;
    }

    close(fd);
    JS_FreeCString(ctx, path);

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

    // Convert mode BEFORE getting data buffer (mode conversion can detach buffer)
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &mode, argv[2]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }
    }

    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }

    int fd;
#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    fd = _wopen(wpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, mode);
    free(wpath);
#else
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
#endif

    if (fd < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    ssize_t total_written = 0;
    while (total_written < (ssize_t) data_len) {
        ssize_t n = write(fd, data + total_written, data_len - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
            JS_FreeCString(ctx, path);
            return err;
        }
        total_written += n;
    }

    close(fd);
    JS_FreeCString(ctx, path);

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

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    int ret = _wmkdir(wpath);
    free(wpath);
#else
    int ret = mkdir(path, mode);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

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

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    int ret = _wrmdir(wpath);
    free(wpath);
#else
    int ret = rmdir(path);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

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

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    int ret = _wunlink(wpath);
    free(wpath);
#else
    int ret = unlink(path);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    return JS_UNDEFINED;
}

/* link() - create hard link */
static JSValue tjs_syncfs_link(JSContext* ctx, JSValueConst this_val,
    int argc, JSValueConst* argv)
{
    const char* existing_path, * new_path;

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
    bool result = CreateHardLinkA(new_path, existing_path, NULL);
    (void) result;  // Silence unused variable warning in case of macro weirdness
    if (!result) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), new_path);
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return err;
    }
#else
    // Unix-like implementation using link()
    int result = link(existing_path, new_path);
    (void) result;  // Silence unused variable warning in case of macro weirdness
    if (result != 0) {
        int uv_err = uv_translate_sys_error(errno);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, new_path);
        JS_FreeCString(ctx, existing_path);
        JS_FreeCString(ctx, new_path);
        return err;
    }
#endif

    // Clean up and return success
    JS_FreeCString(ctx, existing_path);
    JS_FreeCString(ctx, new_path);

    return JS_UNDEFINED;
}

/* symlink() - create symbolic link */
static JSValue tjs_syncfs_symlink(JSContext* ctx, JSValueConst this_val,
    int argc, JSValueConst* argv)
{
    const char* target, * path;

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
    bool is_directory = false;

    // Check if we should treat as directory (third argument or auto-detect)
    if (argc >= 3) {
        JSValue type_val = argv[2];
        if (JS_IsString(type_val)) {
            const char* type_str = JS_ToCString(ctx, type_val);
            if (type_str) {
                if (strcmp(type_str, "dir") == 0 || strcmp(type_str, "directory") == 0) {
                    flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
                    is_directory = true;
                }
                else if (strcmp(type_str, "file") == 0) {
                    flags = 0;
                    is_directory = false;
                }
                else {
                    JS_FreeCString(ctx, target);
                    JS_FreeCString(ctx, path);
                    JS_FreeCString(ctx, type_str);
                    return JS_ThrowTypeError(ctx, "Link type must be 'file' or 'dir' on Windows");
                }
                JS_FreeCString(ctx, type_str);
            }
        }
    }
    else {
        // Auto-detect: try to determine if target is a directory
        WCHAR *wtarget = utf8_to_wcs(target);
        DWORD attribs = INVALID_FILE_ATTRIBUTES;
        if (wtarget) {
            attribs = GetFileAttributesW(wtarget);
            free(wtarget);
        }
        if (attribs != INVALID_FILE_ATTRIBUTES) {
            if (attribs & FILE_ATTRIBUTE_DIRECTORY) {
                flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
                is_directory = true;
            }
            else {
                flags = 0;
                is_directory = false;
            }
        }
        else {
            // If target doesn't exist, use file extension heuristic
            const char* last_dot = strrchr(target, '.');
            const char* last_slash = strrchr(target, '/');
            if (!last_slash) last_slash = strrchr(target, '\\');

            if (last_dot && (!last_slash || last_dot > last_slash)) {
                // Has file extension, treat as file
                flags = 0;
                is_directory = false;
            }
            else {
                // No extension or extension before slash, treat as directory
                flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
                is_directory = true;
            }
        }
    }

    // Convert paths to wide strings for Windows API
    wchar_t* w_target = NULL;
    wchar_t* w_path = NULL;
    int w_target_len = 0, w_path_len = 0;
    bool success = false;

    do {
        w_target_len = MultiByteToWideChar(CP_UTF8, 0, target, -1, NULL, 0);
        w_path_len = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);

        if (w_target_len <= 0 || w_path_len <= 0) {
            break;
        }

        w_target = (wchar_t*) js_malloc(ctx, w_target_len * sizeof(wchar_t));
        w_path = (wchar_t*) js_malloc(ctx, w_path_len * sizeof(wchar_t));

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
        char errbuf[512];
        win32_strerror_utf8(error_code, errbuf, sizeof(errbuf));
        JSValue error = JS_ThrowTypeError(ctx, "Failed to create symbolic link: %s", errbuf);
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return error;
    }
#else
    // Unix-like implementation using symlink
    // For Unix, we can ignore the type parameter as symlink works for both files and directories
    int symlink_result = symlink(target, path);

    if (symlink_result != 0) {
        int uv_err = uv_translate_sys_error(errno);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, path);
        JS_FreeCString(ctx, target);
        JS_FreeCString(ctx, path);
        return err;
    }
#endif

    // Clean up and return success
    JS_FreeCString(ctx, target);
    JS_FreeCString(ctx, path);

    return JS_UNDEFINED;
}

/* readlink() - read symbolic link */
static JSValue tjs_syncfs_readlink(JSContext* ctx, JSValueConst this_val,
    int argc, JSValueConst* argv)
{
    const char* path;
    char* link_path = NULL;
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

    // Convert UTF-8 path to wide-char for Unicode support
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) {
        JS_FreeCString(ctx, path);
        return JS_ThrowOutOfMemory(ctx);
    }

    // Open the symbolic link
    hFile = CreateFileW(
        wpath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );
    free(wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error_code = GetLastError();
        char errbuf[512];
        win32_strerror_utf8(error_code, errbuf, sizeof(errbuf));
        JSValue error = JS_ThrowTypeError(ctx, "Cannot open symbolic link: %s", errbuf);
        JS_FreeCString(ctx, path);
        return error;
    }

    // Allocate buffer for reparse point data
    BYTE* buffer = (BYTE*) js_malloc(ctx, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (!buffer) {
        CloseHandle(hFile);
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Memory allocation failed");
    }

    // Read the reparse point data
    DWORD bytes_returned;
    bool success = DeviceIoControl(
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
        PREPARSE_DATA_BUFFER reparse_data = (PREPARSE_DATA_BUFFER) buffer;

        // Check if it's a symbolic link reparse point
        if (reparse_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
            // Extract the target path from the reparse data
            WCHAR* substitute_name = reparse_data->SymbolicLinkReparseBuffer.PathBuffer +
                reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
            DWORD substitute_name_length = reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

            // Convert wide char to UTF-8
            int utf8_size = WideCharToMultiByte(CP_UTF8, 0, substitute_name, substitute_name_length,
                NULL, 0, NULL, NULL);
            if (utf8_size > 0) {
                link_path = (char*) js_malloc(ctx, utf8_size + 1);
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
        char errbuf[512];
        win32_strerror_utf8(error_code, errbuf, sizeof(errbuf));
        JSValue error = JS_ThrowTypeError(ctx, "Failed to read symbolic link: %s", errbuf);
        JS_FreeCString(ctx, path);
        if (link_path) js_free(ctx, link_path);
        return error;
    }
#else
    // Unix-like implementation using readlink
    size_t buffer_size = 4096; // Initial buffer size
    ssize_t link_size;

    // Allocate buffer for the link path
    link_path = (char*) js_malloc(ctx, buffer_size + 1);
    if (!link_path) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Memory allocation failed");
    }

    // Read the symbolic link
    link_size = readlink(path, link_path, buffer_size);

    // Handle buffer too small case
    if (link_size == (ssize_t) buffer_size) {
        // Buffer might be too small (content was truncated), try with larger buffer
        js_free(ctx, link_path);
        buffer_size = 65536; // 64KB should be sufficient for most paths
        link_path = (char*) js_malloc(ctx, buffer_size + 1);
        if (!link_path) {
            JS_FreeCString(ctx, path);
            return JS_ThrowTypeError(ctx, "Memory allocation failed");
        }
        link_size = readlink(path, link_path, buffer_size);
    }

    if (link_size == -1) {
        int uv_err = uv_translate_sys_error(errno);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, path);
        js_free(ctx, link_path);
        JS_FreeCString(ctx, path);
        return err;
    }

    // Null-terminate the string
    link_path[link_size] = '\0';
#endif

    // Create JavaScript string from the link path
    if (link_path) {
        result = JS_NewString(ctx, link_path);
        js_free(ctx, link_path);
    }
    else {
        result = JS_NewString(ctx, "");
    }

    // Clean up and return result
    JS_FreeCString(ctx, path);
    return result;
}

/* copy(): high-performance file copy */
static JSValue tjs_syncfs_copy(JSContext* ctx, JSValueConst this_val,
    int argc, JSValueConst* argv)
{
    const char* src_path, * dest_path;

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
    WCHAR *wsrc = utf8_to_wcs(src_path);
    DWORD src_attribs = INVALID_FILE_ATTRIBUTES;
    if (wsrc) {
        src_attribs = GetFileAttributesW(wsrc);
        free(wsrc);
    }
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
    WCHAR *wsrc_copy = utf8_to_wcs(src_path);
    WCHAR *wdest_copy = utf8_to_wcs(dest_path);
    bool result = false;
    if (wsrc_copy && wdest_copy) {
        result = CopyFileExW(wsrc_copy, wdest_copy, NULL, NULL, NULL, 0);
    }
    free(wsrc_copy);
    free(wdest_copy);
    if (!result) {
        DWORD error_code = GetLastError();
        char error_msg[512];
        char errbuf[400];
        win32_strerror_utf8(error_code, errbuf, sizeof(errbuf));
        snprintf(error_msg, sizeof(error_msg), "Failed to copy file: %s", errbuf);

        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return JS_ThrowTypeError(ctx, "%s", error_msg);
    }
#else
    // Unix high-performance copy using sendfile() for efficient kernel-space copying
    int src_fd = -1, dest_fd = -1;
    struct stat src_stat;
    ssize_t bytes_copied;

    // Open source file (read-only)
    src_fd = open(src_path, O_RDONLY);
    if (src_fd == -1) {
        int uv_err = uv_translate_sys_error(errno);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, src_path);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return err;
    }

    // Check if source is a regular file (don't copy directories or special files)
    if (fstat(src_fd, &src_stat) == -1) {
        int uv_err = uv_translate_sys_error(errno);
        close(src_fd);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, src_path);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return err;
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
        int uv_err = uv_translate_sys_error(errno);
        close(src_fd);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, dest_path);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return err;
    }

    // Use sendfile for efficient zero-copy file transfer (where available)
#ifdef __linux__

    off_t offset = 0;
    // Loop to handle partial writes and EINTR
    bytes_copied = 0;
    while (offset < src_stat.st_size) {
        size_t to_send = (size_t) (src_stat.st_size - offset);
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
    }
    else if (close_ret1 < 0 || close_ret2 < 0) {
        saved_errno = errno;
        bytes_copied = -1;
    }

    // Check if copy was successful (bytes_copied should match file size)
    if (bytes_copied < 0 || bytes_copied != src_stat.st_size) {
        // Clean up partial destination file on error
        int saved_errno2 = errno;
        unlink(dest_path);

        if (saved_errno != 0) {
            JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(saved_errno), src_path);
            JS_FreeCString(ctx, src_path);
            JS_FreeCString(ctx, dest_path);
            return err;
        }
        if (saved_errno2 != 0 && saved_errno2 != ENOENT) {
            JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(saved_errno2), src_path);
            JS_FreeCString(ctx, src_path);
            JS_FreeCString(ctx, dest_path);
            return err;
        }
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
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
    const char* oldpath, * newpath;

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

#ifdef _WIN32
    WCHAR *wold = utf8_to_wcs(oldpath);
    WCHAR *wnew = utf8_to_wcs(newpath);
    if (!wold || !wnew) {
        free(wold); free(wnew);
        JS_FreeCString(ctx, oldpath);
        JS_FreeCString(ctx, newpath);
        return JS_ThrowOutOfMemory(ctx);
    }
    int ret = _wrename(wold, wnew);
    free(wold);
    free(wnew);
#else
    int ret = rename(oldpath, newpath);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), oldpath);
        JS_FreeCString(ctx, oldpath);
        JS_FreeCString(ctx, newpath);
        return err;
    }
    JS_FreeCString(ctx, oldpath);
    JS_FreeCString(ctx, newpath);

    return JS_UNDEFINED;
}

/* readdir() - read directory contents */
static JSValue tjs_syncfs_readdir(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    bool with_types = false;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "readdir() requires 1 argument: path");
    }

    path = JS_ToCString(ctx, argv[0]);
    if (!path) {
        return JS_EXCEPTION;
    }
    if (argc >= 2) {
        int32_t types_flag;
        if (JS_ToInt32(ctx, &types_flag, argv[1]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }
        with_types = types_flag != 0;
    }

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }

    /* Build wide-char search path: path\\* */
    size_t wlen = wcslen(wpath);
    WCHAR *wsearch = (WCHAR *)malloc((wlen + 3) * sizeof(WCHAR));
    if (!wsearch) { free(wpath); JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    wcscpy(wsearch, wpath);
    wsearch[wlen] = L'\\';
    wsearch[wlen + 1] = L'*';
    wsearch[wlen + 2] = L'\0';
    free(wpath);

    WIN32_FIND_DATAW find_data;
    HANDLE handle = FindFirstFileW(wsearch, &find_data);
    free(wsearch);

    if (handle == INVALID_HANDLE_VALUE) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;

    do {
        if (wcscmp(find_data.cFileName, L".") != 0 &&
            wcscmp(find_data.cFileName, L"..") != 0) {
            char *utf8_name = wcs_to_utf8(find_data.cFileName, -1);
            if (utf8_name) {
                if (with_types) {
                    int kind = UV_DIRENT_UNKNOWN;
                    DWORD attrs = find_data.dwFileAttributes;
                    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) kind = UV_DIRENT_LINK;
                    else if (attrs & FILE_ATTRIBUTE_DIRECTORY) kind = UV_DIRENT_DIR;
                    else kind = UV_DIRENT_FILE;
                    JS_SetPropertyUint32(ctx, arr, idx++, build_dirent_obj(ctx, utf8_name, kind));
                } else {
                    JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, utf8_name));
                }
                free(utf8_name);
            }
        }
    } while (FindNextFileW(handle, &find_data));

    FindClose(handle);
#else
    DIR* dir = opendir(path);

    if (!dir) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            if (with_types) {
                int kind = UV_DIRENT_UNKNOWN;
#ifdef DT_BLK
                if (entry->d_type == DT_BLK) kind = UV_DIRENT_BLOCK;
#endif
#ifdef DT_CHR
                else if (entry->d_type == DT_CHR) kind = UV_DIRENT_CHAR;
#endif
#ifdef DT_DIR
                else if (entry->d_type == DT_DIR) kind = UV_DIRENT_DIR;
#endif
#ifdef DT_FIFO
                else if (entry->d_type == DT_FIFO) kind = UV_DIRENT_FIFO;
#endif
#ifdef DT_REG
                else if (entry->d_type == DT_REG) kind = UV_DIRENT_FILE;
#endif
#ifdef DT_LNK
                else if (entry->d_type == DT_LNK) kind = UV_DIRENT_LINK;
#endif
#ifdef DT_SOCK
                else if (entry->d_type == DT_SOCK) kind = UV_DIRENT_SOCKET;
#endif
                JS_SetPropertyUint32(ctx, arr, idx++, build_dirent_obj(ctx, entry->d_name, kind));
            } else {
                JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, entry->d_name));
            }
        }
    }

    closedir(dir);
#endif

    return arr;
}

/* realpath() - resolve canonical path */
static JSValue tjs_syncfs_realpath(JSContext* ctx,
    JSValueConst this_val,
    int argc, JSValueConst* argv)
{
    const char* path;

    if (argc < 1)
        return JS_ThrowTypeError(ctx, "realpath() requires 1 argument: path");

    path = JS_ToCString(ctx, argv[0]);
    if (!path) return JS_EXCEPTION;

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }

    HANDLE hFile = CreateFileW(wpath,
        0,    // query only
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);
    free(wpath);
    if (hFile == INVALID_HANDLE_VALUE) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    /* 2. get final path (resolved symlinks, ., and ..) */
    WCHAR wbuf[MAX_PATH * 4];
    DWORD len = GetFinalPathNameByHandleW(hFile, wbuf, sizeof(wbuf) / sizeof(WCHAR),
        VOLUME_NAME_DOS);
    CloseHandle(hFile);
    if (len == 0 || len >= sizeof(wbuf) / sizeof(WCHAR)) {
        DWORD err = (len == 0) ? ERROR_GEN_FAILURE : ERROR_INSUFFICIENT_BUFFER;
        JSValue err_val = tjs_throw_errno_path(ctx, uv_translate_sys_error(err), path);
        JS_FreeCString(ctx, path);
        return err_val;
    }

    const WCHAR* out = wbuf;
    // UNC path: \\?\UNC\server\share\file.txt -> \\server\share\file.txt
    if (wcsncmp(out, L"\\\\?\\", 4) == 0) {
        out += 4;
        if (wcsncmp(out, L"UNC\\", 4) == 0) {
            // Convert \\?\UNC\server\share to \\server\share
            // We need to modify the buffer, so use a non-const pointer
            WCHAR* out_mut = (WCHAR*) out;
            out_mut -= 2;
            *out_mut = L'\\';
            out = out_mut;
        }
    }
    char *utf8_out = wcs_to_utf8(out, -1);
    if (!utf8_out) {
        JSValue err_val = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err_val;
    }
    JSValue result = JS_NewString(ctx, utf8_out);
    free(utf8_out);
    JS_FreeCString(ctx, path);
    return result;
#else
    // Use NULL to let realpath allocate, which is safer than PATH_MAX on some platforms
    char* ret = realpath(path, NULL);
    if (!ret) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);
    JSValue result = JS_NewString(ctx, ret);
    free(ret);
    return result;
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
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        THROW2("flock")
    }

    OVERLAPPED overlapped = { 0 };
    DWORD flags = 0;

    // LOCK_SH = 1, LOCK_EX = 2, LOCK_UN = 8, LOCK_NB = 4
    if (operation & 8) { // LOCK_UN
        if (!UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &overlapped)) {
            THROW2("unlock")
        }
    }
    else {
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
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
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
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
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
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }

    HANDLE hFile = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    LARGE_INTEGER li;
    li.QuadPart = length;

    if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        CloseHandle(hFile);
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    CloseHandle(hFile);
    JS_FreeCString(ctx, path);
#else
    int ret = truncate(path, length);
    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);
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
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
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

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

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

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);
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
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }

    HANDLE hFile = CreateFileW(wpath, FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    FILETIME ft_atime, ft_mtime;
    ULARGE_INTEGER ul;

    // Convert Unix timestamp (seconds since 1970) to Windows FILETIME (100ns since 1601)
    ul.QuadPart = (ULONGLONG) ((atime + 11644473600.0) * 10000000.0);
    ft_atime.dwLowDateTime = ul.LowPart;
    ft_atime.dwHighDateTime = ul.HighPart;

    ul.QuadPart = (ULONGLONG) ((mtime + 11644473600.0) * 10000000.0);
    ft_mtime.dwLowDateTime = ul.LowPart;
    ft_mtime.dwHighDateTime = ul.HighPart;

    if (!SetFileTime(hFile, NULL, &ft_atime, &ft_mtime)) {
        CloseHandle(hFile);
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(GetLastError()), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    CloseHandle(hFile);
    JS_FreeCString(ctx, path);
#else
    struct timeval times[2];
    times[0].tv_sec = (time_t) atime;
    times[0].tv_usec = (suseconds_t) ((atime - times[0].tv_sec) * 1000000);
    times[1].tv_sec = (time_t) mtime;
    times[1].tv_usec = (suseconds_t) ((mtime - times[1].tv_sec) * 1000000);

    int ret = utimes(path, times);

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);
#endif

    return JS_UNDEFINED;
}

/* futimes() - change file access and modification times by fd */
static JSValue tjs_syncfs_futimes(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t fd;
    double atime, mtime;

    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "futimes() requires 3 arguments: fd, atime, mtime");
    }

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) {
        return JS_EXCEPTION;
    }

    if (JS_ToFloat64(ctx, &atime, argv[1]) < 0) {
        return JS_EXCEPTION;
    }

    if (JS_ToFloat64(ctx, &mtime, argv[2]) < 0) {
        return JS_EXCEPTION;
    }

#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        return JS_ThrowTypeError(ctx, "futimes: invalid file descriptor");
    }

    FILETIME ft_atime, ft_mtime;
    ULARGE_INTEGER ul;

    ul.QuadPart = (ULONGLONG) ((atime + 11644473600.0) * 10000000.0);
    ft_atime.dwLowDateTime = ul.LowPart;
    ft_atime.dwHighDateTime = ul.HighPart;

    ul.QuadPart = (ULONGLONG) ((mtime + 11644473600.0) * 10000000.0);
    ft_mtime.dwLowDateTime = ul.LowPart;
    ft_mtime.dwHighDateTime = ul.HighPart;

    if (!SetFileTime(hFile, NULL, &ft_atime, &ft_mtime)) {
        return tjs_throw_errno(ctx, uv_translate_sys_error(GetLastError()));
    }
#else
    struct timeval times[2];
    times[0].tv_sec = (time_t) atime;
    times[0].tv_usec = (suseconds_t) ((atime - times[0].tv_sec) * 1000000);
    times[1].tv_sec = (time_t) mtime;
    times[1].tv_usec = (suseconds_t) ((mtime - times[1].tv_sec) * 1000000);

    if (futimes(fd, times) < 0) {
        return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
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

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_translate_sys_error(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    return JS_UNDEFINED;
}

/* Module function list */
static const JSCFunctionListEntry tjs_syncfs_funcs[] = {
    /* File status */
    JS_CFUNC_DEF("stat", 1, tjs_syncfs_stat),
    JS_CFUNC_DEF("fstat", 1, tjs_syncfs_fstat),
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
    JS_CFUNC_DEF("futimes", 3, tjs_syncfs_futimes),

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
