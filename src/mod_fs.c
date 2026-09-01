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

/*
 * `_wopen` opens without FILE_SHARE_DELETE, so a file cno holds open cannot be
 * unlinked or renamed by anyone — including cno itself. libuv always passes
 * FILE_SHARE_READ|WRITE|DELETE, so real Node deletes an open file happily while
 * cno returned EACCES (sync) / EBUSY (async). Measured: holding a read fd then
 * unlinking gives "OK" on Node v24.18.0 and EACCES here. That surfaced as five
 * separate `cts.lock` EACCES test failures, which looked like a locking bug
 * rather than an open-flags bug.
 *
 * The CRT exposes no share-delete flag (`_SH_DENY*` cannot express it), so open
 * through CreateFileW and adopt the handle into a CRT fd.
 */
static int tjs__wopen_shared(const WCHAR *wpath, int flags, int mode) {
    DWORD access;
    switch (flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
        case O_WRONLY: access = GENERIC_WRITE; break;
        case O_RDWR:   access = GENERIC_READ | GENERIC_WRITE; break;
        default:       access = GENERIC_READ; break;
    }
    if (flags & O_APPEND) access = (access & ~GENERIC_WRITE) | FILE_APPEND_DATA | SYNCHRONIZE;

    DWORD disposition;
    const int create_excl = (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
    if (create_excl)                          disposition = CREATE_NEW;
    else if (flags & O_CREAT) disposition = (flags & O_TRUNC) ? CREATE_ALWAYS : OPEN_ALWAYS;
    else                      disposition = (flags & O_TRUNC) ? TRUNCATE_EXISTING : OPEN_EXISTING;

    /* Mode only controls the read-only attribute on Windows, matching _wopen. */
    DWORD attrs = ((flags & O_CREAT) && !(mode & 0200)) ? FILE_ATTRIBUTE_READONLY
                                                        : FILE_ATTRIBUTE_NORMAL;

    /*
     * Setting this makes it possible to open a DIRECTORY, which libuv does
     * unconditionally in fs__open ("Setting this flag makes it possible to open a
     * directory"). Without it, opening a directory failed ERROR_ACCESS_DENIED.
     * Measured 2026-08-04, and note Node distinguishes read from write intent:
     *
     *                       cno (before)   node v24.18.0
     *   openSync(dir,'r')   EACCES         returns an fd
     *   openSync(dir,'w')   EACCES         EISDIR
     *   readFileSync(dir)   EACCES         EISDIR
     *
     * cno's own async path already matched Node on all three, because it goes
     * through uv_fs_open -- the same sync/async tell as rename and unlink.
     */
    attrs |= FILE_FLAG_BACKUP_SEMANTICS;

    HANDLE h = CreateFileW(wpath, access,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, disposition, attrs, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        /* Callers read `errno`, so translate rather than leaving a Win32 code. */
        DWORD e = GetLastError();
        switch (e) {
            case ERROR_FILE_NOT_FOUND:
            case ERROR_PATH_NOT_FOUND:    errno = ENOENT; break;
            case ERROR_FILE_EXISTS:
                /*
                 * libuv's fs__open: "when ERROR_FILE_EXISTS happens and
                 * UV_FS_O_CREAT was specified, it means the path referred to a
                 * directory". That is how a write-intent open of a directory
                 * becomes EISDIR instead of EEXIST, for both creating
                 * dispositions -- CREATE_ALWAYS for 'w' (O_CREAT|O_TRUNC) and
                 * OPEN_ALWAYS for 'a' (O_CREAT). The !O_EXCL guard is
                 * load-bearing and copied deliberately: with O_CREAT|O_EXCL the
                 * disposition is CREATE_NEW, and an existing plain FILE must keep
                 * reporting EEXIST ('wx'/'ax').
                 *
                 * ERROR_ALWAYS_EXISTS is deliberately NOT folded in here, unlike
                 * an earlier draft of this patch: OPEN_ALWAYS/CREATE_ALWAYS report
                 * ERROR_ALREADY_EXISTS as a non-error last-error on SUCCESS, so a
                 * genuine failure carrying it is not the directory case and must
                 * stay EEXIST. libuv special-cases only ERROR_FILE_EXISTS.
                 */
                if ((flags & O_CREAT) && !(flags & O_EXCL)) errno = EISDIR;
                else                                        errno = EEXIST;
                break;
            case ERROR_ALREADY_EXISTS:    errno = EEXIST; break;
            case ERROR_ACCESS_DENIED:     errno = EACCES; break;
            case ERROR_SHARING_VIOLATION: errno = EACCES; break;
            case ERROR_TOO_MANY_OPEN_FILES: errno = EMFILE; break;
            case ERROR_INVALID_NAME:
            case ERROR_DIRECTORY:         errno = ENOENT; break;
            default:                      errno = EINVAL; break;
        }
        return -1;
    }

    /* _open_osfhandle only understands these; the rest were applied above. */
    int osf = flags & (O_RDONLY | O_APPEND | O_TEXT | O_WRONLY);
    int fd = _open_osfhandle((intptr_t) h, osf);
    if (fd < 0) {
        CloseHandle(h);
        errno = EMFILE;
        return -1;
    }
    return fd;
}
#define stat _stat64
#define fstat _fstat64
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
/* MSVC's <sys/stat.h> has no S_IFLNK; libuv's uv/win.h defines it as 0xA000
 * and uv_fs_lstat() sets it, so lstat() can report symlinks like POSIX. */
#ifndef S_IFLNK
#define S_IFLNK 0xA000
#endif
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
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
    if (!ReadFile((HANDLE) _get_osfhandle(fd), buf, (DWORD) len, &rd, &ov)) {
        if (GetLastError() == ERROR_HANDLE_EOF) return 0;
        return -1;
    }
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
        JS_FreeCString(ctx, str);
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

/* Sync fs paths set a CRT `errno`, NOT a Win32 error code. The two numbering
 * spaces overlap but mean different things, so feeding errno to
 * uv_translate_sys_error() silently mistranslates: EACCES(13) reads as
 * ERROR_INVALID_DATA(13) -> UV_EINVAL, and codes with no Win32 twin come out
 * UV_UNKNOWN, which no `e.code === 'ENOENT'` check can ever match. Use this
 * wherever the error came from errno; use uv_translate_sys_error(GetLastError())
 * for genuine Win32 failures. Measured against real Node v24.18.0 before/after. */
static inline int fs_errno2uv(int crt_err) {
#ifdef _WIN32
    return crt2uv(crt_err);
#else
    return uv_translate_sys_error(crt_err);
#endif
}

#define THROW_PATH() return JS_ThrowTypeError(ctx, "path is not a string");
#define THROW_FD() return JS_ThrowTypeError(ctx, "fd is not a number");
#define THROW_MODE() return JS_ThrowTypeError(ctx, "mode is not a number");

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

#ifdef _WIN32
/*
 * Windows stat timestamps, full 64-bit.
 *
 * libuv's uv_stat_t carries uv_timespec_t, whose tv_sec is a 32-bit `long` on
 * Windows (see the "not 2038-proof" note in deps/libuv/include/uv.h and libuv
 * issue 3864). uv__filetime_to_timespec computes the seconds as int64 and then
 * assigns them into that 32-bit field, so uv_fs_stat silently truncates any
 * timestamp at or beyond 2^31 seconds: a year-2038 stamp reads back as
 * -2147483648 (year 1901), and 4294967297 s reads back as 1 s.
 *
 * Measured 2026-08-03 on Windows 11: real Deno 2.9.3 round-trips both 2^31 and
 * 4294967297 on this same OS, and Node v24.18.0 wraps unsigned at 2^32, so this
 * is a cno defect rather than an OS limit -- and matching Node would not be
 * enough. The write path is already correct (it uses SetFileTime directly).
 *
 * The sub-second part survives (tv_nsec comes from filetime % TICKS_PER_SEC and
 * always fits), but the truncated seconds cannot be recovered from the low 32
 * bits alone, so read the FILETIME directly instead.
 *
 * FILETIME counts 100-ns ticks since 1601-01-01; the Unix epoch is 11644473600
 * seconds later, i.e. 116444736000000000 ticks, and 1 ms is 10000 ticks.
 * Verified both directions against a real file: 4294967297 s encodes to
 * 159394408970000000 ticks, which decodes back to 4294967297000 ms.
 *
 * tjs_win_stat_times_t and the two path/fd readers are declared in private.h so
 * mod_asyncfs.c can reuse them; the HANDLE-taking helper stays static because
 * private.h does not include windows.h.
 */
#define TJS_FILETIME_UNIX_EPOCH_TICKS 116444736000000000LL
#define TJS_FILETIME_TICKS_PER_MS 10000LL

static double tjs_filetime_ticks_to_ms(int64_t ticks) {
    int64_t rel = ticks - TJS_FILETIME_UNIX_EPOCH_TICKS;
    int64_t ms = rel / TJS_FILETIME_TICKS_PER_MS;

    /* C integer division truncates toward zero; floor instead so pre-1970
       stamps round the same way the POSIX timespec path does. */
    if (rel < 0 && (rel % TJS_FILETIME_TICKS_PER_MS) != 0) {
        ms -= 1;
    }

    return (double) ms;
}

static void tjs_win_stat_times_from_handle(HANDLE handle, tjs_win_stat_times_t* out) {
    FILE_BASIC_INFO bi;

    out->valid = 0;
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &bi, sizeof(bi))) {
        return;
    }

    /* Same field mapping libuv's fs__stat_handle uses: atim from LastAccessTime,
       mtim from LastWriteTime, ctim from ChangeTime, birthtim from CreationTime. */
    out->atim_ms = tjs_filetime_ticks_to_ms(bi.LastAccessTime.QuadPart);
    out->mtim_ms = tjs_filetime_ticks_to_ms(bi.LastWriteTime.QuadPart);
    out->ctim_ms = tjs_filetime_ticks_to_ms(bi.ChangeTime.QuadPart);
    out->birthtim_ms = tjs_filetime_ticks_to_ms(bi.CreationTime.QuadPart);
    out->valid = 1;
}

void tjs_win_stat_times_from_path(const char* path,
                                 int follow_symlinks,
                                 tjs_win_stat_times_t* out) {
    WCHAR* wpath;
    HANDLE handle;
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;

    out->valid = 0;
    wpath = utf8_to_wcs(path);
    if (!wpath) {
        return;
    }
    if (!follow_symlinks) {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }

    /* FILE_READ_ATTRIBUTES only, so this never blocks on a file opened for
       exclusive data access. FILE_FLAG_BACKUP_SEMANTICS is what lets a
       directory be opened at all. */
    handle = CreateFileW(wpath,
                         FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         flags,
                         NULL);
    free(wpath);
    if (handle == INVALID_HANDLE_VALUE) {
        return;
    }
    tjs_win_stat_times_from_handle(handle, out);
    CloseHandle(handle);
}

void tjs_win_stat_times_from_fd(int fd, tjs_win_stat_times_t* out) {
    intptr_t raw = _get_osfhandle(fd);

    out->valid = 0;
    /* _get_osfhandle yields -1 for a bad fd and -2 for a closed stdio slot. */
    if (raw == -1 || raw == -2) {
        return;
    }
    tjs_win_stat_times_from_handle((HANDLE) raw, out);
}

/* times may be NULL or invalid, in which case libuv's own (possibly truncated)
   timespec values are used -- a stat never fails just because the extra
   FILETIME read did. */
static inline JSValue build_uv_stat_obj(JSContext* ctx,
                                        const uv_stat_t* st,
                                        const tjs_win_stat_times_t* times) {
    JSValue obj = JS_NewObject(ctx);

#define SET_UINT64_FIELD(x) \
    JS_DefinePropertyValueStr(ctx, obj, STRINGIFY(x), JS_NewInt64(ctx, (int64_t) st->st_##x), JS_PROP_C_W_E);

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
#undef SET_UINT64_FIELD

#define SET_TIMESPEC_FIELD(x) \
    JS_DefinePropertyValueStr(ctx, obj, STRINGIFY(x), \
        JS_NewDate(ctx, (times && times->valid) ? times->x##_ms \
                                               : (st->st_##x.tv_sec * 1e3 + st->st_##x.tv_nsec / 1e6)), \
        JS_PROP_C_W_E);

    SET_TIMESPEC_FIELD(atim);
    SET_TIMESPEC_FIELD(mtim);
    SET_TIMESPEC_FIELD(ctim);
    SET_TIMESPEC_FIELD(birthtim);
#undef SET_TIMESPEC_FIELD

    JS_SetPropertyStr(ctx, obj, "isBlockDevice", JS_NewBool(ctx, S_ISBLK(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isCharacterDevice", JS_NewBool(ctx, S_ISCHR(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, S_ISDIR(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isFIFO", JS_NewBool(ctx, S_ISFIFO(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, S_ISREG(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSocket", JS_NewBool(ctx, S_ISSOCK(st->st_mode)));
    JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, S_ISLNK(st->st_mode)));
    return obj;
}
#endif

static JSValue build_statfs_obj(JSContext* ctx, const uv_statfs_t* st) {
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(obj)) {
        return obj;
    }

#define SET_STATFS_FIELD(x) \
    JS_DefinePropertyValueStr(ctx, obj, STRINGIFY(x), JS_NewInt64(ctx, (int64_t) st->f_##x), JS_PROP_C_W_E);
    SET_STATFS_FIELD(type);
    SET_STATFS_FIELD(bsize);
    SET_STATFS_FIELD(blocks);
    SET_STATFS_FIELD(bfree);
    SET_STATFS_FIELD(bavail);
    SET_STATFS_FIELD(files);
    SET_STATFS_FIELD(ffree);
#undef SET_STATFS_FIELD

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
#ifndef _WIN32
    struct stat st;
#endif

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "stat() requires 1 argument: path");
    }

    path = JS_ToCString(ctx, argv[0]);
    if (!path)  THROW_PATH();

#ifdef _WIN32
    uv_fs_t req;
    tjs_win_stat_times_t wtimes;
    int ret = uv_fs_stat(NULL, &req, path, NULL);
#else
    int ret = stat(path, &st);
#endif

    if (ret < 0) {
#ifdef _WIN32
        JSValue err = tjs_throw_errno_path(ctx, ret, path);
        uv_fs_req_cleanup(&req);
#else
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
#endif
        JS_FreeCString(ctx, path);
        return err;
    }
#ifdef _WIN32
    /* Read the 64-bit FILETIME before path is released. */
    tjs_win_stat_times_from_path(path, 1, &wtimes);
#endif
    JS_FreeCString(ctx, path);

#ifdef _WIN32
    JSValue result = build_uv_stat_obj(ctx, &req.statbuf, &wtimes);
    uv_fs_req_cleanup(&req);
    return result;
#else
    return build_stat_obj(ctx, &st);
#endif
}

/* fstat() - get file status by fd */
static JSValue tjs_syncfs_fstat(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
#ifndef _WIN32
    struct stat st;
#endif
    int fd;

    if (argc < 1 || -1 == JS_ToInt32(ctx, &fd, argv[0])) {
        return JS_ThrowTypeError(ctx, "stat() requires 1 number argument: fd");
    }

#ifdef _WIN32
    uv_fs_t req;
    tjs_win_stat_times_t wtimes;
    int ret = uv_fs_fstat(NULL, &req, fd, NULL);
#else
    int ret = fstat(fd, &st);
#endif

    if (ret < 0) {
#ifdef _WIN32
        JSValue err = tjs_throw_errno(ctx, ret);
        uv_fs_req_cleanup(&req);
#else
        JSValue err = tjs_throw_errno(ctx, fs_errno2uv(errno));
#endif
        return err;
    }

#ifdef _WIN32
    tjs_win_stat_times_from_fd(fd, &wtimes);
    JSValue result = build_uv_stat_obj(ctx, &req.statbuf, &wtimes);
    uv_fs_req_cleanup(&req);
    return result;
#else
    return build_stat_obj(ctx, &st);
#endif
}

/* lstat() - like stat but doesn't follow symlinks */
static JSValue tjs_syncfs_lstat(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "lstat() requires 1 argument: path");
    }

    path = JS_ToCString(ctx, argv[0]);
    if (!path) THROW_PATH();

#ifdef _WIN32
    /* MSVC has no lstat; libuv also preserves sub-second timestamps. */
    uv_fs_t lreq;
    tjs_win_stat_times_t wtimes;
    int ret = uv_fs_lstat(NULL, &lreq, path, NULL);
    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, ret, path);
        uv_fs_req_cleanup(&lreq);
        JS_FreeCString(ctx, path);
        return err;
    }
    /* Do not follow the link: lstat must describe the reparse point itself. */
    tjs_win_stat_times_from_path(path, 0, &wtimes);
    JS_FreeCString(ctx, path);
    JSValue result = build_uv_stat_obj(ctx, &lreq.statbuf, &wtimes);
    uv_fs_req_cleanup(&lreq);
    return result;
#else
    struct stat st;
    int ret = lstat(path, &st);

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }
    JS_FreeCString(ctx, path);

    return build_stat_obj(ctx, &st);
#endif
}

/* statFs() - get filesystem status */
static JSValue tjs_syncfs_statfs(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    uv_fs_t req;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "statFs() requires 1 argument: path");
    }

    path = JS_ToCString(ctx, argv[0]);
    if (!path) THROW_PATH();

    int ret = uv_fs_statfs(NULL, &req, path, NULL);
    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, ret, path);
        JS_FreeCString(ctx, path);
        uv_fs_req_cleanup(&req);
        return err;
    }

    JSValue result = build_statfs_obj(ctx, (const uv_statfs_t*) req.ptr);
    JS_FreeCString(ctx, path);
    uv_fs_req_cleanup(&req);
    return result;
}

/* exists() - check if file exists */
static JSValue tjs_syncfs_exists(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* path;
    struct stat st;

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "exists() requires 1 argument: path");
    }

    path = JS_ToCString(ctx, argv[0]);
    if (!path)  THROW_PATH();

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
    if (!path) THROW_PATH();

    flags = parse_open_flags(ctx, argv[1]);
    if (flags < 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "Invalid flags");
    }

    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &mode, argv[2]) < 0) {
            JS_FreeCString(ctx, path);
            THROW_MODE();
        }
    }

    int fd;
#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    fd = tjs__wopen_shared(wpath, flags, mode);
    free(wpath);
#else
    fd = open(path, flags, mode);
#endif

    if (fd < 0) {
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

    // Convert offset BEFORE getting buffer pointer (offset conversion can detach buffer)
    if (JS_ToInt64(ctx, &offset, argv[2]) < 0) {
        return JS_ThrowTypeError(ctx, "invaild offset: expect number or bigint");
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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
    if (!path) THROW_PATH();

    int fd;
#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }
    fd = tjs__wopen_shared(wpath, O_RDONLY | O_BINARY, 0);
    free(wpath);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    if (fstat(fd, &st) < 0) {
        close(fd);
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    /*
     * A directory is now openable read-only (see FILE_FLAG_BACKUP_SEMANTICS in
     * tjs__wopen_shared), so reject it here instead of letting the read loop below
     * run. Node reports EISDIR for readFileSync on a directory, and so does
     * libuv's fs__read on a directory fd -- measured 2026-08-04, cno's own async
     * fh.read(dirfd) returned UV_EISDIR (-4068). Without this check the read would
     * fail with ERROR_INVALID_FUNCTION -> EINVAL, which matches neither.
     *
     * S_ISDIR works on both legs: MSVC has no S_ISDIR, so this file defines it at
     * :105 in terms of _S_IFDIR.
     */
    if (S_ISDIR(st.st_mode)) {
        close(fd);
        JSValue err = tjs_throw_errno_path(ctx, UV_EISDIR, path);
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
                JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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
            JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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
    if (!path) THROW_PATH();

    // Convert mode BEFORE getting data buffer (mode conversion can detach buffer)
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        if (JS_ToInt32(ctx, &mode, argv[2]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_ThrowTypeError(ctx, "mode must be a number");
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
    fd = tjs__wopen_shared(wpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, mode);
    free(wpath);
#else
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
#endif

    if (fd < 0) {
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
        JS_FreeCString(ctx, path);
        return err;
    }

    ssize_t total_written = 0;
    while (total_written < (ssize_t) data_len) {
        ssize_t n = write(fd, data + total_written, data_len - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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
    if (!path) THROW_PATH();

    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &mode, argv[1]) < 0) {
            JS_FreeCString(ctx, path);
            return JS_ThrowTypeError(ctx, "mode must be a number");
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
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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
    if (!path) THROW_PATH();

#ifdef _WIN32
    /*
     * Delegate to libuv rather than calling _wrmdir, for consistency with the
     * unlink path above: both end up in libuv's fs__unlink_rmdir, so a directory
     * carrying the readonly attribute is removable, matching Node.
     *
     * It also fixes the error code for a non-directory target. Measured
     * 2026-08-04: rmdirSync on a FILE symlink gave EINVAL here (_wrmdir sets
     * ERROR_DIRECTORY) where node v24.18.0 gives ENOENT. libuv maps that case to
     * UV_ENOENT explicitly.
     *
     * Error convention: negative UV code from uv_fs_*, used as-is.
     */
    uv_fs_t req;
    int ret = uv_fs_rmdir(NULL, &req, path, NULL);
    int uv_err = ret;
    uv_fs_req_cleanup(&req);
#else
    int ret = rmdir(path);
    int uv_err = fs_errno2uv(errno);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_err, path);
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
    if (!path) THROW_PATH();

#ifdef _WIN32
    /*
     * Delegate to libuv rather than calling _wunlink.
     *
     * _wunlink is DeleteFileW, which refuses a DIRECTORY reparse point:
     * ERROR_ACCESS_DENIED -> EACCES. POSIX unlink(2) removes a symlink whatever
     * its target is, and Node does too. Measured 2026-08-04 vs node v24.18.0,
     * with the three Win32 reparse shapes tested separately because they take
     * different kernel paths:
     *
     *                       cno fs.unlinkSync   node fs.unlinkSync
     *   directory symlink   THREW EACCES        OK
     *   junction            THREW EACCES        OK
     *   file symlink        OK                  OK      <- so not a blanket bug
     *   readonly file       THREW EACCES        OK
     *
     * Only the two DIRECTORY-shaped reparse points and the readonly file fail,
     * which is exactly the DeleteFileW signature. cno's own async fsp.unlink and
     * Deno.removeSync already handled all of them, because uv_fs_unlink opens
     * with FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, verifies
     * the reparse point is a real symlink, and deletes with
     * FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE.
     *
     * Deleting a link must not touch the target; verified intact in the repro.
     *
     * Error convention: uv_fs_* yields a negative UV code, passed through
     * unchanged. fs_errno2uv() is for CRT errno only.
     */
    uv_fs_t req;
    int ret = uv_fs_unlink(NULL, &req, path, NULL);
    int uv_err = ret;
    uv_fs_req_cleanup(&req);
#else
    int ret = unlink(path);
    int uv_err = fs_errno2uv(errno);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_err, path);
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
    if (!existing_path) THROW_PATH();

    new_path = JS_ToCString(ctx, argv[1]);
    if (!new_path) {
        JS_FreeCString(ctx, existing_path);
        THROW_PATH();
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
        int uv_err = fs_errno2uv(errno);
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
        int uv_err = fs_errno2uv(errno);
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
    /* Only the POSIX leg uses this: the Windows leg delegates to
     * uv_fs_readlink, which owns its buffer via uv_fs_t.ptr and returns early. */
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
    /*
     * Delegate to libuv, which is what Node itself uses.
     *
     * The previous hand-rolled DeviceIoControl path only accepted
     * IO_REPARSE_TAG_SYMLINK, so a **junction** (IO_REPARSE_TAG_MOUNT_POINT) —
     * which is exactly what `cts/src/resolve/linker.ts` creates via
     * `asyncfs.symlink(..., FS_SYMLINK_JUNCTION)` — left `link_path` NULL. The
     * guard then read `GetLastError()` *after a successful DeviceIoControl*, so
     * it formatted error code 0 and threw the nonsense
     * "Failed to read symbolic link: The operation completed successfully."
     * Measured: `readlinkSync` on a junction gave UNKNOWN(-4094) here while Node
     * returned the target. That accounted for 4 failures in linker.test.ts.
     *
     * uv_fs_readlink handles SYMLINK, MOUNT_POINT and APPEXECLINK. A NULL loop
     * runs it synchronously — same pattern as the uv_fs_stat call at :697, which
     * likewise passes the negative `ret` (a UV code) rather than `errno`.
     */
    uv_fs_t req;
    int ret = uv_fs_readlink(NULL, &req, path, NULL);
    if (ret < 0) {
        JSValue error = tjs_throw_errno_path(ctx, ret, path);
        uv_fs_req_cleanup(&req);
        JS_FreeCString(ctx, path);
        return error;
    }
    result = JS_NewString(ctx, (const char *) req.ptr);
    uv_fs_req_cleanup(&req);
    JS_FreeCString(ctx, path);
    return result;
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
        int uv_err = fs_errno2uv(errno);
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
        int uv_err = fs_errno2uv(errno);
        JSValue err = tjs_throw_errno_path(ctx, uv_err, src_path);
        JS_FreeCString(ctx, src_path);
        JS_FreeCString(ctx, dest_path);
        return err;
    }

    // Check if source is a regular file (don't copy directories or special files)
    if (fstat(src_fd, &src_stat) == -1) {
        int uv_err = fs_errno2uv(errno);
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
        int uv_err = fs_errno2uv(errno);
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
    if (!oldpath) THROW_PATH();

    newpath = JS_ToCString(ctx, argv[1]);
    if (!newpath) {
        JS_FreeCString(ctx, oldpath); THROW_PATH();
    }

#ifdef _WIN32
    /*
     * Delegate to libuv rather than calling _wrename.
     *
     * POSIX rename(2) REPLACES an existing destination silently, and both Node
     * and Deno do the same on Windows. MSVC's _wrename does not: it fails with
     * EEXIST as soon as the target exists. Measured 2026-08-04 on Windows 11
     * against node v24.18.0:
     *
     *   cno  fs.renameSync(a, b)   b exists -> THREW EEXIST
     *   cno  Deno.renameSync(a, b) b exists -> THREW EEXIST
     *   cno  Deno.rename  (async)  b exists -> OK          <- already correct
     *   node fs.renameSync(a, b)   b exists -> OK          <- the oracle
     *
     * The async path was already right because uv_fs_rename passes
     * MOVEFILE_REPLACE_EXISTING to MoveFileExW; that sync/async split inside cno
     * is what rules out "Windows cannot do this". Using uv_fs_rename here also
     * fixes the error code for the failure cases: _wrename reported EEXIST for
     * renaming onto a directory, where Node reports EPERM.
     *
     * A NULL loop runs the request synchronously, the same pattern already used
     * by uv_fs_stat at :816 and uv_fs_readlink at :1785.
     *
     * Error convention: uv_fs_* returns a negative UV code in `ret`, so it goes
     * to tjs_throw_errno_path() AS-IS. Passing it through fs_errno2uv() would be
     * a double translation, since that helper expects a CRT errno.
     */
    uv_fs_t req;
    int ret = uv_fs_rename(NULL, &req, oldpath, newpath, NULL);
    int uv_err = ret;
    uv_fs_req_cleanup(&req);
#else
    int ret = rename(oldpath, newpath);
    int uv_err = fs_errno2uv(errno);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_err, oldpath);
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
    if (!path) THROW_PATH();
    if (argc >= 2) {
        int32_t types_flag;
        if (JS_ToInt32(ctx, &types_flag, argv[1]) < 0) {
            JS_FreeCString(ctx, path);
            THROW_MODE();
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
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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
    if (!path) THROW_PATH();

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
        JSValue err_val = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();
    if (JS_ToInt32(ctx, &operation, argv[1]) < 0)
        return JS_ThrowTypeError(ctx, "invaild operation: expect a number");

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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

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
    if (!path) THROW_PATH();

    if (JS_ToInt64(ctx, &length, argv[1]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "length should be a number");
    }

#ifdef _WIN32
    WCHAR *wpath = utf8_to_wcs(path);
    if (!wpath) { JS_FreeCString(ctx, path); return JS_ThrowOutOfMemory(ctx); }

    /*
     * Share flags matter here. This used to pass dwShareMode 0, which denies all
     * concurrent access, so truncating a file that anything else -- including cno
     * itself -- had open failed. Measured 2026-08-04:
     *
     *   cno  openSync(p,'r') then truncateSync(p, 2) -> THREW EBUSY
     *   node openSync(p,'r') then truncateSync(p, 2) -> OK, size 2
     *
     * libuv opens with FILE_SHARE_READ|WRITE|DELETE (fs__open), and the long
     * comment at the top of this file records the same class of bug for _wopen
     * lacking FILE_SHARE_DELETE. Matching libuv's share set fixes it.
     *
     * Kept as CreateFileW rather than uv_fs_open + uv_fs_ftruncate to stay a
     * one-line semantic change; the remaining known divergence is that truncating
     * a DIRECTORY reports EPERM here and EINVAL in Node (see the survey).
     */
    HANDLE hFile = CreateFileW(wpath, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();
    if (JS_ToInt64(ctx, &length, argv[1]) < 0)
        return JS_ThrowTypeError(ctx, "length should be a number");

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
    if (!path) THROW_PATH();

    if (JS_ToInt32(ctx, &mode, argv[1]) < 0) {
        JS_FreeCString(ctx, path);
        THROW_MODE();
    }

#ifdef _WIN32
    /*
     * Delegate to libuv rather than calling _chmod.
     *
     * libuv's fs__chmod is _wchmod, i.e. the same CRT call with a wide path, so
     * the semantics are identical -- only the read-only attribute moves either
     * way. The reason to route through uv is the path encoding: `_chmod` takes a
     * char* and interprets it in the ANSI code page. No failure was OBSERVED here
     * (this host is ACP 65001, so UTF-8 bytes survive), but that is a machine
     * property; on a CP1252 host a Japanese or Cyrillic filename would not
     * round-trip. Every other Windows leg in this file already converts with
     * utf8_to_wcs, so this was the odd one out.
     *
     * Error convention: negative UV code from uv_fs_*, used as-is. Note libuv
     * feeds _doserrno (a Win32 code) to SET_REQ_WIN32_ERROR here, so the decoding
     * happens inside libuv and must not be repeated with fs_errno2uv().
     */
    uv_fs_t req;
    int ret = uv_fs_chmod(NULL, &req, path, mode, NULL);
    int uv_err = ret;
    uv_fs_req_cleanup(&req);
#else
    int ret = chmod(path, mode);
    int uv_err = fs_errno2uv(errno);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_err, path);
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();
    if (JS_ToInt32(ctx, &mode, argv[1]) < 0) THROW_MODE();

#ifdef _WIN32
    /*
     * Delegate to libuv rather than refusing.
     *
     * The old code here returned a bare JS_ThrowInternalError("fchmod not
     * supported on Windows"), which was wrong on two counts: it carried no errno
     * (so it surfaced as code UNKNOWN, matching no `e.code` check), and Windows
     * does in fact support this. libuv's fs__fchmod
     * (deps/libuv/src/win/fs.c:2567) implements it with ReOpenFile(
     * FILE_WRITE_ATTRIBUTES) + NtSetInformationFile, so Node succeeds.
     *
     * Contrast fchown/chown/lchown immediately below: libuv's fs__fchown
     * (:3105) really IS a bare SET_REQ_RESULT(req, 0) no-op, because Windows has
     * no POSIX uid/gid. Grouping fchmod with those was the original mistake --
     * only the chown family is genuinely unsupported.
     *
     * Measured 2026-08-04 vs node v24.18.0, mode read back with fstatSync:
     *
     *   route                        node            cno (before)
     *   fs.fchmodSync(fd, 0o444)     OK, 666->444    UNKNOWN, stays 666
     *   fs.fchmod(fd, 0o444, cb)     OK, 666->444    UNKNOWN, stays 666
     *   FileHandle.chmod(0o444)      OK, 666->444    OK, 666->444   <- already right
     *
     * That last row is the same sync/async tell as rename, unlink and open: the
     * async path already reached the correct behaviour through uv_fs_fchmod, so
     * "Windows cannot do this" was never the explanation.
     *
     * Error convention: uv_fs_* returns a negative UV code, passed through
     * as-is. fs_errno2uv() is for CRT errno only and must not be applied here.
     */
    uv_fs_t req;
    int ret = uv_fs_fchmod(NULL, &req, fd, mode, NULL);
    int uv_err = ret;
    uv_fs_req_cleanup(&req);
#else
    int ret = fchmod(fd, mode);
    int uv_err = fs_errno2uv(errno);
#endif

    if (ret < 0) {
        return tjs_throw_errno(ctx, uv_err);
    }

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
    if (!path) THROW_PATH();

    if (JS_ToInt32(ctx, &uid, argv[1]) < 0 || JS_ToInt32(ctx, &gid, argv[2]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "uid and gid should be positive numbers");
    }

#ifdef _WIN32
    JS_FreeCString(ctx, path);
    return JS_ThrowInternalError(ctx, "chown not supported on Windows");
#else
    int ret = chown(path, uid, gid);

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

    if (JS_ToInt32(ctx, &uid, argv[1]) < 0 || JS_ToInt32(ctx, &gid, argv[2]) < 0) {
        return JS_ThrowTypeError(ctx, "uid and gid should be positive numbers");
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
    if (!path) THROW_PATH();

    if (JS_ToFloat64(ctx, &atime, argv[1]) < 0 || JS_ToFloat64(ctx, &mtime, argv[2]) < 0) {
        JS_FreeCString(ctx, path);
        return JS_ThrowTypeError(ctx, "atime and mtime should be positive numbers");
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
        JSValue err = tjs_throw_errno_path(ctx, fs_errno2uv(errno), path);
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

    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) THROW_FD();

    if (JS_ToFloat64(ctx, &atime, argv[1]) < 0 || JS_ToFloat64(ctx, &mtime, argv[2]) < 0) {
        return JS_ThrowTypeError(ctx, "atime and mtime should be positive numbers");
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
        return tjs_throw_errno(ctx, fs_errno2uv(errno));
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
    if (!path) THROW_PATH();

    if (argc >= 2 && !JS_IsUndefined(argv[1])) {
        if (JS_ToInt32(ctx, &mode, argv[1]) < 0) {
            JS_FreeCString(ctx, path);
            THROW_MODE();
        }
    }

#ifdef _WIN32
    /*
     * Delegate to libuv rather than calling _access.
     *
     * _access only accepts mode bits 00/02/04/06. X_OK is 1, so accessSync(p,
     * X_OK) trips the UCRT invalid-parameter handler. Measured 2026-08-04:
     *
     *   cno  fs.accessSync(file, X_OK) -> THREW EINVAL, and the UCRT printed
     *        "minkernel\crts\ucrt\src\appcrt\filesystem\waccess.cpp(20) :
     *         Assertion failed: (access_mode & (~6)) == 0"
     *        straight to the console, which no JS program can suppress
     *   node fs.accessSync(file, X_OK) -> OK
     *
     * There is no executable bit on Windows, so libuv's fs__access ignores X_OK
     * and only rejects W_OK against FILE_ATTRIBUTE_READONLY. That also corrects a
     * second divergence measured in the same run: W_OK on a readonly file gave
     * EACCES here and EPERM in Node, because libuv reports UV_EPERM for it.
     *
     * As a bonus this stops passing a char* path to an ANSI CRT entry point.
     * Nothing was observed to break there -- this host runs ACP 65001 (UTF-8), so
     * `_access` happened to accept UTF-8 -- but that is a property of the machine,
     * not of the code, and it would fail on a CP1252 host.
     *
     * Error convention: negative UV code from uv_fs_*, used as-is.
     */
    uv_fs_t req;
    int ret = uv_fs_access(NULL, &req, path, mode, NULL);
    int uv_err = ret;
    uv_fs_req_cleanup(&req);
#else
    int ret = access(path, mode);
    int uv_err = fs_errno2uv(errno);
#endif

    if (ret < 0) {
        JSValue err = tjs_throw_errno_path(ctx, uv_err, path);
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
    JS_CFUNC_DEF("statFs", 1, tjs_syncfs_statfs),
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
