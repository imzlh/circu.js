/**
 * Circu.js Console
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

#include "capability.h"
#include "mem.h"
#include "private.h"

/* ── Platform abstractions ─────────────────────────────────────────── */
#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
# include <iphlpapi.h>
  typedef SOCKET sock_fd_t;
# define SOCK_INVALID        INVALID_SOCKET
# define sock_close(fd)      closesocket(fd)
# define sock_valid(fd)      ((fd) != INVALID_SOCKET)
# define THROW_STRERROR()    tjs_throw_errno(ctx, uv_translate_sys_error(WSAGetLastError()))
# define uv_poll_init_fd     uv_poll_init_socket
#else
# include <net/if.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
  typedef int sock_fd_t;
# define SOCK_INVALID        (-1)
# define sock_close(fd)      close(fd)
# define sock_valid(fd)      ((fd) >= 0)
# define THROW_STRERROR()    tjs_throw_errno(ctx, errno)
# define uv_poll_init_fd     uv_poll_init
#endif

#ifdef __APPLE__
# include <libproc.h>
# include <sys/proc_info.h>
#endif

/* ── Types ─────────────────────────────────────────────────────────── */
#define TJS_SOCK_CLASS_NAME "Socket"
static thread_local JSClassID tjs_sock_classid;

#ifdef _WIN32
typedef struct {
    sock_fd_t sock;
    int error;
    bool owned;
} tjs_sock_pin_t;
#else
typedef TJSPinnedFd tjs_sock_pin_t;
#endif

typedef struct {
    TJSRuntime *trt;
    sock_fd_t  sock;
    bool       close_on_close;
    bool       closed, poll_init, in_cb, finalized;
    bool       poll_closing;  /* uv_close on poll handle initiated */
    bool       poll_closed;   /* poll close_cb has fired */
    struct list_head runtime_link;
    bool       runtime_linked;
    JSValue    callback, this_obj;
    JSContext *jsctx;
    uv_poll_t  poll;
    tjs_sock_pin_t poll_pin;
} tjs_sock_t;

static void tjs_sock_list_add(tjs_sock_t *s) {
    init_list_head(&s->runtime_link);
    list_add(&s->runtime_link, &s->trt->sockets);
    s->runtime_linked = true;
}

static void tjs_sock_list_remove(tjs_sock_t *s) {
    if (!s->runtime_linked) return;
    list_del(&s->runtime_link);
    s->runtime_linked = false;
}

static tjs_sock_pin_t tjs_sock_pin_init(sock_fd_t sock) {
    return (tjs_sock_pin_t) { sock, 0, false };
}

static tjs_sock_pin_t tjs_sock_pin(sock_fd_t sock) {
#ifdef _WIN32
    tjs_sock_pin_t pin = tjs_sock_pin_init(sock);
    WSAPROTOCOL_INFOW info;
    if (WSADuplicateSocketW(sock, GetCurrentProcessId(), &info) != 0) {
        pin.sock = SOCK_INVALID;
        pin.error = WSAGetLastError();
        return pin;
    }

    DWORD flags = WSA_FLAG_OVERLAPPED;
# ifdef WSA_FLAG_NO_HANDLE_INHERIT
    flags |= WSA_FLAG_NO_HANDLE_INHERIT;
# endif
    pin.sock = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                          FROM_PROTOCOL_INFO, &info, 0, flags);
    if (!sock_valid(pin.sock)) {
        pin.error = WSAGetLastError();
        return pin;
    }
# ifndef WSA_FLAG_NO_HANDLE_INHERIT
    if (!SetHandleInformation((HANDLE) pin.sock, HANDLE_FLAG_INHERIT, 0)) {
        pin.error = WSAEINVAL;
        closesocket(pin.sock);
        pin.sock = SOCK_INVALID;
        return pin;
    }
# endif
    pin.owned = true;
    return pin;
#else
    return TJS_PinFd(sock);
#endif
}

static sock_fd_t tjs_sock_pin_socket(const tjs_sock_pin_t *pin) {
#ifdef _WIN32
    return pin->sock;
#else
    return pin->fd;
#endif
}

static int tjs_sock_pin_error(const tjs_sock_pin_t *pin) {
    return pin->error;
}

static bool tjs_sock_pin_owned(const tjs_sock_pin_t *pin) {
    return pin->owned;
}

static TJSObjectHandleIdentity tjs_sock_pin_matches_socket(
    const tjs_sock_pin_t *pin, sock_fd_t sock) {
    if (!pin->owned)
        return tjs_sock_pin_socket(pin) == sock
            ? TJS_OBJECT_HANDLE_IDENTITY_SAME
            : TJS_OBJECT_HANDLE_IDENTITY_DIFFERENT;
#ifdef _WIN32
    return TJS_CompareObjectHandles(
        (void *) (uintptr_t) tjs_sock_pin_socket(pin),
        (void *) (uintptr_t) sock);
#else
    struct stat pinned_stat;
    struct stat raw_stat;
    bool matches = fstat(tjs_sock_pin_socket(pin), &pinned_stat) == 0 &&
                   fstat(sock, &raw_stat) == 0 &&
                   pinned_stat.st_dev == raw_stat.st_dev &&
                   pinned_stat.st_ino == raw_stat.st_ino &&
                   (pinned_stat.st_mode & S_IFMT) ==
                       (raw_stat.st_mode & S_IFMT);
    return matches ? TJS_OBJECT_HANDLE_IDENTITY_SAME
                   : TJS_OBJECT_HANDLE_IDENTITY_DIFFERENT;
#endif
}

static void tjs_sock_unpin(tjs_sock_pin_t *pin) {
#ifdef _WIN32
    if (!pin || !pin->owned) return;
    int saved_error = WSAGetLastError();
    closesocket(pin->sock);
    WSASetLastError(saved_error);
    pin->sock = SOCK_INVALID;
    pin->owned = false;
#else
    TJS_UnpinFd(pin);
#endif
}

static JSValue tjs_sock_throw_pin_error(JSContext *ctx, int error) {
#ifdef _WIN32
    return tjs_throw_errno(ctx, uv_translate_sys_error(error));
#else
    return tjs_throw_errno(ctx, uv_translate_sys_error(error));
#endif
}

static bool tjs_sock_reget(JSContext *ctx, JSValueConst this_val,
                           tjs_sock_t **result) {
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);
    if (!s) {
        JS_ThrowTypeError(ctx, "expected " TJS_SOCK_CLASS_NAME);
        return false;
    }
    if (s->closed) {
        tjs_throw_errno_msg(ctx, UV_EBADF, "Socket closed");
        return false;
    }
    *result = s;
    return true;
}

static bool tjs_sock_revalidate_pin(JSContext *ctx, JSValueConst this_val,
                                    tjs_sock_t **state,
                                    tjs_sock_pin_t *pin,
                                    sock_fd_t *operation_sock) {
    if (!tjs_sock_reget(ctx, this_val, state)) {
        tjs_sock_unpin(pin);
        return false;
    }
    int error = tjs_sock_pin_error(pin);
    if (error) {
        tjs_sock_unpin(pin);
        tjs_sock_throw_pin_error(ctx, error);
        return false;
    }
    *operation_sock = tjs_sock_pin_socket(pin);
    return true;
}

/* ── Macros ────────────────────────────────────────────────────────── */

/* Declare `s`, validate opaque only (no closed check) */
#define DECL_SOCK(ctx, this_val, s)                                          \
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);               \
    if (!s) return JS_ThrowTypeError(ctx, "expected " TJS_SOCK_CLASS_NAME)

/* Declare `s`, validate opaque + closed */
#define GET_SOCK(ctx, this_val, s)                                           \
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);               \
    if (!s) return JS_ThrowTypeError(ctx, "expected " TJS_SOCK_CLASS_NAME);  \
    if (s->closed) return tjs_throw_errno_msg(ctx, UV_EBADF, "Socket closed")

/* Argument conversion and capability hooks can synchronously close or
 * otherwise re-enter this wrapper. Never use an opaque pointer or descriptor
 * cached across either boundary. */
#define REGET_SOCK(ctx, this_val, s)                                         \
    do {                                                                    \
        if (!tjs_sock_reget((ctx), (this_val), &(s)))                       \
            return JS_EXCEPTION;                                           \
    } while (0)

#define RET_THROW_ERRNO(ctx, cond)  if (!(cond)) return THROW_STRERROR()

/* Get Uint8Array from argv[n] into ptr/sz, return JS_EXCEPTION on failure */
#define ARGV_BUF(ctx, argv, n, ptr, sz) \
    size_t sz;                           \
    uint8_t *ptr = JS_GetUint8Array(ctx, &(sz), (argv)[n]); \
    if (!(ptr)) return JS_EXCEPTION

/* ── Lifecycle ─────────────────────────────────────────────────────── */

static JSValue tjs_sock_new_from_fd(JSContext *ctx, sock_fd_t fd, bool close_on_close) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_sock_classid);
    if (JS_IsException(obj)) {
        if (close_on_close) sock_close(fd);
        return obj;
    }

    /* The socket wrapper can outlive JS finalization while libuv finishes
     * closing the poll handle, so keep the host object on neutral heap
     * memory and only route embedded JSValues through QuickJS. */
    tjs_sock_t *s = tjs__mallocz(sizeof(*s));
    if (!s) {
        JS_FreeValue(ctx, obj);
        if (close_on_close) sock_close(fd);
        return JS_ThrowOutOfMemory(ctx);
    }
    s->sock           = fd;
    s->trt            = TJS_GetRuntime(ctx);
    s->close_on_close = close_on_close;
    s->callback       = JS_UNDEFINED;
    s->this_obj       = JS_UNDEFINED;
    s->jsctx          = ctx;
    s->poll_pin       = tjs_sock_pin_init(fd);
    tjs_sock_list_add(s);
    JS_SetOpaque(obj, s);
    return obj;
}

static void tjs_sock_poll_close_cb(uv_handle_t *handle) {
    tjs_sock_t *s = uv_handle_get_data(handle);
    if (!s) return;
    tjs_sock_unpin(&s->poll_pin);
    s->poll_closed = true;
    /* Only free once the JS wrapper has also been finalized; otherwise the
     * opaque pointer is still live and freeing here would be a use-after-free
     * on the next method call / finalizer. JSValues freed in finalizer. */
    if (s->finalized) {
        tjs_sock_list_remove(s);
        tjs__free(s);
    }
}

static JSValue tjs_sock_create(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "expected domain and type");
    unsigned domain, type, protocol = 0;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &domain,   argv[0]), 0, "uint");
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &type,     argv[1]), 1, "uint");
    if (argc > 2 && !JS_IsUndefined(argv[2]) && JS_ToUint32(ctx, &protocol, argv[2]))
        return JS_EXCEPTION;

    TJS_CAPABILITY(tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "socket.create", NULL), (void)0);
    sock_fd_t fd = socket(domain, type, protocol);
    RET_THROW_ERRNO(ctx, sock_valid(fd));
    return tjs_sock_new_from_fd(ctx, fd, true);
}

static int tjs_sock_fd_from_js(JSContext *ctx, JSValueConst value, sock_fd_t *result) {
#ifdef _WIN32
    const uint64_t maximum = (uint64_t) UINTPTR_MAX;
#else
    const uint64_t maximum = INT_MAX;
#endif
    uint64_t raw;

    if (JS_IsBigInt(value)) {
        int negative = 0;
        size_t count = 1;
        uint64_t word = 0;
        if (JS_GetBigIntWords(ctx, value, &negative, &count, &word) < 0)
            return -1;
        if (negative || count > 1 || word > maximum)
            return JS_ThrowRangeError(ctx, "socket descriptor is out of range"), -1;
        raw = word;
    } else {
        double number;
        if (!JS_IsNumber(value) || JS_ToFloat64(ctx, &number, value) < 0)
            return JS_ThrowTypeError(ctx, "socket descriptor must be a number or bigint"), -1;
        if (!isfinite(number) || trunc(number) != number || number < 0 ||
            number > 9007199254740991.0 || number > (double) maximum)
            return JS_ThrowRangeError(ctx, "socket descriptor is out of range"), -1;
        raw = (uint64_t) number;
    }

#ifdef _WIN32
    *result = (sock_fd_t) (uintptr_t) raw;
#else
    *result = (sock_fd_t) raw;
#endif
    return 0;
}

static JSValue tjs_sock_from_fd(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected socket fd");
    sock_fd_t fd;
    if (tjs_sock_fd_from_js(ctx, argv[0], &fd) < 0)
        return JS_EXCEPTION;
    bool close_on_close = false;

    /* Property access and the capability hook can close fd and reuse its
     * numeric slot. Duplicate before either re-entry boundary so this call
     * keeps referring to the socket supplied by the caller. */
    tjs_sock_pin_t pin = tjs_sock_pin(fd);

    if (argc > 1 && !JS_IsUndefined(argv[1])) {
        if (!JS_IsObject(argv[1])) {
            tjs_sock_unpin(&pin);
            return JS_ThrowTypeError(ctx, "createFrom options must be an object");
        }
        JSValue value = JS_GetPropertyStr(ctx, argv[1], "closeOnClose");
        if (JS_IsException(value)) {
            tjs_sock_unpin(&pin);
            return JS_EXCEPTION;
        }
        if (!JS_IsUndefined(value)) {
            int close_value = JS_ToBool(ctx, value);
            JS_FreeValue(ctx, value);
            if (close_value < 0) {
                tjs_sock_unpin(&pin);
                return JS_EXCEPTION;
            }
            close_on_close = close_value != 0;
        } else {
            JS_FreeValue(ctx, value);
        }
    }

    TJS_CAPABILITY(tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "socket.createFrom", NULL), tjs_sock_unpin(&pin));

    if (tjs_sock_pin_error(&pin)) {
        tjs_sock_unpin(&pin);
        return JS_ThrowTypeError(ctx, "not a valid socket descriptor");
    }

    /* Validate the pinned socket, never a same-number replacement. */
    int dummy; socklen_t dlen = sizeof(dummy);
    if (getsockopt(tjs_sock_pin_socket(&pin), SOL_SOCKET, SO_TYPE,
                   (char *) &dummy, &dlen) < 0) {
        tjs_sock_unpin(&pin);
        return JS_ThrowTypeError(ctx, "not a valid socket descriptor");
    }

    /* Build around the duplicate first. Allocation/GC may finalize another
     * wrapper that owned fd; only switch back to fd after all allocations. */
    sock_fd_t pinned_sock = tjs_sock_pin_socket(&pin);
    pin.owned = false;
    JSValue obj = tjs_sock_new_from_fd(ctx, pinned_sock, true);
    if (JS_IsException(obj))
        return obj;

    tjs_sock_t *s = JS_GetOpaque(obj, tjs_sock_classid);
    tjs_sock_pin_t owned_pin = tjs_sock_pin_init(pinned_sock);
    owned_pin.owned = true;
    TJSObjectHandleIdentity identity =
        tjs_sock_pin_matches_socket(&owned_pin, fd);
    if (identity == TJS_OBJECT_HANDLE_IDENTITY_UNSUPPORTED) {
        /* The wrapper owns pinned_sock now, so freeing it releases only the
         * duplicate and never the caller's socket. */
        JS_FreeValue(ctx, obj);
        return TJS_ThrowObjectHandleIdentityUnsupported(ctx);
    }
    if (identity == TJS_OBJECT_HANDLE_IDENTITY_SAME) {
        tjs_sock_unpin(&owned_pin);
        s->sock = fd;
        s->close_on_close = close_on_close;
        s->poll_pin = tjs_sock_pin_init(fd);
    }

    return obj;
}

static void close_sock(tjs_sock_t *s) {
    if (!s->closed) {
        s->closed = true;
        if (s->poll_init && uv_is_active((uv_handle_t *) &s->poll))
            uv_poll_stop(&s->poll);
        if (s->close_on_close && sock_valid(s->sock))
            sock_close(s->sock);
        s->sock = SOCK_INVALID;
    }
    /* A nested loop must not complete the close while libuv's poll callback
     * still owns the handle (Windows also reads it after our callback). */
    if (s->poll_init && !s->in_cb) {
        if (!uv_is_closing((uv_handle_t *) &s->poll)) {
            s->poll_closing = true;
            uv_close((uv_handle_t *) &s->poll, tjs_sock_poll_close_cb);
        }
        s->poll_init = false;
    }
}

static void tjs_sock_clear_poll_refs(JSRuntime *rt, tjs_sock_t *s) {
    JSValue callback = s->callback;
    s->callback = JS_UNDEFINED;
    JSValue this_obj = s->this_obj;
    s->this_obj = JS_UNDEFINED;
    /* Either release can reenter; leave no shared refs or later accesses to s. */
    JS_FreeValueRT(rt, callback);
    JS_FreeValueRT(rt, this_obj);
}

static void tjs_sock_finalizer(JSRuntime *rt, JSValue val) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (s) {
        /* this_obj is only set while polling and keeps the wrapper alive until
         * stopPoll() or close() releases the native strong reference. */
        s->this_obj = JS_UNDEFINED;
        close_sock(s);
        tjs_sock_clear_poll_refs(rt, s);
        /* A callback finalizer may pump the poll close callback above. */
        s->finalized = true;
        /* Free now only if the poll close_cb will not run later. If a close
         * is in flight and its cb has not fired yet, defer freeing to the cb
         * (which now checks s->finalized). */
        if (!s->in_cb && (!s->poll_closing || s->poll_closed)) {
            tjs_sock_list_remove(s);
            tjs__free(s);
        }
    }
}

static void tjs_sock_gc_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (s) {
        if (!JS_IsUndefined(s->callback))
            JS_MarkValue(rt, s->callback, mark_func);
        /* Do not mark this_obj: it is a C-owned root rather than an edge owned
         * by this JS object. Marking the self-reference would let cycle GC
         * collect a wrapper while its uv_poll_t can still call back. */
    }
}

JSClassDef tjs_sock_class = {
    TJS_SOCK_CLASS_NAME,
    .finalizer = tjs_sock_finalizer,
    .gc_mark   = tjs_sock_gc_mark,
};

/* ── Socket methods ────────────────────────────────────────────────── */

static socklen_t tjs_sock_addrlen(const struct sockaddr_storage *addr) {
    return addr->ss_family == AF_INET6
        ? sizeof(struct sockaddr_in6)
        : sizeof(struct sockaddr_in);
}

static JSValue tjs_sock_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    DECL_SOCK(ctx, this_val, s);
    if (s->closed)  return tjs_throw_errno_msg(ctx, UV_EBADF, "Socket already closed");
    if (s->in_cb)   return tjs_throw_errno_msg(ctx, UV_EBUSY, "Cannot close during poll callback");
    close_sock(s);
    tjs_sock_clear_poll_refs(JS_GetRuntime(ctx), s);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_bind(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected address");
    GET_SOCK(ctx, this_val, s);
    struct sockaddr_storage addr;
    if (tjs_obj2addr(ctx, argv[0], &addr) != 0) return JS_EXCEPTION;
    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_LISTEN, TJS_CAP_FLAG_REPLACEABLE, "socket.bind", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    int ret = bind(operation_sock, (struct sockaddr *) &addr, tjs_sock_addrlen(&addr));
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_connect(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected address");
    GET_SOCK(ctx, this_val, s);
    struct sockaddr_storage addr;
    if (tjs_obj2addr(ctx, argv[0], &addr) != 0) return JS_EXCEPTION;
    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_CONNECT, TJS_CAP_FLAG_REPLACEABLE, "socket.connect", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    int ret = connect(operation_sock, (struct sockaddr *) &addr, tjs_sock_addrlen(&addr));
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_listen(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    unsigned backlog = 511;
    if (argc > 0 && !JS_IsUndefined(argv[0]) && JS_ToUint32(ctx, &backlog, argv[0]))
        return JS_EXCEPTION;
    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_LISTEN, TJS_CAP_FLAG_REPLACEABLE, "socket.listen", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    int ret = listen(operation_sock, backlog);
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_accept(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_LISTEN | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "socket.accept", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    sock_fd_t fd = accept(operation_sock, NULL, NULL);
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, sock_valid(fd));
    return tjs_sock_new_from_fd(ctx, fd, true);
}

static JSValue tjs_sock_shutdown(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected shutdown mode");
    GET_SOCK(ctx, this_val, s);
    unsigned how;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &how, argv[0]), 0, "uint");
    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "socket.shutdown", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    int ret = shutdown(operation_sock, how);
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret == 0);
    return JS_UNDEFINED;
}

/* recv: read bytes (cross-platform via recv(flags=0) or with flags) */
static JSValue tjs_sock_recv(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected byte count");
    GET_SOCK(ctx, this_val, s);
    unsigned count, flags = 0;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &count, argv[0]), 0, "uint");
    if (argc > 1 && !JS_IsUndefined(argv[1]) &&
        JS_ToUint32(ctx, &flags, argv[1]))
        return JS_EXCEPTION;

    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "socket.recv", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    uint8_t *buf = js_malloc(ctx, count);
    if (!buf && count != 0) {
        tjs_sock_unpin(&pin);
        return JS_ThrowOutOfMemory(ctx);
    }
    int ret = recv(operation_sock, (char *) buf, count, (int) flags);
    tjs_sock_unpin(&pin);
    if (ret < 0)  { js_free(ctx, buf); return THROW_STRERROR(); }
    if (ret == 0) { js_free(ctx, buf); return JS_NULL; }
    return TJS_NewUint8Array(ctx, buf, ret);
}

/* send: write bytes (cross-platform via send) */
static JSValue tjs_sock_send(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected data buffer");
    GET_SOCK(ctx, this_val, s);
    /* Convert flags BEFORE capturing the backing store: JS_ToUint32 can run a
     * user valueOf() that detaches argv[0] and frees the memory (see the
     * setsockopt ordering below). */
    unsigned flags = 0;
    if (argc > 1 && !JS_IsUndefined(argv[1]) &&
        JS_ToUint32(ctx, &flags, argv[1]))
        return JS_EXCEPTION;
    REGET_SOCK(ctx, this_val, s);
    size_t sz;
    uint8_t *buf = JS_GetUint8Array(ctx, &sz, argv[0]);
    if (!buf) return JS_EXCEPTION;
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_WRITE, TJS_CAP_FLAG_REPLACEABLE, "socket.send", NULL),
        tjs_sock_unpin(&pin),
        do {
            if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION;
            buf = JS_GetUint8Array(ctx, &sz, argv[0]);
            if (!buf) { tjs_sock_unpin(&pin); return JS_EXCEPTION; }
        } while (0));
    int ret = send(operation_sock, (const char *) buf, sz, (int) flags);
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret >= 0);
    return JS_NewUint32(ctx, ret);
}

static JSValue tjs_sock_setsockopt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 3) return JS_ThrowTypeError(ctx, "expected level, option, and value");
    GET_SOCK(ctx, this_val, s);
    unsigned level, optname;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &level,   argv[0]), 0, "uint");
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &optname, argv[1]), 1, "uint");
    REGET_SOCK(ctx, this_val, s);
    size_t optlen;
    uint8_t *optval = JS_GetUint8Array(ctx, &optlen, argv[2]);
    if (!optval) return JS_EXCEPTION;
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "socket.setopt", NULL),
        tjs_sock_unpin(&pin),
        do {
            if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION;
            optval = JS_GetUint8Array(ctx, &optlen, argv[2]);
            if (!optval) { tjs_sock_unpin(&pin); return JS_EXCEPTION; }
        } while (0));
    int ret = setsockopt(operation_sock, level, optname, (const char *) optval, optlen);
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_getsockopt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "expected level and option");
    GET_SOCK(ctx, this_val, s);
    unsigned level, optname;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &level,   argv[0]), 0, "uint");
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &optname, argv[1]), 1, "uint");

    socklen_t optlen = sizeof(struct sockaddr_storage);
    if (argc > 2 && !JS_IsUndefined(argv[2])) {
        uint32_t optlen32;
        if (JS_ToUint32(ctx, &optlen32, argv[2])) return JS_EXCEPTION;
        optlen = (socklen_t)optlen32;
    }

    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "socket.getopt", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);
    void *optval = js_malloc(ctx, optlen);
    if (!optval && optlen != 0) {
        tjs_sock_unpin(&pin);
        return JS_ThrowOutOfMemory(ctx);
    }
    int ret = getsockopt(operation_sock, level, optname, (char *) optval, &optlen);
    tjs_sock_unpin(&pin);
    if (ret < 0) { js_free(ctx, optval); return THROW_STRERROR(); }
    return TJS_NewUint8Array(ctx, optval, optlen);
}

/* ── POSIX-only: sendmsg / recvmsg ─────────────────────────────────── */
#ifndef _WIN32

static JSValue tjs_sock_recvmsg(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected buffer size");
    GET_SOCK(ctx, this_val, s);
    int32_t bufsz;
    TJS_CHECK_ARG_RET(ctx, JS_IsNumber(argv[0]), 0, "uint");
    if (JS_ToInt32(ctx, &bufsz, argv[0])) return JS_EXCEPTION;
    TJS_CHECK_ARG_RET(ctx, bufsz > 0, 0, "positive integer");

    uint32_t ctrlsz = 0;
    if (argc > 1 && !JS_IsUndefined(argv[1]) && JS_ToUint32(ctx, &ctrlsz, argv[1])) return JS_EXCEPTION;
    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "socket.recvmsg", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock)) return JS_EXCEPTION);

    struct msghdr msg = {0};
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    msg.msg_name    = js_malloc(ctx, msg.msg_namelen);
    if (!msg.msg_name) {
        tjs_sock_unpin(&pin);
        return JS_ThrowOutOfMemory(ctx);
    }

    if (ctrlsz > 0) {
        msg.msg_controllen = ctrlsz;
        msg.msg_control    = js_malloc(ctx, ctrlsz);
        if (!msg.msg_control) {
            js_free(ctx, msg.msg_name);
            tjs_sock_unpin(&pin);
            return JS_ThrowOutOfMemory(ctx);
        }
    }

    struct iovec iov = { .iov_base = js_malloc(ctx, bufsz), .iov_len = bufsz };
    if (!iov.iov_base) {
        js_free(ctx, msg.msg_name);
        js_free(ctx, msg.msg_control);
        tjs_sock_unpin(&pin);
        return JS_ThrowOutOfMemory(ctx);
    }
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    int ret = recvmsg(operation_sock, &msg, 0);
    tjs_sock_unpin(&pin);
    if (ret < 0) {
        /* clean up on error */
        js_free(ctx, msg.msg_name);
        js_free(ctx, msg.msg_control);
        js_free(ctx, iov.iov_base);
        return THROW_STRERROR();
    }

    JSValue result = JS_NewObject(ctx);
    if (JS_IsException(result)) {
        js_free(ctx, msg.msg_name);
        js_free(ctx, msg.msg_control);
        js_free(ctx, iov.iov_base);
        return result;
    }
    if (msg.msg_namelen > 0) {
        JSValue addr = JS_NewObjectProto(ctx, JS_NULL);
        if (JS_IsException(addr)) {
            JS_FreeValue(ctx, result);
            js_free(ctx, msg.msg_name);
            js_free(ctx, msg.msg_control);
            js_free(ctx, iov.iov_base);
            return JS_EXCEPTION;
        }
        tjs_addr2obj(ctx, addr, msg.msg_name, false);
        if (JS_HasException(ctx)) {
            JS_FreeValue(ctx, addr);
            JS_FreeValue(ctx, result);
            js_free(ctx, msg.msg_name);
            js_free(ctx, msg.msg_control);
            js_free(ctx, iov.iov_base);
            return JS_EXCEPTION;
        }
        if (JS_SetPropertyStr(ctx, result, "address", addr) < 0) {
            JS_FreeValue(ctx, result);
            js_free(ctx, msg.msg_name);
            js_free(ctx, msg.msg_control);
            js_free(ctx, iov.iov_base);
            return JS_EXCEPTION;
        }
    }
    js_free(ctx, msg.msg_name);
    msg.msg_name = NULL;
    if (msg.msg_control) {
        JSValue control = TJS_NewUint8Array(ctx, msg.msg_control, msg.msg_controllen);
        msg.msg_control = NULL;
        if (JS_IsException(control)) {
            JS_FreeValue(ctx, result);
            js_free(ctx, iov.iov_base);
            return JS_EXCEPTION;
        }
        if (JS_SetPropertyStr(ctx, result, "control", control) < 0) {
            JS_FreeValue(ctx, result);
            js_free(ctx, iov.iov_base);
            return JS_EXCEPTION;
        }
    }
    JSValue data = TJS_NewUint8Array(ctx, iov.iov_base, ret);
    iov.iov_base = NULL;
    if (JS_IsException(data)) {
        JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    if (JS_SetPropertyStr(ctx, result, "data", data) < 0) {
        JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    return result;
}

static int tjs_sock_sendmsg_buffers(JSContext *ctx, struct msghdr *msg,
                                    JSValue *argv) {
    msg->msg_control = NULL;
    msg->msg_controllen = 0;
    if (!JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        size_t size;
        uint8_t *buffer = JS_GetUint8Array(ctx, &size, argv[1]);
        if (!buffer) return -1;
        msg->msg_control = buffer;
        msg->msg_controllen = size;
    }

    for (size_t i = 0; i < (size_t) msg->msg_iovlen; i++) {
        size_t size;
        uint8_t *buffer = JS_GetUint8Array(ctx, &size, argv[i + 3]);
        if (!buffer) return -1;
        msg->msg_iov[i] = (struct iovec) { buffer, size };
    }
    return 0;
}

static JSValue tjs_sock_sendmsg(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    /* argv: address|null, control|null, flags, ...data_bufs */
    if (argc < 4) return JS_ThrowTypeError(ctx, "expected address, control, flags, and data");
    GET_SOCK(ctx, this_val, s);

    /* Convert every JS value before capturing backing stores. No JS may run
     * between acquiring raw buffer pointers and sendmsg(). */
    unsigned flags;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &flags, argv[2]), 2, "uint");

    struct msghdr msg = {0};
    struct sockaddr_storage addr;

    if (!JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        if (tjs_obj2addr(ctx, argv[0], &addr) != 0) return JS_EXCEPTION;
        msg.msg_name = &addr;
        msg.msg_namelen = tjs_sock_addrlen(&addr);
    }
    REGET_SOCK(ctx, this_val, s);

    msg.msg_iovlen = argc - 3;
    if ((size_t)msg.msg_iovlen > SIZE_MAX / sizeof(struct iovec)) {
        return JS_ThrowRangeError(ctx, "too many data buffers");
    }
    msg.msg_iov = js_malloc(ctx, sizeof(struct iovec) * msg.msg_iovlen);
    if (!msg.msg_iov) return JS_ThrowOutOfMemory(ctx);
    if (tjs_sock_sendmsg_buffers(ctx, &msg, argv) < 0) {
        js_free(ctx, msg.msg_iov);
        return JS_EXCEPTION;
    }
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_WRITE | (msg.msg_name ? TJS_CAP_IO_CONNECT : 0), TJS_CAP_FLAG_REPLACEABLE, "socket.sendmsg", NULL),
        (tjs_sock_unpin(&pin), js_free(ctx, msg.msg_iov)),
        do {
            if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin, &operation_sock) ||
                tjs_sock_sendmsg_buffers(ctx, &msg, argv) < 0) {
                tjs_sock_unpin(&pin);
                js_free(ctx, msg.msg_iov);
                return JS_EXCEPTION;
            }
        } while (0));

    int ret = sendmsg(operation_sock, &msg, flags);
    tjs_sock_unpin(&pin);
    js_free(ctx, msg.msg_iov);
    RET_THROW_ERRNO(ctx, ret >= 0);
    return JS_NewUint32(ctx, ret);
}

#endif /* !_WIN32 */

/* ── Poll ──────────────────────────────────────────────────────────── */

static void tjs_sock_uv_poll_cb(uv_poll_t *handle, int status, int events) {
    tjs_sock_t *s = uv_handle_get_data((uv_handle_t *) handle);
    if (!s || !s->trt || s->trt->freeing) {
        if (s) close_sock(s);
        return;
    }
    if (s->closed || s->in_cb || JS_IsUndefined(s->callback)) return;
    JSContext *ctx = s->jsctx;
    /* poll() can replace its callback; cleanup can drop both shared roots. */
    JSValue callback = JS_DupValue(ctx, s->callback);
    JSValue this_obj = JS_DupValue(ctx, s->this_obj);
    JSValue args[] = { JS_NewInt32(ctx, status), JS_NewInt32(ctx, events) };
    s->in_cb = true;
    JSValue ret = JS_Call(ctx, callback, this_obj, countof(args), args);
    JS_FreeValue(ctx, ret);
    JS_FreeValue(ctx, args[0]);
    JS_FreeValue(ctx, args[1]);
    JS_FreeValue(ctx, callback);
    JS_FreeValue(ctx, this_obj);
    s->in_cb = false;
    if (s->closed) close_sock(s);
}

void tjs__mod_socket_cleanup_runtime(TJSRuntime *trt) {
    while (!list_empty(&trt->sockets)) {
        tjs_sock_t *s = list_entry(trt->sockets.next, tjs_sock_t, runtime_link);
        /* JS roots may own other sockets, whose finalizers can remove any
         * remaining node. Never retain a successor across JS_FreeValueRT. */
        tjs_sock_list_remove(s);
        close_sock(s);
        tjs_sock_clear_poll_refs(trt->rt, s);
    }
}

static JSValue tjs_sock_poll(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "expected events and callback");
    GET_SOCK(ctx, this_val, s);
    unsigned events;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &events, argv[0]) && events > 0, 0, "uint");
    TJS_CHECK_ARG_RET(ctx, JS_IsFunction(ctx, argv[1]), 1, "function");

    REGET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    TJS_CAPABILITY_GUARDED(
        do { if (!s->poll_init) pin = tjs_sock_pin(s->sock); } while (0),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_WATCH | ((events & UV_READABLE) ? TJS_CAP_IO_READ : 0) | ((events & UV_WRITABLE) ? TJS_CAP_IO_WRITE : 0) | ((events & (UV_DISCONNECT | UV_PRIORITIZED)) ? TJS_CAP_IO_CONTROL : 0), TJS_CAP_FLAG_REPLACEABLE, "socket.poll", NULL),
        tjs_sock_unpin(&pin),
        do {
            if (!tjs_sock_reget(ctx, this_val, &s)) {
                tjs_sock_unpin(&pin);
                return JS_EXCEPTION;
            }
            if (s->poll_init) {
                tjs_sock_unpin(&pin);
            } else if (tjs_sock_pin_error(&pin)) {
                int error = tjs_sock_pin_error(&pin);
                tjs_sock_unpin(&pin);
                return tjs_sock_throw_pin_error(ctx, error);
            }
        } while (0));

    if (!s->poll_init) {
        /* uv_poll_t retains the descriptor after this function returns. Keep
         * a duplicate for the handle's whole lifetime, including when no hook
         * is installed yet (one may be installed before a later restart). */
        if (!tjs_sock_pin_owned(&pin)) {
            pin = tjs_sock_pin(s->sock);
            if (tjs_sock_pin_error(&pin)) {
                int error = tjs_sock_pin_error(&pin);
                tjs_sock_unpin(&pin);
                return tjs_sock_throw_pin_error(ctx, error);
            }
        }
        int ret = uv_poll_init_fd(tjs_get_loop(ctx), &s->poll,
                                  tjs_sock_pin_socket(&pin));
        if (ret < 0) {
            tjs_sock_unpin(&pin);
            return tjs_throw_errno(ctx, ret);
        }
        s->poll_pin = pin;
        pin = tjs_sock_pin_init(s->sock);
        uv_handle_set_data((uv_handle_t *) &s->poll, s);
        s->poll_init = true;
    }

    JSValue old_callback = s->callback;
    s->callback = JS_DupValue(ctx, argv[1]);

    int ret = uv_poll_start(&s->poll, events, tjs_sock_uv_poll_cb);
    if (ret < 0) {
        JS_FreeValue(ctx, s->callback);
        /* An active poll keeps its previous registration on a failed restart;
         * put the old callback back so state stays consistent with libuv. */
        s->callback = old_callback;
        return tjs_throw_errno(ctx, ret);
    }
    if (JS_IsUndefined(s->this_obj))
        s->this_obj = JS_DupValue(ctx, this_val);
    JS_FreeValue(ctx, old_callback);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_poll_stop(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    DECL_SOCK(ctx, this_val, s);
    if (s->in_cb)    return tjs_throw_errno_msg(ctx, UV_EBUSY, "Cannot stop poll during callback");
    if (!s->poll_init || uv_is_closing((uv_handle_t *) &s->poll))
        return tjs_throw_errno_msg(ctx, UV_EBADF, "Poll not active");
    int ret = uv_poll_stop(&s->poll);
    if (ret < 0) return tjs_throw_errno(ctx, ret);
    tjs_sock_clear_poll_refs(JS_GetRuntime(ctx), s);
    return JS_UNDEFINED;
}

/* ── Getters ───────────────────────────────────────────────────────── */

static JSValue tjs_sock_get_fd(JSContext *ctx, JSValue this_val) {
    GET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    sock_fd_t fd = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "socket.fileno", NULL),
        tjs_sock_unpin(&pin),
        do {
            if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin,
                                         &operation_sock))
                return JS_EXCEPTION;
            TJSObjectHandleIdentity identity =
                tjs_sock_pin_matches_socket(&pin, s->sock);
            if (identity == TJS_OBJECT_HANDLE_IDENTITY_UNSUPPORTED) {
                tjs_sock_unpin(&pin);
                return TJS_ThrowObjectHandleIdentityUnsupported(ctx);
            }
            if (identity != TJS_OBJECT_HANDLE_IDENTITY_SAME) {
                tjs_sock_unpin(&pin);
                return JS_ThrowTypeError(
                    ctx, "Socket descriptor changed during capability check");
            }
            fd = s->sock;
        } while (0));
    tjs_sock_unpin(&pin);
#ifdef _WIN32
    return JS_NewBigUint64(ctx, (uint64_t) (uintptr_t) fd);
#else
    return JS_NewInt32(ctx, fd);
#endif
}

static JSValue tjs_sock_get_sockpeername(JSContext *ctx, JSValue this_val, int magic) {
    GET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, magic == 0 ? "socket.sockname" : "socket.peername", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin,
                                     &operation_sock))
            return JS_EXCEPTION);
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    int ret = magic == 0
        ? getsockname(operation_sock, (struct sockaddr *) &addr, &len)
        : getpeername(operation_sock, (struct sockaddr *) &addr, &len);
    tjs_sock_unpin(&pin);
    RET_THROW_ERRNO(ctx, ret == 0);

    JSValue result = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(result)) return result;
    tjs_addr2obj(ctx, result, (struct sockaddr *) &addr, false);
    if (JS_HasException(ctx)) {
        JS_FreeValue(ctx, result);
        return JS_EXCEPTION;
    }
    return result;
}

static JSValue tjs_sock_get_polling(JSContext *ctx, JSValue this_val) {
    DECL_SOCK(ctx, this_val, s);
    return JS_NewBool(ctx, s->poll_init && uv_is_active((uv_handle_t *) &s->poll));
}

static JSValue tjs_sock_get_info(JSContext *ctx, JSValue this_val) {
    GET_SOCK(ctx, this_val, s);
    tjs_sock_pin_t pin = tjs_sock_pin_init(s->sock);
    sock_fd_t operation_sock = s->sock;
    TJS_CAPABILITY_GUARDED(
        pin = tjs_sock_pin(s->sock),
        tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "socket.info", NULL),
        tjs_sock_unpin(&pin),
        if (!tjs_sock_revalidate_pin(ctx, this_val, &s, &pin,
                                     &operation_sock))
            return JS_EXCEPTION);

    int type = 0;
    int domain = 0;
    int protocol = 0;
    bool has_type = false;
    bool has_domain = false;
    bool has_protocol = false;

#ifdef __APPLE__
    struct socket_fdinfo sfi;
    if (proc_pidfdinfo(getpid(), operation_sock, PROC_PIDFDSOCKETINFO, &sfi,
                       sizeof sfi) > 0) {
        type = sfi.psi.soi_type;
        domain = sfi.psi.soi_family;
        protocol = sfi.psi.soi_protocol;
        has_type = has_domain = has_protocol = true;
    }
#else
    socklen_t vlen = sizeof(type);
    has_type = getsockopt(operation_sock, SOL_SOCKET, SO_TYPE, (char *) &type,
                          &vlen) == 0;

# ifndef _WIN32
    vlen = sizeof(domain);
    has_domain = getsockopt(operation_sock, SOL_SOCKET, SO_DOMAIN,
                            (char *) &domain, &vlen) == 0;
    vlen = sizeof(protocol);
    has_protocol = getsockopt(operation_sock, SOL_SOCKET, SO_PROTOCOL,
                              (char *) &protocol, &vlen) == 0;
# endif
#endif

    tjs_sock_unpin(&pin);

    JSValue info = JS_NewObject(ctx);
    if (JS_IsException(info)) return info;
    if (has_type)
        JS_SetPropertyStr(ctx, info, "type", JS_NewInt32(ctx, type));
    if (has_domain)
        JS_SetPropertyStr(ctx, info, "domain", JS_NewInt32(ctx, domain));
    if (has_protocol)
        JS_SetPropertyStr(ctx, info, "protocol", JS_NewInt32(ctx, protocol));
    return info;
}

/* ── Utilities ─────────────────────────────────────────────────────── */

static JSValue tjs_sock_if_name_to_index(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected interface name");
    TJS_CHECK_ARG_RET(ctx, JS_IsString(argv[0]), 0, "string");
    const char *name = JS_ToCString(ctx, argv[0]);
    TJS_CHECK_ARG_RET(ctx, name, 0, "string");
    TJS_CAPABILITY(tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "socket.ifNameToIndex", name), JS_FreeCString(ctx, name));
    unsigned idx = if_nametoindex(name);
    JS_FreeCString(ctx, name);
    RET_THROW_ERRNO(ctx, idx > 0);
    return JS_NewUint32(ctx, idx);
}

static JSValue tjs_sock_if_index_to_name(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected interface index");
    unsigned idx;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &idx, argv[0]), 0, "uint");
    TJS_CAPABILITY(tjs__capability_network(ctx, TJS_CAP_NETWORK | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "socket.ifIndexToName", NULL), (void)0);
    char buf[IF_NAMESIZE];
    RET_THROW_ERRNO(ctx, if_indextoname(idx, buf) == buf);
    return JS_NewString(ctx, buf);
}

static uint16_t ip_checksum(const void *data, size_t len) {
    const char *p   = (const char *) data;
    uint64_t    acc = 0xffff;
    unsigned    off = ((uintptr_t) p) & 3;

    if (off) {
        size_t n = (4 - off < len) ? 4 - off : len;
        uint32_t w = 0;
        memcpy(off + (char *) &w, p, n);
        acc += ntohl(w);
        p += n; len -= n;
    }
    for (const char *end = p + (len & ~3); p != end; p += 4) {
        uint32_t w; memcpy(&w, p, 4); acc += ntohl(w);
    }
    if (len & 3) {
        uint32_t w = 0; memcpy(&w, p, len & 3); acc += ntohl(w);
    }
    acc = (acc & 0xffffffff) + (acc >> 32);
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    if (off & 1) acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
    return htons(~acc);
}

static JSValue tjs_sock_checksum(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "expected data buffer");
    ARGV_BUF(ctx, argv, 0, data, len);
    return JS_NewUint32(ctx, ip_checksum(data, len));
}

/* ── Function tables ───────────────────────────────────────────────── */

static const JSCFunctionListEntry tjs_sock_proto_funcs[] = {
    TJS_CFUNC_DEF("bind",     1, tjs_sock_bind),
    TJS_CFUNC_DEF("close",    0, tjs_sock_close),
    TJS_CFUNC_DEF("accept",   0, tjs_sock_accept),
    TJS_CFUNC_DEF("connect",  1, tjs_sock_connect),
    TJS_CFUNC_DEF("listen",   1, tjs_sock_listen),
    TJS_CFUNC_DEF("shutdown", 1, tjs_sock_shutdown),
    TJS_CFUNC_DEF("recv",     2, tjs_sock_recv),
    TJS_CFUNC_DEF("send",     2, tjs_sock_send),
    TJS_CFUNC_DEF("setopt",   3, tjs_sock_setsockopt),
    TJS_CFUNC_DEF("getopt",   3, tjs_sock_getsockopt),
    TJS_CFUNC_DEF("poll",     2, tjs_sock_poll),
    TJS_CFUNC_DEF("stopPoll", 0, tjs_sock_poll_stop),
#ifndef _WIN32
    TJS_CFUNC_DEF("recvmsg",  2, tjs_sock_recvmsg),
    TJS_CFUNC_DEF("sendmsg",  4, tjs_sock_sendmsg),
#endif
    TJS_CGETSET_DEF("polling", tjs_sock_get_polling, NULL),
    TJS_CGETSET_DEF("fileno",  tjs_sock_get_fd,      NULL),
    TJS_CGETSET_DEF("info",    tjs_sock_get_info,    NULL),
    JS_CGETSET_MAGIC_DEF("sockname", tjs_sock_get_sockpeername, NULL, 0),
    JS_CGETSET_MAGIC_DEF("peername", tjs_sock_get_sockpeername, NULL, 1),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", TJS_SOCK_CLASS_NAME, JS_PROP_CONFIGURABLE),
};

#define TJS_SOCK_CONST(x) JS_PROP_INT32_DEF(#x, x, JS_PROP_ENUMERABLE)

/* clang-format off */
static const JSCFunctionListEntry socket_constants[] = {
    TJS_SOCK_CONST(AF_INET),
    TJS_SOCK_CONST(AF_INET6),
#ifdef AF_UNIX
    TJS_SOCK_CONST(AF_UNIX),
#endif
#ifdef AF_NETLINK
    TJS_SOCK_CONST(AF_NETLINK),
#endif
#ifdef AF_PACKET
    TJS_SOCK_CONST(AF_PACKET),
#endif
    TJS_SOCK_CONST(SOCK_STREAM),
    TJS_SOCK_CONST(SOCK_DGRAM),
    TJS_SOCK_CONST(SOCK_RAW),
    TJS_SOCK_CONST(SOCK_SEQPACKET),
#ifdef SOCK_RDM
    TJS_SOCK_CONST(SOCK_RDM),
#endif
    TJS_SOCK_CONST(SOL_SOCKET),
#ifdef SOL_PACKET
    TJS_SOCK_CONST(SOL_PACKET),
#endif
#ifdef SOL_NETLINK
    TJS_SOCK_CONST(SOL_NETLINK),
#endif
    TJS_SOCK_CONST(SO_REUSEADDR),
    TJS_SOCK_CONST(SO_KEEPALIVE),
    TJS_SOCK_CONST(SO_LINGER),
    TJS_SOCK_CONST(SO_BROADCAST),
    TJS_SOCK_CONST(SO_RCVBUF),
    TJS_SOCK_CONST(SO_SNDBUF),
    TJS_SOCK_CONST(SO_ERROR),
    TJS_SOCK_CONST(SO_TYPE),
#ifdef SO_REUSEPORT
    TJS_SOCK_CONST(SO_REUSEPORT),
#endif
#ifdef SO_PRIORITY
    TJS_SOCK_CONST(SO_PRIORITY),
#endif
    TJS_SOCK_CONST(IPPROTO_IP),
    TJS_SOCK_CONST(IPPROTO_IPV6),
    TJS_SOCK_CONST(IPPROTO_ICMP),
    TJS_SOCK_CONST(IPPROTO_TCP),
    TJS_SOCK_CONST(IPPROTO_UDP),
};

/* clang-format on */

static const JSCFunctionListEntry socket_module_funcs[] = {
    TJS_CFUNC_DEF("createFrom",    1, tjs_sock_from_fd),
    TJS_CFUNC_DEF("ifNameToIndex", 1, tjs_sock_if_name_to_index),
    TJS_CFUNC_DEF("ifIndexToName", 1, tjs_sock_if_index_to_name),
    TJS_CFUNC_DEF("checksum",      1, tjs_sock_checksum),

    TJS_UVCONST(READABLE),
    TJS_UVCONST(WRITABLE),
    TJS_UVCONST(DISCONNECT),
    TJS_UVCONST(PRIORITIZED),
};

/* ── Module init ───────────────────────────────────────────────────── */

void tjs__mod_socket_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, &tjs_sock_classid);
    JS_NewClass(rt, tjs_sock_classid, &tjs_sock_class);

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_sock_proto_funcs, countof(tjs_sock_proto_funcs));
    JS_SetClassProto(ctx, tjs_sock_classid, proto);

    JS_SetPropertyFunctionList(ctx, ns, socket_module_funcs, countof(socket_module_funcs));
    JS_SetPropertyFunctionList(ctx, ns, socket_constants, countof(socket_constants));
    JSValue constructor = JS_NewCFunction2(
        ctx, tjs_sock_create, TJS_SOCK_CLASS_NAME, 2, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, constructor, proto);
    JS_DefinePropertyValueStr(ctx, ns, TJS_SOCK_CLASS_NAME, constructor, JS_PROP_C_W_E);
}
