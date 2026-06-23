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
# define THROW_STRERROR()    JS_ThrowInternalError(ctx, "WSA error %d", WSAGetLastError())
# define uv_poll_init_fd     uv_poll_init_socket
#else
# include <net/if.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
  typedef int sock_fd_t;
# define SOCK_INVALID        (-1)
# define sock_close(fd)      close(fd)
# define sock_valid(fd)      ((fd) >= 0)
# define THROW_STRERROR()    JS_ThrowInternalError(ctx, "%s (%d)", strerror(errno), errno)
# define uv_poll_init_fd     uv_poll_init
#endif

#ifdef __APPLE__
# include <libproc.h>
# include <sys/proc_info.h>
#endif

/* ── Types ─────────────────────────────────────────────────────────── */
#define TJS_SOCK_CLASS_NAME "PosixSocket"
static thread_local JSClassID tjs_sock_classid;

typedef struct {
    sock_fd_t  sock;
    bool       closed, poll_init, in_cb, finalized;
    JSValue    callback, this_obj;
    JSContext *jsctx;
    uv_poll_t  poll;
} tjs_sock_t;

/* ── Macros ────────────────────────────────────────────────────────── */

/* Declare `s`, validate opaque only (no closed check) */
#define DECL_SOCK(ctx, this_val, s)                                          \
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);               \
    if (!s) return JS_ThrowTypeError(ctx, "expected " TJS_SOCK_CLASS_NAME)

/* Declare `s`, validate opaque + closed */
#define GET_SOCK(ctx, this_val, s)                                           \
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);               \
    if (!s) return JS_ThrowTypeError(ctx, "expected " TJS_SOCK_CLASS_NAME);  \
    if (s->closed) return JS_ThrowInternalError(ctx, "Socket closed")

#define RET_THROW_ERRNO(ctx, cond)  if (!(cond)) return THROW_STRERROR()

/* Get Uint8Array from argv[n] into ptr/sz, return JS_EXCEPTION on failure */
#define ARGV_BUF(ctx, argv, n, ptr, sz) \
    size_t sz;                           \
    uint8_t *ptr = JS_GetUint8Array(ctx, &(sz), (argv)[n]); \
    if (!(ptr)) return JS_EXCEPTION

/* ── Lifecycle ─────────────────────────────────────────────────────── */

static JSValue tjs_sock_new_from_fd(JSContext *ctx, sock_fd_t fd) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_sock_classid);
    if (JS_IsException(obj))
        return obj;

    tjs_sock_t *s = js_mallocz(ctx, sizeof(*s));
    if (!s) {
        JS_FreeValue(ctx, obj);
        sock_close(fd);
        return JS_ThrowOutOfMemory(ctx);
    }
    s->sock      = fd;
    s->callback  = JS_UNDEFINED;
    s->this_obj  = JS_DupValue(ctx, obj);
    s->jsctx     = ctx;
    JS_SetOpaque(obj, s);
    return obj;
}

static void tjs_sock_poll_close_cb(uv_handle_t *handle) {
    tjs_sock_t *s = uv_handle_get_data(handle);
    if (!s) return;
    // Only free the structure; JSValues freed in finalizer when rt is alive
    tjs__free(s);
}

static JSValue tjs_sock_create(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    unsigned domain, type, protocol;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &domain,   argv[0]), 0, "uint");
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &type,     argv[1]), 1, "uint");
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &protocol, argv[2]), 2, "uint");

    sock_fd_t fd = socket(domain, type, protocol);
    RET_THROW_ERRNO(ctx, sock_valid(fd));
    return tjs_sock_new_from_fd(ctx, fd);
}

static JSValue tjs_sock_create_from_fd(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    unsigned ufd;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &ufd, argv[0]), 0, "uint");
    sock_fd_t fd = (sock_fd_t) ufd;

    /* validate fd by probing socket type */
    int dummy; socklen_t dlen = sizeof(dummy);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, (char *) &dummy, &dlen) < 0)
        return JS_ThrowTypeError(ctx, "%u is not a valid socket fd", ufd);

    return tjs_sock_new_from_fd(ctx, fd);
}

static void close_sock(tjs_sock_t *s) {
    if (s->closed) return;
    if (s->poll_init) {
        if (uv_is_active((uv_handle_t *) &s->poll))
            uv_poll_stop(&s->poll);
        if (!uv_is_closing((uv_handle_t *) &s->poll))
            uv_close((uv_handle_t *) &s->poll, tjs_sock_poll_close_cb);
        if (!JS_IsUndefined(s->callback)) {
            JS_FreeValue(s->jsctx, s->callback);
            s->callback  = JS_UNDEFINED;
        }
        s->poll_init = false;
    }
    sock_close(s->sock);
    s->closed = true;
}

static void tjs_sock_finalizer(JSRuntime *rt, JSValue val) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (s) {
        s->finalized = true;
        JS_FreeValueRT(rt, s->callback);
        s->callback = JS_UNDEFINED;
        JS_FreeValueRT(rt, s->this_obj);
        s->this_obj = JS_UNDEFINED;
        close_sock(s);
        // Only free if close_cb won't (i.e., handle not pending close)
        if (!uv_is_closing((uv_handle_t *) &s->poll)) {
            js_free_rt(rt, s);
        }
        // If handle is closing, close_cb will free s
    }
}

static void tjs_sock_gc_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (s) {
        if (!JS_IsUndefined(s->callback))
            JS_MarkValue(rt, s->callback, mark_func);
        JS_MarkValue(rt, s->this_obj, mark_func);
    }
}

JSClassDef tjs_sock_class = {
    TJS_SOCK_CLASS_NAME,
    .finalizer = tjs_sock_finalizer,
    .gc_mark   = tjs_sock_gc_mark,
};

/* ── Socket methods ────────────────────────────────────────────────── */

static JSValue tjs_sock_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    DECL_SOCK(ctx, this_val, s);
    if (s->closed)  return JS_ThrowInternalError(ctx, "Socket already closed");
    if (s->in_cb)   return JS_ThrowInternalError(ctx, "Cannot close during poll callback");
    close_sock(s);
    if (!JS_IsUndefined(s->this_obj)) {
        JSValue obj = s->this_obj;
        s->this_obj = JS_UNDEFINED;
        JS_FreeValue(ctx, obj);
    }
    return JS_UNDEFINED;
}

static JSValue tjs_sock_bind(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    ARGV_BUF(ctx, argv, 0, buf, sz);
    RET_THROW_ERRNO(ctx, bind(s->sock, (struct sockaddr *) buf, sz) == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_connect(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    ARGV_BUF(ctx, argv, 0, buf, sz);
    RET_THROW_ERRNO(ctx, connect(s->sock, (struct sockaddr *) buf, sz) == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_listen(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    unsigned backlog;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &backlog, argv[0]), 0, "uint");
    RET_THROW_ERRNO(ctx, listen(s->sock, backlog) == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_accept(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    socklen_t sz = sizeof(struct sockaddr_storage);
    struct sockaddr *addr = js_malloc(ctx, sz);
    if (!addr)
        return JS_ThrowOutOfMemory(ctx);
    sock_fd_t fd = accept(s->sock, addr, &sz);
    if (!sock_valid(fd)) {
        js_free(ctx, addr);
        return THROW_STRERROR();
    }
    JSValue newSock = tjs_sock_new_from_fd(ctx, fd);
    if (JS_IsException(newSock)) {
        js_free(ctx, addr);
        return newSock;
    }
    JS_SetPropertyStr(ctx, newSock, "_sockaddr", TJS_NewUint8Array(ctx, (uint8_t *) addr, sz));
    return newSock;
}

static JSValue tjs_sock_shutdown(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    unsigned how;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &how, argv[0]), 0, "uint");
    RET_THROW_ERRNO(ctx, shutdown(s->sock, how) == 0);
    return JS_UNDEFINED;
}

/* recv: read bytes (cross-platform via recv(flags=0) or with flags) */
static JSValue tjs_sock_recv(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    unsigned count, flags = 0;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &count, argv[0]), 0, "uint");
    if (argc > 1 && !JS_IsUndefined(argv[1]))
        JS_ToUint32(ctx, &flags, argv[1]);

    uint8_t *buf = js_malloc(ctx, count);
    if (!buf && count != 0)
        return JS_ThrowOutOfMemory(ctx);
    int ret = recv(s->sock, (char *) buf, count, (int) flags);
    if (ret < 0)  { js_free(ctx, buf); return THROW_STRERROR(); }
    if (ret == 0) { js_free(ctx, buf); return JS_NULL; }
    return TJS_NewUint8Array(ctx, buf, ret);
}

/* send: write bytes (cross-platform via send) */
static JSValue tjs_sock_send(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    ARGV_BUF(ctx, argv, 0, buf, sz);
    unsigned flags = 0;
    if (argc > 1 && !JS_IsUndefined(argv[1]))
        JS_ToUint32(ctx, &flags, argv[1]);
    int ret = send(s->sock, (const char *) buf, sz, (int) flags);
    RET_THROW_ERRNO(ctx, ret >= 0);
    return JS_NewUint32(ctx, ret);
}

static JSValue tjs_sock_setsockopt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    unsigned level, optname;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &level,   argv[0]), 0, "uint");
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &optname, argv[1]), 1, "uint");
    ARGV_BUF(ctx, argv, 2, optval, optlen);
    RET_THROW_ERRNO(ctx, setsockopt(s->sock, level, optname, (const char *) optval, optlen) == 0);
    return JS_UNDEFINED;
}

static JSValue tjs_sock_getsockopt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
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

    void *optval = js_malloc(ctx, optlen);
    if (!optval && optlen != 0)
        return JS_ThrowOutOfMemory(ctx);
    int ret = getsockopt(s->sock, level, optname, (char *) optval, &optlen);
    if (ret < 0) { js_free(ctx, optval); return THROW_STRERROR(); }
    return TJS_NewUint8Array(ctx, optval, optlen);
}

/* ── POSIX-only: sendmsg / recvmsg ─────────────────────────────────── */
#ifndef _WIN32

static JSValue tjs_sock_recvmsg(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    GET_SOCK(ctx, this_val, s);
    int32_t bufsz;
    TJS_CHECK_ARG_RET(ctx, JS_IsNumber(argv[0]), 0, "uint");
    JS_ToInt32(ctx, &bufsz, argv[0]);
    TJS_CHECK_ARG_RET(ctx, bufsz > 0, 0, "positive integer");

    struct msghdr msg = {0};
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    msg.msg_name    = js_malloc(ctx, msg.msg_namelen);
    if (!msg.msg_name)
        return JS_ThrowOutOfMemory(ctx);

    if (argc > 1 && !JS_IsUndefined(argv[1])) {
        uint32_t ctrlsz;
        JS_ToUint32(ctx, &ctrlsz, argv[1]);
        if (ctrlsz > 0) {
            msg.msg_controllen = ctrlsz;
            msg.msg_control    = js_malloc(ctx, ctrlsz);
            if (!msg.msg_control) {
                js_free(ctx, msg.msg_name);
                return JS_ThrowOutOfMemory(ctx);
            }
        }
    }

    struct iovec iov = { .iov_base = js_malloc(ctx, bufsz), .iov_len = bufsz };
    if (!iov.iov_base) {
        js_free(ctx, msg.msg_name);
        js_free(ctx, msg.msg_control);
        return JS_ThrowOutOfMemory(ctx);
    }
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    int ret = recvmsg(s->sock, &msg, 0);
    if (ret < 0) {
        /* clean up on error */
        js_free(ctx, msg.msg_name);
        js_free(ctx, msg.msg_control);
        js_free(ctx, iov.iov_base);
        return THROW_STRERROR();
    }

    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "addr",
        TJS_NewUint8Array(ctx, (uint8_t *) msg.msg_name, msg.msg_namelen));
    if (msg.msg_control)
        JS_SetPropertyStr(ctx, result, "control",
            TJS_NewUint8Array(ctx, msg.msg_control, msg.msg_controllen));
    JS_SetPropertyStr(ctx, result, "data",
        TJS_NewUint8Array(ctx, iov.iov_base, ret));
    return result;
}

static JSValue tjs_sock_sendmsg(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    /* argv: addr|undefined, control|undefined, flags, ...data_bufs */
    GET_SOCK(ctx, this_val, s);
    if (argc < 4) return JS_ThrowInternalError(ctx, "expected at least 4 arguments");

    struct msghdr msg = {0};

    if (!JS_IsUndefined(argv[0])) {
        ARGV_BUF(ctx, argv, 0, abuf, asz);
        msg.msg_name    = abuf;
        msg.msg_namelen = asz;
    }
    if (!JS_IsUndefined(argv[1])) {
        ARGV_BUF(ctx, argv, 1, cbuf, csz);
        msg.msg_control    = cbuf;
        msg.msg_controllen = csz;
    }
    unsigned flags;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &flags, argv[2]), 2, "uint");

    msg.msg_iovlen = argc - 3;
    msg.msg_iov    = js_malloc(ctx, sizeof(struct iovec) * msg.msg_iovlen);
    for (size_t i = 0; i < (size_t) msg.msg_iovlen; i++) {
        size_t sz;
        uint8_t *buf = JS_GetUint8Array(ctx, &sz, argv[i + 3]);
        if (!buf) { js_free(ctx, msg.msg_iov); return JS_EXCEPTION; }
        msg.msg_iov[i] = (struct iovec){ buf, sz };
    }

    int ret = sendmsg(s->sock, &msg, flags);
    js_free(ctx, msg.msg_iov);
    RET_THROW_ERRNO(ctx, ret >= 0);
    return JS_NewUint32(ctx, ret);
}

#endif /* !_WIN32 */

/* ── Poll ──────────────────────────────────────────────────────────── */

static void tjs_sock_uv_poll_cb(uv_poll_t *handle, int status, int events) {
    tjs_sock_t *s = uv_handle_get_data((uv_handle_t *) handle);
    JSValue args[] = { JS_NewInt32(s->jsctx, status), JS_NewInt32(s->jsctx, events) };
    s->in_cb = true;
    JSValue ret = JS_Call(s->jsctx, s->callback, s->this_obj, countof(args), args);
    s->in_cb = false;
    JS_FreeValue(s->jsctx, ret);
}

static JSValue tjs_sock_poll(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    DECL_SOCK(ctx, this_val, s);  /* allow polling on closed? no – keep closed check */
    if (s->closed) return JS_ThrowInternalError(ctx, "Socket closed");
    unsigned events;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &events, argv[0]) && events > 0, 0, "uint");
    TJS_CHECK_ARG_RET(ctx, JS_IsFunction(ctx, argv[1]), 1, "function");

    if (!s->poll_init) {
        int ret = uv_poll_init_fd(tjs_get_loop(ctx), &s->poll, s->sock);
        if (ret < 0) return tjs_throw_errno(ctx, ret);
        uv_handle_set_data((uv_handle_t *) &s->poll, s);
        s->poll_init = true;
    }

    if (!JS_IsUndefined(s->callback))
        JS_FreeValue(ctx, s->callback);
    s->callback = JS_DupValue(ctx, argv[1]);

    int ret = uv_poll_start(&s->poll, events, tjs_sock_uv_poll_cb);
    if (ret < 0) {
        JS_FreeValue(ctx, s->callback);
        s->callback = JS_UNDEFINED;
        return tjs_throw_errno(ctx, ret);
    }
    return JS_UNDEFINED;
}

static JSValue tjs_sock_poll_stop(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    DECL_SOCK(ctx, this_val, s);
    if (s->in_cb)    return JS_ThrowInternalError(ctx, "Cannot stop poll during callback");
    if (!s->poll_init || uv_is_closing((uv_handle_t *) &s->poll))
        return JS_ThrowInternalError(ctx, "Poll not active");
    int ret = uv_poll_stop(&s->poll);
    if (ret < 0) return tjs_throw_errno(ctx, ret);
    return JS_UNDEFINED;
}

/* ── Getters ───────────────────────────────────────────────────────── */

static JSValue tjs_sock_get_fd(JSContext *ctx, JSValue this_val) {
    DECL_SOCK(ctx, this_val, s);
    return JS_NewUint32(ctx, (uint32_t) s->sock);
}

static JSValue tjs_sock_get_polling(JSContext *ctx, JSValue this_val) {
    DECL_SOCK(ctx, this_val, s);
    return JS_NewBool(ctx, s->poll_init && uv_is_active((uv_handle_t *) &s->poll));
}

static JSValue tjs_sock_get_info(JSContext *ctx, JSValue this_val) {
    DECL_SOCK(ctx, this_val, s);
    JSValue info = JS_NewObject(ctx);
    JSValue sock_info = JS_NewObject(ctx);
    int cnt = 0;

#ifdef __APPLE__
    struct socket_fdinfo sfi;
    if (proc_pidfdinfo(getpid(), s->sock, PROC_PIDFDSOCKETINFO, &sfi, sizeof sfi) > 0) {
        JS_SetPropertyStr(ctx, sock_info, "type",     JS_NewInt32(ctx, sfi.psi.soi_type));
        JS_SetPropertyStr(ctx, sock_info, "domain",   JS_NewInt32(ctx, sfi.psi.soi_family));
        JS_SetPropertyStr(ctx, sock_info, "protocol", JS_NewInt32(ctx, sfi.psi.soi_protocol));
        cnt = 3;
    }
#else
    int val; socklen_t vlen = sizeof(val);
# define TRY_SOCKOPT(name, key) \
    if (getsockopt(s->sock, SOL_SOCKET, name, (char*)&val, &vlen) == 0) { \
        JS_SetPropertyStr(ctx, sock_info, key, JS_NewInt32(ctx, val)); cnt++; }

    TRY_SOCKOPT(SO_TYPE, "type")
# ifndef _WIN32
    TRY_SOCKOPT(SO_DOMAIN,   "domain")
    TRY_SOCKOPT(SO_PROTOCOL, "protocol")
# endif
# undef TRY_SOCKOPT
#endif

    if (cnt > 0)
        JS_SetPropertyStr(ctx, info, "socket", sock_info);
    else
        JS_FreeValue(ctx, sock_info);
    return info;
}

/* ── Utilities ─────────────────────────────────────────────────────── */

static JSValue tjs_uv_strerror(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    int code;
    TJS_CHECK_ARG_RET(ctx, !JS_ToInt32(ctx, &code, argv[0]), 0, "int");
    return JS_NewString(ctx, uv_strerror(code));
}

static JSValue tjs_sock_sockaddr_inet(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    struct sockaddr_storage *ss = js_malloc(ctx, sizeof(*ss));
    if (!ss)
        return JS_ThrowOutOfMemory(ctx);
    if (tjs_obj2addr(ctx, argv[0], ss) != 0) {
        js_free(ctx, ss);
        return JS_EXCEPTION;
    }

    size_t addr_len;
    if (ss->ss_family == AF_INET6)
        addr_len = sizeof(struct sockaddr_in6);
    else if (ss->ss_family == AF_INET)
        addr_len = sizeof(struct sockaddr_in);
#if defined(AF_UNIX) && !defined(_WIN32)
    else if (ss->ss_family == AF_UNIX)
        addr_len = sizeof(struct sockaddr_un);
#endif
    else
        addr_len = sizeof(struct sockaddr_storage);

    struct sockaddr *addr = js_realloc(ctx, ss, addr_len);
    if (!addr) {
        js_free(ctx, ss);
        return JS_ThrowOutOfMemory(ctx);
    }
    return TJS_NewUint8Array(ctx, (uint8_t *) addr, addr_len);
}

static JSValue tjs_posix_if_nametoindex(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJS_CHECK_ARG_RET(ctx, JS_IsString(argv[0]), 0, "string");
    const char *name = JS_ToCString(ctx, argv[0]);
    TJS_CHECK_ARG_RET(ctx, name, 0, "string");
    unsigned idx = if_nametoindex(name);
    JS_FreeCString(ctx, name);
    RET_THROW_ERRNO(ctx, idx > 0);
    return JS_NewUint32(ctx, idx);
}

static JSValue tjs_posix_if_indextoname(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    unsigned idx;
    TJS_CHECK_ARG_RET(ctx, !JS_ToUint32(ctx, &idx, argv[0]), 0, "uint");
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

static JSValue tjs_posix_checksum(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
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
    TJS_CFUNC_DEF("pollStop", 0, tjs_sock_poll_stop),
#ifndef _WIN32
    TJS_CFUNC_DEF("recvmsg",  2, tjs_sock_recvmsg),
    TJS_CFUNC_DEF("sendmsg",  4, tjs_sock_sendmsg),
#endif
    TJS_CGETSET_DEF("polling", tjs_sock_get_polling, NULL),
    TJS_CGETSET_DEF("fileno",  tjs_sock_get_fd,      NULL),
    TJS_CGETSET_DEF("info",    tjs_sock_get_info,    NULL),
};

#define JS_PROT_INT_DEF(x)  JS_PROP_INT32_DEF(#x, x, JS_PROP_ENUMERABLE)

/* clang-format off */
static const JSCFunctionListEntry defines_list[] = {
    JS_PROT_INT_DEF(AF_INET),
    JS_PROT_INT_DEF(AF_INET6),
#ifdef AF_UNIX
    JS_PROT_INT_DEF(AF_UNIX),
#endif
#ifdef AF_NETLINK
    JS_PROT_INT_DEF(AF_NETLINK),
#endif
#ifdef AF_PACKET
    JS_PROT_INT_DEF(AF_PACKET),
#endif
    JS_PROT_INT_DEF(SOCK_STREAM),
    JS_PROT_INT_DEF(SOCK_DGRAM),
    JS_PROT_INT_DEF(SOCK_RAW),
    JS_PROT_INT_DEF(SOCK_SEQPACKET),
#ifdef SOCK_RDM
    JS_PROT_INT_DEF(SOCK_RDM),
#endif
    JS_PROT_INT_DEF(SOL_SOCKET),
#ifdef SOL_PACKET
    JS_PROT_INT_DEF(SOL_PACKET),
#endif
#ifdef SOL_NETLINK
    JS_PROT_INT_DEF(SOL_NETLINK),
#endif
    JS_PROT_INT_DEF(SO_REUSEADDR),
    JS_PROT_INT_DEF(SO_KEEPALIVE),
    JS_PROT_INT_DEF(SO_LINGER),
    JS_PROT_INT_DEF(SO_BROADCAST),
    JS_PROT_INT_DEF(SO_RCVBUF),
    JS_PROT_INT_DEF(SO_SNDBUF),
    JS_PROT_INT_DEF(SO_ERROR),
    JS_PROT_INT_DEF(SO_TYPE),
#ifdef SO_REUSEPORT
    JS_PROT_INT_DEF(SO_REUSEPORT),
#endif
#ifdef SO_PRIORITY
    JS_PROT_INT_DEF(SO_PRIORITY),
#endif
    JS_PROT_INT_DEF(IPPROTO_IP),
    JS_PROT_INT_DEF(IPPROTO_IPV6),
    JS_PROT_INT_DEF(IPPROTO_ICMP),
    JS_PROT_INT_DEF(IPPROTO_TCP),
    JS_PROT_INT_DEF(IPPROTO_UDP),
};

static const JSCFunctionListEntry tjs_uv_poll_events[] = {
    TJS_UVCONST(READABLE),
    TJS_UVCONST(WRITABLE),
    TJS_UVCONST(DISCONNECT),
    TJS_UVCONST(PRIORITIZED),
};
/* clang-format on */

static const JSCFunctionListEntry posix_ns_funcs[] = {
    TJS_CFUNC_DEF("create_sockaddr_inet", 1, tjs_sock_sockaddr_inet),
    TJS_CFUNC_DEF("uv_strerror",          1, tjs_uv_strerror),
    TJS_CFUNC_DEF("socket_from_fd",       1, tjs_sock_create_from_fd),
    TJS_CFUNC_DEF("if_nametoindex",       1, tjs_posix_if_nametoindex),
    TJS_CFUNC_DEF("if_indextoname",       1, tjs_posix_if_indextoname),
    TJS_CFUNC_DEF("checksum",             1, tjs_posix_checksum),
    TJS_CONST2("sizeof_struct_sockaddr",  sizeof(struct sockaddr)),
    JS_OBJECT_DEF("defines",             defines_list,        countof(defines_list),        JS_PROP_C_W_E),
    JS_OBJECT_DEF("uv_poll_event_bits",  tjs_uv_poll_events,  countof(tjs_uv_poll_events),  JS_PROP_C_W_E),
};

/* ── Module init ───────────────────────────────────────────────────── */

void tjs__mod_socket_init(JSContext *ctx, JSValue ns) {JSRuntime *rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, &tjs_sock_classid);
    JS_NewClass(rt, tjs_sock_classid, &tjs_sock_class);

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_sock_proto_funcs, countof(tjs_sock_proto_funcs));
    JS_SetClassProto(ctx, tjs_sock_classid, proto);

    JS_SetPropertyFunctionList(ctx, ns, posix_ns_funcs, countof(posix_ns_funcs));
    JS_DefinePropertyValueStr(ctx, ns, TJS_SOCK_CLASS_NAME,
        JS_NewCFunction2(ctx, tjs_sock_create, TJS_SOCK_CLASS_NAME, 3, JS_CFUNC_constructor, 0),
        JS_PROP_C_W_E);
}
