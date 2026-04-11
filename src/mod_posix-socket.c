/*
 * POSIX Socket Module - Refactored
 * Low-level POSIX socket interface for txiki.js
 */

#include "private.h"

#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#endif

#define TJS_SOCK_CLASS_NAME "PosixSocket"

static JSClassID tjs_sock_classid;

typedef struct {
    int sock;
    bool closed;
    bool poll_init;
    JSValue callback;
    JSValue this_val;
    JSContext *ctx;
    bool in_cb;
    uv_poll_t poll;
} tjs_sock_t;

/* Error handling helper - always use errno consistently */
static JSValue throw_socket_error(JSContext *ctx) {
    return JS_ThrowInternalError(ctx, "%s (errno=%d)", strerror(errno), errno);
}

/* Check socket is valid and not closed */
static tjs_sock_t* get_socket(JSContext *ctx, JSValue val) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (!s) {
        JS_ThrowTypeError(ctx, "Not a PosixSocket");
        return NULL;
    }
    if (s->closed) {
        JS_ThrowInternalError(ctx, "Socket closed");
        return NULL;
    }
    return s;
}

static void close_sock(tjs_sock_t *s);

/* Create socket object from fd */
static JSValue tjs_sock_new_from_fd(JSContext *ctx, int fd) {
    JSValue obj = JS_NewObjectClass(ctx, tjs_sock_classid);
    if (JS_IsException(obj)) {
        return obj;
    }

    tjs_sock_t *tjs_sock = js_mallocz(ctx, sizeof(tjs_sock_t));
    if (!tjs_sock) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    tjs_sock->sock = fd;
    tjs_sock->this_val = JS_DupValue(ctx, obj);
    tjs_sock->ctx = ctx;
    tjs_sock->callback = JS_UNDEFINED;
    JS_SetOpaque(obj, tjs_sock);

    return obj;
}

/* socket(domain, type, protocol) */
static JSValue tjs_sock_create(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "socket(domain, type, protocol) requires 3 arguments");
    }
    
    uint32_t domain, type, protocol;
    if (JS_ToUint32(ctx, &domain, argv[0]) || 
        JS_ToUint32(ctx, &type, argv[1]) || 
        JS_ToUint32(ctx, &protocol, argv[2])) {
        return JS_EXCEPTION;
    }

    int sock = socket(domain, type, protocol);
    if (sock < 0) {
        return throw_socket_error(ctx);
    }

    return tjs_sock_new_from_fd(ctx, sock);
}

/* fromFd(fd) - create from existing fd */
static JSValue tjs_sock_from_fd(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "fromFd(fd) requires 1 argument");
    }
    
    uint32_t fd;
    if (JS_ToUint32(ctx, &fd, argv[0])) {
        return JS_EXCEPTION;
    }

    int ret = fcntl(fd, F_GETFD);
    if (ret < 0) {
        return JS_ThrowTypeError(ctx, "%d is not a valid file descriptor: %s", fd, strerror(errno));
    }

    return tjs_sock_new_from_fd(ctx, fd);
}

/* bind(sockaddr) */
static JSValue tjs_sock_bind(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "bind(sockaddr) requires Uint8Array");
    }

    size_t sz;
    struct sockaddr *sockaddr = (struct sockaddr *) JS_GetUint8Array(ctx, &sz, argv[0]);
    if (!sockaddr) {
        return JS_ThrowTypeError(ctx, "sockaddr must be Uint8Array");
    }

    if (bind(s->sock, sockaddr, sz) < 0) {
        return throw_socket_error(ctx);
    }

    return JS_UNDEFINED;
}

/* connect(sockaddr) */
static JSValue tjs_sock_connect(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "connect(sockaddr) requires Uint8Array");
    }

    size_t sz;
    struct sockaddr *sockaddr = (struct sockaddr *) JS_GetUint8Array(ctx, &sz, argv[0]);
    if (!sockaddr) {
        return JS_ThrowTypeError(ctx, "sockaddr must be Uint8Array");
    }

    if (connect(s->sock, sockaddr, sz) < 0) {
        return throw_socket_error(ctx);
    }

    return JS_UNDEFINED;
}

/* listen(backlog) */
static JSValue tjs_sock_listen(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    uint32_t backlog = 128;  // default
    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        if (JS_ToUint32(ctx, &backlog, argv[0])) {
            return JS_EXCEPTION;
        }
    }

    if (listen(s->sock, backlog) < 0) {
        return throw_socket_error(ctx);
    }
    return JS_UNDEFINED;
}

/* accept() -> new socket */
static JSValue tjs_sock_accept(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    
    int fd = accept(s->sock, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) {
        return throw_socket_error(ctx);
    }

    JSValue newSock = tjs_sock_new_from_fd(ctx, fd);
    if (JS_IsException(newSock)) {
        close(fd);
        return newSock;
    }

    /* Attach remote address */
    JSValue addr_arr = JS_NewUint8ArrayCopy(ctx, (uint8_t *)&addr, addrlen);
    JS_SetPropertyStr(ctx, newSock, "_remoteAddr", addr_arr);
    
    return newSock;
}

/* read(buffer) - read into provided buffer */
static JSValue tjs_sock_read(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    size_t count;
    uint8_t *buf;
    
    /* If buffer provided, use it; else allocate new one */
    if (argc > 0 && JS_IsObject(argv[0])) {
        buf = JS_GetUint8Array(ctx, &count, argv[0]);
        if (!buf) {
            return JS_ThrowTypeError(ctx, "buffer must be Uint8Array");
        }
    } else {
        count = 65536;  // default 64K
        buf = js_malloc(ctx, count);
        if (!buf) return JS_EXCEPTION;
    }

    ssize_t ret;
    do {
        ret = read(s->sock, buf, count);
    } while (ret < 0 && errno == EINTR);
    
    if (ret < 0) {
        if (argc == 0 || !JS_IsObject(argv[0])) {
            js_free(ctx, buf);
        }
        return throw_socket_error(ctx);
    }
    
    if (ret == 0) {
        /* EOF */
        if (argc == 0 || !JS_IsObject(argv[0])) {
            js_free(ctx, buf);
        }
        return JS_NULL;
    }

    if (argc > 0 && JS_IsObject(argv[0])) {
        /* Return bytes read */
        return JS_NewInt64(ctx, ret);
    }
    /* Return new Uint8Array with actual data */
    /* Return new Uint8Array that owns the buffer */
    return TJS_NewUint8Array(ctx, buf, ret);
}

/* write(buffer) - write all data (handles short writes) */
static JSValue tjs_sock_write(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "write(buffer) requires Uint8Array");
    }

    size_t sz;
    uint8_t *buf = JS_GetUint8Array(ctx, &sz, argv[0]);
    if (!buf) {
        return JS_ThrowTypeError(ctx, "buffer must be Uint8Array");
    }

    size_t total = 0;
    while (total < sz) {
        ssize_t ret;
        do {
            ret = write(s->sock, buf + total, sz - total);
        } while (ret < 0 && errno == EINTR);
        
        if (ret < 0) {
            return throw_socket_error(ctx);
        }
        total += ret;
    }
    
    return JS_NewUint32(ctx, total);
}

/* recv(buffer, flags) - receive into buffer */
static JSValue tjs_sock_recv(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "recv(buffer, flags) requires Uint8Array");
    }

    size_t count;
    uint8_t *buf = JS_GetUint8Array(ctx, &count, argv[0]);
    if (!buf) {
        return JS_ThrowTypeError(ctx, "buffer must be Uint8Array");
    }

    int flags = 0;
    if (argc > 1 && JS_IsNumber(argv[1])) {
        int32_t f;
        if (JS_ToInt32(ctx, &f, argv[1])) return JS_EXCEPTION;
        flags = f;
    }

    ssize_t ret;
    do {
        ret = recv(s->sock, buf, count, flags);
    } while (ret < 0 && errno == EINTR);
    
    if (ret < 0) {
        return throw_socket_error(ctx);
    }
    if (ret == 0) {
        return JS_NULL;  /* EOF */
    }
    
    return JS_NewInt64(ctx, ret);
}

/* send(buffer, flags) */
static JSValue tjs_sock_send(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "send(buffer, flags) requires Uint8Array");
    }

    size_t sz;
    uint8_t *buf = JS_GetUint8Array(ctx, &sz, argv[0]);
    if (!buf) {
        return JS_ThrowTypeError(ctx, "buffer must be Uint8Array");
    }

    int flags = 0;
    if (argc > 1 && JS_IsNumber(argv[1])) {
        int32_t f;
        if (JS_ToInt32(ctx, &f, argv[1])) return JS_EXCEPTION;
        flags = f;
    }

    ssize_t ret;
    do {
        ret = send(s->sock, buf, sz, flags);
    } while (ret < 0 && errno == EINTR);
    
    if (ret < 0) {
        return throw_socket_error(ctx);
    }
    
    return JS_NewInt64(ctx, ret);
}

/* sendto(buffer, flags, addr) */
static JSValue tjs_sock_sendto(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "sendto(buffer, flags, addr) requires 3 arguments");
    }

    size_t sz;
    uint8_t *buf = JS_GetUint8Array(ctx, &sz, argv[0]);
    if (!buf) {
        return JS_ThrowTypeError(ctx, "buffer must be Uint8Array");
    }

    int32_t flags;
    if (JS_ToInt32(ctx, &flags, argv[1])) return JS_EXCEPTION;

    size_t addrsz;
    struct sockaddr *addr = (struct sockaddr *) JS_GetUint8Array(ctx, &addrsz, argv[2]);
    if (!addr) {
        return JS_ThrowTypeError(ctx, "addr must be Uint8Array");
    }

    ssize_t ret;
    do {
        ret = sendto(s->sock, buf, sz, flags, addr, addrsz);
    } while (ret < 0 && errno == EINTR);
    
    if (ret < 0) {
        return throw_socket_error(ctx);
    }
    
    return JS_NewInt64(ctx, ret);
}

/* recvfrom(buffer, flags) -> { bytes, addr } */
static JSValue tjs_sock_recvfrom(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "recvfrom(buffer, flags) requires Uint8Array");
    }

    size_t count;
    uint8_t *buf = JS_GetUint8Array(ctx, &count, argv[0]);
    if (!buf) {
        return JS_ThrowTypeError(ctx, "buffer must be Uint8Array");
    }

    int flags = 0;
    if (argc > 1 && JS_IsNumber(argv[1])) {
        int32_t f;
        if (JS_ToInt32(ctx, &f, argv[1])) return JS_EXCEPTION;
        flags = f;
    }

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    ssize_t ret;
    do {
        ret = recvfrom(s->sock, buf, count, flags, (struct sockaddr *)&addr, &addrlen);
    } while (ret < 0 && errno == EINTR);
    
    if (ret < 0) {
        return throw_socket_error(ctx);
    }
    if (ret == 0) {
        return JS_NULL;
    }

    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "bytes", JS_NewInt64(ctx, ret));
    JS_SetPropertyStr(ctx, result, "addr", JS_NewUint8ArrayCopy(ctx, (uint8_t *)&addr, addrlen));
    return result;
}

/* setsockopt(level, optname, optval) */
static JSValue tjs_sock_setsockopt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "setsockopt(level, optname, optval) requires 3 arguments");
    }

    uint32_t level, optname;
    if (JS_ToUint32(ctx, &level, argv[0]) || JS_ToUint32(ctx, &optname, argv[1])) {
        return JS_EXCEPTION;
    }

    size_t optlen;
    void *optval = JS_GetUint8Array(ctx, &optlen, argv[2]);
    if (!optval) {
        return JS_ThrowTypeError(ctx, "optval must be Uint8Array");
    }

    if (setsockopt(s->sock, level, optname, optval, optlen) < 0) {
        return throw_socket_error(ctx);
    }

    return JS_UNDEFINED;
}

/* getsockopt(level, optname, maxlen) -> Uint8Array */
static JSValue tjs_sock_getsockopt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "getsockopt(level, optname, maxlen) requires at least 2 arguments");
    }

    uint32_t level, optname;
    if (JS_ToUint32(ctx, &level, argv[0]) || JS_ToUint32(ctx, &optname, argv[1])) {
        return JS_EXCEPTION;
    }

    socklen_t optlen = sizeof(struct sockaddr_storage);
    if (argc > 2) {
        uint32_t len;
        if (JS_ToUint32(ctx, &len, argv[2])) return JS_EXCEPTION;
        optlen = len;
    }

    void *optval = js_malloc(ctx, optlen);
    if (!optval) return JS_EXCEPTION;

    if (getsockopt(s->sock, level, optname, optval, &optlen) < 0) {
        js_free(ctx, optval);
        return throw_socket_error(ctx);
    }

    return TJS_NewUint8Array(ctx, optval, optlen);
}

/* shutdown(how) */
static JSValue tjs_sock_shutdown(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    uint32_t how = SHUT_RDWR;  // default both
    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        if (JS_ToUint32(ctx, &how, argv[0])) return JS_EXCEPTION;
    }

    if (shutdown(s->sock, how) < 0) {
        return throw_socket_error(ctx);
    }
    return JS_UNDEFINED;
}

/* close() */
static void close_sock(tjs_sock_t *s) {
    if (!s || s->closed) return;
    
    if (s->poll_init) {
        if (uv_is_active((uv_handle_t *) &s->poll)) {
            uv_poll_stop(&s->poll);
        }
        if (!uv_is_closing((uv_handle_t *) &s->poll)) {
            uv_close((uv_handle_t *) &s->poll, NULL);
        }
        if (!JS_IsUndefined(s->callback)) {
            JS_FreeValue(s->ctx, s->callback);
            s->callback = JS_UNDEFINED;
        }
        s->poll_init = false;
    }
    
    close(s->sock);
    s->closed = true;
}

static JSValue tjs_sock_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);
    if (!s) return JS_ThrowTypeError(ctx, "Not a PosixSocket");
    
    if (s->closed) {
        return JS_ThrowInternalError(ctx, "Socket already closed");
    }
    if (s->in_cb) {
        return JS_ThrowInternalError(ctx, "Cannot close socket during poll callback");
    }
    
    close_sock(s);
    return JS_UNDEFINED;
}

/* get fd */
static JSValue tjs_sock_get_fd(JSContext *ctx, JSValue this_val) {
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);
    if (!s) return JS_ThrowTypeError(ctx, "Not a PosixSocket");
    return JS_NewInt32(ctx, s->sock);
}

/* get info: { domain, type, protocol } */
static JSValue tjs_sock_get_info(JSContext *ctx, JSValue this_val) {
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);
    if (!s) return JS_ThrowTypeError(ctx, "Not a PosixSocket");

    JSValue info = JS_NewObject(ctx);
    int val;
    socklen_t len = sizeof(val);

    if (getsockopt(s->sock, SOL_SOCKET, SO_DOMAIN, &val, &len) == 0) {
        JS_SetPropertyStr(ctx, info, "domain", JS_NewInt32(ctx, val));
    }
    if (getsockopt(s->sock, SOL_SOCKET, SO_TYPE, &val, &len) == 0) {
        JS_SetPropertyStr(ctx, info, "type", JS_NewInt32(ctx, val));
    }
    if (getsockopt(s->sock, SOL_SOCKET, SO_PROTOCOL, &val, &len) == 0) {
        JS_SetPropertyStr(ctx, info, "protocol", JS_NewInt32(ctx, val));
    }

    return info;
}

/* poll(events, callback) - event polling */
static void tjs_sock_uv_poll_cb(uv_poll_t *handle, int status, int events) {
    tjs_sock_t *s = uv_handle_get_data((uv_handle_t *) handle);
    if (!s || s->closed) return;
    
    JSValue args[2] = { 
        JS_NewInt32(s->ctx, status), 
        JS_NewInt32(s->ctx, events) 
    };
    s->in_cb = true;
    JSValue ret = JS_Call(s->ctx, s->callback, s->this_val, 2, args);
    JS_FreeValue(s->ctx, ret);
    JS_FreeValue(s->ctx, args[0]);
    JS_FreeValue(s->ctx, args[1]);
    s->in_cb = false;
}

static JSValue tjs_sock_poll(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_sock_t *s = get_socket(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "poll(events, callback) requires 2 arguments");
    }

    uint32_t events;
    if (JS_ToUint32(ctx, &events, argv[0])) return JS_EXCEPTION;
    if (events == 0 || events > 0xF) {
        return JS_ThrowRangeError(ctx, "events must be 1-15");
    }
    if (!JS_IsFunction(ctx, argv[1])) {
        return JS_ThrowTypeError(ctx, "callback must be function");
    }

    if (!s->poll_init) {
        int ret = uv_poll_init(tjs_get_loop(ctx), &s->poll, s->sock);
        if (ret < 0) {
            return tjs_throw_errno(ctx, ret);
        }
        s->poll_init = true;
        uv_handle_set_data((uv_handle_t *) &s->poll, s);
    }

    if (!JS_IsUndefined(s->callback)) {
        JS_FreeValue(ctx, s->callback);
    }
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
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);
    if (!s) return JS_ThrowTypeError(ctx, "Not a PosixSocket");
    
    if (s->in_cb) {
        return JS_ThrowInternalError(ctx, "Cannot stop poll during callback");
    }
    if (!s->poll_init || uv_is_closing((uv_handle_t *) &s->poll)) {
        return JS_ThrowInternalError(ctx, "Poll not started");
    }
    
    int ret = uv_poll_stop(&s->poll);
    if (ret < 0) {
        return tjs_throw_errno(ctx, ret);
    }
    return JS_UNDEFINED;
}

static JSValue tjs_sock_get_polling(JSContext *ctx, JSValue this_val) {
    tjs_sock_t *s = JS_GetOpaque(this_val, tjs_sock_classid);
    if (!s) return JS_ThrowTypeError(ctx, "Not a PosixSocket");
    return JS_NewBool(ctx, s->poll_init && uv_is_active((uv_handle_t *) &s->poll));
}

/* Finalizer and GC mark */
static void tjs_sock_finalizer(JSRuntime *rt, JSValue val) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (s) {
        close_sock(s);
        JS_FreeValueRT(rt, s->this_val);
        js_free_rt(rt, s);
    }
}

static void tjs_sock_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    tjs_sock_t *s = JS_GetOpaque(val, tjs_sock_classid);
    if (s) {
        if (!JS_IsUndefined(s->callback)) {
            JS_MarkValue(rt, s->callback, mark_func);
        }
        JS_MarkValue(rt, s->this_val, mark_func);
    }
}

static JSClassDef tjs_sock_class = { 
    TJS_SOCK_CLASS_NAME, 
    .finalizer = tjs_sock_finalizer,
    .gc_mark = tjs_sock_gc_mark 
};

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Create sockaddr from JS object { host, port } or [host, port] */
static JSValue tjs_sock_create_sockaddr(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "createSockaddr(family, obj) requires 2 arguments");
    }

    uint32_t family;
    if (JS_ToUint32(ctx, &family, argv[0])) return JS_EXCEPTION;

    struct sockaddr_storage ss;
    int ret = tjs_obj2addr(ctx, argv[1], &ss);
    if (ret < 0) {
        return tjs_throw_errno(ctx, uv_translate_sys_error(ret));
    }

    size_t len = (family == AF_INET6) ? sizeof(struct sockaddr_in6) : 
                 (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(ss);
    
    return JS_NewUint8ArrayCopy(ctx, (uint8_t *)&ss, len);
}

/* strerror for errno */
static JSValue tjs_sock_strerror(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "strerror(errno) requires 1 argument");
    }
    int32_t err;
    if (JS_ToInt32(ctx, &err, argv[0])) return JS_EXCEPTION;
    return JS_NewString(ctx, strerror(err));
}

/* Interface name <-> index */
static JSValue tjs_posix_if_nametoindex(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "ifNametoindex(name) requires string");
    }
    const char *name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_EXCEPTION;
    
    unsigned ret = if_nametoindex(name);
    JS_FreeCString(ctx, name);
    
    if (ret == 0) {
        return throw_socket_error(ctx);
    }
    return JS_NewUint32(ctx, ret);
}

static JSValue tjs_posix_if_indextoname(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "ifIndextoname(index) requires number");
    }
    uint32_t idx;
    if (JS_ToUint32(ctx, &idx, argv[0])) return JS_EXCEPTION;
    
    char name[IF_NAMESIZE];
    if (!if_indextoname(idx, name)) {
        return throw_socket_error(ctx);
    }
    return JS_NewString(ctx, name);
}

/* IP checksum */
static uint16_t ip_checksum(void *data, size_t length) {
    uint8_t *buf = data;
    uint64_t sum = 0;
    
    while (length > 1) {
        sum += *(uint16_t *)buf;
        buf += 2;
        length -= 2;
    }
    if (length) {
        sum += *buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

static JSValue tjs_posix_checksum(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "checksum(data) requires Uint8Array");
    }
    size_t len;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if (!data) {
        return JS_ThrowTypeError(ctx, "data must be Uint8Array");
    }
    return JS_NewUint32(ctx, ip_checksum(data, len));
}

/* ============================================================================
 * Constants and Module Definition
 * ============================================================================ */

#define CONST_INT(x) JS_PROP_INT32_DEF(#x, x, JS_PROP_ENUMERABLE)

static const JSCFunctionListEntry tjs_sock_proto_funcs[] = {
    /* Core I/O */
    TJS_CFUNC_DEF("read", 1, tjs_sock_read),
    TJS_CFUNC_DEF("write", 1, tjs_sock_write),
    TJS_CFUNC_DEF("recv", 2, tjs_sock_recv),
    TJS_CFUNC_DEF("send", 2, tjs_sock_send),
    TJS_CFUNC_DEF("recvfrom", 2, tjs_sock_recvfrom),
    TJS_CFUNC_DEF("sendto", 3, tjs_sock_sendto),
    
    /* Connection management */
    TJS_CFUNC_DEF("bind", 1, tjs_sock_bind),
    TJS_CFUNC_DEF("connect", 1, tjs_sock_connect),
    TJS_CFUNC_DEF("listen", 1, tjs_sock_listen),
    TJS_CFUNC_DEF("accept", 0, tjs_sock_accept),
    TJS_CFUNC_DEF("shutdown", 1, tjs_sock_shutdown),
    TJS_CFUNC_DEF("close", 0, tjs_sock_close),
    
    /* Socket options */
    TJS_CFUNC_DEF("setopt", 3, tjs_sock_setsockopt),
    TJS_CFUNC_DEF("getopt", 3, tjs_sock_getsockopt),
    
    /* Polling */
    TJS_CFUNC_DEF("poll", 2, tjs_sock_poll),
    TJS_CFUNC_DEF("pollStop", 0, tjs_sock_poll_stop),
    
    /* Properties */
    TJS_CGETSET_DEF("fd", tjs_sock_get_fd, NULL),
    TJS_CGETSET_DEF("info", tjs_sock_get_info, NULL),
    TJS_CGETSET_DEF("polling", tjs_sock_get_polling, NULL),
};

/* clang-format off */
static const JSCFunctionListEntry defines_list[] = {
    /* Address families */
    CONST_INT(AF_UNSPEC),
    CONST_INT(AF_INET),
    CONST_INT(AF_INET6),
#ifdef AF_UNIX
    CONST_INT(AF_UNIX),
#endif
#ifdef AF_NETLINK
    CONST_INT(AF_NETLINK),
#endif
#ifdef AF_PACKET
    CONST_INT(AF_PACKET),
#endif

    /* Socket types */
    CONST_INT(SOCK_STREAM),
    CONST_INT(SOCK_DGRAM),
    CONST_INT(SOCK_RAW),
    CONST_INT(SOCK_SEQPACKET),
    CONST_INT(SOCK_RDM),

    /* Protocols */
    CONST_INT(IPPROTO_IP),
    CONST_INT(IPPROTO_TCP),
    CONST_INT(IPPROTO_UDP),
    CONST_INT(IPPROTO_ICMP),
    CONST_INT(IPPROTO_IPV6),

    /* Socket levels */
    CONST_INT(SOL_SOCKET),
#ifdef SOL_TCP
    CONST_INT(SOL_TCP),
#endif
#ifdef SOL_UDP
    CONST_INT(SOL_UDP),
#endif
#ifdef SOL_NETLINK
    CONST_INT(SOL_NETLINK),
#endif
#ifdef SOL_PACKET
    CONST_INT(SOL_PACKET),
#endif

    /* Socket options */
    CONST_INT(SO_REUSEADDR),
    CONST_INT(SO_KEEPALIVE),
    CONST_INT(SO_LINGER),
    CONST_INT(SO_BROADCAST),
    CONST_INT(SO_OOBINLINE),
    CONST_INT(SO_RCVBUF),
    CONST_INT(SO_SNDBUF),
    CONST_INT(SO_RCVTIMEO),
    CONST_INT(SO_SNDTIMEO),
    CONST_INT(SO_ERROR),
    CONST_INT(SO_TYPE),
    CONST_INT(SO_DEBUG),
    CONST_INT(SO_DONTROUTE),
#ifdef SO_REUSEPORT
    CONST_INT(SO_REUSEPORT),
#endif
#ifdef SO_TIMESTAMP
    CONST_INT(SO_TIMESTAMP),
#endif

    /* Shutdown modes */
    CONST_INT(SHUT_RD),
    CONST_INT(SHUT_WR),
    CONST_INT(SHUT_RDWR),

    /* Send/recv flags */
    CONST_INT(MSG_OOB),
    CONST_INT(MSG_PEEK),
    CONST_INT(MSG_DONTROUTE),
    CONST_INT(MSG_CTRUNC),
    CONST_INT(MSG_PROXY),
    CONST_INT(MSG_TRUNC),
    CONST_INT(MSG_DONTWAIT),
    CONST_INT(MSG_EOR),
    CONST_INT(MSG_WAITALL),
    CONST_INT(MSG_FIN),
    CONST_INT(MSG_SYN),
    CONST_INT(MSG_CONFIRM),
    CONST_INT(MSG_RST),
    CONST_INT(MSG_ERRQUEUE),
    CONST_INT(MSG_NOSIGNAL),
    CONST_INT(MSG_MORE),
    CONST_INT(MSG_WAITFORONE),
    CONST_INT(MSG_FASTOPEN),
    CONST_INT(MSG_CMSG_CLOEXEC),
};

static const JSCFunctionListEntry uv_poll_events[] = {
    TJS_UVCONST(READABLE),
    TJS_UVCONST(WRITABLE),
    TJS_UVCONST(DISCONNECT),
    TJS_UVCONST(PRIORITIZED),
};
/* clang-format on */

static const JSCFunctionListEntry posix_ns_funcs[] = {
    TJS_CFUNC_DEF("socket", 3, tjs_sock_create),
    TJS_CFUNC_DEF("fromFd", 1, tjs_sock_from_fd),
    TJS_CFUNC_DEF("createSockaddr", 2, tjs_sock_create_sockaddr),
    TJS_CFUNC_DEF("strerror", 1, tjs_sock_strerror),
    TJS_CFUNC_DEF("ifNametoindex", 1, tjs_posix_if_nametoindex),
    TJS_CFUNC_DEF("ifIndextoname", 1, tjs_posix_if_indextoname),
    TJS_CFUNC_DEF("checksum", 1, tjs_posix_checksum),
    
    JS_OBJECT_DEF("defines", defines_list, countof(defines_list), JS_PROP_C_W_E),
    JS_OBJECT_DEF("pollEvents", uv_poll_events, countof(uv_poll_events), JS_PROP_C_W_E),
    
    TJS_CONST2("sizeofSockaddr", sizeof(struct sockaddr_storage)),
};

void tjs__mod_posix_socket_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    JS_NewClassID(rt, &tjs_sock_classid);
    JS_NewClass(rt, tjs_sock_classid, &tjs_sock_class);
    
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_sock_proto_funcs, countof(tjs_sock_proto_funcs));
    JS_SetClassProto(ctx, tjs_sock_classid, proto);
    
    JS_SetPropertyFunctionList(ctx, ns, posix_ns_funcs, countof(posix_ns_funcs));
}
