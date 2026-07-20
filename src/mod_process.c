/*
 * circu.js
 *
 * Copyright (c) 2026-present iz
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
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
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <io.h>
    #include <process.h>
    typedef int pid_t;
    #ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
    #define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE \
        ProcThreadAttributeValue(22, false, true, false)
    typedef VOID *HPCON;
    #endif
    #define STDIN_FILENO  0
    #define STDOUT_FILENO 1
    #define STDERR_FILENO 2
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/wait.h>
    #include <sys/ioctl.h>
    #include <sys/select.h>
    #include <termios.h>
    #if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <util.h>
    #elif defined(__FreeBSD__)
    #include <libutil.h>
    #else
    #include <pty.h>
    #endif
    extern char **environ;
#endif


/* ============================================================
 * Windows ConPTY — dynamic load from kernel32
 * ============================================================ */
#ifdef _WIN32
typedef HRESULT (WINAPI *CreatePseudoConsolePtr)(COORD, HANDLE, HANDLE, DWORD, HPCON *);
typedef HRESULT (WINAPI *ResizePseudoConsolePtr)(HPCON, COORD);
typedef void    (WINAPI *ClosePseudoConsolePtr)(HPCON);

static CreatePseudoConsolePtr pCreatePseudoConsole;
static ResizePseudoConsolePtr pResizePseudoConsole;
static ClosePseudoConsolePtr  pClosePseudoConsole;

static bool load_conpty(void) {
    static int loaded = -1;
    if (loaded >= 0) return (bool)loaded;
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) { loaded = 0; return false; }
    pCreatePseudoConsole = (CreatePseudoConsolePtr)GetProcAddress(k32, "CreatePseudoConsole");
    pResizePseudoConsole = (ResizePseudoConsolePtr)GetProcAddress(k32, "ResizePseudoConsole");
    pClosePseudoConsole  = (ClosePseudoConsolePtr) GetProcAddress(k32, "ClosePseudoConsole");
    loaded = (pCreatePseudoConsole && pResizePseudoConsole && pClosePseudoConsole) ? 1 : 0;
    return (bool)loaded;
}
#endif /* _WIN32 */


/* ============================================================
 * TJSProcess — unified normal-process + PTY
 *
 * Normal mode:  uv_process_t + stdio Pipe objects.
 * PTY mode:     fork+openpty (Unix) / ConPTY (Windows).
 *               p->process is NOT initialized in PTY mode.
 * ============================================================ */
static thread_local JSClassID tjs_process_class_id;

typedef struct {
    JSContext *ctx;
    JSValue    obj;        /* GC pin while live; intentionally omitted from gc_mark */
    bool pty_mode;
    bool handle_initialized;
    bool closed;
    bool finalized;
    uv_process_t process;  /* normal mode only */
    JSValue stdio[3];      /* normal mode: stdin/stdout/stderr Pipe objects */
    JSValue stdio_extra;   /* normal mode: extra fd pipes, indexed by fd */
    JSValue ipc_pipe;      /* IPC channel pipe (fd 3) */
    struct {
        bool    exited;
        int64_t exit_status;
        int     term_signal;
        TJSPromise result;
    } status;

    /* PTY-mode fields */
    pid_t   pty_pid;
    JSValue pty_readable;
    JSValue pty_writable;
    int     pty_cols;
    int     pty_rows;
    uv_timer_t pty_waiter;
#ifdef _WIN32
    HPCON  hpc;
    HANDLE pty_proc_handle; /* kept for waitSync */
#else
    int master_fd;  /* ioctl target; libuv owns the fd via pty_readable */
#endif
} TJSProcess;

#ifdef _WIN32
static WCHAR *spawn_sync_utf8_to_wide(JSContext *ctx, const char *s);
static WCHAR *spawn_sync_resolve_win_app(JSContext *ctx, const WCHAR *app);
static WCHAR *spawn_sync_build_win_cmdline(JSContext *ctx, char **args);
static WCHAR *spawn_sync_build_win_env(JSContext *ctx, char **env);
#endif


/* ============================================================
 * Shared helpers
 * ============================================================ */

static JSValue make_exit_obj(JSContext *ctx, int64_t es, int ts) {
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    JS_DefinePropertyValueStr(ctx, obj, "exit_status", JS_NewInt64(ctx, es), JS_PROP_C_W_E);
    JSValue sig = ts == 0 ? JS_NULL : JS_NewString(ctx, tjs_getsig(ts));
    JS_DefinePropertyValueStr(ctx, obj, "term_signal", sig, JS_PROP_C_W_E);
    return obj;
}

/* Parse a signal: string name or integer.  Returns -1 with exception set on error. */
static int parse_signal(JSContext *ctx, JSValue val, int def) {
    if (JS_IsUndefined(val) || JS_IsNull(val)) return def;
    if (JS_IsNumber(val)) {
        int n;
        if (JS_ToInt32(ctx, &n, val)) return -1;
        return n;
    }
    if (JS_IsString(val)) {
        const char *s = JS_ToCString(ctx, val);
        if (!s) return -1;
        int n = tjs_getsignum(s);
        if (n == -1) JS_ThrowRangeError(ctx, "unknown signal: %s", s);
        JS_FreeCString(ctx, s);
        return n;
    }
    JS_ThrowTypeError(ctx, "signal must be a string or integer");
    return -1;
}

/* Build a NULL-terminated "KEY=VALUE" array from a JS object.  Uses js_malloc throughout. */
static char **parse_env_obj(JSContext *ctx, JSValue js_env) {
    if (!JS_IsObject(js_env)) return NULL;
    JSPropertyEnum *ptab; uint32_t plen;
    if (JS_GetOwnPropertyNames(ctx, &ptab, &plen, js_env, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY))
        return NULL;
    char **env = js_mallocz(ctx, sizeof(char *) * (plen + 1));
    if (!env) { JS_FreePropertyEnum(ctx, ptab, plen); return NULL; }
    int n = 0;
    for (uint32_t i = 0; i < plen; i++) {
        const char *key = JS_AtomToCString(ctx, ptab[i].atom);
        JSValue pv = JS_GetProperty(ctx, js_env, ptab[i].atom);
        const char *val = JS_IsException(pv) ? NULL : JS_ToCString(ctx, pv);
        JS_FreeValue(ctx, pv);
        if (key && val) {
            size_t len = strlen(key) + strlen(val) + 2;
            env[n] = js_malloc(ctx, len);
            if (env[n]) { snprintf(env[n], len, "%s=%s", key, val); n++; }
        }
        JS_FreeCString(ctx, key);
        JS_FreeCString(ctx, val);
    }
    JS_FreePropertyEnum(ctx, ptab, plen);
    return env;
}

static char **empty_env(JSContext *ctx) {
    return js_mallocz(ctx, sizeof(char *));
}

static void free_env(JSContext *ctx, char **env) {
    if (!env) return;
    for (int i = 0; env[i]; i++) js_free(ctx, env[i]);
    js_free(ctx, env);
}

static __maybe_unused int ensure_stdio_capacity(JSContext *ctx, uv_process_options_t *options, uv_stdio_container_t stdio[3], uv_stdio_container_t **stdio_heap, int count) {
    if ((int)options->stdio_count >= count) return 0;
    uv_stdio_container_t *new_stdio = js_malloc(ctx, sizeof(*new_stdio) * count);
    if (!new_stdio) return -1;
    memcpy(new_stdio, options->stdio, sizeof(*new_stdio) * options->stdio_count);
    for (int i = (int)options->stdio_count; i < count; i++) {
        new_stdio[i].flags = UV_IGNORE;
    }
    if (*stdio_heap) js_free(ctx, *stdio_heap);
    *stdio_heap = new_stdio;
    options->stdio = new_stdio;
    options->stdio_count = count;
    (void)stdio;
    return 0;
}

static int setup_extra_stdio(JSContext *ctx, TJSProcess *p, uv_process_options_t *options, uv_stdio_container_t stdio[3], uv_stdio_container_t **stdio_heap, JSValue js_extra) {
    if (!JS_IsArray(js_extra)) return 0;

    JSValue js_len = JS_GetPropertyStr(ctx, js_extra, "length");
    uint64_t extra_len;
    if (JS_ToIndex(ctx, &extra_len, js_len)) {
        JS_FreeValue(ctx, js_len);
        return -1;
    }
    JS_FreeValue(ctx, js_len);
    if (extra_len == 0) return 0;
    if (extra_len > 253) {
        JS_ThrowRangeError(ctx, "stdioExtra cannot contain more than 253 entries");
        return -1;
    }

    int stdio_count = (int)extra_len + 3;
    if (ensure_stdio_capacity(ctx, options, stdio, stdio_heap, stdio_count) < 0) {
        JS_ThrowOutOfMemory(ctx);
        return -1;
    }

    p->stdio_extra = JS_NewArray(ctx);
    if (JS_IsException(p->stdio_extra)) return -1;
    for (int fd = 0; fd < stdio_count; fd++) {
        JS_SetPropertyUint32(ctx, p->stdio_extra, (uint32_t)fd, JS_NULL);
    }

    for (uint64_t i = 0; i < extra_len; i++) {
        uint32_t fd = (uint32_t)i + 3;
        JSValue item = JS_GetPropertyUint32(ctx, js_extra, (uint32_t)i);
        if (JS_IsException(item)) return -1;
        if (JS_IsUndefined(item) || JS_IsNull(item)) {
            JS_FreeValue(ctx, item);
            continue;
        }

        if (JS_IsNumber(item)) {
            int32_t inherited_fd;
            if (JS_ToInt32(ctx, &inherited_fd, item)) {
                JS_FreeValue(ctx, item);
                return -1;
            }
            options->stdio[fd].flags = UV_INHERIT_FD;
            options->stdio[fd].data.fd = inherited_fd;
            JS_FreeValue(ctx, item);
            continue;
        }

        const char *mode = JS_ToCString(ctx, item);
        JS_FreeValue(ctx, item);
        if (!mode) return -1;

        if (strcmp(mode, "pipe") == 0) {
            JSValue pipe_obj = tjs_new_pipe(ctx);
            if (JS_IsException(pipe_obj)) {
                JS_FreeCString(ctx, mode);
                return -1;
            }
            options->stdio[fd].flags = UV_CREATE_PIPE | UV_READABLE_PIPE | UV_WRITABLE_PIPE;
            options->stdio[fd].data.stream = tjs_pipe_get_stream(ctx, pipe_obj);
            if (!options->stdio[fd].data.stream) {
                JS_FreeValue(ctx, pipe_obj);
                JS_FreeCString(ctx, mode);
                JS_ThrowInternalError(ctx, "failed to create extra stdio pipe");
                return -1;
            }
            JS_SetPropertyUint32(ctx, p->stdio_extra, fd, pipe_obj);
        } else if (strcmp(mode, "ignore") == 0) {
            options->stdio[fd].flags = UV_IGNORE;
        } else if (strcmp(mode, "inherit") == 0) {
            options->stdio[fd].flags = UV_INHERIT_FD;
            options->stdio[fd].data.fd = (int)fd;
        } else {
            JS_ThrowRangeError(ctx, "unsupported stdioExtra entry: %s", mode);
            JS_FreeCString(ctx, mode);
            return -1;
        }
        JS_FreeCString(ctx, mode);
    }

    return 0;
}

/* Build a NULL-terminated argv array from a JS array.  Uses js_malloc / js_strdup. */
static char **parse_argv_arr(JSContext *ctx, JSValue js_arr, int *len_out) {
    JSValue lv = JS_GetPropertyStr(ctx, js_arr, "length");
    int32_t len = 0; JS_ToInt32(ctx, &len, lv); JS_FreeValue(ctx, lv);
    *len_out = 0;
    if (len <= 0) return NULL;
    char **arr = js_mallocz(ctx, sizeof(char *) * (len + 1));
    if (!arr) return NULL;
    int n = 0;
    for (int32_t i = 0; i < len; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, js_arr, (uint32_t)i);
        const char *s = JS_ToCString(ctx, item);
        JS_FreeValue(ctx, item);
        if (s) {
            arr[n] = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
            if (arr[n]) n++;
        }
    }
    *len_out = n;
    return arr;
}

static bool bool_prop(JSContext *ctx, JSValue obj, const char *name) {
    if (!JS_IsObject(obj)) return false;
    JSValue val = JS_GetPropertyStr(ctx, obj, name);
    bool ret = JS_ToBool(ctx, val) == 1;
    JS_FreeValue(ctx, val);
    return ret;
}

static void free_str_arr(JSContext *ctx, char **arr, int len) {
    if (!arr) return;
    for (int i = 0; i < len; i++) js_free(ctx, arr[i]);
    js_free(ctx, arr);
}

static char **tjs__parse_args(JSContext *ctx, JSValue arg0);
static void tjs__free_args(JSContext *ctx, char **args);

/* Read { cols, rows } from a JS options object, with defaults. */
static void parse_winsize(JSContext *ctx, JSValue opts, int *cols, int *rows) {
    *cols = 80; *rows = 24;
    if (!JS_IsObject(opts)) return;
    JSValue v;
    v = JS_GetPropertyStr(ctx, opts, "cols");
    if (JS_IsNumber(v)) { int32_t n; JS_ToInt32(ctx, &n, v); *cols = n; }
    JS_FreeValue(ctx, v);
    v = JS_GetPropertyStr(ctx, opts, "rows");
    if (JS_IsNumber(v)) { int32_t n; JS_ToInt32(ctx, &n, v); *rows = n; }
    JS_FreeValue(ctx, v);
}

static TJSProcess *tjs_process_get(JSContext *ctx, JSValue obj) {
    return JS_GetOpaque2(ctx, obj, tjs_process_class_id);
}


/* ============================================================
 * Lifecycle — close / finalize / GC mark
 * ============================================================ */

static void uv__proc_close_cb(uv_handle_t *handle) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    p->closed = true;
    if (p->finalized) tjs__free(p);
}

static void maybe_close(TJSProcess *p) {
    if (!p->handle_initialized) return;
    uv_handle_t *handle = p->pty_mode
        ? (uv_handle_t *)&p->pty_waiter
        : (uv_handle_t *)&p->process;
    if (!uv_is_closing(handle))
        uv_close(handle, uv__proc_close_cb);
}

static void process_finish(TJSProcess *p, int64_t exit_status, int term_signal) {
    if (p->status.exited) return;

    p->status.exited = true;
    p->status.exit_status = exit_status;
    p->status.term_signal = term_signal;

    if (!JS_IsUndefined(p->status.result.p)) {
        JSValue arg = make_exit_obj(p->ctx, exit_status, term_signal);
        TJS_SettlePromise(p->ctx, &p->status.result, false, 1, &arg);
    }

    maybe_close(p);
    if (!JS_IsUndefined(p->obj)) {
        JSValue obj = p->obj;
        p->obj = JS_UNDEFINED;
        JS_FreeValue(p->ctx, obj);
    }
}

#ifndef _WIN32
static int decode_wait_status(int status, int64_t *exit_status, int *term_signal) {
    if (WIFEXITED(status)) {
        *exit_status = WEXITSTATUS(status);
        *term_signal = 0;
        return 0;
    }
    if (WIFSIGNALED(status)) {
        *term_signal = WTERMSIG(status);
        *exit_status = 128 + *term_signal;
        return 0;
    }
    return -1;
}
#endif

static void uv__pty_wait_cb(uv_timer_t *handle) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    if (p->status.exited) return;

    int64_t exit_status = 0;
    int term_signal = 0;
#ifdef _WIN32
    DWORD wait_result = WaitForSingleObject(p->pty_proc_handle, 0);
    if (wait_result == WAIT_TIMEOUT) return;
    if (wait_result != WAIT_OBJECT_0) return;
    DWORD status;
    if (!GetExitCodeProcess(p->pty_proc_handle, &status)) return;
    exit_status = (int64_t)status;
#else
    int status;
    pid_t result;
    do {
        result = waitpid(p->pty_pid, &status, WNOHANG);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) return;
    if (decode_wait_status(status, &exit_status, &term_signal) < 0) return;
#endif

    process_finish(p, exit_status, term_signal);
}

static void tjs_process_finalizer(JSRuntime *rt, JSValue val) {
    TJSProcess *p = JS_GetOpaque(val, tjs_process_class_id);
    if (!p) return;

    /* p->obj pins this same Process wrapper while the child is alive. Once
     * QuickJS is finalizing the wrapper, only detach the pin. */
    p->obj = JS_UNDEFINED;
    TJS_FreePromiseRT(rt, &p->status.result);
    for (int i = 0; i < 3; i++) JS_FreeValueRT(rt, p->stdio[i]);
    JS_FreeValueRT(rt, p->stdio_extra);
    JS_FreeValueRT(rt, p->ipc_pipe);

    if (p->pty_mode) {
        JS_FreeValueRT(rt, p->pty_readable);
        JS_FreeValueRT(rt, p->pty_writable);
#ifdef _WIN32
        if (p->hpc && pClosePseudoConsole) pClosePseudoConsole(p->hpc);
        if (p->pty_proc_handle) CloseHandle(p->pty_proc_handle);
#else
        /* master_fd is owned by libuv through pty_readable; do NOT close here */
#endif
    }

    p->finalized = true;
    if (!p->handle_initialized || p->closed) tjs__free(p);
    else maybe_close(p);
}

static void tjs_process_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSProcess *p = JS_GetOpaque(val, tjs_process_class_id);
    if (!p) return;
    TJS_MarkPromise(rt, &p->status.result, mark_func);
    for (int i = 0; i < 3; i++) JS_MarkValue(rt, p->stdio[i], mark_func);
    JS_MarkValue(rt, p->stdio_extra, mark_func);
    JS_MarkValue(rt, p->ipc_pipe, mark_func);
    if (p->pty_mode) {
        JS_MarkValue(rt, p->pty_readable, mark_func);
        JS_MarkValue(rt, p->pty_writable, mark_func);
    }
}

static JSClassDef tjs_process_class = {
    "Process",
    .finalizer = tjs_process_finalizer,
    .gc_mark   = tjs_process_mark,
};


/* ============================================================
 * PTY spawn — Unix
 * ============================================================ */
#ifndef _WIN32
/*
 * On success: populates p->pty_pid, p->master_fd, p->pty_readable/writable.
 *             Returns JS_UNDEFINED.
 * On failure: returns JS_EXCEPTION (exception is set).
 */
static JSValue pty_unix_spawn(TJSProcess *p, JSContext *ctx,
                               const char *name, const char *cwd,
                               char **env_arr, char **argv_arr, int argc_val,
                               int cols, int rows, bool clear_env) {
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)cols;
    ws.ws_row = (unsigned short)rows;

    int master_fd = -1, slave_fd = -1;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, &ws) == -1)
        return JS_ThrowInternalError(ctx, "openpty: %s", strerror(errno));

    /* Make master non-blocking so libuv can poll it. */
    int fl = fcntl(master_fd, F_GETFL, 0);
    if (fl != -1) fcntl(master_fd, F_SETFL, fl | O_NONBLOCK);

    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        close(master_fd); close(slave_fd);
        return JS_ThrowInternalError(ctx, "fork: %s", strerror(e));
    }

    if (pid == 0) {
        /* Child — no QuickJS API, _exit on any error */
        close(master_fd);
        if (setsid() < 0) _exit(1);
#ifdef TIOCSCTTY
        if (ioctl(slave_fd, TIOCSCTTY, NULL) < 0) _exit(1);
#endif
        if (dup2(slave_fd, STDIN_FILENO)  < 0) _exit(1);
        if (dup2(slave_fd, STDOUT_FILENO) < 0) _exit(1);
        if (dup2(slave_fd, STDERR_FILENO) < 0) _exit(1);
        if (slave_fd > STDERR_FILENO) close(slave_fd);
        if (cwd && chdir(cwd) < 0) _exit(1);
        if (clear_env) environ = NULL;
        if (env_arr) {
            for (int i = 0; env_arr[i]; i++) {
                char *eq = strchr(env_arr[i], '=');
                if (eq) { *eq = '\0'; setenv(env_arr[i], eq + 1, 1); *eq = '='; }
            }
        }
        const char *file = (name && *name) ? name : getenv("SHELL");
        if (!file || !*file) file = "/bin/sh";
        if (argv_arr && argc_val > 0) {
            execvp(file, argv_arr);
        } else {
            char *def[] = { (char *)file, NULL };
            execvp(file, def);
        }
        _exit(1);
    }

    /* Parent — hand the master fd to libuv via uv_pipe_open.
       libuv then owns the fd and will close it when the pipe is closed.
       We keep master_fd as an integer for ioctl (resize / getwinsize). */
    close(slave_fd);

    JSValue pipe_obj = tjs_new_pipe(ctx);
    if (JS_IsException(pipe_obj)) {
        close(master_fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        return pipe_obj;
    }
    uv_pipe_t *pp = tjs_pipe_get_pipe(ctx, pipe_obj);
    if (!pp) {
        JS_FreeValue(ctx, pipe_obj);
        close(master_fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        return JS_ThrowInternalError(ctx, "failed to get pipe handle");
    }
    int r = uv_pipe_open(pp, master_fd);
    if (r != 0) {
        JS_FreeValue(ctx, pipe_obj);
        close(master_fd); kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        return tjs_throw_errno(ctx, r);
    }
    tjs_pipe_set_pty_master(ctx, pipe_obj);
    /* uv_pipe_open does not change handle->data — TJSStream pointer is intact. */

    p->pty_pid      = pid;
    p->master_fd    = master_fd; /* ioctl only; libuv owns the fd */
    p->pty_readable = JS_DupValue(ctx, pipe_obj);
    p->pty_writable = JS_DupValue(ctx, pipe_obj); /* bidirectional on Unix */
    JS_FreeValue(ctx, pipe_obj);
    return JS_UNDEFINED;
}
#endif /* !_WIN32 */


/* ============================================================
 * PTY spawn — Windows (ConPTY)
 * ============================================================ */
#ifdef _WIN32
static JSValue pty_win_spawn(TJSProcess *p, JSContext *ctx,
                              const char *name, const char *cwd,
                              char **env_arr, char **argv_arr, int argc_val,
                              int cols, int rows) {
    if (!load_conpty())
        return JS_ThrowInternalError(ctx, "ConPTY not supported on this Windows version");

    HANDLE hPipeIn  = INVALID_HANDLE_VALUE;
    HANDLE hPipeOut = INVALID_HANDLE_VALUE;
    HANDLE hConIn   = INVALID_HANDLE_VALUE;
    HANDLE hConOut  = INVALID_HANDLE_VALUE;
    HPCON  hPC      = NULL;
    HANDLE hProc    = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;
    WCHAR *wapp = NULL, *wexe = NULL, *wcmd = NULL, *wcwd = NULL, *wenv = NULL;
    JSValue ret = JS_EXCEPTION;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, true };
    if (!CreatePipe(&hConIn, &hPipeIn, &sa, 0) ||
        !CreatePipe(&hPipeOut, &hConOut, &sa, 0)) {
        JS_ThrowInternalError(ctx, "CreatePipe failed: %lu", GetLastError());
        goto cleanup;
    }

    COORD sz = { (SHORT)cols, (SHORT)rows };
    HRESULT hr = pCreatePseudoConsole(sz, hConIn, hConOut, 0, &hPC);
    if (FAILED(hr)) {
        JS_ThrowInternalError(ctx, "CreatePseudoConsole failed: 0x%08lx", hr);
        goto cleanup;
    }

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
    if (!attrList) {
        JS_ThrowOutOfMemory(ctx);
        goto cleanup;
    }
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize) ||
        !UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   hPC, sizeof(HPCON), NULL, NULL)) {
        JS_ThrowInternalError(ctx, "ProcThreadAttribute setup failed");
        goto cleanup;
    }

    const char *cmd = (name && *name) ? name : getenv("COMSPEC");
    if (!cmd || !*cmd) cmd = "cmd.exe";
    wapp = spawn_sync_utf8_to_wide(ctx, cmd);
    if (!wapp) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
    wexe = spawn_sync_resolve_win_app(ctx, wapp);
    if (!wexe) {
        JS_ThrowInternalError(ctx, "SearchPath failed for PTY command: %s", cmd);
        goto cleanup;
    }
    char *default_argv[] = { (char *)cmd, NULL };
    wcmd = spawn_sync_build_win_cmdline(ctx,
                                        argv_arr && argc_val > 0 ? argv_arr : default_argv);
    if (!wcmd) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
    if (cwd) {
        wcwd = spawn_sync_utf8_to_wide(ctx, cwd);
        if (!wcwd) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
    }
    wenv = spawn_sync_build_win_env(ctx, env_arr);
    if (env_arr && !wenv) { JS_ThrowOutOfMemory(ctx); goto cleanup; }

    STARTUPINFOEXW siEx = { 0 };
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siEx.lpAttributeList = attrList;
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(wexe, wcmd, NULL, NULL, false,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                        wenv, wcwd,
                        &siEx.StartupInfo, &pi)) {
        JS_ThrowInternalError(ctx, "CreateProcess failed: %lu", GetLastError());
        goto cleanup;
    }
    CloseHandle(pi.hThread);
    hProc = pi.hProcess; /* retain for waitSync */

    /* ConPTY internal pipe ends are no longer needed. */
    CloseHandle(hConIn);  hConIn  = INVALID_HANDLE_VALUE;
    CloseHandle(hConOut); hConOut = INVALID_HANDLE_VALUE;

    /* Writable pipe: JS writes → ConPTY → child stdin */
    JSValue write_obj = tjs_new_pipe(ctx);
    if (JS_IsException(write_obj)) goto cleanup;
    uv_pipe_t *pw = tjs_pipe_get_pipe(ctx, write_obj);
    if (!pw) { JS_FreeValue(ctx, write_obj); goto cleanup; }
    int wfd = _open_osfhandle((intptr_t)hPipeIn, 0);
    if (wfd < 0) {
        JS_FreeValue(ctx, write_obj);
        JS_ThrowInternalError(ctx, "_open_osfhandle (write) failed: %s", strerror(errno));
        goto cleanup;
    }
    hPipeIn = INVALID_HANDLE_VALUE; /* ownership transferred to the CRT fd */
    if (uv_pipe_open(pw, wfd) != 0) {
        _close(wfd); JS_FreeValue(ctx, write_obj);
        JS_ThrowInternalError(ctx, "uv_pipe_open (write) failed");
        goto cleanup;
    }

    /* Readable pipe: child stdout → ConPTY → JS */
    JSValue read_obj = tjs_new_pipe(ctx);
    if (JS_IsException(read_obj)) { JS_FreeValue(ctx, write_obj); goto cleanup; }
    uv_pipe_t *pr = tjs_pipe_get_pipe(ctx, read_obj);
    if (!pr) { JS_FreeValue(ctx, read_obj); JS_FreeValue(ctx, write_obj); goto cleanup; }
    int rfd = _open_osfhandle((intptr_t)hPipeOut, 0);
    if (rfd < 0) {
        JS_FreeValue(ctx, read_obj);
        JS_FreeValue(ctx, write_obj);
        JS_ThrowInternalError(ctx, "_open_osfhandle (read) failed: %s", strerror(errno));
        goto cleanup;
    }
    hPipeOut = INVALID_HANDLE_VALUE; /* ownership transferred to the CRT fd */
    if (uv_pipe_open(pr, rfd) != 0) {
        _close(rfd); JS_FreeValue(ctx, read_obj); JS_FreeValue(ctx, write_obj);
        JS_ThrowInternalError(ctx, "uv_pipe_open (read) failed");
        goto cleanup;
    }

    p->pty_pid         = (pid_t)pi.dwProcessId;
    p->hpc             = hPC;   hPC   = NULL;
    p->pty_proc_handle = hProc; hProc = NULL;
    p->pty_readable    = read_obj;
    p->pty_writable    = write_obj;
    ret = JS_UNDEFINED;

cleanup:
    if (attrList) { DeleteProcThreadAttributeList(attrList); free(attrList); }
    if (hConIn  != INVALID_HANDLE_VALUE) CloseHandle(hConIn);
    if (hConOut != INVALID_HANDLE_VALUE) CloseHandle(hConOut);
    if (hPipeIn != INVALID_HANDLE_VALUE) CloseHandle(hPipeIn);
    if (hPipeOut!= INVALID_HANDLE_VALUE) CloseHandle(hPipeOut);
    if (hPC && pClosePseudoConsole) pClosePseudoConsole(hPC);
    if (hProc) CloseHandle(hProc);
    js_free(ctx, wapp);
    js_free(ctx, wexe);
    js_free(ctx, wcmd);
    js_free(ctx, wcwd);
    js_free(ctx, wenv);
    return ret;
}
#endif /* _WIN32 */


/* ============================================================
 * SETUP_STDIO macro — used inside tjs_spawn
 * ============================================================ */
#define SETUP_STDIO(name, idx, pipe_flag, def_fd) do {                         \
    JSValue js_##name = JS_GetPropertyStr(ctx, arg1, #name);                   \
    if (!JS_IsException(js_##name) && !JS_IsUndefined(js_##name)) {            \
        const char *_v = JS_ToCString(ctx, js_##name);                         \
        if (!_v) { JS_FreeValue(ctx, js_##name); goto fail; }                  \
        if (strcmp(_v, "pipe") == 0) {                                          \
            JSValue _o = tjs_new_pipe(ctx);                                     \
            if (JS_IsException(_o)) { JS_FreeCString(ctx, _v);                 \
                JS_FreeValue(ctx, js_##name); goto fail; }                      \
            p->stdio[idx] = _o;                                                 \
            stdio[idx].flags = UV_CREATE_PIPE | (pipe_flag);                   \
            stdio[idx].data.stream = tjs_pipe_get_stream(ctx, _o);             \
            if (!stdio[idx].data.stream) { JS_FreeCString(ctx, _v);            \
                JS_FreeValue(ctx, js_##name); goto fail; }                      \
        } else if (strcmp(_v, "ignore") == 0) {                                \
            stdio[idx].flags = UV_IGNORE;                                       \
        } else {                                                                \
            stdio[idx].flags = UV_INHERIT_FD; stdio[idx].data.fd = (def_fd);   \
        }                                                                       \
        JS_FreeCString(ctx, _v);                                                \
    }                                                                           \
    JS_FreeValue(ctx, js_##name);                                               \
} while (0)


/* ============================================================
 * uv exit callback — normal mode only
 * ============================================================ */
/* ---- Argument parsing ---- */

static char **tjs__parse_args(JSContext *ctx, JSValue arg0) {
    char **args = NULL;
    if (JS_IsString(arg0)) {
        args = js_mallocz(ctx, sizeof(*args) * 2);
        if (!args) return NULL;
        const char *s = JS_ToCString(ctx, arg0);
        if (!s) { js_free(ctx, args); return NULL; }
        args[0] = js_strdup(ctx, s);
        JS_FreeCString(ctx, s);
        if (!args[0]) { js_free(ctx, args); return NULL; }
    } else if (JS_IsArray(arg0)) {
        JSValue js_len = JS_GetPropertyStr(ctx, arg0, "length");
        uint64_t len;
        if (JS_ToIndex(ctx, &len, js_len)) { JS_FreeValue(ctx, js_len); return NULL; }
        JS_FreeValue(ctx, js_len);
        args = js_mallocz(ctx, sizeof(*args) * (len + 1));
        if (!args) return NULL;
        for (uint64_t i = 0; i < len; i++) {
            JSValue v = JS_GetPropertyUint32(ctx, arg0, (uint32_t)i);
            if (JS_IsException(v)) goto fail;
            const char *s = JS_ToCString(ctx, v);
            JS_FreeValue(ctx, v);
            if (!s) goto fail;
            args[i] = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
            if (!args[i]) goto fail;
        }
    } else {
        JS_ThrowTypeError(ctx, "only string and array are allowed");
    }
    return args;
fail:
    if (args) { for (int i = 0; args[i]; i++) js_free(ctx, args[i]); js_free(ctx, args); }
    return NULL;
}

static void tjs__free_args(JSContext *ctx, char **args) {
    if (!args) return;
    for (int i = 0; args[i]; i++) js_free(ctx, args[i]);
    js_free(ctx, args);
}

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} TJSSpawnSyncBuf;

static void spawn_sync_buf_free(TJSSpawnSyncBuf *b) {
    if (b->data) free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static int spawn_sync_buf_append(TJSSpawnSyncBuf *b, const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    if (b->len > SIZE_MAX - len) return -1;
    size_t need = b->len + len;
    if (need > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 4096;
        while (cap < need) {
            if (cap > SIZE_MAX / 2) { cap = need; break; }
            cap *= 2;
        }
        uint8_t *p = realloc(b->data, cap);
        if (!p) return -1;
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

static JSValue spawn_sync_new_buffer(JSContext *ctx, TJSSpawnSyncBuf *b) {
    return JS_NewArrayBufferCopy(ctx, b->data, b->len);
}

static const char *spawn_sync_stdio_mode(JSContext *ctx, JSValue opts, const char *name, const char *def) {
    if (!JS_IsObject(opts)) return def;
    JSValue v = JS_GetPropertyStr(ctx, opts, name);
    if (JS_IsUndefined(v) || JS_IsNull(v)) { JS_FreeValue(ctx, v); return def; }
    if (JS_IsNumber(v)) { JS_FreeValue(ctx, v); return "inherit"; }
    const char *s = JS_ToCString(ctx, v);
    JS_FreeValue(ctx, v);
    if (!s) return def;
    const char *ret = def;
    if (!strcmp(s, "ignore")) ret = "ignore";
    else if (!strcmp(s, "inherit")) ret = "inherit";
    else if (!strcmp(s, "pipe")) ret = "pipe";
    JS_FreeCString(ctx, s);
    return ret;
}

static JSValue spawn_sync_make_result(JSContext *ctx, int pid, int64_t status, int signal,
                                      TJSSpawnSyncBuf *out, TJSSpawnSyncBuf *err,
                                      bool capture_out, bool capture_err) {
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(obj)) return obj;

    JS_DefinePropertyValueStr(ctx, obj, "pid", JS_NewInt32(ctx, pid), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "status", signal ? JS_NULL : JS_NewInt64(ctx, status), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "signal", signal ? JS_NewString(ctx, tjs_getsig(signal)) : JS_NULL, JS_PROP_C_W_E);

    JSValue stdout_val = capture_out ? spawn_sync_new_buffer(ctx, out) : JS_NULL;
    JSValue stderr_val = capture_err ? spawn_sync_new_buffer(ctx, err) : JS_NULL;
    JSValue output = JS_NewArray(ctx);
    if (JS_IsException(stdout_val) || JS_IsException(stderr_val) || JS_IsException(output)) {
        JS_FreeValue(ctx, stdout_val);
        JS_FreeValue(ctx, stderr_val);
        JS_FreeValue(ctx, output);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    JS_SetPropertyUint32(ctx, output, 0, JS_NULL);
    JS_SetPropertyUint32(ctx, output, 1, JS_DupValue(ctx, stdout_val));
    JS_SetPropertyUint32(ctx, output, 2, JS_DupValue(ctx, stderr_val));
    JS_DefinePropertyValueStr(ctx, obj, "stdout", stdout_val, JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "stderr", stderr_val, JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "output", output, JS_PROP_C_W_E);
    return obj;
}

static char **spawn_sync_parse_call_args(JSContext *ctx, int argc, JSValue *argv, JSValue *opts_out) {
    *opts_out = argc >= 2 ? argv[1] : JS_UNDEFINED;
    if (argc >= 2 && JS_IsArray(argv[1])) {
        if (!JS_IsString(argv[0])) {
            JS_ThrowTypeError(ctx, "spawnSync(command, args?, options?): command must be a string");
            return NULL;
        }
        JSValue full = JS_NewArray(ctx);
        if (JS_IsException(full)) return NULL;
        JS_SetPropertyUint32(ctx, full, 0, JS_DupValue(ctx, argv[0]));
        JSValue lv = JS_GetPropertyStr(ctx, argv[1], "length");
        uint64_t len = 0;
        if (JS_ToIndex(ctx, &len, lv)) { JS_FreeValue(ctx, lv); JS_FreeValue(ctx, full); return NULL; }
        JS_FreeValue(ctx, lv);
        for (uint64_t i = 0; i < len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, argv[1], (uint32_t)i);
            if (JS_IsException(item)) { JS_FreeValue(ctx, full); return NULL; }
            JS_SetPropertyUint32(ctx, full, (uint32_t)i + 1, item);
        }
        char **args = tjs__parse_args(ctx, full);
        JS_FreeValue(ctx, full);
        *opts_out = argc >= 3 ? argv[2] : JS_UNDEFINED;
        return args;
    }
    return tjs__parse_args(ctx, argv[0]);
}

static int spawn_sync_get_input(JSContext *ctx, JSValue opts, uint8_t **data, size_t *len) {
    *data = NULL;
    *len = 0;
    if (!JS_IsObject(opts)) return 0;
    JSValue v = JS_GetPropertyStr(ctx, opts, "input");
    if (JS_IsUndefined(v) || JS_IsNull(v)) { JS_FreeValue(ctx, v); return 0; }
    const uint8_t *src = NULL;
    if (JS_IsString(v)) {
        src = (const uint8_t *)JS_ToCStringLen(ctx, len, v);
        if (!src) { JS_FreeValue(ctx, v); return -1; }
        *data = malloc(*len);
        if (*len && *data) memcpy(*data, src, *len);
        JS_FreeCString(ctx, (const char *)src);
        JS_FreeValue(ctx, v);
        return (*len == 0 || *data) ? 1 : -1;
    }
    src = JS_GetAnyBuffer(ctx, len, v);
    if (src) {
        *data = malloc(*len);
        if (*len && *data) memcpy(*data, src, *len);
    }
    JS_FreeValue(ctx, v);
    return (src && (*len == 0 || *data)) ? 1 : -1;
}

static void spawn_sync_free_input(uint8_t *data) {
    if (data) free(data);
}

#ifndef _WIN32
static void spawn_sync_set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags != -1) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void spawn_sync_set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static JSValue tjs_spawn_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "spawnSync: expected command or argv array");

    JSValue opts;
    char **args = spawn_sync_parse_call_args(ctx, argc, argv, &opts);
    if (!args) return JS_EXCEPTION;
    if (!args[0]) { tjs__free_args(ctx, args); return JS_ThrowTypeError(ctx, "spawnSync: empty argv"); }

    uint8_t *input = NULL;
    size_t input_len = 0, input_off = 0;
    int input_kind = spawn_sync_get_input(ctx, opts, &input, &input_len);
    if (input_kind < 0) { tjs__free_args(ctx, args); return JS_ThrowTypeError(ctx, "input must be a string or buffer"); }

    const char *stdin_mode = input_len > 0 ? "pipe" : spawn_sync_stdio_mode(ctx, opts, "stdin", "pipe");
    const char *stdout_mode = spawn_sync_stdio_mode(ctx, opts, "stdout", "pipe");
    const char *stderr_mode = spawn_sync_stdio_mode(ctx, opts, "stderr", "pipe");
    bool cap_out = strcmp(stdout_mode, "pipe") == 0;
    bool cap_err = strcmp(stderr_mode, "pipe") == 0;
    bool pipe_in = strcmp(stdin_mode, "pipe") == 0;

    int in_pipe[2] = { -1, -1 }, out_pipe[2] = { -1, -1 }, err_pipe[2] = { -1, -1 };
    JSValue ret = JS_EXCEPTION;
    TJSSpawnSyncBuf out = { 0 }, err = { 0 };
    char **env_arr = NULL;
    char *cwd = NULL;
    bool clear_env = bool_prop(ctx, opts, "clearEnv");

    if (pipe_in && pipe(in_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
    if (cap_out && pipe(out_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
    if (cap_err && pipe(err_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }

    for (int i = 0; i < 2; i++) {
        if (in_pipe[i] != -1) spawn_sync_set_cloexec(in_pipe[i]);
        if (out_pipe[i] != -1) spawn_sync_set_cloexec(out_pipe[i]);
        if (err_pipe[i] != -1) spawn_sync_set_cloexec(err_pipe[i]);
    }

    if (JS_IsObject(opts)) {
        JSValue v = JS_GetPropertyStr(ctx, opts, "env");
        if (JS_IsObject(v)) env_arr = parse_env_obj(ctx, v);
        JS_FreeValue(ctx, v);
        if (clear_env && !env_arr) {
            env_arr = empty_env(ctx);
            if (!env_arr) goto cleanup;
        }
        v = JS_GetPropertyStr(ctx, opts, "cwd");
        if (JS_IsString(v)) {
            const char *s = JS_ToCString(ctx, v);
            if (!s) { JS_FreeValue(ctx, v); goto cleanup; }
            cwd = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
        }
        JS_FreeValue(ctx, v);
    }

    pid_t pid = fork();
    if (pid < 0) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }

    if (pid == 0) {
        if (pipe_in) dup2(in_pipe[0], STDIN_FILENO);
        else if (!strcmp(stdin_mode, "ignore")) {
            int fd = open("/dev/null", O_RDONLY); if (fd >= 0) { dup2(fd, STDIN_FILENO); if (fd > STDERR_FILENO) close(fd); }
        }
        if (cap_out) dup2(out_pipe[1], STDOUT_FILENO);
        else if (!strcmp(stdout_mode, "ignore")) {
            int fd = open("/dev/null", O_WRONLY); if (fd >= 0) { dup2(fd, STDOUT_FILENO); if (fd > STDERR_FILENO) close(fd); }
        }
        if (cap_err) dup2(err_pipe[1], STDERR_FILENO);
        else if (!strcmp(stderr_mode, "ignore")) {
            int fd = open("/dev/null", O_WRONLY); if (fd >= 0) { dup2(fd, STDERR_FILENO); if (fd > STDERR_FILENO) close(fd); }
        }
        if (in_pipe[0] != -1) close(in_pipe[0]);
        if (in_pipe[1] != -1) close(in_pipe[1]);
        if (out_pipe[0] != -1) close(out_pipe[0]);
        if (out_pipe[1] != -1) close(out_pipe[1]);
        if (err_pipe[0] != -1) close(err_pipe[0]);
        if (err_pipe[1] != -1) close(err_pipe[1]);
        if (cwd && chdir(cwd) < 0) _exit(127);
        if (clear_env) environ = NULL;
        if (env_arr) {
            for (int i = 0; env_arr[i]; i++) {
                char *eq = strchr(env_arr[i], '=');
                if (eq) { *eq = '\0'; setenv(env_arr[i], eq + 1, 1); *eq = '='; }
            }
        }
        execvp(args[0], args);
        _exit(127);
    }

    if (in_pipe[0] != -1) { close(in_pipe[0]); in_pipe[0] = -1; }
    if (out_pipe[1] != -1) { close(out_pipe[1]); out_pipe[1] = -1; }
    if (err_pipe[1] != -1) { close(err_pipe[1]); err_pipe[1] = -1; }
    if (in_pipe[1] != -1) spawn_sync_set_nonblock(in_pipe[1]);
    if (out_pipe[0] != -1) spawn_sync_set_nonblock(out_pipe[0]);
    if (err_pipe[0] != -1) spawn_sync_set_nonblock(err_pipe[0]);

    bool child_done = false;
    int wait_status = 0;
    while (out_pipe[0] != -1 || err_pipe[0] != -1 || in_pipe[1] != -1 || !child_done) {
        if (!child_done) {
            pid_t wr = waitpid(pid, &wait_status, WNOHANG);
            if (wr == pid) child_done = true;
            else if (wr < 0 && errno != EINTR) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
        }

        if (in_pipe[1] != -1 && input_off >= input_len) { close(in_pipe[1]); in_pipe[1] = -1; }
        if (child_done && out_pipe[0] == -1 && err_pipe[0] == -1 && in_pipe[1] == -1) break;

        fd_set rfds, wfds;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        int maxfd = -1;
        if (out_pipe[0] != -1) { FD_SET(out_pipe[0], &rfds); if (out_pipe[0] > maxfd) maxfd = out_pipe[0]; }
        if (err_pipe[0] != -1) { FD_SET(err_pipe[0], &rfds); if (err_pipe[0] > maxfd) maxfd = err_pipe[0]; }
        if (in_pipe[1] != -1) { FD_SET(in_pipe[1], &wfds); if (in_pipe[1] > maxfd) maxfd = in_pipe[1]; }
        if (maxfd < 0) {
            if (!child_done) {
                pid_t wr;
                do { wr = waitpid(pid, &wait_status, 0); } while (wr < 0 && errno == EINTR);
                if (wr == pid) child_done = true;
                else { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
            }
            continue;
        }
        int sr;
        do { sr = select(maxfd + 1, &rfds, &wfds, NULL, NULL); } while (sr < 0 && errno == EINTR);
        if (sr < 0) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }

        uint8_t buf[8192];
        if (out_pipe[0] != -1 && FD_ISSET(out_pipe[0], &rfds)) {
            ssize_t n = read(out_pipe[0], buf, sizeof(buf));
            if (n > 0) { if (spawn_sync_buf_append(&out, buf, (size_t)n)) { ret = JS_ThrowOutOfMemory(ctx); goto cleanup; } }
            else if (n == 0 || errno != EAGAIN) { close(out_pipe[0]); out_pipe[0] = -1; }
        }
        if (err_pipe[0] != -1 && FD_ISSET(err_pipe[0], &rfds)) {
            ssize_t n = read(err_pipe[0], buf, sizeof(buf));
            if (n > 0) { if (spawn_sync_buf_append(&err, buf, (size_t)n)) { ret = JS_ThrowOutOfMemory(ctx); goto cleanup; } }
            else if (n == 0 || errno != EAGAIN) { close(err_pipe[0]); err_pipe[0] = -1; }
        }
        if (in_pipe[1] != -1 && FD_ISSET(in_pipe[1], &wfds)) {
            size_t remain = input_len - input_off;
            ssize_t n = remain ? write(in_pipe[1], input + input_off, remain > 8192 ? 8192 : remain) : 0;
            if (n > 0) input_off += (size_t)n;
            else if (n == 0 || (errno != EAGAIN && errno != EPIPE)) { close(in_pipe[1]); in_pipe[1] = -1; }
            else if (errno == EPIPE) { close(in_pipe[1]); in_pipe[1] = -1; }
        }
    }

    int64_t es = 0;
    int ts = 0;
    if (WIFEXITED(wait_status)) es = WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status)) { ts = WTERMSIG(wait_status); es = 128 + ts; }
    ret = spawn_sync_make_result(ctx, (int)pid, es, ts, &out, &err, cap_out, cap_err);

cleanup:
    if (in_pipe[0] != -1) close(in_pipe[0]);
    if (in_pipe[1] != -1) close(in_pipe[1]);
    if (out_pipe[0] != -1) close(out_pipe[0]);
    if (out_pipe[1] != -1) close(out_pipe[1]);
    if (err_pipe[0] != -1) close(err_pipe[0]);
    if (err_pipe[1] != -1) close(err_pipe[1]);
    spawn_sync_buf_free(&out);
    spawn_sync_buf_free(&err);
    spawn_sync_free_input(input);
    free_env(ctx, env_arr);
    if (cwd) js_free(ctx, cwd);
    tjs__free_args(ctx, args);
    return ret;
}
#endif /* !_WIN32 */

#ifdef _WIN32
typedef struct {
    HANDLE pipe;
    TJSSpawnSyncBuf *buf;
} TJSWinReadThread;

typedef struct {
    HANDLE pipe;
    const uint8_t *data;
    size_t len;
} TJSWinWriteThread;

static DWORD WINAPI spawn_sync_win_read_thread(LPVOID arg) {
    TJSWinReadThread *r = arg;
    uint8_t buf[8192];
    DWORD n;
    while (ReadFile(r->pipe, buf, sizeof(buf), &n, NULL) && n > 0) {
        if (spawn_sync_buf_append(r->buf, buf, n)) break;
    }
    return 0;
}

static DWORD WINAPI spawn_sync_win_write_thread(LPVOID arg) {
    TJSWinWriteThread *w = arg;
    size_t off = 0;
    while (off < w->len) {
        DWORD chunk = (DWORD)((w->len - off) > 8192 ? 8192 : (w->len - off));
        DWORD n = 0;
        if (!WriteFile(w->pipe, w->data + off, chunk, &n, NULL) || n == 0) break;
        off += n;
    }
    CloseHandle(w->pipe);
    w->pipe = INVALID_HANDLE_VALUE;
    return 0;
}

static WCHAR *spawn_sync_utf8_to_wide(JSContext *ctx, const char *s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (len <= 0) return NULL;
    WCHAR *w = js_malloc(ctx, sizeof(WCHAR) * len);
    if (!w) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len)) { js_free(ctx, w); return NULL; }
    return w;
}

/* CreateProcess does not search PATH when lpApplicationName is supplied.
 * Resolve the PTY executable first so argv[0] can remain independent from the
 * executable path, matching the Unix spawn contract. */
static WCHAR *spawn_sync_resolve_win_app(JSContext *ctx, const WCHAR *app) {
    DWORD capacity = MAX_PATH;
    for (;;) {
        WCHAR *resolved = js_malloc(ctx, sizeof(WCHAR) * capacity);
        if (!resolved) return NULL;
        DWORD length = SearchPathW(NULL, app, L".exe", capacity, resolved, NULL);
        if (length == 0) {
            js_free(ctx, resolved);
            return NULL;
        }
        if (length < capacity) return resolved;
        js_free(ctx, resolved);
        if (length >= UINT_MAX - 1) return NULL;
        capacity = length + 1;
    }
}

static char *spawn_sync_quote_win_arg(JSContext *ctx, const char *arg) {
    bool quote = *arg == '\0';
    for (const char *cursor = arg; *cursor; cursor++) {
        if (*cursor == ' ' || *cursor == '\t' || *cursor == '"') {
            quote = true;
            break;
        }
    }
    if (!quote) return js_strdup(ctx, arg);

    size_t arg_len = strlen(arg);
    if (arg_len > (SIZE_MAX - 3) / 2) return NULL;
    char *out = js_malloc(ctx, arg_len * 2 + 3);
    if (!out) return NULL;

    char *write = out;
    const char *cursor = arg;
    *write++ = '"';
    while (*cursor) {
        size_t backslashes = 0;
        while (*cursor == '\\') {
            backslashes++;
            cursor++;
        }

        size_t escaped = backslashes;
        if (*cursor == '"') escaped = backslashes * 2 + 1;
        else if (*cursor == '\0') escaped = backslashes * 2;
        for (size_t index = 0; index < escaped; index++) *write++ = '\\';

        if (*cursor == '\0') break;
        *write++ = *cursor++;
    }
    *write++ = '"';
    *write = '\0';
    return out;
}

static WCHAR *spawn_sync_build_win_cmdline(JSContext *ctx, char **args) {
    size_t total = 0;
    char **quoted = NULL;
    int count = 0;
    while (args[count]) count++;
    quoted = js_mallocz(ctx, sizeof(char *) * (count + 1));
    if (!quoted) return NULL;
    for (int i = 0; i < count; i++) {
        quoted[i] = spawn_sync_quote_win_arg(ctx, args[i]);
        if (!quoted[i]) goto fail;
        total += strlen(quoted[i]) + (i ? 1 : 0);
    }
    char *cmd = js_malloc(ctx, total + 1);
    if (!cmd) goto fail;
    cmd[0] = '\0';
    for (int i = 0; i < count; i++) {
        if (i) strcat(cmd, " ");
        strcat(cmd, quoted[i]);
    }
    WCHAR *wcmd = spawn_sync_utf8_to_wide(ctx, cmd);
    js_free(ctx, cmd);
    for (int i = 0; i < count; i++) js_free(ctx, quoted[i]);
    js_free(ctx, quoted);
    return wcmd;
fail:
    if (quoted) { for (int i = 0; i < count; i++) js_free(ctx, quoted[i]); js_free(ctx, quoted); }
    return NULL;
}

static WCHAR *spawn_sync_build_win_env(JSContext *ctx, char **env) {
    if (!env) return NULL;
    int total = 2;
    for (int i = 0; env[i]; i++) {
        int len = MultiByteToWideChar(CP_UTF8, 0, env[i], -1, NULL, 0);
        if (len <= 0) return NULL;
        if (total > INT_MAX - len) return NULL;
        total += len;
    }
    WCHAR *wenv = js_mallocz(ctx, sizeof(WCHAR) * total);
    if (!wenv) return NULL;
    WCHAR *p = wenv;
    for (int i = 0; env[i]; i++) {
        int len = MultiByteToWideChar(CP_UTF8, 0, env[i], -1, p, total - (int)(p - wenv));
        if (len <= 0) { js_free(ctx, wenv); return NULL; }
        p += len;
    }
    *p = L'\0';
    return wenv;
}

static JSValue tjs_spawn_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "spawnSync: expected command or argv array");

    JSValue opts;
    char **args = spawn_sync_parse_call_args(ctx, argc, argv, &opts);
    if (!args) return JS_EXCEPTION;
    if (!args[0]) { tjs__free_args(ctx, args); return JS_ThrowTypeError(ctx, "spawnSync: empty argv"); }

    uint8_t *input = NULL;
    size_t input_len = 0;
    int input_kind = spawn_sync_get_input(ctx, opts, &input, &input_len);
    if (input_kind < 0) { tjs__free_args(ctx, args); return JS_ThrowTypeError(ctx, "input must be a string or buffer"); }

    const char *stdin_mode = input_len > 0 ? "pipe" : spawn_sync_stdio_mode(ctx, opts, "stdin", "pipe");
    const char *stdout_mode = spawn_sync_stdio_mode(ctx, opts, "stdout", "pipe");
    const char *stderr_mode = spawn_sync_stdio_mode(ctx, opts, "stderr", "pipe");
    bool pipe_in = strcmp(stdin_mode, "pipe") == 0;
    bool cap_out = strcmp(stdout_mode, "pipe") == 0;
    bool cap_err = strcmp(stderr_mode, "pipe") == 0;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, true };
    HANDLE in_r = INVALID_HANDLE_VALUE, in_w = INVALID_HANDLE_VALUE;
    HANDLE out_r = INVALID_HANDLE_VALUE, out_w = INVALID_HANDLE_VALUE;
    HANDLE err_r = INVALID_HANDLE_VALUE, err_w = INVALID_HANDLE_VALUE;
    HANDLE out_thread = NULL, err_thread = NULL, in_thread = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOW si = { 0 };
    TJSSpawnSyncBuf out = { 0 }, err = { 0 };
    TJSWinReadThread out_arg = { 0 }, err_arg = { 0 };
    TJSWinWriteThread in_arg = { 0 };
    WCHAR *wcmd = NULL, *wcwd = NULL, *wenv = NULL;
    char **env_arr = NULL;
    JSValue ret = JS_EXCEPTION;
    bool spawned = false;
    bool clear_env = bool_prop(ctx, opts, "clearEnv");

    if (pipe_in && !CreatePipe(&in_r, &in_w, &sa, 0)) { JS_ThrowInternalError(ctx, "CreatePipe(stdin) failed: %lu", GetLastError()); goto cleanup; }
    if (cap_out && !CreatePipe(&out_r, &out_w, &sa, 0)) { JS_ThrowInternalError(ctx, "CreatePipe(stdout) failed: %lu", GetLastError()); goto cleanup; }
    if (cap_err && !CreatePipe(&err_r, &err_w, &sa, 0)) { JS_ThrowInternalError(ctx, "CreatePipe(stderr) failed: %lu", GetLastError()); goto cleanup; }
    if (in_w != INVALID_HANDLE_VALUE) SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    if (out_r != INVALID_HANDLE_VALUE) SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    if (err_r != INVALID_HANDLE_VALUE) SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);

    wcmd = spawn_sync_build_win_cmdline(ctx, args);
    if (!wcmd) { JS_ThrowOutOfMemory(ctx); goto cleanup; }

    if (JS_IsObject(opts)) {
        JSValue v = JS_GetPropertyStr(ctx, opts, "cwd");
        if (JS_IsString(v)) {
            const char *s = JS_ToCString(ctx, v);
            if (!s) { JS_FreeValue(ctx, v); goto cleanup; }
            wcwd = spawn_sync_utf8_to_wide(ctx, s);
            JS_FreeCString(ctx, s);
            if (!wcwd) { JS_FreeValue(ctx, v); JS_ThrowOutOfMemory(ctx); goto cleanup; }
        }
        JS_FreeValue(ctx, v);
        v = JS_GetPropertyStr(ctx, opts, "env");
        if (JS_IsObject(v)) {
            env_arr = parse_env_obj(ctx, v);
            wenv = spawn_sync_build_win_env(ctx, env_arr);
            if (env_arr && !wenv) { JS_FreeValue(ctx, v); JS_ThrowOutOfMemory(ctx); goto cleanup; }
        }
        JS_FreeValue(ctx, v);
        if (clear_env && !env_arr) {
            env_arr = empty_env(ctx);
            if (!env_arr) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
            wenv = spawn_sync_build_win_env(ctx, env_arr);
            if (!wenv) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
        }
    }

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = pipe_in ? in_r : (!strcmp(stdin_mode, "ignore") ? INVALID_HANDLE_VALUE : GetStdHandle(STD_INPUT_HANDLE));
    si.hStdOutput = cap_out ? out_w : (!strcmp(stdout_mode, "ignore") ? INVALID_HANDLE_VALUE : GetStdHandle(STD_OUTPUT_HANDLE));
    si.hStdError = cap_err ? err_w : (!strcmp(stderr_mode, "ignore") ? INVALID_HANDLE_VALUE : GetStdHandle(STD_ERROR_HANDLE));

    DWORD flags = CREATE_UNICODE_ENVIRONMENT;
    if (JS_IsObject(opts)) {
        JSValue bg = JS_GetPropertyStr(ctx, opts, "background");
        if (JS_IsEqual(ctx, bg, JS_TRUE)) flags |= CREATE_NO_WINDOW;
        JS_FreeValue(ctx, bg);
    }

    if (!CreateProcessW(NULL, wcmd, NULL, NULL, true, flags, wenv, wcwd, &si, &pi)) {
        JS_ThrowInternalError(ctx, "CreateProcess failed: %lu", GetLastError());
        goto cleanup;
    }
    spawned = true;
    CloseHandle(pi.hThread); pi.hThread = NULL;

    if (in_r != INVALID_HANDLE_VALUE) { CloseHandle(in_r); in_r = INVALID_HANDLE_VALUE; }
    if (out_w != INVALID_HANDLE_VALUE) { CloseHandle(out_w); out_w = INVALID_HANDLE_VALUE; }
    if (err_w != INVALID_HANDLE_VALUE) { CloseHandle(err_w); err_w = INVALID_HANDLE_VALUE; }

    if (cap_out) {
        out_arg.pipe = out_r; out_arg.buf = &out;
        out_thread = CreateThread(NULL, 0, spawn_sync_win_read_thread, &out_arg, 0, NULL);
        if (!out_thread) { JS_ThrowInternalError(ctx, "CreateThread(stdout) failed: %lu", GetLastError()); goto cleanup; }
    }
    if (cap_err) {
        err_arg.pipe = err_r; err_arg.buf = &err;
        err_thread = CreateThread(NULL, 0, spawn_sync_win_read_thread, &err_arg, 0, NULL);
        if (!err_thread) { JS_ThrowInternalError(ctx, "CreateThread(stderr) failed: %lu", GetLastError()); goto cleanup; }
    }
    if (pipe_in) {
        in_arg.pipe = in_w; in_arg.data = input; in_arg.len = input_len;
        in_thread = CreateThread(NULL, 0, spawn_sync_win_write_thread, &in_arg, 0, NULL);
        if (!in_thread) { JS_ThrowInternalError(ctx, "CreateThread(stdin) failed: %lu", GetLastError()); goto cleanup; }
        in_w = INVALID_HANDLE_VALUE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    if (in_thread) WaitForSingleObject(in_thread, INFINITE);
    if (out_thread) WaitForSingleObject(out_thread, INFINITE);
    if (err_thread) WaitForSingleObject(err_thread, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    ret = spawn_sync_make_result(ctx, (int)pi.dwProcessId, (int64_t)code, 0, &out, &err, cap_out, cap_err);

cleanup:
    if (spawned && JS_IsException(ret) && pi.hProcess) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }
    if (in_thread) WaitForSingleObject(in_thread, INFINITE);
    if (out_thread) WaitForSingleObject(out_thread, INFINITE);
    if (err_thread) WaitForSingleObject(err_thread, INFINITE);
    if (in_r != INVALID_HANDLE_VALUE) CloseHandle(in_r);
    if (in_w != INVALID_HANDLE_VALUE) CloseHandle(in_w);
    if (out_r != INVALID_HANDLE_VALUE) CloseHandle(out_r);
    if (out_w != INVALID_HANDLE_VALUE) CloseHandle(out_w);
    if (err_r != INVALID_HANDLE_VALUE) CloseHandle(err_r);
    if (err_w != INVALID_HANDLE_VALUE) CloseHandle(err_w);
    if (out_thread) CloseHandle(out_thread);
    if (err_thread) CloseHandle(err_thread);
    if (in_thread) CloseHandle(in_thread);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (wcmd) js_free(ctx, wcmd);
    if (wcwd) js_free(ctx, wcwd);
    if (wenv) js_free(ctx, wenv);
    free_env(ctx, env_arr);
    spawn_sync_buf_free(&out);
    spawn_sync_buf_free(&err);
    spawn_sync_free_input(input);
    tjs__free_args(ctx, args);
    return ret;
}
#endif /* _WIN32 */

static void uv__exit_cb(uv_process_t *handle, int64_t exit_status, int term_signal) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    process_finish(p, exit_status, term_signal);
}


/* ============================================================
 * spawn(args, opts?) — entry point
 * ============================================================ */
static JSValue tjs_spawn(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "spawn: expected at least 1 argument");

    JSValue obj = JS_NewObjectClass(ctx, tjs_process_class_id);
    if (JS_IsException(obj)) return obj;

    TJSProcess *p = tjs__mallocz(sizeof(*p));
    if (!p) { JS_FreeValue(ctx, obj); return JS_ThrowOutOfMemory(ctx); }

    p->ctx           = ctx;
    p->process.data  = p;
    p->obj           = JS_UNDEFINED;
    p->stdio[0]      = JS_UNDEFINED;
    p->stdio[1]      = JS_UNDEFINED;
    p->stdio[2]      = JS_UNDEFINED;
    p->stdio_extra   = JS_UNDEFINED;
    p->ipc_pipe      = JS_UNDEFINED;
    p->pty_readable  = JS_UNDEFINED;
    p->pty_writable  = JS_UNDEFINED;
    TJS_ClearPromise(ctx, &p->status.result);
#ifndef _WIN32
    p->master_fd = -1;
#else
    p->hpc             = NULL;
    p->pty_proc_handle = NULL;
#endif

    /* ---- PTY mode ---- */
    bool use_pty = false;
    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue v = JS_GetPropertyStr(ctx, argv[1], "pty");
        use_pty = JS_ToBool(ctx, v) == 1;
        JS_FreeValue(ctx, v);
    }

    if (use_pty) {
        p->pty_mode = true;
        JSValue opts = argc >= 2 ? argv[1] : JS_UNDEFINED;

        const char *name = NULL, *cwd = NULL;
        char **env_arr = NULL, **argv_arr = NULL;
        int argv_len = 0;
        int cols, rows;
        bool clear_env = bool_prop(ctx, opts, "clearEnv");
        parse_winsize(ctx, opts, &cols, &rows);
        p->pty_cols = cols; p->pty_rows = rows;

        if (JS_IsObject(opts)) {
            JSValue v;
            v = JS_GetPropertyStr(ctx, opts, "name");
            if (JS_IsString(v)) name = JS_ToCString(ctx, v);
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, opts, "cwd");
            if (JS_IsString(v)) cwd = JS_ToCString(ctx, v);
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, opts, "env");
            if (JS_IsObject(v)) env_arr = parse_env_obj(ctx, v);
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, opts, "argv");
            if (JS_IsArray(v)) argv_arr = parse_argv_arr(ctx, v, &argv_len);
            JS_FreeValue(ctx, v);
        }

        JSValue err = JS_UNDEFINED;
        if (clear_env && !env_arr) {
            env_arr = empty_env(ctx);
            if (!env_arr) err = JS_ThrowOutOfMemory(ctx);
        }
        if (!JS_IsException(err)) {
#ifdef _WIN32
            err = pty_win_spawn(p, ctx, name, cwd, env_arr, argv_arr, argv_len, cols, rows);
#else
            err = pty_unix_spawn(p, ctx, name, cwd, env_arr, argv_arr, argv_len, cols, rows, clear_env);
#endif
        }
        if (name) JS_FreeCString(ctx, name);
        if (cwd)  JS_FreeCString(ctx, cwd);
        free_env(ctx, env_arr);
        free_str_arr(ctx, argv_arr, argv_len);

        if (JS_IsException(err)) {
            tjs__free(p); JS_FreeValue(ctx, obj);
            return err;
        }

        int r = uv_timer_init(tjs_get_loop(ctx), &p->pty_waiter);
        if (r != 0) {
            JSValue init_err = tjs_throw_errno(ctx, r);
#ifdef _WIN32
            TerminateProcess(p->pty_proc_handle, 1);
            WaitForSingleObject(p->pty_proc_handle, INFINITE);
            if (p->hpc && pClosePseudoConsole) pClosePseudoConsole(p->hpc);
            if (p->pty_proc_handle) CloseHandle(p->pty_proc_handle);
#else
            kill(p->pty_pid, SIGKILL);
            while (waitpid(p->pty_pid, NULL, 0) < 0 && errno == EINTR) {}
#endif
            JS_FreeValue(ctx, p->pty_readable);
            JS_FreeValue(ctx, p->pty_writable);
            tjs__free(p);
            JS_FreeValue(ctx, obj);
            return init_err;
        }
        p->handle_initialized = true;
        p->pty_waiter.data = p;
        CHECK_EQ(uv_timer_start(&p->pty_waiter, uv__pty_wait_cb, 0, 10), 0);

        JS_SetOpaque(obj, p);
        p->obj = JS_DupValue(ctx, obj);
        return obj;
    }

    /* ---- Normal mode ---- */
    JSValue ret = JS_EXCEPTION;
    uv_process_options_t options;
    memset(&options, 0, sizeof(options));
    uv_stdio_container_t *stdio_heap = NULL;
    int ipc_child_fd = -1;
#ifdef _WIN32
    options.flags = UV_PROCESS_WINDOWS_FILE_PATH_EXACT_NAME;
#endif
    uv_stdio_container_t stdio[3];
    stdio[0].flags = UV_INHERIT_FD; stdio[0].data.fd = STDIN_FILENO;
    stdio[1].flags = UV_INHERIT_FD; stdio[1].data.fd = STDOUT_FILENO;
    stdio[2].flags = UV_INHERIT_FD; stdio[2].data.fd = STDERR_FILENO;
    options.stdio_count = 3;
    options.stdio = stdio;

    options.args = tjs__parse_args(ctx, argv[0]);
    if (!options.args) goto fail;
    options.file = options.args[0];

    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue arg1 = argv[1];

        JSValue js_env = JS_GetPropertyStr(ctx, arg1, "env");
        if (JS_IsObject(js_env)) options.env = parse_env_obj(ctx, js_env);
        JS_FreeValue(ctx, js_env);
        if (bool_prop(ctx, arg1, "clearEnv") && !options.env) {
            options.env = empty_env(ctx);
            if (!options.env) goto fail;
        }

        JSValue js_cwd = JS_GetPropertyStr(ctx, arg1, "cwd");
        if (!JS_IsUndefined(js_cwd) && !JS_IsException(js_cwd)) {
            const char *s = JS_ToCString(ctx, js_cwd);
            if (!s) { JS_FreeValue(ctx, js_cwd); goto fail; }
            options.cwd = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
        }
        JS_FreeValue(ctx, js_cwd);

        JSValue js_uid = JS_GetPropertyStr(ctx, arg1, "uid");
        if (!JS_IsUndefined(js_uid) && !JS_IsException(js_uid)) {
            uint32_t uid;
            if (JS_ToUint32(ctx, &uid, js_uid)) { JS_FreeValue(ctx, js_uid); goto fail; }
            options.uid = uid; options.flags |= UV_PROCESS_SETUID;
        }
        JS_FreeValue(ctx, js_uid);

        JSValue js_gid = JS_GetPropertyStr(ctx, arg1, "gid");
        if (!JS_IsUndefined(js_gid) && !JS_IsException(js_gid)) {
            uint32_t gid;
            if (JS_ToUint32(ctx, &gid, js_gid)) { JS_FreeValue(ctx, js_gid); goto fail; }
            options.gid = gid; options.flags |= UV_PROCESS_SETGID;
        }
        JS_FreeValue(ctx, js_gid);

        SETUP_STDIO(stdin,  0, UV_READABLE_PIPE, STDIN_FILENO);
        SETUP_STDIO(stdout, 1, UV_WRITABLE_PIPE, STDOUT_FILENO);
        SETUP_STDIO(stderr, 2, UV_WRITABLE_PIPE, STDERR_FILENO);

        JSValue js_stdio_extra = JS_GetPropertyStr(ctx, arg1, "stdioExtra");
        if (!JS_IsException(js_stdio_extra) && !JS_IsUndefined(js_stdio_extra)) {
            if (setup_extra_stdio(ctx, p, &options, stdio, &stdio_heap, js_stdio_extra) < 0) {
                JS_FreeValue(ctx, js_stdio_extra);
                goto fail;
            }
        }
        JS_FreeValue(ctx, js_stdio_extra);

        // Check for IPC option
        JSValue js_ipc = JS_GetPropertyStr(ctx, arg1, "ipc");
        if (JS_ToBool(ctx, js_ipc) || (JS_IsNumber(js_ipc) && JS_ToBool(ctx, js_ipc))) {
            uint32_t ipc_fd = 3;
            JSValue js_ipc_fd = JS_GetPropertyStr(ctx, arg1, "ipcFd");
            if (!JS_IsUndefined(js_ipc_fd) && !JS_IsException(js_ipc_fd)) {
                if (JS_ToUint32(ctx, &ipc_fd, js_ipc_fd) || ipc_fd > 255) {
                    JS_FreeValue(ctx, js_ipc_fd);
                    JS_FreeValue(ctx, js_ipc);
                    JS_ThrowRangeError(ctx, "ipcFd must be an integer between 0 and 255");
                    goto fail;
                }
            }
            JS_FreeValue(ctx, js_ipc_fd);

            // Create IPC pipe pair
            int ipc_fds[2];
#ifdef _WIN32
            if (_pipe(ipc_fds, 65536, _O_BINARY) != 0) {
                tjs_throw_errno(ctx, -1);
                JS_FreeValue(ctx, js_ipc);
                goto fail;
            }
#else
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, ipc_fds) != 0) {
                tjs_throw_errno(ctx, uv_translate_sys_error(errno));
                JS_FreeValue(ctx, js_ipc);
                goto fail;
            }
#endif
            // Store the read end in the parent process
            p->ipc_pipe = tjs_new_pipe(ctx);
            if (JS_IsException(p->ipc_pipe)) {
                close(ipc_fds[0]);
                close(ipc_fds[1]);
                p->ipc_pipe = JS_UNDEFINED;
                JS_FreeValue(ctx, js_ipc);
                goto fail;
            }
            uv_pipe_t *pipe = tjs_pipe_get_pipe(ctx, p->ipc_pipe);
            if (pipe) {
                uv_pipe_open(pipe, ipc_fds[0]);
            }

            // Add the peer endpoint to the child's requested stdio fd. Node's
            // child_process allows "ipc" at any stdio array index.
            ipc_child_fd = ipc_fds[1];
            if (ipc_fd < 3) {
                JS_FreeValue(ctx, p->stdio[ipc_fd]);
                p->stdio[ipc_fd] = JS_UNDEFINED;
                stdio[ipc_fd].flags = UV_INHERIT_FD;
                stdio[ipc_fd].data.fd = ipc_child_fd;
            } else {
                if (ensure_stdio_capacity(ctx, &options, stdio, &stdio_heap, (int)ipc_fd + 1) < 0) {
                    close(ipc_fds[1]);
                    ipc_child_fd = -1;
                    JS_ThrowOutOfMemory(ctx);
                    JS_FreeValue(ctx, js_ipc);
                    goto fail;
                }
                if (!JS_IsUndefined(p->stdio_extra)) {
                    JS_SetPropertyUint32(ctx, p->stdio_extra, ipc_fd, JS_NULL);
                }
                options.stdio[ipc_fd].flags = UV_INHERIT_FD;
                options.stdio[ipc_fd].data.fd = ipc_child_fd;
            }

            // Store write fd info for cleanup
            // Note: we'll close it after spawn
        }
        JS_FreeValue(ctx, js_ipc);

        JSValue js_det = JS_GetPropertyStr(ctx, arg1, "detached");
        if (JS_IsEqual(ctx, js_det, JS_TRUE)) options.flags |= UV_PROCESS_DETACHED;
        JS_FreeValue(ctx, js_det);
#ifdef _WIN32
        JSValue js_bg = JS_GetPropertyStr(ctx, arg1, "background");
        if (JS_IsEqual(ctx, js_bg, JS_TRUE)) options.flags |= UV_PROCESS_WINDOWS_HIDE;
        JS_FreeValue(ctx, js_bg);
#endif
    }

    options.exit_cb = uv__exit_cb;
    int r = uv_spawn(tjs_get_loop(ctx), &p->process, &options);
    if (r != 0) { tjs_throw_errno(ctx, r); goto fail; }
    p->handle_initialized = true;

    // Close child endpoint of IPC pipe in parent (child owns it now)
    if (ipc_child_fd >= 0) {
        close(ipc_child_fd);
        ipc_child_fd = -1;
    }

    JS_SetOpaque(obj, p);
    p->obj = JS_DupValue(ctx, obj);
    ret = obj;
    goto cleanup;

fail:
    if (ipc_child_fd >= 0) close(ipc_child_fd);
    for (int i = 0; i < 3; i++) { JS_FreeValue(ctx, p->stdio[i]); p->stdio[i] = JS_UNDEFINED; }
    JS_FreeValue(ctx, p->stdio_extra);
    p->stdio_extra = JS_UNDEFINED;
    JS_FreeValue(ctx, p->ipc_pipe);
    p->ipc_pipe = JS_UNDEFINED;
    tjs__free(p);
    JS_FreeValue(ctx, obj);
cleanup:
    tjs__free_args(ctx, options.args);
    free_env(ctx, (char **)options.env);
    if (options.cwd) js_free(ctx, (void *)options.cwd);
    if (stdio_heap) js_free(ctx, stdio_heap);
    return ret;
}
#undef SETUP_STDIO


/* ============================================================
 * Process methods
 * ============================================================ */

/* pid — works for both modes */
static JSValue tjs_process_pid_get(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    pid_t pid = p->pty_mode ? p->pty_pid : (pid_t)uv_process_get_pid(&p->process);
    return JS_NewInt32(ctx, pid);
}

/* stdin/stdout/stderr — normal mode only */
static JSValue tjs_process_stdio_get(JSContext *ctx, JSValue this_val, int magic) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    return JS_DupValue(ctx, p->stdio[magic]);
}

static JSValue tjs_process_stdio_extra_get(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (JS_IsUndefined(p->stdio_extra)) return JS_NULL;
    return JS_DupValue(ctx, p->stdio_extra);
}

/* IPC pipe getter */
static JSValue tjs_process_ipc_get(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (JS_IsUndefined(p->ipc_pipe)) return JS_NULL;
    return JS_DupValue(ctx, p->ipc_pipe);
}

/* readable / writable — PTY mode only */
static JSValue tjs_process_readable_get(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (!p->pty_mode) return JS_ThrowTypeError(ctx, "not a PTY process");
    return JS_DupValue(ctx, p->pty_readable);
}

static JSValue tjs_process_writable_get(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (!p->pty_mode) return JS_ThrowTypeError(ctx, "not a PTY process");
    return JS_DupValue(ctx, p->pty_writable);
}

/* kill(signal?) — works for both modes */
static JSValue tjs_process_kill(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (p->status.exited) return JS_UNDEFINED;
    int sig = parse_signal(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, SIGTERM);
    if (sig < 0) return JS_EXCEPTION;
    int r = p->pty_mode
        ? uv_kill((int)p->pty_pid, sig)
        : uv_process_kill(&p->process, sig);
    if (r != 0 && r != UV_ESRCH) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

/* wait() → Promise */
static JSValue tjs_process_wait(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (p->status.exited) {
        JSValue obj = make_exit_obj(ctx, p->status.exit_status, p->status.term_signal);
        return TJS_NewResolvedPromise(ctx, 1, &obj);
    }
    if (!JS_IsUndefined(p->status.result.p))
        return JS_DupValue(ctx, p->status.result.p);
    return TJS_InitPromise(ctx, &p->status.result);
}

/* waitSync() — blocking wait, works for both modes */
static JSValue tjs_process_wait_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (p->status.exited)
        return make_exit_obj(ctx, p->status.exit_status, p->status.term_signal);

    int64_t es = 0; int ts = 0;

    if (p->pty_mode) {
#ifdef _WIN32
        if (!p->pty_proc_handle)
            return JS_ThrowInternalError(ctx, "PTY process handle unavailable");
        if (WaitForSingleObject(p->pty_proc_handle, INFINITE) != WAIT_OBJECT_0)
            return JS_ThrowInternalError(ctx, "WaitForSingleObject failed");
        DWORD ws; GetExitCodeProcess(p->pty_proc_handle, &ws);
        es = (int64_t)ws; ts = 0;
#else
        int stat;
        pid_t result;
        do {
            result = waitpid(p->pty_pid, &stat, 0);
        } while (result < 0 && errno == EINTR);
        if (result < 0)
            return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
        if (decode_wait_status(stat, &es, &ts) < 0)
            return JS_ThrowInternalError(ctx, "unexpected waitpid status");
#endif
    } else {
#ifdef _WIN32
        if (WaitForSingleObject(p->process.process_handle, INFINITE) != WAIT_OBJECT_0)
            return JS_ThrowInternalError(ctx, "WaitForSingleObject failed");
        DWORD ws; GetExitCodeProcess(p->process.process_handle, &ws);
        es = (int64_t)ws; ts = 0;
#else
        pid_t pid = uv_process_get_pid(&p->process);
        int stat;
        pid_t result;
        do {
            result = waitpid(pid, &stat, 0);
        } while (result < 0 && errno == EINTR);
        if (result < 0)
            return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
        if (decode_wait_status(stat, &es, &ts) < 0)
            return JS_ThrowInternalError(ctx, "unexpected waitpid status");
#endif
    }

    JSValue result = make_exit_obj(ctx, es, ts);
    process_finish(p, es, ts);
    return result;
}

/* resize(cols, rows) — PTY only */
static JSValue tjs_process_resize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p || !p->pty_mode) return JS_ThrowTypeError(ctx, "not a PTY process");
    if (argc < 2) return JS_ThrowTypeError(ctx, "resize(cols, rows)");
    int32_t cols, rows;
    if (JS_ToInt32(ctx, &cols, argv[0]) || JS_ToInt32(ctx, &rows, argv[1]))
        return JS_EXCEPTION;

#ifdef _WIN32
    if (!p->hpc) return JS_ThrowInternalError(ctx, "ConPTY unavailable");
    COORD sz = { (SHORT)cols, (SHORT)rows };
    HRESULT hr = pResizePseudoConsole(p->hpc, sz);
    if (FAILED(hr)) return JS_ThrowInternalError(ctx, "ResizePseudoConsole failed: 0x%08lx", hr);
#else
    if (p->master_fd < 0) return JS_ThrowInternalError(ctx, "PTY closed");
    struct winsize ws; memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)cols; ws.ws_row = (unsigned short)rows;
    if (ioctl(p->master_fd, TIOCSWINSZ, &ws) == -1)
        return JS_ThrowInternalError(ctx, "TIOCSWINSZ: %s", strerror(errno));
#endif
    p->pty_cols = cols; p->pty_rows = rows;
    return JS_UNDEFINED;
}

/* get size() — PTY only */
static JSValue tjs_process_getwinsize(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p || !p->pty_mode) return JS_ThrowTypeError(ctx, "not a PTY process");

    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);

#ifdef _WIN32
    /* Windows: we track size ourselves (ConPTY has no query API). */
    JS_DefinePropertyValueStr(ctx, obj, "cols", JS_NewInt32(ctx, p->pty_cols), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "rows", JS_NewInt32(ctx, p->pty_rows), JS_PROP_C_W_E);
#else
    if (p->master_fd < 0) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowInternalError(ctx, "PTY closed");
    }
    struct winsize ws; memset(&ws, 0, sizeof(ws));
    if (ioctl(p->master_fd, TIOCGWINSZ, &ws) == -1) {
        JS_FreeValue(ctx, obj);
        return JS_ThrowInternalError(ctx, "TIOCGWINSZ: %s", strerror(errno));
    }
    JS_DefinePropertyValueStr(ctx, obj, "cols",   JS_NewInt32(ctx, ws.ws_col),    JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "rows",   JS_NewInt32(ctx, ws.ws_row),    JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "xpixel", JS_NewInt32(ctx, ws.ws_xpixel), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "ypixel", JS_NewInt32(ctx, ws.ws_ypixel), JS_PROP_C_W_E);
#endif
    return obj;
}


/* ============================================================
 * Global functions: kill(pid, signal?) and exec(args)
 * ============================================================ */

static JSValue tjs_kill(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0 || JS_IsUndefined(argv[0]))
        return JS_ThrowTypeError(ctx, "kill(pid, signal?)");
    int32_t pid;
    if (JS_ToInt32(ctx, &pid, argv[0])) return JS_EXCEPTION;
    int sig = parse_signal(ctx, argc >= 2 ? argv[1] : JS_UNDEFINED, SIGTERM);
    if (sig < 0) return JS_EXCEPTION;
    int r = uv_kill(pid, sig);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

static JSValue tjs_exec(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
#ifdef _WIN32
    return JS_ThrowInternalError(ctx, "exec() not supported on Windows");
#else
    if (argc == 0) return JS_ThrowTypeError(ctx, "exec(args)");
    char **args = NULL;
    JSValue arg0 = argv[0];

    if (JS_IsString(arg0)) {
        args = js_mallocz(ctx, sizeof(*args) * 2);
        if (!args) return JS_EXCEPTION;
        const char *s = JS_ToCString(ctx, arg0);
        if (!s) { js_free(ctx, args); return JS_EXCEPTION; }
        args[0] = js_strdup(ctx, s);
        JS_FreeCString(ctx, s);
        if (!args[0]) { js_free(ctx, args); return JS_EXCEPTION; }
    } else if (JS_IsArray(arg0)) {
        int len = 0;
        args = parse_argv_arr(ctx, arg0, &len);
        if (!args) return JS_EXCEPTION;
    } else {
        return JS_ThrowTypeError(ctx, "exec: expected string or array");
    }

    execvp(args[0], args);
    /* execvp only returns on error */
    JSValue err = tjs_throw_errno(ctx, uv_translate_sys_error(errno));
    for (int i = 0; args[i]; i++) js_free(ctx, args[i]);
    js_free(ctx, args);
    return err;
#endif
}


/* ============================================================
 * Proto / function tables + module init
 * ============================================================ */

/* clang-format off */
static const JSCFunctionListEntry tjs_process_proto_funcs[] = {
    JS_CGETSET_DEF("pid",         tjs_process_pid_get,      NULL),
    JS_CGETSET_MAGIC_DEF("stdin",  tjs_process_stdio_get,   NULL, 0),
    JS_CGETSET_MAGIC_DEF("stdout", tjs_process_stdio_get,   NULL, 1),
    JS_CGETSET_MAGIC_DEF("stderr", tjs_process_stdio_get,   NULL, 2),
    JS_CGETSET_DEF("stdioExtra",   tjs_process_stdio_extra_get, NULL),
    JS_CGETSET_DEF("ipc",         tjs_process_ipc_get,      NULL),
    JS_CGETSET_DEF("readable",    tjs_process_readable_get, NULL),
    JS_CGETSET_DEF("writable",    tjs_process_writable_get, NULL),
    JS_CGETSET_DEF("getwinsize",  tjs_process_getwinsize,   NULL),
    TJS_CFUNC_DEF("kill",         1, tjs_process_kill),
    TJS_CFUNC_DEF("wait",         0, tjs_process_wait),
    TJS_CFUNC_DEF("waitSync",     0, tjs_process_wait_sync),
    TJS_CFUNC_DEF("resize",       2, tjs_process_resize),
};

static const JSCFunctionListEntry tjs_process_funcs[] = {
    TJS_CFUNC_DEF("spawn",     2, tjs_spawn),
    TJS_CFUNC_DEF("spawnSync", 3, tjs_spawn_sync),
    TJS_CFUNC_DEF("kill",      2, tjs_kill),
    TJS_CFUNC_DEF("exec",      1, tjs_exec),
};
/* clang-format on */

void tjs__mod_process_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, &tjs_process_class_id);
    JS_NewClass(rt, tjs_process_class_id, &tjs_process_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_process_proto_funcs,
                               countof(tjs_process_proto_funcs));
    JS_SetClassProto(ctx, tjs_process_class_id, proto);
    JS_SetPropertyFunctionList(ctx, ns, tjs_process_funcs, countof(tjs_process_funcs));
}
