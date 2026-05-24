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

#include <string.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <io.h>
    #include <process.h>
    typedef int pid_t;
    #ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
    #define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE \
        ProcThreadAttributeValue(22, FALSE, TRUE, FALSE)
    typedef VOID *HPCON;
    #endif
    #define STDIN_FILENO  0
    #define STDOUT_FILENO 1
    #define STDERR_FILENO 2
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/ioctl.h>
    #include <termios.h>
    #include <errno.h>
    #if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <util.h>
    #elif defined(__FreeBSD__)
    #include <libutil.h>
    #else
    #include <pty.h>
    #endif
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
JSClassID tjs_process_class_id;

typedef struct {
    JSContext *ctx;
    JSValue    obj;        /* GC pin while process is live */
    bool pty_mode;
    bool closed;           /* normal mode: set by uv close callback */
    bool finalized;
    uv_process_t process;  /* normal mode only */
    JSValue stdio[3];      /* normal mode: stdin/stdout/stderr Pipe objects */
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
#ifdef _WIN32
    HPCON  hpc;
    HANDLE pty_proc_handle; /* kept for waitSync */
#else
    int master_fd;  /* ioctl target; libuv owns the fd via pty_readable */
#endif
} TJSProcess;


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
    if (!env) { js_free(ctx, ptab); return NULL; }
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
    js_free(ctx, ptab);
    return env;
}

static void free_env(JSContext *ctx, char **env) {
    if (!env) return;
    for (int i = 0; env[i]; i++) js_free(ctx, env[i]);
    js_free(ctx, env);
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

static void free_str_arr(JSContext *ctx, char **arr, int len) {
    if (!arr) return;
    for (int i = 0; i < len; i++) js_free(ctx, arr[i]);
    js_free(ctx, arr);
}

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

/* Only called in normal mode (process handle is valid). */
static void maybe_close(TJSProcess *p) {
    CHECK(!p->pty_mode);
    if (!uv_is_closing((uv_handle_t *)&p->process))
        uv_close((uv_handle_t *)&p->process, uv__proc_close_cb);
}

static void tjs_process_finalizer(JSRuntime *rt, JSValue val) {
    TJSProcess *p = JS_GetOpaque(val, tjs_process_class_id);
    if (!p) return;

    JS_FreeValueRT(rt, p->obj);
    TJS_FreePromiseRT(rt, &p->status.result);
    for (int i = 0; i < 3; i++) JS_FreeValueRT(rt, p->stdio[i]);

    if (p->pty_mode) {
        JS_FreeValueRT(rt, p->pty_readable);
        JS_FreeValueRT(rt, p->pty_writable);
#ifdef _WIN32
        if (p->hpc && pClosePseudoConsole) pClosePseudoConsole(p->hpc);
        if (p->pty_proc_handle) CloseHandle(p->pty_proc_handle);
#else
        /* master_fd is owned by libuv through pty_readable; do NOT close here */
#endif
        tjs__free(p);  /* no async uv handle — free directly */
    } else {
        p->finalized = true;
        if (p->closed) tjs__free(p);
        else maybe_close(p);
    }
}

static void tjs_process_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSProcess *p = JS_GetOpaque(val, tjs_process_class_id);
    if (!p) return;
    JS_MarkValue(rt, p->obj, mark_func);
    TJS_MarkPromise(rt, &p->status.result, mark_func);
    for (int i = 0; i < 3; i++) JS_MarkValue(rt, p->stdio[i], mark_func);
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
                               int cols, int rows) {
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
                              char **env_arr, int cols, int rows) {
    if (!load_conpty())
        return JS_ThrowInternalError(ctx, "ConPTY not supported on this Windows version");

    HANDLE hPipeIn  = INVALID_HANDLE_VALUE;
    HANDLE hPipeOut = INVALID_HANDLE_VALUE;
    HANDLE hConIn   = INVALID_HANDLE_VALUE;
    HANDLE hConOut  = INVALID_HANDLE_VALUE;
    HPCON  hPC      = NULL;
    HANDLE hProc    = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;
    WCHAR *wcmd = NULL, *wcwd = NULL;
    JSValue ret = JS_EXCEPTION;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
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
    { int wl = MultiByteToWideChar(CP_UTF8, 0, cmd, -1, NULL, 0);
      if (wl <= 0) { JS_ThrowInternalError(ctx, "MultiByteToWideChar(cmd) failed"); goto cleanup; }
      wcmd = (WCHAR *)malloc(wl * sizeof(WCHAR));
      if (!wcmd) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
      MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd, wl); }
    if (cwd) {
        int wl = MultiByteToWideChar(CP_UTF8, 0, cwd, -1, NULL, 0);
        if (wl <= 0) { JS_ThrowInternalError(ctx, "MultiByteToWideChar(cwd) failed"); goto cleanup; }
        wcwd = (WCHAR *)malloc(wl * sizeof(WCHAR));
        if (!wcwd) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
        MultiByteToWideChar(CP_UTF8, 0, cwd, -1, wcwd, wl);
    }

    STARTUPINFOEXW siEx = { 0 };
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siEx.lpAttributeList = attrList;
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT, NULL, wcwd,
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
    if (uv_pipe_open(pw, wfd) != 0) {
        _close(wfd); JS_FreeValue(ctx, write_obj);
        JS_ThrowInternalError(ctx, "uv_pipe_open (write) failed");
        goto cleanup;
    }
    hPipeIn = INVALID_HANDLE_VALUE; /* libuv owns the fd */

    /* Readable pipe: child stdout → ConPTY → JS */
    JSValue read_obj = tjs_new_pipe(ctx);
    if (JS_IsException(read_obj)) { JS_FreeValue(ctx, write_obj); goto cleanup; }
    uv_pipe_t *pr = tjs_pipe_get_pipe(ctx, read_obj);
    if (!pr) { JS_FreeValue(ctx, read_obj); JS_FreeValue(ctx, write_obj); goto cleanup; }
    int rfd = _open_osfhandle((intptr_t)hPipeOut, 0);
    if (uv_pipe_open(pr, rfd) != 0) {
        _close(rfd); JS_FreeValue(ctx, read_obj); JS_FreeValue(ctx, write_obj);
        JS_ThrowInternalError(ctx, "uv_pipe_open (read) failed");
        goto cleanup;
    }
    hPipeOut = INVALID_HANDLE_VALUE;

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
    free(wcmd); free(wcwd);
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

static void uv__exit_cb(uv_process_t *handle, int64_t exit_status, int term_signal) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    JSContext *ctx = p->ctx;

    p->status.exited      = true;
    p->status.exit_status = exit_status;
    p->status.term_signal = term_signal;

    if (!JS_IsUndefined(p->status.result.p)) {
        JSValue arg = make_exit_obj(ctx, exit_status, term_signal);
        TJS_SettlePromise(ctx, &p->status.result, false, 1, &arg);
        TJS_ClearPromise(ctx, &p->status.result);
    }

    JS_FreeValue(ctx, p->obj);
    p->obj = JS_UNDEFINED;
    maybe_close(p);
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

        JSValue err;
#ifdef _WIN32
        err = pty_win_spawn(p, ctx, name, cwd, env_arr, cols, rows);
#else
        err = pty_unix_spawn(p, ctx, name, cwd, env_arr, argv_arr, argv_len, cols, rows);
#endif
        if (name) JS_FreeCString(ctx, name);
        if (cwd)  JS_FreeCString(ctx, cwd);
        free_env(ctx, env_arr);
        free_str_arr(ctx, argv_arr, argv_len);

        if (JS_IsException(err)) {
            tjs__free(p); JS_FreeValue(ctx, obj);
            return err;
        }

        JS_SetOpaque(obj, p);
        p->obj = JS_DupValue(ctx, obj);
        return obj;
    }

    /* ---- Normal mode ---- */
    JSValue ret = JS_EXCEPTION;
    uv_process_options_t options;
    memset(&options, 0, sizeof(options));
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

    JS_SetOpaque(obj, p);
    p->obj = JS_DupValue(ctx, obj);
    ret = obj;
    goto cleanup;

fail:
    for (int i = 0; i < 3; i++) { JS_FreeValue(ctx, p->stdio[i]); p->stdio[i] = JS_UNDEFINED; }
    tjs__free(p);
    JS_FreeValue(ctx, obj);
cleanup:
    tjs__free_args(ctx, options.args);
    free_env(ctx, (char **)options.env);
    if (options.cwd) js_free(ctx, (void *)options.cwd);
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
    int sig = parse_signal(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, SIGTERM);
    if (sig < 0) return JS_EXCEPTION;
    int r = p->pty_mode
        ? uv_kill((int)p->pty_pid, sig)
        : uv_process_kill(&p->process, sig);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

/* wait() → Promise — normal mode only (PTY has no libuv exit callback) */
static JSValue tjs_process_wait(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    if (p->pty_mode)
        return JS_ThrowInternalError(ctx, "wait() not supported for PTY; use waitSync()");
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
        if (waitpid(p->pty_pid, &stat, 0) < 0)
            return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
        if (WIFEXITED(stat))        { es = WEXITSTATUS(stat); ts = 0; }
        else if (WIFSIGNALED(stat)) { es = 128 + WTERMSIG(stat); ts = WTERMSIG(stat); }
        else return JS_ThrowInternalError(ctx, "unexpected waitpid status");
#endif
    } else {
#ifdef _WIN32
        if (WaitForSingleObject(p->process.process_handle, INFINITE) != WAIT_OBJECT_0)
            return JS_ThrowInternalError(ctx, "WaitForSingleObject failed");
        DWORD ws; GetExitCodeProcess(p->process.process_handle, &ws);
        es = (int64_t)ws; ts = 0;
#else
        int stat;
        if (waitpid(p->process.pid, &stat, 0) < 0)
            return tjs_throw_errno(ctx, uv_translate_sys_error(errno));
        if (WIFEXITED(stat))        { es = WEXITSTATUS(stat); ts = 0; }
        else if (WIFSIGNALED(stat)) { es = 128 + WTERMSIG(stat); ts = WTERMSIG(stat); }
        else return JS_ThrowInternalError(ctx, "unexpected waitpid status");
#endif
    }

    p->status.exited = true;
    p->status.exit_status = es;
    p->status.term_signal = ts;
    return make_exit_obj(ctx, es, ts);
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
    JS_CGETSET_DEF("readable",    tjs_process_readable_get, NULL),
    JS_CGETSET_DEF("writable",    tjs_process_writable_get, NULL),
    JS_CGETSET_DEF("getwinsize",  tjs_process_getwinsize,   NULL),
    TJS_CFUNC_DEF("kill",         1, tjs_process_kill),
    TJS_CFUNC_DEF("wait",         0, tjs_process_wait),
    TJS_CFUNC_DEF("waitSync",     0, tjs_process_wait_sync),
    TJS_CFUNC_DEF("resize",       2, tjs_process_resize),
};

static const JSCFunctionListEntry tjs_process_funcs[] = {
    TJS_CFUNC_DEF("spawn", 2, tjs_spawn),
    TJS_CFUNC_DEF("kill",  2, tjs_kill),
    TJS_CFUNC_DEF("exec",  1, tjs_exec),
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