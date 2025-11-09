/*
 * txiki.ts
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE \
  ProcThreadAttributeValue(22, FALSE, TRUE, FALSE)
typedef VOID* HPCON;
#endif
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <sys/wait.h>
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <util.h>
#elif defined(__FreeBSD__)
#include <libutil.h>
#else
#include <pty.h>
#endif
#endif

#ifdef _WIN32
/* ConPTY function pointers */
typedef HRESULT (WINAPI *CreatePseudoConsolePtr)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
typedef HRESULT (WINAPI *ResizePseudoConsolePtr)(HPCON, COORD);
typedef void (WINAPI *ClosePseudoConsolePtr)(HPCON);

static CreatePseudoConsolePtr pCreatePseudoConsole = NULL;
static ResizePseudoConsolePtr pResizePseudoConsole = NULL;
static ClosePseudoConsolePtr pClosePseudoConsole = NULL;
static BOOL conpty_loaded = FALSE;

static BOOL load_conpty_functions(void) {
    if (conpty_loaded) return TRUE;
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return FALSE;
    
    pCreatePseudoConsole = (CreatePseudoConsolePtr)GetProcAddress(kernel32, "CreatePseudoConsole");
    pResizePseudoConsole = (ResizePseudoConsolePtr)GetProcAddress(kernel32, "ResizePseudoConsole");
    pClosePseudoConsole = (ClosePseudoConsolePtr)GetProcAddress(kernel32, "ClosePseudoConsole");
    
    conpty_loaded = (pCreatePseudoConsole && pResizePseudoConsole && pClosePseudoConsole);
    return conpty_loaded;
}
#endif

static JSValue tjs_pty_openpty(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
#ifdef _WIN32
    if (!load_conpty_functions()) {
        return JS_ThrowInternalError(ctx, "ConPTY not supported on this Windows version");
    }
    
    HANDLE hPipeIn = INVALID_HANDLE_VALUE;
    HANDLE hPipeOut = INVALID_HANDLE_VALUE;
    HANDLE hConPtyIn = INVALID_HANDLE_VALUE;
    HANDLE hConPtyOut = INVALID_HANDLE_VALUE;
    HPCON hPC = NULL;
    PROCESS_INFORMATION pi = {0};
    JSValue ret_obj = JS_UNDEFINED;
    
    /* Parse options */
    int cols = 80, rows = 24;
    const char *name = NULL;
    const char *cwd = NULL;
    WCHAR *wcwd = NULL;
    WCHAR *wname = NULL;
    WCHAR *wargs = NULL;
    
    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue js_cols = JS_GetPropertyStr(ctx, argv[0], "cols");
        JSValue js_rows = JS_GetPropertyStr(ctx, argv[0], "rows");
        JSValue js_name = JS_GetPropertyStr(ctx, argv[0], "name");
        JSValue js_cwd = JS_GetPropertyStr(ctx, argv[0], "cwd");
        
        if (JS_IsNumber(js_cols)) JS_ToInt32(ctx, &cols, js_cols);
        if (JS_IsNumber(js_rows)) JS_ToInt32(ctx, &rows, js_rows);
        if (JS_IsString(js_name)) name = JS_ToCString(ctx, js_name);
        if (JS_IsString(js_cwd)) cwd = JS_ToCString(ctx, js_cwd);
        
        JS_FreeValue(ctx, js_cols);
        JS_FreeValue(ctx, js_rows);
        JS_FreeValue(ctx, js_name);
        JS_FreeValue(ctx, js_cwd);
    }
    
    /* Create pipes */
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&hConPtyIn, &hPipeIn, &sa, 0) ||
        !CreatePipe(&hPipeOut, &hConPtyOut, &sa, 0)) {
        JS_ThrowInternalError(ctx, "Failed to create pipes: %lu", GetLastError());
        goto win_cleanup;
    }
    
    /* Create ConPTY */
    COORD consoleSize = {cols, rows};
    HRESULT hr = pCreatePseudoConsole(consoleSize, hConPtyIn, hConPtyOut, 0, &hPC);
    if (FAILED(hr)) {
        JS_ThrowInternalError(ctx, "CreatePseudoConsole failed: 0x%08lx", hr);
        goto win_cleanup;
    }
    
    /* Setup startup info */
    STARTUPINFOEXW siEx = {0};
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrListSize);
    
    if (!InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrListSize)) {
        JS_ThrowInternalError(ctx, "InitializeProcThreadAttributeList failed");
        goto win_cleanup;
    }
    
    if (!UpdateProcThreadAttribute(siEx.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   hPC, sizeof(HPCON), NULL, NULL)) {
        JS_ThrowInternalError(ctx, "UpdateProcThreadAttribute failed");
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        goto win_cleanup;
    }
    
    /* Prepare command */
    if (!name) name = getenv("COMSPEC");
    if (!name) name = "cmd.exe";
    
    int wname_len = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);
    wname = malloc(wname_len * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, wname_len);
    
    if (cwd) {
        int wcwd_len = MultiByteToWideChar(CP_UTF8, 0, cwd, -1, NULL, 0);
        wcwd = malloc(wcwd_len * sizeof(WCHAR));
        MultiByteToWideChar(CP_UTF8, 0, cwd, -1, wcwd, wcwd_len);
    }
    
    /* Create process */
    if (!CreateProcessW(NULL, wname, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT, NULL, wcwd,
                        &siEx.StartupInfo, &pi)) {
        JS_ThrowInternalError(ctx, "CreateProcess failed: %lu", GetLastError());
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        goto win_cleanup;
    }
    
    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    CloseHandle(hConPtyIn);
    CloseHandle(hConPtyOut);
    hConPtyIn = INVALID_HANDLE_VALUE;
    hConPtyOut = INVALID_HANDLE_VALUE;
    
    /* Return object */
    ret_obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ret_obj, "fd", JS_NewInt64(ctx, (intptr_t)hPipeOut));
    JS_SetPropertyStr(ctx, ret_obj, "pid", JS_NewInt64(ctx, pi.dwProcessId));
    JS_SetPropertyStr(ctx, ret_obj, "pty", JS_NewInt64(ctx, (intptr_t)hPC));
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    hPipeOut = INVALID_HANDLE_VALUE;
    hPC = NULL;
    
win_cleanup:
    if (name) JS_FreeCString(ctx, name);
    if (cwd) JS_FreeCString(ctx, cwd);
    if (wname) free(wname);
    if (wcwd) free(wcwd);
    if (wargs) free(wargs);
    if (hPipeIn != INVALID_HANDLE_VALUE) CloseHandle(hPipeIn);
    if (hPipeOut != INVALID_HANDLE_VALUE) CloseHandle(hPipeOut);
    if (hConPtyIn != INVALID_HANDLE_VALUE) CloseHandle(hConPtyIn);
    if (hConPtyOut != INVALID_HANDLE_VALUE) CloseHandle(hConPtyOut);
    if (hPC && pClosePseudoConsole) pClosePseudoConsole(hPC);
    if (siEx.lpAttributeList) free(siEx.lpAttributeList);
    
    return ret_obj;
    
#else
    /* Unix/Linux implementation */
    int master_fd = -1;
    int slave_fd = -1;
    struct winsize ws;
    const char *name = NULL;
    const char *cwd = NULL;
    JSValue ret_obj = JS_UNDEFINED;
    JSValue js_env = JS_UNDEFINED;
    JSValue js_argv = JS_UNDEFINED;
    
    /* Parse arguments */
    if (argc > 0 && JS_IsObject(argv[0])) {
        JSValue js_cols = JS_GetPropertyStr(ctx, argv[0], "cols");
        JSValue js_rows = JS_GetPropertyStr(ctx, argv[0], "rows");
        JSValue js_name = JS_GetPropertyStr(ctx, argv[0], "name");
        JSValue js_cwd = JS_GetPropertyStr(ctx, argv[0], "cwd");
        
        memset(&ws, 0, sizeof(ws));
        if (JS_IsNumber(js_cols)) {
            int32_t cols;
            JS_ToInt32(ctx, &cols, js_cols);
            ws.ws_col = cols;
        } else {
            ws.ws_col = 80;
        }
        
        if (JS_IsNumber(js_rows)) {
            int32_t rows;
            JS_ToInt32(ctx, &rows, js_rows);
            ws.ws_row = rows;
        } else {
            ws.ws_row = 24;
        }
        
        if (JS_IsString(js_name)) name = JS_ToCString(ctx, js_name);
        if (JS_IsString(js_cwd)) cwd = JS_ToCString(ctx, js_cwd);
        
        js_env = JS_GetPropertyStr(ctx, argv[0], "env");
        js_argv = JS_GetPropertyStr(ctx, argv[0], "argv");
        
        JS_FreeValue(ctx, js_cols);
        JS_FreeValue(ctx, js_rows);
        JS_FreeValue(ctx, js_name);
        JS_FreeValue(ctx, js_cwd);
    } else {
        memset(&ws, 0, sizeof(ws));
        ws.ws_col = 80;
        ws.ws_row = 24;
    }
    
    /* Open PTY */
    if (openpty(&master_fd, &slave_fd, NULL, NULL, &ws) == -1) {
        JS_ThrowInternalError(ctx, "openpty failed: %s", strerror(errno));
        goto unix_cleanup;
    }
    
    /* Set non-blocking */
    int flags = fcntl(master_fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    /* Fork */
    pid_t pid = fork();
    if (pid < 0) {
        JS_ThrowInternalError(ctx, "fork failed: %s", strerror(errno));
        goto unix_cleanup;
    }
    
    if (pid == 0) {
        /* Child process */
        close(master_fd);
        
        if (setsid() == -1) _exit(1);
        
#ifdef TIOCSCTTY
        if (ioctl(slave_fd, TIOCSCTTY, NULL) == -1) _exit(1);
#endif
        
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        
        if (slave_fd > STDERR_FILENO) close(slave_fd);
        
        if (cwd && chdir(cwd) == -1) _exit(1);
        
        /* Set environment */
        if (JS_IsObject(js_env)) {
            JSPropertyEnum *props;
            uint32_t prop_count;
            if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, js_env,
                                       JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                for (uint32_t i = 0; i < prop_count; i++) {
                    JSValue key = JS_AtomToString(ctx, props[i].atom);
                    JSValue val = JS_GetProperty(ctx, js_env, props[i].atom);
                    
                    const char *key_str = JS_ToCString(ctx, key);
                    const char *val_str = JS_ToCString(ctx, val);
                    
                    if (key_str && val_str) setenv(key_str, val_str, 1);
                    
                    JS_FreeCString(ctx, key_str);
                    JS_FreeCString(ctx, val_str);
                    JS_FreeValue(ctx, key);
                    JS_FreeValue(ctx, val);
                }
                js_free(ctx, props);
            }
        }
        
        /* Execute */
        const char *file = name ? name : getenv("SHELL");
        if (!file) file = "/bin/sh";
        
        if (JS_IsArray(js_argv)) {
            JSValue len_val = JS_GetPropertyStr(ctx, js_argv, "length");
            int32_t len;
            JS_ToInt32(ctx, &len, len_val);
            JS_FreeValue(ctx, len_val);
            
            char **argv_arr = malloc(sizeof(char *) * (len + 1));
            for (int32_t i = 0; i < len; i++) {
                JSValue item = JS_GetPropertyUint32(ctx, js_argv, i);
                argv_arr[i] = (char *)JS_ToCString(ctx, item);
                JS_FreeValue(ctx, item);
            }
            argv_arr[len] = NULL;
            execvp(file, argv_arr);
        } else {
            char *argv_default[] = {(char *)file, NULL};
            execvp(file, argv_default);
        }
        
        _exit(1);
    }
    
    /* Parent */
    close(slave_fd);
    slave_fd = -1;
    
    ret_obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ret_obj, "fd", JS_NewInt32(ctx, master_fd));
    JS_SetPropertyStr(ctx, ret_obj, "pid", JS_NewInt32(ctx, pid));
    
    master_fd = -1;
    
unix_cleanup:
    if (name) JS_FreeCString(ctx, name);
    if (cwd) JS_FreeCString(ctx, cwd);
    if (master_fd >= 0) close(master_fd);
    if (slave_fd >= 0) close(slave_fd);
    JS_FreeValue(ctx, js_env);
    JS_FreeValue(ctx, js_argv);
    
    return ret_obj;
#endif
}

static JSValue tjs_pty_resize(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "resize requires fd/pty, cols, rows");
    }
    
    int32_t cols, rows;
    if (JS_ToInt32(ctx, &cols, argv[1]) || JS_ToInt32(ctx, &rows, argv[2])) {
        return JS_EXCEPTION;
    }
    
#ifdef _WIN32
    int64_t pty_handle;
    if (JS_ToInt64(ctx, &pty_handle, argv[0])) {
        return JS_EXCEPTION;
    }
    
    if (!load_conpty_functions() || !pResizePseudoConsole) {
        return JS_ThrowInternalError(ctx, "ConPTY resize not supported");
    }
    
    COORD consoleSize = {cols, rows};
    HRESULT hr = pResizePseudoConsole((HPCON)pty_handle, consoleSize);
    if (FAILED(hr)) {
        return JS_ThrowInternalError(ctx, "ResizePseudoConsole failed: 0x%08lx", hr);
    }
#else
    int32_t fd;
    if (JS_ToInt32(ctx, &fd, argv[0])) {
        return JS_EXCEPTION;
    }
    
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = cols;
    ws.ws_row = rows;
    
    if (ioctl(fd, TIOCSWINSZ, &ws) == -1) {
        return JS_ThrowInternalError(ctx, "ioctl TIOCSWINSZ failed: %s", strerror(errno));
    }
#endif
    
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_pty_funcs[] = {
    TJS_CFUNC_DEF("openpty", 1, tjs_pty_openpty),
    TJS_CFUNC_DEF("resize", 3, tjs_pty_resize),
};

void tjs__mod_pty_init(JSContext *ctx, JSValue ns) {
    JS_SetPropertyFunctionList(ctx, ns, tjs_pty_funcs, countof(tjs_pty_funcs));
}