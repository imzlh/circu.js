/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé
 * Copyright (c) 2025-present iz
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

#include "tjs.h"

#ifdef _WIN32
#include <crtdbg.h>
#include <stdlib.h> /* _set_abort_behavior */
#include <string.h>
#include <windows.h> /* IsDebuggerPresent, SetErrorMode */

/* MSVC-only debug hook: _CRT_WARN / __debugbreak() */
int exit_hook(int reportType, char* message, int* returnValue) {
    if (reportType == _CRT_WARN && strstr(message, "calling exit")) {
        /* Only trap when someone is actually attached to catch it. */
        if (IsDebuggerPresent()) {
            __debugbreak();
        }
    }
    return 0;
}

/* Last-resort backstop for a native stack overflow. */
static int tjs__stack_overflow_filter(unsigned long code) {
    return code == (unsigned long) EXCEPTION_STACK_OVERFLOW ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

static void tjs__report_stack_overflow(void) {
    static const char msg[] = "cno: fatal: native stack overflow (the JS stack limit could not stop it); "
                              "lower --max-stack-size\n";
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        WriteFile(h, msg, (DWORD) (sizeof(msg) - 1), &written, NULL);
    }
}
#endif

int main(int argc, char **argv) {
#if defined(_WIN32)
    _CrtSetReportHook(exit_hook);

    /* Route asserts and errors to stderr unless a debugger is attached to answer the dialog. */
    if (!IsDebuggerPresent()) {
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
        /* Suppress the "Debug Error!" popup from abort()/CRT invalid-parameter paths too */
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    }
#endif

    TJS_Initialize(argc, argv);

    TJSRuntime *qrt = TJS_NewRuntime();
    if (!qrt) {
        return 1;
    }

    int exit_code = 1;
#if defined(_WIN32)
    __try {
        exit_code = TJS_Run(qrt);
    } __except (tjs__stack_overflow_filter(GetExceptionCode())) {
        tjs__report_stack_overflow();
        /* 134 mirrors the SIGABRT-equivalent status a fatal runtime abort already reports  */
        return 134;
    }
#else
    exit_code = TJS_Run(qrt);
#endif

    TJS_FreeRuntime(qrt);

    return exit_code;
}
