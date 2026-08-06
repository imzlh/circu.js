/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé
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

/* MSVC-only debug hook: _CRT_WARN / __debugbreak() do not exist on other
 * toolchains, so this must stay inside the _WIN32 guard or non-Windows builds
 * fail to compile. */
int exit_hook(int reportType, char* message, int* returnValue) {
    if (reportType == _CRT_WARN && strstr(message, "calling exit")) {
        /* Only trap when someone is actually attached to catch it. Unguarded,
         * __debugbreak() raises an unhandled breakpoint exception that Windows
         * turns into a crash dialog on every normal process exit — which under
         * a test run (hundreds of short-lived workers) is a dialog storm, and
         * each box blocks its process until dismissed. */
        if (IsDebuggerPresent()) {
            __debugbreak();
        }
    }
    return 0;
}

/* Last-resort backstop for a native stack overflow.
 *
 * tjs__clamp_stack_size (utils.c) keeps QuickJS's soft limit above the guard
 * page, so ordinary JS recursion now raises a catchable RangeError. It cannot
 * cover a native C recursion that never calls js_check_stack_overflow, and the
 * requirement for --max-stack-size is absolute: no value may produce a crash
 * with empty stdout AND empty stderr. Before this, 0xC00000FD went straight to
 * the OS and the process died mute (OBSERVED: --max-stack-size=8MB, rc
 * -1073741571, both streams zero bytes).
 *
 * The message is written from the __except BLOCK, not from the filter: by then
 * the frames have unwound back to main and there is stack to work in. The
 * filter itself only compares an integer, which is safe on an exhausted stack.
 * WriteFile is used rather than fprintf because it neither allocates nor takes
 * a CRT lock that the overflowing thread may already hold.
 *
 * Only covers the main thread. An overflow on a Worker's uv thread is not
 * visible here — the vm.c clamp is what protects that path. */
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

    /* This is a Debug build, so assert() is compiled in. The Debug CRT's
     * default for a failed assert is a modal Abort/Retry/Ignore box that
     * writes to no log, so an assertion failure under automation looks like a
     * silent hang instead of a diagnosable error. Route asserts and errors to
     * stderr unless a debugger is attached to answer the dialog. */
    if (!IsDebuggerPresent()) {
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
        /* Suppress the "Debug Error!" popup from abort()/CRT invalid-parameter
         * paths too; the process still fails, just without a modal box.
         * assert() reports and then calls abort(), so both need handling. */
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
        /* Deliberately NOT calling TJS_FreeRuntime: after a guard-page hit the
         * runtime is in an indeterminate state and the guard page has not been
         * re-armed (_resetstkoflw is not called because the process is going
         * away regardless). 134 mirrors the SIGABRT-equivalent status a fatal
         * runtime abort already reports (tests/cts/resource-limits.test.ts). */
        return 134;
    }
#else
    exit_code = TJS_Run(qrt);
#endif

    TJS_FreeRuntime(qrt);

    return exit_code;
}
