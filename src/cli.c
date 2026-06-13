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
#include <string.h>

/* MSVC-only debug hook: _CRT_WARN / __debugbreak() do not exist on other
 * toolchains, so this must stay inside the _WIN32 guard or non-Windows builds
 * fail to compile. */
int exit_hook(int reportType, char* message, int* returnValue) {
    if (reportType == _CRT_WARN && strstr(message, "calling exit")) {
        __debugbreak();
    }
    return 0;
}
#endif

int main(int argc, char **argv) {
#if defined(_WIN32)
    _CrtSetReportHook(exit_hook);
#endif

    TJS_Initialize(argc, argv);

    TJSRuntime *qrt = TJS_NewRuntime();
    if (!qrt) {
        return 1;
    }

    int exit_code = TJS_Run(qrt);

    TJS_FreeRuntime(qrt);

    return exit_code;
}
