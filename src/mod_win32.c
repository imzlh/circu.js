/*
 * circu.js win32
 *
 * Copyright (c) 2026-present iz
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

#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

/* ── String helpers ─────────────────────────────────────────── */

static WCHAR *to_wcs(JSContext *ctx, JSValue v) {
    const char *s = JS_ToCString(ctx, v);
    if (!s) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w = js_malloc(ctx, n * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    JS_FreeCString(ctx, s);
    return w;
}

static JSValue from_wcs(JSContext *ctx, const WCHAR *w, int nchars) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, nchars, NULL, 0, NULL, NULL);
    char *s = js_malloc(ctx, n + 1);
    WideCharToMultiByte(CP_UTF8, 0, w, nchars, s, n, NULL, NULL);
    s[n] = '\0';
    JSValue v = JS_NewString(ctx, s);
    js_free(ctx, s);
    return v;
}

#define THROW_WIN32() JS_ThrowInternalError(ctx, "Win32 error %lu", GetLastError())

/* HKEY predefined handles stored as int32; JS_ToUint32 recovers correctly */
static inline HKEY to_hkey(JSContext *ctx, JSValue v) {
    uint32_t u; JS_ToUint32(ctx, &u, v);
    return (HKEY)(uintptr_t)u;
}

/* Open a registry key; sets JS exception and returns NULL on failure */
static HKEY open_key(JSContext *ctx, JSValue hive_v, JSValue key_v, REGSAM access) {
    WCHAR *key = to_wcs(ctx, key_v);
    if (!key) return NULL;
    HKEY hk;
    LONG r = RegOpenKeyExW(to_hkey(ctx, hive_v), key, 0, access, &hk);
    js_free(ctx, key);
    if (r != ERROR_SUCCESS) { THROW_WIN32(); return NULL; }
    return hk;
}

/* ── Registry value type conversion ─────────────────────────── */

static JSValue reg_to_js(JSContext *ctx, DWORD type, const BYTE *data, DWORD sz) {
    switch (type) {
    case REG_SZ: case REG_EXPAND_SZ: {
        int n = sz / sizeof(WCHAR);
        if (n > 0 && ((const WCHAR *)data)[n - 1] == L'\0') n--;
        return from_wcs(ctx, (const WCHAR *)data, n);
    }
    case REG_DWORD:
        return JS_NewUint32(ctx, *(const DWORD *)data);
    case REG_QWORD:
        return JS_NewInt64(ctx, *(const int64_t *)data);
    case REG_MULTI_SZ: {
        JSValue arr = JS_NewArray(ctx);
        const WCHAR *p = (const WCHAR *)data;
        uint32_t i = 0;
        while (*p) { JS_SetPropertyUint32(ctx, arr, i++, from_wcs(ctx, p, -1)); p += wcslen(p) + 1; }
        return arr;
    }
    default: {
        uint8_t *copy = js_malloc(ctx, sz);
        memcpy(copy, data, sz);
        return TJS_NewUint8Array(ctx, copy, sz);
    }
    }
}

/* ── reg_read(hive, key, name) ──────────────────────────────── */

static JSValue tjs_reg_read(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    HKEY hk = open_key(ctx, argv[0], argv[1], KEY_READ);
    if (!hk) return JS_EXCEPTION;

    WCHAR *name = to_wcs(ctx, argv[2]);
    DWORD type, size;
    LONG r = RegQueryValueExW(hk, name, NULL, &type, NULL, &size);
    if (r != ERROR_SUCCESS) { js_free(ctx, name); RegCloseKey(hk); return THROW_WIN32(); }

    BYTE *data = js_malloc(ctx, size + 2);  /* +2: guard missing null terminator */
    memset(data + size, 0, 2);
    r = RegQueryValueExW(hk, name, NULL, &type, data, &size);
    js_free(ctx, name); RegCloseKey(hk);
    if (r != ERROR_SUCCESS) { js_free(ctx, data); return THROW_WIN32(); }

    JSValue result = reg_to_js(ctx, type, data, size);
    js_free(ctx, data);
    return result;
}

/* ── reg_write(hive, key, name, value) ──────────────────────── */
/* value: string → REG_SZ, number → REG_DWORD, Uint8Array → REG_BINARY */

static JSValue tjs_reg_write(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    HKEY hk = open_key(ctx, argv[0], argv[1], KEY_WRITE);
    if (!hk) return JS_EXCEPTION;

    WCHAR *name = to_wcs(ctx, argv[2]);
    JSValue val = argv[3];
    DWORD type, size;
    WCHAR *wbuf = NULL;
    DWORD dword_val;
    const BYTE *data;
    bool is_extbuf = false;

    if (JS_IsString(val)) {
        wbuf = to_wcs(ctx, val);
        type = REG_SZ; size = (wcslen(wbuf) + 1) * sizeof(WCHAR);
        data = (const BYTE *)wbuf;
    } else if (JS_IsNumber(val)) {
        JS_ToUint32(ctx, &dword_val, val);
        type = REG_DWORD; size = sizeof(DWORD);
        data = (const BYTE *)&dword_val;
    } else {
        size_t sz;
        uint8_t *buf = JS_GetUint8Array(ctx, &sz, val);
        if (!buf) { js_free(ctx, name); RegCloseKey(hk); return JS_EXCEPTION; }
        type = REG_BINARY; size = sz; data = buf; is_extbuf = true;
    }

    LONG r = RegSetValueExW(hk, name, 0, type, data, size);
    js_free(ctx, name); RegCloseKey(hk);
    if (wbuf) js_free(ctx, wbuf);
    return r == ERROR_SUCCESS ? JS_UNDEFINED : THROW_WIN32();
}

/* ── reg_delete(hive, key, name) ────────────────────────────── */

static JSValue tjs_reg_delete(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    HKEY hk = open_key(ctx, argv[0], argv[1], KEY_WRITE);
    if (!hk) return JS_EXCEPTION;
    WCHAR *name = to_wcs(ctx, argv[2]);
    LONG r = RegDeleteValueW(hk, name);
    js_free(ctx, name); RegCloseKey(hk);
    return r == ERROR_SUCCESS ? JS_UNDEFINED : THROW_WIN32();
}

/* ── RegWatch class ──────────────────────────────────────────── */

static JSClassID tjs_regwatch_classid;

typedef struct {
    HKEY        hkey;
    HANDLE      event;
    uv_async_t  async;
    uv_thread_t thread;
    JSValue     callback;
    JSContext  *jsctx;
    volatile LONG stopped;
} tjs_regwatch_t;

static void reg_watch_thread(void *arg) {
    tjs_regwatch_t *w = arg;
    for (;;) {
        /* re-arm before waiting to avoid missing changes */
        RegNotifyChangeKeyValue(w->hkey, TRUE,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES,
            w->event, TRUE);
        if (WaitForSingleObject(w->event, INFINITE) == WAIT_OBJECT_0) {
            if (InterlockedCompareExchange(&w->stopped, 0, 0)) break;
            uv_async_send(&w->async);
        }
    }
}

static void reg_watch_async_cb(uv_async_t *handle) {
    tjs_regwatch_t *w = uv_handle_get_data((uv_handle_t *)handle);
    if (InterlockedCompareExchange(&w->stopped, 0, 0) || JS_IsUndefined(w->callback)) return;
    JSValue ret = JS_Call(w->jsctx, w->callback, JS_UNDEFINED, 0, NULL);
    JS_FreeValue(w->jsctx, ret);
}

/* Stop the watcher (idempotent, pure C, no JS calls) */
static void regwatch_stop(tjs_regwatch_t *w) {
    if (!InterlockedExchange(&w->stopped, 1)) {
        SetEvent(w->event);             /* unblock thread */
        uv_thread_join(&w->thread);     /* wait for exit */
        RegCloseKey(w->hkey);
        CloseHandle(w->event);
        if (!uv_is_closing((uv_handle_t *)&w->async))
            uv_close((uv_handle_t *)&w->async, NULL);
    }
}

static JSValue tjs_regwatch_close(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    tjs_regwatch_t *w = JS_GetOpaque(this_val, tjs_regwatch_classid);
    if (!w) return JS_UNDEFINED;
    regwatch_stop(w);
    if (!JS_IsUndefined(w->callback)) {
        JS_FreeValue(ctx, w->callback);
        w->callback = JS_UNDEFINED;
    }
    return JS_UNDEFINED;
}

static void tjs_regwatch_finalizer(JSRuntime *rt, JSValue val) {
    tjs_regwatch_t *w = JS_GetOpaque(val, tjs_regwatch_classid);
    if (!w) return;
    regwatch_stop(w);
    JS_FreeValueRT(rt, w->callback);
    js_free_rt(rt, w);
}

static void tjs_regwatch_gc_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    tjs_regwatch_t *w = JS_GetOpaque(val, tjs_regwatch_classid);
    if (w && !JS_IsUndefined(w->callback))
        JS_MarkValue(rt, w->callback, mark_func);
}

static JSClassDef tjs_regwatch_class = {
    "RegWatch", .finalizer = tjs_regwatch_finalizer, .gc_mark = tjs_regwatch_gc_mark
};

static const JSCFunctionListEntry tjs_regwatch_proto_funcs[] = {
    TJS_CFUNC_DEF("close", 0, tjs_regwatch_close),
};

/* ── reg_watch(hive, key, callback) → RegWatch ──────────────── */

static JSValue tjs_reg_watch(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJS_CHECK_ARG_RET(ctx, JS_IsFunction(ctx, argv[2]), 2, "function");
    HKEY hk = open_key(ctx, argv[0], argv[1], KEY_NOTIFY);
    if (!hk) return JS_EXCEPTION;

    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!event) { RegCloseKey(hk); return THROW_WIN32(); }

    tjs_regwatch_t *w = js_mallocz(ctx, sizeof(*w));
    w->hkey = hk; w->event = event; w->jsctx = ctx; w->stopped = 0;
    w->callback = JS_DupValue(ctx, argv[2]);

    uv_async_init(tjs_get_loop(ctx), &w->async, reg_watch_async_cb);
    uv_handle_set_data((uv_handle_t *)&w->async, w);
    uv_thread_create(&w->thread, reg_watch_thread, w);

    JSValue obj = JS_NewObjectClass(ctx, tjs_regwatch_classid);
    JS_SetOpaque(obj, w);
    return obj;
}

/* ── get_certs([storeName]) → string[] ──────────────────────── */
/* Returns PEM strings; storeName defaults to "ROOT", can also be "CA", "MY" */

static JSValue tjs_get_certs(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    const char *store_name = "ROOT";
    const char *store_cstr = NULL;
    if (argc > 0 && JS_IsString(argv[0]))
        store_name = store_cstr = JS_ToCString(ctx, argv[0]);

    HCERTSTORE store = CertOpenSystemStoreA(0, store_name);
    if (store_cstr) JS_FreeCString(ctx, store_cstr);
    if (!store) return THROW_WIN32();

    JSValue arr = JS_NewArray(ctx);
    uint32_t i = 0;
    PCCERT_CONTEXT cert = NULL;
    while ((cert = CertEnumCertificatesInStore(store, cert))) {
        /* CRYPT_STRING_BASE64HEADER produces -----BEGIN/END CERTIFICATE----- wrapped PEM */
        DWORD pem_len = 0;
        CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded,
                             CRYPT_STRING_BASE64HEADER, NULL, &pem_len);
        char *pem = js_malloc(ctx, pem_len);
        CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded,
                             CRYPT_STRING_BASE64HEADER, pem, &pem_len);
        JS_SetPropertyUint32(ctx, arr, i++, JS_NewString(ctx, pem));
        js_free(ctx, pem);
    }
    CertCloseStore(store, 0);
    return arr;
}

/* ── Module init ─────────────────────────────────────────────── */

#define HKEY_CONST(alias, key) JS_PROP_INT32_DEF(#alias, (int32_t)(uintptr_t)(key), JS_PROP_ENUMERABLE)

static const JSCFunctionListEntry win32_funcs[] = {
    TJS_CFUNC_DEF("readRegistry",   3, tjs_reg_read),
    TJS_CFUNC_DEF("writeRegistry",  4, tjs_reg_write),
    TJS_CFUNC_DEF("delRegistry", 3, tjs_reg_delete),
    TJS_CFUNC_DEF("watchRegistry",  3, tjs_reg_watch),
    TJS_CFUNC_DEF("exportCerts",  1, tjs_get_certs),
    HKEY_CONST(HKCR, HKEY_CLASSES_ROOT),
    HKEY_CONST(HKCU, HKEY_CURRENT_USER),
    HKEY_CONST(HKLM, HKEY_LOCAL_MACHINE),
    HKEY_CONST(HKU,  HKEY_USERS),
    HKEY_CONST(HKCC, HKEY_CURRENT_CONFIG),
};

void tjs__mod_win32_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, &tjs_regwatch_classid);
    JS_NewClass(rt, tjs_regwatch_classid, &tjs_regwatch_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_regwatch_proto_funcs, countof(tjs_regwatch_proto_funcs));
    JS_SetClassProto(ctx, tjs_regwatch_classid, proto);
    JS_SetPropertyFunctionList(ctx, ns, win32_funcs, countof(win32_funcs));
}