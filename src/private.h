/*
 * circu.js
 *
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

#ifndef TJS_PRIVATE_H
#define TJS_PRIVATE_H

#include "../deps/quickjs/cutils.h"
#include "../deps/quickjs/quickjs.h"
#include "../deps/quickjs/list.h"
#include "tjs.h"
#include "utils.h"
#include "sourcemap.h"

#include <curl/curl.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <uv.h>
#include <openssl/ssl.h>

#ifdef HAVE_THREADS_H
#include <threads.h>
#else
#define thread_local _Thread_local
#endif

enum {
    __JS_ATOM_NULL = JS_ATOM_NULL,
#define DEF(name, str) JS_ATOM_ ## name,
#include "../deps/quickjs/quickjs-atom.h"
#undef DEF
    JS_ATOM_END,
};

typedef struct TJSTimer TJSTimer;

struct TJSRuntime {
    TJSRunOptions options;
    JSRuntime *rt;
    JSContext *main_ctx;
    uv_loop_t loop;
    struct {
        uv_check_t check;
        uv_idle_t idle;
        uv_prepare_t prepare;
		bool paused;
		int waitio_depth;  /* Track nested waitIO calls */
    } jobs;
    uv_async_t stop;

    bool is_worker;
    int8_t exit_code;
    struct list_head workers;

	bool freeing;
    struct {
        TJSTimer *timers;
        int64_t next_timer;
    } timers;
    struct {
        JSValue dispatch_event_func;
		JSValue message_pipe;	// for worker messaging
		JSValue worker_udata;	// user-data passed from parent
    } builtins;
	struct {
		JSValue resolver;
		JSValue loader;
		JSValue metaloader;
		JSValue attrchecker;

		JSValue imod_ns;
		JSValue dyn_registry;       /* name -> path map for external native modules */
		struct list_head dyn_libs;  /* loaded uv_lib_t handles, freed after JS shutdown */
		MappingContext* mapctx;
	} module;
};

struct TJSApp {
    TJSRuntime* trt;
    JSContext *ctx;

    bool is_sandbox;
    struct list_head link;
};

typedef struct TJSDynLib {
	uv_lib_t lib;
	struct list_head link;
} TJSDynLib;

typedef struct {
    JSContext *ctx;
    uv_thread_t tid;
    JSValue message_pipe;
    TJSRuntime *wrt;
    bool terminated;
	struct list_head link;
} TJSWorker;

typedef enum {
	EV_PROMISE = 0,
	EV_UNHANDLED_REJECTION,
	EV_JOB_EXCEPTION,
	EV_EXIT,
	EV_LOAD
} TJSEvents;

void tjs__mod_algorithm_init(JSContext* ctx, JSValue ns);
void tjs__mod_dns_init(JSContext *ctx, JSValue ns);
void tjs__mod_engine_init(JSContext *ctx, JSValue ns);
void tjs__mod_error_init(JSContext *ctx, JSValue ns);
void tjs__mod_ffi_init(JSContext *ctx, JSValue ns);
void tjs__mod_asyncfs_init(JSContext *ctx, JSValue ns);
void tjs__mod_fs_init(JSContext* ctx, JSValue ns);
void tjs__mod_fswatch_init(JSContext *ctx, JSValue ns);
void tjs__mod_os_init(JSContext *ctx, JSValue ns);
void tjs__mod_process_init(JSContext *ctx, JSValue ns);
void tjs__mod_signals_init(JSContext *ctx, JSValue ns);
void tjs__mod_sqlite3_init(JSContext *ctx, JSValue ns);
void tjs__mod_streams_init(JSContext *ctx, JSValue ns);
void tjs__mod_timers_init(JSContext *ctx, JSValue ns);
void tjs__mod_udp_init(JSContext *ctx, JSValue ns);
void tjs__mod_worker_init(JSContext *ctx, JSValue ns);
void tjs__mod_http_init(JSContext *ctx, JSValue ns);
void tjs__mod_curl_init(JSContext* ctx, JSValue ns);
void tjs__mod_crypto_init(JSContext* ctx, JSValue ns);
void tjs__mod_console_init(JSContext *ctx, JSValue ns);
void tjs__mod_zlib_init(JSContext* ctx, JSValue ns);
void tjs__mod_sourcemap_init(JSContext* ctx, JSValue ns);
void tjs__mod_xml_init(JSContext *ctx, JSValue ns);
void tjs__mod_ssl_init(JSContext *ctx, JSValue ns);
void tjs__mod_socket_init(JSContext *ctx, JSValue ns);

#ifdef _WIN32
void tjs__mod_win32_init(JSContext *ctx, JSValue ns);
#endif

#ifdef CJS__HAS_ICONV
void tjs__mod_text_init(JSContext *ctx, JSValue ns);
#endif

#ifdef CJS__HAS_WASM
void tjs__mod_wasm_init(JSContext *ctx, JSValue ns);
#endif

JSValue tjs_new_error(JSContext *ctx, int err);
JSValue tjs_new_error_path(JSContext *ctx, int err, const char *path);
JSValue tjs_throw_errno(JSContext *ctx, int err);
JSValue tjs_throw_errno_path(JSContext *ctx, int err, const char *path);

JSValue tjs_new_pipe(JSContext *ctx);
uv_stream_t *tjs_pipe_get_stream(JSContext *ctx, JSValue obj);
uv_pipe_t *tjs_pipe_get_pipe(JSContext *ctx, JSValue obj);

void tjs__execute_jobs(TJSRuntime *trt);
int tjs__load_file(JSContext *ctx, DynBuf *dbuf, const char *filename);

JSValue tjs__module_use(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic, JSValueConst* value);
JSValue tjs__module_register(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);
JSValue tjs__mod_list_init(JSContext* ctx);

JSModuleDef *tjs__module_loader(JSContext *ctx, const char *module_name, void *opaque, JSValueConst attributes);
char *tjs__module_normalizer(JSContext *ctx, const char *base_name, const char *name, void *opaque);
int tjs__module_checkattr(JSContext *ctx, void *opaque, JSValueConst attributes);

int js_module_set_import_meta(JSContext *ctx, JSValue func_val, bool use_realpath, bool is_main);

JSValue tjs__get_args(JSContext *ctx);
void tjs__run_main(TJSRuntime* qrt);
void tjs__destroy_timers(TJSRuntime *qrt);

void tjs__sab_free(void *opaque, void *ptr);
void tjs__sab_dup(void *opaque, void *ptr);

// Warn: will not dup, use JS_Dup if you want to keep it alive
JSModuleDef* tjs__module_getdef(JSContext* ctx, JSValueConst this_val);
JSValue tjs__new_module(JSContext* ctx, JSModuleDef* def);
SSL_CTX* tjs__sslctx_get(JSContext *ctx, JSValueConst obj);

JSValue tjs__dispatch_event(JSContext *ctx, TJSEvents evname, JSValue data);
void tjs__dispatch_event2(JSContext *ctx, TJSEvents evname, JSValue data);
#endif
