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
#include "capability.h"
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
    #include <psapi.h>
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
    #include <sys/resource.h>
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

typedef struct TJSProcess TJSProcess;

#ifndef _WIN32

typedef struct TJSProcessReapTask {
    pid_t pid;
    bool terminate;
    struct TJSProcessReapTask *next;
} TJSProcessReapTask;

static uv_once_t tjs_process_reaper_once = UV_ONCE_INIT;
static uv_mutex_t tjs_process_reaper_mutex;
static uv_cond_t tjs_process_reaper_cond;
static uv_thread_t tjs_process_reaper_thread;
static TJSProcessReapTask *tjs_process_reaper_head;
static TJSProcessReapTask *tjs_process_reaper_tail;
static size_t tjs_process_reaper_reservations;
static bool tjs_process_reaper_active;
static bool tjs_process_reaper_joinable;
static bool tjs_process_fork_in_progress;
static int tjs_process_reaper_init_error;

static void process_reaper_init(void) {
    tjs_process_reaper_init_error = uv_mutex_init(&tjs_process_reaper_mutex);
    if (tjs_process_reaper_init_error != 0) return;
    tjs_process_reaper_init_error = uv_cond_init(&tjs_process_reaper_cond);
    if (tjs_process_reaper_init_error != 0)
        uv_mutex_destroy(&tjs_process_reaper_mutex);
}

static void process_reaper_worker(void *arg) {
    (void)arg;
    uv_mutex_lock(&tjs_process_reaper_mutex);

    for (;;) {
        TJSProcessReapTask *completed = NULL;
        TJSProcessReapTask **completed_tail = &completed;
        TJSProcessReapTask **link = &tjs_process_reaper_head;
        TJSProcessReapTask *previous = NULL;
        bool pending = false;

        while (*link) {
            TJSProcessReapTask *task = *link;
            pid_t result;
            if (task->terminate) {
                int kill_result;
                do {
                    kill_result = kill(task->pid, SIGKILL);
                } while (kill_result != 0 && errno == EINTR);
                /* ESRCH means the child already exited; other errors leave
                 * waitpid as the ownership-preserving fallback. */
                task->terminate = false;
            }
            do {
                result = waitpid(task->pid, NULL, WNOHANG);
            } while (result < 0 && errno == EINTR);

            if (result == task->pid || (result < 0 && errno == ECHILD)) {
                *link = task->next;
                if (tjs_process_reaper_tail == task)
                    tjs_process_reaper_tail = previous;
                task->next = NULL;
                *completed_tail = task;
                completed_tail = &task->next;
                CHECK_GT(tjs_process_reaper_reservations, 0);
                tjs_process_reaper_reservations--;
                continue;
            }

            pending = true;
            previous = task;
            link = &task->next;
        }

        while (completed) {
            TJSProcessReapTask *task = completed;
            completed = task->next;
            tjs__free(task);
        }

        if (tjs_process_reaper_reservations == 0) {
            CHECK_NULL(tjs_process_reaper_head);
            tjs_process_reaper_tail = NULL;
            tjs_process_reaper_active = false;
            uv_cond_broadcast(&tjs_process_reaper_cond);
            uv_mutex_unlock(&tjs_process_reaper_mutex);
            return;
        }

        if (pending) {
            (void)uv_cond_timedwait(&tjs_process_reaper_cond,
                                    &tjs_process_reaper_mutex,
                                    20 * 1000 * 1000);
        } else {
            uv_cond_wait(&tjs_process_reaper_cond,
                         &tjs_process_reaper_mutex);
        }
    }
}

static int process_reaper_reserve(TJSProcess *p);
static void process_reaper_release(TJSProcess *p);
static void process_reaper_adopt(TJSProcess *p, bool terminate);
static int process_reaper_adopt_pid(pid_t pid);
static int process_reaper_fork_prepare(void);
static void process_reaper_fork_finish(void);
#endif


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


/* Modes: normal (uv_process_t + Pipe objects), PTY (fork+openpty / ConPTY),
 * raw fork (waitpid + timer). p->process is NOT initialized in PTY/fork. */
static thread_local struct list_head tjs_fork_processes;
static thread_local bool tjs_fork_processes_initialized;
static thread_local size_t tjs_live_nonfork_processes;

static JSClassID tjs_process_class_id;
static JSClassDef tjs_process_class;

static int tjs_process_register_class(JSContext *ctx) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSClassID class_id = JS_NewClassID(rt, &tjs_process_class_id);
    if (class_id == JS_INVALID_CLASS_ID) {
        JS_ThrowInternalError(ctx, "failed to allocate Process class ID");
        return -1;
    }
    if (!JS_IsRegisteredClass(rt, class_id) &&
        JS_NewClass(rt, class_id, &tjs_process_class) < 0) {
        JS_ThrowInternalError(ctx, "failed to register Process class");
        return -1;
    }
    return 0;
}

struct TJSProcess {
    TJSRuntime *trt;
    JSContext *ctx;
    JSValue    obj;        /* GC pin while live; intentionally omitted from gc_mark */
    bool pty_mode;
    bool fork_mode;
    bool handle_initialized;
    bool process_spawned;
    bool closed;
    bool finalized;
    bool counted_nonfork;
    uv_process_t process;  /* normal mode only */
    JSValue stdio[3];      /* normal mode: stdin/stdout/stderr Pipe objects */
    JSValue stdio_extra;   /* normal mode: extra fd pipes, indexed by fd */
    JSValue ipc_pipe;      /* IPC channel pipe (fd 3) */
    struct {
        bool    exited;
        bool    lost;
        int64_t exit_status;
        int     term_signal;
        int     wait_error;
        TJSPromise result;
    } status;

    /* PTY-mode fields */
    pid_t   pty_pid;
    JSValue pty_readable;
    JSValue pty_writable;
    int     pty_cols;
    int     pty_rows;
    uv_timer_t pty_waiter;
    pid_t   fork_pid;
    pid_t   fork_owner_pid;
    uv_timer_t fork_waiter;
    struct list_head fork_link;
    bool    fork_linked;
    struct list_head runtime_link;
    bool    runtime_linked;
    bool    runtime_cleanup_queued;
    bool    runtime_cleaning;
#ifndef _WIN32
    TJSProcessReapTask *reaper_task;
#endif
#ifdef _WIN32
    HPCON  hpc;
    HANDLE pty_proc_handle; /* kept for waitSync */
#else
    int master_fd;  /* ioctl target; libuv owns the fd via pty_readable */
#endif
};

static void process_list_add(TJSProcess *p) {
    init_list_head(&p->runtime_link);
    list_add(&p->runtime_link, &p->trt->processes);
    p->runtime_linked = true;
    p->runtime_cleanup_queued = false;
}

static void process_list_remove(TJSProcess *p) {
    if (!p->runtime_linked) return;
    list_del(&p->runtime_link);
    p->runtime_linked = false;
}

#ifdef _WIN32
typedef struct {
    HANDLE handle;
} TJSProcessWaitTask;

static void process_windows_wait_worker(void *arg) {
    TJSProcessWaitTask *task = arg;
    (void) WaitForSingleObject(task->handle, INFINITE);
    CloseHandle(task->handle);
    tjs__free(task);
}

/* Runtime teardown may outlive the JS Process wrapper. Transfer the process
 * handle to a detached waiter instead of closing it while the child is live. */
static int process_windows_adopt_wait(HANDLE handle, bool *consumed) {
    TJSProcessWaitTask *task;
    uv_thread_t thread;

    *consumed = false;
    if (!handle || handle == INVALID_HANDLE_VALUE) return UV_EINVAL;
    task = tjs__mallocz(sizeof(*task));
    if (!task) return UV_ENOMEM;
    task->handle = handle;

    int r = uv_thread_create(&thread, process_windows_wait_worker, task);
    if (r != 0) {
        tjs__free(task);
        return r;
    }
    *consumed = true;
    r = uv_thread_detach(&thread);
    if (r != 0) {
        /* The thread owns task after creation; joining is the only safe way
         * to reclaim it if the platform refuses to detach the thread. */
        (void) uv_thread_join(&thread);
        return r;
    }
    return 0;
}

/* The caller must clear its handle after this returns. If the detached waiter
 * could not be created, wait synchronously so the live process handle is still
 * accounted for rather than being closed under a running child. */
static void process_windows_relinquish_failed_handle(HANDLE *handle) {
    bool consumed = false;
    int r = process_windows_adopt_wait(*handle, &consumed);
    if (consumed) {
        *handle = NULL;
        return;
    }
    if (r != 0) {
        (void) WaitForSingleObject(*handle, INFINITE);
        CloseHandle(*handle);
    }
    *handle = NULL;
}

/* Keep a normal uv_process_t's handle valid for libuv while a duplicate is
 * watched independently. This is needed when uv_process_kill() fails: closing
 * the uv handle alone would otherwise abandon a still-running child. */
static void process_windows_preserve_process_until_exit(HANDLE handle) {
    HANDLE duplicate = NULL;
    bool consumed = false;

    if (!handle || handle == INVALID_HANDLE_VALUE) return;
    if (DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(),
                        &duplicate, SYNCHRONIZE, FALSE, 0)) {
        int r = process_windows_adopt_wait(duplicate, &consumed);
        if (!consumed) {
            (void) WaitForSingleObject(duplicate, INFINITE);
            CloseHandle(duplicate);
        } else if (r != 0) {
            /* A failed detach still leaves ownership with the worker/join path. */
        }
        return;
    }

    /* Preserve ownership even if duplicating or creating a waiter is not
     * possible. The original handle remains owned by libuv and is closed only
     * after this bounded-to-exit fallback returns. */
    (void) WaitForSingleObject(handle, INFINITE);
}

static int process_reaper_reserve(TJSProcess *p) {
    (void)p;
    return 0;
}

static void process_reaper_release(TJSProcess *p) {
    (void)p;
}

static void process_reaper_adopt(TJSProcess *p, bool terminate) {
    (void)p;
    (void)terminate;
}
#else
static int process_reaper_reserve(TJSProcess *p) {
    TJSProcessReapTask *task = tjs__mallocz(sizeof(*task));
    if (!task) return UV_ENOMEM;

    uv_once(&tjs_process_reaper_once, process_reaper_init);
    if (tjs_process_reaper_init_error != 0) {
        tjs__free(task);
        return tjs_process_reaper_init_error;
    }
    uv_mutex_lock(&tjs_process_reaper_mutex);
    if (tjs_process_fork_in_progress) {
        uv_mutex_unlock(&tjs_process_reaper_mutex);
        tjs__free(task);
        return UV_EBUSY;
    }

    CHECK_NULL(p->reaper_task);
    int r = 0;
    if (!tjs_process_reaper_active) {
        if (tjs_process_reaper_joinable) {
            r = uv_thread_join(&tjs_process_reaper_thread);
            if (r != 0) {
                uv_mutex_unlock(&tjs_process_reaper_mutex);
                tjs__free(task);
                return r;
            }
            tjs_process_reaper_joinable = false;
        }

        tjs_process_reaper_active = true;
        tjs_process_reaper_reservations++;
        r = uv_thread_create(&tjs_process_reaper_thread,
                             process_reaper_worker, NULL);
        if (r != 0) {
            tjs_process_reaper_active = false;
            tjs_process_reaper_reservations--;
            uv_mutex_unlock(&tjs_process_reaper_mutex);
            tjs__free(task);
            return r;
        }
        tjs_process_reaper_joinable = true;
    } else {
        tjs_process_reaper_reservations++;
    }

    p->reaper_task = task;
    uv_mutex_unlock(&tjs_process_reaper_mutex);
    return 0;
}

static void process_reaper_release(TJSProcess *p) {
    TJSProcessReapTask *task = p->reaper_task;
    if (!task) return;
    p->reaper_task = NULL;

    uv_mutex_lock(&tjs_process_reaper_mutex);
    CHECK_GT(tjs_process_reaper_reservations, 0);
    tjs_process_reaper_reservations--;
    uv_cond_signal(&tjs_process_reaper_cond);
    uv_mutex_unlock(&tjs_process_reaper_mutex);
    tjs__free(task);
}

static void process_reaper_adopt(TJSProcess *p, bool terminate) {
    TJSProcessReapTask *task = p->reaper_task;
    if (!task) return;
    p->reaper_task = NULL;

    uv_mutex_lock(&tjs_process_reaper_mutex);
    CHECK(tjs_process_reaper_active);
    CHECK_GT(tjs_process_reaper_reservations, 0);
    task->pid = p->process.pid;
    task->terminate = terminate;
    if (tjs_process_reaper_tail)
        tjs_process_reaper_tail->next = task;
    else
        tjs_process_reaper_head = task;
    tjs_process_reaper_tail = task;
    uv_cond_signal(&tjs_process_reaper_cond);
    uv_mutex_unlock(&tjs_process_reaper_mutex);
}

static int process_reaper_adopt_pid(pid_t pid) {
    TJSProcessReapTask *task;

    if (pid <= 0) return UV_EINVAL;
    task = tjs__mallocz(sizeof(*task));
    if (!task) return UV_ENOMEM;

    uv_once(&tjs_process_reaper_once, process_reaper_init);
    if (tjs_process_reaper_init_error != 0) {
        tjs__free(task);
        return tjs_process_reaper_init_error;
    }

    uv_mutex_lock(&tjs_process_reaper_mutex);
    if (tjs_process_fork_in_progress) {
        uv_mutex_unlock(&tjs_process_reaper_mutex);
        tjs__free(task);
        return UV_EBUSY;
    }

    int r = 0;
    if (!tjs_process_reaper_active) {
        if (tjs_process_reaper_joinable) {
            r = uv_thread_join(&tjs_process_reaper_thread);
            if (r != 0) {
                uv_mutex_unlock(&tjs_process_reaper_mutex);
                tjs__free(task);
                return r;
            }
            tjs_process_reaper_joinable = false;
        }

        tjs_process_reaper_active = true;
        tjs_process_reaper_reservations++;
        r = uv_thread_create(&tjs_process_reaper_thread,
                             process_reaper_worker, NULL);
        if (r != 0) {
            tjs_process_reaper_active = false;
            tjs_process_reaper_reservations--;
            uv_mutex_unlock(&tjs_process_reaper_mutex);
            tjs__free(task);
            return r;
        }
        tjs_process_reaper_joinable = true;
    } else {
        tjs_process_reaper_reservations++;
    }

    task->pid = pid;
    task->terminate = true;
    if (tjs_process_reaper_tail)
        tjs_process_reaper_tail->next = task;
    else
        tjs_process_reaper_head = task;
    tjs_process_reaper_tail = task;
    uv_cond_signal(&tjs_process_reaper_cond);
    uv_mutex_unlock(&tjs_process_reaper_mutex);
    return 0;
}

static int process_reaper_fork_prepare(void) {
    uv_once(&tjs_process_reaper_once, process_reaper_init);
    if (tjs_process_reaper_init_error != 0)
        return tjs_process_reaper_init_error;
    uv_mutex_lock(&tjs_process_reaper_mutex);
    if (tjs_process_fork_in_progress || tjs_process_reaper_reservations != 0) {
        uv_mutex_unlock(&tjs_process_reaper_mutex);
        return UV_EBUSY;
    }

    tjs_process_fork_in_progress = true;
    if (tjs_process_reaper_joinable) {
        uv_cond_broadcast(&tjs_process_reaper_cond);
        uv_thread_t thread = tjs_process_reaper_thread;
        uv_mutex_unlock(&tjs_process_reaper_mutex);
        int r = uv_thread_join(&thread);
        uv_mutex_lock(&tjs_process_reaper_mutex);
        if (r != 0) {
            tjs_process_fork_in_progress = false;
            uv_mutex_unlock(&tjs_process_reaper_mutex);
            return r;
        }
        tjs_process_reaper_active = false;
        tjs_process_reaper_joinable = false;
    }
    if (tjs_process_reaper_head || tjs_process_reaper_reservations != 0) {
        tjs_process_fork_in_progress = false;
        uv_mutex_unlock(&tjs_process_reaper_mutex);
        return UV_EBUSY;
    }
    uv_mutex_unlock(&tjs_process_reaper_mutex);
    return 0;
}

static void process_reaper_fork_finish(void) {
    uv_mutex_lock(&tjs_process_reaper_mutex);
    CHECK(tjs_process_fork_in_progress);
    tjs_process_fork_in_progress = false;
    uv_cond_broadcast(&tjs_process_reaper_cond);
    uv_mutex_unlock(&tjs_process_reaper_mutex);
}
#endif

#ifdef _WIN32
static WCHAR *spawn_sync_utf8_to_wide(JSContext *ctx, const char *s);
static WCHAR *spawn_sync_resolve_win_app(JSContext *ctx, const WCHAR *app);
static WCHAR *spawn_sync_build_win_cmdline(JSContext *ctx, char **args, bool verbatim);
static WCHAR *spawn_sync_build_win_env(JSContext *ctx, char **env);
#endif

static JSValue make_exit_obj(JSContext *ctx, int64_t es, int ts) {
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    JS_DefinePropertyValueStr(ctx, obj, "exit_status", JS_NewInt64(ctx, es), JS_PROP_C_W_E);
    JSValue sig = ts == 0 ? JS_NULL : JS_NewInt32(ctx, ts);
    JS_DefinePropertyValueStr(ctx, obj, "term_signal", sig, JS_PROP_C_W_E);
    return obj;
}

static JSValue make_rusage_obj(JSContext *ctx, const uv_rusage_t *usage) {
    if (!usage) return JS_UNDEFINED;

    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    uint64_t user_us = (uint64_t)usage->ru_utime.tv_sec * 1000000ULL
        + (uint64_t)usage->ru_utime.tv_usec;
    uint64_t system_us = (uint64_t)usage->ru_stime.tv_sec * 1000000ULL
        + (uint64_t)usage->ru_stime.tv_usec;
    JSValue user = JS_NewBigUint64(ctx, user_us);
    JSValue system = JS_NewBigUint64(ctx, system_us);
    if (JS_IsException(obj) || JS_IsException(user) || JS_IsException(system)) {
        JS_FreeValue(ctx, obj);
        JS_FreeValue(ctx, user);
        JS_FreeValue(ctx, system);
        return JS_EXCEPTION;
    }

#define SET_U64(target, name, value)                                           \
    JS_DefinePropertyValueStr(ctx, target, name,                               \
                              JS_NewInt64(ctx, (int64_t)(value)), JS_PROP_C_W_E)

    JSValue switches = JS_NewObjectProto(ctx, JS_NULL);
    SET_U64(switches, "voluntary", usage->ru_nvcsw);
    SET_U64(switches, "involuntary", usage->ru_nivcsw);
    JS_DefinePropertyValueStr(ctx, obj, "contextSwitches", switches, JS_PROP_C_W_E);

    JSValue cpu = JS_NewObjectProto(ctx, JS_NULL);
    JS_DefinePropertyValueStr(ctx, cpu, "user", JS_DupValue(ctx, user), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, cpu, "system", JS_DupValue(ctx, system), JS_PROP_C_W_E);
    JSValue sum = JS_NewBigUint64(ctx, user_us + system_us);
    JS_FreeValue(ctx, user);
    JS_FreeValue(ctx, system);
    if (JS_IsException(sum)) {
        JS_FreeValue(ctx, cpu);
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_DefinePropertyValueStr(ctx, cpu, "total", sum, JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "cpuTime", cpu, JS_PROP_C_W_E);

    SET_U64(obj, "maxRSS", usage->ru_maxrss);
    JSValue messages = JS_NewObjectProto(ctx, JS_NULL);
    SET_U64(messages, "sent", usage->ru_msgsnd);
    SET_U64(messages, "received", usage->ru_msgrcv);
    JS_DefinePropertyValueStr(ctx, obj, "messages", messages, JS_PROP_C_W_E);
    JSValue ops = JS_NewObjectProto(ctx, JS_NULL);
    SET_U64(ops, "in", usage->ru_inblock);
    SET_U64(ops, "out", usage->ru_oublock);
    JS_DefinePropertyValueStr(ctx, obj, "ops", ops, JS_PROP_C_W_E);
    SET_U64(obj, "shmSize", usage->ru_ixrss);
    SET_U64(obj, "signalCount", usage->ru_nsignals);
    SET_U64(obj, "swapCount", usage->ru_nswap);
#undef SET_U64
    return obj;
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
        if (!key) goto fail;
        JSValue pv = JS_GetProperty(ctx, js_env, ptab[i].atom);
        if (JS_IsException(pv)) {
            JS_FreeValue(ctx, pv);
            JS_FreeCString(ctx, key);
            goto fail;
        }
        const char *val = JS_ToCString(ctx, pv);
        JS_FreeValue(ctx, pv);
        if (!val) {
            JS_FreeCString(ctx, key);
            goto fail;
        }
        size_t key_len = strlen(key), val_len = strlen(val);
        if (key_len > SIZE_MAX - val_len - 2) {
            JS_ThrowRangeError(ctx, "environment entry is too large");
            JS_FreeCString(ctx, key);
            JS_FreeCString(ctx, val);
            goto fail;
        }
        size_t len = key_len + val_len + 2;
        env[n] = js_malloc(ctx, len);
        if (!env[n]) {
            JS_FreeCString(ctx, key);
            JS_FreeCString(ctx, val);
            goto fail;
        }
        snprintf(env[n], len, "%s=%s", key, val);
        n++;
        JS_FreeCString(ctx, key);
        JS_FreeCString(ctx, val);
    }
    JS_FreePropertyEnum(ctx, ptab, plen);
    return env;

fail:
    for (int i = 0; i < n; i++) js_free(ctx, env[i]);
    js_free(ctx, env);
    JS_FreePropertyEnum(ctx, ptab, plen);
    return NULL;
}

static inline char **empty_env(JSContext *ctx) {
    return js_mallocz(ctx, sizeof(char *));
}

static inline void free_env(JSContext *ctx, char **env) {
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

static int parse_extra_stdio(JSContext *ctx, uv_process_options_t *options, uv_stdio_container_t stdio[3], uv_stdio_container_t **stdio_heap, JSValue js_extra, bool *present) {
    *present = false;
    if (!JS_IsArray(js_extra)) return 0;

    JSValue js_len = JS_GetPropertyStr(ctx, js_extra, "length");
    uint64_t extra_len;
    if (JS_ToIndex(ctx, &extra_len, js_len)) {
        JS_FreeValue(ctx, js_len);
        return -1;
    }
    JS_FreeValue(ctx, js_len);
    if (extra_len == 0) return 0;
    *present = true;
    if (extra_len > 253) {
        JS_ThrowRangeError(ctx, "stdioExtra cannot contain more than 253 entries");
        return -1;
    }

    int stdio_count = (int)extra_len + 3;
    if (ensure_stdio_capacity(ctx, options, stdio, stdio_heap, stdio_count) < 0) {
        JS_ThrowOutOfMemory(ctx);
        return -1;
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
            options->stdio[fd].flags = UV_CREATE_PIPE | UV_READABLE_PIPE | UV_WRITABLE_PIPE;
            options->stdio[fd].data.stream = NULL;
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

static int parse_stdio_option(JSContext *ctx, JSValue opts,
                              const char *name, int idx,
                              unsigned pipe_flag, int default_fd,
                              uv_process_options_t *options) {
    JSValue value = JS_GetPropertyStr(ctx, opts, name);
    if (JS_IsException(value)) {
        JS_FreeValue(ctx, value);
        return -1;
    }
    if (JS_IsUndefined(value)) {
        JS_FreeValue(ctx, value);
        return 0;
    }

    const char *mode = JS_ToCString(ctx, value);
    JS_FreeValue(ctx, value);
    if (!mode) return -1;

    if (strcmp(mode, "pipe") == 0) {
        options->stdio[idx].flags = UV_CREATE_PIPE | pipe_flag;
        options->stdio[idx].data.stream = NULL;
    } else if (strcmp(mode, "ignore") == 0) {
        options->stdio[idx].flags = UV_IGNORE;
    } else if (strcmp(mode, "inherit") == 0) {
        options->stdio[idx].flags = UV_INHERIT_FD;
        options->stdio[idx].data.fd = default_fd;
    } else {
        options->stdio[idx].flags = UV_INHERIT_FD;
        options->stdio[idx].data.fd = default_fd;
    }
    JS_FreeCString(ctx, mode);
    return 0;
}

static int materialize_spawn_stdio(JSContext *ctx, TJSProcess *p,
                                   uv_process_options_t *options,
                                   bool has_stdio_extra,
                                   bool use_ipc,
                                   uint32_t ipc_fd) {
    if (has_stdio_extra) {
        p->stdio_extra = JS_NewArray(ctx);
        if (JS_IsException(p->stdio_extra)) return -1;
        for (uint32_t fd = 0; fd < options->stdio_count; fd++) {
            if (JS_SetPropertyUint32(ctx, p->stdio_extra, fd, JS_NULL) < 0)
                return -1;
        }
    }

    for (uint32_t fd = 0; fd < options->stdio_count; fd++) {
        if (use_ipc && fd == ipc_fd) continue;
        if (!(options->stdio[fd].flags & UV_CREATE_PIPE)) continue;

        JSValue pipe_obj = tjs_new_pipe(ctx);
        if (JS_IsException(pipe_obj)) return -1;
        uv_stream_t *stream = tjs_pipe_get_stream(ctx, pipe_obj);
        if (!stream) {
            JS_FreeValue(ctx, pipe_obj);
            if (!JS_HasException(ctx))
                tjs_throw_plain_error(ctx, "failed to create stdio pipe");
            return -1;
        }
        options->stdio[fd].data.stream = stream;
        if (fd < 3) {
            p->stdio[fd] = pipe_obj;
        } else if (!JS_IsUndefined(p->stdio_extra)) {
            if (JS_SetPropertyUint32(ctx, p->stdio_extra, fd, pipe_obj) < 0)
                return -1;
        } else {
            JS_FreeValue(ctx, pipe_obj);
            tjs_throw_plain_error(ctx, "extra stdio pipe has no owner");
            return -1;
        }
    }
    return 0;
}

static void free_str_arr(JSContext *ctx, char **arr, int len);
static int process_argv_length(JSContext *ctx, JSValue array, uint64_t *len_out);

/* Build a NULL-terminated argv array from a JS array.  Uses js_malloc / js_strdup. */
static char **parse_argv_arr(JSContext *ctx, JSValue js_arr, int *len_out) {
    *len_out = 0;
    uint64_t len64;
    if (process_argv_length(ctx, js_arr, &len64) < 0) {
        *len_out = -1;
        return NULL;
    }
    if (len64 == 0) return NULL;
    int32_t len = (int32_t)len64;
    char **arr = js_mallocz(ctx, sizeof(char *) * ((size_t)len + 1));
    if (!arr) {
        *len_out = -1;
        return NULL;
    }
    int n = 0;
    for (int32_t i = 0; i < len; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, js_arr, (uint32_t)i);
        if (JS_IsException(item)) {
            free_str_arr(ctx, arr, n);
            *len_out = -1;
            return NULL;
        }
        const char *s = JS_ToCString(ctx, item);
        JS_FreeValue(ctx, item);
        if (!s) {
            free_str_arr(ctx, arr, n);
            *len_out = -1;
            return NULL;
        }
        arr[n] = js_strdup(ctx, s);
        JS_FreeCString(ctx, s);
        if (!arr[n]) {
            free_str_arr(ctx, arr, n);
            *len_out = -1;
            return NULL;
        }
        n++;
    }
    *len_out = n;
    return arr;
}

static int bool_prop(JSContext *ctx, JSValue obj, const char *name, bool *out) {
    *out = false;
    if (!JS_IsObject(obj)) return 0;
    JSValue val = JS_GetPropertyStr(ctx, obj, name);
    if (JS_IsException(val)) {
        JS_FreeValue(ctx, val);
        return -1;
    }
    int ret = JS_ToBool(ctx, val);
    JS_FreeValue(ctx, val);
    if (ret < 0) return -1;
    *out = ret != 0;
    return 0;
}

static void free_str_arr(JSContext *ctx, char **arr, int len) {
    if (!arr) return;
    for (int i = 0; i < len; i++) js_free(ctx, arr[i]);
    js_free(ctx, arr);
}

static int process_argv_length(JSContext *ctx, JSValue array, uint64_t *len_out) {
    JSValue length = JS_GetPropertyStr(ctx, array, "length");
    uint64_t len;
    if (JS_IsException(length) || JS_ToIndex(ctx, &len, length) < 0) {
        JS_FreeValue(ctx, length);
        return -1;
    }
    JS_FreeValue(ctx, length);
    if (len > INT_MAX || len > (uint64_t)(SIZE_MAX / sizeof(char *) - 1)) {
        JS_ThrowRangeError(ctx, "argv array is too large");
        return -1;
    }
    *len_out = len;
    return 0;
}

static char **tjs__parse_args(JSContext *ctx, JSValue arg0);
static void tjs__free_args(JSContext *ctx, char **args);

/* Read { cols, rows } from a JS options object, with defaults. */
static int parse_winsize(JSContext *ctx, JSValue opts, int *cols, int *rows) {
    *cols = 80; *rows = 24;
    if (!JS_IsObject(opts)) return 0;
    JSValue v;
    v = JS_GetPropertyStr(ctx, opts, "cols");
    if (JS_IsException(v)) { JS_FreeValue(ctx, v); return -1; }
    if (JS_IsNumber(v)) {
        int32_t n;
        if (JS_ToInt32(ctx, &n, v) < 0) { JS_FreeValue(ctx, v); return -1; }
        *cols = n;
    }
    JS_FreeValue(ctx, v);
    v = JS_GetPropertyStr(ctx, opts, "rows");
    if (JS_IsException(v)) { JS_FreeValue(ctx, v); return -1; }
    if (JS_IsNumber(v)) {
        int32_t n;
        if (JS_ToInt32(ctx, &n, v) < 0) { JS_FreeValue(ctx, v); return -1; }
        *rows = n;
    }
    JS_FreeValue(ctx, v);
    return 0;
}

static inline TJSProcess *tjs_process_get(JSContext *ctx, JSValue obj) {
    JSClassID class_id = tjs_process_class_id;
    if (class_id == 0) {
        JS_ThrowTypeError(ctx, "invalid process runtime");
        return NULL;
    }
    return JS_GetOpaque2(ctx, obj, class_id);
}

static TJSProcess *tjs_process_new(JSContext *ctx, JSValue *obj_out) {
    JSClassID class_id = tjs_process_class_id;
    if (class_id == 0) {
        *obj_out = JS_ThrowTypeError(ctx, "process module is not initialized");
        return NULL;
    }
    JSValue obj = JS_NewObjectClass(ctx, class_id);
    if (JS_IsException(obj)) {
        *obj_out = obj;
        return NULL;
    }

    TJSProcess *p = tjs__mallocz(sizeof(*p));
    if (!p) {
        JS_FreeValue(ctx, obj);
        *obj_out = JS_ThrowOutOfMemory(ctx);
        return NULL;
    }

    p->trt           = TJS_GetRuntime(ctx);
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
    process_list_add(p);
    *obj_out = obj;
    return p;
}

static void uv__proc_close_cb(uv_handle_t *handle) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    p->closed = true;
    if (p->counted_nonfork) {
        CHECK_GT(tjs_live_nonfork_processes, 0);
        tjs_live_nonfork_processes--;
        p->counted_nonfork = false;
    }
    if (p->fork_linked) {
        list_del(&p->fork_link);
        p->fork_linked = false;
    }
    if (p->finalized) {
        process_list_remove(p);
        tjs__free(p);
    }
}

static void maybe_close(TJSProcess *p) {
    if (!p->handle_initialized) return;
    uv_handle_t *handle;
    if (p->fork_mode)
        handle = (uv_handle_t *)&p->fork_waiter;
    else if (p->pty_mode)
        handle = (uv_handle_t *)&p->pty_waiter;
    else
        handle = (uv_handle_t *)&p->process;
    if (!uv_is_closing(handle))
        uv_close(handle, uv__proc_close_cb);
}

#ifdef _WIN32
/* Null hpc first so the finalizer and exit path both become no-ops. */
static void pty_win_close_hpcon(TJSProcess *p) {
    HPCON hpc = p->hpc;
    p->hpc = NULL;
    if (hpc && pClosePseudoConsole) pClosePseudoConsole(hpc);
}

static void process_windows_close_pty_handle(TJSProcess *p) {
    HANDLE handle = p->pty_proc_handle;
    p->pty_proc_handle = NULL;
    if (handle) CloseHandle(handle);
}
#endif

static void process_finish(TJSProcess *p, int64_t exit_status, int term_signal) {
    if (p->status.exited || p->status.lost) return;

    process_reaper_release(p);
    p->status.exited = true;
    p->status.exit_status = exit_status;
    p->status.term_signal = term_signal;

#ifdef _WIN32
    /* Reached only after the child is confirmed dead; close before the
     * promise settles so EOF is already in flight when JS sees the exit. */
    if (p->pty_mode) {
        pty_win_close_hpcon(p);
        process_windows_close_pty_handle(p);
    }
#endif

    if (p->trt && p->trt->freeing) {
        process_list_remove(p);
        maybe_close(p);
        return;
    }

    if (!JS_IsUndefined(p->status.result.p)) {
        JSValue arg = make_exit_obj(p->ctx, exit_status, term_signal);
        TJS_SettlePromise(p->ctx, &p->status.result, false, 1, &arg);
    }

    maybe_close(p);
    process_list_remove(p);
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

static int process_no_child_error(void) {
#ifdef _WIN32
    return UV_EIO;
#else
    return uv_translate_sys_error(ECHILD);
#endif
}

#ifdef _WIN32
static int process_windows_terminate_and_wait(HANDLE process_handle) {
    if (!process_handle) return UV_EINVAL;

    if (!TerminateProcess(process_handle, 1)) {
        DWORD terminate_error = GetLastError();
        DWORD wait_result = WaitForSingleObject(process_handle, 0);
        if (wait_result != WAIT_OBJECT_0) {
            if (wait_result == WAIT_FAILED)
                terminate_error = GetLastError();
            return uv_translate_sys_error((int)terminate_error);
        }
    }

    DWORD wait_result = WaitForSingleObject(process_handle, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        return uv_translate_sys_error((int)wait_error);
    }
    return 0;
}

static int process_windows_get_exit_code(HANDLE process_handle,
                                         int64_t *exit_status) {
    DWORD status;
    if (!process_handle) return UV_EINVAL;
    if (!GetExitCodeProcess(process_handle, &status))
        return uv_translate_sys_error(GetLastError());
    *exit_status = (int64_t)status;
    return 0;
}
#else
static int process_posix_kill_and_reap(pid_t pid, int64_t *exit_status,
                                       int *term_signal) {
    if (pid <= 0) return UV_EINVAL;

    if (kill(pid, SIGKILL) != 0) {
        int err = errno;
        if (err != ESRCH) return uv_translate_sys_error(err);
    }

    int status;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) {
        int err = waited < 0 ? uv_translate_sys_error(errno)
                             : process_no_child_error();
        return err;
    }

    int64_t ignored_exit_status;
    int ignored_term_signal;
    if (!exit_status) exit_status = &ignored_exit_status;
    if (!term_signal) term_signal = &ignored_term_signal;
    if (decode_wait_status(status, exit_status, term_signal) < 0)
        return process_no_child_error();
    return 0;
}

/* Last-resort cleanup when the asynchronous reaper cannot be started. The
 * caller still owns the child at this point, so a blocking wait is preferable
 * to dropping the PID and leaving a zombie behind. */
static int process_posix_force_reap(pid_t pid, int64_t *exit_status,
                                    int *term_signal) {
    if (pid <= 0) return UV_EINVAL;
    int kill_result;
    do {
        kill_result = kill(pid, SIGKILL);
    } while (kill_result != 0 && errno == EINTR);
    /* A failed SIGKILL does not transfer waitpid ownership. Still wait and
     * reap the child here; this is the last synchronous fallback after the
     * independent reaper could not be started. */

    int status;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) {
        int err = waited < 0 ? uv_translate_sys_error(errno)
                             : process_no_child_error();
        return err;
    }

    int64_t ignored_exit_status;
    int ignored_term_signal;
    if (!exit_status) exit_status = &ignored_exit_status;
    if (!term_signal) term_signal = &ignored_term_signal;
    if (decode_wait_status(status, exit_status, term_signal) < 0)
        return process_no_child_error();
    return 0;
}
#endif

static void process_mark_lost_impl(TJSProcess *p, int err, bool terminate_reaper);

static void process_mark_lost(TJSProcess *p, int err) {
    process_mark_lost_impl(p, err, true);
}

static void uv__pty_wait_cb(uv_timer_t *handle) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    if (p->status.exited || p->status.lost) return;

    int64_t exit_status = 0;
    int term_signal = 0;
#ifdef _WIN32
    DWORD wait_result = WaitForSingleObject(p->pty_proc_handle, 0);
    if (wait_result == WAIT_TIMEOUT) return;
    if (wait_result != WAIT_OBJECT_0) {
        DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        process_mark_lost(p, uv_translate_sys_error((int)wait_error));
        return;
    }
    int exit_code_result = process_windows_get_exit_code(p->pty_proc_handle,
                                                          &exit_status);
    if (exit_code_result != 0) {
        process_mark_lost(p, exit_code_result);
        return;
    }
#else
    int status;
    pid_t result;
    do {
        result = waitpid(p->pty_pid, &status, WNOHANG);
    } while (result < 0 && errno == EINTR);
    if (result == 0) return;
    if (result < 0) {
        process_mark_lost(p, uv_translate_sys_error(errno));
        return;
    }
    if (decode_wait_status(status, &exit_status, &term_signal) < 0) {
        process_mark_lost(p, process_no_child_error());
        return;
    }
#endif

    process_finish(p, exit_status, term_signal);
}

static JSValue make_fork_wait_error(TJSProcess *p, JSContext *ctx, int err) {
#ifndef _WIN32
    if (p->fork_mode && p->fork_owner_pid != getpid()) {
        tjs_throw_plain_error(ctx,
                              "ECHILD: forked process handle belongs to another process");
        return JS_GetException(ctx);
    }
#endif
    tjs_throw_errno(ctx, err);
    return JS_GetException(ctx);
}

static void process_mark_lost_impl(TJSProcess *p, int err, bool terminate_reaper) {
    if (p->status.exited || p->status.lost) return;
    p->status.lost = true;
    p->status.wait_error = err;

#ifdef _WIN32
    if (p->pty_mode && p->pty_proc_handle) {
        /* The wait handle is no longer usable on this path. Keep an
         * independent wait owner until the child exits before releasing it. */
        process_windows_preserve_process_until_exit(p->pty_proc_handle);
        process_windows_close_pty_handle(p);
    }
#endif

    if (p->process_spawned && !p->pty_mode && !p->fork_mode) {
#ifdef _WIN32
        if (err != UV_ESRCH)
            process_windows_preserve_process_until_exit(
                p->process.process_handle);
#endif
        /* Remove libuv's wait owner before waking the independent reaper. */
        maybe_close(p);
        process_reaper_adopt(p, terminate_reaper);
    }

    if (p->trt && p->trt->freeing) {
        process_list_remove(p);
        maybe_close(p);
        return;
    }

    if (!JS_IsUndefined(p->status.result.p)) {
        JSValue arg = make_fork_wait_error(p, p->ctx, err);
        TJS_SettlePromise(p->ctx, &p->status.result, true, 1, &arg);
    }

    maybe_close(p);
    process_list_remove(p);
    if (!JS_IsUndefined(p->obj)) {
        JSValue obj = p->obj;
        p->obj = JS_UNDEFINED;
        JS_FreeValue(p->ctx, obj);
    }
}

#ifndef _WIN32
/* A raw fork has no uv_process_t, so libuv cannot deliver the exit callback. */
static bool fork_handle_is_foreign(const TJSProcess *p) {
    return p->fork_mode && p->fork_owner_pid != getpid();
}

/* A later fork inherits Process wrappers whose PIDs are not children of the
 * new process; disarm the inherited timer so it cannot spin on ECHILD. */
static void fork_disown_in_child(TJSProcess *p) {
    uv_timer_stop(&p->fork_waiter);
    process_mark_lost(p, uv_translate_sys_error(ECHILD));
}

static void ensure_fork_process_list(void) {
    if (tjs_fork_processes_initialized) return;
    init_list_head(&tjs_fork_processes);
    tjs_fork_processes_initialized = true;
}

static void disown_inherited_fork_handles(void) {
    struct list_head *el, *tmp;
    list_for_each_safe(el, tmp, &tjs_fork_processes) {
        TJSProcess *p = list_entry(el, TJSProcess, fork_link);
        if (fork_handle_is_foreign(p)) fork_disown_in_child(p);
    }
}

static void uv__fork_wait_cb(uv_timer_t *handle) {
    TJSProcess *p = handle->data;
    CHECK_NOT_NULL(p);
    if (fork_handle_is_foreign(p)) {
        fork_disown_in_child(p);
        return;
    }
    if (p->status.exited) return;

    int status;
    pid_t result;
    do {
        result = waitpid(p->fork_pid, &status, WNOHANG);
    } while (result < 0 && errno == EINTR);

    if (result == 0) return;
    if (result < 0) {
        process_mark_lost(p, uv_translate_sys_error(errno));
        return;
    }

    int64_t exit_status = 0;
    int term_signal = 0;
    if (decode_wait_status(status, &exit_status, &term_signal) < 0) return;
    process_finish(p, exit_status, term_signal);
}
#endif

static void tjs_process_finalizer(JSRuntime *rt, JSValue val) {
    TJSProcess *p = JS_GetOpaque(val, JS_GetClassID(val));
    if (!p) return;

    /* p->obj pins this same Process wrapper while the child is alive. Once
     * QuickJS is finalizing the wrapper, only detach the pin. */
    p->obj = JS_UNDEFINED;
    TJS_FreePromiseRT(rt, &p->status.result);
    for (int i = 0; i < 3; i++) {
        JSValue value = p->stdio[i];
        p->stdio[i] = JS_UNDEFINED;
        JS_FreeValueRT(rt, value);
    }
    JSValue stdio_extra = p->stdio_extra;
    p->stdio_extra = JS_UNDEFINED;
    JS_FreeValueRT(rt, stdio_extra);
    JSValue ipc_pipe = p->ipc_pipe;
    p->ipc_pipe = JS_UNDEFINED;
    JS_FreeValueRT(rt, ipc_pipe);

    if (p->pty_mode) {
        JSValue pty_readable = p->pty_readable;
        JSValue pty_writable = p->pty_writable;
        p->pty_readable = JS_UNDEFINED;
        p->pty_writable = JS_UNDEFINED;
        JS_FreeValueRT(rt, pty_readable);
        JS_FreeValueRT(rt, pty_writable);
#ifdef _WIN32
        /* Normally already closed by process_finish(); this covers a wrapper
         * collected while the child is still running. */
        pty_win_close_hpcon(p);
#else
        /* master_fd is owned by libuv through pty_readable; do NOT close here */
#endif
    }

    p->finalized = true;
    if (p->trt && p->trt->freeing && p->runtime_cleanup_queued)
        return;
    if (!p->handle_initialized || p->closed) {
        process_list_remove(p);
        tjs__free(p);
    } else {
        /* A live child's waiter owns its native lifetime after the JS wrapper
         * is collected. Keep it open so process_finish() can reap the child
         * and close the Windows PTY handle on the confirmed-exit path. */
        if (p->status.exited || p->status.lost ||
            (!p->pty_mode && !p->fork_mode && !p->process_spawned))
            maybe_close(p);
    }
}

void tjs__mod_process_cleanup_runtime(TJSRuntime *trt) {
    struct list_head cleanup_list;
    init_list_head(&cleanup_list);

    /* Keep the live runtime list independent from JS refcount teardown. A
     * finalizer may remove a different process, so a cached next pointer is
     * not stable across JS_FreeValueRT(). */
    while (!list_empty(&trt->processes)) {
        TJSProcess *p = list_entry(trt->processes.next, TJSProcess,
                                   runtime_link);
        list_del(&p->runtime_link);
        p->runtime_cleanup_queued = true;
        list_add_tail(&p->runtime_link, &cleanup_list);
    }

    while (!list_empty(&cleanup_list)) {
        TJSProcess *p = list_entry(cleanup_list.next, TJSProcess,
                                   runtime_link);
        list_del(&p->runtime_link);
        p->runtime_linked = false;
        p->runtime_cleanup_queued = false;
        if (p->trt != trt || p->runtime_cleaning) continue;
        p->runtime_cleaning = true;
        JSValue obj = JS_UNDEFINED;
        bool keep_for_drain = false;

        TJS_FreePromiseRT(trt->rt, &p->status.result);
        for (int i = 0; i < 3; i++) {
            JS_FreeValueRT(trt->rt, p->stdio[i]);
            p->stdio[i] = JS_UNDEFINED;
        }
        JS_FreeValueRT(trt->rt, p->stdio_extra);
        p->stdio_extra = JS_UNDEFINED;
        JS_FreeValueRT(trt->rt, p->ipc_pipe);
        p->ipc_pipe = JS_UNDEFINED;
        JS_FreeValueRT(trt->rt, p->pty_readable);
        p->pty_readable = JS_UNDEFINED;
        JS_FreeValueRT(trt->rt, p->pty_writable);
        p->pty_writable = JS_UNDEFINED;

        if (p->status.exited || p->status.lost) {
            maybe_close(p);
        } else if (p->fork_mode || p->pty_mode) {
#ifdef _WIN32
            if (!p->pty_mode || !p->pty_proc_handle) {
                process_mark_lost(p, UV_EBADF);
                goto runtime_drop_process_pin;
            }
            int teardown_result = process_windows_terminate_and_wait(
                p->pty_proc_handle);
            if (teardown_result != 0) {
                process_windows_relinquish_failed_handle(&p->pty_proc_handle);
                process_mark_lost(p, teardown_result);
                goto runtime_drop_process_pin;
            }
            int exit_code_result = process_windows_get_exit_code(
                p->pty_proc_handle, &p->status.exit_status);
            if (exit_code_result != 0) {
                process_mark_lost(p, exit_code_result);
                goto runtime_drop_process_pin;
            }
            CloseHandle(p->pty_proc_handle);
            p->pty_proc_handle = NULL;
#else
            pid_t pid = p->fork_mode ? p->fork_pid : p->pty_pid;
            int teardown_result = process_posix_kill_and_reap(
                pid, &p->status.exit_status, &p->status.term_signal);
            if (teardown_result != 0) {
                if (teardown_result == process_no_child_error()) {
                    /* Another waiter owns the reap result; never hand this
                     * numeric PID to a later reaper after possible reuse. */
                    process_mark_lost(p, teardown_result);
                    goto runtime_drop_process_pin;
                }
                /* The synchronous helper may fail while the child is still
                 * alive. Keep waitpid ownership in the independent reaper
                 * before dropping the Process wrapper and its timer. */
                int adopt_result = process_reaper_adopt_pid(pid);
                if (adopt_result != 0) {
                    int reap_result = process_posix_force_reap(
                        pid, &p->status.exit_status, &p->status.term_signal);
                    if (reap_result == 0) {
                        process_finish(p, p->status.exit_status,
                                       p->status.term_signal);
                        goto runtime_drop_process_pin;
                    }
                    process_mark_lost(p, reap_result);
                } else {
                    process_mark_lost(p, teardown_result);
                }
                goto runtime_drop_process_pin;
            }
#endif
            p->status.exited = true;
#ifdef _WIN32
            if (p->pty_mode) pty_win_close_hpcon(p);
#endif
            if (p->handle_initialized) {
                if (p->fork_mode) uv_timer_stop(&p->fork_waiter);
                else uv_timer_stop(&p->pty_waiter);
            }
            maybe_close(p);
            process_list_remove(p);
        } else if (p->handle_initialized && p->process_spawned) {
#ifdef _WIN32
            int kill_result = uv_process_kill(&p->process, SIGTERM);
#else
            int kill_result = uv_process_kill(&p->process, SIGKILL);
#endif
            if (kill_result != 0)
                /* SIGKILL was already attempted on this path. Preserve
                 * waitpid ownership without issuing a redundant retry from
                 * the independent reaper. */
                process_mark_lost_impl(p, kill_result, false);
            keep_for_drain = !p->status.exited && !p->status.lost;
        }

        if (keep_for_drain)
            process_list_add(p);

runtime_drop_process_pin:
        /* Dropping the self pin may run the finalizer synchronously. Do not
         * inspect p after this point; a pending handle callback owns it. */
        obj = p->obj;
        p->obj = JS_UNDEFINED;
        JS_FreeValueRT(trt->rt, obj);
    }
}

static bool process_runtime_has_active_normal(TJSRuntime *trt) {
    struct list_head *el;
    list_for_each(el, &trt->processes) {
        TJSProcess *p = list_entry(el, TJSProcess, runtime_link);
        if (!p->pty_mode && !p->fork_mode && p->process_spawned &&
            !p->status.exited && !p->status.lost)
            return true;
    }
    return false;
}

void tjs__mod_process_drain_runtime(TJSRuntime *trt) {
    while (process_runtime_has_active_normal(trt)) {
        if (uv_run(&trt->loop, UV_RUN_ONCE) == 0) {
            /* A process handle that no longer keeps libuv alive cannot ever
             * produce the exit callback needed by the list above. Preserve a
             * bounded teardown even for a platform-specific kill failure. */
            struct list_head *el, *tmp;
            list_for_each_safe(el, tmp, &trt->processes) {
                TJSProcess *p = list_entry(el, TJSProcess, runtime_link);
                if (!p->pty_mode && !p->fork_mode && p->process_spawned &&
                    !p->status.exited && !p->status.lost)
                    process_mark_lost(p, process_no_child_error());
            }
            break;
        }
    }
}

static void tjs_process_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSProcess *p = JS_GetOpaque(val, JS_GetClassID(val));
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

#ifndef _WIN32
static JSValue pty_unix_spawn_abort(JSContext *ctx, JSValue error,
                                    int master_fd, pid_t pid) {
    if (master_fd >= 0) close(master_fd);
    int cleanup_result = process_posix_kill_and_reap(pid, NULL, NULL);
    if (cleanup_result != 0 && cleanup_result != process_no_child_error()) {
        int adopt_result = process_reaper_adopt_pid(pid);
        if (adopt_result != 0) {
            cleanup_result = process_posix_force_reap(pid, NULL, NULL);
            if (cleanup_result != 0) {
                JSValue pending = JS_GetException(ctx);
                JS_FreeValue(ctx, pending);
                return tjs_throw_errno_msg(ctx, cleanup_result,
                                           "PTY child cleanup failed");
            }
        }
    }
    return error;
}

static JSValue pty_unix_spawn(TJSProcess *p, JSContext *ctx,
                               const char *name, const char *cwd,
                               char **env_arr, char **argv_arr, int argc_val,
                               int cols, int rows, bool clear_env) {
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)cols;
    ws.ws_row = (unsigned short)rows;

    int master_fd = -1, slave_fd = -1;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, &ws) == -1) {
        int e = errno;
        return tjs_throw_errno_msg(ctx, e, "openpty: %s", strerror(e));
    }

    /* Make master non-blocking so libuv can poll it. */
    int fl = fcntl(master_fd, F_GETFL, 0);
    if (fl != -1) fcntl(master_fd, F_SETFL, fl | O_NONBLOCK);

    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        close(master_fd); close(slave_fd);
        return tjs_throw_errno_msg(ctx, e, "fork: %s", strerror(e));
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

    /* uv_pipe_open hands the master fd to libuv, which owns and closes it;
     * master_fd stays an integer solely for ioctl (resize/getwinsize). */
    close(slave_fd);

    JSValue pipe_obj = tjs_new_pipe(ctx);
    if (JS_IsException(pipe_obj))
        return pty_unix_spawn_abort(ctx, pipe_obj, master_fd, pid);
    uv_pipe_t *pp = tjs_pipe_get_pipe(ctx, pipe_obj);
    if (!pp) {
        JS_FreeValue(ctx, pipe_obj);
        return pty_unix_spawn_abort(ctx,
                                    tjs_throw_plain_error(ctx,
                                                          "failed to get pipe handle"),
                                    master_fd, pid);
    }
    int r = uv_pipe_open(pp, master_fd);
    if (r != 0) {
        JS_FreeValue(ctx, pipe_obj);
        return pty_unix_spawn_abort(ctx, tjs_throw_errno(ctx, r),
                                    master_fd, pid);
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

#ifdef _WIN32
static JSValue pty_win_spawn(TJSProcess *p, JSContext *ctx,
                              const char *name, const char *cwd,
                              char **env_arr, char **argv_arr, int argc_val,
                              int cols, int rows) {
    if (!load_conpty())
        return tjs_throw_errno_msg(ctx, UV_ENOSYS, "ConPTY not supported on this Windows version");

    HANDLE hPipeIn  = INVALID_HANDLE_VALUE;
    HANDLE hPipeOut = INVALID_HANDLE_VALUE;
    HANDLE hConIn   = INVALID_HANDLE_VALUE;
    HANDLE hConOut  = INVALID_HANDLE_VALUE;
    HPCON  hPC      = NULL;
    HANDLE hProc    = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;
    WCHAR *wapp = NULL, *wexe = NULL, *wcmd = NULL, *wcwd = NULL, *wenv = NULL;
    JSValue write_obj = JS_UNDEFINED;
    JSValue read_obj = JS_UNDEFINED;
    JSValue ret = JS_EXCEPTION;
    int process_cleanup_error = 0;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, true };
    if (!CreatePipe(&hConIn, &hPipeIn, &sa, 0) ||
        !CreatePipe(&hPipeOut, &hConOut, &sa, 0)) {
        tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreatePipe failed: %lu", GetLastError());
        goto cleanup;
    }

    COORD sz = { (SHORT)cols, (SHORT)rows };
    HRESULT hr = pCreatePseudoConsole(sz, hConIn, hConOut, 0, &hPC);
    if (FAILED(hr)) {
        tjs_throw_plain_error(ctx, "CreatePseudoConsole failed: 0x%08lx", hr);
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
        tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "ProcThreadAttribute setup failed");
        goto cleanup;
    }

    const char *cmd = (name && *name) ? name : getenv("COMSPEC");
    if (!cmd || !*cmd) cmd = "cmd.exe";
    wapp = spawn_sync_utf8_to_wide(ctx, cmd);
    if (!wapp) { JS_ThrowOutOfMemory(ctx); goto cleanup; }
    wexe = spawn_sync_resolve_win_app(ctx, wapp);
    if (!wexe) {
        tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "SearchPath failed for PTY command: %s", cmd);
        goto cleanup;
    }
    char *default_argv[] = { (char *)cmd, NULL };
    wcmd = spawn_sync_build_win_cmdline(ctx,
                                        argv_arr && argc_val > 0 ? argv_arr : default_argv,
                                        false);
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
    /* Without STARTF_USESTDHANDLES the child keeps the parent's stdio when
     * ours is a pipe/file; NULL handles and bInheritHandles=false fix that. */
    siEx.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;
    siEx.StartupInfo.hStdInput  = NULL;
    siEx.StartupInfo.hStdOutput = NULL;
    siEx.StartupInfo.hStdError  = NULL;
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(wexe, wcmd, NULL, NULL, false,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                        wenv, wcwd,
                        &siEx.StartupInfo, &pi)) {
        tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreateProcess failed: %lu", GetLastError());
        goto cleanup;
    }
    CloseHandle(pi.hThread);
    pi.hThread = NULL;
    hProc = pi.hProcess; /* retain for waitSync */
    pi.hProcess = NULL;

    /* ConPTY internal pipe ends are no longer needed. */
    CloseHandle(hConIn);  hConIn  = INVALID_HANDLE_VALUE;
    CloseHandle(hConOut); hConOut = INVALID_HANDLE_VALUE;

    /* Writable pipe: JS writes → ConPTY → child stdin */
    write_obj = tjs_new_pipe(ctx);
    if (JS_IsException(write_obj)) goto cleanup;
    uv_pipe_t *pw = tjs_pipe_get_pipe(ctx, write_obj);
    if (!pw) {
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        if (!JS_HasException(ctx))
            tjs_throw_plain_error(ctx, "failed to get PTY write pipe handle");
        goto cleanup;
    }
    int wfd = _open_osfhandle((intptr_t)hPipeIn, 0);
    if (wfd < 0) {
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        int e = errno;
        tjs_throw_errno_msg(ctx, e, "_open_osfhandle (write) failed: %s", strerror(e));
        goto cleanup;
    }
    hPipeIn = INVALID_HANDLE_VALUE; /* ownership transferred to the CRT fd */
    int r = uv_pipe_open(pw, wfd);
    if (r != 0) {
        _close(wfd);
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        tjs_throw_errno(ctx, r);
        goto cleanup;
    }

    /* Readable pipe: child stdout → ConPTY → JS */
    read_obj = tjs_new_pipe(ctx);
    if (JS_IsException(read_obj)) {
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        goto cleanup;
    }
    uv_pipe_t *pr = tjs_pipe_get_pipe(ctx, read_obj);
    if (!pr) {
        JS_FreeValue(ctx, read_obj);
        read_obj = JS_UNDEFINED;
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        if (!JS_HasException(ctx))
            tjs_throw_plain_error(ctx, "failed to get PTY read pipe handle");
        goto cleanup;
    }
    int rfd = _open_osfhandle((intptr_t)hPipeOut, 0);
    if (rfd < 0) {
        JS_FreeValue(ctx, read_obj);
        read_obj = JS_UNDEFINED;
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        int e = errno;
        tjs_throw_errno_msg(ctx, e, "_open_osfhandle (read) failed: %s", strerror(e));
        goto cleanup;
    }
    hPipeOut = INVALID_HANDLE_VALUE; /* ownership transferred to the CRT fd */
    int rr = uv_pipe_open(pr, rfd);
    if (rr != 0) {
        _close(rfd);
        JS_FreeValue(ctx, read_obj);
        read_obj = JS_UNDEFINED;
        JS_FreeValue(ctx, write_obj);
        write_obj = JS_UNDEFINED;
        tjs_throw_errno(ctx, rr);
        goto cleanup;
    }

    p->pty_pid         = (pid_t)pi.dwProcessId;
    p->hpc             = hPC;   hPC   = NULL;
    p->pty_proc_handle = hProc; hProc = NULL;
    p->pty_readable    = read_obj;
    p->pty_writable    = write_obj;
    read_obj = JS_UNDEFINED;
    write_obj = JS_UNDEFINED;
    ret = JS_UNDEFINED;

cleanup:
    if (!JS_IsUndefined(read_obj) && !JS_IsException(read_obj))
        JS_FreeValue(ctx, read_obj);
    if (!JS_IsUndefined(write_obj) && !JS_IsException(write_obj))
        JS_FreeValue(ctx, write_obj);
    if (attrList) { DeleteProcThreadAttributeList(attrList); free(attrList); }
    if (hProc) {
        process_cleanup_error = process_windows_terminate_and_wait(hProc);
        if (process_cleanup_error != 0)
            process_windows_relinquish_failed_handle(&hProc);
        else
            CloseHandle(hProc);
        hProc = NULL;
    }
    if (hConIn  != INVALID_HANDLE_VALUE) CloseHandle(hConIn);
    if (hConOut != INVALID_HANDLE_VALUE) CloseHandle(hConOut);
    if (hPipeIn != INVALID_HANDLE_VALUE) CloseHandle(hPipeIn);
    if (hPipeOut!= INVALID_HANDLE_VALUE) CloseHandle(hPipeOut);
    if (hPC && pClosePseudoConsole) pClosePseudoConsole(hPC);
    js_free(ctx, wapp);
    js_free(ctx, wexe);
    js_free(ctx, wcmd);
    js_free(ctx, wcwd);
    js_free(ctx, wenv);
    if (process_cleanup_error != 0) {
        JSValue pending = JS_GetException(ctx);
        JS_FreeValue(ctx, pending);
        ret = tjs_throw_errno_msg(ctx, process_cleanup_error,
                                  "PTY child cleanup failed");
    }
    return ret;
}
#endif /* _WIN32 */

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
        uint64_t len;
        if (process_argv_length(ctx, arg0, &len) < 0) return NULL;
        args = js_mallocz(ctx, sizeof(*args) * ((size_t)len + 1));
        if (!args) return NULL;
        for (uint32_t i = 0; i < (uint32_t)len; i++) {
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

static int spawn_sync_stdio_mode(JSContext *ctx, JSValue opts, const char *name,
                                 const char *def, const char **mode_out) {
    *mode_out = def;
    if (!JS_IsObject(opts)) return 0;
    JSValue v = JS_GetPropertyStr(ctx, opts, name);
    if (JS_IsException(v)) { JS_FreeValue(ctx, v); return -1; }
    if (JS_IsUndefined(v) || JS_IsNull(v)) { JS_FreeValue(ctx, v); return 0; }
    if (JS_IsNumber(v)) { JS_FreeValue(ctx, v); *mode_out = "inherit"; return 0; }
    const char *s = JS_ToCString(ctx, v);
    JS_FreeValue(ctx, v);
    if (!s) return -1;
    if (!strcmp(s, "ignore")) *mode_out = "ignore";
    else if (!strcmp(s, "inherit")) *mode_out = "inherit";
    else if (!strcmp(s, "pipe")) *mode_out = "pipe";
    /* Preserve the existing fallback: unknown values use the default mode. */
    JS_FreeCString(ctx, s);
    return 0;
}

static JSValue spawn_sync_make_result(JSContext *ctx, int pid, int64_t status, int signal,
                                      TJSSpawnSyncBuf *out, TJSSpawnSyncBuf *err,
                                      bool capture_out, bool capture_err,
                                      const uv_rusage_t *usage, int exec_errno) {
    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
    if (JS_IsException(obj)) return obj;

    /* exec/chdir never ran to completion: Node reports the failure through
     * `error` with status null and empty output, never a 127 exit status. */
    if (exec_errno != 0) {
        JSValue err_obj = tjs_new_error(ctx, uv_translate_sys_error(exec_errno));
        if (JS_IsException(err_obj)) {
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
        JS_DefinePropertyValueStr(ctx, obj, "pid", JS_NewInt32(ctx, pid), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "status", JS_NULL, JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "signal", JS_NULL, JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "stdout", JS_NULL, JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "stderr", JS_NULL, JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "output", JS_NewArray(ctx), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "error", err_obj, JS_PROP_C_W_E);
        return obj;
    }

    JS_DefinePropertyValueStr(ctx, obj, "pid", JS_NewInt32(ctx, pid), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "status", signal ? JS_NULL : JS_NewInt64(ctx, status), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "signal", signal ? JS_NewInt32(ctx, signal) : JS_NULL, JS_PROP_C_W_E);

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
    JSValue rusage = make_rusage_obj(ctx, usage);
    if (JS_IsException(rusage)) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    JS_DefinePropertyValueStr(ctx, obj, "resourceUsage", rusage, JS_PROP_C_W_E);
    return obj;
}

static char **spawn_sync_parse_call_args(JSContext *ctx, int argc, JSValue *argv, JSValue *opts_out) {
    *opts_out = argc >= 2 ? argv[1] : JS_UNDEFINED;
    if (argc >= 2 && JS_IsArray(argv[1])) {
        if (!JS_IsString(argv[0])) {
            JS_ThrowTypeError(ctx, "spawnSync(command, args?, options?): command must be a string");
            return NULL;
        }
        uint64_t len;
        if (process_argv_length(ctx, argv[1], &len) < 0) {
            return NULL;
        }
        if (len >= INT_MAX) {
            JS_ThrowRangeError(ctx, "argv array is too large");
            return NULL;
        }

        JSValue full = JS_NewArray(ctx);
        if (JS_IsException(full)) return NULL;
        if (JS_SetPropertyUint32(ctx, full, 0, JS_DupValue(ctx, argv[0])) < 0) {
            JS_FreeValue(ctx, full);
            return NULL;
        }
        for (uint32_t i = 0; i < (uint32_t)len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, argv[1], (uint32_t)i);
            if (JS_IsException(item)) { JS_FreeValue(ctx, full); return NULL; }
            if (JS_SetPropertyUint32(ctx, full, i + 1, item) < 0) {
                JS_FreeValue(ctx, full);
                return NULL;
            }
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
    if (JS_IsException(v)) { JS_FreeValue(ctx, v); return -1; }
    if (JS_IsUndefined(v) || JS_IsNull(v)) { JS_FreeValue(ctx, v); return 0; }
    const uint8_t *src = NULL;
    if (JS_IsString(v)) {
        src = (const uint8_t *)JS_ToCStringLen(ctx, len, v);
        if (!src) { JS_FreeValue(ctx, v); return -1; }
        *data = malloc(*len);
        if (*len && *data) memcpy(*data, src, *len);
        JS_FreeCString(ctx, (const char *)src);
        JS_FreeValue(ctx, v);
        if (*len != 0 && !*data) { JS_ThrowOutOfMemory(ctx); return -1; }
        return 1;
    }
    src = JS_GetAnyBuffer(ctx, len, v);
    if (src) {
        *data = malloc(*len);
        if (*len && *data) memcpy(*data, src, *len);
    }
    JS_FreeValue(ctx, v);
    if (!src) return -1;
    if (*len != 0 && !*data) { JS_ThrowOutOfMemory(ctx); return -1; }
    return 1;
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
    if (input_kind < 0) { tjs__free_args(ctx, args); return JS_HasException(ctx) ? JS_EXCEPTION : JS_ThrowTypeError(ctx, "input must be a string or buffer"); }

    const char *stdin_mode = "pipe", *stdout_mode = "pipe", *stderr_mode = "pipe";
    if ((input_len == 0 && spawn_sync_stdio_mode(ctx, opts, "stdin", "pipe", &stdin_mode) < 0) ||
        spawn_sync_stdio_mode(ctx, opts, "stdout", "pipe", &stdout_mode) < 0 ||
        spawn_sync_stdio_mode(ctx, opts, "stderr", "pipe", &stderr_mode) < 0) {
        spawn_sync_free_input(input);
        tjs__free_args(ctx, args);
        return JS_EXCEPTION;
    }
    bool cap_out = strcmp(stdout_mode, "pipe") == 0;
    bool cap_err = strcmp(stderr_mode, "pipe") == 0;
    bool pipe_in = strcmp(stdin_mode, "pipe") == 0;

    int in_pipe[2] = { -1, -1 }, out_pipe[2] = { -1, -1 }, err_pipe[2] = { -1, -1 };
    /* exec-fail report pipe, libuv's uv_spawn trick: the child writes the exec
     * errno before _exit(127), the parent reads it after reaping. Without it a
     * failed execvp is indistinguishable from a real exit-127 child, so the JS
     * layer cannot report ENOENT for unresolvable commands. */
    int exec_pipe[2] = { -1, -1 };
    int exec_errno = 0;
    JSValue ret = JS_EXCEPTION;
    TJSSpawnSyncBuf out = { 0 }, err = { 0 };
    char **env_arr = NULL;
    char *cwd = NULL;
    bool clear_env;
    if (bool_prop(ctx, opts, "clearEnv", &clear_env) < 0) goto cleanup;

    if (JS_IsObject(opts)) {
        JSValue v = JS_GetPropertyStr(ctx, opts, "env");
        if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto cleanup; }
        if (JS_IsObject(v)) {
            env_arr = parse_env_obj(ctx, v);
            if (!env_arr && JS_HasException(ctx)) { JS_FreeValue(ctx, v); goto cleanup; }
        }
        JS_FreeValue(ctx, v);
        if (clear_env && !env_arr) {
            env_arr = empty_env(ctx);
            if (!env_arr) goto cleanup;
        }
        v = JS_GetPropertyStr(ctx, opts, "cwd");
        if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto cleanup; }
        if (JS_IsString(v)) {
            const char *s = JS_ToCString(ctx, v);
            if (!s) { JS_FreeValue(ctx, v); goto cleanup; }
            cwd = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
        }
        JS_FreeValue(ctx, v);
    }

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.spawnSync"), (free_env(ctx, env_arr), js_free(ctx, cwd), spawn_sync_free_input(input), tjs__free_args(ctx, args)));

    if (pipe_in && pipe(in_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
    if (cap_out && pipe(out_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
    if (cap_err && pipe(err_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }
    if (pipe(exec_pipe) == -1) { ret = tjs_throw_errno(ctx, uv_translate_sys_error(errno)); goto cleanup; }

    for (int i = 0; i < 2; i++) {
        if (in_pipe[i] != -1) spawn_sync_set_cloexec(in_pipe[i]);
        if (out_pipe[i] != -1) spawn_sync_set_cloexec(out_pipe[i]);
        if (err_pipe[i] != -1) spawn_sync_set_cloexec(err_pipe[i]);
        if (exec_pipe[i] != -1) spawn_sync_set_cloexec(exec_pipe[i]);
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
        if (exec_pipe[0] != -1) close(exec_pipe[0]);
        if (cwd && chdir(cwd) < 0) {
            int e = errno;
            if (write(exec_pipe[1], &e, sizeof(e)) < 0) { /* parent already gone */ }
            _exit(127);
        }
        if (clear_env) environ = NULL;
        if (env_arr) {
            for (int i = 0; env_arr[i]; i++) {
                char *eq = strchr(env_arr[i], '=');
                if (eq) { *eq = '\0'; setenv(env_arr[i], eq + 1, 1); *eq = '='; }
            }
        }
        execvp(args[0], args);
        {
            int e = errno;
            if (write(exec_pipe[1], &e, sizeof(e)) < 0) { /* parent already gone */ }
        }
        _exit(127);
    }

    /* Parent holds the write end: close it so the post-wait read reaches EOF
     * both when exec succeeded (CLOEXEC) and when the child died. */
    close(exec_pipe[1]);
    exec_pipe[1] = -1;

    if (in_pipe[0] != -1) { close(in_pipe[0]); in_pipe[0] = -1; }
    if (out_pipe[1] != -1) { close(out_pipe[1]); out_pipe[1] = -1; }
    if (err_pipe[1] != -1) { close(err_pipe[1]); err_pipe[1] = -1; }
    if (in_pipe[1] != -1) spawn_sync_set_nonblock(in_pipe[1]);
    if (out_pipe[0] != -1) spawn_sync_set_nonblock(out_pipe[0]);
    if (err_pipe[0] != -1) spawn_sync_set_nonblock(err_pipe[0]);

    bool child_done = false;
    int wait_status = 0;
    struct rusage child_usage;
    memset(&child_usage, 0, sizeof(child_usage));
    while (out_pipe[0] != -1 || err_pipe[0] != -1 || in_pipe[1] != -1 || !child_done) {
        if (!child_done) {
            pid_t wr = wait4(pid, &wait_status, WNOHANG, &child_usage);
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
                do { wr = wait4(pid, &wait_status, 0, &child_usage); }
                while (wr < 0 && errno == EINTR);
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
    uv_rusage_t normalized_usage;
    memset(&normalized_usage, 0, sizeof(normalized_usage));
    normalized_usage.ru_utime.tv_sec = child_usage.ru_utime.tv_sec;
    normalized_usage.ru_utime.tv_usec = child_usage.ru_utime.tv_usec;
    normalized_usage.ru_stime.tv_sec = child_usage.ru_stime.tv_sec;
    normalized_usage.ru_stime.tv_usec = child_usage.ru_stime.tv_usec;
    normalized_usage.ru_maxrss = child_usage.ru_maxrss;
    normalized_usage.ru_ixrss = child_usage.ru_ixrss;
    normalized_usage.ru_idrss = child_usage.ru_idrss;
    normalized_usage.ru_isrss = child_usage.ru_isrss;
    normalized_usage.ru_minflt = child_usage.ru_minflt;
    normalized_usage.ru_majflt = child_usage.ru_majflt;
    normalized_usage.ru_nswap = child_usage.ru_nswap;
    normalized_usage.ru_inblock = child_usage.ru_inblock;
    normalized_usage.ru_oublock = child_usage.ru_oublock;
    normalized_usage.ru_msgsnd = child_usage.ru_msgsnd;
    normalized_usage.ru_msgrcv = child_usage.ru_msgrcv;
    normalized_usage.ru_nsignals = child_usage.ru_nsignals;
    normalized_usage.ru_nvcsw = child_usage.ru_nvcsw;
    normalized_usage.ru_nivcsw = child_usage.ru_nivcsw;
#if defined(__APPLE__)
    normalized_usage.ru_maxrss /= 1024;
#endif

    /* Child reported an exec/chdir failure? One int of errno, or EOF on exec
     * success (CLOEXEC closed the write end) or on an empty-queue failure. */
    if (exec_pipe[0] != -1) {
        int e = 0;
        ssize_t n = read(exec_pipe[0], &e, sizeof(e));
        if (n == (ssize_t)sizeof(e) && e != 0)
            exec_errno = e;
    }

    ret = spawn_sync_make_result(ctx, (int)pid, es, ts, &out, &err, cap_out, cap_err,
                                 &normalized_usage, exec_errno);

cleanup:
    if (in_pipe[0] != -1) close(in_pipe[0]);
    if (in_pipe[1] != -1) close(in_pipe[1]);
    if (out_pipe[0] != -1) close(out_pipe[0]);
    if (out_pipe[1] != -1) close(out_pipe[1]);
    if (err_pipe[0] != -1) close(err_pipe[0]);
    if (err_pipe[1] != -1) close(err_pipe[1]);
    if (exec_pipe[0] != -1) close(exec_pipe[0]);
    if (exec_pipe[1] != -1) close(exec_pipe[1]);
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

/* CreateProcess does not search PATH with lpApplicationName; resolve first. */
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

static WCHAR *spawn_sync_build_win_cmdline(JSContext *ctx, char **args, bool verbatim) {
    size_t total = 0;
    char **quoted = NULL;
    int count = 0;
    while (args[count]) count++;
    quoted = js_mallocz(ctx, sizeof(char *) * (count + 1));
    if (!quoted) return NULL;
    for (int i = 0; i < count; i++) {
        quoted[i] = verbatim && i > 0 ? js_strdup(ctx, args[i]) : spawn_sync_quote_win_arg(ctx, args[i]);
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
    if (input_kind < 0) { tjs__free_args(ctx, args); return JS_HasException(ctx) ? JS_EXCEPTION : JS_ThrowTypeError(ctx, "input must be a string or buffer"); }

    const char *stdin_mode = "pipe", *stdout_mode = "pipe", *stderr_mode = "pipe";
    if ((input_len == 0 && spawn_sync_stdio_mode(ctx, opts, "stdin", "pipe", &stdin_mode) < 0) ||
        spawn_sync_stdio_mode(ctx, opts, "stdout", "pipe", &stdout_mode) < 0 ||
        spawn_sync_stdio_mode(ctx, opts, "stderr", "pipe", &stderr_mode) < 0) {
        spawn_sync_free_input(input);
        tjs__free_args(ctx, args);
        return JS_EXCEPTION;
    }
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
    bool clear_env, verbatim;
    if (bool_prop(ctx, opts, "clearEnv", &clear_env) < 0 ||
        bool_prop(ctx, opts, "windowsVerbatimArguments", &verbatim) < 0)
        goto cleanup;

    wcmd = spawn_sync_build_win_cmdline(ctx, args, verbatim);
    if (!wcmd) { JS_ThrowOutOfMemory(ctx); goto cleanup; }

    if (JS_IsObject(opts)) {
        JSValue v = JS_GetPropertyStr(ctx, opts, "cwd");
        if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto cleanup; }
        if (JS_IsString(v)) {
            const char *s = JS_ToCString(ctx, v);
            if (!s) { JS_FreeValue(ctx, v); goto cleanup; }
            wcwd = spawn_sync_utf8_to_wide(ctx, s);
            JS_FreeCString(ctx, s);
            if (!wcwd) { JS_FreeValue(ctx, v); JS_ThrowOutOfMemory(ctx); goto cleanup; }
        }
        JS_FreeValue(ctx, v);
        v = JS_GetPropertyStr(ctx, opts, "env");
        if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto cleanup; }
        if (JS_IsObject(v)) {
            env_arr = parse_env_obj(ctx, v);
            if (!env_arr && JS_HasException(ctx)) { JS_FreeValue(ctx, v); goto cleanup; }
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

    DWORD flags = CREATE_UNICODE_ENVIRONMENT;
    if (JS_IsObject(opts)) {
        JSValue bg = JS_GetPropertyStr(ctx, opts, "background");
        if (JS_IsException(bg)) { JS_FreeValue(ctx, bg); goto cleanup; }
        int is_background = JS_IsEqual(ctx, bg, JS_TRUE);
        JS_FreeValue(ctx, bg);
        if (is_background < 0) goto cleanup;
        if (is_background) flags |= CREATE_NO_WINDOW;
    }

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.spawnSync"), (js_free(ctx, wcmd), js_free(ctx, wcwd), js_free(ctx, wenv), free_env(ctx, env_arr), spawn_sync_free_input(input), tjs__free_args(ctx, args)));

    if (pipe_in && !CreatePipe(&in_r, &in_w, &sa, 0)) { tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreatePipe(stdin) failed: %lu", GetLastError()); goto cleanup; }
    if (cap_out && !CreatePipe(&out_r, &out_w, &sa, 0)) { tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreatePipe(stdout) failed: %lu", GetLastError()); goto cleanup; }
    if (cap_err && !CreatePipe(&err_r, &err_w, &sa, 0)) { tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreatePipe(stderr) failed: %lu", GetLastError()); goto cleanup; }
    if (in_w != INVALID_HANDLE_VALUE) SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    if (out_r != INVALID_HANDLE_VALUE) SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    if (err_r != INVALID_HANDLE_VALUE) SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = pipe_in ? in_r : (!strcmp(stdin_mode, "ignore") ? INVALID_HANDLE_VALUE : GetStdHandle(STD_INPUT_HANDLE));
    si.hStdOutput = cap_out ? out_w : (!strcmp(stdout_mode, "ignore") ? INVALID_HANDLE_VALUE : GetStdHandle(STD_OUTPUT_HANDLE));
    si.hStdError = cap_err ? err_w : (!strcmp(stderr_mode, "ignore") ? INVALID_HANDLE_VALUE : GetStdHandle(STD_ERROR_HANDLE));

    if (!CreateProcessW(NULL, wcmd, NULL, NULL, true, flags, wenv, wcwd, &si, &pi)) {
        tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreateProcess failed: %lu", GetLastError());
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
        if (!out_thread) { tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreateThread(stdout) failed: %lu", GetLastError()); goto cleanup; }
    }
    if (cap_err) {
        err_arg.pipe = err_r; err_arg.buf = &err;
        err_thread = CreateThread(NULL, 0, spawn_sync_win_read_thread, &err_arg, 0, NULL);
        if (!err_thread) { tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreateThread(stderr) failed: %lu", GetLastError()); goto cleanup; }
    }
    if (pipe_in) {
        in_arg.pipe = in_w; in_arg.data = input; in_arg.len = input_len;
        in_thread = CreateThread(NULL, 0, spawn_sync_win_write_thread, &in_arg, 0, NULL);
        if (!in_thread) { tjs_throw_errno_msg(ctx, uv_translate_sys_error(GetLastError()), "CreateThread(stdin) failed: %lu", GetLastError()); goto cleanup; }
        in_w = INVALID_HANDLE_VALUE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    if (in_thread) WaitForSingleObject(in_thread, INFINITE);
    if (out_thread) WaitForSingleObject(out_thread, INFINITE);
    if (err_thread) WaitForSingleObject(err_thread, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    uv_rusage_t child_usage;
    memset(&child_usage, 0, sizeof(child_usage));
    FILETIME create_time, exit_time, kernel_time, user_time;
    PROCESS_MEMORY_COUNTERS mem_counters;
    IO_COUNTERS io_counters;
    if (GetProcessTimes(pi.hProcess, &create_time, &exit_time, &kernel_time, &user_time) &&
        GetProcessMemoryInfo(pi.hProcess, &mem_counters, sizeof(mem_counters)) &&
        GetProcessIoCounters(pi.hProcess, &io_counters)) {
        ULARGE_INTEGER ticks;
        ticks.LowPart = user_time.dwLowDateTime;
        ticks.HighPart = user_time.dwHighDateTime;
        child_usage.ru_utime.tv_sec = (long)(ticks.QuadPart / 10000000ULL);
        child_usage.ru_utime.tv_usec = (long)((ticks.QuadPart % 10000000ULL) / 10ULL);
        ticks.LowPart = kernel_time.dwLowDateTime;
        ticks.HighPart = kernel_time.dwHighDateTime;
        child_usage.ru_stime.tv_sec = (long)(ticks.QuadPart / 10000000ULL);
        child_usage.ru_stime.tv_usec = (long)((ticks.QuadPart % 10000000ULL) / 10ULL);
        child_usage.ru_majflt = mem_counters.PageFaultCount;
        child_usage.ru_maxrss = (uint64_t)mem_counters.PeakWorkingSetSize / 1024;
        child_usage.ru_oublock = io_counters.WriteOperationCount;
        child_usage.ru_inblock = io_counters.ReadOperationCount;
    }
    ret = spawn_sync_make_result(ctx, (int)pi.dwProcessId, (int64_t)code, 0, &out, &err,
                                 cap_out, cap_err, &child_usage, 0);

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

static JSValue tjs_spawn(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "spawn: expected at least 1 argument");

    /* ---- PTY mode ---- */
    bool use_pty = false;
    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue v = JS_GetPropertyStr(ctx, argv[1], "pty");
        if (JS_IsException(v)) {
            JS_FreeValue(ctx, v);
            return JS_EXCEPTION;
        }
        int pty_value = JS_ToBool(ctx, v);
        JS_FreeValue(ctx, v);
        if (pty_value < 0) {
            return JS_EXCEPTION;
        }
        use_pty = pty_value != 0;
    }

    if (use_pty) {
        JSValue opts = argc >= 2 ? argv[1] : JS_UNDEFINED;

        const char *name = NULL, *cwd = NULL;
        char **env_arr = NULL, **argv_arr = NULL;
        int argv_len = 0;
        int cols, rows;
        bool clear_env;
        if (bool_prop(ctx, opts, "clearEnv", &clear_env) < 0 ||
            parse_winsize(ctx, opts, &cols, &rows) < 0) {
            return JS_EXCEPTION;
        }

        if (JS_IsObject(opts)) {
            JSValue v;
            v = JS_GetPropertyStr(ctx, opts, "name");
            if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto pty_fail; }
            if (JS_IsString(v)) {
                name = JS_ToCString(ctx, v);
                if (!name) { JS_FreeValue(ctx, v); goto pty_fail; }
            }
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, opts, "cwd");
            if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto pty_fail; }
            if (JS_IsString(v)) {
                cwd = JS_ToCString(ctx, v);
                if (!cwd) { JS_FreeValue(ctx, v); goto pty_fail; }
            }
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, opts, "env");
            if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto pty_fail; }
            if (JS_IsObject(v)) {
                env_arr = parse_env_obj(ctx, v);
                if (!env_arr && JS_HasException(ctx)) { JS_FreeValue(ctx, v); goto pty_fail; }
            }
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, opts, "argv");
            if (JS_IsException(v)) { JS_FreeValue(ctx, v); goto pty_fail; }
            if (JS_IsArray(v)) argv_arr = parse_argv_arr(ctx, v, &argv_len);
            JS_FreeValue(ctx, v);
            if (argv_len < 0) goto pty_fail;
        }

        if (clear_env && !env_arr) {
            env_arr = empty_env(ctx);
            if (!env_arr) { JS_ThrowOutOfMemory(ctx); goto pty_fail; }
        }

        TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.spawn"), (name ? JS_FreeCString(ctx, name) : (void)0, cwd ? JS_FreeCString(ctx, cwd) : (void)0, free_env(ctx, env_arr), free_str_arr(ctx, argv_arr, argv_len)));

        JSValue obj;
        TJSProcess *p = tjs_process_new(ctx, &obj);
        if (!p) {
            if (name) JS_FreeCString(ctx, name);
            if (cwd) JS_FreeCString(ctx, cwd);
            free_env(ctx, env_arr);
            free_str_arr(ctx, argv_arr, argv_len);
            return obj;
        }
        p->pty_mode = true;
        p->pty_cols = cols; p->pty_rows = rows;

        JSValue err;
#ifdef _WIN32
        err = pty_win_spawn(p, ctx, name, cwd, env_arr, argv_arr, argv_len, cols, rows);
#else
        err = pty_unix_spawn(p, ctx, name, cwd, env_arr, argv_arr, argv_len, cols, rows, clear_env);
#endif
        if (name) JS_FreeCString(ctx, name);
        if (cwd)  JS_FreeCString(ctx, cwd);
        free_env(ctx, env_arr);
        free_str_arr(ctx, argv_arr, argv_len);

        if (JS_IsException(err)) {
            process_list_remove(p);
            tjs__free(p); JS_FreeValue(ctx, obj);
            return err;
        }

        int r = uv_timer_init(tjs_get_loop(ctx), &p->pty_waiter);
        if (r != 0) {
            JSValue init_err = tjs_throw_errno(ctx, r);
#ifdef _WIN32
            int cleanup_result = process_windows_terminate_and_wait(
                p->pty_proc_handle);
            if (cleanup_result != 0) {
                process_windows_relinquish_failed_handle(&p->pty_proc_handle);
                JS_FreeValue(ctx, init_err);
                init_err = tjs_throw_errno_msg(ctx, cleanup_result,
                                               "PTY child cleanup failed");
            } else {
                CloseHandle(p->pty_proc_handle);
                p->pty_proc_handle = NULL;
            }
            pty_win_close_hpcon(p);
#else
            int cleanup_result = process_posix_kill_and_reap(
                p->pty_pid, NULL, NULL);
            if (cleanup_result != 0 && cleanup_result != process_no_child_error()) {
                int adopt_result = process_reaper_adopt_pid(p->pty_pid);
                if (adopt_result != 0) {
                    cleanup_result = process_posix_force_reap(
                        p->pty_pid, NULL, NULL);
                    if (cleanup_result != 0) {
                        JS_FreeValue(ctx, init_err);
                        init_err = tjs_throw_errno_msg(ctx, cleanup_result,
                                                       "PTY child cleanup failed");
                    }
                }
            }
#endif
            JS_FreeValue(ctx, p->pty_readable);
            JS_FreeValue(ctx, p->pty_writable);
            process_list_remove(p);
            tjs__free(p);
            JS_FreeValue(ctx, obj);
            return init_err;
        }
        p->handle_initialized = true;
        p->pty_waiter.data = p;
        CHECK_EQ(uv_timer_start(&p->pty_waiter, uv__pty_wait_cb, 0, 10), 0);
        p->counted_nonfork = true;
        tjs_live_nonfork_processes++;

        JS_SetOpaque(obj, p);
        p->obj = JS_DupValue(ctx, obj);
        return obj;

pty_fail:
        if (name) JS_FreeCString(ctx, name);
        if (cwd) JS_FreeCString(ctx, cwd);
        free_env(ctx, env_arr);
        free_str_arr(ctx, argv_arr, argv_len < 0 ? 0 : argv_len);
        return JS_EXCEPTION;
    }

    /* ---- Normal mode ---- */
    JSValue ret = JS_EXCEPTION;
    JSValue obj = JS_UNDEFINED;
    TJSProcess *p = NULL;
    uv_process_options_t options;
    memset(&options, 0, sizeof(options));
    uv_stdio_container_t *stdio_heap = NULL;
    char *argv0_file_owned = NULL;
    bool has_stdio_extra = false;
    bool use_ipc = false;
    uint32_t ipc_fd = 3;
    /* Once uv_spawn() is entered, &p->process is linked into the loop's
     * handle queue and must be uv_close()d, never freed. */
    bool spawn_attempted = false;
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
    if (!options.args[0]) { JS_ThrowTypeError(ctx, "spawn: empty argv"); goto fail; }
    options.file = options.args[0];

    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue arg1 = argv[1];

        /* options.file aliases options.args[0]; take ownership of the
         * executable string before replacing args[0] or it dangles on free. */
        JSValue js_argv0 = JS_GetPropertyStr(ctx, arg1, "argv0");
        if (JS_IsException(js_argv0)) {
            JS_FreeValue(ctx, js_argv0);
            goto fail;
        }
        if (JS_IsString(js_argv0)) {
            const char *s = JS_ToCString(ctx, js_argv0);
            /* Bail: the pending exception must not survive a successful spawn
             * of a live process object (only OOM reaches here for a string). */
            if (!s) {
                JS_FreeValue(ctx, js_argv0);
                goto fail;
            }
            char *dup = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
            if (!dup) {
                JS_FreeValue(ctx, js_argv0);
                JS_ThrowOutOfMemory(ctx);
                goto fail;
            }
            argv0_file_owned = options.args[0];
            options.file = argv0_file_owned;
            options.args[0] = dup;
        }
        JS_FreeValue(ctx, js_argv0);

        JSValue js_env = JS_GetPropertyStr(ctx, arg1, "env");
        if (JS_IsException(js_env)) { JS_FreeValue(ctx, js_env); goto fail; }
        if (JS_IsObject(js_env)) {
            options.env = parse_env_obj(ctx, js_env);
            if (!options.env && JS_HasException(ctx)) { JS_FreeValue(ctx, js_env); goto fail; }
        }
        JS_FreeValue(ctx, js_env);
        bool clear_env;
        if (bool_prop(ctx, arg1, "clearEnv", &clear_env) < 0) goto fail;
        if (clear_env) {
            /* Vendored libuv has no exact-env flag: an empty array clears
             * inheritance. */
            if (!options.env) {
                options.env = empty_env(ctx);
                if (!options.env) goto fail;
            }
// #ifdef _WIN32: options.flags |= UV_PROCESS_WINDOWS_CLEAR_ENV; #endif
        }

        JSValue js_cwd = JS_GetPropertyStr(ctx, arg1, "cwd");
        if (JS_IsException(js_cwd)) { JS_FreeValue(ctx, js_cwd); goto fail; }
        if (!JS_IsUndefined(js_cwd)) {
            const char *s = JS_ToCString(ctx, js_cwd);
            if (!s) { JS_FreeValue(ctx, js_cwd); goto fail; }
            options.cwd = js_strdup(ctx, s);
            JS_FreeCString(ctx, s);
        }
        JS_FreeValue(ctx, js_cwd);

        JSValue js_uid = JS_GetPropertyStr(ctx, arg1, "uid");
        if (JS_IsException(js_uid)) { JS_FreeValue(ctx, js_uid); goto fail; }
        if (!JS_IsUndefined(js_uid)) {
            uint32_t uid;
            if (JS_ToUint32(ctx, &uid, js_uid)) { JS_FreeValue(ctx, js_uid); goto fail; }
            options.uid = uid; options.flags |= UV_PROCESS_SETUID;
        }
        JS_FreeValue(ctx, js_uid);

        JSValue js_gid = JS_GetPropertyStr(ctx, arg1, "gid");
        if (JS_IsException(js_gid)) { JS_FreeValue(ctx, js_gid); goto fail; }
        if (!JS_IsUndefined(js_gid)) {
            uint32_t gid;
            if (JS_ToUint32(ctx, &gid, js_gid)) { JS_FreeValue(ctx, js_gid); goto fail; }
            options.gid = gid; options.flags |= UV_PROCESS_SETGID;
        }
        JS_FreeValue(ctx, js_gid);

        if (parse_stdio_option(ctx, arg1, "stdin", 0, UV_READABLE_PIPE, STDIN_FILENO, &options) < 0 ||
            parse_stdio_option(ctx, arg1, "stdout", 1, UV_WRITABLE_PIPE, STDOUT_FILENO, &options) < 0 ||
            parse_stdio_option(ctx, arg1, "stderr", 2, UV_WRITABLE_PIPE, STDERR_FILENO, &options) < 0)
            goto fail;

        JSValue js_stdio_extra = JS_GetPropertyStr(ctx, arg1, "stdioExtra");
        if (JS_IsException(js_stdio_extra)) { JS_FreeValue(ctx, js_stdio_extra); goto fail; }
        if (!JS_IsUndefined(js_stdio_extra)) {
            if (parse_extra_stdio(ctx, &options, stdio, &stdio_heap, js_stdio_extra, &has_stdio_extra) < 0) {
                JS_FreeValue(ctx, js_stdio_extra);
                goto fail;
            }
        }
        JS_FreeValue(ctx, js_stdio_extra);

        // Check for IPC option
        JSValue js_ipc = JS_GetPropertyStr(ctx, arg1, "ipc");
        if (JS_IsException(js_ipc)) { JS_FreeValue(ctx, js_ipc); goto fail; }
        int ipc_value = JS_ToBool(ctx, js_ipc);
        if (ipc_value < 0) { JS_FreeValue(ctx, js_ipc); goto fail; }
        use_ipc = ipc_value != 0;
        if (use_ipc) {
            JSValue js_ipc_fd = JS_GetPropertyStr(ctx, arg1, "ipcFd");
            if (JS_IsException(js_ipc_fd)) {
                JS_FreeValue(ctx, js_ipc_fd);
                JS_FreeValue(ctx, js_ipc);
                goto fail;
            }
            if (!JS_IsUndefined(js_ipc_fd)) {
                if (JS_ToUint32(ctx, &ipc_fd, js_ipc_fd) || ipc_fd > 255) {
                    JS_FreeValue(ctx, js_ipc_fd);
                    JS_FreeValue(ctx, js_ipc);
                    JS_ThrowRangeError(ctx, "ipcFd must be an integer between 0 and 255");
                    goto fail;
                }
            }
            JS_FreeValue(ctx, js_ipc_fd);
            if (ensure_stdio_capacity(ctx, &options, stdio, &stdio_heap, (int)ipc_fd + 1) < 0) {
                JS_ThrowOutOfMemory(ctx);
                JS_FreeValue(ctx, js_ipc);
                goto fail;
            }
            /* UV_NONBLOCK_PIPE is IPC contract, not optimization: the parent
             * writes from the event loop, and a blocking pipe can stall it. */
            options.stdio[ipc_fd].flags = UV_CREATE_PIPE | UV_READABLE_PIPE |
                                           UV_WRITABLE_PIPE | UV_NONBLOCK_PIPE;
            options.stdio[ipc_fd].data.stream = NULL;
        }
        JS_FreeValue(ctx, js_ipc);

        JSValue js_det = JS_GetPropertyStr(ctx, arg1, "detached");
        if (JS_IsException(js_det)) { JS_FreeValue(ctx, js_det); goto fail; }
        int is_detached = JS_IsEqual(ctx, js_det, JS_TRUE);
        JS_FreeValue(ctx, js_det);
        if (is_detached < 0) goto fail;
        if (is_detached) options.flags |= UV_PROCESS_DETACHED;
#ifdef _WIN32
        JSValue js_bg = JS_GetPropertyStr(ctx, arg1, "background");
        if (JS_IsException(js_bg)) { JS_FreeValue(ctx, js_bg); goto fail; }
        int is_background = JS_IsEqual(ctx, js_bg, JS_TRUE);
        JS_FreeValue(ctx, js_bg);
        if (is_background < 0) goto fail;
        if (is_background) options.flags |= UV_PROCESS_WINDOWS_HIDE;
        /* Without it libuv's quote_cmd_arg() rewrites inner quotes and cmd.exe
         * passes backslashes through literally, corrupting shell commands. */
        JSValue js_verbatim = JS_GetPropertyStr(ctx, arg1, "windowsVerbatimArguments");
        if (JS_IsException(js_verbatim)) { JS_FreeValue(ctx, js_verbatim); goto fail; }
        int is_verbatim = JS_IsEqual(ctx, js_verbatim, JS_TRUE);
        JS_FreeValue(ctx, js_verbatim);
        if (is_verbatim < 0) goto fail;
        if (is_verbatim) options.flags |= UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS;
#endif
    }

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.spawn"), (tjs__free_args(ctx, options.args), argv0_file_owned ? js_free(ctx, argv0_file_owned) : (void)0, free_env(ctx, (char **)options.env), options.cwd ? js_free(ctx, (void *)options.cwd) : (void)0, stdio_heap ? js_free(ctx, stdio_heap) : (void)0));

    p = tjs_process_new(ctx, &obj);
    if (!p) { ret = obj; obj = JS_UNDEFINED; goto cleanup; }

    if (materialize_spawn_stdio(ctx, p, &options, has_stdio_extra, use_ipc, ipc_fd) < 0)
        goto fail;
    if (use_ipc) {
        p->ipc_pipe = tjs_new_pipe(ctx);
        if (JS_IsException(p->ipc_pipe)) { p->ipc_pipe = JS_UNDEFINED; goto fail; }
        uv_pipe_t *pipe = tjs_pipe_get_pipe(ctx, p->ipc_pipe);
        if (!pipe) { if (!JS_HasException(ctx)) tjs_throw_errno(ctx, UV_EINVAL); goto fail; }
        options.stdio[ipc_fd].data.stream = (uv_stream_t *)pipe;
        if (ipc_fd >= 3 && !JS_IsUndefined(p->stdio_extra) &&
            JS_SetPropertyUint32(ctx, p->stdio_extra, ipc_fd, JS_NULL) < 0)
            goto fail;
        /* materialize_spawn_stdio skips fd == ipc_fd when use_ipc, so
         * p->stdio[ipc_fd] is always JS_UNDEFINED here — nothing to free. */
    }

    int reserve_result = process_reaper_reserve(p);
    if (reserve_result != 0) {
        tjs_throw_errno(ctx, reserve_result);
        goto fail;
    }

    options.exit_cb = uv__exit_cb;
    spawn_attempted = true;
    int r = uv_spawn(tjs_get_loop(ctx), &p->process, &options);
    /* Even a failed uv_spawn() leaves the handle registered with the loop
     * until its close callback runs; a fork in that window copies it. */
    p->counted_nonfork = true;
    tjs_live_nonfork_processes++;
    if (r != 0) {
#ifndef _WIN32
        /* libuv may have exec'd the child before a parent-side stdio setup
         * failure. Its error path removes the wait owner, so preserve the
         * reaper reservation for that already-created child. Exec failures
         * have pid == 0 because libuv has already waited for them. */
        if (p->process.pid > 0) {
            p->process_spawned = true;
            process_reaper_adopt(p, true);
        } else {
            process_reaper_release(p);
        }
#else
        process_reaper_release(p);
#endif
        tjs_throw_errno(ctx, r);
        goto fail;
    }
    p->handle_initialized = true;
    p->process_spawned = true;

    /* libuv created and owns both ends of the UV_CREATE_PIPE IPC channel and
     * closes the child end itself, so there is nothing to close here. */

    JS_SetOpaque(obj, p);
    p->obj = JS_DupValue(ctx, obj);
    ret = obj;
    goto cleanup;

fail:
    if (p) {
        process_reaper_release(p);
        for (int i = 0; i < 3; i++) { JS_FreeValue(ctx, p->stdio[i]); p->stdio[i] = JS_UNDEFINED; }
        JS_FreeValue(ctx, p->stdio_extra);
        p->stdio_extra = JS_UNDEFINED;
        JS_FreeValue(ctx, p->ipc_pipe);
        p->ipc_pipe = JS_UNDEFINED;
        /* A failed uv_spawn() still leaves the handle registered with the loop.
         * Here we try to close it completely */
        if (spawn_attempted) {
            p->handle_initialized = true;
            p->finalized = true;
            maybe_close(p);
        } else {
            process_list_remove(p);
            tjs__free(p);
        }
    }
    if (!JS_IsUndefined(obj)) JS_FreeValue(ctx, obj);
cleanup:
    tjs__free_args(ctx, options.args);
    if (argv0_file_owned) js_free(ctx, argv0_file_owned);
    free_env(ctx, (char **)options.env);
    if (options.cwd) js_free(ctx, (void *)options.cwd);
    if (stdio_heap) js_free(ctx, stdio_heap);
    return ret;
}

#ifndef _WIN32
static void reap_fork_failure(pid_t pid) {
    if (pid <= 0) return;
    (void)kill(pid, SIGKILL);
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

typedef struct {
    TJSRuntime *runtime;
    bool found;
} ForkHandleScan;

static bool fork_is_runtime_handle(const TJSRuntime *runtime, const uv_handle_t *handle) {
    return handle == (const uv_handle_t *) &runtime->jobs.prepare
        || handle == (const uv_handle_t *) &runtime->jobs.idle
        || handle == (const uv_handle_t *) &runtime->jobs.check
        || handle == (const uv_handle_t *) &runtime->stop;
}

static void fork_scan_handle(uv_handle_t *handle, void *opaque) {
    ForkHandleScan *scan = opaque;
    if (!fork_is_runtime_handle(scan->runtime, handle) && uv_is_active(handle)) {
        scan->found = true;
    }
}

static bool fork_runtime_is_quiescent(TJSRuntime *qrt) {
    /* The current job may be the last queued job, while the idle handle still
     * reflects the queue before this checkpoint. Refresh it before testing. */
    tjs__notify_work(qrt);
    if (uv_loop_alive(&qrt->loop) != 0
        || JS_IsJobPending(qrt->rt)
        || qrt->jobs.ticks_pending) {
        return false;
    }

    /* uv_loop_alive() omits active handles after uv_unref(). */
    ForkHandleScan scan = { .runtime = qrt, .found = false };
    uv_walk(&qrt->loop, fork_scan_handle, &scan);
    return !scan.found;
}

static int fork_check_allowed(JSContext *ctx, TJSRuntime **runtime_out) {
    TJSRuntime *qrt = TJS_GetRuntime(ctx);
    if (!qrt) {
        tjs_throw_plain_error(ctx, "fork() requires an initialized runtime");
        return -1;
    }
    if (qrt->is_worker) {
        JS_ThrowTypeError(ctx, "fork() is unavailable inside a worker");
        return -1;
    }
    if (!list_empty(&qrt->workers) || tjs__active_worker_count() != 0) {
        JS_ThrowTypeError(ctx, "fork() is unavailable while workers exist");
        return -1;
    }
    if (tjs_live_nonfork_processes != 0) {
        JS_ThrowTypeError(ctx,
                          "fork() is unavailable while child process handles are active or closing");
        return -1;
    }
    if (!fork_runtime_is_quiescent(qrt)) {
        JS_ThrowTypeError(ctx, "fork() requires an idle event loop");
        return -1;
    }
    *runtime_out = qrt;
    return 0;
}
#endif

/* The child must repair libuv's inherited kernel state before any other loop
 * operation; it returns null — only the parent owns and reaps the new PID. */
static JSValue tjs_fork(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    (void)this_val;
    (void)argv;
    if (argc != 0) return JS_ThrowTypeError(ctx, "fork() does not accept arguments");

#ifdef _WIN32
    return tjs_throw_errno(ctx, UV_ENOSYS);
#else
    TJSRuntime *qrt;
    if (fork_check_allowed(ctx, &qrt) < 0) return JS_EXCEPTION;

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.fork"), (void)0);

    if (fork_check_allowed(ctx, &qrt) < 0) return JS_EXCEPTION;
    ensure_fork_process_list();

    int prepare_result = process_reaper_fork_prepare();
    if (prepare_result != 0)
        return tjs_throw_errno(ctx, prepare_result);

    pid_t pid = fork();
    int fork_error = errno;
    if (pid < 0) {
        process_reaper_fork_finish();
        return tjs_throw_errno(ctx, uv_translate_sys_error(fork_error));
    }

    if (pid == 0) {
        /* The reaper thread was joined before fork(). No other thread exists
         * in this child, so clear the inherited guard without touching the
         * parent's mutex/condition variable; the child must be able to spawn
         * its own processes after uv_loop_fork(). */
        tjs_process_fork_in_progress = false;
        int r = uv_loop_fork(tjs_get_loop(ctx));
        /* A failed uv_loop_fork() may leave the backend half-rebuilt; keep
         * user JS off that loop by terminating only this failed child. */
        if (r != 0) _exit(127);
        /* Any Process handles created before the fork belong only to the
         * original parent; invalidate the child's copied wait promises. */
        disown_inherited_fork_handles();
        return JS_NULL;
    }

    process_reaper_fork_finish();

    JSClassID class_id = tjs_process_class_id;
    if (class_id == 0) return JS_ThrowTypeError(ctx, "process module is not initialized");
    JSValue obj = JS_NewObjectClass(ctx, class_id);
    if (JS_IsException(obj)) {
        reap_fork_failure(pid);
        return obj;
    }

    TJSProcess *p = tjs__mallocz(sizeof(*p));
    if (!p) {
        JS_FreeValue(ctx, obj);
        reap_fork_failure(pid);
        return JS_ThrowOutOfMemory(ctx);
    }

    p->trt          = TJS_GetRuntime(ctx);
    p->ctx          = ctx;
    p->obj          = JS_UNDEFINED;
    p->fork_mode    = true;
    p->fork_pid     = pid;
    p->fork_owner_pid = getpid();
    init_list_head(&p->fork_link);
    p->stdio[0]     = JS_UNDEFINED;
    p->stdio[1]     = JS_UNDEFINED;
    p->stdio[2]     = JS_UNDEFINED;
    p->stdio_extra  = JS_UNDEFINED;
    p->ipc_pipe     = JS_UNDEFINED;
    p->pty_readable = JS_UNDEFINED;
    p->pty_writable = JS_UNDEFINED;
    TJS_ClearPromise(ctx, &p->status.result);
    process_list_add(p);

    int r = uv_timer_init(tjs_get_loop(ctx), &p->fork_waiter);
    if (r != 0) {
        process_list_remove(p);
        tjs__free(p);
        JS_FreeValue(ctx, obj);
        reap_fork_failure(pid);
        return tjs_throw_errno(ctx, r);
    }

    p->handle_initialized = true;
    p->fork_waiter.data = p;
    r = uv_timer_start(&p->fork_waiter, uv__fork_wait_cb, 0, 10);
    if (r != 0) {
        p->finalized = true;
        maybe_close(p);
        JS_FreeValue(ctx, obj);
        reap_fork_failure(pid);
        return tjs_throw_errno(ctx, r);
    }

    JS_SetOpaque(obj, p);
    p->obj = JS_DupValue(ctx, obj);
    list_add(&p->fork_link, &tjs_fork_processes);
    p->fork_linked = true;
    return obj;
#endif
}

/* pid — works for both modes */
static JSValue tjs_process_pid_get(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
    pid_t pid;
    if (p->fork_mode)
        pid = p->fork_pid;
    else if (p->pty_mode)
        pid = p->pty_pid;
    else
        pid = (pid_t)uv_process_get_pid(&p->process);
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
static JSValue tjs_process_kill_revalidate(JSContext *ctx, JSValue this_val,
                                           TJSProcess **process_out) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
#ifndef _WIN32
    if (fork_handle_is_foreign(p))
        return tjs_throw_errno_msg(ctx, UV_ESRCH, "forked process handle belongs to another process");
#endif
    if (p->status.exited) return JS_UNDEFINED;
    if (p->status.lost)
        return tjs_throw_errno(ctx, p->status.wait_error);
    *process_out = p;
    return JS_UNINITIALIZED;
}

static JSValue tjs_process_kill(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p;
    JSValue process_state = tjs_process_kill_revalidate(ctx, this_val, &p);
    if (!JS_IsUninitialized(process_state)) return process_state;
    int sig = TJS_ToSignal(ctx, argc > 0 ? argv[0] : JS_UNDEFINED, SIGTERM);
    if (sig < 0) return JS_EXCEPTION;
    process_state = tjs_process_kill_revalidate(ctx, this_val, &p);
    if (!JS_IsUninitialized(process_state)) return process_state;
    TJS_CAPABILITY_REVALIDATE(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.kill"), (void)0, do { process_state = tjs_process_kill_revalidate(ctx, this_val, &p); if (!JS_IsUninitialized(process_state)) return process_state; } while (0));

    int r;
    if (p->fork_mode)
        r = uv_kill((int)p->fork_pid, sig);
    else if (p->pty_mode)
        r = uv_kill((int)p->pty_pid, sig);
    else
        r = uv_process_kill(&p->process, sig);
    if (r != 0 && r != UV_ESRCH) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

/* wait() → Promise */
static JSValue tjs_process_wait(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
#ifndef _WIN32
    if (fork_handle_is_foreign(p))
        return tjs_throw_errno_msg(ctx, UV_ESRCH, "forked process handle belongs to another process");
#endif
    if (p->status.exited) {
        JSValue obj = make_exit_obj(ctx, p->status.exit_status, p->status.term_signal);
        return TJS_NewResolvedPromise(ctx, 1, &obj);
    }
    if (p->status.lost) {
        JSValue err = make_fork_wait_error(p, ctx, p->status.wait_error);
        return TJS_NewRejectedPromise(ctx, 1, &err);
    }
    if (!JS_IsUndefined(p->status.result.p))
        return JS_DupValue(ctx, p->status.result.p);

    /* INIT hooks may finish the child or publish another wait promise. Keep
     * this capability local until that synchronous reentry has completed. */
    TJSPromise pending;
    JSValue promise = TJS_InitPromise(ctx, &pending);
    if (JS_IsException(promise)) return promise;

    if (p->status.exited || p->status.lost) {
        bool lost = p->status.lost;
        JSValue result = lost
            ? make_fork_wait_error(p, ctx, p->status.wait_error)
            : make_exit_obj(ctx, p->status.exit_status, p->status.term_signal);
        TJS_SettlePromise(ctx, &pending, lost, 1, &result);
    } else if (!JS_IsUndefined(p->status.result.p)) {
        JSValue shared = JS_DupValue(ctx, p->status.result.p);
        TJS_FreePromise(ctx, &pending);
        JS_FreeValue(ctx, promise);
        return shared;
    } else {
        p->status.result = pending;
    }
    return promise;
}

/* waitSync() — blocking wait, works for both modes */
static JSValue tjs_process_wait_sync(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return JS_EXCEPTION;
#ifndef _WIN32
    if (fork_handle_is_foreign(p))
        return tjs_throw_errno_msg(ctx, UV_ESRCH, "forked process handle belongs to another process");
#else
    if (p->fork_mode)
        return tjs_throw_errno_msg(ctx, UV_ENOSYS, "fork process unavailable on Windows");
    if (p->pty_mode && !p->pty_proc_handle &&
        !p->status.exited && !p->status.lost)
        return tjs_throw_errno_msg(ctx, UV_ENOSYS, "PTY process handle unavailable");
#endif
    if (p->status.exited)
        return make_exit_obj(ctx, p->status.exit_status, p->status.term_signal);
    if (p->status.lost)
        return tjs_throw_errno(ctx, p->status.wait_error);

    int64_t es = 0; int ts = 0;

    if (p->fork_mode) {
#ifdef _WIN32
        return tjs_throw_errno_msg(ctx, UV_ENOSYS, "fork process unavailable on Windows");
#else
        int stat;
        pid_t result;
        do {
            result = waitpid(p->fork_pid, &stat, 0);
        } while (result < 0 && errno == EINTR);
        if (result < 0) {
            int err = uv_translate_sys_error(errno);
            process_mark_lost(p, err);
            return tjs_throw_errno(ctx, err);
        }
        if (decode_wait_status(stat, &es, &ts) < 0)
            return JS_ThrowInternalError(ctx, "unexpected waitpid status");
#endif
    } else if (p->pty_mode) {
#ifdef _WIN32
        DWORD wait_result = WaitForSingleObject(p->pty_proc_handle, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
            int err = uv_translate_sys_error((int)wait_error);
            process_mark_lost(p, err);
            return tjs_throw_errno(ctx, err);
        }
        int exit_code_result = process_windows_get_exit_code(
            p->pty_proc_handle, &es);
        if (exit_code_result != 0) {
            process_mark_lost(p, exit_code_result);
            return tjs_throw_errno(ctx, exit_code_result);
        }
        ts = 0;
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
        DWORD wait_result = WaitForSingleObject(p->process.process_handle, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
            int err = uv_translate_sys_error((int)wait_error);
            process_mark_lost(p, err);
            return tjs_throw_errno(ctx, err);
        }
        int exit_code_result = process_windows_get_exit_code(
            p->process.process_handle, &es);
        if (exit_code_result != 0) {
            process_mark_lost(p, exit_code_result);
            return tjs_throw_errno(ctx, exit_code_result);
        }
        ts = 0;
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
#ifndef _WIN32
static int tjs_process_pty_fd(JSContext *ctx, TJSProcess *p, int *fd_out) {
    uv_pipe_t *pipe = tjs_pipe_get_pipe(ctx, p->pty_readable);
    if (!pipe || uv_is_closing((uv_handle_t *)pipe)) {
        tjs_throw_errno_msg(ctx, UV_EBADF, "PTY closed");
        return -1;
    }
    uv_os_fd_t fd;
    int r = uv_fileno((uv_handle_t *)pipe, &fd);
    if (r != 0) {
        tjs_throw_errno(ctx, r);
        return -1;
    }
    *fd_out = (int)fd;
    return 0;
}
#endif

static int tjs_process_resize_revalidate(JSContext *ctx, JSValue this_val,
                                         TJSProcess **process_out,
                                         int *pty_fd_out) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p) return -1;
    if (!p->pty_mode) {
        JS_ThrowTypeError(ctx, "not a PTY process");
        return -1;
    }
#ifdef _WIN32
    (void)pty_fd_out;
    if (!p->hpc && !p->status.exited) {
        tjs_throw_plain_error(ctx, "ConPTY unavailable");
        return -1;
    }
#else
    if (tjs_process_pty_fd(ctx, p, pty_fd_out) < 0) return -1;
#endif
    *process_out = p;
    return 0;
}

static JSValue tjs_process_resize(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "resize(cols, rows)");
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p || !p->pty_mode) return JS_ThrowTypeError(ctx, "not a PTY process");
    int32_t cols, rows;
    if (JS_ToInt32(ctx, &cols, argv[0]) || JS_ToInt32(ctx, &rows, argv[1]))
        return JS_EXCEPTION;

    int pty_fd = -1;
    if (tjs_process_resize_revalidate(ctx, this_val, &p, &pty_fd) < 0)
        return JS_EXCEPTION;
    TJS_CAPABILITY_REVALIDATE(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.resize"), (void)0, if (tjs_process_resize_revalidate(ctx, this_val, &p, &pty_fd) < 0) return JS_EXCEPTION);

#ifdef _WIN32
    /* After child exit the pseudoconsole is gone; POSIX still resizes the
     * master fd, so keep the tracked size coherent instead of throwing. */
    if (!p->hpc) {
        p->pty_cols = cols; p->pty_rows = rows;
        return JS_UNDEFINED;
    }
    COORD sz = { (SHORT)cols, (SHORT)rows };
    HRESULT hr = pResizePseudoConsole(p->hpc, sz);
    if (FAILED(hr)) return tjs_throw_plain_error(ctx, "ResizePseudoConsole failed: 0x%08lx", hr);
#else
    struct winsize ws; memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)cols; ws.ws_row = (unsigned short)rows;
    if (ioctl(pty_fd, TIOCSWINSZ, &ws) == -1)
        { int e = errno; return tjs_throw_errno_msg(ctx, e, "TIOCSWINSZ: %s", strerror(e)); }
#endif
    p->pty_cols = cols; p->pty_rows = rows;
    return JS_UNDEFINED;
}

/* get size() — PTY only */
static JSValue tjs_process_getwinsize(JSContext *ctx, JSValue this_val) {
    TJSProcess *p = tjs_process_get(ctx, this_val);
    if (!p || !p->pty_mode) return JS_ThrowTypeError(ctx, "not a PTY process");

#ifndef _WIN32
    int pty_fd;
    if (tjs_process_pty_fd(ctx, p, &pty_fd) < 0) return JS_EXCEPTION;
#endif

    JSValue obj = JS_NewObjectProto(ctx, JS_NULL);

#ifdef _WIN32
    /* Windows: we track size ourselves (ConPTY has no query API). */
    JS_DefinePropertyValueStr(ctx, obj, "cols", JS_NewInt32(ctx, p->pty_cols), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "rows", JS_NewInt32(ctx, p->pty_rows), JS_PROP_C_W_E);
#else
    struct winsize ws; memset(&ws, 0, sizeof(ws));
    if (ioctl(pty_fd, TIOCGWINSZ, &ws) == -1) {
        JS_FreeValue(ctx, obj);
        { int e = errno; return tjs_throw_errno_msg(ctx, e, "TIOCGWINSZ: %s", strerror(e)); }
    }
    JS_DefinePropertyValueStr(ctx, obj, "cols",   JS_NewInt32(ctx, ws.ws_col),    JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "rows",   JS_NewInt32(ctx, ws.ws_row),    JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "xpixel", JS_NewInt32(ctx, ws.ws_xpixel), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, obj, "ypixel", JS_NewInt32(ctx, ws.ws_ypixel), JS_PROP_C_W_E);
#endif
    return obj;
}

static JSValue tjs_kill(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0 || JS_IsUndefined(argv[0]))
        return JS_ThrowTypeError(ctx, "kill(pid, signal?)");
    int32_t pid;
    if (JS_ToInt32(ctx, &pid, argv[0])) return JS_EXCEPTION;
    int sig = TJS_ToSignal(ctx, argc >= 2 ? argv[1] : JS_UNDEFINED, SIGTERM);
    if (sig < 0) return JS_EXCEPTION;
    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.kill"), (void)0);
    int r = uv_kill(pid, sig);
    if (r != 0) return tjs_throw_errno(ctx, r);
    return JS_UNDEFINED;
}

static JSValue tjs_process_is_alive(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0 || JS_IsUndefined(argv[0]))
        return JS_ThrowTypeError(ctx, "isAlive(pid)");

    int32_t pid;
    if (JS_ToInt32(ctx, &pid, argv[0])) return JS_EXCEPTION;

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_ACCESS, TJS_CAP_FLAG_REPLACEABLE, "process.isAlive"), (void)0);

    int r = uv_kill(pid, 0);
    if (r == 0 || r == UV_EPERM || r == UV_EACCES)
        return JS_TRUE;
    if (r == UV_ESRCH)
        return JS_FALSE;
    return tjs_throw_errno(ctx, r);
}

static JSValue tjs_exec(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
#ifdef _WIN32
    return tjs_throw_errno_msg(ctx, UV_ENOSYS, "exec() not supported on Windows");
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
        if (len < 0) return JS_EXCEPTION;
        if (!args) return JS_ThrowTypeError(ctx, "exec: argv array must not be empty");
    } else {
        return JS_ThrowTypeError(ctx, "exec: expected string or array");
    }

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_PROCESS | TJS_CAP_IO_CONTROL, TJS_CAP_FLAG_REPLACEABLE, "process.exec"), tjs__free_args(ctx, args));

    execvp(args[0], args);
    /* execvp only returns on error */
    JSValue err = tjs_throw_errno(ctx, uv_translate_sys_error(errno));
    for (int i = 0; args[i]; i++) js_free(ctx, args[i]);
    js_free(ctx, args);
    return err;
#endif
}

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
    TJS_CFUNC_DEF("fork",      0, tjs_fork),
    TJS_CFUNC_DEF("kill",      2, tjs_kill),
    TJS_CFUNC_DEF("isAlive",   1, tjs_process_is_alive),
    TJS_CFUNC_DEF("exec",      1, tjs_exec),
};
/* clang-format on */

void tjs__mod_process_init(JSContext *ctx, JSValue ns) {
    if (tjs__streams_register_pipe_class(ctx) < 0) return;
    if (tjs_process_register_class(ctx) < 0) return;

    JSValue proto = JS_GetClassProto(ctx, tjs_process_class_id);
    if (JS_IsNull(proto)) {
        proto = JS_NewObject(ctx);
        if (JS_IsException(proto)) return;
        if (JS_SetPropertyFunctionList(ctx, proto, tjs_process_proto_funcs,
                                       countof(tjs_process_proto_funcs)) < 0) {
            JS_FreeValue(ctx, proto);
            return;
        }
        JS_SetClassProto(ctx, tjs_process_class_id, proto);
    } else {
        JS_FreeValue(ctx, proto);
    }

    if (JS_SetPropertyFunctionList(ctx, ns, tjs_process_funcs,
                                   countof(tjs_process_funcs)) < 0)
        return;
}
