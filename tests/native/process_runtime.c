#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "private.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

static pid_t fail_kill_pids[2];
static size_t fail_kill_pid_count;
static unsigned injected_kill_failures;
static volatile sig_atomic_t teardown_watchdog_pid;

static void teardown_timeout(int signal_number) {
    (void)signal_number;
    pid_t pid = (pid_t)teardown_watchdog_pid;
    if (pid > 0) {
        (void)syscall(SYS_kill, pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    _exit(124);
}

int kill(pid_t pid, int signal_number) {
    for (size_t i = 0; i < fail_kill_pid_count; i++) {
        if (pid == fail_kill_pids[i]) {
            injected_kill_failures++;
            errno = EPERM;
            return -1;
        }
    }
    return (int)syscall(SYS_kill, pid, signal_number);
}

static JSValue eval(JSContext *ctx, const char *source) {
    JSValue value = JS_Eval(ctx, source, strlen(source), "<process-runtime>",
                            JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(value)) TJS_DumpException(ctx);
    CHECK(!JS_IsException(value));
    return value;
}

static void init_module(JSContext *ctx, const char *name,
                        void (*initialize)(JSContext *, JSValue)) {
    JSValue namespace = JS_NewObject(ctx);
    CHECK(!JS_IsException(namespace));
    initialize(ctx, namespace);
    CHECK(!JS_HasException(ctx));
    JSValue global = JS_GetGlobalObject(ctx);
    CHECK_GE(JS_SetPropertyStr(ctx, global, name, namespace), 0);
    JS_FreeValue(ctx, global);
}

static TJSRuntime *new_runtime(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    init_module(runtime->main_ctx, "process", tjs__mod_process_init);
    /* The embedded runner normally unreferences this before executing JS. */
    uv_unref((uv_handle_t *)&runtime->stop);
    return runtime;
}

typedef struct {
    JSValue child;
    JSValue wait;
    JSValue wait_sync;
    JSValue nested_wait;
    bool finish_in_hook;
    bool called;
} WaitInitReentry;

static void wait_init_hook(JSContext *ctx, JSPromiseHookType type,
                           JSValueConst promise, JSValueConst parent,
                           void *opaque) {
    (void)promise;
    (void)parent;
    WaitInitReentry *state = opaque;
    if (type != JS_PROMISE_HOOK_INIT || state->called) return;
    state->called = true;
    JS_SetPromiseHook(JS_GetRuntime(ctx), NULL, NULL);
    if (state->finish_in_hook) {
        JSValue status = JS_Call(ctx, state->wait_sync, state->child, 0, NULL);
        CHECK(!JS_IsException(status));
        JS_FreeValue(ctx, status);
    } else {
        state->nested_wait = JS_Call(ctx, state->wait, state->child, 0, NULL);
        CHECK(!JS_IsException(state->nested_wait));
    }
}

static void test_wait_init_reentry(bool finish_in_hook) {
    TJSRuntime *runtime = new_runtime();
    JSContext *ctx = runtime->main_ctx;
    JSValue child = eval(ctx, "process.spawn(['/bin/sh', '-c', 'exit 19'])");
    JSValue wait = JS_GetPropertyStr(ctx, child, "wait");
    WaitInitReentry state = {
        .child = child,
        .wait = wait,
        .wait_sync = JS_GetPropertyStr(ctx, child, "waitSync"),
        .nested_wait = JS_UNDEFINED,
        .finish_in_hook = finish_in_hook,
    };
    CHECK(JS_IsFunction(ctx, wait));
    CHECK(JS_IsFunction(ctx, state.wait_sync));
    JS_SetPromiseHook(runtime->rt, wait_init_hook, &state);
    JSValue result = JS_Call(ctx, wait, child, 0, NULL);
    CHECK(!JS_IsException(result));
    CHECK(state.called);
    if (!finish_in_hook) {
        CHECK(JS_IsSameValue(ctx, result, state.nested_wait));
        CHECK_EQ(JS_PromiseState(ctx, result), JS_PROMISE_PENDING);
        JSValue repeated = JS_Call(ctx, wait, child, 0, NULL);
        CHECK(JS_IsSameValue(ctx, result, repeated));
        JS_FreeValue(ctx, repeated);
        JSValue sync_status = JS_Call(ctx, state.wait_sync, child, 0, NULL);
        CHECK(!JS_IsException(sync_status));
        JS_FreeValue(ctx, sync_status);
    }
    CHECK_EQ(JS_PromiseState(ctx, result), JS_PROMISE_FULFILLED);
    if (!finish_in_hook)
        CHECK_EQ(JS_PromiseState(ctx, state.nested_wait), JS_PROMISE_FULFILLED);
    JSValue status = JS_PromiseResult(ctx, result);
    JSValue code = JS_GetPropertyStr(ctx, status, "exit_status");
    int32_t exit_code;
    CHECK_EQ(JS_ToInt32(ctx, &exit_code, code), 0);
    CHECK_EQ(exit_code, 19);
    JS_FreeValue(ctx, code);
    JS_FreeValue(ctx, status);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, state.nested_wait);
    JS_FreeValue(ctx, state.wait_sync);
    JS_FreeValue(ctx, wait);
    JS_FreeValue(ctx, child);
    TJS_FreeRuntime(runtime);
}

static void test_process_classes_across_runtimes(void) {
    TJSRuntime *first_runtime = new_runtime();
    TJSRuntime *second_runtime = TJS_NewRuntime();
    CHECK(second_runtime);
    uv_unref((uv_handle_t *)&second_runtime->stop);
    JSContext *first_context = first_runtime->main_ctx;
    JSContext *second_context = second_runtime->main_ctx;
    JSValue first_child = eval(first_context,
        "globalThis.child = process.spawn(['/bin/sleep', '60'],"
        " { stdout: 'pipe' }); child");
    JSValue first_process_proto = JS_GetPrototype(first_context, first_child);
    JSValue first_pipe = JS_GetPropertyStr(first_context, first_child, "stdout");
    JSValue first_pipe_proto = JS_GetPrototype(first_context, first_pipe);
    CHECK(JS_IsObject(first_process_proto));
    CHECK(JS_IsObject(first_pipe_proto));
    init_module(first_context, "process", tjs__mod_process_init);
    init_module(first_context, "streams", tjs__mod_streams_init);
    init_module(first_context, "streams", tjs__mod_streams_init);
    JSValue later_pipe = eval(first_context, "new streams.Pipe()");
    JSValue later_pipe_proto = JS_GetPrototype(first_context, later_pipe);
    CHECK(JS_IsSameValue(first_context, first_pipe_proto, later_pipe_proto));
    JS_FreeValue(first_context, later_pipe_proto);
    JS_FreeValue(first_context, later_pipe);

    init_module(second_context, "streams", tjs__mod_streams_init);
    JSValue second_tcp = eval(second_context,
        "globalThis.tcpBeforeProcess = new streams.TCP()");
    init_module(second_context, "process", tjs__mod_process_init);
    JSValue streams_valid = eval(second_context,
        "globalThis.tcpAfterProcess = new streams.TCP();"
        " Object.getPrototypeOf(tcpBeforeProcess) ==="
        " Object.getPrototypeOf(tcpAfterProcess) &&"
        " typeof tcpAfterProcess.bind === 'function'");
    CHECK_EQ(JS_ToBool(second_context, streams_valid), 1);
    JS_FreeValue(second_context, streams_valid);
    JSValue second_child = eval(second_context,
        "globalThis.child = process.spawn(['/bin/sleep', '60'],"
        " { stdout: 'pipe' }); child");
    CHECK_EQ(JS_GetClassID(first_child), JS_GetClassID(second_child));
    JSValue second_pipe = JS_GetPropertyStr(second_context, second_child, "stdout");
    CHECK_EQ(JS_GetClassID(first_pipe), JS_GetClassID(second_pipe));
    JS_FreeValue(second_context, second_pipe);
    JSValue later_child = eval(first_context,
        "globalThis.laterChild = process.spawn(['/bin/true']);"
        " laterChild.waitSync(); laterChild");
    JSValue later_process_proto = JS_GetPrototype(first_context, later_child);
    CHECK(JS_IsSameValue(first_context, first_process_proto, later_process_proto));
    JS_FreeValue(first_context, later_process_proto);
    JS_FreeValue(first_context, later_child);
    JS_FreeValue(first_context, first_process_proto);
    JS_FreeValue(first_context, first_pipe_proto);
    JS_FreeValue(first_context, first_pipe);

    JSContext *realm = JS_NewContext(first_runtime->rt);
    CHECK(realm);
    init_module(realm, "process", tjs__mod_process_init);
    init_module(realm, "streams", tjs__mod_streams_init);
    JSValue realm_child = eval(realm,
        "globalThis.child = process.spawn(['/bin/true'], { stdout: 'pipe' });"
        " child.waitSync(); child");
    JSValue realm_proto = JS_GetPrototype(realm, realm_child);
    JSValue realm_pipe = JS_GetPropertyStr(realm, realm_child, "stdout");
    JSValue realm_pipe_proto = JS_GetPrototype(realm, realm_pipe);
    CHECK(JS_IsObject(realm_proto));
    CHECK(JS_IsObject(realm_pipe_proto));
    JSValue realm_methods = eval(realm,
        "typeof child.wait === 'function' &&"
        " typeof child.stdout.read === 'function' &&"
        " typeof child.stdout.close === 'function'");
    CHECK_EQ(JS_ToBool(realm, realm_methods), 1);
    JS_FreeValue(realm, realm_methods);
    JS_FreeValue(realm, realm_pipe_proto);
    JS_FreeValue(realm, realm_pipe);
    JS_FreeValue(realm, realm_proto);
    JS_FreeValue(realm, realm_child);
    JS_FreeContext(realm);
    JSValue tcp_bind = JS_GetPropertyStr(second_context, second_tcp, "bind");
    CHECK(JS_IsFunction(second_context, tcp_bind));
    JS_FreeValue(second_context, tcp_bind);

    TJSRuntime *runtimes[] = { first_runtime, second_runtime };
    for (unsigned runtime_index = 0; runtime_index < countof(runtimes); runtime_index++) {
        TJSRuntime *runtime = runtimes[runtime_index];
        JSContext *ctx = runtime->main_ctx;
        JSValue valid = eval(ctx,
            "child.pid > 0 && typeof child.wait === 'function' &&"
            " typeof child.waitSync === 'function' &&"
            " typeof child.kill === 'function' &&"
            " child.stdout instanceof Object &&"
            " typeof child.stdout.read === 'function' &&"
            " typeof child.stdout.close === 'function'");
        CHECK_EQ(JS_ToBool(ctx, valid), 1);
        JS_FreeValue(ctx, valid);
        JSValue status = eval(ctx,
            "globalThis.wait = child.wait(); child.kill();"
            " child.waitSync().term_signal");
        int32_t term_signal;
        CHECK_EQ(JS_ToInt32(ctx, &term_signal, status), 0);
        CHECK_EQ(term_signal, SIGTERM);
        JS_FreeValue(ctx, status);
        tjs__execute_jobs(runtime);
        JSValue wait = eval(ctx, "wait");
        CHECK_EQ(JS_PromiseState(ctx, wait), JS_PROMISE_FULFILLED);
        JS_FreeValue(ctx, wait);
    }

    for (unsigned runtime_index = 0; runtime_index < countof(runtimes); runtime_index++)
        CHECK_EQ(uv_run(&runtimes[runtime_index]->loop, UV_RUN_NOWAIT), 0);

    for (unsigned runtime_index = 0; runtime_index < countof(runtimes); runtime_index++) {
        JSContext *ctx = runtimes[runtime_index]->main_ctx;
        int expected_status = 31 + (int)runtime_index;
        JSValue child = eval(ctx, "globalThis.forked = process.fork()");
        if (JS_IsNull(child)) _exit(expected_status);
        CHECK(JS_IsObject(child));
        JSValue status = eval(ctx, "forked.waitSync().exit_status");
        int32_t exit_status;
        CHECK_EQ(JS_ToInt32(ctx, &exit_status, status), 0);
        CHECK_EQ(exit_status, expected_status);
        JS_FreeValue(ctx, status);
        JS_FreeValue(ctx, child);
        CHECK_EQ(uv_run(&runtimes[runtime_index]->loop, UV_RUN_NOWAIT), 0);
    }

    JS_FreeValue(first_context, first_child);
    JS_FreeValue(second_context, second_child);
    JS_FreeValue(second_context, second_tcp);
    TJS_FreeRuntime(second_runtime);
    JSValue valid = eval(first_context,
        "child.pid > 0 && typeof child.wait === 'function'");
    CHECK_EQ(JS_ToBool(first_context, valid), 1);
    JS_FreeValue(first_context, valid);
    JSValue status = eval(first_context, "child.waitSync().term_signal");
    int32_t term_signal;
    CHECK_EQ(JS_ToInt32(first_context, &term_signal, status), 0);
    CHECK_EQ(term_signal, SIGTERM);
    JS_FreeValue(first_context, status);
    TJS_FreeRuntime(first_runtime);
}

static unsigned fork_jobs_run;

static JSValue fork_last_job(JSContext *ctx, int argc, JSValueConst *argv) {
    CHECK(!JS_IsJobPending(JS_GetRuntime(ctx)));
    JSValue child = eval(ctx, "process.fork()");
    if (JS_IsNull(child)) _exit(23);
    CHECK(JS_IsObject(child));
    JSValue wait = JS_GetPropertyStr(ctx, child, "waitSync");
    JSValue status = JS_Call(ctx, wait, child, 0, NULL);
    CHECK(!JS_IsException(status));
    JSValue code = JS_GetPropertyStr(ctx, status, "exit_status");
    int32_t exit_code;
    CHECK_EQ(JS_ToInt32(ctx, &exit_code, code), 0);
    CHECK_EQ(exit_code, 23);
    JS_FreeValue(ctx, code);
    JS_FreeValue(ctx, status);
    JS_FreeValue(ctx, wait);
    JS_FreeValue(ctx, child);
    fork_jobs_run++;
    return JS_UNDEFINED;
}

static void test_fork_last_job(void) {
    TJSRuntime *runtime = new_runtime();
    CHECK_EQ(JS_EnqueueJob(runtime->main_ctx, fork_last_job, 0, NULL), 0);
    tjs__notify_work(runtime);
    CHECK(uv_is_active((uv_handle_t *)&runtime->jobs.idle));
    tjs__execute_jobs(runtime);
    CHECK_EQ(fork_jobs_run, 1);
    TJS_FreeRuntime(runtime);
}

static void unused_timer(uv_timer_t *timer) {
    CHECK(false);
}

static void test_fork_rejects_unref_timer(void) {
    TJSRuntime *runtime = new_runtime();
    uv_timer_t timer;
    CHECK_EQ(uv_timer_init(&runtime->loop, &timer), 0);
    CHECK_EQ(uv_timer_start(&timer, unused_timer, 60000, 0), 0);
    uv_unref((uv_handle_t *)&timer);
    CHECK(!uv_loop_alive(&runtime->loop));
    JSValue result = eval(runtime->main_ctx,
        "(() => { try { process.fork(); return false; }"
        " catch (error) { return error instanceof TypeError &&"
        " error.message.includes('idle event loop'); } })()");
    CHECK(JS_ToBool(runtime->main_ctx, result));
    JS_FreeValue(runtime->main_ctx, result);
    uv_close((uv_handle_t *)&timer, NULL);
    uv_run(&runtime->loop, UV_RUN_NOWAIT);
    TJS_FreeRuntime(runtime);
}

static void test_teardown_reaps_children(void) {
    TJSRuntime *runtime = new_runtime();
    JSContext *ctx = runtime->main_ctx;
    /* Include a failed spawn (closing handle, no JS wrapper) beside two live
     * children. Their wait promises and pipes hold each other's wrappers. */
    JSValue children = eval(ctx,
        "(() => {"
        " try { process.spawn(['/circu-test-missing-executable']); } catch {}"
        " const a = process.spawn(['/bin/sleep', '60'], { stdout: 'pipe' });"
        " const b = process.spawn([], { pty: true, name: '/bin/sleep',"
        " argv: ['sleep', '60'] });"
        " a.wait().peer = b; b.wait().peer = a;"
        " a.stdout.peer = b;"
        " return [a.pid, b.pid];"
        "})()");
    int32_t pids[2];
    for (unsigned i = 0; i < 2; i++) {
        JSValue pid = JS_GetPropertyUint32(ctx, children, i);
        CHECK_EQ(JS_ToInt32(ctx, &pids[i], pid), 0);
        CHECK_GT(pids[i], 0);
        JS_FreeValue(ctx, pid);
    }
    JS_FreeValue(ctx, children);
    TJS_FreeRuntime(runtime);
    for (unsigned i = 0; i < 2; i++) {
        int status;
        errno = 0;
        CHECK_EQ(waitpid(pids[i], &status, WNOHANG), -1);
        CHECK_EQ(errno, ECHILD);
    }
}

static void test_teardown_does_not_wait_after_kill_failure(void) {
    TJSRuntime *runtime = new_runtime();
    JSContext *ctx = runtime->main_ctx;
    JSValue children = eval(ctx,
        "globalThis.children = ["
        " process.spawn(['/bin/sleep', '60']).pid,"
        " process.spawn(['/bin/sleep', '60']).pid"
        "]; children");
    int32_t pids[2];
    for (unsigned i = 0; i < countof(pids); i++) {
        JSValue child_pid = JS_GetPropertyUint32(ctx, children, i);
        CHECK_EQ(JS_ToInt32(ctx, &pids[i], child_pid), 0);
        CHECK_GT(pids[i], 0);
        JS_FreeValue(ctx, child_pid);
    }
    JS_FreeValue(ctx, children);

    struct sigaction timeout_action = { 0 };
    struct sigaction previous_action;
    timeout_action.sa_handler = teardown_timeout;
    sigemptyset(&timeout_action.sa_mask);
    CHECK_EQ(sigaction(SIGALRM, &timeout_action, &previous_action), 0);
    teardown_watchdog_pid = (sig_atomic_t)pids[0];
    alarm(5);
    fail_kill_pids[0] = (pid_t)pids[0];
    fail_kill_pids[1] = (pid_t)pids[1];
    fail_kill_pid_count = countof(fail_kill_pids);
    TJS_FreeRuntime(runtime);
    alarm(0);
    fail_kill_pid_count = 0;
    fail_kill_pids[0] = 0;
    fail_kill_pids[1] = 0;
    teardown_watchdog_pid = 0;
    CHECK_EQ(sigaction(SIGALRM, &previous_action, NULL), 0);
    CHECK_EQ(injected_kill_failures, countof(pids));

    for (unsigned i = 0; i < countof(pids); i++)
        CHECK_EQ(syscall(SYS_kill, (pid_t)pids[i], SIGKILL), 0);

    /* Observe without consuming the status: only the runtime's reaper may
     * transition this child from waitable to ECHILD. */
    for (unsigned i = 0; i < countof(pids); i++) {
        bool reaped = false;
        for (unsigned attempt = 0; attempt < 5000; attempt++) {
            siginfo_t info;
            memset(&info, 0, sizeof(info));
            if (waitid(P_PID, (id_t)pids[i], &info,
                       WEXITED | WNOHANG | WNOWAIT) == -1) {
                if (errno == ECHILD) {
                    reaped = true;
                    break;
                }
                CHECK_EQ(errno, EINTR);
            }
            uv_sleep(1);
        }
        if (!reaped) {
            int status;
            (void)waitpid((pid_t)pids[i], &status, 0);
        }
        CHECK(reaped);
    }

    /* A later raw fork must join the now-idle reaper thread before forking. */
    runtime = new_runtime();
    ctx = runtime->main_ctx;
    JSValue forked = eval(ctx, "globalThis.forked = process.fork()");
    if (JS_IsNull(forked)) _exit(37);
    JSValue status = eval(ctx, "forked.waitSync().exit_status");
    int32_t exit_status;
    CHECK_EQ(JS_ToInt32(ctx, &exit_status, status), 0);
    CHECK_EQ(exit_status, 37);
    JS_FreeValue(ctx, status);
    JS_FreeValue(ctx, forked);
    TJS_FreeRuntime(runtime);
}

int main(void) {
    test_wait_init_reentry(true);
    test_wait_init_reentry(false);
    test_process_classes_across_runtimes();
    test_fork_last_job();
    test_fork_rejects_unref_timer();
    test_teardown_reaps_children();
    test_teardown_does_not_wait_after_kill_failure();
    return 0;
}
