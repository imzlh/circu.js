#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "private.h"

#include <string.h>
#include <fcntl.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#endif
#ifndef _WIN32
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <poll.h>
#endif

typedef struct {
    JSValue target;
    JSValue buffer;
    const char *method;
    bool called;
    bool threw;
} HookState;

typedef struct {
    uv_work_t req;
    uv_sem_t *started;
    uv_sem_t *release;
    unsigned *completed;
} Blocker;

static JSValue call(JSContext *ctx, JSValue obj, const char *method,
                    int argc, JSValue *argv) {
    JSValue fn = JS_GetPropertyStr(ctx, obj, method);
    CHECK(JS_IsFunction(ctx, fn));
    JSValue result = JS_Call(ctx, fn, obj, argc, argv);
    JS_FreeValue(ctx, fn);
    return result;
}

static void promise_hook(JSContext *ctx, JSPromiseHookType type,
                          JSValueConst promise, JSValueConst parent,
                          void *opaque) {
    (void)promise;
    (void)parent;
    HookState *state = opaque;
    if (type != JS_PROMISE_HOOK_INIT || state->called) return;
    state->called = true;
    JS_SetPromiseHook(JS_GetRuntime(ctx), NULL, NULL);
    if (!JS_IsUndefined(state->buffer)) {
        CHECK_EQ(JS_DetachArrayBuffer(ctx, state->buffer), 0);
    } else {
        JSValue result = call(ctx, state->target, state->method, 0, NULL);
        state->threw = JS_IsException(result);
        if (state->threw) JS_FreeValue(ctx, JS_GetException(ctx));
        JS_FreeValue(ctx, result);
    }
}

static JSValue await_result(TJSRuntime *runtime, JSValue promise) {
    JSContext *ctx = runtime->main_ctx;
    CHECK(!JS_IsException(promise));
    while (JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING)
        uv_run(&runtime->loop, UV_RUN_ONCE);
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_FULFILLED);
    JSValue result = JS_PromiseResult(ctx, promise);
    JS_FreeValue(ctx, promise);
    return result;
}

static JSValue await_result_before(TJSRuntime *runtime, JSValue promise,
                                   uint64_t timeout_ns) {
    JSContext *ctx = runtime->main_ctx;
    uint64_t deadline = uv_hrtime() + timeout_ns;
    CHECK(!JS_IsException(promise));
    while (JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING) {
        CHECK_LT(uv_hrtime(), deadline);
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    }
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_FULFILLED);
    JSValue result = JS_PromiseResult(ctx, promise);
    JS_FreeValue(ctx, promise);
    return result;
}

static JSValue module(TJSRuntime *runtime) {
    JSValue ns = JS_NewObject(runtime->main_ctx);
    CHECK(!JS_IsException(ns));
    tjs__mod_asyncfs_init(runtime->main_ctx, ns);
    return ns;
}

#if defined(__linux__) || defined(_WIN32)
#define ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED 1
#else
#define ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED 0
#endif

static void close_test_fd(uv_file fd) {
    uv_fs_t req;
    CHECK_EQ(uv_fs_close(NULL, &req, fd, NULL), 0);
    uv_fs_req_cleanup(&req);
}

static void block_work(uv_work_t *req) {
    Blocker *blocker = req->data;
    uv_sem_post(blocker->started);
    uv_sem_wait(blocker->release);
}

static void after_block(uv_work_t *req, int status) {
    Blocker *blocker = req->data;
    CHECK_EQ(status, 0);
    (*blocker->completed)++;
}

static void test_directory_teardown(bool close_directory) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, ".");
    JSValue dir = await_result(runtime, call(ctx, ns, "readDir", 1, &path));
    JS_FreeValue(ctx, path);

    uv_sem_t started, release;
    CHECK_EQ(uv_sem_init(&started, 0), 0);
    CHECK_EQ(uv_sem_init(&release, 0), 0);
    Blocker blockers[4];
    unsigned completed = 0;
    for (size_t i = 0; i < countof(blockers); i++) {
        blockers[i].started = &started;
        blockers[i].release = &release;
        blockers[i].completed = &completed;
        blockers[i].req.data = &blockers[i];
        CHECK_EQ(uv_queue_work(&runtime->loop, &blockers[i].req,
                               block_work, after_block), 0);
    }
    for (size_t i = 0; i < countof(blockers); i++) uv_sem_wait(&started);

    JSValue pending = call(ctx, dir, close_directory ? "close" : "next", 0, NULL);
    CHECK(!JS_IsException(pending));
    JS_FreeValue(ctx, pending);
    JS_FreeValue(ctx, dir);
    JS_FreeValue(ctx, ns);
    /* Deterministically cancel a queued CLOSEDIR/READDIR before its worker
     * starts, then let runtime teardown deliver the canceled callback. */
    tjs__mod_asyncfs_cleanup_runtime(runtime);
    runtime->freeing = true;
    for (size_t i = 0; i < countof(blockers); i++) uv_sem_post(&release);
    /* These blockers belong to the test, not the runtime's request registry.
     * Drain them ourselves while canceled FS callbacks take the teardown path. */
    while (completed != countof(blockers))
        uv_run(&runtime->loop, UV_RUN_ONCE);
    TJS_FreeRuntime(runtime);
    uv_sem_destroy(&started);
    uv_sem_destroy(&release);
}

static void test_promise_reentry(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    uv_fs_t req;
    int fd = uv_fs_mkstemp(NULL, &req, "asyncfs-review-XXXXXX", NULL);
    CHECK_GE(fd, 0);
    char *filename = js_strdup(ctx, req.path);
    CHECK(filename);
    uv_fs_req_cleanup(&req);
    JSValue options = JS_NewObject(ctx);
    CHECK_EQ(JS_SetPropertyStr(ctx, options, "closeOnClose",
                               ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED
                                   ? JS_TRUE
                                   : JS_FALSE), 1);
    JSValue create_args[] = { JS_NewInt32(ctx, fd), JS_UNDEFINED, options };
    JSValue file = call(ctx, ns, "createFrom", countof(create_args), create_args);
    JS_FreeValue(ctx, options);
    CHECK(!JS_IsException(file));

    JSValue bytes = JS_NewUint8ArrayCopy(ctx, (const uint8_t *)"test", 4);
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, bytes, NULL, NULL, NULL);
    CHECK(!JS_IsException(buffer));
    HookState state = { .target = file, .buffer = buffer };
    JS_SetPromiseHook(runtime->rt, promise_hook, &state);
    JSValue result = call(ctx, file, "write", 1, &bytes);
    CHECK(state.called);
    CHECK(JS_IsException(result));
    JS_FreeValue(ctx, JS_GetException(ctx));
    JS_FreeValue(ctx, bytes);
    JS_FreeValue(ctx, buffer);

    state = (HookState) { .target = file, .buffer = JS_UNDEFINED, .method = "close" };
    JS_SetPromiseHook(runtime->rt, promise_hook, &state);
    result = await_result(runtime, call(ctx, file, "stat", 0, NULL));
    CHECK(state.called && state.threw);
    JS_FreeValue(ctx, result);
    state = (HookState) { .target = file, .buffer = JS_UNDEFINED, .method = "detach" };
    JS_SetPromiseHook(runtime->rt, promise_hook, &state);
    result = await_result(runtime, call(ctx, file, "stat", 0, NULL));
    CHECK(state.called && state.threw);
    JS_FreeValue(ctx, result);
    state.method = "close";
    state.called = state.threw = false;
    JS_SetPromiseHook(runtime->rt, promise_hook, &state);
    result = await_result(runtime, call(ctx, file, "close", 0, NULL));
    CHECK(state.called && state.threw);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, file);
    if (!ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED)
        close_test_fd(fd);

    JSValue path = JS_NewString(ctx, ".");
    JSValue dir = await_result(runtime, call(ctx, ns, "readDir", 1, &path));
    JS_FreeValue(ctx, path);
    state = (HookState) { .target = dir, .buffer = JS_UNDEFINED, .method = "close" };
    JS_SetPromiseHook(runtime->rt, promise_hook, &state);
    result = await_result(runtime, call(ctx, dir, "next", 0, NULL));
    CHECK(state.called && state.threw);
    JS_FreeValue(ctx, result);
    state = (HookState) { .target = dir, .buffer = JS_UNDEFINED, .method = "next" };
    JS_SetPromiseHook(runtime->rt, promise_hook, &state);
    result = await_result(runtime, call(ctx, dir, "close", 0, NULL));
    CHECK(state.called && !state.threw);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, dir);
    JS_FreeValue(ctx, ns);
    CHECK_EQ(uv_fs_unlink(NULL, &req, filename, NULL), 0);
    uv_fs_req_cleanup(&req);
    js_free(ctx, filename);
    TJS_FreeRuntime(runtime);
}

static void test_file_detach(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    uv_fs_t req;
    int fd = uv_fs_mkstemp(NULL, &req, "asyncfs-detach-XXXXXX", NULL);
    CHECK_GE(fd, 0);
    char *filename = js_strdup(ctx, req.path);
    CHECK(filename);
    uv_fs_req_cleanup(&req);
    JSValue options = JS_NewObject(ctx);
    CHECK_EQ(JS_SetPropertyStr(ctx, options, "closeOnClose",
                               ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED
                                   ? JS_TRUE
                                   : JS_FALSE), 1);
    JSValue create_args[] = { JS_NewInt32(ctx, fd), JS_UNDEFINED, options };
    JSValue file = call(ctx, ns, "createFrom", countof(create_args), create_args);
    JS_FreeValue(ctx, options);
    CHECK(!JS_IsException(file));
    JSValue result = call(ctx, file, "detach", 0, NULL);
    CHECK(!JS_IsException(result));
    int detached_fd;
    CHECK_EQ(JS_ToInt32(ctx, &detached_fd, result), 0);
    if (ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED)
        CHECK_EQ(detached_fd, fd);
    else
        CHECK_NE(detached_fd, fd);
    JS_FreeValue(ctx, result);
    result = call(ctx, file, "fileno", 0, NULL);
    CHECK(JS_IsException(result));
    JS_FreeValue(ctx, JS_GetException(ctx));
    JS_FreeValue(ctx, file);
    JS_RunGC(runtime->rt);
    CHECK_EQ(uv_fs_fstat(NULL, &req, detached_fd, NULL), 0);
    uv_fs_req_cleanup(&req);
    close_test_fd(detached_fd);
    if (!ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED)
        close_test_fd(fd);
    CHECK_EQ(uv_fs_unlink(NULL, &req, filename, NULL), 0);
    uv_fs_req_cleanup(&req);
    js_free(ctx, filename);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
}

#ifndef _WIN32
typedef struct {
    int target_fd;
    int replacement_fd;
    bool reused;
} ReuseFdHookState;

static JSValue reuse_fd_hook(JSContext *ctx, const TJSCapability *capability,
                             void *opaque) {
    ReuseFdHookState *state = opaque;
    if (!state->reused && strcmp(capability->api, "asyncfs.createFrom") == 0) {
        if (close(state->target_fd) != 0)
            return JS_ThrowInternalError(ctx, "close test fd failed");
        if (dup2(state->replacement_fd, state->target_fd) < 0)
            return JS_ThrowInternalError(ctx, "replace test fd failed");
        state->reused = true;
    }
    return TJS_CAPABILITY_PASS;
}

static void test_close_on_close_reused_same_inode(void) {
    char scratch[] = "/tmp/cjs-asyncfs-XXXXXX";
    CHECK(mkdtemp(scratch));
    char filename[sizeof(scratch) + 8];
    snprintf(filename, sizeof(filename), "%s/file", scratch);
    int first = open(filename, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    CHECK_GE(first, 0);
    int second = open(filename, O_RDWR | O_CLOEXEC);
    CHECK_GE(second, 0);
    struct stat first_stat;
    struct stat second_stat;
    CHECK_EQ(fstat(first, &first_stat), 0);
    CHECK_EQ(fstat(second, &second_stat), 0);
    CHECK_EQ(first_stat.st_dev, second_stat.st_dev);
    CHECK_EQ(first_stat.st_ino, second_stat.st_ino);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    ReuseFdHookState hook_state = {
        .target_fd = first,
        .replacement_fd = second,
    };
    CHECK(TJS_SetCapabilityHook(runtime, reuse_fd_hook, &hook_state, 0));
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue options = JS_NewObject(ctx);
    CHECK_EQ(JS_SetPropertyStr(ctx, options, "closeOnClose", JS_TRUE), 1);
    JSValue create_args[] = { JS_NewInt32(ctx, first), JS_UNDEFINED, options };
    JSValue file = call(ctx, ns, "createFrom", countof(create_args), create_args);
    JS_FreeValue(ctx, options);
    TJS_SetCapabilityHook(runtime, NULL, NULL, 0);
    CHECK(hook_state.reused);

    if (ASYNCFS_TEST_CLOSE_ON_CLOSE_SUPPORTED) {
        CHECK(!JS_IsException(file));
        JSValue detached = call(ctx, file, "detach", 0, NULL);
        CHECK(!JS_IsException(detached));
        int pinned_fd;
        CHECK_EQ(JS_ToInt32(ctx, &pinned_fd, detached), 0);
        CHECK_NE(pinned_fd, first);
        close_test_fd(pinned_fd);
        JS_FreeValue(ctx, detached);
        JS_FreeValue(ctx, file);
    } else {
        CHECK(JS_IsException(file));
        JSValue exception = JS_GetException(ctx);
        const char *message = JS_ToCString(ctx, exception);
        CHECK(message);
        CHECK(strcmp(message,
                     "TypeError: object handle identity comparison is not supported on this platform") == 0);
        JS_FreeCString(ctx, message);
        JS_FreeValue(ctx, exception);
    }
    CHECK(fcntl(first, F_GETFD) >= 0);
    JS_FreeValue(ctx, ns);

    TJS_FreeRuntime(runtime);
    CHECK_EQ(close(first), 0);
    CHECK_EQ(close(second), 0);
    CHECK_EQ(unlink(filename), 0);
    CHECK_EQ(rmdir(scratch), 0);
}

static void test_file_pipe_io(void) {
    int pipe_fds[2];
    CHECK_EQ(pipe(pipe_fds), 0);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue create_args[] = { JS_NewInt32(ctx, pipe_fds[0]) };
    JSValue file = call(ctx, ns, "createFrom", countof(create_args), create_args);
    CHECK(!JS_IsException(file));
    int original_flags = fcntl(pipe_fds[0], F_GETFL);
    CHECK_GE(original_flags, 0);
    uint8_t storage[8] = { 0 };
    JSValue bytes = JS_NewUint8ArrayCopy(ctx, storage, sizeof(storage));
    JSValue pending = call(ctx, file, "read", 1, &bytes);
    CHECK(!JS_IsException(pending));
    CHECK_EQ(JS_PromiseState(ctx, pending), JS_PROMISE_PENDING);
    CHECK_EQ(fcntl(pipe_fds[0], F_GETFL), original_flags);
    CHECK_EQ(write(pipe_fds[1], "pipe", 4), 4);
    JSValue result = await_result_before(runtime, pending, UINT64_C(3000000000));
    int count;
    CHECK_EQ(JS_ToInt32(ctx, &count, result), 0);
    CHECK_EQ(count, 4);
    JS_FreeValue(ctx, result);
    size_t length;
    uint8_t *data = JS_GetUint8Array(ctx, &length, bytes);
    CHECK(data && length == sizeof(storage));
    CHECK_EQ(memcmp(data, "pipe", 4), 0);
    CHECK_EQ(fcntl(pipe_fds[0], F_GETFL), original_flags);

    JSValue writer_fd = JS_NewInt32(ctx, pipe_fds[1]);
    JSValue writer = call(ctx, ns, "createFrom", 1, &writer_fd);
    CHECK(!JS_IsException(writer));
    JSValue payload = JS_NewUint8ArrayCopy(ctx, (const uint8_t *)"out", 3);
    result = await_result_before(runtime, call(ctx, writer, "write", 1, &payload),
                                  UINT64_C(3000000000));
    CHECK_EQ(JS_ToInt32(ctx, &count, result), 0);
    CHECK_EQ(count, 3);
    JS_FreeValue(ctx, result);
    CHECK_EQ(read(pipe_fds[0], storage, sizeof(storage)), 3);
    CHECK_EQ(memcmp(storage, "out", 3), 0);
    JS_FreeValue(ctx, payload);
    JS_FreeValue(ctx, writer);
    CHECK_EQ(close(pipe_fds[1]), 0);
    result = await_result_before(runtime, call(ctx, file, "read", 1, &bytes),
                                  UINT64_C(3000000000));
    CHECK(JS_IsNull(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, bytes);
    JS_FreeValue(ctx, file);
    JS_FreeValue(ctx, ns);
    CHECK_EQ(close(pipe_fds[0]), 0);
    TJS_FreeRuntime(runtime);
}

static void test_file_special_and_directory_io(void) {
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    uv_fs_t req;
    int fd = uv_fs_open(NULL, &req, "/dev/null", O_RDWR, 0, NULL);
    uv_fs_req_cleanup(&req);
    CHECK_GE(fd, 0);
    JSValue descriptor = JS_NewInt32(ctx, fd);
    JSValue file = call(ctx, ns, "createFrom", 1, &descriptor);
    CHECK(!JS_IsException(file));
    JSValue empty = JS_NewUint8ArrayCopy(ctx, (const uint8_t *)"", 0);
    JSValue result = await_result_before(runtime, call(ctx, file, "write", 1, &empty),
                                          UINT64_C(3000000000));
    int count;
    CHECK_EQ(JS_ToInt32(ctx, &count, result), 0);
    CHECK_EQ(count, 0);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, empty);
    JSValue bytes = JS_NewUint8ArrayCopy(ctx, (const uint8_t *)"a", 1);
    result = await_result_before(runtime, call(ctx, file, "read", 1, &bytes),
                                  UINT64_C(3000000000));
    CHECK(JS_IsNull(result));
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, file);
    close_test_fd(fd);

    fd = uv_fs_open(NULL, &req, ".", O_RDONLY, 0, NULL);
    uv_fs_req_cleanup(&req);
    CHECK_GE(fd, 0);
    descriptor = JS_NewInt32(ctx, fd);
    file = call(ctx, ns, "createFrom", 1, &descriptor);
    CHECK(!JS_IsException(file));
    char byte;
    uv_buf_t buffer = uv_buf_init(&byte, 1);
    int expected = uv_fs_read(NULL, &req, fd, &buffer, 1, -1, NULL);
    uv_fs_req_cleanup(&req);
    JSValue promise = call(ctx, file, "read", 1, &bytes);
    CHECK(!JS_IsException(promise));
    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    while (JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING) {
        CHECK_LT(uv_hrtime(), deadline);
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    }
    result = JS_PromiseResult(ctx, promise);
    if (expected < 0) {
        CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_REJECTED);
        JSValue error_number = JS_GetPropertyStr(ctx, result, "code");
        CHECK_EQ(JS_ToInt32(ctx, &count, error_number), 0);
        CHECK_EQ(count, expected);
        JS_FreeValue(ctx, error_number);
    } else {
        CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_FULFILLED);
    }
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, bytes);
    JS_FreeValue(ctx, file);
    close_test_fd(fd);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
}
#endif

static void test_file_pipe_pending_teardown(bool writing) {
    uv_file fds[2];
    CHECK_EQ(uv_pipe(fds, 0, 0), 0);
    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue descriptor = JS_NewInt32(ctx, fds[writing ? 1 : 0]);
    JSValue file = call(ctx, ns, "createFrom", 1, &descriptor);
    CHECK(!JS_IsException(file));
    size_t length = writing ? 1024 * 1024 : 8;
    uint8_t *storage = js_mallocz(ctx, length);
    CHECK(storage);
    JSValue bytes = JS_NewUint8ArrayCopy(ctx, storage, length);
    js_free(ctx, storage);
    CHECK(!JS_IsException(bytes));
    JSValue promise = call(ctx, file, writing ? "write" : "read", 1, &bytes);
    CHECK(!JS_IsException(promise));
    /* Keep the peer open without consuming or producing data. A large write
     * must encounter pipe backpressure; the read has no way to complete. */
    uint64_t deadline = uv_hrtime() + UINT64_C(50000000);
    do {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    } while (uv_hrtime() < deadline);
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, bytes);
    JS_FreeValue(ctx, file);
    JS_FreeValue(ctx, ns);
    uint64_t start = uv_hrtime();
    TJS_FreeRuntime(runtime);
    CHECK_LT(uv_hrtime() - start, UINT64_C(3000000000));
    close_test_fd(fds[0]);
    close_test_fd(fds[1]);
}

#ifndef _WIN32
typedef struct {
    const char *path;
    uv_sem_t opened;
    uv_sem_t release;
    uv_sem_t closed;
    const char *payload;
} FifoWriter;

static void fifo_writer(void *opaque) {
    FifoWriter *writer = opaque;
    int fd = open(writer->path, O_WRONLY);
    CHECK_GE(fd, 0);
    uv_sem_post(&writer->opened);
    uv_sem_wait(&writer->release);
    if (writer->payload) {
        size_t length = strlen(writer->payload);
        CHECK_EQ(write(fd, writer->payload, length), (ssize_t) length);
    }
    CHECK_EQ(close(fd), 0);
    uv_sem_post(&writer->closed);
}

static void fifo_init(const char *filename, FifoWriter *writer,
                      uv_thread_t *thread, const char *payload) {
    writer->path = filename;
    writer->payload = payload;
    CHECK_EQ(uv_sem_init(&writer->opened, 0), 0);
    CHECK_EQ(uv_sem_init(&writer->release, 0), 0);
    CHECK_EQ(uv_sem_init(&writer->closed, 0), 0);
    CHECK_EQ(uv_thread_create(thread, fifo_writer, writer), 0);
}

static void fifo_destroy(FifoWriter *writer, uv_thread_t *thread) {
    CHECK_EQ(uv_thread_join(thread), 0);
    uv_sem_destroy(&writer->opened);
    uv_sem_destroy(&writer->release);
    uv_sem_destroy(&writer->closed);
}

#ifdef __linux__
static _Atomic(FifoWriter *) empty_fifo_writer;

/* Interpose only in this test executable so the writer closes before the
 * readFile worker's first poll/read, without a production test hook. */
int poll(struct pollfd *fds, nfds_t count, int timeout) {
    FifoWriter *writer = atomic_load_explicit(&empty_fifo_writer,
                                             memory_order_acquire);
    if (writer && count == 1 && fds[0].events == POLLIN) {
        struct stat fd_stat, path_stat;
        if (fstat(fds[0].fd, &fd_stat) == 0 &&
            stat(writer->path, &path_stat) == 0 &&
            fd_stat.st_dev == path_stat.st_dev &&
            fd_stat.st_ino == path_stat.st_ino) {
            writer = atomic_exchange_explicit(&empty_fifo_writer, NULL,
                                              memory_order_acq_rel);
            if (writer) {
                uv_sem_wait(&writer->opened);
                uv_sem_post(&writer->release);
                uv_sem_wait(&writer->closed);
            }
        }
    }
    struct timespec wait = {
        .tv_sec = timeout < 0 ? 0 : timeout / 1000,
        .tv_nsec = timeout < 0 ? 0 : (timeout % 1000) * 1000000L,
    };
    return ppoll(fds, count, timeout < 0 ? NULL : &wait, NULL);
}
#endif

static void test_readfile_fifo_no_writer(void) {
    char scratch[] = "/tmp/cjs-asyncfs-XXXXXX";
    CHECK(mkdtemp(scratch));
    char filename[sizeof(scratch) + 8];
    snprintf(filename, sizeof(filename), "%s/fifo", scratch);
    CHECK_EQ(mkfifo(filename, 0600), 0);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, filename);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));
    for (int i = 0; i < 5; i++) {
        uv_sleep(20);
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
    }
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);

    CHECK_EQ(unlink(filename), 0);
    CHECK_EQ(rmdir(scratch), 0);
}

#ifdef __linux__
static void test_readfile_fifo_empty_writer(void) {
    char scratch[] = "/tmp/cjs-asyncfs-XXXXXX";
    CHECK(mkdtemp(scratch));
    char filename[sizeof(scratch) + 8];
    snprintf(filename, sizeof(filename), "%s/fifo", scratch);
    CHECK_EQ(mkfifo(filename, 0600), 0);

    FifoWriter writer;
    uv_thread_t thread;
    fifo_init(filename, &writer, &thread, NULL);
    atomic_store_explicit(&empty_fifo_writer, &writer, memory_order_release);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, filename);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    JSValue result = await_result_before(runtime, promise, UINT64_C(3000000000));
    CHECK(atomic_load_explicit(&empty_fifo_writer, memory_order_acquire) == NULL);
    size_t length = 0;
    uint8_t *bytes = JS_GetUint8Array(ctx, &length, result);
    CHECK(bytes || length == 0);
    CHECK_EQ(length, 0);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
    fifo_destroy(&writer, &thread);

    CHECK_EQ(unlink(filename), 0);
    CHECK_EQ(rmdir(scratch), 0);
}
#endif

static void test_readfile_fifo_data_eof(void) {
    char scratch[] = "/tmp/cjs-asyncfs-XXXXXX";
    CHECK(mkdtemp(scratch));
    char filename[sizeof(scratch) + 8];
    snprintf(filename, sizeof(filename), "%s/fifo", scratch);
    CHECK_EQ(mkfifo(filename, 0600), 0);

    FifoWriter writer;
    uv_thread_t thread;
    fifo_init(filename, &writer, &thread, "fifo-data");

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, filename);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));
    uv_sem_wait(&writer.opened);
    uv_sleep(50);
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    uv_sem_post(&writer.release);
    JSValue result = await_result(runtime, promise);
    size_t length;
    uint8_t *bytes = JS_GetUint8Array(ctx, &length, result);
    CHECK(bytes);
    CHECK_EQ(length, sizeof("fifo-data") - 1);
    CHECK_EQ(memcmp(bytes, "fifo-data", length), 0);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
    fifo_destroy(&writer, &thread);

    CHECK_EQ(unlink(filename), 0);
    CHECK_EQ(rmdir(scratch), 0);
}

static void test_readfile_fifo_running_teardown(void) {
    char scratch[] = "/tmp/cjs-asyncfs-XXXXXX";
    CHECK(mkdtemp(scratch));
    char filename[sizeof(scratch) + 8];
    snprintf(filename, sizeof(filename), "%s/fifo", scratch);
    CHECK_EQ(mkfifo(filename, 0600), 0);

    FifoWriter writer;
    uv_thread_t thread;
    fifo_init(filename, &writer, &thread, NULL);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, filename);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));
    /* The writer can open only after the worker has opened the FIFO. Keeping
     * it open prevents natural EOF; the readFile work callback has definitely
     * started and is executing rather than remaining queued when canceled. */
    uv_sem_wait(&writer.opened);
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);

    runtime->freeing = true;
    tjs__mod_asyncfs_cleanup_runtime(runtime);
    TJS_FreeRuntime(runtime);

    /* The external writer is deliberately released only after the runtime
     * has drained the running work request. */
    uv_sem_post(&writer.release);
    fifo_destroy(&writer, &thread);

    CHECK_EQ(unlink(filename), 0);
    CHECK_EQ(rmdir(scratch), 0);
}

static void test_readfile_fifo_queued_teardown(void) {
    char scratch[] = "/tmp/cjs-asyncfs-XXXXXX";
    CHECK(mkdtemp(scratch));
    char filename[sizeof(scratch) + 8];
    snprintf(filename, sizeof(filename), "%s/fifo", scratch);
    CHECK_EQ(mkfifo(filename, 0600), 0);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);

    uv_sem_t started, release;
    CHECK_EQ(uv_sem_init(&started, 0), 0);
    CHECK_EQ(uv_sem_init(&release, 0), 0);
    Blocker blockers[4];
    unsigned completed = 0;
    for (size_t i = 0; i < countof(blockers); i++) {
        blockers[i].started = &started;
        blockers[i].release = &release;
        blockers[i].completed = &completed;
        blockers[i].req.data = &blockers[i];
        CHECK_EQ(uv_queue_work(&runtime->loop, &blockers[i].req,
                               block_work, after_block), 0);
    }
    for (size_t i = 0; i < countof(blockers); i++) uv_sem_wait(&started);

    JSValue path = JS_NewString(ctx, filename);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);

    tjs__mod_asyncfs_cleanup_runtime(runtime);
    runtime->freeing = true;
    for (size_t i = 0; i < countof(blockers); i++) uv_sem_post(&release);
    while (completed != countof(blockers))
        uv_run(&runtime->loop, UV_RUN_ONCE);
    TJS_FreeRuntime(runtime);
    uv_sem_destroy(&started);
    uv_sem_destroy(&release);

    CHECK_EQ(unlink(filename), 0);
    CHECK_EQ(rmdir(scratch), 0);
}

#else
static void test_readfile_named_pipe_is_rejected(void) {
    char pipe_path[128];
    snprintf(pipe_path, sizeof(pipe_path), "\\\\.\\pipe\\cjs-asyncfs-%lu",
             (unsigned long)GetCurrentProcessId());
    HANDLE server = CreateNamedPipeA(pipe_path, PIPE_ACCESS_INBOUND,
                                     PIPE_TYPE_BYTE | PIPE_WAIT, 1,
                                     4096, 4096, 0, NULL);
    CHECK(server != INVALID_HANDLE_VALUE);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, pipe_path);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));

    uint64_t deadline = uv_hrtime() + UINT64_C(3000000000);
    while (JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING) {
        CHECK_LT(uv_hrtime(), deadline);
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    }
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_REJECTED);
    JS_FreeValue(ctx, JS_PromiseResult(ctx, promise));
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);
    TJS_FreeRuntime(runtime);
    CHECK(CloseHandle(server));
}
#endif

#if defined(__linux__)
static void teardown_timeout(int signal_number) {
    (void)signal_number;
    _exit(124);
}

static void test_readfile_special_teardown(void) {
    /* A pty slave is a character device whose canonical read blocks until
     * input arrives. Keep the master open while readFile is pending so the
     * worker reaches the read/poll path deterministically. */
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
    CHECK_GE(master, 0);
    CHECK_EQ(grantpt(master), 0);
    CHECK_EQ(unlockpt(master), 0);
    char slave[PATH_MAX];
    CHECK_EQ(ptsname_r(master, slave, sizeof(slave)), 0);

    TJSRuntime *runtime = TJS_NewRuntime();
    CHECK(runtime);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = module(runtime);
    JSValue path = JS_NewString(ctx, slave);
    JSValue promise = call(ctx, ns, "readFile", 1, &path);
    CHECK(!JS_IsException(promise));
    uint64_t pending_deadline = uv_hrtime() + UINT64_C(1000000000);
    while (JS_PromiseState(ctx, promise) == JS_PROMISE_PENDING &&
           uv_hrtime() < pending_deadline) {
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    }
    CHECK_EQ(JS_PromiseState(ctx, promise), JS_PROMISE_PENDING);
    JS_FreeValue(ctx, promise);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, ns);

    struct sigaction timeout_action = { 0 };
    struct sigaction previous_action = { 0 };
    timeout_action.sa_handler = teardown_timeout;
    sigemptyset(&timeout_action.sa_mask);
    CHECK_EQ(sigaction(SIGALRM, &timeout_action, &previous_action), 0);
    alarm(5);
    runtime->freeing = true;
    tjs__mod_asyncfs_cleanup_runtime(runtime);
    TJS_FreeRuntime(runtime);
    alarm(0);
    CHECK_EQ(sigaction(SIGALRM, &previous_action, NULL), 0);
    CHECK_EQ(close(master), 0);
}
#endif

int main(void) {
    CHECK_EQ(uv_os_setenv("UV_THREADPOOL_SIZE", "4"), 0);
    test_promise_reentry();
    test_file_detach();
    test_file_pipe_pending_teardown(false);
    test_file_pipe_pending_teardown(true);
#ifndef _WIN32
    test_close_on_close_reused_same_inode();
    test_file_pipe_io();
    test_file_special_and_directory_io();
#endif
    test_directory_teardown(false);
    test_directory_teardown(true);
#ifndef _WIN32
    test_readfile_fifo_no_writer();
#ifdef __linux__
    test_readfile_fifo_empty_writer();
#endif
    test_readfile_fifo_data_eof();
    test_readfile_fifo_running_teardown();
    test_readfile_fifo_queued_teardown();
#if defined(__linux__)
    test_readfile_special_teardown();
#endif
#else
    test_readfile_named_pipe_is_rejected();
#endif
    return 0;
}
