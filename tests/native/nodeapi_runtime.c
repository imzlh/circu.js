#include "private.h"
#include "node_api.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    napi_env env;
    napi_value object;
    napi_value source;
    napi_value number;
    napi_handle_scope callback_scope;
    napi_value rejected_callback;
    napi_value callback_name;
    bool rejected_callback_finalized;
    napi_threadsafe_function tsfn;
    napi_async_work work;
    napi_ref reference;
    napi_async_cleanup_hook_handle cleanup;
    uv_timer_t timer;
    uv_thread_t producer;
    uv_thread_t remover;
    uv_sem_t ready;
    uv_sem_t closing;
    uv_sem_t remove_ready;
    uv_sem_t execute_started;
    uv_sem_t execute_finish;
    bool cleanup_called;
    bool cleanup_removed;
    bool env_finalized;
    bool work_completed;
    bool tsfn_finalized;
    bool payload_freed;
    bool reference_finalized;
} TestState;

#ifdef NODEAPI_TEST_FIXTURE
static TestState state;
static void tsfn_call_js(napi_env env, napi_value callback, void *context,
                          void *data) {
    CHECK(env == NULL);
    CHECK(callback == NULL);
    CHECK(context == &state);
    CHECK(data == &state);
    CHECK(!state.payload_freed);
    state.payload_freed = true;
}

static void tsfn_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    CHECK(hint == NULL);
    CHECK(data == &state);
    CHECK(state.payload_freed);
    CHECK_EQ(uv_thread_join(&state.producer), 0);
    state.tsfn_finalized = true;
}

static void producer(void *data) {
    TestState *test_state = data;
    CHECK_EQ(napi_call_threadsafe_function(test_state->tsfn, test_state,
                                          napi_tsfn_nonblocking), napi_ok);
    uv_sem_post(&test_state->ready);
    uv_sem_wait(&test_state->closing);
    /* napi_closing is this acquired producer's final TSFN use. No additional
     * release call is required and teardown must still finish. */
    CHECK_EQ(napi_call_threadsafe_function(test_state->tsfn, NULL,
                                          napi_tsfn_nonblocking), napi_closing);
}

static void timer_closed(uv_handle_t *handle) {
    CHECK(handle == (uv_handle_t *)&state.timer);
    uv_sem_post(&state.remove_ready);
}

static void remove_cleanup(void *data) {
    CHECK(data == &state);
    uv_sem_wait(&state.remove_ready);
    CHECK_EQ(napi_remove_async_cleanup_hook(state.cleanup), napi_ok);
    state.cleanup_removed = true;
}

static void timer_fired(uv_timer_t *timer) {
    uv_close((uv_handle_t *)timer, timer_closed);
}

static void rejected_callback_finalize(napi_env env, void *data, void *hint) {
    CHECK(env == state.env && data == &state && hint == NULL);
    CHECK(!state.rejected_callback_finalized);
    state.rejected_callback_finalized = true;
}

/* Open after addon registration so this scope lives through the cleanup hook. */
NAPI_MODULE_EXPORT void nodeapi_fixture_prepare_closing_tsfn(void) {
    napi_env env = state.env;
    CHECK_EQ(napi_open_handle_scope(env, &state.callback_scope), napi_ok);
    CHECK_EQ(napi_create_string_utf8(env, "closingTsfn", NAPI_AUTO_LENGTH, &state.callback_name), napi_ok);
    napi_value source;
    CHECK_EQ(napi_create_string_utf8(env, "() => {}", NAPI_AUTO_LENGTH, &source), napi_ok);
    CHECK_EQ(napi_run_script(env, source, &state.rejected_callback), napi_ok);
    CHECK_EQ(napi_add_finalizer(env, state.rejected_callback, &state,
                                rejected_callback_finalize, NULL, NULL), napi_ok);
}

static void cleanup_hook(napi_async_cleanup_hook_handle handle, void *data) {
    CHECK(data == &state);
    CHECK(handle == state.cleanup);
    state.cleanup_called = true;
    napi_threadsafe_function rejected = NULL;
    CHECK_EQ(napi_create_threadsafe_function(state.env, state.rejected_callback,
                                             NULL, state.callback_name, 0, 1, NULL, NULL,
                                             NULL, NULL, &rejected), napi_closing);
    CHECK(rejected == NULL);
    CHECK_EQ(napi_close_handle_scope(state.env, state.callback_scope), napi_ok);
    CHECK(state.rejected_callback_finalized);
    CHECK_EQ(napi_release_threadsafe_function(state.tsfn, napi_tsfn_abort), napi_ok);
    uv_sem_post(&state.closing);
    uv_sem_post(&state.execute_finish);
    /* Hook returns before its uv_close callback acknowledges completion. */
    CHECK_EQ(uv_timer_start(&state.timer, timer_fired, 1, 0), 0);
}

static void execute(napi_env env, void *data) {
    (void)env;
    CHECK(data == &state);
    uv_sem_post(&state.execute_started);
    uv_sem_wait(&state.execute_finish);
}

static void reference_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    CHECK(data == &state);
    CHECK(hint == &state);
    CHECK(state.work_completed);
    CHECK(!state.reference_finalized);
    state.reference_finalized = true;
}

typedef struct {
    napi_ref reference;
    napi_ref successor;
    unsigned finalized;
    unsigned successor_finalized;
} ReentrantReferences;

static ReentrantReferences self_deleting_reference;
static ReentrantReferences successor_deleting_reference;

static void successor_reference_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    ReentrantReferences *test = data;
    CHECK(state.work_completed);
    CHECK_EQ(++test->successor_finalized, 1);
    CHECK(test->successor == NULL);
}

static void reentrant_reference_finalize(napi_env env, void *data, void *hint) {
    (void)hint;
    ReentrantReferences *test = data;
    CHECK(state.work_completed);
    CHECK_EQ(++test->finalized, 1);
    if (test->successor) {
        napi_ref successor = test->successor;
        test->successor = NULL;
        CHECK_EQ(napi_delete_reference(env, successor), napi_ok);
    }
    napi_ref reference = test->reference;
    CHECK(reference);
    test->reference = NULL;
    CHECK_EQ(napi_delete_reference(env, reference), napi_ok);
}

static void test_reference_cleanup_reentry(napi_env env, ReentrantReferences *test,
                                          bool delete_successor) {
    napi_handle_scope scope;
    napi_value value;
    CHECK_EQ(napi_open_handle_scope(env, &scope), napi_ok);
    CHECK_EQ(napi_create_external(env, test, reentrant_reference_finalize, NULL,
                                  &value), napi_ok);
    CHECK_EQ(napi_create_reference(env, value, 1, &test->reference), napi_ok);
    if (delete_successor) {
        CHECK_EQ(napi_create_external(env, test, successor_reference_finalize,
                                      NULL, &value), napi_ok);
        CHECK_EQ(napi_create_reference(env, value, 1, &test->successor), napi_ok);
    }
    CHECK_EQ(napi_close_handle_scope(env, scope), napi_ok);
    CHECK_EQ(test->finalized, 0);
    CHECK_EQ(test->successor_finalized, 0);
}

static void complete(napi_env env, napi_status status, void *data) {
    CHECK(data == &state);
    CHECK_EQ(status, napi_ok);
    CHECK(state.cleanup_called);
    napi_value object = state.object;
    napi_value value;
    uint32_t refcount;
    CHECK(object);
    CHECK_EQ(napi_get_global(env, &value), napi_cannot_run_js);
    CHECK_EQ(napi_create_object(env, &value), napi_cannot_run_js);
    CHECK_EQ(napi_create_int32(env, 7, &value), napi_cannot_run_js);
    CHECK_EQ(napi_create_string_utf8(env, "teardown", NAPI_AUTO_LENGTH, &value),
             napi_cannot_run_js);
    int32_t number;
    CHECK_EQ(napi_get_value_int32(env, state.number, &number), napi_cannot_run_js);
    CHECK_EQ(napi_get_value_string_utf8(env, state.source, NULL, 0, NULL),
             napi_cannot_run_js);
    CHECK_EQ(napi_reference_ref(env, state.reference, &refcount), napi_cannot_run_js);
    CHECK_EQ(napi_reference_unref(env, state.reference, &refcount), napi_cannot_run_js);
    CHECK_EQ(napi_get_reference_value(env, state.reference, &value), napi_cannot_run_js);
    bool is_array;
    CHECK_EQ(napi_is_array(env, object, &is_array), napi_cannot_run_js);
    CHECK_EQ(napi_get_named_property(env, object, "value", &value), napi_cannot_run_js);
    CHECK_EQ(napi_get_element(env, object, 0, &value), napi_cannot_run_js);
    CHECK_EQ(napi_coerce_to_number(env, object, &value), napi_cannot_run_js);
    CHECK_EQ(napi_coerce_to_string(env, object, &value), napi_cannot_run_js);
    CHECK_EQ(napi_coerce_to_object(env, object, &value), napi_cannot_run_js);
    CHECK_EQ(napi_get_property_names(env, object, &value), napi_cannot_run_js);
    void *buffer_data;
    size_t buffer_length;
    size_t byte_offset;
    napi_typedarray_type typedarray_type;
    napi_deferred deferred;
    CHECK_EQ(napi_create_arraybuffer(env, 0, &buffer_data, &value), napi_cannot_run_js);
    CHECK_EQ(napi_create_external_arraybuffer(env, NULL, 0, NULL, NULL, &value), napi_cannot_run_js);
    CHECK_EQ(napi_get_arraybuffer_info(env, object, &buffer_data, &buffer_length), napi_cannot_run_js);
    CHECK_EQ(napi_create_typedarray(env, napi_uint8_array, 0, object, 0, &value), napi_cannot_run_js);
    CHECK_EQ(napi_get_typedarray_info(env, object, &typedarray_type, &buffer_length,
                                      &buffer_data, &value, &byte_offset), napi_cannot_run_js);
    CHECK_EQ(napi_get_dataview_info(env, object, &buffer_length, &buffer_data,
                                    &value, &byte_offset), napi_cannot_run_js);
    CHECK_EQ(napi_detach_arraybuffer(env, object), napi_cannot_run_js);
    CHECK_EQ(napi_create_promise(env, &deferred, &value), napi_cannot_run_js);
    CHECK_EQ(napi_create_date(env, 0, &value), napi_cannot_run_js);
    CHECK_EQ(napi_create_bigint_words(env, 0, 0, NULL, &value), napi_cannot_run_js);
    CHECK_EQ(napi_queue_async_work(env, state.work), napi_closing);
    state.work_completed = true;
    CHECK_EQ(napi_delete_reference(env, state.reference), napi_ok);
    CHECK_EQ(napi_delete_async_work(env, state.work), napi_ok);
}

typedef struct {
    napi_async_cleanup_hook_handle handle;
    uv_thread_t thread;
    bool removed;
} ImmediateCleanup;

static ImmediateCleanup immediate_cleanup;

static void immediate_remove(void *data) {
    ImmediateCleanup *cleanup = data;
    CHECK_EQ(napi_remove_async_cleanup_hook(cleanup->handle), napi_ok);
    cleanup->removed = true;
}

static void immediate_cleanup_hook(napi_async_cleanup_hook_handle handle, void *data) {
    ImmediateCleanup *cleanup = data;
    CHECK(handle == cleanup->handle);
    CHECK_EQ(uv_thread_create(&cleanup->thread, immediate_remove, cleanup), 0);
    CHECK_EQ(uv_thread_join(&cleanup->thread), 0);
    CHECK(cleanup->removed);
}

static void uncalled_cleanup_hook(napi_async_cleanup_hook_handle handle, void *data) {
    (void)handle;
    (void)data;
    CHECK(false);
}

typedef struct {
    napi_threadsafe_function tsfn;
    uv_thread_t blocked_thread;
    uv_thread_t holding_thread;
    uv_sem_t blocked_ready;
    uv_sem_t holder_ready;
    void *payload;
    bool disposed;
    bool finalized;
} BlockingTsfn;

static BlockingTsfn blocking_tsfn;

typedef struct {
    napi_threadsafe_function tsfn;
    uv_thread_t holder;
    uv_sem_t ready;
    uv_sem_t release;
    bool finalized;
} AbortTsfn;

static AbortTsfn abort_tsfn;

static void abort_call_js(napi_env env, napi_value callback, void *context,
                          void *data) {
    (void)env;
    (void)callback;
    (void)context;
    (void)data;
}

static uv_loop_t *test_loop(napi_env env) {
    uv_loop_t *loop = NULL;
    CHECK_EQ(napi_get_uv_event_loop(env, &loop), napi_ok);
    return loop;
}

static void abort_holder(void *data) {
    AbortTsfn *test = data;
    uv_sem_post(&test->ready);
    uv_sem_wait(&test->release);
    CHECK_EQ(napi_release_threadsafe_function(test->tsfn, napi_tsfn_release), napi_ok);
}

static void abort_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    AbortTsfn *test = data;
    CHECK(!test->finalized);
    test->finalized = true;
}

static void test_abort_waits_for_holders(napi_env env) {
    AbortTsfn *test = &abort_tsfn;
    CHECK_EQ(uv_sem_init(&test->ready, 0), 0);
    CHECK_EQ(uv_sem_init(&test->release, 0), 0);
    CHECK_EQ(napi_create_threadsafe_function(env, NULL, NULL, NULL, 0, 2,
                                             test, abort_finalize, test,
                                             abort_call_js, &test->tsfn), napi_ok);
    CHECK_EQ(uv_thread_create(&test->holder, abort_holder, test), 0);
    uv_sem_wait(&test->ready);
    CHECK_EQ(napi_release_threadsafe_function(test->tsfn, napi_tsfn_abort), napi_ok);
    uv_run(test_loop(env), UV_RUN_NOWAIT);
    CHECK(!test->finalized);
    uv_sem_post(&test->release);
    CHECK_EQ(uv_thread_join(&test->holder), 0);
    while (!test->finalized)
        uv_run(test_loop(env), UV_RUN_ONCE);
    uv_sem_destroy(&test->ready);
    uv_sem_destroy(&test->release);
}

static void blocked_producer(void *data) {
    BlockingTsfn *test = data;
    unsigned *payload = malloc(sizeof(*payload));
    CHECK(payload);
    *payload = 42;
    uv_sem_post(&test->blocked_ready);
    CHECK_EQ(napi_call_threadsafe_function(test->tsfn, payload,
                                          napi_tsfn_blocking), napi_closing);
    CHECK_EQ(*payload, 42);
    free(payload);
}

static void holding_producer(void *data) {
    BlockingTsfn *test = data;
    uv_sem_wait(&test->holder_ready);
    CHECK_EQ(napi_acquire_threadsafe_function(test->tsfn), napi_closing);
}

static void blocking_dispose(napi_env env, napi_value callback, void *context, void *data) {
    BlockingTsfn *test = context;
    CHECK(env != NULL);
    CHECK(callback == NULL);
    CHECK(data == test->payload);
    CHECK(!test->disposed);
    test->disposed = true;
    free(data);
}

static void blocking_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    BlockingTsfn *test = data;
    CHECK(hint == NULL);
    CHECK(test->disposed);
    CHECK(!test->finalized);
    test->finalized = true;
}

static void test_blocked_abort(napi_env env) {
    BlockingTsfn *test = &blocking_tsfn;
    CHECK_EQ(uv_sem_init(&test->blocked_ready, 0), 0);
    CHECK_EQ(uv_sem_init(&test->holder_ready, 0), 0);
    CHECK_EQ(napi_create_threadsafe_function(env, NULL, NULL, NULL, 1, 2,
                                             test, blocking_finalize, test,
                                             blocking_dispose, &test->tsfn), napi_ok);
    test->payload = malloc(1);
    CHECK(test->payload);
    CHECK_EQ(napi_call_threadsafe_function(test->tsfn, test->payload,
                                          napi_tsfn_nonblocking), napi_ok);
    CHECK_EQ(uv_thread_create(&test->holding_thread, holding_producer, test), 0);
    CHECK_EQ(uv_thread_create(&test->blocked_thread, blocked_producer, test), 0);
    uv_sem_wait(&test->blocked_ready);
    uv_sleep(10);
    CHECK_EQ(napi_release_threadsafe_function(test->tsfn, napi_tsfn_abort), napi_ok);
    CHECK_EQ(uv_thread_join(&test->blocked_thread), 0);
    uv_sem_post(&test->holder_ready);
    CHECK_EQ(uv_thread_join(&test->holding_thread), 0);
    while (!test->finalized)
        uv_run(test_loop(env), UV_RUN_ONCE);
    uv_sem_destroy(&test->blocked_ready);
    uv_sem_destroy(&test->holder_ready);
}

typedef struct {
    napi_threadsafe_function tsfn;
    uv_thread_t thread;
    uv_sem_t ready;
    uv_sem_t finish;
    napi_async_cleanup_hook_handle cleanup;
    bool finalized;
} FinalizerTsfn;

static FinalizerTsfn finalizer_tsfn;

typedef struct {
    napi_threadsafe_function tsfn;
    uv_thread_t release_threads[2];
    uv_sem_t release;
    uv_timer_t release_timer;
    napi_async_cleanup_hook_handle cleanup;
    _Atomic unsigned release_started;
    bool finalized;
} RetiredTsfn;

static RetiredTsfn retired_tsfn;

static void instance_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    CHECK(data == &state);
    CHECK(hint == NULL);
    CHECK(!state.env_finalized);
    CHECK(state.tsfn_finalized);
    CHECK(blocking_tsfn.finalized);
    CHECK(finalizer_tsfn.finalized);
    CHECK(retired_tsfn.finalized);
    CHECK(immediate_cleanup.removed);
    state.env_finalized = true;
}

static void retired_call_js(napi_env env, napi_value callback, void *context,
                            void *data) {
    (void)env;
    (void)callback;
    (void)context;
    (void)data;
    CHECK(false);
}

static void retired_finalize(napi_env env, void *data, void *hint) {
    (void)hint;
    RetiredTsfn *test = data;
    CHECK(env);
    CHECK(!test->finalized);
    CHECK_EQ(atomic_load_explicit(&test->release_started, memory_order_acquire), 2);
    CHECK_EQ(uv_thread_join(&test->release_threads[0]), 0);
    CHECK_EQ(uv_thread_join(&test->release_threads[1]), 0);
    test->finalized = true;
}

static void retired_release(void *data) {
    RetiredTsfn *test = data;
    uv_sem_wait(&test->release);
    atomic_fetch_add_explicit(&test->release_started, 1, memory_order_release);
    CHECK_EQ(napi_release_threadsafe_function(test->tsfn, napi_tsfn_release), napi_ok);
}

static void retired_release_timer_closed(uv_handle_t *handle) {
    RetiredTsfn *test = handle->data;
    CHECK(handle == (uv_handle_t *)&test->release_timer);
    CHECK_EQ(napi_remove_async_cleanup_hook(test->cleanup), napi_ok);
}

static void retired_release_timer_fired(uv_timer_t *timer) {
    RetiredTsfn *test = timer->data;
    uv_sem_post(&test->release);
    uv_sem_post(&test->release);
    uv_close((uv_handle_t *)timer, retired_release_timer_closed);
}

static void retired_cleanup(napi_async_cleanup_hook_handle handle, void *data) {
    RetiredTsfn *test = data;
    CHECK(handle == test->cleanup);
    CHECK_EQ(uv_timer_start(&test->release_timer, retired_release_timer_fired,
                            20, 0), 0);
}

static void finalizer_producer(void *data) {
    FinalizerTsfn *test = data;
    uv_sem_post(&test->ready);
    uv_sem_wait(&test->finish);
    CHECK_EQ(napi_call_threadsafe_function(test->tsfn, NULL,
                                          napi_tsfn_nonblocking), napi_closing);
}

static void finalizer_call_js(napi_env env, napi_value callback, void *context, void *data) {
    (void)env;
    (void)callback;
    (void)context;
    (void)data;
    CHECK(false);
}

static void finalizer_join(napi_env env, void *data, void *hint) {
    CHECK(env);
    FinalizerTsfn *test = data;
    CHECK(hint == NULL);
    CHECK(!test->finalized);
    uv_sem_post(&test->finish);
    CHECK_EQ(uv_thread_join(&test->thread), 0);
    test->finalized = true;
    uv_sem_destroy(&test->ready);
    uv_sem_destroy(&test->finish);
}

static void wake_finalizer_producer(napi_async_cleanup_hook_handle handle,
                                    void *data) {
    FinalizerTsfn *test = data;
    CHECK(handle == test->cleanup);
    uv_sem_post(&test->finish);
    CHECK_EQ(napi_remove_async_cleanup_hook(handle), napi_ok);
}

static void test_finalizer_join(napi_env env) {
    FinalizerTsfn *test = &finalizer_tsfn;
    CHECK_EQ(uv_sem_init(&test->ready, 0), 0);
    CHECK_EQ(uv_sem_init(&test->finish, 0), 0);
    CHECK_EQ(napi_create_threadsafe_function(env, NULL, NULL, NULL, 0, 1,
                                             test, finalizer_join, test,
                                             finalizer_call_js, &test->tsfn), napi_ok);
    CHECK_EQ(napi_unref_threadsafe_function(env, test->tsfn), napi_ok);
    CHECK_EQ(napi_add_async_cleanup_hook(env, wake_finalizer_producer, test,
                                         &test->cleanup), napi_ok);
    CHECK_EQ(uv_thread_create(&test->thread, finalizer_producer, test), 0);
    uv_sem_wait(&test->ready);
}

static void test_retired_owner(napi_env env) {
    RetiredTsfn *test = &retired_tsfn;
    atomic_init(&test->release_started, 0);
    CHECK_EQ(uv_sem_init(&test->release, 0), 0);
    CHECK_EQ(uv_timer_init(test_loop(env), &test->release_timer), 0);
    test->release_timer.data = test;
    CHECK_EQ(napi_create_threadsafe_function(env, NULL, NULL, NULL, 0, 2,
                                             test, retired_finalize, test,
                                             retired_call_js, &test->tsfn), napi_ok);
    CHECK_EQ(uv_thread_create(&test->release_threads[0], retired_release, test), 0);
    CHECK_EQ(uv_thread_create(&test->release_threads[1], retired_release, test), 0);
    CHECK_EQ(napi_add_async_cleanup_hook(env, retired_cleanup, test,
                                         &test->cleanup), napi_ok);
}

NAPI_MODULE_EXPORT napi_value napi_register_module_v1(napi_env env,
                                                       napi_value exports) {
    CHECK_EQ(uv_sem_init(&state.ready, 0), 0);
    CHECK_EQ(uv_sem_init(&state.closing, 0), 0);
    CHECK_EQ(uv_sem_init(&state.remove_ready, 0), 0);
    CHECK_EQ(uv_sem_init(&state.execute_started, 0), 0);
    CHECK_EQ(uv_sem_init(&state.execute_finish, 0), 0);
    state.env = env;
    CHECK_EQ(napi_set_instance_data(env, &state, instance_finalize, NULL), napi_ok);
    test_reference_cleanup_reentry(env, &self_deleting_reference, false);
    test_reference_cleanup_reentry(env, &successor_deleting_reference, true);
    test_abort_waits_for_holders(env);
    test_blocked_abort(env);
    test_finalizer_join(env);
    test_retired_owner(env);
    ImmediateCleanup uncalled_cleanup = {0};
    CHECK_EQ(napi_add_async_cleanup_hook(env, uncalled_cleanup_hook,
                                         &uncalled_cleanup, &uncalled_cleanup.handle), napi_ok);
    CHECK_EQ(uv_thread_create(&uncalled_cleanup.thread, immediate_remove, &uncalled_cleanup), 0);
    CHECK_EQ(uv_thread_join(&uncalled_cleanup.thread), 0);
    CHECK(uncalled_cleanup.removed);
    CHECK_EQ(napi_add_async_cleanup_hook(env, immediate_cleanup_hook,
                                         &immediate_cleanup, &immediate_cleanup.handle), napi_ok);
    napi_value source;
    napi_value object;
    CHECK_EQ(napi_create_string_utf8(env,
        "({ get value() { return 42; }, get 0() { return 42; },"
        " [Symbol.toPrimitive]() { return 42; } })", NAPI_AUTO_LENGTH, &source), napi_ok);
    CHECK_EQ(napi_run_script(env, source, &object), napi_ok);
    napi_value value;
    int32_t number;
    CHECK_EQ(napi_get_named_property(env, object, "value", &value), napi_ok);
    CHECK_EQ(napi_get_value_int32(env, value, &number), napi_ok);
    CHECK_EQ(number, 42);
    state.object = object;
    state.source = source;
    state.number = value;
    CHECK_EQ(napi_create_reference(env, object, 1, &state.reference), napi_ok);
    CHECK_EQ(napi_add_finalizer(env, object, &state, reference_finalize, &state, NULL), napi_ok);
    uv_loop_t *loop;
    CHECK_EQ(napi_get_uv_event_loop(env, &loop), napi_ok);
    CHECK_EQ(uv_timer_init(loop, &state.timer), 0);
    CHECK_EQ(napi_create_threadsafe_function(env, NULL, NULL, NULL, 0, 2,
                                             &state, tsfn_finalize, &state,
                                             tsfn_call_js, &state.tsfn), napi_ok);
    CHECK_EQ(napi_unref_threadsafe_function(env, state.tsfn), napi_ok);
    CHECK_EQ(napi_add_async_cleanup_hook(env, cleanup_hook, &state,
                                         &state.cleanup), napi_ok);
    CHECK_EQ(napi_create_async_work(env, NULL, NULL, execute, complete,
                                     &state, &state.work), napi_ok);
    CHECK_EQ(napi_queue_async_work(env, state.work), napi_ok);
    uv_sem_wait(&state.execute_started);
    CHECK_EQ(napi_cancel_async_work(env, state.work), napi_generic_failure);
    CHECK_EQ(uv_thread_create(&state.remover, remove_cleanup, &state), 0);
    CHECK_EQ(uv_thread_create(&state.producer, producer, &state), 0);
    uv_sem_wait(&state.ready);
    return exports;
}

NAPI_MODULE_EXPORT void nodeapi_fixture_check(void) {
    CHECK_EQ(uv_thread_join(&state.remover), 0);
    CHECK(state.cleanup_called && state.cleanup_removed);
    CHECK(state.env_finalized);
    CHECK(state.work_completed && state.tsfn_finalized && state.payload_freed);
    CHECK(state.reference_finalized);
    CHECK(self_deleting_reference.reference == NULL);
    CHECK_EQ(self_deleting_reference.finalized, 1);
    CHECK(successor_deleting_reference.reference == NULL);
    CHECK(successor_deleting_reference.successor == NULL);
    CHECK_EQ(successor_deleting_reference.finalized, 1);
    CHECK_EQ(successor_deleting_reference.successor_finalized, 1);
    CHECK(immediate_cleanup.removed);
    CHECK(blocking_tsfn.disposed && blocking_tsfn.finalized);
    CHECK(finalizer_tsfn.finalized);
    CHECK(retired_tsfn.finalized);
    uv_sem_destroy(&retired_tsfn.release);
    uv_sem_destroy(&state.ready);
    uv_sem_destroy(&state.closing);
    uv_sem_destroy(&state.remove_ready);
    uv_sem_destroy(&state.execute_started);
    uv_sem_destroy(&state.execute_finish);
}
#else
typedef struct {
    TJSRuntime *runtime;
    uv_check_t check;
    unsigned checks;
} TeardownSchedulerProbe;

static unsigned teardown_jobs_run;

static JSValue teardown_job(JSContext *ctx, int argc, JSValueConst *argv) {
    (void)ctx;
    (void)argc;
    (void)argv;
    teardown_jobs_run++;
    return JS_UNDEFINED;
}

static void check_teardown_scheduler(uv_check_t *handle) {
    TeardownSchedulerProbe *probe = handle->data;
    TJSRuntime *runtime = probe->runtime;
    CHECK(runtime->freeing);
    CHECK(JS_IsJobPending(runtime->rt));
    CHECK(!uv_is_active((uv_handle_t *)&runtime->jobs.prepare));
    CHECK(!uv_is_active((uv_handle_t *)&runtime->jobs.check));
    CHECK(!uv_is_active((uv_handle_t *)&runtime->jobs.idle));
    /* Native completion callbacks can still notify work during cleanup. */
    tjs__notify_work(runtime);
    CHECK(!uv_is_active((uv_handle_t *)&runtime->jobs.idle));
    probe->checks++;
    uv_close((uv_handle_t *)handle, NULL);
}

int main(int argc, char **argv) {
    CHECK_EQ(argc, 2);
    uv_lib_t fixture;
    CHECK_EQ(uv_dlopen(argv[1], &fixture), 0);
    void (*check_fixture)(void) = NULL;
    CHECK_EQ(uv_dlsym(&fixture, "nodeapi_fixture_check", (void **)&check_fixture), 0);
    TJSRuntime *runtime = TJS_NewRuntimeWorker();
    CHECK(runtime);
    /* Start the real core watchers without requiring embedded JS bootstrap. */
    CHECK_EQ(TJS_Run(runtime), 0);
    JSContext *ctx = runtime->main_ctx;
    JSValue ns = JS_NewObject(ctx);
    tjs__mod_nodeapi_init(ctx, ns);
    JSValue dlopen = JS_GetPropertyStr(ctx, ns, "dlopen");
    CHECK(JS_IsFunction(ctx, dlopen));
    JSValue path = JS_NewString(ctx, argv[1]);
    JSValue result = JS_Call(ctx, dlopen, ns, 1, &path);
    if (JS_IsException(result)) TJS_DumpException(ctx);
    CHECK(!JS_IsException(result));
    void (*prepare_closing_tsfn)(void) = NULL;
    CHECK_EQ(uv_dlsym(&fixture, "nodeapi_fixture_prepare_closing_tsfn",
                      (void **)&prepare_closing_tsfn), 0);
    prepare_closing_tsfn();
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, path);
    JS_FreeValue(ctx, dlopen);
    JS_FreeValue(ctx, ns);

    CHECK_EQ(JS_EnqueueJob(ctx, teardown_job, 0, NULL), 0);
    tjs__notify_work(runtime);
    CHECK(uv_is_active((uv_handle_t *)&runtime->jobs.idle));
    TeardownSchedulerProbe probe = { .runtime = runtime };
    CHECK_EQ(uv_check_init(&runtime->loop, &probe.check), 0);
    probe.check.data = &probe;
    CHECK_EQ(uv_check_start(&probe.check, check_teardown_scheduler), 0);
    uv_unref((uv_handle_t *)&probe.check);
    TJS_FreeRuntime(runtime);
    CHECK_EQ(probe.checks, 1);
    CHECK_EQ(teardown_jobs_run, 0);
    check_fixture();
    uv_dlclose(&fixture);
    return 0;
}
#endif
