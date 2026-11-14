#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#define FFI_FIXTURE_EXPORT __declspec(dllexport)
#else
#include <pthread.h>
#define FFI_FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

typedef struct {
    uint8_t tag;
    uint32_t value;
    double ratio;
} ffi_fixture_record;

typedef struct {
    uint8_t tag;
    uint16_t values[3];
    uint32_t total;
} ffi_fixture_array_record;

typedef int32_t (*ffi_fixture_binary_callback)(int32_t, int32_t);

typedef struct {
    ffi_fixture_binary_callback callback;
    int32_t left;
    int32_t right;
    int32_t result;
} ffi_fixture_thread_callback;

FFI_FIXTURE_EXPORT int32_t ffi_fixture_global = 0x12345678;

static const char ffi_fixture_message[] = "circu ffi fixture";
static void *ffi_fixture_message_pointer = (void *)ffi_fixture_message;
static uint32_t ffi_fixture_disposed_count;

FFI_FIXTURE_EXPORT int32_t ffi_fixture_add_i32(int32_t left, int32_t right) {
    return left + right;
}

FFI_FIXTURE_EXPORT bool ffi_fixture_roundtrip_bool(bool value) {
    return value;
}

FFI_FIXTURE_EXPORT int8_t ffi_fixture_roundtrip_i8(int8_t value) {
    return value;
}

FFI_FIXTURE_EXPORT uint8_t ffi_fixture_roundtrip_u8(uint8_t value) {
    return value;
}

FFI_FIXTURE_EXPORT int16_t ffi_fixture_roundtrip_i16(int16_t value) {
    return value;
}

FFI_FIXTURE_EXPORT uint16_t ffi_fixture_roundtrip_u16(uint16_t value) {
    return value;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_roundtrip_i32(int32_t value) {
    return value;
}

FFI_FIXTURE_EXPORT uint32_t ffi_fixture_roundtrip_u32(uint32_t value) {
    return value;
}

FFI_FIXTURE_EXPORT int64_t ffi_fixture_roundtrip_i64(int64_t value) {
    return value;
}

FFI_FIXTURE_EXPORT uint64_t ffi_fixture_roundtrip_u64(uint64_t value) {
    return value;
}

FFI_FIXTURE_EXPORT double ffi_fixture_weighted_sum(double left, double right, int32_t scale) {
    return (left + right) * scale;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_sum_varargs(int32_t count, ...) {
    int32_t sum = 0;
    int32_t i;
    va_list arguments;
    va_start(arguments, count);
    for (i = 0; i < count; i++) sum += va_arg(arguments, int32_t);
    va_end(arguments);
    return sum;
}

FFI_FIXTURE_EXPORT void ffi_fixture_xor_bytes(uint8_t *bytes, size_t length, uint8_t mask) {
    size_t i;
    for (i = 0; i < length; i++) bytes[i] ^= mask;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_pointer_is_null(const void *pointer) {
    return pointer == NULL;
}

FFI_FIXTURE_EXPORT ffi_fixture_record ffi_fixture_transform_record(ffi_fixture_record record) {
    record.tag = (uint8_t)(record.tag + 1);
    record.value += 7;
    record.ratio *= 2;
    return record;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_record_score(ffi_fixture_record record) {
    return (int32_t)record.tag + (int32_t)record.value + (int32_t)record.ratio;
}

FFI_FIXTURE_EXPORT ffi_fixture_array_record
ffi_fixture_transform_array_record(ffi_fixture_array_record record) {
    record.tag++;
    record.values[0]++;
    record.values[1]++;
    record.values[2]++;
    record.total = (uint32_t)record.values[0] + record.values[1] + record.values[2];
    return record;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_call_callback(ffi_fixture_binary_callback callback,
                                                     int32_t left,
                                                     int32_t right) {
    return callback(left, right);
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_call_callback_twice(ffi_fixture_binary_callback callback,
                                                           int32_t left,
                                                           int32_t right) {
    int32_t first = callback(left, right);
    int32_t second = callback(left, right);
    return first * 1000 + second;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_call_callback_then_add(
        ffi_fixture_binary_callback callback,
        int32_t left,
        int32_t right,
        int32_t addend) {
    int32_t result = callback(left, right);
    return result + addend;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_mutate_around_callback(
        uint8_t *bytes,
        ffi_fixture_binary_callback callback) {
    bytes[0] = 1;
    int32_t result = callback(4, 2);
    bytes[1] = (uint8_t)result;
    return (int32_t)bytes[0] + bytes[1];
}

#if defined(_WIN32)
static DWORD WINAPI ffi_fixture_thread_main(LPVOID argument) {
    ffi_fixture_thread_callback *call = argument;
    call->result = call->callback(call->left, call->right);
    return 0;
}
#else
static void *ffi_fixture_thread_main(void *argument) {
    ffi_fixture_thread_callback *call = argument;
    call->result = call->callback(call->left, call->right);
    return NULL;
}
#endif

FFI_FIXTURE_EXPORT int32_t ffi_fixture_call_callback_on_thread(ffi_fixture_binary_callback callback,
                                                               int32_t left,
                                                               int32_t right) {
    ffi_fixture_thread_callback call = { callback, left, right, -1 };
#if defined(_WIN32)
    HANDLE thread = CreateThread(NULL, 0, ffi_fixture_thread_main, &call, 0, NULL);
    if (thread == NULL) return INT32_MIN;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    pthread_t thread;
    if (pthread_create(&thread, NULL, ffi_fixture_thread_main, &call) != 0) return INT32_MIN;
    if (pthread_join(thread, NULL) != 0) return INT32_MIN;
#endif
    return call.result;
}

FFI_FIXTURE_EXPORT void *ffi_fixture_add_pointer(void) {
    return (void *)ffi_fixture_add_i32;
}

FFI_FIXTURE_EXPORT const char *ffi_fixture_string(void) {
    return ffi_fixture_message;
}

FFI_FIXTURE_EXPORT void **ffi_fixture_pointer_slot(void) {
    return &ffi_fixture_message_pointer;
}

FFI_FIXTURE_EXPORT int32_t ffi_fixture_set_errno(int32_t error_number) {
    errno = error_number;
    return -1;
}

FFI_FIXTURE_EXPORT void *ffi_fixture_alloc(size_t size) {
    return calloc(1, size);
}

FFI_FIXTURE_EXPORT void ffi_fixture_free(void *pointer) {
    free(pointer);
}

FFI_FIXTURE_EXPORT void ffi_fixture_count_disposed(void *pointer) {
    uint32_t *count = pointer;
    (*count)++;
}

FFI_FIXTURE_EXPORT void ffi_fixture_reset_disposed_count(void) {
    ffi_fixture_disposed_count = 0;
}

FFI_FIXTURE_EXPORT uint32_t ffi_fixture_get_disposed_count(void) {
    return ffi_fixture_disposed_count;
}

FFI_FIXTURE_EXPORT void ffi_fixture_count_disposed_and_free(void *pointer) {
    ffi_fixture_disposed_count++;
    free(pointer);
}
