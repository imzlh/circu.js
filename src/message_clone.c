/*
 * circu.js private process-local message clone transport.
 */

#include "message_clone.h"

#include "mem.h"
#include "private.h"

#include <stdatomic.h>
#include <string.h>

typedef enum {
    TJS_MESSAGE_CLONE_PREPARED = 0,
    TJS_MESSAGE_CLONE_COMMITTED,
    TJS_MESSAGE_CLONE_CONSUMED,
    TJS_MESSAGE_CLONE_ABORTED,
} TJSMessageCloneState;

struct TJSMessageClone {
    _Atomic unsigned refs;
    _Atomic int state;
    uint8_t *data;
    size_t size;
    void **sabs;
    size_t sab_count;
    JSAutoTransferTab transfers;
};

static void message_clone_free_transfer_values(JSContext *ctx,
                                               TJSMessageClone *clone) {
    for (size_t i = 0; i < clone->transfers.len; i++) {
        JS_FreeValue(ctx, clone->transfers.tab[i].value);
        clone->transfers.tab[i].value = JS_UNDEFINED;
    }
}

static int message_clone_parse_transfers(JSContext *ctx,
                                         JSValueConst value,
                                         TJSMessageClone *clone) {
    JSValue length_value;
    uint64_t length = 0;

    if (JS_IsUndefined(value) || JS_IsNull(value)) return 0;
    if (!JS_IsArray(value)) {
        JS_ThrowTypeError(ctx, "transfer list must be an array");
        return -1;
    }
    length_value = JS_GetPropertyStr(ctx, value, "length");
    if (JS_IsException(length_value)) return -1;
    int converted = JS_ToIndex(ctx, &length, length_value);
    JS_FreeValue(ctx, length_value);
    if (converted < 0) return -1;
    if (length > UINT32_MAX ||
        length > SIZE_MAX / sizeof(clone->transfers.tab[0])) {
        JS_ThrowRangeError(ctx, "transfer list is too large");
        return -1;
    }
    if (length == 0) return 0;

    clone->transfers.tab =
        tjs__mallocz((size_t)length * sizeof(clone->transfers.tab[0]));
    if (!clone->transfers.tab) {
        JS_ThrowOutOfMemory(ctx);
        return -1;
    }
    clone->transfers.len = (size_t)length;
    for (size_t i = 0; i < clone->transfers.len; i++) {
        clone->transfers.tab[i].value =
            JS_GetPropertyUint32(ctx, value, (uint32_t)i);
        if (JS_IsException(clone->transfers.tab[i].value)) {
            for (size_t j = 0; j < i; j++)
                JS_FreeValue(ctx, clone->transfers.tab[j].value);
            tjs__free(clone->transfers.tab);
            memset(&clone->transfers, 0, sizeof(clone->transfers));
            return -1;
        }
    }
    return 0;
}

static void message_clone_release_sabs(TJSMessageClone *clone) {
    for (size_t i = 0; i < clone->sab_count; i++)
        tjs__sab_free(NULL, clone->sabs[i]);
    tjs__free(clone->sabs);
    clone->sabs = NULL;
    clone->sab_count = 0;
}

static void message_clone_abort_prepared(JSContext *ctx,
                                         TJSMessageClone *clone) {
    JS_ReleaseAutoTransferTab(&clone->transfers);
    message_clone_free_transfer_values(ctx, clone);
    message_clone_release_sabs(clone);
    atomic_store_explicit(&clone->state, TJS_MESSAGE_CLONE_ABORTED,
                          memory_order_release);
}

TJSMessageClone *tjs__message_clone_prepare(
    JSContext *ctx, JSValueConst value, JSValueConst transfer_list) {
    TJSMessageClone *clone;
    JSSABTab sab_tab = { 0 };
    uint8_t *serialized;

    if (!ctx) return NULL;
    clone = tjs__mallocz(sizeof(*clone));
    if (!clone) {
        JS_ThrowOutOfMemory(ctx);
        return NULL;
    }
    atomic_init(&clone->refs, 1);
    atomic_init(&clone->state, TJS_MESSAGE_CLONE_PREPARED);
    if (message_clone_parse_transfers(ctx, transfer_list, clone) < 0) {
        tjs__free(clone);
        return NULL;
    }

    serialized = JS_WriteObject3(
        ctx, &clone->size, value,
        JS_WRITE_OBJ_SAB | JS_WRITE_OBJ_REFERENCE |
            JS_WRITE_OBJ_STRUCTURED_CLONE,
        &sab_tab, &clone->transfers);
    if (!serialized) {
        message_clone_free_transfer_values(ctx, clone);
        tjs__free(clone->transfers.tab);
        tjs__free(clone);
        return NULL;
    }

    clone->data = tjs__malloc(clone->size ? clone->size : 1);
    if (!clone->data) {
        js_free(ctx, serialized);
        js_free(ctx, sab_tab.tab);
        message_clone_abort_prepared(ctx, clone);
        tjs__free(clone->transfers.tab);
        tjs__free(clone);
        JS_ThrowOutOfMemory(ctx);
        return NULL;
    }
    if (clone->size) memcpy(clone->data, serialized, clone->size);
    js_free(ctx, serialized);

    if (sab_tab.len) {
        clone->sabs = tjs__malloc(sab_tab.len * sizeof(clone->sabs[0]));
        if (!clone->sabs) {
            js_free(ctx, sab_tab.tab);
            message_clone_abort_prepared(ctx, clone);
            tjs__free(clone->transfers.tab);
            tjs__free(clone->data);
            tjs__free(clone);
            JS_ThrowOutOfMemory(ctx);
            return NULL;
        }
        clone->sab_count = sab_tab.len;
        for (size_t i = 0; i < sab_tab.len; i++) {
            tjs__sab_dup(NULL, sab_tab.tab[i]);
            clone->sabs[i] = sab_tab.tab[i];
        }
    }
    js_free(ctx, sab_tab.tab);
    return clone;
}

int tjs__message_clone_commit(JSContext *ctx, TJSMessageClone *clone) {
    if (!ctx || !clone ||
        atomic_load_explicit(&clone->state, memory_order_acquire) !=
            TJS_MESSAGE_CLONE_PREPARED) {
        if (ctx) JS_ThrowTypeError(ctx, "message clone is not prepared");
        return -1;
    }
    if (JS_CommitArrayBufferTransfers(ctx, &clone->transfers) < 0) {
        message_clone_abort_prepared(ctx, clone);
        return -1;
    }
    message_clone_free_transfer_values(ctx, clone);
    atomic_store_explicit(&clone->state, TJS_MESSAGE_CLONE_COMMITTED,
                          memory_order_release);
    return 0;
}

void tjs__message_clone_abort(JSContext *ctx, TJSMessageClone *clone) {
    if (!clone) return;
    if (ctx && atomic_load_explicit(&clone->state, memory_order_acquire) ==
                   TJS_MESSAGE_CLONE_PREPARED)
        message_clone_abort_prepared(ctx, clone);
    tjs__message_clone_free(clone);
}

JSValue tjs__message_clone_read(JSContext *ctx, TJSMessageClone *clone) {
    int expected = TJS_MESSAGE_CLONE_COMMITTED;
    JSSABTab read_sabs = { 0 };
    const uint8_t *data;
    JSValue result;

    if (!ctx || !clone)
        return ctx ? JS_ThrowTypeError(ctx, "message clone is NULL")
                   : JS_EXCEPTION;
    if (!atomic_compare_exchange_strong_explicit(
            &clone->state, &expected, TJS_MESSAGE_CLONE_CONSUMED,
            memory_order_acq_rel, memory_order_acquire)) {
        return JS_ThrowTypeError(ctx, "message clone is not readable");
    }

    data = clone->size ? clone->data : (const uint8_t *)"";
    result = JS_ReadObject3(
        ctx, data, clone->size,
        JS_READ_OBJ_SAB | JS_READ_OBJ_REFERENCE |
            JS_READ_OBJ_STRUCTURED_CLONE,
        &read_sabs, &clone->transfers);

    /* Destination objects now own their references. Drop all wire refs even
     * when decoding failed part-way through the graph. */
    message_clone_release_sabs(clone);
    js_free(ctx, read_sabs.tab);
    JS_ReleaseAutoTransferTab(&clone->transfers);
    return result;
}

TJSMessageClone *tjs__message_clone_retain(TJSMessageClone *clone) {
    if (clone)
        atomic_fetch_add_explicit(&clone->refs, 1, memory_order_relaxed);
    return clone;
}

void tjs__message_clone_free(TJSMessageClone *clone) {
    if (!clone) return;
    if (atomic_fetch_sub_explicit(&clone->refs, 1, memory_order_acq_rel) != 1)
        return;

    int state = atomic_load_explicit(&clone->state, memory_order_acquire);
    /* A prepared clone owns source-runtime JSValues and must be aborted on
     * that source thread instead of arriving here. */
    CHECK_NE(state, TJS_MESSAGE_CLONE_PREPARED);
    message_clone_release_sabs(clone);
    JS_ReleaseAutoTransferTab(&clone->transfers);
    tjs__free(clone->transfers.tab);
    tjs__free(clone->data);
    tjs__free(clone);
}

size_t tjs__message_clone_size(const TJSMessageClone *clone) {
    return clone ? clone->size : 0;
}

size_t tjs__message_clone_transfer_count(const TJSMessageClone *clone) {
    return clone ? clone->transfers.len + clone->sab_count : 0;
}

const uint8_t *tjs__message_clone_data(const TJSMessageClone *clone) {
    return clone ? clone->data : NULL;
}
