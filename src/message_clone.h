/*
 * Private, process-local message clone transport shared by native modules.
 * This is intentionally not part of tjs.h: callers are compiled into libcjs.
 */
#ifndef TJS_MESSAGE_CLONE_H
#define TJS_MESSAGE_CLONE_H

#include "quickjs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TJSMessageClone TJSMessageClone;

/* Prepare serializes value and retains all wire references, but does not
 * detach ArrayBuffers in transfer_list. The returned object is still tied to
 * ctx until commit or abort. */
TJSMessageClone *tjs__message_clone_prepare(
    JSContext *ctx, JSValueConst value, JSValueConst transfer_list);

/* Commit atomically detaches all transferred ArrayBuffers and makes clone
 * thread-neutral. On failure it also drops every source-context reference;
 * clone remains valid only so it can be released. */
int tjs__message_clone_commit(JSContext *ctx, TJSMessageClone *clone);

/* Abort a prepared clone on its source thread and release it. */
void tjs__message_clone_abort(JSContext *ctx, TJSMessageClone *clone);

/* Read consumes the wire references exactly once. */
JSValue tjs__message_clone_read(JSContext *ctx, TJSMessageClone *clone);

/* References may be retained and released on any thread after commit. */
TJSMessageClone *tjs__message_clone_retain(TJSMessageClone *clone);
void tjs__message_clone_free(TJSMessageClone *clone);

size_t tjs__message_clone_size(const TJSMessageClone *clone);
size_t tjs__message_clone_transfer_count(const TJSMessageClone *clone);
const uint8_t *tjs__message_clone_data(const TJSMessageClone *clone);

#ifdef __cplusplus
}
#endif

#endif
