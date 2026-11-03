/*
 * circu.js
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

#include "mem.h"
#include "private.h"

#include <stdint.h>

#define TJS_RUNTIME_EVENT_NAMESPACE "circu.runtime"
#define TJS_RUNTIME_EVENT_NAME "event"

typedef struct TJSEvBusValue {
    struct list_head link;
    App *owner;
    JSAtom namespace_atom;
    JSAtom key_atom;
    JSValue value;
} TJSEvBusValue;

typedef struct TJSEvBusListener {
    struct list_head link;
    App *owner;
    JSContext *realm;
    JSAtom namespace_atom;
    JSAtom event_atom;
    JSValue callback;
    uint64_t id;
    int32_t priority;
    uint64_t sequence;
    size_t dispatch_refs;
    bool active;
} TJSEvBusListener;

typedef struct {
    TJSEvBus *bus;
    uint64_t id;
} TJSEvBusSubscription;

struct TJSEvBus {
    struct list_head values;
    struct list_head listeners;
    uint64_t next_listener_id;
    uint64_t next_listener_sequence;
    size_t ref_count;
    size_t dispatch_depth;
    bool released_entries_pending;
    bool disposed;
};

static void evbus_cleanup_released_contexts(TJSEvBus *bus);
static void evbus_retain(TJSEvBus *bus);
static void evbus_release(TJSEvBus *bus);

static void evbus_dispatch_enter(TJSEvBus *bus) {
    evbus_retain(bus);
    bus->dispatch_depth++;
}

static void evbus_dispatch_leave(TJSEvBus *bus) {
    assert(bus->dispatch_depth > 0);
    bus->dispatch_depth--;
    if (bus->dispatch_depth == 0 && bus->released_entries_pending) {
        /* A snapshotted callback can create entries after its owner was freed. */
        bus->released_entries_pending = false;
        evbus_cleanup_released_contexts(bus);
    }
    evbus_release(bus);
}

static void evbus_retain(TJSEvBus *bus) {
    if (bus) {
        assert(bus->ref_count != SIZE_MAX);
        bus->ref_count++;
    }
}

static void evbus_release(TJSEvBus *bus) {
    if (!bus || bus->ref_count == 0) {
        return;
    }
    if (--bus->ref_count == 0) {
        tjs__free(bus);
    }
}

static void evbus_value_free(JSRuntime *rt, TJSEvBusValue *entry) {
    JS_FreeAtomRT(rt, entry->namespace_atom);
    JS_FreeAtomRT(rt, entry->key_atom);
    JS_FreeValueRT(rt, entry->value);
    tjs__free(entry);
}

static void evbus_value_remove(JSRuntime *rt, TJSEvBusValue *entry) {
    list_del(&entry->link);
    evbus_value_free(rt, entry);
}

static TJSEvBusValue *evbus_find_value(TJSEvBus *bus, JSAtom namespace_atom, JSAtom key_atom) {
    struct list_head *pos;
    list_for_each(pos, &bus->values) {
        TJSEvBusValue *entry = list_entry(pos, TJSEvBusValue, link);
        if (entry->namespace_atom == namespace_atom && entry->key_atom == key_atom) {
            return entry;
        }
    }
    return NULL;
}

static void evbus_listener_free(JSRuntime *rt, TJSEvBusListener *listener) {
    JS_FreeAtomRT(rt, listener->namespace_atom);
    JS_FreeAtomRT(rt, listener->event_atom);
    JS_FreeValueRT(rt, listener->callback);
    JS_FreeContext(listener->realm);
    tjs__free(listener);
}

static void evbus_listener_remove(JSRuntime *rt, TJSEvBusListener *listener) {
    if (!listener->active) {
        return;
    }
    listener->active = false;
    list_del(&listener->link);
    if (listener->dispatch_refs == 0) {
        evbus_listener_free(rt, listener);
    }
}

static void evbus_listener_release_dispatch(JSRuntime *rt, TJSEvBusListener *listener) {
    assert(listener->dispatch_refs > 0);
    listener->dispatch_refs--;
    if (!listener->active && listener->dispatch_refs == 0) {
        evbus_listener_free(rt, listener);
    }
}

static void evbus_remove_listener(JSRuntime *rt, TJSEvBus *bus, uint64_t id) {
    struct list_head *pos;
    struct list_head *tmp;

    list_for_each_safe(pos, tmp, &bus->listeners) {
        TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
        if (listener->id == id) {
            evbus_listener_remove(rt, listener);
            return;
        }
    }
}

static TJSEvBus *evbus_get(JSContext *ctx, App **app_out) {
    App *app = TJS_GetApp(ctx);
    if (!app || !app->trt) {
        JS_ThrowInternalError(ctx, "evbus requires an application context");
        return NULL;
    }

    TJSRuntime *trt = app->trt;
    if (trt->freeing) {
        JS_ThrowInternalError(ctx, "evbus is unavailable while its runtime is shutting down");
        return NULL;
    }

    TJSEvBus *bus = trt->evbus;
    if (!bus) {
        bus = tjs__mallocz(sizeof(*bus));
        if (!bus) {
            JS_ThrowOutOfMemory(ctx);
            return NULL;
        }
        init_list_head(&bus->values);
        init_list_head(&bus->listeners);
        bus->next_listener_id = 1;
        bus->ref_count = 1;  /* The owning TJSRuntime reference. */
        trt->evbus = bus;
    }
    if (bus->disposed) {
        JS_ThrowInternalError(ctx, "evbus is unavailable while its runtime is shutting down");
        return NULL;
    }
    if (app_out && app->context_released) {
        if (bus->dispatch_depth == 0) {
            JS_ThrowTypeError(ctx, "evbus cannot create entries for a released sandbox");
            return NULL;
        }
        bus->released_entries_pending = true;
    }

    if (app_out) {
        *app_out = app;
    }
    return bus;
}

static int evbus_namespace_atom(JSContext *ctx, int argc, JSValueConst *argv,
                                const char *method, JSAtom *namespace_atom) {
    *namespace_atom = JS_ATOM_NULL;
    if (argc < 1 || !JS_IsString(argv[0])) {
        JS_ThrowTypeError(ctx, "evbus.%s requires a string namespace", method);
        return -1;
    }
    *namespace_atom = JS_ValueToAtom(ctx, argv[0]);
    return *namespace_atom == JS_ATOM_NULL ? -1 : 0;
}

static int evbus_pair_atoms(JSContext *ctx, int argc, JSValueConst *argv,
                            const char *method, JSAtom *namespace_atom, JSAtom *name_atom) {
    *namespace_atom = JS_ATOM_NULL;
    *name_atom = JS_ATOM_NULL;
    if (argc < 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) {
        JS_ThrowTypeError(ctx, "evbus.%s requires string namespace and name", method);
        return -1;
    }
    *namespace_atom = JS_ValueToAtom(ctx, argv[0]);
    if (*namespace_atom == JS_ATOM_NULL) {
        return -1;
    }
    *name_atom = JS_ValueToAtom(ctx, argv[1]);
    if (*name_atom == JS_ATOM_NULL) {
        JS_FreeAtom(ctx, *namespace_atom);
        *namespace_atom = JS_ATOM_NULL;
        return -1;
    }
    return 0;
}

static JSValue tjs_evbus_set(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "evbus.set requires (namespace, key, value)");
    }

    JSAtom namespace_atom;
    JSAtom key_atom;
    if (evbus_pair_atoms(ctx, argc, argv, "set", &namespace_atom, &key_atom) < 0) {
        return JS_EXCEPTION;
    }

    App *app;
    TJSEvBus *bus = evbus_get(ctx, &app);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, key_atom);
        return JS_EXCEPTION;
    }

    TJSEvBusValue *entry = evbus_find_value(bus, namespace_atom, key_atom);
    if (entry) {
        JSValue old_value = entry->value;
        entry->value = JS_DupValue(ctx, argv[2]);
        entry->owner = app;
        /* Freeing a value can finalize a sandbox and reenter cleanup. */
        JS_FreeValue(ctx, old_value);
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, key_atom);
        return JS_UNDEFINED;
    }

    entry = tjs__mallocz(sizeof(*entry));
    if (!entry) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, key_atom);
        return JS_ThrowOutOfMemory(ctx);
    }
    entry->owner = app;
    entry->namespace_atom = namespace_atom;
    entry->key_atom = key_atom;
    entry->value = JS_DupValue(ctx, argv[2]);
    list_add_tail(&entry->link, &bus->values);
    return JS_UNDEFINED;
}

static JSValue tjs_evbus_get(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    JSAtom namespace_atom;
    JSAtom key_atom;
    if (evbus_pair_atoms(ctx, argc, argv, "get", &namespace_atom, &key_atom) < 0) {
        return JS_EXCEPTION;
    }

    TJSEvBus *bus = evbus_get(ctx, NULL);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, key_atom);
        return JS_EXCEPTION;
    }

    TJSEvBusValue *entry = evbus_find_value(bus, namespace_atom, key_atom);
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, key_atom);
    return entry ? JS_DupValue(ctx, entry->value) : JS_UNDEFINED;
}

static JSValue tjs_evbus_has(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    JSAtom namespace_atom;
    JSAtom key_atom;
    if (evbus_pair_atoms(ctx, argc, argv, "has", &namespace_atom, &key_atom) < 0) {
        return JS_EXCEPTION;
    }

    TJSEvBus *bus = evbus_get(ctx, NULL);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, key_atom);
        return JS_EXCEPTION;
    }

    bool has = evbus_find_value(bus, namespace_atom, key_atom) != NULL;
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, key_atom);
    return JS_NewBool(ctx, has);
}

static JSValue tjs_evbus_delete(JSContext *ctx, JSValueConst this_val, int argc,
                                 JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    JSAtom namespace_atom;
    JSAtom key_atom;
    if (evbus_pair_atoms(ctx, argc, argv, "delete", &namespace_atom, &key_atom) < 0) {
        return JS_EXCEPTION;
    }

    TJSEvBus *bus = evbus_get(ctx, NULL);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, key_atom);
        return JS_EXCEPTION;
    }

    TJSEvBusValue *entry = evbus_find_value(bus, namespace_atom, key_atom);
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, key_atom);
    if (!entry) {
        return JS_FALSE;
    }
    evbus_value_remove(JS_GetRuntime(ctx), entry);
    return JS_TRUE;
}

static JSValue tjs_evbus_clear(JSContext *ctx, JSValueConst this_val, int argc,
                                JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    JSAtom namespace_atom;
    if (evbus_namespace_atom(ctx, argc, argv, "clear", &namespace_atom) < 0) {
        return JS_EXCEPTION;
    }

    TJSEvBus *bus = evbus_get(ctx, NULL);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        return JS_EXCEPTION;
    }

    for (;;) {
        TJSEvBusValue *match = NULL;
        struct list_head *pos;
        list_for_each(pos, &bus->values) {
            TJSEvBusValue *entry = list_entry(pos, TJSEvBusValue, link);
            if (entry->namespace_atom == namespace_atom) {
                match = entry;
                break;
            }
        }
        if (!match) break;
        evbus_value_remove(JS_GetRuntime(ctx), match);
    }
    JS_FreeAtom(ctx, namespace_atom);
    return JS_UNDEFINED;
}

static void evbus_subscription_finalizer(void *opaque) {
    TJSEvBusSubscription *subscription = opaque;
    if (!subscription) {
        return;
    }
    evbus_release(subscription->bus);
    tjs__free(subscription);
}

static JSValue tjs_evbus_unsubscribe(JSContext *ctx, JSValueConst this_val, int argc,
                                      JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)argc;
    (void)argv;
    (void)magic;

    TJSEvBusSubscription *subscription = opaque;
    if (subscription && subscription->bus && !subscription->bus->disposed) {
        evbus_remove_listener(JS_GetRuntime(ctx), subscription->bus, subscription->id);
    }
    return JS_UNDEFINED;
}

static JSValue tjs_evbus_on(JSContext *ctx, JSValueConst this_val, int argc,
                             JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    if (argc < 3 || !JS_IsFunction(ctx, argv[2])) {
        return JS_ThrowTypeError(ctx, "evbus.on requires (namespace, event, listener)");
    }

    JSAtom namespace_atom;
    JSAtom event_atom;
    if (evbus_pair_atoms(ctx, argc, argv, "on", &namespace_atom, &event_atom) < 0) {
        return JS_EXCEPTION;
    }

    App *app;
    TJSEvBus *bus = evbus_get(ctx, &app);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_EXCEPTION;
    }
    if (bus->next_listener_id == 0) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowRangeError(ctx, "evbus listener id space exhausted");
    }
    int32_t priority = 0;
    if (argc >= 4 && !JS_IsUndefined(argv[3]) &&
        JS_ToInt32(ctx, &priority, argv[3])) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_EXCEPTION;
    }

    TJSEvBusListener *listener = tjs__mallocz(sizeof(*listener));
    if (!listener) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowOutOfMemory(ctx);
    }
    listener->owner = app;
    listener->realm = JS_DupContext(ctx);
    listener->namespace_atom = namespace_atom;
    listener->event_atom = event_atom;
    listener->callback = JS_DupValue(ctx, argv[2]);
    listener->id = bus->next_listener_id++;
    listener->priority = priority;
    listener->sequence = bus->next_listener_sequence++;
    listener->active = true;
    list_add_tail(&listener->link, &bus->listeners);

    TJSEvBusSubscription *subscription = tjs__mallocz(sizeof(*subscription));
    if (!subscription) {
        evbus_listener_remove(JS_GetRuntime(ctx), listener);
        return JS_ThrowOutOfMemory(ctx);
    }
    subscription->bus = bus;
    subscription->id = listener->id;
    evbus_retain(bus);

    /* Closure allocation can run GC and remove the listener through sandbox cleanup. */
    listener->dispatch_refs++;
    /* A null name avoids a post-opaque allocation path in this QuickJS fork. */
    JSValue unsubscribe = JS_NewCClosure(ctx, tjs_evbus_unsubscribe, NULL,
                                         evbus_subscription_finalizer, 0, 0, subscription);
    if (JS_IsException(unsubscribe)) {
        evbus_release(bus);
        tjs__free(subscription);
        evbus_listener_remove(JS_GetRuntime(ctx), listener);
        evbus_listener_release_dispatch(JS_GetRuntime(ctx), listener);
        return unsubscribe;
    }
    evbus_listener_release_dispatch(JS_GetRuntime(ctx), listener);
    return unsubscribe;
}

static int evbus_listener_compare(const void *left, const void *right) {
    const TJSEvBusListener *a = *(TJSEvBusListener * const *) left;
    const TJSEvBusListener *b = *(TJSEvBusListener * const *) right;
    if (a->priority != b->priority) {
        return a->priority > b->priority ? -1 : 1;
    }
    if (a->sequence == b->sequence) {
        return 0;
    }
    return a->sequence < b->sequence ? -1 : 1;
}

static void evbus_discard_exception(JSContext *ctx) {
    if (JS_HasException(ctx)) {
        JS_FreeValue(ctx, JS_GetException(ctx));
    }
}

static JSValue evbus_move_exception(JSContext *from, JSContext *to) {
    if (from != to) {
        JS_Throw(to, JS_GetException(from));
    }
    return JS_EXCEPTION;
}

static void evbus_cleanup_released_contexts(TJSEvBus *bus) {
    for (;;) {
        App *owner = NULL;
        struct list_head *pos;

        list_for_each(pos, &bus->values) {
            TJSEvBusValue *entry = list_entry(pos, TJSEvBusValue, link);
            if (entry->owner->context_released) {
                owner = entry->owner;
                break;
            }
        }
        if (!owner) {
            list_for_each(pos, &bus->listeners) {
                TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
                if (listener->owner->context_released) {
                    owner = listener->owner;
                    break;
                }
            }
        }
        if (!owner) {
            return;
        }
        tjs__mod_evbus_cleanup_context(owner);
    }
}

static JSValue tjs_evbus_emit(JSContext *ctx, JSValueConst this_val, int argc,
                               JSValueConst *argv, int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    JSAtom namespace_atom;
    JSAtom event_atom;
    if (evbus_pair_atoms(ctx, argc, argv, "emit", &namespace_atom, &event_atom) < 0) {
        return JS_EXCEPTION;
    }

    TJSEvBus *bus = evbus_get(ctx, NULL);
    if (!bus) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_EXCEPTION;
    }

    size_t count = 0;
    struct list_head *pos;
    list_for_each(pos, &bus->listeners) {
        TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
        if (listener->active && listener->namespace_atom == namespace_atom && listener->event_atom == event_atom) {
            count++;
        }
    }
    if (count == 0) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_FALSE;
    }
    if (count > SIZE_MAX / sizeof(TJSEvBusListener *)) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowOutOfMemory(ctx);
    }

    TJSEvBusListener **snapshot = tjs__malloc(count * sizeof(*snapshot));
    if (!snapshot) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowOutOfMemory(ctx);
    }

    size_t index = 0;
    list_for_each(pos, &bus->listeners) {
        TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
        if (listener->active && listener->namespace_atom == namespace_atom && listener->event_atom == event_atom) {
            listener->dispatch_refs++;
            snapshot[index++] = listener;
        }
    }
    evbus_dispatch_enter(bus);
    JSAtom runtime_namespace = JS_NewAtom(ctx, TJS_RUNTIME_EVENT_NAMESPACE);
    if (runtime_namespace == JS_ATOM_NULL) {
        for (size_t i = 0; i < count; i++) {
            evbus_listener_release_dispatch(JS_GetRuntime(ctx), snapshot[i]);
        }
        evbus_dispatch_leave(bus);
        tjs__free(snapshot);
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_EXCEPTION;
    }
    JSAtom runtime_event = JS_NewAtom(ctx, TJS_RUNTIME_EVENT_NAME);
    if (runtime_event == JS_ATOM_NULL) {
        JS_FreeAtom(ctx, runtime_namespace);
        for (size_t i = 0; i < count; i++) {
            evbus_listener_release_dispatch(JS_GetRuntime(ctx), snapshot[i]);
        }
        evbus_dispatch_leave(bus);
        tjs__free(snapshot);
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_EXCEPTION;
    }
    if (namespace_atom == runtime_namespace && event_atom == runtime_event && count > 1) {
        qsort(snapshot, count, sizeof(*snapshot), evbus_listener_compare);
    }
    JS_FreeAtom(ctx, runtime_namespace);
    JS_FreeAtom(ctx, runtime_event);

    JSValue payload = argc >= 3 ? argv[2] : JS_UNDEFINED;
    JSValue dispatch_result = JS_TRUE;
    for (size_t i = 0; i < count; i++) {
        TJSEvBusListener *listener = snapshot[i];
        JSContext *realm = listener->realm;
        JSValue result = JS_Call(realm, listener->callback, JS_UNDEFINED, 1, &payload);
        if (JS_IsException(result)) {
            dispatch_result = evbus_move_exception(realm, ctx);
            evbus_listener_release_dispatch(JS_GetRuntime(ctx), listener);
            for (size_t j = i + 1; j < count; j++) {
                evbus_listener_release_dispatch(JS_GetRuntime(ctx), snapshot[j]);
            }
            break;
        }
        JS_FreeValueRT(JS_GetRuntime(ctx), result);
        evbus_listener_release_dispatch(JS_GetRuntime(ctx), listener);
    }

    evbus_dispatch_leave(bus);
    tjs__free(snapshot);
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, event_atom);
    return dispatch_result;
}

static JSValue evbus_default_runtime_result(JSContext *ctx, int32_t event_name) {
    return JS_NewBool(ctx, event_name == EV_JOB_EXCEPTION);
}

static void evbus_release_snapshot(JSRuntime *rt, TJSEvBusListener **snapshot,
                                   size_t start, size_t count) {
    for (size_t i = start; i < count; i++) {
        evbus_listener_release_dispatch(rt, snapshot[i]);
    }
}

static int evbus_define_property(JSContext *ctx, JSValueConst object,
                                 const char *name, JSValue value) {
    return JS_DefinePropertyValueStr(ctx, object, name, value, JS_PROP_C_W_E);
}

JSValue tjs__mod_evbus_dispatch_runtime_event(JSContext *ctx, int32_t event_name,
                                              JSValueConst data) {
    TJSEvBus *bus = evbus_get(ctx, NULL);
    if (!bus) {
        return JS_EXCEPTION;
    }

    JSAtom namespace_atom = JS_NewAtom(ctx, TJS_RUNTIME_EVENT_NAMESPACE);
    if (namespace_atom == JS_ATOM_NULL) {
        return JS_EXCEPTION;
    }
    JSAtom event_atom = JS_NewAtom(ctx, TJS_RUNTIME_EVENT_NAME);
    if (event_atom == JS_ATOM_NULL) {
        JS_FreeAtom(ctx, namespace_atom);
        return JS_EXCEPTION;
    }

    size_t count = 0;
    struct list_head *pos;
    list_for_each(pos, &bus->listeners) {
        TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
        if (listener->active && listener->namespace_atom == namespace_atom &&
            listener->event_atom == event_atom) {
            count++;
        }
    }
    if (count == 0) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return evbus_default_runtime_result(ctx, event_name);
    }
    if (count > SIZE_MAX / sizeof(TJSEvBusListener *)) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowOutOfMemory(ctx);
    }

    TJSEvBusListener **snapshot = tjs__malloc(count * sizeof(*snapshot));
    if (!snapshot) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowOutOfMemory(ctx);
    }

    size_t index = 0;
    list_for_each(pos, &bus->listeners) {
        TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
        if (listener->active && listener->namespace_atom == namespace_atom &&
            listener->event_atom == event_atom) {
            listener->dispatch_refs++;
            snapshot[index++] = listener;
        }
    }
    if (count > 1) {
        qsort(snapshot, count, sizeof(*snapshot), evbus_listener_compare);
    }

    JSRuntime *rt = JS_GetRuntime(ctx);
    evbus_dispatch_enter(bus);
    JSValue context = JS_NewObject(ctx);
    JSValue frame = JS_UNDEFINED;
    if (JS_IsException(context)) {
        goto fail_frame;
    }
    frame = JS_NewObject(ctx);
    if (JS_IsException(frame) ||
        evbus_define_property(ctx, context, "handled", JS_FALSE) < 0 ||
        evbus_define_property(ctx, context, "dispatched", JS_FALSE) < 0 ||
        evbus_define_property(ctx, context, "rejectionEmitted", JS_FALSE) < 0 ||
        evbus_define_property(ctx, frame, "name", JS_NewInt32(ctx, event_name)) < 0 ||
        evbus_define_property(ctx, frame, "data", JS_DupValue(ctx, data)) < 0 ||
        evbus_define_property(ctx, frame, "context", JS_DupValue(ctx, context)) < 0) {
        goto fail_frame;
    }

    JSValue result = evbus_default_runtime_result(ctx, event_name);
    for (size_t i = 0; i < count; i++) {
        TJSEvBusListener *listener = snapshot[i];
        JSContext *realm = listener->realm;
        JSValue value = JS_Call(realm, listener->callback, JS_UNDEFINED, 1,
                                (JSValueConst *) &frame);
        if (JS_IsException(value)) {
            if (event_name == EV_BEFORE_UNLOAD || event_name == EV_BEFORE_EXIT) {
                JS_FreeValueRT(rt, result);
                result = evbus_move_exception(realm, ctx);
                evbus_release_snapshot(rt, snapshot, i, count);
                break;
            }
            evbus_discard_exception(realm);
            evbus_listener_release_dispatch(rt, listener);
            continue;
        }
        evbus_listener_release_dispatch(rt, listener);
        if (JS_IsBool(value)) {
            if (event_name == EV_BEFORE_UNLOAD &&
                ((JS_IsBool(result) && JS_VALUE_GET_BOOL(result)) ||
                 JS_VALUE_GET_BOOL(value))) {
                JS_FreeValueRT(rt, result);
                JS_FreeValueRT(rt, value);
                result = JS_TRUE;
            } else {
                JS_FreeValueRT(rt, result);
                result = value;
            }
        } else {
            JS_FreeValueRT(rt, value);
        }
    }

    evbus_dispatch_leave(bus);
    JS_FreeValueRT(rt, frame);
    JS_FreeValueRT(rt, context);
    tjs__free(snapshot);
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, event_atom);
    return result;

fail_frame:
    JS_FreeValueRT(rt, frame);
    JS_FreeValueRT(rt, context);
    evbus_release_snapshot(rt, snapshot, 0, count);
    evbus_dispatch_leave(bus);
    tjs__free(snapshot);
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, event_atom);
    return JS_EXCEPTION;
}

static JSValue tjs_evbus_dispatch_runtime_event(JSContext *ctx, JSValueConst this_val,
                                                 int argc, JSValueConst *argv,
                                                 int magic, void *opaque) {
    (void)this_val;
    (void)magic;
    (void)opaque;
    int32_t event_name;
    if (argc < 1 || JS_ToInt32(ctx, &event_name, argv[0])) {
        return JS_ThrowTypeError(ctx, "evbus.dispatchRuntimeEvent requires an integer event name");
    }
    return tjs__mod_evbus_dispatch_runtime_event(
        ctx, event_name, argc >= 2 ? argv[1] : JS_UNDEFINED);
}

typedef struct {
    const char *name;
    int length;
    JSCClosure *function;
} TJSEvBusMethod;

static const TJSEvBusMethod tjs_evbus_methods[] = {
    { "set", 3, tjs_evbus_set },
    { "get", 2, tjs_evbus_get },
    { "has", 2, tjs_evbus_has },
    { "delete", 2, tjs_evbus_delete },
    { "clear", 1, tjs_evbus_clear },
    { "on", 4, tjs_evbus_on },
    { "emit", 3, tjs_evbus_emit },
    { "dispatchRuntimeEvent", 2, tjs_evbus_dispatch_runtime_event },
};

void tjs__mod_evbus_init(JSContext *ctx, JSValue ns) {
    for (size_t i = 0; i < countof(tjs_evbus_methods); i++) {
        const TJSEvBusMethod *method = &tjs_evbus_methods[i];
        /* C closures retain no realm, so each call observes its caller's App. */
        JSValue function = JS_NewCClosure(ctx, method->function, method->name,
                                          NULL, method->length, 0, NULL);
        if (JS_IsException(function)) {
            return;
        }
        if (JS_SetPropertyStr(ctx, ns, method->name, function) < 0) {
            return;
        }
    }
    JSValue value = JS_NewString(ctx, TJS_RUNTIME_EVENT_NAMESPACE);
    if (JS_IsException(value) ||
        JS_DefinePropertyValueStr(ctx, ns, "RUNTIME_NAMESPACE", value,
                                  JS_PROP_ENUMERABLE | JS_PROP_CONFIGURABLE) < 0) {
        return;
    }
    value = JS_NewString(ctx, TJS_RUNTIME_EVENT_NAME);
    if (JS_IsException(value)) {
        return;
    }
    if (JS_DefinePropertyValueStr(ctx, ns, "RUNTIME_EVENT", value,
                                  JS_PROP_ENUMERABLE | JS_PROP_CONFIGURABLE) < 0) {
        return;
    }
}

void tjs__mod_evbus_cleanup_context(App *app) {
    if (!app || !app->trt || !app->trt->evbus || app->trt->evbus->disposed) {
        return;
    }

    TJSEvBus *bus = app->trt->evbus;
    /* The sandbox context may already be gone; values and atoms belong to the runtime. */
    JSRuntime *rt = app->trt->rt;
    for (;;) {
        TJSEvBusValue *value_match = NULL;
        TJSEvBusListener *listener_match = NULL;
        struct list_head *pos;
        list_for_each(pos, &bus->values) {
            TJSEvBusValue *entry = list_entry(pos, TJSEvBusValue, link);
            if (entry->owner == app) { value_match = entry; break; }
        }
        if (value_match) {
            evbus_value_remove(rt, value_match);
            continue;
        }
        list_for_each(pos, &bus->listeners) {
            TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
            if (listener->owner == app) { listener_match = listener; break; }
        }
        if (listener_match) {
            evbus_listener_remove(rt, listener_match);
            continue;
        }
        break;
    }
}

void tjs__mod_evbus_cleanup_runtime(TJSRuntime *trt) {
    if (!trt || !trt->evbus) {
        return;
    }

    TJSEvBus *bus = trt->evbus;
    trt->evbus = NULL;
    bus->disposed = true;

    JSRuntime *rt = trt->rt;
    while (!list_empty(&bus->values)) {
        TJSEvBusValue *entry = list_entry(bus->values.next, TJSEvBusValue, link);
        evbus_value_remove(rt, entry);
    }
    while (!list_empty(&bus->listeners)) {
        TJSEvBusListener *listener = list_entry(bus->listeners.next, TJSEvBusListener, link);
        evbus_listener_remove(rt, listener);
    }

    evbus_release(bus);
}
