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
    JSAtom namespace_atom;
    JSAtom event_atom;
    JSValue callback;
    uint64_t id;
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
    size_t ref_count;
    size_t dispatch_depth;
    bool released_entries_pending;
    bool disposed;
};

static void evbus_retain(TJSEvBus *bus) {
    if (bus) {
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

static void evbus_value_free(JSContext *ctx, TJSEvBusValue *entry) {
    JS_FreeAtom(ctx, entry->namespace_atom);
    JS_FreeAtom(ctx, entry->key_atom);
    JS_FreeValue(ctx, entry->value);
    tjs__free(entry);
}

static void evbus_value_remove(JSContext *ctx, TJSEvBusValue *entry) {
    list_del(&entry->link);
    evbus_value_free(ctx, entry);
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

static void evbus_listener_free(JSContext *ctx, TJSEvBusListener *listener) {
    JS_FreeAtom(ctx, listener->namespace_atom);
    JS_FreeAtom(ctx, listener->event_atom);
    JS_FreeValue(ctx, listener->callback);
    tjs__free(listener);
}

static void evbus_listener_remove(JSContext *ctx, TJSEvBusListener *listener) {
    if (!listener->active) {
        return;
    }
    listener->active = false;
    list_del(&listener->link);
    if (listener->dispatch_refs == 0) {
        evbus_listener_free(ctx, listener);
    }
}

static void evbus_listener_release_dispatch(JSContext *ctx, TJSEvBusListener *listener) {
    if (listener->dispatch_refs > 0) {
        listener->dispatch_refs--;
    }
    if (!listener->active && listener->dispatch_refs == 0) {
        evbus_listener_free(ctx, listener);
    }
}

static void evbus_remove_listener(JSContext *ctx, TJSEvBus *bus, uint64_t id) {
    struct list_head *pos;
    struct list_head *tmp;

    list_for_each_safe(pos, tmp, &bus->listeners) {
        TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
        if (listener->id == id) {
            evbus_listener_remove(ctx, listener);
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
    evbus_value_remove(ctx, entry);
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
        evbus_value_remove(ctx, match);
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
    (void)ctx;
    (void)this_val;
    (void)argc;
    (void)argv;
    (void)magic;

    TJSEvBusSubscription *subscription = opaque;
    if (subscription && subscription->bus && !subscription->bus->disposed) {
        evbus_remove_listener(ctx, subscription->bus, subscription->id);
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

    TJSEvBusListener *listener = tjs__mallocz(sizeof(*listener));
    if (!listener) {
        JS_FreeAtom(ctx, namespace_atom);
        JS_FreeAtom(ctx, event_atom);
        return JS_ThrowOutOfMemory(ctx);
    }
    listener->owner = app;
    listener->namespace_atom = namespace_atom;
    listener->event_atom = event_atom;
    listener->callback = JS_DupValue(ctx, argv[2]);
    listener->id = bus->next_listener_id++;
    listener->active = true;
    list_add_tail(&listener->link, &bus->listeners);

    TJSEvBusSubscription *subscription = tjs__mallocz(sizeof(*subscription));
    if (!subscription) {
        evbus_listener_remove(ctx, listener);
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
        evbus_listener_remove(ctx, listener);
        evbus_listener_release_dispatch(ctx, listener);
        return unsubscribe;
    }
    evbus_listener_release_dispatch(ctx, listener);
    return unsubscribe;
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

    JSValue payload = argc >= 3 ? argv[2] : JS_UNDEFINED;
    JSValue dispatch_result = JS_TRUE;
    bus->dispatch_depth++;
    for (size_t i = 0; i < count; i++) {
        TJSEvBusListener *listener = snapshot[i];
        JSValue result = JS_Call(ctx, listener->callback, JS_UNDEFINED, 1, &payload);
        evbus_listener_release_dispatch(ctx, listener);
        if (JS_IsException(result)) {
            for (size_t j = i + 1; j < count; j++) {
                evbus_listener_release_dispatch(ctx, snapshot[j]);
            }
            dispatch_result = result;
            break;
        }
        JS_FreeValue(ctx, result);
    }

    if (--bus->dispatch_depth == 0 && bus->released_entries_pending) {
        /* A snapshotted callback can create entries after its owner was freed. */
        bus->released_entries_pending = false;
        evbus_cleanup_released_contexts(bus);
    }
    tjs__free(snapshot);
    JS_FreeAtom(ctx, namespace_atom);
    JS_FreeAtom(ctx, event_atom);
    return dispatch_result;
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
    { "on", 3, tjs_evbus_on },
    { "emit", 3, tjs_evbus_emit },
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
}

void tjs__mod_evbus_cleanup_context(App *app) {
    if (!app || !app->trt || !app->trt->evbus || app->trt->evbus->disposed) {
        return;
    }

    TJSEvBus *bus = app->trt->evbus;
    /* The sandbox context may already be gone; values and atoms belong to the runtime. */
    JSContext *ctx = app->trt->main_ctx;
    for (;;) {
        TJSEvBusValue *value_match = NULL;
        TJSEvBusListener *listener_match = NULL;
        struct list_head *pos;
        list_for_each(pos, &bus->values) {
            TJSEvBusValue *entry = list_entry(pos, TJSEvBusValue, link);
            if (entry->owner == app) { value_match = entry; break; }
        }
        if (value_match) {
            evbus_value_remove(ctx, value_match);
            continue;
        }
        list_for_each(pos, &bus->listeners) {
            TJSEvBusListener *listener = list_entry(pos, TJSEvBusListener, link);
            if (listener->owner == app) { listener_match = listener; break; }
        }
        if (listener_match) {
            evbus_listener_remove(ctx, listener_match);
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

    JSContext *ctx = trt->main_ctx;
    while (!list_empty(&bus->values)) {
        TJSEvBusValue *entry = list_entry(bus->values.next, TJSEvBusValue, link);
        evbus_value_remove(ctx, entry);
    }
    while (!list_empty(&bus->listeners)) {
        TJSEvBusListener *listener = list_entry(bus->listeners.next, TJSEvBusListener, link);
        evbus_listener_remove(ctx, listener);
    }

    evbus_release(bus);
}
