/*
 * circu.js debug module 鈥?DebugChannel
 *
 * Copyright (c) 2025 iz
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

#include "private.h"
#include "tjs.h"
#include "utils.h"
#include "mem.h"

#ifndef CJS_DISABLE_DEBUG

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Branch hints for the trace hot path. MSVC has no __builtin_expect, so these
 * degrade to a plain expression there; GCC/Clang use them to keep the common
 * free-running path as the straight-line fall-through and push the break path
 * out of line. */
#if defined(__GNUC__) || defined(__clang__)
#  define DC_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define DC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define DC_LIKELY(x)   (x)
#  define DC_UNLIKELY(x) (x)
#endif

#ifdef _WIN32
#  include <windows.h>
   /* Wrap Win32 semaphore as sem_t-alike */
   typedef HANDLE tjs_sem_t;
   static inline void tjs_sem_init(tjs_sem_t *s)   { *s = CreateSemaphoreW(NULL, 0, 0x7fffffff, NULL); }
   static inline void tjs_sem_destroy(tjs_sem_t *s){ CloseHandle(*s); }
   static inline void tjs_sem_post(tjs_sem_t *s)   { ReleaseSemaphore(*s, 1, NULL); }
   static inline void tjs_sem_wait(tjs_sem_t *s)   { WaitForSingleObject(*s, INFINITE); }
   static inline int  tjs_sem_trywait(tjs_sem_t *s){ return WaitForSingleObject(*s, 0) == WAIT_OBJECT_0 ? 0 : -1; }
   static inline int  tjs_sem_timedwait(tjs_sem_t *s, uint32_t ms) {
       return WaitForSingleObject(*s, ms) == WAIT_OBJECT_0 ? 0 : -1;
   }
#elif defined(__APPLE__)
#  include <dispatch/dispatch.h>
#  include <errno.h>
   typedef dispatch_semaphore_t tjs_sem_t;
   static inline void tjs_sem_init(tjs_sem_t *s)   { *s = dispatch_semaphore_create(0); }
   static inline void tjs_sem_destroy(tjs_sem_t *s){ dispatch_release(*s); }
   static inline void tjs_sem_post(tjs_sem_t *s)   { dispatch_semaphore_signal(*s); }
   static inline void tjs_sem_wait(tjs_sem_t *s)   { dispatch_semaphore_wait(*s, DISPATCH_TIME_FOREVER); }
   static inline int  tjs_sem_trywait(tjs_sem_t *s){
       return dispatch_semaphore_wait(*s, DISPATCH_TIME_NOW) == 0 ? 0 : (errno = EAGAIN, -1);
   }
   static inline int  tjs_sem_timedwait(tjs_sem_t *s, uint32_t ms) {
       dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                                                 (int64_t)ms * (int64_t)1000000);
       return dispatch_semaphore_wait(*s, deadline) == 0 ? 0 : (errno = ETIMEDOUT, -1);
   }
#else
#  include <semaphore.h>
#  include <time.h>
#  include <errno.h>
   typedef sem_t tjs_sem_t;
   static inline void tjs_sem_init(tjs_sem_t *s)   { sem_init(s, 0, 0); }
   static inline void tjs_sem_destroy(tjs_sem_t *s){ sem_destroy(s); }
   static inline void tjs_sem_post(tjs_sem_t *s)   { sem_post(s); }
   static inline void tjs_sem_wait(tjs_sem_t *s)   { while (sem_wait(s) == -1 && errno == EINTR) {} }
   static inline int  tjs_sem_trywait(tjs_sem_t *s){ int r; do { r = sem_trywait(s); } while (r == -1 && errno == EINTR); return r; }
   static inline int  tjs_sem_timedwait(tjs_sem_t *s, uint32_t ms) {
       struct timespec ts;
       clock_gettime(CLOCK_REALTIME, &ts);
       ts.tv_sec  += ms / 1000;
       ts.tv_nsec += (long)(ms % 1000) * 1000000L;
       if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
       int r; do { r = sem_timedwait(s, &ts); } while (r == -1 && errno == EINTR);
       return r;
   }
#endif

/* ---- SPSC ring buffer --------------------------------------------------- */

#define RING_CAP        64    /* must be power-of-2 */
#define MSG_INLINE_MAX  256   /* payload bytes stored inline per slot */

typedef struct {
    uint32_t type;
    uint32_t id;
    uint32_t len;
    union {
        char     payload[MSG_INLINE_MAX];
        uint8_t *heap_ptr;              /* valid when RING_FLAG_HEAP is set */
    };
} RingSlot;

/* Large payloads (> MSG_INLINE_MAX) live in a malloc'd buffer whose pointer is
 * stored in the slot; the high bit of `type` flags this. */
#define RING_FLAG_HEAP  0x80000000u

typedef struct {
    _Atomic uint32_t head;   /* producer writes here */
    _Atomic uint32_t tail;   /* consumer reads here  */
    RingSlot slots[RING_CAP];
} MsgRing;

/* A message copied out of the ring. For inline messages, `data` points at the
 * struct's own inline_buf. For heap messages, `data` points at a malloc'd
 * buffer that the consumer MUST release with ring_msg_free(). Either way the
 * payload has been fully copied out before the slot is released, so it is safe
 * to keep using after ring_pop() returns. */
typedef struct {
    uint32_t type;
    uint32_t id;
    uint32_t len;
    bool     is_heap;
    uint8_t  *data;
    uint8_t  inline_buf[MSG_INLINE_MAX];
} RingMsg;

static inline bool ring_push(MsgRing *r, uint32_t type, uint32_t id,
                             uint8_t *payload, uint32_t len) {
    uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
    if (h - t >= RING_CAP) return false;   /* full */
    RingSlot *s = &r->slots[h & (RING_CAP - 1)];
    s->id  = id;
    s->len = len;
    if (len <= MSG_INLINE_MAX) {
        s->type = type;
        if (len && payload) memcpy(s->payload, payload, len);
    } else {
        uint8_t *buf = tjs__malloc(len);
        if (!buf) return false;
        memcpy(buf, payload, len);
        s->heap_ptr = buf;
        s->type = type | RING_FLAG_HEAP;
    }
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
    return true;
}

/* Pop one message, copying it out of the ring before releasing the slot.
 * Returns false when the ring is empty. */
static inline bool ring_pop(MsgRing *r, RingMsg *out) {
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    if (t == h) return false;
    RingSlot *s = &r->slots[t & (RING_CAP - 1)];
    out->id  = s->id;
    out->len = s->len;
    if (s->type & RING_FLAG_HEAP) {
        out->type    = s->type & ~RING_FLAG_HEAP;
        out->is_heap = true;
        out->data = s->heap_ptr;   /* take ownership */
    } else {
        out->type    = s->type;
        out->is_heap = false;
        uint32_t n = s->len <= MSG_INLINE_MAX ? s->len : MSG_INLINE_MAX;
        if (n) memcpy(out->inline_buf, s->payload, n);    /* COPY before releasing slot */
        out->data = out->inline_buf;
    }
    atomic_store_explicit(&r->tail, t + 1, memory_order_release);
    return true;
}

static inline void ring_msg_free(RingMsg *m) {
    if (m->is_heap && m->data) { free(m->data); m->data = NULL; }
}

/* ---- Message types ------------------------------------------------------- */

/* Control class (搂5a) 鈥?handled in C safepoint, never needs JS */
#define MSG_ADD_BP       1
#define MSG_REMOVE_BP    2
#define MSG_CLEAR_BP     3
#define MSG_SET_EXC_BP   4
#define MSG_SET_STEP     5
#define MSG_SET_BP_ACTIVE 6

/* Inspect class (搂5b) 鈥?carried to_main, handled by JS onBreak loop.
 * A single generic carrier type is used; the real CDP method lives in the
 * payload as `method '\0' params '\0'`. */
#define MSG_INSPECT      10
#define MSG_RESUME       15

/* Events / replies 鈥?from main to worker */
#define MSG_REPLY        20
#define MSG_EV_PAUSED    21
#define MSG_EV_RESUMED   22

#define MSG_REQ_INSPECT  30
#define MSG_REQ_RESUME   31
#define MSG_RES_EVENT    32
#define MSG_RES_REPLY    33

enum {
    TJS_DEBUG_EXCEPTION_NONE     = 0,
    TJS_DEBUG_EXCEPTION_CAUGHT   = 1,
    TJS_DEBUG_EXCEPTION_UNCAUGHT = 2,
    TJS_DEBUG_EXCEPTION_ALL      = 3,
};

/* ---- DebugControlBlock --------------------------------------------------- */

#define DCB_STATE_IDLE    0
#define DCB_STATE_RUNNING 1
#define DCB_STATE_PAUSED  2

typedef struct DebugControlBlock {
    _Atomic uint32_t refcount;     /* main handle + worker handle (2 at alloc) */
    _Atomic int32_t  state;        /* DCB_STATE_* */
    _Atomic uint32_t interrupt;    /* set by worker 鈫?main breaks at next safepoint */
    _Atomic uint32_t pending_step; /* reserved (resume step is driven via JS) */

    MsgRing to_main;    /* worker 鈫?main: control + inspect requests */
    MsgRing to_worker;  /* main  鈫?worker: events + replies */

    tjs_sem_t main_sem;    /* posted when to_main gets a message; main waits on this */
    tjs_sem_t worker_sem;  /* posted when to_worker gets a message; worker timedwaits */
} DebugControlBlock;

static inline int tjs__debug_current_pause_depth(TJSRuntime *trt, JSContext *ctx);

static DebugControlBlock *dcb_alloc(void) {
    DebugControlBlock *cb = tjs__calloc(1, sizeof(DebugControlBlock));
    if (!cb) return NULL;
    atomic_store(&cb->refcount, 2);   /* main handle + worker handle each hold one ref */
    atomic_store(&cb->state,    DCB_STATE_RUNNING);
    atomic_store(&cb->interrupt, 0);
    atomic_store(&cb->pending_step, 0);
    tjs_sem_init(&cb->main_sem);
    tjs_sem_init(&cb->worker_sem);
    return cb;
}

static void dcb_decref(DebugControlBlock *cb) {
    if (!cb) return;
    if (atomic_fetch_sub(&cb->refcount, 1u) == 1u) {
        /* we were the last holder */
        tjs_sem_destroy(&cb->main_sem);
        tjs_sem_destroy(&cb->worker_sem);
        free(cb);
    }
}

/* ---- payload decode helpers --------------------------------------------- */

static const char *payload_str(const uint8_t *p, uint32_t len, uint32_t *off) {
    const char *s = (const char *)p + *off;
    uint32_t i = *off;
    while (i < len && p[i] != '\0') i++;
    *off = (i < len) ? i + 1 : len;
    return s;
}

static uint32_t payload_u32(const uint8_t *p, uint32_t len, uint32_t *off) {
    if (*off + 4 > len) return 0;
    uint32_t v;
    memcpy(&v, p + *off, 4);
    *off += 4;
    return v;
}

#ifdef _WIN32
static void normalize_debug_path_inplace(char *path) {
    if (!path) return;
    for (char *p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
    if (((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) &&
        path[1] == ':' && path[2] == '/') {
        path[0] = (char)(path[0] - 'a' + 'A');
    }
}
#endif

static bool debug_path_eq(JSContext *ctx, JSAtom a, JSAtom b) {
    const char *sa = JS_AtomToCString(ctx, a);
    const char *sb = JS_AtomToCString(ctx, b);
    if (!sa || !sb) {
        if (sa) JS_FreeCString(ctx, sa);
        if (sb) JS_FreeCString(ctx, sb);
        return false;
    }
    bool eq = strcmp(sa, sb) == 0;
#ifdef _WIN32
    if (!eq) {
        char *la = strdup(sa);
        char *lb = strdup(sb);
        if (la && lb) {
            normalize_debug_path_inplace(la);
            normalize_debug_path_inplace(lb);
            eq = strcmp(la, lb) == 0;
        }
        free(la);
        free(lb);
    }
#endif
    JS_FreeCString(ctx, sa);
    JS_FreeCString(ctx, sb);
    return eq;
}

static bool debug_breakpoint_matches(JSContext *ctx, const TJSBreakpoint *bp, JSAtom filename, int line, int col) {
    if (!bp || bp->line != line) return false;
    if (!debug_path_eq(ctx, bp->filename, filename)) return false;
    return bp->col == -1 || bp->col == col;
}

/* ---- structured payload (de)serialization -------------------------------- *
 * CDP params, results and event payloads are plain data (no functions, no
 * bytecode), so they travel as a QuickJS object-serialization blob instead of
 * JSON text: no parsing, no printing, no string interning on the message path.
 * Flags mirror the worker postMessage convention (SAB | REFERENCE); BYTECODE is
 * deliberately omitted 鈥?we never ship code across the debug channel. The blob
 * is allocated on `ctx`'s runtime allocator, so it must be freed with
 * js_free(ctx, .); ring_push copies it into a neutral buffer before it crosses
 * to the other runtime. */
#define DC_WRITE_FLAGS (JS_WRITE_OBJ_SAB | JS_WRITE_OBJ_REFERENCE | JS_WRITE_OBJ_STRIP_SOURCE)
#define DC_READ_FLAGS  (JS_READ_OBJ_SAB | JS_READ_OBJ_REFERENCE)

/* Serialize `v` into a malloc'd blob (free with js_free(ctx, .)); on failure
 * returns NULL with a pending exception. */
static uint8_t *dc_write(JSContext *ctx, JSValueConst v, size_t *len) {
    return JS_WriteObject(ctx, len, v, DC_WRITE_FLAGS);
}

/* Rebuild a JS value from a dc_write() blob. An empty blob maps to undefined;
 * malformed bytes yield a pending exception (caller must propagate). */
static JSValue dc_read(JSContext *ctx, const uint8_t *data, uint32_t len) {
    if (!data || len == 0) return JS_UNDEFINED;
    return JS_ReadObject(ctx, data, len, DC_READ_FLAGS);
}

/* ---- C-level control application ------------------------------ */

/* Apply one control-class message in C. Returns true if it was a control
 * message (fully consumed here); false for inspect/resume messages. */
static bool dcb_apply_control(JSContext *ctx, TJSRuntime *trt, const RingMsg *m) {
    uint32_t off = 0;
    switch (m->type) {
        case MSG_ADD_BP: {
            const char *file = payload_str(m->data, m->len, &off);
            uint32_t line = payload_u32(m->data, m->len, &off);
            uint32_t col  = payload_u32(m->data, m->len, &off);
            JSAtom atom = JS_NewAtom(ctx, file);
            TJSBreakpoint key = { .filename = atom, .line = (int)line };
            TJSBreakpoint *found = NULL;
            HASH_FIND(hh, trt->debug.breakpoints, &key, sizeof(JSAtom)+sizeof(int), found);
            if (found) {
                found->col = (int)(int32_t)col;
            } else {
                TJSBreakpoint *bp = js_malloc(ctx, sizeof(TJSBreakpoint));
                if (bp) {
                    bp->filename = atom;
                    bp->line = (int)line;
                    bp->col  = (int)(int32_t)col;
                    HASH_ADD(hh, trt->debug.breakpoints, filename,
                             sizeof(JSAtom)+sizeof(int), bp);
                    atom = JS_ATOM_NULL;   /* ownership moved into table */
                }
            }
            if (atom != JS_ATOM_NULL) JS_FreeAtom(ctx, atom);
            return true;
        }
        case MSG_REMOVE_BP: {
            const char *file = payload_str(m->data, m->len, &off);
            uint32_t line = payload_u32(m->data, m->len, &off);
            JSAtom atom = JS_NewAtom(ctx, file);
            TJSBreakpoint key = { .filename = atom, .line = (int)line };
            TJSBreakpoint *found = NULL;
            HASH_FIND(hh, trt->debug.breakpoints, &key, sizeof(JSAtom)+sizeof(int), found);
            if (found) {
                HASH_DEL(trt->debug.breakpoints, found);
                JS_FreeAtom(ctx, found->filename);
                js_free(ctx, found);
            }
            JS_FreeAtom(ctx, atom);
            return true;
        }
        case MSG_CLEAR_BP: {
            TJSBreakpoint *bp, *tmp;
            HASH_ITER(hh, trt->debug.breakpoints, bp, tmp) {
                HASH_DEL(trt->debug.breakpoints, bp);
                JS_FreeAtom(ctx, bp->filename);
                js_free(ctx, bp);
            }
            return true;
        }
        case MSG_SET_EXC_BP:
            trt->debug.exception_break_mode = (int)payload_u32(m->data, m->len, &off);
            if (trt->debug.exception_break_mode < TJS_DEBUG_EXCEPTION_NONE ||
                trt->debug.exception_break_mode > TJS_DEBUG_EXCEPTION_ALL)
                trt->debug.exception_break_mode = TJS_DEBUG_EXCEPTION_NONE;
            return true;
        case MSG_SET_STEP:
            trt->debug.step_mode  = (int)payload_u32(m->data, m->len, &off);
            trt->debug.step_depth = tjs__debug_current_pause_depth(trt, ctx);
            return true;
        case MSG_SET_BP_ACTIVE:
            trt->debug.breakpoints_active = (payload_u32(m->data, m->len, &off) != 0);
            return true;
        default:
            return false;   /* inspect / resume 鈥?not handled here */
    }
}

/* Drain all pending control-class messages while the program is RUNNING
 * (called from the trace hook). Inspect/resume messages must not arrive while
 * running; if one does it is dropped. Keeps main_sem balanced with to_main. */
static void dcb_drain_control(JSContext *ctx, DebugControlBlock *cb) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    RingMsg m;
    while (ring_pop(&cb->to_main, &m)) {
        tjs_sem_trywait(&cb->main_sem);    /* consume the matching post */
        dcb_apply_control(ctx, trt, &m);   /* control applied; inspect/resume dropped */
        ring_msg_free(&m);
    }
}

/* ---- Trace / throw hooks -------------------------------------------------- */

enum {
    TJS_DEBUG_BREAKPOINT = 0,
    TJS_DEBUG_EXCEPTION  = 1,
    TJS_DEBUG_DEBUGGER   = 2,
    TJS_DEBUG_STEP       = 3,
    TJS_DEBUG_INTERRUPT  = 4,
};

/* Guard against re-entering the break logic while already paused. Debugger-
 * driven evaluation (evalInFrame / engine.eval) runs JS with the trace hook
 * still installed; it must never recursively invoke onBreak. */
static thread_local bool tjs__in_debug_break = false;

static inline int tjs__debug_current_pause_depth(TJSRuntime *trt, JSContext *ctx) {
    if (trt->debug.pause_depth > 0) return trt->debug.pause_depth;
    return JS_GetStackDepth(ctx);
}

static int tjs__debug_exception_mode_from_arg(JSContext *ctx, JSValueConst val, uint32_t *out) {
    uint32_t mode = TJS_DEBUG_EXCEPTION_NONE;
    if (JS_IsBool(val)) {
        mode = JS_ToBool(ctx, val) ? TJS_DEBUG_EXCEPTION_ALL : TJS_DEBUG_EXCEPTION_NONE;
    } else if (JS_ToUint32(ctx, &mode, val)) {
        return -1;
    }
    if (mode > TJS_DEBUG_EXCEPTION_ALL)
        return JS_ThrowRangeError(ctx, "invalid exception breakpoint mode"), -1;
    *out = mode;
    return 0;
}

static int tjs__debug_trace_cb(JSContext *ctx, JSAtom filename, JSAtom funcname,
                                int line, int col, int flags, void *opaque) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    if (!trt->debug.active) return 0;
    if (tjs__in_debug_break) return 0;

    uint32_t step_mode_at_entry = trt->debug.step_mode;

    DebugControlBlock *cb = trt->debug.channel;
    bool interrupted = false;

    /* Hot-path gate. This callback fires on *every* traced line, so it does the
     * absolute minimum. All three loads below are relaxed (plain MOVs, no
     * barrier): `tail` is written only by us (the consumer); `head` and
     * `interrupt` are written by the worker, and observing either one line late
     * is harmless for a debugger. We only touch the ring or perform the costly
     * lock-prefixed atomic_exchange when something is actually pending 鈥?the
     * previous code ran an unconditional drain + atomic_exchange every line. */
    if (cb) {
        uint32_t h = atomic_load_explicit(&cb->to_main.head, memory_order_relaxed);
        uint32_t t = atomic_load_explicit(&cb->to_main.tail, memory_order_relaxed);
        if (DC_UNLIKELY(h != t)) dcb_drain_control(ctx, cb);
        if (DC_UNLIKELY(atomic_load_explicit(&cb->interrupt, memory_order_relaxed) &&
                        atomic_exchange(&cb->interrupt, 0u))) {
            interrupted = true;
            goto do_break;
        }
    }

    bool should_break = (flags & JS_DEBUG_TRACE_DEBUGGER_STMT) && trt->debug.breakpoints_active;

    /* Free-running fast path: no debugger statement, not stepping, and no
     * breakpoints installed 鈫?bail before hashing or any further work. */
    if (DC_LIKELY(!should_break && trt->debug.step_mode == 0 && (trt->debug.breakpoints == NULL || !trt->debug.breakpoints_active)))
        return 0;

    if (!should_break && trt->debug.step_mode != 0) {
        int depth = JS_GetStackDepth(ctx);
        switch (trt->debug.step_mode) {
            case 1:
                trt->debug.step_mode = 0;
                should_break = true;
                break;
            case 2:
                if (depth <= trt->debug.step_depth) {
                    trt->debug.step_mode = 0;
                    should_break = true;
                } else return 0;
                break;
            case 3:
                if (depth < trt->debug.step_depth) {
                    trt->debug.step_mode = 0;
                    should_break = true;
                } else return 0;
                break;
        }
    }

    if (!should_break && trt->debug.breakpoints != NULL && trt->debug.breakpoints_active) {
        TJSBreakpoint *found = NULL;
        for (TJSBreakpoint *bp = trt->debug.breakpoints; bp != NULL; bp = bp->hh.next) {
            if (debug_breakpoint_matches(ctx, bp, filename, line, col)) {
                found = bp;
                break;
            }
        }
        should_break = found != NULL;
    }

    if (DC_LIKELY(!should_break)) return 0;

do_break:;
    trt->debug.pause_depth = JS_GetStackDepth(ctx);
    int reason;
    if (interrupted)
        reason = TJS_DEBUG_INTERRUPT;
    else if (trt->debug.step_mode == 0 && step_mode_at_entry != 0)
        reason = TJS_DEBUG_STEP;
    else
        reason = (flags & JS_DEBUG_TRACE_DEBUGGER_STMT)
                 ? TJS_DEBUG_DEBUGGER : TJS_DEBUG_BREAKPOINT;

    JSValue argv[6] = {
        JS_NewInt32(ctx, reason),
        JS_AtomToString(ctx, filename),
        JS_AtomToString(ctx, funcname),
        JS_NewInt32(ctx, line),
        JS_NewInt32(ctx, col),
        JS_UNDEFINED,
    };
    bool prev_in_break = tjs__in_debug_break;
    tjs__in_debug_break = true;
    JSValue ret = JS_Call(ctx, trt->debug.onBreak, JS_UNDEFINED, 6, argv);
    tjs__in_debug_break = prev_in_break;
    for (int i = 0; i < 6; i++) JS_FreeValue(ctx, argv[i]);

    int result = 0;
    if (JS_IsException(ret)) {
        result = -1;
#ifdef DEBUG
        TJS_DumpException(ctx);
#endif
    } else if (JS_IsNumber(ret)) {
        JS_ToInt32(ctx, &result, ret);
    }

    JS_FreeValue(ctx, ret);
    return result;
}

static int tjs__debug_throw_cb(JSContext *ctx, JSValueConst exception, int throw_state, void *opaque) {
    (void)opaque;
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    int mode = trt->debug.exception_break_mode;
    if (!trt->debug.active || mode == TJS_DEBUG_EXCEPTION_NONE) return 0;
    if (tjs__in_debug_break) return 0;

    bool should_break = false;
    switch (mode) {
        case TJS_DEBUG_EXCEPTION_ALL:
            should_break = (throw_state == JS_DEBUG_THROW_AT_THROW);
            break;
        case TJS_DEBUG_EXCEPTION_CAUGHT:
            should_break = (throw_state == JS_DEBUG_THROW_CAUGHT_IN_FRAME);
            break;
        case TJS_DEBUG_EXCEPTION_UNCAUGHT:
            should_break = (throw_state == JS_DEBUG_THROW_UNCAUGHT_IN_FRAME);
            break;
    }
    if (!should_break) return 0;

    JSValue saved_exception = JS_UNINITIALIZED;
    if (JS_HasException(ctx))
        saved_exception = JS_GetException(ctx);

    JSValue filename = JS_UNDEFINED;
    JSValue funcname = JS_UNDEFINED;
    int line = 0;
    int col = 0;
    JSFrameInfo frame = JS_GetStackFrame(ctx, 0);
    if (frame.line_num != -1) {
        line = frame.line_num;
        col = frame.col_num;
        if (frame.func_path != JS_ATOM_NULL) {
            filename = JS_AtomToString(ctx, frame.func_path);
            if (JS_IsException(filename)) {
                JS_FreeValue(ctx, JS_GetException(ctx));
                filename = JS_UNDEFINED;
            }
        }
        JS_FreeValue(ctx, frame.func);
    } else {
        JS_FreeValue(ctx, frame.func);
    }

    JSValue argv[6] = {
        JS_NewInt32(ctx, TJS_DEBUG_EXCEPTION),
        filename,
        funcname,
        JS_NewInt32(ctx, line),
        JS_NewInt32(ctx, col),
        JS_DupValue(ctx, exception),
    };
    bool prev_in_break = tjs__in_debug_break;
    tjs__in_debug_break = true;
    JSValue ret = JS_Call(ctx, trt->debug.onBreak, JS_UNDEFINED, 6, argv);
    if (JS_IsException(ret)) {
        JSValue cb_exception = JS_GetException(ctx);
        JS_FreeValue(ctx, cb_exception);
    }
    for (int i = 0; i < 6; i++) JS_FreeValue(ctx, argv[i]);
    JS_FreeValue(ctx, ret);
    if (!JS_IsUninitialized(saved_exception))
        JS_Throw(ctx, saved_exception);
    tjs__in_debug_break = prev_in_break;
    return 0;
}

/* ---- JS bindings: existing debug primitives ------------------------------ */

static JSValue tjs_debug_start(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0 || !JS_IsFunction(ctx, argv[0]))
        return JS_ThrowTypeError(ctx, "startDebug requires a callback function");
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    JS_FreeValue(ctx, trt->debug.onBreak);
    trt->debug.onBreak = JS_DupValue(ctx, argv[0]);
    trt->debug.active  = true;
    JS_SetDebugTraceHandler(ctx, tjs__debug_trace_cb, NULL);
    JS_SetDebugThrowHook(ctx, tjs__debug_throw_cb, NULL);
    return JS_UNDEFINED;
}

static JSValue tjs_debug_stop(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    JS_SetDebugTraceHandler(ctx, NULL, NULL);
    JS_SetDebugThrowHook(ctx, NULL, NULL);
    JS_FreeValue(ctx, trt->debug.onBreak);
    trt->debug.onBreak = JS_UNDEFINED;
    JS_FreeValue(ctx, trt->debug.onException);
    trt->debug.onException = JS_UNDEFINED;
    trt->debug.active = false;
    trt->debug.exception_break_mode = TJS_DEBUG_EXCEPTION_NONE;
    trt->debug.step_mode = 0;
    trt->debug.step_depth = 0;
    trt->debug.pause_depth = 0;
    TJSBreakpoint *bp, *tmp;
    HASH_ITER(hh, trt->debug.breakpoints, bp, tmp) {
        HASH_DEL(trt->debug.breakpoints, bp);
        JS_FreeAtom(ctx, bp->filename);
        js_free(ctx, bp);
    }
    /* The channel is owned by its DebugChannel/Worker handles; this is only
     * a weak pointer used by the trace hook, so just detach it (no decref). */
    trt->debug.channel = NULL;
    return JS_UNDEFINED;
}

static JSValue tjs_debug_add_breakpoint(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "addBreakpoint requires (filename: string, line: number)");
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    const char *filename = JS_ToCString(ctx, argv[0]);
    if (!filename) return JS_EXCEPTION;
    JSAtom filename_atom = JS_NewAtom(ctx, filename);
    JS_FreeCString(ctx, filename);
    int32_t line;
    if (JS_ToInt32(ctx, &line, argv[1])) { JS_FreeAtom(ctx, filename_atom); return JS_EXCEPTION; }
    int32_t col = -1;
    if (argc >= 3 && JS_IsNumber(argv[2]))
        if (JS_ToInt32(ctx, &col, argv[2])) { JS_FreeAtom(ctx, filename_atom); return JS_EXCEPTION; }
    TJSBreakpoint key = { .filename = filename_atom, .line = line };
    TJSBreakpoint *existing = NULL;
    HASH_FIND(hh, trt->debug.breakpoints, &key, sizeof(JSAtom)+sizeof(int), existing);
#ifdef _WIN32
    if (!existing) {
        const char *tmp = JS_AtomToCString(ctx, filename_atom);
        if (tmp) {
            char *normalized = strdup(tmp);
            if (normalized) {
                normalize_debug_path_inplace(normalized);
                JSAtom norm_atom = JS_NewAtom(ctx, normalized);
                if (norm_atom != JS_ATOM_NULL) {
                    TJSBreakpoint norm_key = { .filename = norm_atom, .line = line };
                    HASH_FIND(hh, trt->debug.breakpoints, &norm_key, sizeof(JSAtom)+sizeof(int), existing);
                    JS_FreeAtom(ctx, norm_atom);
                }
                free(normalized);
            }
            JS_FreeCString(ctx, tmp);
        }
    }
#endif
    if (existing) { existing->col = col; JS_FreeAtom(ctx, filename_atom); return JS_UNDEFINED; }
    TJSBreakpoint *bp = js_malloc(ctx, sizeof(TJSBreakpoint));
    if (!bp) { JS_FreeAtom(ctx, filename_atom); return JS_EXCEPTION; }
    bp->filename = filename_atom; bp->line = line; bp->col = col;
    HASH_ADD(hh, trt->debug.breakpoints, filename, sizeof(JSAtom)+sizeof(int), bp);
    return JS_UNDEFINED;
}

static JSValue tjs_debug_remove_breakpoint(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "removeBreakpoint requires (filename: string, line: number)");
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    const char *filename = JS_ToCString(ctx, argv[0]);
    if (!filename) return JS_EXCEPTION;
    JSAtom filename_atom = JS_NewAtom(ctx, filename);
    JS_FreeCString(ctx, filename);
    int32_t line;
    if (JS_ToInt32(ctx, &line, argv[1])) { JS_FreeAtom(ctx, filename_atom); return JS_EXCEPTION; }
    TJSBreakpoint key = { .filename = filename_atom, .line = line };
    TJSBreakpoint *found = NULL;
    HASH_FIND(hh, trt->debug.breakpoints, &key, sizeof(JSAtom)+sizeof(int), found);
    JS_FreeAtom(ctx, filename_atom);
    if (found) { HASH_DEL(trt->debug.breakpoints, found); JS_FreeAtom(ctx, found->filename); js_free(ctx, found); }
    return JS_UNDEFINED;
}

static JSValue tjs_debug_clear_breakpoints(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    TJSBreakpoint *bp, *tmp;
    HASH_ITER(hh, trt->debug.breakpoints, bp, tmp) {
        HASH_DEL(trt->debug.breakpoints, bp);
        JS_FreeAtom(ctx, bp->filename);
        js_free(ctx, bp);
    }
    return JS_UNDEFINED;
}

static JSValue tjs_debug_get_stack_depth(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    return JS_NewInt32(ctx, JS_GetStackDepth(ctx));
}

static JSValue tjs_debug_get_frame_info(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    int level;
    if (argc == 0 || -1 == JS_ToInt32(ctx, &level, argv[0]))
        return JS_ThrowTypeError(ctx, "getFrameInfo requires (level: number)");
    JSFrameInfo frame = JS_GetStackFrame(ctx, level);
    if (frame.line_num == -1) {
        JS_FreeValue(ctx, frame.func);
        return JS_ThrowTypeError(ctx, "stack frame at level %i is not a JS function", level);
    }
    JSValue info = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, info, "line",   JS_NewInt32(ctx, frame.line_num));
    JS_SetPropertyStr(ctx, info, "column", JS_NewInt32(ctx, frame.col_num));
    JS_SetPropertyStr(ctx, info, "func",   frame.func);
    JS_SetPropertyStr(ctx, info, "file",   JS_AtomToString(ctx, frame.func_path));
    return info;
}

static JSValue tjs_debug_get_local_variables(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "getLocalVariables requires (level: number)");
    int32_t level;
    if (JS_ToInt32(ctx, &level, argv[0])) return JS_EXCEPTION;
    JSDebugLocalVar *vars = NULL;
    int count = 0;
    int rc = JS_GetLocalVariablesAtLevel(ctx, level, &vars, &count);
    if (rc != 0) return JS_EXCEPTION;
    JSValue arr = JS_NewArray(ctx);
    for (int i = 0; i < count; i++) {
        JSValue obj = JS_NewObject(ctx);
        JS_DefinePropertyValue(ctx, obj, JS_ATOM_name,    JS_NewString(ctx, vars[i].name), JS_PROP_C_W_E);
        JS_DefinePropertyValue(ctx, obj, JS_ATOM_value,   JS_DupValue(ctx, vars[i].value), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "isArg",           JS_NewBool(ctx, vars[i].is_arg),          JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "isClosure",       JS_NewBool(ctx, vars[i].is_closure),      JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "isUninitialized", JS_NewBool(ctx, vars[i].is_uninitialized), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, obj, "scopeLevel", JS_NewInt32(ctx, vars[i].scope_level), JS_PROP_C_W_E);
        JS_SetPropertyUint32(ctx, arr, i, obj);
    }
    if (vars) JS_FreeLocalVariables(ctx, vars, count);
    return arr;
}

static JSValue tjs_debug_set_variable(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 3) return JS_ThrowTypeError(ctx, "setVariable requires (level, name, value[, scopeNumber])");
    int32_t level;
    if (JS_ToInt32(ctx, &level, argv[0])) return JS_EXCEPTION;
    if (!JS_IsString(argv[1])) return JS_ThrowTypeError(ctx, "name must be a string");
    const char *name = JS_ToCString(ctx, argv[1]);
    if (!name) return JS_EXCEPTION;
    int32_t scopeNumber = -1;
    if (argc >= 4) {
        if (JS_ToInt32(ctx, &scopeNumber, argv[3])) {
            JS_FreeCString(ctx, name);
            return JS_EXCEPTION;
        }
    }
    if (scopeNumber == 2) {
        /* CDP global scope — set property on the global object. */
        int ret = JS_SetPropertyStr(ctx, JS_GetGlobalObject(ctx), name, JS_DupValue(ctx, argv[2]));
        JS_FreeCString(ctx, name);
        if (ret < 0) return JS_EXCEPTION;
        return JS_UNDEFINED;
    }
    int ret = JS_SetVariableAtLevel(ctx, level, name, JS_DupValue(ctx, argv[2]), scopeNumber);
    JS_FreeCString(ctx, name);
    if (ret < 0) {
        if (ret == -1) return JS_ThrowTypeError(ctx, "variable not found");
        if (ret == -2) return JS_ThrowTypeError(ctx, "cannot set const binding");
        return JS_EXCEPTION;
    }
    return JS_UNDEFINED;
}

static JSValue tjs_debug_eval_in_frame(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "evalInFrame requires (level, expr)");
    int32_t level;
    if (JS_ToInt32(ctx, &level, argv[0])) return JS_EXCEPTION;
    size_t len;
    const char *expr = JS_ToCStringLen(ctx, &len, argv[1]);
    if (!expr) return JS_EXCEPTION;
    JSValue ret = JS_EvalInStackFrame(ctx, level, expr, len, "<eval>");
    JS_FreeCString(ctx, expr);
    return ret;
}

static JSValue tjs_debug_set_exception_breakpoint(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "setExceptionBreakpoint requires (mode: number | boolean)");
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    uint32_t mode = TJS_DEBUG_EXCEPTION_NONE;
    if (tjs__debug_exception_mode_from_arg(ctx, argv[0], &mode))
        return JS_EXCEPTION;
    trt->debug.exception_break_mode = (int)mode;
    return JS_UNDEFINED;
}

static JSValue tjs_debug_set_step_mode(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "step requires (mode: number)");
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    int32_t mode;
    if (JS_ToInt32(ctx, &mode, argv[0])) return JS_EXCEPTION;
    trt->debug.step_mode  = (int)mode;
    trt->debug.step_depth = tjs__debug_current_pause_depth(trt, ctx);
    return JS_UNDEFINED;
}

/* ---- DebugChannel JS object (main-thread handle) ------------------------- */

static thread_local JSClassID tjs_dc_main_class_id;

#ifdef _WIN32
static HANDLE tjs_dc_active_stop_event = NULL;

static BOOL WINAPI tjs_dc_ctrl_handler(DWORD type) {
    (void)type;
    if (tjs_dc_active_stop_event)
        SetEvent(tjs_dc_active_stop_event);
    return true;  /* handled -- don't let Windows terminate us */
}
#endif

typedef struct {
    DebugControlBlock *cb;
#ifdef _WIN32
    HANDLE stop_event;   /* manual-reset; SetEvent from dc.stop() wakes waitRequest */
#endif
} TJSDCMain;

static void tjs_dc_main_finalizer(JSRuntime *rt, JSValue val) {
    TJSDCMain *h = JS_GetOpaque(val, tjs_dc_main_class_id);
    if (h) {
#ifdef _WIN32
        if (h->stop_event) CloseHandle(h->stop_event);
#endif
        /* Note: relies on debug.stop()/dc.stop() having already cleared the
         * weak trt->debug.channel pointer before the handle is collected. */
        dcb_decref(h->cb);
        js_free_rt(rt, h);
    }
}

static JSClassDef tjs_dc_main_class = { "DebugChannel", .finalizer = tjs_dc_main_finalizer };

/* dc.notify(evType, payload) 鈥?main 鈫?worker; payload serialized with JS_WriteObject (true if enqueued) */
static JSValue tjs_dc_main_notify(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCMain *h = JS_GetOpaque(this_val, tjs_dc_main_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    int32_t ev_type;
    if (JS_ToInt32(ctx, &ev_type, argv[0])) return JS_EXCEPTION;
    size_t len;
    uint8_t *buf = dc_write(ctx, argv[1], &len);
    if (!buf) return JS_EXCEPTION;
    bool ok = ring_push(&h->cb->to_worker, (uint32_t)ev_type, 0, buf, (uint32_t)len);
    js_free(ctx, buf);
    if (ok) tjs_sem_post(&h->cb->worker_sem);
    return JS_NewBool(ctx, ok);
}

/* dc.waitRequest() 鈥?blocks on main_sem; applies control msgs inline and only
 * returns inspect / resume requests to JS. Shapes:
 *   { kind: 'inspect', id, method, params }
 *   { kind: 'resume',  step }                                                */
static JSValue tjs_dc_main_wait_request(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCMain *h = JS_GetOpaque(this_val, tjs_dc_main_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    DebugControlBlock *cb = h->cb;
    for (;;) {
        RingMsg m;
        if (ring_pop(&cb->to_main, &m)) {
            tjs_sem_trywait(&cb->main_sem);          /* keep sem ~ queue length */
            if (dcb_apply_control(ctx, trt, &m)) {   /* breakpoint/step set while paused */
                ring_msg_free(&m);
                continue;
            }
            JSValue obj;
            if (m.type == MSG_RESUME) {
                uint32_t off = 0;
                uint32_t step = payload_u32(m.data, m.len, &off);
                obj = JS_NewObject(ctx);
                JS_SetPropertyStr(ctx, obj, "kind", JS_NewInt32(ctx, MSG_REQ_RESUME));
                JS_SetPropertyStr(ctx, obj, "step", JS_NewUint32(ctx, step));
            } else {
                /* inspect carrier: method '\0' + JS_WriteObject(params) bytes. The
                 * params half is binary (may contain NULs), so it is delimited by
                 * offset, not by a terminator. */
                const char *method = (const char *)m.data;
                uint32_t poff = 0;
                while (poff < m.len && m.data[poff] != '\0') poff++;
                if (poff < m.len) poff++;   /* skip the method's NUL terminator */
                JSValue params = dc_read(ctx, m.data + poff, m.len - poff);
                if (JS_IsException(params)) { ring_msg_free(&m); return params; }
                obj = JS_NewObject(ctx);
                JS_SetPropertyStr(ctx, obj, "kind",   JS_NewInt32(ctx, MSG_REQ_INSPECT));
                JS_SetPropertyStr(ctx, obj, "id",     JS_NewUint32(ctx, m.id));
                JS_SetPropertyStr(ctx, obj, "method", JS_NewString(ctx, method));
                JS_SetPropertyStr(ctx, obj, "params", params);
            }
            ring_msg_free(&m);
            return obj;
        }
        /* Block until a message arrives or stop() signals stop_event.
         * On Windows, WaitForMultipleObjects lets us wait on both the
         * semaphore (message arrived) and stop_event (dc.stop()) at once,
         * so dc.stop() wakes this thread immediately without needing uv. */
#ifdef _WIN32
        /* Register Ctrl+C handler: libuv signals need the event loop to dispatch,
         * but we're blocked here 鈥?go direct via SetConsoleCtrlHandler. */
        tjs_dc_active_stop_event = h->stop_event;
        SetConsoleCtrlHandler(tjs_dc_ctrl_handler, true);

        HANDLE wait_hdls[2] = { cb->main_sem, h->stop_event };
        DWORD wr = WaitForMultipleObjects(2, wait_hdls, false, INFINITE);

        SetConsoleCtrlHandler(tjs_dc_ctrl_handler, false);
        tjs_dc_active_stop_event = NULL;

        if (wr == WAIT_OBJECT_0 + 1 || !h->cb)
            return JS_ThrowInternalError(ctx, "EAGAIN: debug channel stopped");
        if (wr == WAIT_OBJECT_0)
            tjs_sem_trywait(&cb->main_sem);  /* keep sem count in sync */
#else
        tjs_sem_wait(&cb->main_sem);
        if (!h->cb)
            return JS_ThrowInternalError(ctx, "EAGAIN: debug channel stopped");
#endif
    }
}

/* dc.reply(id, result) 鈥?main 鈫?worker; result serialized with JS_WriteObject */
static JSValue tjs_dc_main_reply(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCMain *h = JS_GetOpaque(this_val, tjs_dc_main_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    int32_t id;
    if (JS_ToInt32(ctx, &id, argv[0])) return JS_EXCEPTION;
    size_t len;
    uint8_t *buf = dc_write(ctx, argv[1], &len);
    if (!buf) return JS_EXCEPTION;
    bool ok = ring_push(&h->cb->to_worker, MSG_REPLY, (uint32_t)id, buf, (uint32_t)len);
    js_free(ctx, buf);
    if (ok) tjs_sem_post(&h->cb->worker_sem);
    return JS_NewBool(ctx, ok);
}

/* dc.stop() 鈥?detach weak pointer (if ours), wake blocked waitRequest, release refcount */
static JSValue tjs_dc_main_stop(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCMain *h = JS_GetOpaque(this_val, tjs_dc_main_class_id);
    if (!h || !h->cb) return JS_UNDEFINED;
    DebugControlBlock *cb = h->cb;
    TJSRuntime *trt = TJS_GetRuntime(ctx);
    if (trt->debug.channel == cb) trt->debug.channel = NULL;
    h->cb = NULL;                     /* signal waitRequest to exit */
#ifdef _WIN32
    SetEvent(h->stop_event);          /* wake WaitForMultipleObjects in waitRequest */
#else
    tjs_sem_post(&cb->main_sem);      /* wake sem_wait in waitRequest */
#endif
    dcb_decref(cb);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_dc_main_proto_funcs[] = {
    TJS_CFUNC_DEF("notify",      2, tjs_dc_main_notify),
    TJS_CFUNC_DEF("waitRequest", 0, tjs_dc_main_wait_request),
    TJS_CFUNC_DEF("reply",       2, tjs_dc_main_reply),
    TJS_CFUNC_DEF("stop",        0, tjs_dc_main_stop),
};

/* ---- createDebugChannel() ------------------------------------------------ */
// Note: We should never bind the memory in ctx, which should be transferred and not stay in current ctx.
static JSValue tjs_debug_create_channel(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSRuntime *trt = TJS_GetRuntime(ctx);

    /* Old channel (if any) stays owned by its existing handles; just drop the
     * weak pointer so the trace hook starts using the new one. */
    trt->debug.channel = NULL;

    DebugControlBlock *cb = dcb_alloc();
    if (!cb) return JS_ThrowOutOfMemory(ctx);

    /* Build main-thread handle object (owns one of the two baked-in refs). */
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_dc_main_proto_funcs, countof(tjs_dc_main_proto_funcs));

    TJSDCMain *h = tjs__malloc(sizeof(TJSDCMain));
    if (!h) {
        dcb_decref(cb); dcb_decref(cb);
        JS_FreeValue(ctx, proto);
        return JS_ThrowOutOfMemory(ctx);
    }
    h->cb = cb;
#ifdef _WIN32
    h->stop_event = CreateEventW(NULL, true /* manual-reset */, false /* initial */, NULL);
#endif

    JSValue handle_obj = JS_NewObjectClass(ctx, tjs_dc_main_class_id);
    if (JS_IsException(handle_obj)) { 
        tjs__free(h); dcb_decref(cb); dcb_decref(cb);
        JS_FreeValue(ctx, proto);
        return handle_obj;
    }

    JS_SetOpaque(handle_obj, h);
    JS_SetPrototype(ctx, handle_obj, proto);
    JS_FreeValue(ctx, proto);

    /* Publish the weak pointer used by the trace hook. */
    trt->debug.channel = cb;

    /* Pass the control block by POINTER VALUE (8 bytes) 鈥?never by embedding the struct.  */
    void *cbptr = cb;
    JSValue ab = JS_NewArrayBufferCopy(ctx, (const uint8_t *)&cbptr, sizeof cbptr);
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "handle", ab);
    JS_SetPropertyStr(ctx, result, "dc",     handle_obj);
    return result;
}

/* ---- DebugChannel JS object (worker-thread handle) ----------------------- */

static thread_local JSClassID tjs_dc_worker_class_id;

typedef struct {
    DebugControlBlock *cb;
} TJSDCWorker;

static void tjs_dc_worker_finalizer(JSRuntime *rt, JSValue val) {
    TJSDCWorker *h = JS_GetOpaque(val, tjs_dc_worker_class_id);
    if (h) {
        dcb_decref(h->cb);
        js_free_rt(rt, h);
    }
}

static JSClassDef tjs_dc_worker_class = { "DebugChannelWorker", .finalizer = tjs_dc_worker_finalizer };

static bool dc_push_control(DebugControlBlock *cb, uint32_t type, uint32_t id,
                             const uint8_t *payload, uint32_t len) {
    bool ok = ring_push(&cb->to_main, type, id, (uint8_t *)payload, len);
    if (ok) tjs_sem_post(&cb->main_sem);
    return ok;
}

static JSValue tjs_dc_worker_interrupt(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    atomic_store(&h->cb->interrupt, 1u);
    return JS_UNDEFINED;
}

static JSValue tjs_dc_worker_state(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    return JS_NewInt32(ctx, (int)atomic_load(&h->cb->state));
}

static JSValue tjs_dc_worker_add_breakpoint(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb || argc < 2) return JS_EXCEPTION;
    const char *file = JS_ToCString(ctx, argv[0]);
    if (!file) return JS_EXCEPTION;
    uint32_t line = 0, col = (uint32_t)-1;
    JS_ToUint32(ctx, &line, argv[1]);
    if (argc >= 3 && JS_IsNumber(argv[2])) JS_ToUint32(ctx, &col, argv[2]);
    size_t flen = strlen(file) + 1;
    uint32_t plen = (uint32_t)(flen + 8);
    uint8_t *buf = malloc(plen);
    if (!buf) { JS_FreeCString(ctx, file); return JS_ThrowOutOfMemory(ctx); }
    memcpy(buf, file, flen);
    memcpy(buf + flen, &line, 4);
    memcpy(buf + flen + 4, &col, 4);
    JS_FreeCString(ctx, file);
    dc_push_control(h->cb, MSG_ADD_BP, 0, buf, plen);
    free(buf);
    return JS_UNDEFINED;
}

static JSValue tjs_dc_worker_remove_breakpoint(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb || argc < 2) return JS_EXCEPTION;
    const char *file = JS_ToCString(ctx, argv[0]);
    if (!file) return JS_EXCEPTION;
    uint32_t line = 0;
    JS_ToUint32(ctx, &line, argv[1]);
    size_t flen = strlen(file) + 1;
    uint32_t plen = (uint32_t)(flen + 4);
    uint8_t *buf = malloc(plen);
    if (!buf) { JS_FreeCString(ctx, file); return JS_ThrowOutOfMemory(ctx); }
    memcpy(buf, file, flen);
    memcpy(buf + flen, &line, 4);
    JS_FreeCString(ctx, file);
    dc_push_control(h->cb, MSG_REMOVE_BP, 0, buf, plen);
    free(buf);
    return JS_UNDEFINED;
}

static JSValue tjs_dc_worker_clear_breakpoints(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    dc_push_control(h->cb, MSG_CLEAR_BP, 0, NULL, 0);
    return JS_UNDEFINED;
}

static JSValue tjs_dc_worker_set_exception_bp(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb || argc == 0) return JS_EXCEPTION;
    uint32_t mode = TJS_DEBUG_EXCEPTION_NONE;
    if (tjs__debug_exception_mode_from_arg(ctx, argv[0], &mode))
        return JS_EXCEPTION;
    dc_push_control(h->cb, MSG_SET_EXC_BP, 0, (const uint8_t *)&mode, 4);
    return JS_UNDEFINED;
}

static JSValue tjs_dc_worker_set_step(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb || argc == 0) return JS_EXCEPTION;
    uint32_t mode = 0;
    JS_ToUint32(ctx, &mode, argv[0]);
    dc_push_control(h->cb, MSG_SET_STEP, 0, (const uint8_t *)&mode, 4);
    return JS_UNDEFINED;
}

static JSValue tjs_dc_worker_set_breakpoints_active(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb || argc == 0) return JS_EXCEPTION;
    uint32_t active = JS_ToBool(ctx, argv[0]) ? 1 : 0;
    dc_push_control(h->cb, MSG_SET_BP_ACTIVE, 0, (const uint8_t *)&active, 4);
    return JS_UNDEFINED;
}

/* dc.send(id, method, params) 鈥?inspect request: worker 鈫?main; params serialized with JS_WriteObject */
static JSValue tjs_dc_worker_send(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb || argc < 3) return JS_EXCEPTION;
    uint32_t id = 0;
    JS_ToUint32(ctx, &id, argv[0]);
    const char *method = JS_ToCString(ctx, argv[1]);
    if (!method) return JS_EXCEPTION;
    size_t params_len;
    uint8_t *params = dc_write(ctx, argv[2], &params_len);
    if (!params) { JS_FreeCString(ctx, method); return JS_EXCEPTION; }
    /* carrier: method '\0' + JS_WriteObject(params) bytes (binary, may hold NULs) */
    size_t mlen = strlen(method) + 1;
    uint32_t plen = (uint32_t)(mlen + params_len);
    uint8_t *buf = malloc(plen);
    if (!buf) { JS_FreeCString(ctx, method); js_free(ctx, params); return JS_ThrowOutOfMemory(ctx); }
    memcpy(buf, method, mlen);
    memcpy(buf + mlen, params, params_len);
    JS_FreeCString(ctx, method);
    js_free(ctx, params);
    bool ok = ring_push(&h->cb->to_main, MSG_INSPECT, id, buf, plen);
    free(buf);
    if (ok) tjs_sem_post(&h->cb->main_sem);
    return JS_NewBool(ctx, ok);
}

/* dc.recv() 鈫?{ kind, type, id, payload? } | null 鈥?non-blocking */
static JSValue tjs_dc_worker_recv(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    RingMsg m;
    if (!ring_pop(&h->cb->to_worker, &m)) return JS_NULL;
    tjs_sem_trywait(&h->cb->worker_sem);   /* keep sem ~ queue length */
    int kind = (m.type == MSG_REPLY) ? MSG_RES_REPLY : MSG_RES_EVENT;
    JSValue payload = dc_read(ctx, m.data, m.len);
    if (JS_IsException(payload)) { ring_msg_free(&m); return payload; }
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "kind",    JS_NewInt32(ctx, kind));
    JS_SetPropertyStr(ctx, obj, "type",    JS_NewInt32(ctx, (int)m.type));
    JS_SetPropertyStr(ctx, obj, "id",      JS_NewUint32(ctx, m.id));
    JS_SetPropertyStr(ctx, obj, "payload", payload);
    ring_msg_free(&m);
    return obj;
}

/* dc.waitRecv(timeoutMs) 鈫?boolean 鈥?timed-wait on worker_sem */
static JSValue tjs_dc_worker_wait_recv(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    uint32_t ms = 1;
    if (argc > 0) JS_ToUint32(ctx, &ms, argv[0]);
    int ret = tjs_sem_timedwait(&h->cb->worker_sem, ms);
    return JS_NewBool(ctx, ret == 0);
}

/* dc.resume(step) 鈥?push MSG_RESUME into to_main + post main_sem */
static JSValue tjs_dc_worker_resume(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_EXCEPTION;
    uint32_t step = 0;
    if (argc > 0) JS_ToUint32(ctx, &step, argv[0]);
    bool ok = ring_push(&h->cb->to_main, MSG_RESUME, 0, (uint8_t *)&step, 4);
    if (ok) tjs_sem_post(&h->cb->main_sem);
    return JS_NewBool(ctx, ok);
}

/* dc.stop() 鈥?release worker's refcount */
static JSValue tjs_dc_worker_stop(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    TJSDCWorker *h = JS_GetOpaque(this_val, tjs_dc_worker_class_id);
    if (!h || !h->cb) return JS_UNDEFINED;
    dcb_decref(h->cb);
    h->cb = NULL;
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry tjs_dc_worker_proto_funcs[] = {
    TJS_CFUNC_DEF("interrupt",              0, tjs_dc_worker_interrupt),
    TJS_CFUNC_DEF("state",                  0, tjs_dc_worker_state),
    TJS_CFUNC_DEF("addBreakpoint",          3, tjs_dc_worker_add_breakpoint),
    TJS_CFUNC_DEF("removeBreakpoint",       2, tjs_dc_worker_remove_breakpoint),
    TJS_CFUNC_DEF("clearBreakpoints",       0, tjs_dc_worker_clear_breakpoints),
    TJS_CFUNC_DEF("setBreakpointsActive",   1, tjs_dc_worker_set_breakpoints_active),
    TJS_CFUNC_DEF("setExceptionBreakpoint", 1, tjs_dc_worker_set_exception_bp),
    TJS_CFUNC_DEF("setStep",                1, tjs_dc_worker_set_step),
    TJS_CFUNC_DEF("send",                   3, tjs_dc_worker_send),
    TJS_CFUNC_DEF("recv",                   0, tjs_dc_worker_recv),
    TJS_CFUNC_DEF("waitRecv",               1, tjs_dc_worker_wait_recv),
    TJS_CFUNC_DEF("resume",                 1, tjs_dc_worker_resume),
    TJS_CFUNC_DEF("stop",                   0, tjs_dc_worker_stop),
};

/* ---- getDebugChannel(handle: ArrayBuffer) -------------------------------- */

static JSValue tjs_debug_get_channel(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    if (argc == 0) return JS_ThrowTypeError(ctx, "getDebugChannel requires an ArrayBuffer");
    size_t byte_len;
    uint8_t *data = (uint8_t *)JS_GetArrayBuffer(ctx, &byte_len, argv[0]);
    if (!data || byte_len != sizeof(void *))
        return JS_ThrowTypeError(ctx, "invalid handle ArrayBuffer (expected an 8-byte channel pointer)");
    DebugControlBlock *cb;
    memcpy(&cb, data, sizeof cb);   /* read the shared control-block pointer */
    if (!cb)
        return JS_ThrowTypeError(ctx, "null debug channel pointer");

    /* Worker claims the second baked-in ref (refcount started at 2) 鈥?do NOT
     * increment here, and do NOT detach: detaching would not affect the shared
     * DCB, and the 8 handle bytes are harmless to leave in place. */

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_dc_worker_proto_funcs, countof(tjs_dc_worker_proto_funcs));

    TJSDCWorker *h = js_mallocz(ctx, sizeof(TJSDCWorker));
    if (!h) { JS_FreeValue(ctx, proto); return JS_ThrowOutOfMemory(ctx); }
    h->cb = cb;

    JSValue obj = JS_NewObjectClass(ctx, tjs_dc_worker_class_id);
    if (JS_IsException(obj)) { js_free(ctx, h); JS_FreeValue(ctx, proto); return obj; }
    JS_SetOpaque(obj, h);
    JS_SetPrototype(ctx, obj, proto);
    JS_FreeValue(ctx, proto);
    return obj;
}

/* ---- Module export table ------------------------------------------------- */

static const JSCFunctionListEntry tjs_debug_funcs[] = {
    TJS_CFUNC_DEF("start",                  1, tjs_debug_start),
    TJS_CFUNC_DEF("stop",                   0, tjs_debug_stop),
    TJS_CFUNC_DEF("addBreakpoint",          3, tjs_debug_add_breakpoint),
    TJS_CFUNC_DEF("removeBreakpoint",       2, tjs_debug_remove_breakpoint),
    TJS_CFUNC_DEF("clearBreakpoints",       0, tjs_debug_clear_breakpoints),
    TJS_CFUNC_DEF("getStackDepth",          0, tjs_debug_get_stack_depth),
    TJS_CFUNC_DEF("getFrameInfo",           1, tjs_debug_get_frame_info),
    TJS_CFUNC_DEF("getLocalVariables",      1, tjs_debug_get_local_variables),
    TJS_CFUNC_DEF("setVariable",            3, tjs_debug_set_variable),
    TJS_CFUNC_DEF("evalInFrame",            2, tjs_debug_eval_in_frame),
    TJS_CFUNC_DEF("setExceptionBreakpoint", 1, tjs_debug_set_exception_breakpoint),
    TJS_CFUNC_DEF("step",                   1, tjs_debug_set_step_mode),
    TJS_CFUNC_DEF("createDebugChannel",     0, tjs_debug_create_channel),
    TJS_CFUNC_DEF("getDebugChannel",        1, tjs_debug_get_channel),

    TJS_CONST2("BREAKPOINT",     TJS_DEBUG_BREAKPOINT),
    TJS_CONST2("EXCEPTION",      TJS_DEBUG_EXCEPTION),
    TJS_CONST2("DEBUGGER",       TJS_DEBUG_DEBUGGER),
    TJS_CONST2("STEP",           TJS_DEBUG_STEP),
    TJS_CONST2("INTERRUPT",      TJS_DEBUG_INTERRUPT),
    TJS_CONST2("EXCEPTION_NONE", TJS_DEBUG_EXCEPTION_NONE),
    TJS_CONST2("EXCEPTION_CAUGHT", TJS_DEBUG_EXCEPTION_CAUGHT),
    TJS_CONST2("EXCEPTION_UNCAUGHT", TJS_DEBUG_EXCEPTION_UNCAUGHT),
    TJS_CONST2("EXCEPTION_ALL",  TJS_DEBUG_EXCEPTION_ALL),
    TJS_CONST2("DEBUGGER_STMT",  JS_DEBUG_TRACE_DEBUGGER_STMT),
    TJS_CONST2("STEP_NONE",      0),
    TJS_CONST2("STEP_INTO",      1),
    TJS_CONST2("STEP_OVER",      2),
    TJS_CONST2("STEP_OUT",       3),
    TJS_CONST2("STATE_IDLE",     DCB_STATE_IDLE),
    TJS_CONST2("STATE_RUNNING",  DCB_STATE_RUNNING),
    TJS_CONST2("STATE_PAUSED",   DCB_STATE_PAUSED),
    TJS_CONST2("EV_PAUSED",      MSG_EV_PAUSED),
    TJS_CONST2("EV_RESUMED",     MSG_EV_RESUMED),
    TJS_CONST2("REQ_INSPECT",    MSG_REQ_INSPECT),
    TJS_CONST2("REQ_RESUME",     MSG_REQ_RESUME),
    TJS_CONST2("RES_EVENT",      MSG_RES_EVENT),
    TJS_CONST2("RES_REPLY",      MSG_RES_REPLY),
};

void tjs__mod_debug_init(JSContext *ctx, JSValue ns) {
    JSRuntime* rt = JS_GetRuntime(ctx);

    /* Register JS classes (thread-local class IDs, one set per runtime/thread) */
    JS_NewClassID(rt, &tjs_dc_main_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_dc_main_class_id, &tjs_dc_main_class);

    JS_NewClassID(rt, &tjs_dc_worker_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_dc_worker_class_id, &tjs_dc_worker_class);

    JS_SetPropertyFunctionList(ctx, ns, tjs_debug_funcs, countof(tjs_debug_funcs));
}

#else
void tjs__mod_debug_init(JSContext *ctx, JSValue ns) {
    (void*)&ctx; (void*)&ns;
}
#endif
