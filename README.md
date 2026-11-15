# circu.js

`circu.js/` is the native JavaScript runtime core used by `cno-cli`. It is built
from QuickJS plus libuv and exposes native modules through the
`import.meta.use()` mechanism.

In the root `cno-cli` build this directory is not shipped alone. CMake builds
the native runtime and `cjsc`, then bundles the TypeScript CLI into bytecode and
attaches it to the final staged `cno` binary.

## What Lives Here

| Path | Role |
| --- | --- |
| `src/` | Runtime C sources and native module implementations |
| `types/` | TypeScript declarations for native `import.meta.use()` modules |
| `deps/quickjs/` | QuickJS engine sources |
| `deps/libuv/` | libuv event loop dependency |
| `deps/wamr/` | WebAssembly runtime dependency |
| `deps/mimalloc/` | Optional allocator dependency |
| `tests/` | Native/runtime-focused tests |
| `cmake/` | CMake helpers |

## Runtime Model

```text
JavaScript module
  -> import.meta.use("fs" | "engine" | ...)
  -> native C module
  -> QuickJS values and libuv handles
```

QuickJS executes JavaScript and owns JS values. libuv owns the event loop,
timers, async file I/O, sockets, workers, and handle shutdown. Native modules
bridge the two.

The final `cno` runtime adds higher layers from sibling directories:

```text
cno-cli
  -> cts loader
  -> cno Web/Deno/Node polyfills
  -> circu.js native runtime
```

## Built-In Modules

Native modules are loaded from bootstrap code with:

```ts
const fs = import.meta.use('fs');
const engine = import.meta.use('engine');
```

Common built-ins include:

```text
algorithm, asyncfs, console, crypto, curl, debug, dns, engine, evbus, ffi, fs,
fswatch, http, nodeapi, os, process, signals, sourcemap, sqlite3,
ssl, streams, text, timers, udp, wasm, win32, worker, xml, zlib
```

Check `types/*.d.ts` for the exposed TypeScript shape and `src/mod_*.c` for the
native implementation.

### Runtime Capability Hooks

An application embedding `libcjs` can install one capability hook on each
`TJSRuntime`. The hook observes selected native operations before their side
effect and may allow, reject, or, where supported, replace the operation. This
is a circu.js embedding API declared in [`src/tjs.h`](src/tjs.h); it is not a
QuickJS API and it does not modify QuickJS's public ABI.

```c
static JSValue capability_hook(JSContext *ctx,
                               const TJSCapability *capability,
                               void *userdata) {
    TJSCapabilityMask category = TJS_CAP_CATEGORY(capability->mask);
    TJSCapabilityMask operations = TJS_CAP_OPERATIONS(capability->mask);

    if (category == TJS_CAP_IO && (operations & TJS_CAP_IO_WRITE))
        return JS_ThrowTypeError(ctx, "file writes are disabled");

    if (category == TJS_CAP_CONSOLE)
        return JS_UNDEFINED; /* replace the call and suppress its output */

    return TJS_CAPABILITY_PASS;
}

TJS_SetCapabilityHook(runtime, capability_hook, application_policy, 0);
```

A mask contains exactly one category in its high 16 bits and one or more
generic operations in its low 16 bits. Categories are tags, not combinable
flags: do not OR `TJS_CAP_IO` with `TJS_CAP_NETWORK`, for example. Operations
are `ACCESS`, `READ`, `WRITE`, `WATCH`, `CONNECT`, `LISTEN`, and `CONTROL`.
Policy should primarily select on the category and operation mask. `api` names
the originating libcjs operation for diagnostics and finer routing, but is not
a second permission bitset.

The result protocol is:

- `TJS_CAPABILITY_PASS` continues the original operation.
- `JS_EXCEPTION` rejects it and requires an exception pending on the supplied
  `JSContext`.
- Any other owned `JSValue` replaces a descriptor marked
  `TJS_CAP_FLAG_REPLACEABLE`; the native operation does not run. Returning a
  replacement for a non-replaceable descriptor is an error.

`TJS_CAP_FLAG_ASYNC` describes the original API, not an automatic conversion.
An async replacement is returned unchanged, so the hook must return a Promise
itself when the JavaScript-facing contract requires one. The runtime takes
ownership of a replacement value. Passing `NULL` to `TJS_SetCapabilityHook`
disables the hook and clears its userdata pointer. The setter returns `false`
and leaves the current hook unchanged for a null/freeing runtime or unknown
hook flags.

The optional `TJS_CAPABILITY_HOOK_PASS_IS_STABLE` installation flag promises
that every `PASS` from this hook executes no user JavaScript, makes no nested
libcjs call, and does not mutate receiver, descriptor, buffer, or other state
used by the pending native operation. Guarded entry points can then skip both
post-hook reacquisition and protection that must otherwise happen before the
hook (notably duplicating file descriptors). Use flags `0` unless this is true
for every allowed event; a hook that sometimes needs to re-enter must remain a
conservative hook.

For a local, non-gating call-path measurement, build the
`capability_benchmark` target and run it with an optional iteration count. It
reports the no-hook, ordinary `PASS`, and stable-hook paths; it deliberately
has no timing assertion because scheduler and platform noise would make one
misleading.

#### Trust and lifetime boundary

The hook is trusted synchronous embedder code. It receives the actual
`JSContext`, so it can construct a replacement or exception. While a hook is
running, capability checks caused by nested libcjs calls on that same runtime
are allowed without recursively invoking the hook. This permits logging and
diagnostics, but it also means code called by the hook is inside the trusted
boundary. Do not call untrusted JavaScript from a hook and expect nested
libcjs operations to be filtered.

The `TJSCapability` descriptor and everything reachable only through it are
borrowed until the hook returns. In particular, `api`, the optional
`details.resource` string, the console `argv` array, and its `JSValueConst`
elements must not be retained by address. `resource` is a best-effort name
whose meaning follows `category` and `api`: for example a path, endpoint,
environment variable, or dynamic-library path. Copy strings and duplicate JS
values during the callback if they must survive it, and keep duplicated JS
values on their owning runtime/thread. The application owns `userdata`;
libcjs neither copies nor frees it.

A hook may re-enter libcjs and mutate native or JavaScript state. It therefore
must not assume that a receiver, file descriptor, buffer address, URL, or other
native pointer obtained before the hook is still valid after the hook returns.
Native entry points are responsible for reacquiring and revalidating such
state. Hook authors should likewise avoid retaining borrowed buffer addresses
or receiver internals across calls into JavaScript.

#### Workers and concurrency

Creating a Worker snapshots the parent's current hook function, userdata
pointer, and hook flags and installs that tuple on the new Worker runtime.
Changing the parent hook later does not update existing Workers; a later Worker
receives the tuple current at its own creation. The tuple is copied, not owned
or reference counted.

Workers run on separate threads and may call the same hook and userdata
concurrently with the parent and with other Workers. The hook and shared
policy state must therefore be thread-safe, and userdata must remain alive
until the parent and every Worker that captured it have finished. Use only the
`JSContext` supplied to the current invocation; QuickJS values and contexts
must not be shared across Worker threads. `TJS_SetCapabilityHook` itself is not
a synchronization primitive and must not race with capability checks or
Worker creation.

#### Path and coverage limits

Capability details are best-effort descriptions, not authority-bearing
handles. An I/O path may be relative, non-canonical, affected by the current
working directory or symlinks, or `NULL` for descriptor, stdio, pipe, and
handle operations. An operation with multiple path operands may expose only
its primary path. Passing a string check also does not bind the later syscall
to the checked file, so ordinary symlink and time-of-check/time-of-use races
still apply. Enforce strict filesystem confinement with suitable OS facilities
and handle-based resolution in addition to this hook; rejecting `..` or
matching a textual prefix is not a secure path sandbox.

Coverage is at selected libcjs entry points, not at every operating-system
syscall performed transitively by a dependency. In particular, a WASI module
currently emits one coarse `OS | ACCESS | READ | WRITE | CONTROL` event when a
WASI instance is created. Its configured environment and preopened paths are
not reported as individual detail events, and WAMR's later WASI syscalls do
not re-enter the capability hook. Treat WASI preopens, inherited descriptors,
native extensions, and FFI as separate trust boundaries; the capability hook
alone is not a complete process sandbox.

### Foreign Function Interface

The `ffi` module prepares a native signature once and returns an ordinary
callable JavaScript function. Type descriptors are immutable module-owned
tokens; strings and look-alike objects are not accepted as types.

```ts
const ffi = import.meta.use('ffi');
const t = ffi.types;

using libc = ffi.open(ffi.libraries.c);

const abs = libc.bind([t.int, 'abs', t.int]);
const strlen = libc.bind([t.usize, 'strlen', t.buffer]);

abs(-42); // 42
strlen(new TextEncoder().encode('hello\0')); // 5n
```

`ffi.libraries.c` and `ffi.libraries.m` contain the platform loader names for
the C and math libraries. A library supports these operations:

- `bind([resultType, symbol, ...parameterTypes], options?)` resolves a function
  and prepares its call interface. Repeating the same binding reuses the
  resolved symbol and prepared interface. For a variadic function, every
  argument type is still listed and `options.fixed` gives the fixed parameter
  count.
- `symbol(name)` returns an opaque `Pointer` to a function or variable.
  `read([type, name])` reads a typed static symbol.
- `close()` and `[Symbol.dispose]()` are idempotent. Closing is immediately
  logical: bindings and pointers derived from that library then throw a closed
  error. The native handle remains loaded internally only while an outstanding
  owned resource still needs a disposer from it.

`ffi.types` includes fixed-width integers and floats, C platform integer
types, `void`, `bool`, `pointer`, `buffer`, and `function`. Integers up to 32
bits and floating-point values use JavaScript `number`; `i64`, `u64`, `isize`,
`usize`, `longLong`, and `ulongLong` use `bigint`. The value for `long` and
`ulong` follows the platform width. Native pointers are opaque `Pointer | null`
values rather than numeric addresses.

Aggregate descriptors calculate their layout with the active ABI:

```ts
const Record = t.struct([t.u8, t.u32, t.f64]);
const Records = t.array(Record, 4);

Record.size;
Record.alignment;
Record.offsets;
Records.offsets;

const bytes = Record.pack([1, 20, 3.5]);
Record.unpack(bytes); // [1, 20, 3.5]
```

Top-level structs cross a function call boundary by value as an exactly
ABI-sized `Uint8Array`. C arrays cannot be top-level function parameters or
results, but their descriptors provide ABI layout, `offsets`, `pack()`, and
`unpack()` for nested fields and typed static-symbol reads. For an array,
`offsets[i]` is the ABI byte offset of element `i`. A `buffer` parameter accepts
an `ArrayBuffer` or view, respects the view's byte offset, and passes its backing
store without a copy while keeping it alive for the synchronous call. Native
code must not retain that borrowed address beyond the call. `buffer` is
input-only and is rejected as a function or callback result when the signature
is bound or prepared.

All native calls are synchronous and block the runtime thread. An arbitrary
function pointer can be called by giving it a signature without a symbol name:

```ts
const compare = ffi.function(comparePointer, [t.int, t.pointer, t.pointer]);
const result = compare(leftPointer, rightPointer);
```

Callbacks also exchange decoded JavaScript values directly:

```ts
using callback = ffi.callback(
    [t.int, t.int, t.int],
    (left, right) => left - right,
);
nativeFunction(callback.pointer);
```

A callback is synchronous and may be invoked only on the thread where it was
created. An invocation from another thread never enters QuickJS; it returns the
ABI zero value and records an unsupported-thread error. When observed by an
enclosing synchronous FFI call, that call throws the error after native code
returns. A
`buffer` callback parameter is delivered as `Pointer | null`, because a raw
native address carries no length from which to reconstruct a `BufferSource`.
If a callback throws during an FFI call, its exception is rethrown after the
outer native call returns. Without an outer FFI call, it is sent to the
runtime's uncaught exception reporting path. Callback `close()` and
`[Symbol.dispose]()` are idempotent and invalidate both future `.pointer`
access and pointers already derived from the callback.

Raw memory operations are intentionally isolated under `ffi.unsafe`:

```ts
const address = ffi.unsafe.address(pointer);        // bigint
const raw = ffi.unsafe.fromAddress(address);        // Pointer | null
const borrowed = ffi.unsafe.pointerOf(uint8Array);
const next = ffi.unsafe.offset(borrowed, 4);
const target = ffi.unsafe.deref(pointerToPointer);
const view = ffi.unsafe.view(next, 16);              // non-copying
const text = ffi.unsafe.readCString(cString, 4096);
const loop = ffi.unsafe.currentEventLoop();
```

Derived pointers retain their owner and inherit its validity. A buffer pointer
keeps the buffer backing store alive. A library pointer becomes invalid when
the library is closed. A pointer made with `fromAddress()` has no owner, and a
view over foreign memory has no independent lifetime or bounds guarantee; the
caller must ensure the address remains valid.

Use `ffi.unsafe.adopt(pointer, disposer)` when JavaScript takes ownership of a
native allocation. The disposer must already be bound with the signature
`[t.void, t.pointer]`. The returned `OwnedPointer` runs it exactly once from
`close()` or `[Symbol.dispose]()`, with garbage collection only as a fallback.
`release()` disables disposal and returns a plain pointer. An owned resource
keeps its disposer and the corresponding native library loaded until it is
disposed or explicitly released, even if the library has been logically
closed. Borrowed buffer and callback pointers cannot be adopted because their
JS-owned storage or closure may be finalized before native cleanup runs.

`ffi.errno()` returns the value captured immediately after the most recent FFI
call, before later JavaScript work can overwrite the process errno. Read it
before making another FFI call; `ffi.strerror(value)` converts it to the
platform error message. See [the declarations](types/ffi.d.ts) for the complete
API and type inference rules.

### Runtime-Local Event Bus

Bootstrap code can use `evbus` to share values and dispatch synchronous
events inside one QuickJS runtime. See the [type declarations](types/evbus.d.ts)
and [native implementation](src/mod_evbus.c):

```ts
const evbus = import.meta.use('evbus');
const state = { count: 0 };

evbus.set('example.app', 'state', state);
const unsubscribe = evbus.on<typeof state>('example.app', 'update', value => {
    value.count++;
});
evbus.emit('example.app', 'update', state); // true; state.count is now 1
unsubscribe();                            // safe to call more than once
evbus.delete('example.app', 'state');
```

- `set(namespace, key, value)` stores a value by identity and returns
  `undefined`. `get` returns the value or `undefined`; use `has` to distinguish
  a stored `undefined` from a missing key. `delete` returns whether a key
  existed. `clear(namespace)` removes values in that namespace, not listeners.
- `on(namespace, event, callback)` returns an idempotent unsubscribe function
  for that registration. There is no separate `off` or `once` method or
  numeric token. To implement once-only behavior, unsubscribe before running
  the callback body so recursive emits do not invoke it again.
- `emit(namespace, event, payload?)` calls a snapshot in registration order,
  synchronously, with exactly one argument (`undefined` if omitted). It
  returns `false` for an empty snapshot and `true` otherwise. The first
  synchronously thrown value propagates and stops dispatch; listener return
  values and promises are ignored. A listener added or unsubscribed during
  dispatch affects later emits, including nested emits, but not the current
  snapshot.
- Native modules can publish through
  `TJS_EvBusEmit(ctx, namespace, event, payload)` from `src/tjs.h`. The call is
  synchronous and must run on the thread that owns `ctx`; its strings and
  payload are borrowed, while the returned boolean or exception is owned by
  the caller. It uses the same snapshot, cross-realm and exception semantics
  as JavaScript `emit()`.
- Namespace, key and event names must be strings (empty strings are allowed);
  a missing value for `set` or a non-callable listener throws `TypeError`.
  TypeScript payload and `get<T>` types are conventions between callers, not
  runtime validation.

Values and listeners are strongly retained. Dropping an unsubscribe function
does not remove the listener; call it when the registration is no longer
needed. Values belong to the context of their most recent `set`, and listeners
to the context that registered them. When a sandbox is finalized, its owned
entries are removed; runtime shutdown removes all entries. An in-flight
dispatch can still invoke an already-snapshotted listener. A retained value or
callback can itself keep other objects reachable, so cleanup is not a
substitute for releasing resources explicitly.

Sandboxes that have access to the module share their runtime's bus and values
by identity. Workers have separate QuickJS runtimes and separate buses. The bus
is not a sandbox security boundary. Native runtime events are published on
`evbus.RUNTIME_NAMESPACE` / `evbus.RUNTIME_EVENT`; listeners can be removed with
the unsubscribe function, so no module owns a global single receiver. The
optional fourth argument to `on()` is a priority for that native channel only;
ordinary application events remain registration ordered.

`evbus` is built in on the current runtime, including workers. On an older
runtime, `import.meta.use('evbus')` may return `null`; callers supporting both
versions must check for availability and provide their own fallback. A
realm-local global or `Symbol.for()` slot does not provide cross-context
sharing. As with other built-ins, `import.meta.use()` is subject to symbol mode
in the root `cno-cli` build.

## Symbol Mode In cno-cli

The root `cno-cli` CMake build forces:

```cmake
CJS_USE_SYMBOL_INTERNAL ON
```

That means the bundled CLI code is transformed to use internal symbols instead
of directly calling `import.meta.use()` at runtime. Source code in this repo
should still be written with `import.meta.use()`; `scripts/bundle.mjs` handles
the release transform.

## Build

Standalone native build:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

From the repository root, the normal integrated build is:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The root build produces:

```text
build/stage/cno
```

## Native Extension Hooks

The root build can pass extension sources and init symbols into circu.js through
these CMake cache variables:

```text
CJS_EXTRA_SOURCES
CJS_EXTRA_INCLUDE_DIRS
CJS_EXTRA_LIBS
CJS_EXTRA_DEFINES
CJS_EXTRA_MODULE_NAMES
CJS_EXTRA_MODULE_INITS
CJS_EXTRA_MODULE_WORKER_SAFE
```

`cno-cli` uses that path for optional HTTP/2 and QUIC static embedding.

## Maintenance Notes

- Keep `uv_run()` ownership centralized in the runtime loop and explicit wait
  helpers.
- Use `uv_close()` for libuv handles and let close callbacks run during runtime
  teardown.
- Data freed from JS finalizers should use QuickJS-tracked allocation only when
  it is owned by the JS runtime.
- Data that can outlive JS teardown or be released from libuv callbacks should
  use runtime/global allocation helpers.
- `uv_queue_work` worker callbacks must not touch QuickJS APIs or QuickJS
  tracked allocation.
- When changing native module exports, update the matching file in `types/`.
