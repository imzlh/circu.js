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
is not a sandbox security boundary, and its events are not automatically
connected to `engine.onEvent` or runtime lifecycle events.

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
