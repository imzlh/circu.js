# circu.js — The tiny JavaScript runtime

A lightweight, fast JavaScript runtime built on [QuickJS](https://bellard.org/quickjs/) and [libuv](https://libuv.org/). Originally forked from [txiki.js](https://github.com/saghul/txiki.js), but heavily modified and expanded with new modules, new APIs, and extensive bug fixes.

**License:** MIT

---

## What is circu.js?

circu.js is a small, self-contained JavaScript engine that you can embed in any C project or use as a standalone CLI runtime. It gives you an ECMAScript 2024+ compliant language core (via QuickJS), an event loop (via libuv), and a rich set of built-in modules — all in a single native binary of just a couple of megabytes.

If you know [Deno](https://deno.com/) or [Node.js](https://nodejs.org/), the general idea will feel familiar. The difference is that circu.js is designed to be **tiny, embeddable, and dependency-light** — no npm, no `node_modules`, roughly 40× smaller than Node. Just a ~2 MB `cjs` binary and your `.js` files.

### Highlights

- **Embeddable.** The core (`libcjs`) is a plain C static library. Drop it into your application and you have a JavaScript scripting engine with zero extra runtime dependencies.
- **Small.** The full dynamically-linked CLI binary is typically ~2 MB on Linux x64 (varies by platform and build options).
- **Fast startup.** QuickJS compiles JavaScript to bytecode on the fly; cold starts are near-instant.
- **`import.meta.use()` module system.** Load built-in modules on demand without `import` statements — a unique pattern that keeps the dependency graph explicit and secure while staying flexible.
- **Self-attaching bytecode.** Compiled JS bytecode can be appended directly to the binary, producing a single-file distributable with no external JS files needed.
- **A toolkit for building your own runtime.** circu.js is designed as a container for your JavaScript code. It provides a simple but powerful API for loading and executing JS, plus a clean way to register your own built-in modules.
- **Full TypeScript support when paired with CNO + CTS.** The project ships complete TypeScript type definitions, and companion projects provide Deno/Node-compatible APIs and TypeScript execution (more on this below).

---

## Companion Projects: CNO and CTS

circu.js is intentionally minimal — it does **not** include Web APIs, Deno APIs, or Node.js APIs out of the box. To build a full-featured runtime, use these companion projects (both by the same author):

### [CNO](https://github.com/imzlh/cno) — Circu.js Node-like Orchestrator

CNO is the polyfill layer. It provides:

- **Web API polyfills** — `fetch`, `WebSocket`, `EventSource`, `URL`, `Headers`, `Request`, `Response`, `Blob`, `FormData`, `AbortController`, `TextEncoder`/`TextDecoder`, `crypto.subtle`, `performance`, `localStorage`, `Intl`, `WebAssembly`, and more.
- **Deno API compatibility** — `Deno.readFile`, `Deno.serve`, `Deno.Command`, `Deno.connect`, `Deno.env`, `Deno.args`, and the rest of the Deno surface.
- **Node.js compatibility** — `fs`, `path`, `os`, `events`, `util`, `buffer`, `stream`, `net`, `child_process`, `process`, `crypto`, `zlib`, `dgram`, and more.
- **CNO namespace** — `CNO.openpty()`, `CNO.engine.serialize()`, `CNO.engine.evalModule()`.

### [CTS](https://github.com/imzlh/cts) — Circu.js TypeScript Support

CTS is a TypeScript bootstrap that bundles CNO with a TypeScript-to-JS transformer (via [sucrase](https://github.com/alangpierce/sucrase)), so you can run `.ts` files directly.

### How they fit together

```
Your .ts / .js file
        │
        ▼
┌────────────┐     ┌──────────────────────────────────────┐
│    CTS     │────►│  circu.js (cjs binary)               │
│  (TS → JS) │     │  ┌────────────────────────────────┐  │
└────────────┘     │  │  CNO (WebAPI + Deno + Node)    │  │
                   │  ├────────────────────────────────┤  │
                   │  │  Built-in modules (fs, os, …)  │  │
                   │  ├────────────────────────────────┤  │
                   │  │  QuickJS + libuv               │  │
                   │  └────────────────────────────────┘  │
                   └──────────────────────────────────────┘
```

Together, the three projects let you run Deno-compatible TypeScript code on the circu.js runtime:

```bash
# 1. Build CTS (produces dist.js)
cd ../cts
pnpm install
pnpm run build

# 2. Attach CTS to the cjs binary (self-contained)
cjsc -b ../circu.js/build/cjs -s -e dist.js

# 3. Run TypeScript files directly
./cjs app.ts
```

For more details, see the CTS and CNO READMEs in their respective repositories.

---

## Quick Start

### Build from source

```bash
git clone --recurse-submodules https://github.com/imzlh/circu.js
cd circu.js
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --build build --target cjsc
```

The resulting binary is at `build/cjs`.

**For the recommended setup** with full TypeScript and Deno API support, follow the CNO + CTS workflow described above. The basic `cjs` binary alone is useful for running plain JavaScript or embedding in C projects.

### Build options

| Option | Default | Description |
|---|---|---|
| `BUILD_WITH_MIMALLOC` | `OFF` | Use [mimalloc](https://github.com/microsoft/mimalloc) as the global allocator (better performance) |
| `USE_EXTERNAL_FFI` | `ON` | Link against system `libffi` instead of a bundled copy |
| `BUILD_WITH_WASM` | `ON` | Enable WebAssembly support via [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) |
| `BUILD_WITH_CURL` | `ON` | Enable the `curl` built-in module |
| `CJS_USE_SYMBOL_INTERNAL` | `OFF` | Use `Symbol` instead of `import.meta.use()` for built-in module loading (see below) |

Options can be toggled via `cmake -B build -DOPTION_NAME=ON` or via environment variables of the same name.

### Docker

```bash
docker build -t cjs .
docker run --rm -v "$PWD:/app" -w /app cjs your-script.js
```

---

## Architecture

### Layer diagram

```
┌──────────────────────────────────────────────┐
│                Your JS code                  │
├──────────────────────────────────────────────┤
│  Built-in modules (fs, os, http, ffi, ...)   │  ◄── import.meta.use('fs')
├──────────────────────────────────────────────┤
│  Engine API (eval, serialize, GC, events)    │  ◄── import.meta.use('engine')
├───────────────┬──────────────────────────────┤
│   QuickJS     │         libuv                │
│  (JS engine)  │    (event loop, I/O)         │
├───────────────┴──────────────────────────────┤
│  Platform layer (POSIX / Win32)              │
└──────────────────────────────────────────────┘
```

**QuickJS** handles parsing, compilation, and execution of JavaScript. It implements the full ES2024+ spec including modules, promises, proxies, BigInt, and more.

**libuv** provides the event loop, file system operations (async), networking (TCP/UDP/timers), threading, and platform abstraction. All built-in modules use libuv handles internally.

**circu.js** glues them together: it registers built-in C modules into the JS runtime, wires up the module loader, manages the interaction between the JS job queue and the libuv event loop, and exposes an `Engine` API surface for runtime introspection and control.

### How the event loop works

The event loop is libuv's `uv_run()`, with three extra handles inserted:

1. **`uv_prepare`** — before polling for I/O, checks whether there are pending JS jobs (promise callbacks, `queueMicrotask`, etc.) and keeps the loop alive.
2. **`uv_idle`** — while JS jobs are pending but no I/O is ready, prevents the loop from blocking.
3. **`uv_check`** — after I/O polling, drains the JS job queue.

This is the same pattern used by Node.js and Deno: **libuv owns the loop, QuickJS jobs are interleaved between I/O phases**.

### Module loading

circu.js supports standard ES module `import` for user code. When you write:

```js
import { readFileSync } from './my-utils.js';
```

…the file is read from disk, compiled by QuickJS, and linked as an ES module. JSON imports (`import data from './config.json'`) are also supported transparently.

For **built-in** C modules (the ones shipped with the runtime), circu.js uses a different mechanism — see `import.meta.use()` below.

---

## The `import.meta.use()` System

This is the most distinctive feature of circu.js.

### The problem it solves

Standard `import` statements are *static* — the engine must resolve all imports before execution begins. That works for user code, but built-in C modules don't exist as files on disk. Other runtimes solve this in various ways: Deno uses `Deno.core.ops`, Node.js uses `internalBinding` in a sandbox. Both approaches are painful to type and maintain, and make static analysis impossible.

circu.js takes a different approach: `import.meta.use()` provides a safe, explicit, and flexible way to load built-in modules from within bootstrap code, without exposing internal symbols to user code.

### How it works

Inside any ES module, `import.meta.use` is a function that loads a built-in module by name:

```js
// Inside a .js module:
const fs = import.meta.use('fs');
const os = import.meta.use('os');
const engine = import.meta.use('engine');

// fs, os, and engine are now regular JS objects with the module's exports
```

Key properties:

- **On-demand.** The first call to `import.meta.use('fs')` initializes the module and caches the result. Subsequent calls return the cached object instantly.
- **Synchronous.** No `await` needed — built-in modules are C functions that register themselves into the runtime at startup.
- **Bootstrap-only.** `import.meta.use` is available inside bootstrap code and is never exposed to user code (unlike the original txiki.js behavior, where it leaked into every module).
- **Discoverable.** `import.meta.module` is an array of all available built-in module names, so you can enumerate what's available at runtime.

### Available built-in modules

| Module | Description |
|---|---|
| `fs` | Synchronous file system operations (open, read, write, stat, …) |
| `asyncfs` | Asynchronous file system operations with promises |
| `fswatch` | File system watcher (inotify / FSEvents / ReadDirectoryChangesW) |
| `os` | Operating system info (hostname, platform, CPU, memory, …) |
| `process` | Process management (cwd, chdir, env, pid, ppid, …) |
| `pty` | Pseudo-terminal spawning (Unix: `openpty`; Windows: ConPTY) |
| `signals` | POSIX signal handling (SIGINT, SIGTERM, etc.) |
| `streams` | Stream and socket abstractions (TCP, Unix, TLS, UDP) |
| `tcp` / `udp` | Low-level networking |
| `dns` | DNS resolution |
| `http` | HTTP parser / builder (llhttp-based) |
| `tls` / `ssl` | TLS/SSL support via OpenSSL |
| `crypto` | Cryptographic primitives (hash, HMAC, AES, RSA, ECDSA, …) |
| `zlib` | Compression (deflate, gzip, brotli) |
| `ffi` | Foreign Function Interface (libffi-based) — call C functions from JS |
| `worker` | Worker threads with message passing |
| `timers` | `setTimeout` / `setInterval` / `setImmediate` |
| `console` | Console output |
| `engine` | Runtime engine API (eval, serialize, GC control, events) |
| `text` | Text encoding conversion (iconv-based, when available) |
| `xml` | XML parsing (expat-based) |
| `algorithm` | Utility functions (sorting, binary search, encoding helpers) |
| `sourcemap` | SourceMap parsing and lookup |
| `curl` | HTTP client via libcurl (when `BUILD_WITH_CURL=ON`) |
| `wasm` | WebAssembly runtime via WAMR (when `BUILD_WITH_WASM=ON`) |
| `posix_socket` | Unix domain sockets (POSIX only) |

### Symbol mode (`CJS_USE_SYMBOL_INTERNAL`)

If you set `CJS_USE_SYMBOL_INTERNAL=ON` at build time, `import.meta.use()` is **disabled** and built-in modules are instead accessed via a global `Symbol`:

```js
// With CJS_USE_SYMBOL_INTERNAL=ON:
const use = globalThis[Symbol.for('cjs.internal.use')] as UseFN;
const fs = use('fs');
```

This exists for environments where modifying `import.meta` is not allowed (e.g. stripped bytecode produced by `cjsc`). The TypeScript type definitions reflect this: when `CJS__DISABLE_MODULE_USE` is active, `import.meta.use` is typed as unavailable.

---

## Embedding circu.js in Your Application

The core of circu.js is `libcjs` — a plain C static library. You link it into your application and interact with it through a small, stable C API:

```c
#include "tjs.h"

// Note: circu.js uses the same naming convention as txiki.js,
// so don't be confused by the `tjs__` or `TJS_` prefix.
int main(int argc, char **argv) {
    // Initialize platform internals
    TJS_Initialize(argc, argv);

    // Create a runtime (includes QuickJS + libuv loop)
    TJSRuntime *qrt = TJS_NewRuntime();

    // Run the JS event loop (loads built-in modules, runs user code)
    int exit_code = TJS_Run(qrt);

    // Clean up
    TJS_FreeRuntime(qrt);
    return exit_code;
}
```

That's literally `cli.c` — the entire `cjs` binary is ~40 lines.

### Customizing module resolution

You can override how modules are found, loaded, and how their metadata is initialized — all from JavaScript:

```js
import.meta.use('engine').onModule({
    resolve(name, base)    { /* custom module name resolution */ },
    load(name, attributes) { /* custom module loading — return source string */ },
    init(name, meta)       { /* custom import.meta initialization */ },
    attrchk(attributes)    { /* validate import attributes (e.g. type: "json") */ },
});
```

This means you can implement `node:`-style specifiers, HTTP imports, virtual file systems, or anything else — in pure JavaScript.

### Runtime options

```ts
const engine = import.meta.use('engine');
engine.setMaxStackSize(8 * 1024 * 1024);
engine.setMemoryLimit(256 * 1024 * 1024);
```

### Evaluating JS from C

```c
JSContext *ctx = TJS_GetJSContext(qrt);

// Evaluate a script file
TJS_EvalScript(ctx, "app.js");

// Evaluate a module file
TJS_EvalModule(ctx, "app.js", true);  // true = is_main

// Evaluate a JS string directly
TJS_EvalModuleContent(ctx, "<inline>", false, false, js_code, js_len);
```

### Serializing to bytecode

QuickJS can compile JavaScript to compact bytecode that loads instantly:

```bash
# Compile a .js file to bytecode and attach it to the binary
cjsc -b cjs -s -e app.js
```

`cjsc` is the bytecode compiler (built alongside `cjs`). The `-b` flag appends bytecode to the `cjs` binary itself, so at runtime the embedded bootstrap code is read from the executable — no separate `.js` files needed.

---

## Engine API

The `engine` module is your window into the runtime itself:

```js
const engine = import.meta.use('engine');

// Version info for all components
console.log(engine.versions);
// { quickjs: '2025-03-29', tjs: '1.0.0', uv: '1.50.0', sqlite3: '3.45.0',
//   zlib: '1.3', openssl: '3.4.1', llhttp: '9.3.0', core: '1.0.0', ... }

// GC control
engine.gc.run();
engine.gc.setThreshold(1024 * 1024);

// Evaluate JS dynamically (returns a Module object)
const mod = engine.eval('export const x = 42;', '<test>');

// Serialize/deserialize JS values to/from bytecode
const bytes = engine.serialize({ hello: 'world' });
const value = engine.deserialize(bytes);

// Synchronously wait for a promise to settle (drives the event loop)
const result = engine.waitPromise(somePromise);

// String encoding helpers
const buf = engine.encodeString('hello');
const str = engine.decodeString(buf);
```

### Events

You can register a global event handler for runtime-level events:

```js
engine.onEvent((eventType, data) => {
    switch (eventType) {
        case engine.EventType.UNHANDLED_REJECTION:
            console.error('Unhandled:', data);
            return false; // cancel default behavior (process exit)
        case engine.EventType.EXIT:
            console.log('Exit code:', data);
            break;
    }
});
```

Available event types: `PROMISE`, `UNHANDLED_REJECTION`, `JOB_EXCEPTION`, `EXIT`, `LOAD`.

### Module class

`engine.Module` gives you first-class access to QuickJS modules from JavaScript:

```js
// Create a module from source code
const mod = new Module('export const x = 42;', '<test>');

// Create a module from a plain JS object (named exports)
const mod2 = Module.from('./virtual.js', { foo: 'bar', baz: 42 });

// Create a C-compatible module (for adding C-side exports later)
const mod3 = Module.create('./c-module.js');

// Evaluate the module
const ns = mod.eval();

// Inspect
console.log(mod.namespace);  // module namespace object
console.log(mod.meta);       // import.meta for this module
console.log(mod.dump());     // serialized bytecode as ArrayBuffer
```

---

## Worker Threads

circu.js supports worker threads — each with its own QuickJS runtime and libuv event loop:

```js
// main.js
const worker = new Worker({ channel: 'main' });

worker.messagePipe.onmessage = (msg) => {
    console.log('From worker:', msg);
};
worker.messagePipe.postMessage({ hello: 'worker' });

// When done:
worker.terminate();
```

Inside the worker:

```js
// worker.js — runs on a separate thread
const pipe = import.meta.use('worker');
pipe.onmessage = (msg) => {
    pipe.postMessage({ reply: 'hello from worker' });
};
```

Workers communicate by serializing and deserializing JavaScript values (including `SharedArrayBuffer`). Note: workers cannot spawn nested workers.

---

## FFI

The `ffi` module lets you call C functions directly from JavaScript — no native addons needed:

```js
const ffi = import.meta.use('ffi');

// Load a shared library
const lib = new ffi.UvLib('libm.so');  // or 'msvcrt.dll' on Windows

// Look up a symbol
const cos = lib.symbol('cos');

// Define the call signature
const cif = new ffi.FfiCif(
    ffi.type_double,    // return type
    ffi.type_double     // argument types...
);

// Call it
const result = cif.call(cos, 3.14159);
console.log(result); // ≈ -1
```

You can also create closures (JavaScript callbacks that C code can call), define struct types, and work with raw memory buffers.

---

## Dependencies

| Dependency | Purpose |
|---|---|
| [QuickJS](https://bellard.org/quickjs/) (fork) | JavaScript engine (ES2024+) |
| [libuv](https://libuv.org/) | Event loop, async I/O, threading |
| [OpenSSL](https://www.openssl.org/) | TLS/SSL, crypto |
| [SQLite3](https://www.sqlite.org/) | Embedded database |
| [libffi](https://sourceware.org/libffi/) | Foreign Function Interface |
| [llhttp](https://github.com/nodejs/llhttp) | HTTP parsing |
| [expat](https://libexpat.github.io/) | XML parsing |
| [zlib](https://zlib.net/) | Compression |
| [libcurl](https://curl.se/libcurl/) (optional) | HTTP client |
| [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) (optional) | WebAssembly runtime |
| [mimalloc](https://github.com/microsoft/mimalloc) (optional) | Alternative global allocator |
| [libiconv](https://www.gnu.org/software/libiconv/) (optional) | Text encoding conversion |

---

## Platforms

- **Linux** (x64, aarch64) — GCC / Clang
- **macOS** (x64, arm64) — Clang
- **Windows** (x64) — MSVC / MinGW

---

## Project Structure

```
circu.js/
├── CMakeLists.txt          # Build system
├── src/
│   ├── cli.c               # Entry point (main function)
│   ├── vm.c                # Runtime initialization, event loop integration
│   ├── modules.c           # Module loader, normalizer, import.meta.use()
│   ├── binary.c            # Bytecode attach / read from self binary
│   ├── qjsc.c              # Bytecode compiler (forked from QuickJS)
│   ├── repl.ts             # Interactive REPL (TypeScript → compiled to bytecode)
│   ├── sourcemap.c         # SourceMap parser and lookup
│   ├── mem.c               # Memory allocator integration (mimalloc or system)
│   ├── mod_*.c             # Built-in modules (one file per module)
│   ├── tjs.h               # Public C API (TJSRuntime)
│   └── private.h           # Internal shared structures
├── deps/                   # Git submodules (quickjs, libuv, wamr, mimalloc)
├── types/                  # TypeScript type definitions (*.d.ts)
├── tests/                  # Test suite
├── Dockerfile              # Docker build
└── cmake/                  # CMake helper scripts
```

---

## Contributing

Issues and PRs are welcome. The codebase is C11 (with some GNU extensions) plus a small amount of TypeScript (the REPL). Please keep changes focused and avoid unnecessary abstractions.

---

## Acknowledgments

- [Fabrice Bellard](https://bellard.org/) — QuickJS
- [Saúl Ibarra Corretgé](https://github.com/saghul) — txiki.js (the original project this was forked from)
- [lal12](https://github.com/lal12) — FFI module (MIT licensed)
- All dependency library authors
