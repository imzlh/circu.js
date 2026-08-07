/**
 * Engine module - QuickJS runtime and module management
 * 
 * @example
 * const engine = import.meta.use('engine');
 * 
 * console.log('Versions:', engine.versions);
 * engine.gc.run(); // Manual GC
 * 
 * const bytecode = engine.serialize({ key: 'value' });
 * const obj = engine.deserialize(bytecode);
 */
declare namespace CModuleEngine {
    export type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;   // not shared
    export type PromiseHookFn = (
        state: PromiseState,
        promise: globalThis.Promise<unknown>,
        parent?: globalThis.Promise<unknown>
    ) => void;
    export type IntrinsicFeature =
        | "date"
        | "regexp"
        | "json"
        | "proxy"
        | "map"
        | "typedarrays"
        | "promise"
        | "bigint"
        | "weakref"
        | "atob"
        | "domexception"
        | "performance";

    /**
     * dump function opcode
     */
    export const DUMP_BYTECODE: number;

    /**
     * disable debug info in dump function
     */
    export const DUMP_NODEBUG: number;

    /**
     * disable source code in dump function
     */
    export const DUMP_NOSOURCE: number;

    /**
     * deep dump object to handle complex objects
     */
    export const DUMP_DEEP: number;

    /**
     * USE with cautious, dump shared array buffer
     * will cause memory access error if program died
     */
    export const DUMP_LOCAL: number;

    /**
     * default dump, include bytecode, deep dump
     */
    export const DUMP_DEFAULT: number;

    /**
     * compile code with async eval support
     */
    export const EVAL_ASYNC: number

    /**
     * force strict
     */
    export const EVAL_STRICT: number

    /**
     * do not record previous backtrace when eval
     */
    export const EVAL_NEW_BACKTRACE: number;

    /**
     * eval code as module
     */
    export const EVAL_MODULE: number;

    /**
     * eval code as global script (CJS-style, synchronous throw)
     */
    export const EVAL_GLOBAL: number;

    /**
     * compile only — do not evaluate. The returned value is not directly
     * usable from script code; pass it to `evalCompiled()` to run it, or
     * `serialize()` to dump it for later `deserialize()` + `evalCompiled()`.
     */
    export const EVAL_COMPILE_ONLY: number;

    export enum PromiseState {
        CONSTRUCT,
        BEFORE_THEN,
        AFTER_THEN,
        FULFILLED
    }

    export enum EventType {
        UNHANDLED_REJECTION = 0,
        JOB_EXCEPTION,
        EXIT,
        LOAD
    }

    export interface GlobalEvents {
        [EventType.EXIT]: number,
        [EventType.UNHANDLED_REJECTION]: [this: Promise<unknown>, reason: unknown],
        [EventType.JOB_EXCEPTION]: Error | unknown,
        [EventType.LOAD]: undefined
    }

    /**
     * Garbage collector module
     */
    export interface GarbageCollector {
        /**
         * Manually trigger garbage collection
         */
        run(): void;

        /**
         * Set GC threshold
         * @param threshold New threshold (bytes)
         */
        setThreshold(threshold: number): void;

        /**
         * Get current GC threshold
         * @returns Current threshold (bytes)
         */
        getThreshold(): number;
    }

    /**
     * Engine version info
     */
    export interface EngineVersions {
        /** QuickJS engine version */
        quickjs: string;
        /** txiki.js version */
        tjs: string;
        /** libuv version */
        uv: string;
        /** SQLite3 version */
        sqlite3: string;
        /** zlib version */
        zlib: string;
        /** OpenSSL version */
        openssl: string;
        /** libcurl version */
        curl: string;
        /** Expat XML parser version */
        expat: string;
        /** llhttp parser version */
        llhttp: string;

        /** If compiled with WAMR */
        wasm3?: string;
        /** If compiled with mimalloc (number) */
        mimalloc?: number;
        /** If compiled with brotil */
        brotli?: string;

        /** Core circu.js version */
        core: string;
    }

    /**
     * Set engine memory limit
     * @param limit Memory limit (bytes)
     */
    export function setMemoryLimit(limit: number): void;

    /**
     * Set engine max stack size
     * @param size Stack size (bytes)
     */
    export function setMaxStackSize(size: number): void;

    /**
     * Temporarily allow or disallow Atomics.wait on this runtime.
     * Main thread defaults to false; set true inside debug pause loop.
     */
    export function setCanBlock(val: boolean): void;

    /**
     * Execute JavaScript code, defaults to module mode
     * @param code Code to compile
     * @param moduleName Module name (for error messages)
     * @param flags Compile options, default `EVAL_MODULE`
     * @returns Compiled bytecode
     */
    export function eval<T = unknown>(code: string, moduleName: string, flags?: number): T | globalThis.Promise<T>;

    /**
     * Serialize a QuickJS object or bytecode-bearing value with `JS_WriteObject`.
     *
     * The default flag is `DUMP_DEFAULT` (`DUMP_BYTECODE | DUMP_DEEP`).
     * `DUMP_LOCAL` permits SharedArrayBuffer serialization and should only be
     * used when the deserializer runs in the same trusted runtime lifetime.
     *
     * @param obj Object to serialize
     * @param flag Serialize options, default `DUMP_DEFAULT`
     * @returns Serialized bytecode
     */
    export function serialize(obj: unknown, flag?: number): Uint8Array;

    /**
     * Deserialize data produced by `serialize()` or `Module.dump()`.
     *
     * If the bytecode contains a module, the native result is wrapped as a
     * `Module` instance. Function bytecode and ordinary objects are returned as
     * their native QuickJS values.
     *
     * @param bytecode Serialized bytecode
     * @returns Deserialized object
     */
    export function deserialize<T = unknown>(bytecode: Uint8Array): T;

    /**
     * Run a value previously compiled with `eval(..., EVAL_COMPILE_ONLY)`
     * (optionally round-tripped through `serialize()`/`deserialize()`).
     * Works for both global/script and module compiled values — the module
     * case is the same mechanism `Module.eval()` uses internally, exposed
     * generically for plain (non-Module) compiled bytecode.
     *
     * The passed value is consumed; do not reuse it after calling this.
     *
     * @param compiled A compile-only result from `eval()` or `deserialize()`
     * @returns The script's completion value, or a Promise for async/module code
     */
    export function evalCompiled<T = unknown>(compiled: unknown): T | globalThis.Promise<T>;

    /**
     * Garbage collector control module
     */
    export const gc: GarbageCollector;

    /**
     * Engine version info
     */
    export const versions: EngineVersions;


    /**
     * Encode a string as UTF-8 using the engine's native helper.
     * @param str Text
     */
    export function encodeString(str: string): Uint8Array;

    /**
     * Copy UTF-8 text or bytes into a SharedArrayBuffer-backed Uint8Array.
     * The returned view has a private trailing NUL guard and is safe to pass
     * through MessagePipe without cloning its payload.
     */
    export function toSharedBytes(value: string | globalThis.Uint8Array | ArrayBuffer): globalThis.Uint8Array<SharedArrayBuffer>;

    /**
     * Decode UTF-8 bytes using the engine's native helper.
     * @param buffer Buffer containing text
     */
    export function decodeString(buffer: globalThis.Uint8Array | ArrayBufferLike): string;

    /**
     * Encode a string as native UTF-16 code units.
     * @param str Text
     */
    export function encodeU16String(str: string): Uint16Array;

    /**
     * Decode native UTF-16 code units.
     * 
     * **Note** circu.js supports Uint8Array but not recommended
     * @param buffer Buffer containing text
     */
    export function decodeU16String(buffer: Uint16Array | ArrayBuffer): string;

    /**
     * Low-level QuickJS module wrapper.
     *
     * `Module` exposes native `JSModuleDef` behavior directly. Keep instances
     * alive while using `namespace`, `meta`, or dumped bytecode derived from
     * them.
     */
    export class Module {
        /**
         * Create a new C module instance
         */
        static create(name: string): Module;

        /**
         * (Recommended, QJS-ng best practice)
         * Create module and add object properties to exports
         */
        static from(name: string, object: Record<string, any>): Module;

        /**
         * Compile module source as an ES module.
         *
         * The module is compiled only. Call `resolve()` to link dependencies or
         * `eval()` to resolve and evaluate it.
         */
        constructor(content: string | globalThis.Uint8Array | ArrayBuffer, filename: string);

        /**
         * Get module (JSModuleDef) pointer address
         */
        get ptr(): number | bigint;

        /**
         * Get module's import.meta object
         */
        get meta(): ImportMeta;

        /**
         * Get the live module namespace object.
         *
         * This is a native namespace reference. Do not shallow-copy it to keep a
         * module alive; keep the `Module` instance reachable instead.
         */
        get namespace(): Record<string, unknown>;

        /**
         * Export module as bytecode
         * @param flag Serialize options, default `DUMP_DEFAULT`
         */
        dump(flag?: number): ArrayBuffer;

        /**
         * Resolve dependencies, initialize `import.meta`, and evaluate as a
         * module.
         */
        eval(): Promise<any>;

        /**
         * Start resolving dependencies. Throws on error
         */
        resolve(): void;

        /**
         * (For modules created with `from`) Add export member
         * @param name Export member name
         * @param value Export member value
         */
        export(name: string, value: unknown): void;

        /**
         * (For `from` created modules and `export` added members) Remove export member
         * NOTE: If referenced by other modules, won't disappear. Only for unused elements
         * @param name Export member name
         */
        unref(name: string): void;
    }

    /**
     * Replace VM module hooks for this runtime.
     *
     * These hooks are replacement hooks, not append-only listeners. Installing
     * a new loader/resolver/init/attr checker overwrites the previous one.
     *
     * @param options Options object
     */
    export function onModule(options: {
        /**
         * Module loader function.
         *
         * Return source text or a native `Module` instance.
         */
        load?: (resolvedName: string) => Module | string;

        /**
         * Module resolver function
         * NOTE: qjs-ng supports import attributes, get from `attr` parameter
         */
        resolve?: (name: string, parent: string, attr: Record<string, unknown>) => string;

        /**
         * Module initialization function
         */
        init?: (name: string, importMeta: Record<string, unknown>) => void;

        /**
         * Import attribute check function
         * Only checks support, full validation should be in `resolve`
         */
        attrchk?: (attr: Record<string, unknown>) => void;
    }): void;

    /**
     * Replace the runtime event handler.
     *
     * Return true to mark handled, otherwise runtime may process the event
     * itself (for example, exit behavior). Only one handler is active.
     */
    export function onEvent(cb:
        <T extends EventType>(eventName: T, eventData: GlobalEvents[T]) => boolean
    ): void;

    /**
     * Get/Set Promise hook
     */
    export function promiseHook(): PromiseHookFn;
    export function promiseHook(hook: PromiseHookFn): void;

    /**
     * Inspect a Promise without awaiting it.
     *
     * Returns `null` for pending promises, returns the fulfillment value for
     * fulfilled promises, and throws the rejection reason for rejected promises.
     *
     * @param promise Promise to inspect
     */
    export function promiseResult<T>(promise: globalThis.Promise<T>): T | null;

    /**
     * Check if value is ArrayBuffer
     * @param value Value to check
     * @returns true if value is ArrayBuffer
     */
    export function isArrayBuffer(value: unknown): boolean;

    /**
     * Check whether a value is a Proxy without invoking any proxy traps.
     */
    export function isProxy(value: unknown): boolean;
    export function isDataView(value: unknown): boolean;
    export function isAsyncFunction(value: unknown): boolean;
    export function isArgumentsObject(value: unknown): boolean;
    export function isGeneratorFunction(value: unknown): boolean;
    export function isGeneratorObject(value: unknown): boolean;
    export function isMapIterator(value: unknown): boolean;
    export function isSetIterator(value: unknown): boolean;
    export function isModuleNamespaceObject(value: unknown): boolean;
    export function isDate(value: unknown): boolean;
    export function isError(value: unknown): boolean;
    export function isMap(value: unknown): boolean;
    export function isPromise(value: unknown): boolean;
    export function isRegExp(value: unknown): boolean;
    export function isSet(value: unknown): boolean;
    export function isWeakMap(value: unknown): boolean;
    export function isWeakRef(value: unknown): boolean;
    export function isWeakSet(value: unknown): boolean;

    /**
     * Detach an ArrayBuffer synchronously.
     *
     * The native function returns `undefined`; it does not create or await a
     * Promise.
     *
     * @param buffer ArrayBuffer to detach
     */
    export function detachArrayBuffer(buffer: ArrayBuffer): void;

    /**
     * **DANGEROUS** pseudo-sync wait for a Promise.
     *
     * This repeatedly enters the libuv loop (`UV_RUN_ONCE`) until the Promise
     * settles, `abortCheck` returns true, the loop is exhausted, or the native
     * iteration guard trips. It can re-enter I/O callbacks and jobs while the
     * current JavaScript stack is still active, so it is only appropriate for
     * carefully controlled bootstrap/debug paths.
     *
     * Rejected promises throw their rejection reason. If `abortCheck` throws,
     * that exception is rethrown. If `abortCheck` returns true before
     * settlement, `waitIO aborted` is thrown.
     *
     * @example
     * const engine = import.meta.use('engine');
     * const fs = import.meta.use('asyncfs');
     *
     * // Bootstrap-only bridge from async native I/O to sync setup code.
     * const data = engine.waitIO(fs.readFile('/etc/hosts'));
     *
     * @param prom Promise with any IO behavior
     * @param abortCheck Optional function called each iteration; return true to abort
     */
    export function waitIO<T>(prom: globalThis.Promise<T>, abortCheck?: () => boolean): T;

    /**
     * Make an ArrayBuffer immutable (neutered/transfer semantics)
     * @param buffer ArrayBuffer to make immutable
     * @param immutable Whether to make it immutable
     */
    export function setImmutableArrayBuffer(buffer: ArrayBuffer, immutable: boolean): void;

    /**
     * Get global lexical scope variables
     */
    export function getGlobalLexVar(): Record<string | symbol | number, any>;

    /**
     * Isolated JavaScript context within the same runtime.
     * Each Sandbox has its own global scope; variables and modules
     * in one sandbox cannot pollute another or the main context.
     *
     * @example
     * const engine = import.meta.use('engine');
     * const sb = new engine.Sandbox();
     * sb.call('var x = 42');
     * sb.call('x'); // 42
     */
    export class Sandbox {
        /**
         * Create a new isolated context
         */
        constructor();

        /**
         * Evaluate code in the sandbox context (global scope)
         * @param code JavaScript code to execute
         * @param name Optional filename for stack traces
         * @returns Result of evaluation
         */
        call<T = any>(code: string, name?: string): T;

        /**
         * Compile and evaluate an ES module in the sandbox context
         * @param code Module source code
         * @param name Module name (for stack traces and import resolution)
         * @returns Module namespace object
         */
        loadModule<T = Record<string, any>>(code: string, name: string): T;

        /**
         * Initialize global object for Sandbox.
         * By default, there is nothing in Sandbox global.
         * 
         * @throws {TypeError} Throw an error if already initialized
         */
        initGlobal(types?: IntrinsicFeature[]): void;

        /**
         * The sandbox's global object
         */
        get global(): Record<string, any> & typeof globalThis;
    }
}
