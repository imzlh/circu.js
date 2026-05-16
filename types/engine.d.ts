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
    type Promise = globalThis.Promise<any>;
    type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;   // not shared

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

    export enum PromiseState {
        CONSTRUCT,
        BEFORE_THEN,
        AFTER_THEN,
        FULFILLED
    }

    export enum EventType {
        PROMISE = 0,
        UNHANDLED_REJECTION,
        JOB_EXCEPTION,
        EXIT,
        LOAD
    }

    interface GlobalEvents {
        [EventType.PROMISE]: [this: Promise, error: Error | any],
        [EventType.EXIT]: number,
        [EventType.UNHANDLED_REJECTION]: [this: Promise, state: PromiseState, parent: Promise],
        [EventType.JOB_EXCEPTION]: Error | unknown,
        [EventType.LOAD]: undefined
    }

    /**
     * Garbage collector module
     */
    interface GarbageCollector {
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
    interface EngineVersions {
        /** QuickJS engine version */
        quickjs: string;
        /** txiki.js version */
        tjs: string;
        /** libuv version */
        uv: string;
        /** libcurl version */
        curl: string;
        /** SQLite3 version */
        sqlite3: string;
        /** zlib version */
        zlib: string;
        /** OpenSSL version */
        openssl: string;
        /** Expat XML parser version */
        expat: string;

        /** If compiled with llhttp */
        llhttp?: string;
        /** If compiled with wasm3 */
        wasm3?: string;
        /** If compiled with mimalloc (number) */
        mimalloc?: number;

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
     * Execute JavaScript code, defaults to module mode
     * @param code Code to compile
     * @param moduleName Module name (for error messages)
     * @param flags Compile options, default `EVAL_MODULE`
     * @returns Compiled bytecode
     */
    export function eval<T = any>(code: string, moduleName: string, flags?: number): { value: T } | globalThis.Promise<{ value: T }>;

    /**
     * Serialize JavaScript object to bytecode
     * @param obj Object to serialize
     * @param flag Serialize options, default `DUMP_DEFAULT`
     * @returns Serialized bytecode
     */
    export function serialize(obj: any, flag?: number): Uint8Array;

    /**
     * Deserialize bytecode to JavaScript object
     * @param bytecode Serialized bytecode
     * @returns Deserialized object
     */
    export function deserialize<T = any>(bytecode: Uint8Array): T;

    /**
     * Garbage collector control module
     */
    export const gc: GarbageCollector;

    /**
     * Engine version info
     */
    export const versions: EngineVersions;


    /**
     * Like `new TextEncoder().encode(str)`
     * Encode to buffer
     * @param str Text
     */
    export function encodeString(str: string): Uint8Array;

    /**
     * Like `new TextDecoder().decode(buffer)` 
     * Decode to text
     * @param buffer Buffer containing text
     */
    export function decodeString(buffer: Uint8Array | ArrayBuffer): string;

    /**
     * Like `new TextEncoder('utf-16').encode(str)`
     * Encode to buffer (Uint16Array, 2 bytes per char)
     * @param str Text
     */
    export function encodeU16String(str: string): Uint16Array;

    /**
     * Like `new TextDecoder('utf-16').decode(buffer)` 
     * Decode to text
     * 
     * **Note** circu.js supports Uint8Array but not recommended
     * @param buffer Buffer containing text
     */
    export function decodeU16String(buffer: Uint16Array | ArrayBuffer): string;

    /**
     * (Unsafe, use with caution) Module class
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
         * Compile module content
         */
        constructor(content: string, filename: string);

        /**
         * Get module (JSModuleDef) pointer address
         */
        get ptr(): number | bigint;

        /**
         * Get module's import.meta object
         */
        get meta(): ImportMeta;

        /**
         * Get module exports. Equivalent to `await import(mod.name)`
         */
        get namespace(): Record<string, any>;

        /**
         * Export module as bytecode
         * @param flag Serialize options, default `DUMP_DEFAULT`
         */
        dump(flag?: number): ArrayBuffer;

        /**
         * Execute as module
         */
        eval(): Promise;

        /**
         * Start resolving dependencies. Throws on error
         */
        resolve(): void;

        /**
         * (For modules created with `from`) Add export member
         * @param name Export member name
         * @param value Export member value
         */
        export(name: string, value: any): void;

        /**
         * (For `from` created modules and `export` added members) Remove export member
         * NOTE: If referenced by other modules, won't disappear. Only for unused elements
         * @param name Export member name
         */
        unref(name: string): void;
    }

    /**
     * Set VM module options
     * @param options Options object
     */
    export function onModule(options: {
        /**
         * Module loader function
         */
        load?: (resolvedName: string) => Module | string;

        /**
         * Module resolver function
         * NOTE: qjs-ng supports import attributes, get from `attr` parameter
         */
        resolve?: (name: string, parent: string, attr: Record<string, any>) => string;

        /**
         * Module initialization function
         */
        init?: (name: string, importMeta: Record<string, any>) => void;

        /**
         * Import attribute check function
         * Only checks support, full validation should be in `resolve`
         */
        attrchk?: (attr: Record<string, any>) => void;
    }): void;

    /**
     * Event handler. Return true to mark handled, otherwise runtime may process (e.g. exit)
     */
    export function onEvent(cb:
        <T extends EventType>(eventName: T, eventData: GlobalEvents[T]) => boolean
    ): void;

    /**
     * Get Promise result directly. Returns null if Promise not settled
     * @param promise Promise to inspect
     */
    export function promiseResult<T>(promise: globalThis.Promise<T>): T | null;

    /**
     * Check if value is ArrayBuffer
     * @param value Value to check
     * @returns true if value is ArrayBuffer
     */
    export function isArrayBuffer(value: any): boolean;

    /**
     * Detach ArrayBuffer
     * @param buffer ArrayBuffer to detach
     * @returns Promise that resolves when detached
     */
    export function detachArrayBuffer(buffer: ArrayBuffer): globalThis.Promise<void>;

    /**
     * **DANGEROUS** Pseudo-sync wait for Promise. Converts async IO to sync IO, may have mutex issues
     * @param prom Promise with any IO behavior
     */
    export function waitPromise<T>(prom: globalThis.Promise<T>): T;
}
