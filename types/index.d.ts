/**
 * circu.js dynamic module type definitions
 */

interface TjsModules {
    dns: typeof CModuleDNS,
    engine: typeof CModuleEngine,
    error: typeof CModuleError,
    ffi: typeof CModuleFFI,
    asyncfs: typeof CModuleAsyncFS,
    fs: typeof CModuleFS,
    fswatch: typeof CModuleFSWatch,
    bjson: typeof CModuleBJSON,
    os: typeof CModuleOS,
    process: typeof CModuleProcess,
    sqlite3: typeof CModuleSQLite3,
    streams: typeof CModuleStreams,
    timers: typeof CModuleTimers,
    udp: typeof CModuleUDP,
    worker: typeof CModuleWorker,
    crypto: typeof CModuleCrypto,
    console: typeof CModuleConsole,
    debug: typeof CModuleDebug,
    zlib: typeof CModuleZLib,
    sourcemap: typeof CModuleSourceMap,
    ssl: typeof CModuleSSL,
    xml: typeof CModuleXML,
    algorithm: typeof CModuleAlgorithm,
    text: typeof CModuleText,
    http: typeof CModuleHTTP,
    socket: typeof CModuleSocket,
    curl: typeof CModuleCURL,
}

interface TJSOptionalModules {
    'wasm': typeof CModuleWASM,
    'win32': typeof CModuleWin32,
    'signals': typeof CModuleSignals,
    'nodeapi': typeof CModuleNodeApi,
}

interface UseFN {
    /**
     * Load a built-in module by name
     *
     * @param name The name of the module to load (e.g. "fs", "dns")
     * @returns The corresponding module object
     */
    <K extends keyof TjsModules>(name: K): TjsModules[K];

    /**
     * Load an optional or context-limited built-in module by name.
     * Returns `null` when the current build or platform does not provide it.
     * Also returns `null` in workers for modules marked not worker-safe by the
     * native module table, such as `signals`, `nodeapi`, and `wasm`.
     * @param name The name of the module to load (e.g. "wasm" or "signals")
     * @returns The corresponding module object or null if module not found
     */
    <K extends keyof TJSOptionalModules>(name: K): TJSOptionalModules[K] | null;

    /**
     * Module not found, upgrade your circu.js type definitions?
     */
    (name: string): null;
}

interface ImportMeta {
    /**
     * Load a built-in module by name
     * **NOTE** unusable if you enabled `CJS_USE_SYMBOL_INTERNAL`
     */
    use: UseFN;

    /**
     * The names of all built-in modules available to this program
     */
    module: Array<keyof TjsModules | keyof TJSOptionalModules>;

    /**
     * Register an external native module (.so/.dll) so it can be loaded by name via `use()`.
     * Only available in bootstrap (bytecode) context; not exposed to regular user modules.
     * @param name  Short name used later with `use(name)`
     * @param path  Filesystem path to the native library
     * @throws If `name` shadows a built-in, is already registered, or arguments are missing
     */
    register(name: string, path: string): void;
}
