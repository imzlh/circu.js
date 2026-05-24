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
    os: typeof CModuleOS,
    process: typeof CModuleProcess,
    signals: typeof CModuleSignals,
    sqlite3: typeof CModuleSQLite3,
    streams: typeof CModuleStreams,
    timers: typeof CModuleTimers,
    udp: typeof CModuleUDP,
    worker: typeof CModuleWorker,
    crypto: typeof CModuleCrypto,
    console: typeof CModuleConsole,
    zlib: typeof CModuleZLib,
    sourcemap: typeof CModuleSourceMap,
    ssl: typeof CModuleSSL,
    xml: typeof CModuleXML,
    jsonc: typeof CModuleJsonC,
    algorithm: typeof CModuleAlgorithm,
    text: typeof CModuleText,
    http: typeof CModuleHTTP,
    socket: typeof CModuleSocket
}

interface TJSOptionalModules {
    'wasm': typeof CModuleWASM,
    'curl': typeof CModuleCURL,
    'win32': typeof CModuleWin32,
}

interface UseFN {
    /**
     * Load a built-in module by name
     * @param name The name of the module to load (e.g. "fs", "dns")
     * @returns The corresponding module object
     */
    <K extends keyof TjsModules>(name: K): TjsModules[K];

    /**
     * Load a built-in module by name
     * return `null` if not running in posix os, eg, windows
     * @param name The name of the module to load (e.g. "posix-ffi")
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
     * Only available in bootstrap (bytecode) context — not exposed to regular user modules.
     * @param name  Short name used later with `use(name)`
     * @param path  Filesystem path to the native library
     * @throws If `name` shadows a built-in, is already registered, or arguments are missing
     */
    register(name: string, path: string): void;
}