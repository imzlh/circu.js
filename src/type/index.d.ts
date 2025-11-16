/**
 * circu.js dynamic module type definitions
 */

interface TjsModules {
    dns: typeof CModuleDNS,
    engine: typeof CModuleEngine,
    error: typeof CModuleError,
    ffi: typeof CModuleFFI,
    fs: typeof CModuleFS,
    fswatch: typeof CModuleFSWatch,
    os: typeof CModuleOS,
    process: typeof CModuleProcess,
    pty: typeof CModulePty,
    server: typeof CModuleServer,
    signal: typeof CModuleSignals,
    sqlite3: typeof CModuleSQLite3,
    streams: typeof CModuleStreams,
    sys: typeof CModuleSys,
    timers: typeof CModuleTimers,
    udp: typeof CModuleUDP,
    worker: typeof CModuleWorker,
    crypto: typeof CModuleCrypto,
    console: typeof CModuleConsole,
    zlib: typeof CModuleZLib
}

interface TjsPosixModules {
    'posix-ffi': typeof CModulePosixFFI,
    'posix-socket': typeof CModulePosixSocket
}

interface ImportMeta {
    /**
     * Load a built-in module by name
     * @param name The name of the module to load (e.g. "fs", "dns")
     * @returns The corresponding module object
     */
    use<K extends keyof TjsModules>(name: K): TjsModules[K];

    /**
     * Load a built-in module by name
     * return `null` if not running in posix os, eg, windows
     * @param name The name of the module to load (e.g. "posix-ffi")
     * @returns The corresponding module object or null if module not found
     */
    use<K extends keyof TjsPosixModules>(name: K): TjsPosixModules[K] | null;

    /**
     * Module not found, upgrade your circu.js type definitions?
     */
    use(name: string): null;
}