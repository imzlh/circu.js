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
    stream: typeof CModuleStreams,
    sys: typeof CModuleSys,
    timer: typeof CModuleTimer,
    udp: typeof CModuleUDP,
    worker: typeof CModuleWorker,

    'posix-ffi': typeof CModulePosixFFI,
    'posix-socket': typeof CModulePosixSocket,
}

interface ImportMeta {
    /**
     * Load a built-in module by name
     * @param name The name of the module to load (e.g. "fs", "dns")
     * @returns The corresponding module object or null if module not found
     */
    use<K extends keyof TjsModules>(name: K): TjsModules[K];
    use(name: string): null;
}

declare function print(...args: any[]): void;