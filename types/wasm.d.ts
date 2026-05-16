/**
 * WebAssembly low-level bindings for txiki.js
 * Loaded via import.meta.use('wasm')
 *
 * This is a low-level API that directly exposes WAMR capabilities.
 * Unlike the standard WebAssembly JS API, this requires manual import resolution.
 *
 * @example
 * const wasm = import.meta.use('wasm');
 *
 * // Parse module
 * const module = wasm.parseModule(bytes);
 *
 * // Get imports info
 * const imports = wasm.moduleImports(module);
 *
 * // Resolve function imports
 * const importDescs = imports.map(imp => ({
 *     module: imp.module,
 *     name: imp.name,
 *     func: myImportFunc
 * }));
 * wasm.resolveImports(module, importDescs);
 *
 * // Set WASI options (optional)
 * wasm.setWasiOptions(module, ['arg1', 'arg2'], { ENV_VAR: 'value' }, { '/guest': '/host' });
 *
 * // Build instance
 * const instance = wasm.buildInstance(module);
 *
 * // Call exported function
 * const result = instance.callFunction('exportedFunc', arg1, arg2);
 */
declare namespace CModuleWASM {
    // Error types
    type WasmErrorName = 'CompileError' | 'LinkError' | 'RuntimeError' | 'RangeError';

    /**
     * Module object - represents a parsed WebAssembly module
     * Created via parseModule(), not a constructor
     */
    interface Module {
        /** Opaque handle - do not access directly */
        readonly _opaque: unique symbol;
    }

    /**
     * Instance object - represents a WebAssembly instance
     * Created via buildInstance(), not a constructor
     */
    interface Instance {
        /**
         * Call an exported function by name
         * @param name The exported function name
         * @param args Arguments to pass to the function
         * @returns The function result (or array of results for multi-return)
         */
        callFunction(name: string, ...args: WasmValue[]): WasmValue | WasmValue[];

        /** Opaque handle - do not access directly */
        readonly _opaque: unique symbol;
    }

    // WebAssembly value types
    type WasmValue = number | bigint;

    // Export descriptor from moduleExports()
    interface ModuleExportDescriptor {
        name: string;
        kind: 'function' | 'table' | 'memory' | 'global';
    }

    // Import descriptor from moduleImports()
    interface ModuleImportDescriptor {
        module: string;
        name: string;
        kind: 'function' | 'table' | 'memory' | 'global';
    }

    // Import function descriptor for resolveImports()
    interface ImportFunctionDescriptor {
        module: string;
        name: string;
        func: (...args: WasmValue[]) => WasmValue | void;
    }

    // Global import descriptor for resolveGlobalImports()
    interface GlobalImportDescriptor {
        module: string;
        name: string;
        value: number | bigint;
        type: 'i32' | 'i64' | 'f32' | 'f64';
        mutable: boolean;
    }

    // Table import descriptor for resolveTableImports()
    interface TableImportDescriptor {
        module: string;
        name: string;
        element: 'funcref' | 'externref';
        initial: number;
        maximum?: number;
    }

    // Memory import descriptor for resolveMemoryImports()
    interface MemoryImportDescriptor {
        module: string;
        name: string;
        initial: number;
        maximum?: number;
    }

    // Global info from getGlobalInfo()
    interface GlobalInfo {
        type: 'i32' | 'i64' | 'f32' | 'f64' | 'externref' | 'funcref' | 'unknown';
        mutable: boolean;
    }

    // Table info from getTableInfo()
    interface TableInfo {
        element: 'funcref' | 'externref' | 'unknown';
        cur_size: number;
        max_size: number;
    }

    // WASI environment variables
    interface WasiEnv {
        [key: string]: string;
    }

    // WASI preopens (directory mappings)
    interface WasiPreopens {
        [guestPath: string]: string;
    }

    // ============================================
    // Module functions
    // ============================================

    /**
     * Parse a WebAssembly binary into a Module
     * @param buffer ArrayBuffer or TypedArray containing WASM binary
     * @returns Parsed Module object
     * @throws CompileError if parsing fails
     */
    function parseModule(buffer: ArrayBuffer | ArrayBufferView): Module;

    /**
     * Get list of exports from a Module
     * @param module The Module to inspect
     * @returns Array of export descriptors
     */
    function moduleExports(module: Module): ModuleExportDescriptor[];

    /**
     * Get list of imports from a Module
     * @param module The Module to inspect
     * @returns Array of import descriptors
     */
    function moduleImports(module: Module): ModuleImportDescriptor[];

    /**
     * Resolve function imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param importDescs Array of import function descriptors
     * @throws LinkError if resolution fails
     */
    function resolveImports(module: Module, importDescs: ImportFunctionDescriptor[]): void;

    /**
     * Resolve global imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param globalDescs Array of global import descriptors
     * @throws LinkError if resolution fails
     */
    function resolveGlobalImports(module: Module, globalDescs: GlobalImportDescriptor[]): void;

    /**
     * Resolve table imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param tableDescs Array of table import descriptors
     * @throws LinkError if resolution fails
     * @throws TypeError if element type is invalid
     * @throws RangeError if size constraints are invalid
     */
    function resolveTableImports(module: Module, tableDescs: TableImportDescriptor[]): void;

    /**
     * Resolve memory imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param memoryDescs Array of memory import descriptors
     * @throws LinkError if resolution fails
     * @throws RangeError if size constraints are invalid
     */
    function resolveMemoryImports(module: Module, memoryDescs: MemoryImportDescriptor[]): void;

    /**
     * Set WASI options for a Module
     * Must be called before buildInstance()
     * @param module The Module to set WASI options for
     * @param args Command-line arguments (argv)
     * @param env Environment variables
     * @param preopens Directory mappings { guestPath: hostPath }
     */
    function setWasiOptions(
        module: Module,
        args: string[],
        env: WasiEnv | null,
        preopens: WasiPreopens | null
    ): void;

    /**
     * Build an Instance from a Module
     * Requires resolveImports() and setWasiOptions() to be called first if needed
     * @param module The Module to instantiate
     * @returns New Instance object
     * @throws LinkError if instantiation fails
     */
    function buildInstance(module: Module): Instance;

    /**
     * Validate a WebAssembly binary
     * @param buffer ArrayBuffer or TypedArray containing WASM binary
     * @returns true if valid, false otherwise
     */
    function validate(buffer: ArrayBuffer | ArrayBufferView): boolean;

    // ============================================
    // Instance functions
    // ============================================

    /**
     * Get the memory buffer from an Instance
     * @param instance The Instance to get memory from
     * @returns ArrayBuffer backed by WASM linear memory
     * @throws RuntimeError if no memory instance
     */
    function getMemoryBuffer(instance: Instance): ArrayBuffer;

    /**
     * Grow the memory of an Instance
     * @param instance The Instance to grow memory for
     * @param delta Number of pages to grow (65536 bytes per page)
     * @returns Previous page count, or -1 on failure
     * @throws RuntimeError if no memory instance
     */
    function growMemory(instance: Instance, delta: number): number;

    /**
     * Get a global value from an Instance
     * @param instance The Instance to get global from
     * @param name The exported global name
     * @returns The global value
     * @throws RuntimeError if global not found
     */
    function getGlobal(instance: Instance, name: string): WasmValue;

    /**
     * Set a global value on an Instance
     * @param instance The Instance to set global on
     * @param name The exported global name
     * @param value The new value
     * @throws RuntimeError if global not found
     * @throws TypeError if global is immutable
     */
    function setGlobal(instance: Instance, name: string, value: WasmValue): void;

    /**
     * Get info about a global in an Instance
     * @param instance The Instance to inspect
     * @param name The exported global name
     * @returns Global info object
     * @throws RuntimeError if global not found
     */
    function getGlobalInfo(instance: Instance, name: string): GlobalInfo;

    // ============================================
    // Table functions
    // ============================================

    /**
     * Get info about a table in an Instance
     * @param instance The Instance to inspect
     * @param name The exported table name
     * @returns Table info object
     * @throws RuntimeError if table not found
     */
    function getTableInfo(instance: Instance, name: string): TableInfo;

    /**
     * Get the size of a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @returns Current table size
     * @throws RuntimeError if table not found
     */
    function tableSize(instance: Instance, name: string): number;

    /**
     * Get an element from a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @param index The element index
     * @returns For funcref: function index (number) or null; For externref: JS value
     * @throws RuntimeError if table not found
     * @throws RangeError if index out of bounds
     */
    function tableGet(instance: Instance, name: string, index: number): number | null | unknown;

    /**
     * Set an element in a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @param index The element index
     * @param value For funcref: function index (number) or null; For externref: JS value
     * @throws RuntimeError if table not found
     * @throws RangeError if index out of bounds
     */
    function tableSet(instance: Instance, name: string, index: number, value: number | null | unknown): void;

    /**
     * Grow a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @param delta Number of elements to grow
     * @returns Previous table size, or -1 on failure
     * @throws RuntimeError if table not found
     */
    function tableGrow(instance: Instance, name: string, delta: number): number;

    // ============================================
    // Function index functions (for funcref tables)
    // ============================================

    /**
     * Get the function index by export name
     * @param instance The Instance to query
     * @param name The exported function name
     * @returns Function index, or -1 if not found
     */
    function getFuncIndex(instance: Instance, name: string): number;

    /**
     * Call a function by index (for funcref table entries)
     * @param instance The Instance containing the function
     * @param funcIndex The function index
     * @param args Arguments to pass
     * @returns Function result
     * @throws RuntimeError if function index out of bounds
     */
    function callFuncByIndex(instance: Instance, funcIndex: number, ...args: WasmValue[]): WasmValue | WasmValue[];
}
