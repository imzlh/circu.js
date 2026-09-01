/**
 * WebAssembly low-level bindings for txiki.js
 * Loaded via import.meta.use('wasm')
 *
 * This is a low-level API that directly exposes WAMR capabilities.
 * Unlike the standard WebAssembly JS API, this requires manual import resolution.
 *
 * @example
 * const wasm = import.meta.use('wasm');
 * if (!wasm) throw new Error('wasm module is unavailable');
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
    export type WasmErrorName = 'CompileError' | 'LinkError' | 'RuntimeError' | 'RangeError';

    /**
     * Module object - represents a parsed WebAssembly module
     * Created via parseModule(), not a constructor
     */
    export interface Module {
        /** Opaque handle - do not access directly */
        readonly _opaque: unique symbol;
    }

    /**
     * Instance object - represents a WebAssembly instance
     * Created via buildInstance(), not a constructor
     */
    export interface Instance {
        /**
         * Call an exported function by name
         * @param name The exported function name
         * @param args Arguments to pass to the function
         * @returns The function result (or array of results for multi-return)
         */
        callFunction(name: string, ...args: WasmFunctionArgument[]): WasmFunctionResult;

        /** Opaque handle - do not access directly */
        readonly _opaque: unique symbol;
    }

    // WebAssembly value types
    export type WasmValue = number | bigint;
    export type WasmExternRef = null | undefined | object | string | number | boolean | bigint | symbol;
    export type WasmFunctionArgument = WasmValue | WasmExternRef;
    export type WasmFunctionResult = WasmValue | WasmExternRef | WasmFunctionResult[] | undefined;
    export type WasmGlobalValue = WasmValue | WasmExternRef | ArrayBuffer | ArrayBufferView;
    export type WasmTableValue = number | null | WasmExternRef;

    // Export descriptor from moduleExports()
    export interface ModuleExportDescriptor {
        name: string;
        kind: 'function' | 'table' | 'memory' | 'global';
    }

    // Import descriptor from moduleImports()
    export interface ModuleImportDescriptor {
        module: string;
        name: string;
        kind: 'function' | 'table' | 'memory' | 'global';
    }

    // Import function descriptor for resolveImports()
    export interface ImportFunctionDescriptor {
        module: string;
        name: string;
        func: (...args: WasmFunctionArgument[]) => WasmFunctionResult | void;
    }

    // Global import descriptor for resolveGlobalImports()
    export interface GlobalImportDescriptor {
        module: string;
        name: string;
        value: number | bigint;
        type: 'i32' | 'i64' | 'f32' | 'f64';
        mutable: boolean;
    }

    // Table import descriptor for resolveTableImports()
    export interface TableImportDescriptor {
        module: string;
        name: string;
        element: 'funcref' | 'externref';
        initial: number;
        maximum?: number;
    }

    // Memory import descriptor for resolveMemoryImports()
    export interface MemoryImportDescriptor {
        module: string;
        name: string;
        initial: number;
        maximum?: number;
    }

    // Global info from getGlobalInfo()
    export interface GlobalInfo {
        type: 'i32' | 'i64' | 'f32' | 'f64' | 'externref' | 'funcref' | 'unknown';
        mutable: boolean;
    }

    // Table info from getTableInfo()
    export interface TableInfo {
        element: 'funcref' | 'externref' | 'unknown';
        cur_size: number;
        max_size: number;
    }

    // WASI environment variables
    export interface WasiEnv {
        [key: string]: string;
    }

    // WASI preopens (directory mappings)
    export interface WasiPreopens {
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
    export function parseModule(buffer: ArrayBuffer | ArrayBufferView): Module;

    /**
     * Get the content of a custom section by name
     * @param module The Module to inspect
     * @param sectionName The name of the custom section
     * @returns Every matching section content in module order
     */
    export function moduleCustomSections(module: Module, sectionName: string): ArrayBuffer[];

    /**
     * Get list of exports from a Module
     * @param module The Module to inspect
     * @returns Array of export descriptors
     */
    export function moduleExports(module: Module): ModuleExportDescriptor[];

    /**
     * Get list of imports from a Module
     * @param module The Module to inspect
     * @returns Array of import descriptors
     */
    export function moduleImports(module: Module): ModuleImportDescriptor[];

    /**
     * Resolve function imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param importDescs Array of import function descriptors
     * @throws LinkError if resolution fails
     */
    export function resolveImports(module: Module, importDescs: ImportFunctionDescriptor[]): void;

    /**
     * Resolve global imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param globalDescs Array of global import descriptors
     * @throws LinkError if resolution fails
     */
    export function resolveGlobalImports(module: Module, globalDescs: GlobalImportDescriptor[]): void;

    /**
     * Resolve table imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param tableDescs Array of table import descriptors
     * @throws LinkError if resolution fails
     * @throws TypeError if element type is invalid
     * @throws RangeError if size constraints are invalid
     */
    export function resolveTableImports(module: Module, tableDescs: TableImportDescriptor[]): void;

    /**
     * Resolve memory imports for a Module
     * Must be called before buildInstance()
     * @param module The Module to resolve imports for
     * @param memoryDescs Array of memory import descriptors
     * @throws LinkError if resolution fails
     * @throws RangeError if size constraints are invalid
     */
    export function resolveMemoryImports(module: Module, memoryDescs: MemoryImportDescriptor[]): void;

    /**
     * Set WASI options for a Module
     * Must be called before buildInstance()
     * @param module The Module to set WASI options for
     * @param args Command-line arguments (argv)
     * @param env Environment variables
     * @param preopens Directory mappings { guestPath: hostPath }
     */
    export function setWasiOptions(
        module: Module,
        args: string[] | null,
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
    export function buildInstance(module: Module): Instance;

    /**
     * Validate a WebAssembly binary
     * @param buffer Uint8Array containing WASM binary
     * @returns true if valid, false otherwise
     */
    export function validate(buffer: Uint8Array): boolean;

    /**
     * Set the WAMR execution stack size used by subsequently created instances.
     * Existing instances keep their original stack size.
     * Valid range is 16 KiB through 64 MiB.
     */
    export function setStackSize(bytes: number): void;

    /** Get the WAMR execution stack size used for new instances. */
    export function getStackSize(): number;

    // ============================================
    // Instance functions
    // ============================================

    /**
     * Get the memory buffer from an Instance
     *
     * The returned ArrayBuffer is a live view over WAMR linear memory. It is
     * detached when growMemory() or an internal memory.grow moves the memory.
     * Request a fresh buffer after any call that may grow memory.
     *
     * @param instance The Instance to get memory from
     * @returns ArrayBuffer backed by WASM linear memory
     * @throws RuntimeError if no memory instance
     */
    export function getMemoryBuffer(instance: Instance): ArrayBuffer;

    /**
     * Grow the memory of an Instance
     * @param instance The Instance to grow memory for
     * @param delta Number of pages to grow (65536 bytes per page)
     * @returns Previous page count
     * @throws RuntimeError if no memory instance
     * @throws RangeError if memory cannot grow
     */
    export function growMemory(instance: Instance, delta: number): number;

    /**
     * Get a global value from an Instance
     * @param instance The Instance to get global from
     * @param name The exported global name
     * @returns The global value; externref can be any JS value, v128 is a copied 16-byte Uint8Array
     * @throws RuntimeError if global not found
     */
    export function getGlobal(instance: Instance, name: string): WasmGlobalValue;

    /**
     * Set a global value on an Instance
     * @param instance The Instance to set global on
     * @param name The exported global name
     * @param value The new value
     * @throws RuntimeError if global not found
     * @throws TypeError if global is immutable
     */
    export function setGlobal(instance: Instance, name: string, value: WasmGlobalValue): void;

    /**
     * Get info about a global in an Instance
     * @param instance The Instance to inspect
     * @param name The exported global name
     * @returns Global info object
     * @throws RuntimeError if global not found
     */
    export function getGlobalInfo(instance: Instance, name: string): GlobalInfo;

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
    export function getTableInfo(instance: Instance, name: string): TableInfo;

    /**
     * Get the size of a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @returns Current table size
     * @throws RuntimeError if table not found
     */
    export function tableSize(instance: Instance, name: string): number;

    /**
     * Get an element from a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @param index The element index
     * @returns For funcref: function index (number) or null; For externref: JS value
     * @throws RuntimeError if table not found
     * @throws RangeError if index out of bounds
     */
    export function tableGet(instance: Instance, name: string, index: number): WasmTableValue;

    /**
     * Set an element in a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @param index The element index
     * @param value For funcref: function index (number) or null; For externref: JS value
     * @throws RuntimeError if table not found
     * @throws RangeError if index out of bounds
     */
    export function tableSet(instance: Instance, name: string, index: number, value: WasmTableValue): void;

    /**
     * Grow a table
     * @param instance The Instance containing the table
     * @param name The exported table name
     * @param delta Number of elements to grow
     * @returns Previous table size, or -1 on failure
     * @throws RuntimeError if table not found
     */
    export function tableGrow(instance: Instance, name: string, delta: number): number;

    // ============================================
    // Function index functions (for funcref tables)
    // ============================================

    /**
     * Get the function index by export name
     * @param instance The Instance to query
     * @param name The exported function name
     * @returns Function index, or -1 if not found
     */
    export function getFuncIndex(instance: Instance, name: string): number;

    /**
     * Call a function by index (for funcref table entries)
     * @param instance The Instance containing the function
     * @param funcIndex The function index
     * @param args Arguments to pass
     * @returns Function result
     * @throws RuntimeError if function index out of bounds
     */
    export function callFuncByIndex(instance: Instance, funcIndex: number, ...args: WasmFunctionArgument[]): WasmFunctionResult;
}
