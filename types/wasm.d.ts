/**
 * WebAssembly API Type Definitions
 * Complete WebAssembly namespace with all standard APIs
 * 
 * @example
 * // Basic usage
 * const wasmCode = new Uint8Array([...]);
 * const module = new WebAssembly.Module(wasmCode);
 * const instance = new WebAssembly.Instance(module);
 * console.log(instance.exports.add(1, 2)); // 3
 */

declare namespace CModuleWASM {
    /**
     * Represents a compiled WebAssembly module
     */
    class Module {
        /**
         * Creates a new WebAssembly module from binary code
         * @param buffer - The binary WebAssembly code
         * @throws {CompileError} If the buffer is not valid WASM
         * 
         * @example
         * const wasmCode = new Uint8Array([0x00, 0x61, 0x73, 0x6d, ...]);
         * const module = new WebAssembly.Module(wasmCode);
         */
        constructor(buffer: ArrayBuffer | ArrayBufferView);

        /**
         * Get all exported items from the module
         * @param module - The module to inspect
         * @returns Array of export descriptors
         * 
         * @example
         * const exports = WebAssembly.Module.exports(module);
         * // [
         * //   { name: "add", kind: "function" },
         * //   { name: "memory", kind: "memory" }
         * // ]
         */
        static exports(module: Module): ModuleExportDescriptor[];

        /**
         * Get all imported items required by the module
         * @param module - The module to inspect
         * @returns Array of import descriptors
         * 
         * @example
         * const imports = WebAssembly.Module.imports(module);
         * // [
         * //   { module: "env", name: "log", kind: "function" }
         * // ]
         */
        static imports(module: Module): ModuleImportDescriptor[];

        /**
         * Get custom sections from the module
         * @param module - The module to inspect
         * @param sectionName - Name of the custom section
         * @returns Array of custom section data
         * 
         * @example
         * const nameSections = WebAssembly.Module.customSections(module, "name");
         */
        static customSections(module: Module, sectionName: string): ArrayBuffer[];

        readonly byteLength: number;
    }

    /**
     * Represents an instantiated WebAssembly module
     */
    class Instance {
        /**
         * Creates a new WebAssembly instance
         * @param module - The compiled module
         * @param importObject - Object containing imported functions/memory/tables/globals
         * @throws {LinkError} If imports cannot be satisfied
         * @throws {RuntimeError} If instantiation fails
         * 
         * @example
         * const module = new WebAssembly.Module(wasmCode);
         * const imports = {
         *   env: {
         *     log: (x: number) => console.log(x)
         *   }
         * };
         * const instance = new WebAssembly.Instance(module, imports);
         * instance.exports.main();
         */
        constructor(module: Module, importObject?: ImportObject);

        /**
         * Exported functions, memory, tables, and globals
         * 
         * @example
         * const add = instance.exports.add as (a: number, b: number) => number;
         * console.log(add(5, 3)); // 8
         */
        readonly exports: Exports;
    }

    /**
     * Represents WebAssembly linear memory
     */
    class Memory {
        /**
         * Creates a new WebAssembly memory
         * @param descriptor - Memory configuration
         * @throws {RangeError} If initial > maximum
         * 
         * @example
         * const memory = new WebAssembly.Memory({ initial: 1, maximum: 10 });
         * const buffer = memory.buffer;
         * const view = new Uint32Array(buffer);
         */
        constructor(descriptor: MemoryDescriptor);

        /**
         * The ArrayBuffer backing this memory
         * 
         * @example
         * const buffer = memory.buffer;
         * const bytes = new Uint8Array(buffer);
         * bytes[0] = 42;
         */
        readonly buffer: ArrayBuffer;

        /**
         * Grow memory by specified number of pages
         * @param delta - Number of pages to add (each page is 64KB)
         * @returns Previous size in pages
         * @throws {RangeError} If growth exceeds maximum
         * 
         * @example
         * const oldPages = memory.grow(1);
         * console.log(oldPages); // 1
         * console.log(memory.buffer.byteLength); // 131072 (2 pages)
         */
        grow(delta: number): number;

        readonly shared?: boolean;
    }

    /**
     * Represents a WebAssembly table
     */
    class Table {
        /**
         * Creates a new WebAssembly table
         * @param descriptor - Table configuration
         * @throws {RangeError} If initial > maximum
         * 
         * @example
         * const table = new WebAssembly.Table({
         *   element: "funcref",
         *   initial: 10,
         *   maximum: 20
         * });
         */
        constructor(descriptor: TableDescriptor);

        /**
         * Current size of the table
         * 
         * @example
         * console.log(table.length); // 10
         */
        readonly length: number;

        /**
         * Get element at index
         * @param index - Table index
         * @returns The element (function or null)
         * @throws {RangeError} If index out of bounds
         * 
         * @example
         * const func = table.get(0);
         * if (func) func();
         */
        get(index: number): Function | null;

        /**
         * Set element at index
         * @param index - Table index
         * @param value - Function or null
         * @throws {RangeError} If index out of bounds
         * @throws {TypeError} If value type mismatch
         * 
         * @example
         * table.set(0, myFunction);
         * table.set(1, null);
         */
        set(index: number, value: Function | null): void;

        /**
         * Grow table by specified number of elements
         * @param delta - Number of elements to add
         * @param init - Initial value for new elements (default: null)
         * @returns Previous size
         * @throws {RangeError} If growth exceeds maximum
         * 
         * @example
         * const oldSize = table.grow(5);
         * console.log(oldSize); // 10
         * console.log(table.length); // 15
         */
        grow(delta: number, init?: Function | null): number;
    }

    /**
     * Represents a WebAssembly global variable
     */
    class Global {
        /**
         * Creates a new WebAssembly global
         * @param descriptor - Global configuration
         * @param value - Initial value
         * 
         * @example
         * const global = new WebAssembly.Global(
         *   { value: "i32", mutable: true },
         *   42
         * );
         * console.log(global.value); // 42
         * global.value = 100;
         */
        constructor(descriptor: GlobalDescriptor, value?: any);

        /**
         * Get or set the global value
         * 
         * @example
         * const g = new WebAssembly.Global({ value: "f64", mutable: true }, 3.14);
         * console.log(g.value); // 3.14
         * g.value = 2.71;
         */
        value: any;

        /**
         * Get the value (same as .value property)
         * 
         * @example
         * const val = global.valueOf();
         */
        valueOf(): any;
    }

    /**
     * Compile a WebAssembly module asynchronously
     * @param buffer - Binary WebAssembly code
     * @returns Promise resolving to compiled Module
     * @throws {CompileError} If compilation fails
     * 
     * @example
     * const wasmCode = await fetch('module.wasm').then(r => r.arrayBuffer());
     * const module = await WebAssembly.compile(wasmCode);
     */
    function compile(buffer: ArrayBuffer | ArrayBufferView): Promise<Module>;

    /**
     * Instantiate a WebAssembly module asynchronously
     * @param buffer - Binary WebAssembly code or compiled Module
     * @param importObject - Object containing imports
     * @returns Promise resolving to { module, instance } or just instance
     * @throws {CompileError} If compilation fails
     * @throws {LinkError} If linking fails
     * 
     * @example
     * // From buffer
     * const { module, instance } = await WebAssembly.instantiate(wasmCode, imports);
     * 
     * // From module
     * const instance = await WebAssembly.instantiate(module, imports);
     */
    function instantiate(
        buffer: ArrayBuffer | ArrayBufferView | Module,
        importObject?: ImportObject
    ): Promise<WebAssemblyInstantiatedSource | Instance>;

    /**
     * Validate WebAssembly binary
     * @param buffer - Binary WebAssembly code
     * @returns true if valid, false otherwise
     * 
     * @example
     * const isValid = WebAssembly.validate(wasmCode);
     * if (isValid) {
     *   const module = new WebAssembly.Module(wasmCode);
     * }
     */
    function validate(buffer: ArrayBuffer | ArrayBufferView): boolean;

    // Utility functions (non-standard)
    function isModule(obj: any): obj is Module;
    function isInstance(obj: any): obj is Instance;
    function isMemory(obj: any): obj is Memory;
    function isTable(obj: any): obj is Table;
    function isGlobal(obj: any): obj is Global;

    // Exception types
    class CompileError extends Error {
        constructor(message?: string);
    }

    class LinkError extends Error {
        constructor(message?: string);
    }

    class RuntimeError extends Error {
        constructor(message?: string);
    }

    // Type definitions
    interface MemoryDescriptor {
        initial: number;
        maximum?: number;
        shared?: boolean;
    }

    interface TableDescriptor {
        element: "funcref" | "anyfunc" | "externref";
        initial: number;
        maximum?: number;
    }

    interface GlobalDescriptor {
        value: "i32" | "i64" | "f32" | "f64";
        mutable?: boolean;
    }

    interface ModuleExportDescriptor {
        name: string;
        kind: "function" | "table" | "memory" | "global";
    }

    interface ModuleImportDescriptor {
        module: string;
        name: string;
        kind: "function" | "table" | "memory" | "global";
    }

    interface ImportObject {
        [moduleName: string]: {
            [itemName: string]: any;
        };
    }

    interface Exports {
        [name: string]: Function | Memory | Table | Global;
    }

    interface WebAssemblyInstantiatedSource {
        module: Module;
        instance: Instance;
    }
}
