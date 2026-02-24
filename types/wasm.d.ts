/**
 * WebAssembly Module for circu.js / txiki.js
 * Loaded via import.meta.use('wasm')
 *
 * @example
 * const wasm = import.meta.use('wasm');
 * const module = new wasm.Module(bytes);
 * const instance = new wasm.Instance(module, { env: { log: console.log } });
 */
declare namespace CModuleWASM {
    // Error classes
    class CompileError extends Error {
        constructor(message?: string);
    }

    class LinkError extends Error {
        constructor(message?: string);
    }

    class RuntimeError extends Error {
        constructor(message?: string);
    }

    // Descriptors
    interface ModuleExportDescriptor {
        name: string;
        kind: "function" | "table" | "memory" | "global";
    }

    interface ModuleImportDescriptor {
        module: string;
        name: string;
        kind: "function" | "table" | "memory" | "global";
    }

    interface MemoryDescriptor {
        initial: number;
        maximum?: number;
        shared?: boolean;
    }

    interface TableDescriptor {
        element: "funcref" | "anyfunc"; // externref not supported by WAMR backend
        initial: number;
        maximum?: number;
    }

    interface GlobalDescriptor {
        value: "i32" | "i64" | "f32" | "f64";
        mutable?: boolean;
    }

    interface ImportObject {
        [moduleName: string]: {
            [itemName: string]: Function | Memory | Table | Global | number | bigint;
        };
    }

    // Classes
    class Module {
        constructor(buffer: ArrayBuffer | ArrayBufferView);

        static exports(module: Module): ModuleExportDescriptor[];
        static imports(module: Module): ModuleImportDescriptor[];
        // customSections: not implemented in WAMR backend
    }

    class Instance {
        constructor(module: Module, importObject?: ImportObject);
        readonly exports: {
            [name: string]: Function | Memory | Table | Global;
        };
    }

    class Memory {
        constructor(descriptor: MemoryDescriptor);
        readonly buffer: ArrayBuffer;
        readonly shared: boolean;
        grow(delta: number): number;
    }

    class Table {
        constructor(descriptor: TableDescriptor);
        readonly length: number;
        get(index: number): Function | null;
        /** Throws TypeError on wasm-exported tables (no WAMR write API). */
        set(index: number, value: Function | null): void;
        /** Throws TypeError on wasm-exported tables (no WAMR write API). */
        grow(delta: number, init?: Function | null): number;
    }

    class Global {
        constructor(descriptor: GlobalDescriptor, value?: number | bigint);
        value: number | bigint;
        valueOf(): number | bigint;
    }

    // Synchronous top-level functions
    function compile(buffer: ArrayBuffer | ArrayBufferView): Module;
    function instantiate(buffer: ArrayBuffer | ArrayBufferView): { module: Module; instance: Instance };
    function instantiate(module: Module, importObject?: ImportObject): Instance;
    function validate(buffer: ArrayBuffer | ArrayBufferView): boolean;
}