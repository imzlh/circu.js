/** Low-level, object-oriented WAMR bindings. */
declare namespace CModuleWASM {
    export type WasmErrorName = 'CompileError' | 'LinkError' | 'RuntimeError' | 'RangeError';
    export type ValueType = 'i32' | 'i64' | 'f32' | 'f64' | 'v128' | 'externref' | 'funcref' | 'unknown';
    export type RunningMode = 'interpreter' | 'fast-jit' | 'llvm-jit' | 'multi-tier-jit';

    export type WasmValue = number | bigint;
    export type WasmExternRef = null | undefined | object | string | number | boolean | bigint | symbol;
    export type WasmFunctionArgument = WasmValue | WasmExternRef;
    export type WasmFunctionResult = WasmValue | WasmExternRef | WasmFunctionResult[] | undefined;
    export type WasmGlobalValue = WasmValue | WasmExternRef | ArrayBuffer | ArrayBufferView;
    export interface WasmFuncref {
        /** Instance whose function index space owns this slot. */
        owner: Instance;
        index: number;
    }
    export type WasmTableValue = number | WasmFuncref | null | WasmExternRef;

    export interface FunctionType {
        parameters: ValueType[];
        results: ValueType[];
    }

    export interface GlobalType {
        value: ValueType;
        mutable: boolean;
    }

    export interface MemoryType {
        initial: number;
        maximum: number;
        shared: boolean;
    }

    export interface TableType {
        element: ValueType;
        initial: number;
        maximum: number;
        shared: boolean;
    }

    type ExportBase = { name: string; externIndex: number };
    export type ModuleExportDescriptor =
        | (ExportBase & { kind: 'function' } & FunctionType)
        | (ExportBase & { kind: 'global' } & GlobalType)
        | (ExportBase & { kind: 'memory' } & MemoryType)
        | (ExportBase & { kind: 'table' } & TableType);

    type ImportBase = { module: string; name: string; linked: boolean; externIndex: number };
    export type ModuleImportDescriptor =
        | (ImportBase & { kind: 'function' } & FunctionType)
        | (ImportBase & { kind: 'global' } & GlobalType)
        | (ImportBase & { kind: 'memory' } & MemoryType)
        | (ImportBase & { kind: 'table' } & TableType);

    export interface ImportFunctionDescriptor {
        module: string;
        name: string;
        func: (...args: WasmFunctionArgument[]) => WasmFunctionResult | void;
        /** Native provider for a wasm-origin function import. */
        provider?: Instance;
        /** Function index in provider. */
        sourceIndex?: number;
        /* Function imports cannot alias an earlier import via
         * `sourceImportIndex` (unlike global/table/memory): WAMR only links
         * function aliases through a live provider instance, so resolution
         * rejects the combination with a LinkError. */
        /** Original high-level wasm function wrapper, retained for re-exports. */
        owner?: unknown;
    }

    export interface GlobalImportDescriptor {
        module: string;
        name: string;
        value: number | bigint;
        type: 'i32' | 'i64' | 'f32' | 'f64';
        mutable: boolean;
        provider?: Instance;
        sourceIndex?: number;
        sourceImportIndex?: number;
        owner?: unknown;
    }

    export interface TableImportDescriptor {
        module: string;
        name: string;
        element: 'funcref' | 'externref';
        initial: number;
        maximum?: number;
        /** Standalone table contents. Null funcref elements require no native seeding. */
        values?: WasmTableValue[];
        provider?: Instance;
        sourceIndex?: number;
        sourceImportIndex?: number;
        owner?: unknown;
    }

    export interface MemoryImportDescriptor {
        module: string;
        name: string;
        initial: number;
        maximum?: number;
        provider?: Instance;
        sourceIndex?: number;
        sourceImportIndex?: number;
        owner?: unknown;
    }

    export interface GlobalInfo {
        type: ValueType;
        mutable: boolean;
    }

    export interface TableInfo {
        element: 'funcref' | 'externref' | 'unknown';
        cur_size: number;
        max_size: number;
    }

    export interface WasiOptions {
        args?: string[] | null;
        env?: Record<string, string> | null;
        preopens?: Record<string, string> | null;
    }

    export interface InstantiateOptions {
        /** WAMR execution stack size, 16 KiB through 64 MiB. */
        stackSize?: number;
        /** Optional WAMR host-managed heap size in bytes. */
        hostManagedHeapSize?: number;
        /** Override max linear-memory pages; zero keeps WAMR's default. */
        maxMemoryPages?: number;
        runningMode?: RunningMode;
        boundsChecks?: boolean;
        /** Per-instance host callbacks, matched to function import occurrences. */
        functions?: ImportFunctionDescriptor[];
    }

    export interface ModuleInfo {
        packageType: 'bytecode' | 'aot' | 'unknown';
        packageVersion: number;
        name: string;
    }

    export interface RuntimeInfo {
        major: number;
        minor: number;
        patch: number;
        runningModes: RunningMode[];
    }

    export interface MemoryInfo {
        currentPages: number;
        maximumPages: number;
        bytesPerPage: number;
        shared: boolean;
    }

    export interface AddressRange {
        start: number;
        end: number;
    }

    /** Loaded WAMR module. Created by load(), not a public constructor. */
    export interface Module {
        info(): ModuleInfo;
        setName(name: string): void;
        exports(): ModuleExportDescriptor[];
        imports(): ModuleImportDescriptor[];
        customSections(name: string): ArrayBuffer[];
        resolveFunctions(descriptors: ImportFunctionDescriptor[]): void;
        resolveGlobals(descriptors: GlobalImportDescriptor[]): void;
        resolveTables(descriptors: TableImportDescriptor[]): void;
        resolveMemories(descriptors: MemoryImportDescriptor[]): void;
        configureWasi(options?: WasiOptions): void;
        instantiate(options?: InstantiateOptions): Instance;
        readonly _opaque: unique symbol;
    }

    /** Instantiated WAMR module and execution environment. */
    export interface Instance {
        call(name: string, ...args: WasmFunctionArgument[]): WasmFunctionResult;
        callByIndex(index: number, ...args: WasmFunctionArgument[]): WasmFunctionResult;
        functionIndex(name: string): number;

        /** Return the original imported extern when its identity is reusable. */
        importedExtern(kind: ModuleExportDescriptor['kind'], externIndex: number): unknown;

        /** Live default-memory view; detached after memory growth. */
        memoryBuffer(): ArrayBuffer;
        memoryInfo(): MemoryInfo;
        /** Bounds-checked Uint8Array over an app-memory offset range. */
        memoryView(offset: number, length: number): Uint8Array;
        growMemory(pages: number): number;
        memoryBufferAt(externIndex: number): ArrayBuffer;
        memoryInfoAt(externIndex: number): MemoryInfo;
        growMemoryAt(externIndex: number, pages: number): number;

        /** Allocate from WAMR's app heap and return a linear-memory offset. */
        malloc(size: number): number;
        free(offset: number): void;
        /** Copy bytes into WAMR's app heap and return their offset. */
        dupData(data: ArrayBuffer | ArrayBufferView): number;
        validateAddress(offset: number, size?: number): boolean;
        addressRange(offset: number): AddressRange | null;

        getGlobal(name: string): WasmGlobalValue;
        setGlobal(name: string, value: WasmGlobalValue): void;
        globalInfo(name: string): GlobalInfo;
        tableInfo(name: string): TableInfo;
        tableSize(name: string): number;
        tableGet(name: string, index: number): WasmTableValue;
        tableSet(name: string, index: number, value: WasmTableValue): void;
        tableGrow(name: string, delta: number): number;
        getGlobalAt(externIndex: number): WasmGlobalValue;
        setGlobalAt(externIndex: number, value: WasmGlobalValue): void;
        globalInfoAt(externIndex: number): GlobalInfo;
        tableInfoAt(externIndex: number): TableInfo;
        tableSizeAt(externIndex: number): number;
        tableGetAt(externIndex: number, index: number): WasmTableValue;
        tableSetAt(externIndex: number, index: number, value: WasmTableValue): void;
        tableGrowAt(externIndex: number, delta: number, init?: WasmTableValue): number;

        runningMode(): RunningMode | 'unknown';
        setRunningMode(mode: RunningMode): void;
        boundsChecks(): boolean;
        setBoundsChecks(enabled: boolean): void;
        isWasiMode(): boolean;
        wasiExitCode(): number;
        exception(): string | null;
        setException(message: string | null): void;
        clearException(): void;
        terminate(): void;
        readonly _opaque: unique symbol;
    }

    export function load(buffer: ArrayBuffer | ArrayBufferView): Module;
    export function validate(buffer: ArrayBuffer | ArrayBufferView): boolean;
    export function runtimeInfo(): RuntimeInfo;
}
