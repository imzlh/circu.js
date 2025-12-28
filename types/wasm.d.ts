declare namespace CModuleWASM {
    // ===========================================================================
    // 类型定义
    // ===========================================================================

    /** WASM 运行时错误接口 */
    interface WasmError extends Error {
        /** WASM 特定错误类型 */
        wasmError: "CompileError" | "LinkError" | "RuntimeError";
    }

    /** 模块导出项描述 */
    interface ExportEntry {
        /** 导出名称 */
        name: string;
        /** 导出类型（当前仅支持函数） */
        kind: "function"; // 未来可扩展: "function" | "global" | "memory" | "table"
    }

    /** WASM 模块对象（不透明句柄） */
    interface Module {
        // 内部持有解析后的模块数据
        // 通过 moduleExports() 获取导出信息
    }

    /** WASM 实例对象（可执行环境） */
    interface Instance {
        /**
         * 调用 WASM 实例中导出的函数
         * @param name - 函数名称
         * @param args - 参数列表（支持 number 和 bigint）
         * @returns 单个返回值或返回值数组
         * @throws {WasmError} 当函数不存在、参数无效或调用失败时抛出 RuntimeError
         * 
         * @example
         * ```ts
         * // 调用无参数函数
         * const version = instance.callFunction('version');
         * 
         * // 调用带参数函数（add(5, 3)）
         * const sum = instance.callFunction('add', 5, 3);
         * 
         * // 处理多返回值
         * const results = instance.callFunction('swap', 10, 20);
         * ```
         */
        callFunction(name: string, ...args: (number | bigint)[]): number | bigint | (number | bigint)[];

        /**
         * 为实例链接 WASI（WebAssembly System Interface）支持
         * 提供文件系统、环境变量、时钟等系统调用能力
         * @throws {WasmError} 当链接失败时抛出 LinkError
         * 
         * @example
         * ```ts
         * // 链接 WASI 后，模块可使用系统接口
         * instance.linkWasi();
         * instance.callFunction('_start'); // 调用 WASI 程序入口
         * ```
         */
        linkWasi(): void;
    }

    // ===========================================================================
    // 核心函数
    // ===========================================================================

    /**
     * 解析 WASM 字节码为可处理的模块对象
     * @param buffer - WASM 字节码（ArrayBuffer 或任意 TypedArray）
     * @returns 解析后的模块对象
     * @throws {WasmError} 当解析失败时抛出 CompileError
     * 
     * @example
     * ```ts
     * // 从 fetch 加载
     * const response = await fetch('module.wasm');
     * const buffer = await response.arrayBuffer();
     * const module = CModuleWASM.parseModule(buffer);
     * 
     * // 从文件系统加载（Node.js）
     * import { readFileSync } from 'fs';
     * const buffer = readFileSync('module.wasm');
     * const module = CModuleWASM.parseModule(buffer);
     * ```
     */
    function parseModule(buffer: ArrayBuffer | ArrayBufferView): Module;

    /**
     * 获取 WASM 模块的所有导出项
     * @param module - 模块对象
     * @returns 导出项数组，包含函数名称和类型
     * 
     * @example
     * ```ts
     * const exports = CModuleWASM.moduleExports(module);
     * console.log(exports);
     * // [{ name: "add", kind: "function" }, { name: "mul", kind: "function" }]
     * ```
     */
    function moduleExports(module: Module): ExportEntry[];

    /**
     * 从模块构建可执行的 WASM 实例
     * @param module - 模块对象
     * @returns 可调用函数的 WASM 实例
     * @throws {WasmError} 当构建失败时抛出 LinkError
     * 
     * @example
     * ```ts
     * const instance = CModuleWASM.buildInstance(module);
     * const result = instance.callFunction('add', 1, 2);
     * ```
     */
    function buildInstance(module: Module): Instance;
}