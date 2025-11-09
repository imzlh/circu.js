declare namespace CModuleEngine {
    /**
     * 内存管理模块
     */
    interface GarbageCollector {
        /**
         * 手动触发垃圾回收
         */
        run(): void;

        /**
         * 设置垃圾回收的阈值（单位：字节）
         * @param threshold 新的阈值大小
         */
        setThreshold(threshold: number): void;

        /**
         * 获取当前垃圾回收的阈值
         * @returns 当前阈值（单位：字节）
         */
        getThreshold(): number;
    }

    /**
     * 引擎版本信息
     */
    interface EngineVersions {
        /**
         * QuickJS 引擎版本
         */
        quickjs: string;

        /**
         * txiki.js 自身版本
         */
        tjs: string;

        /**
         * libuv 版本
         */
        uv: string;

        /**
         * libcurl 版本（如可用）
         */
        curl?: string;

        /**
         * WASM3 版本（如可用）
         */
        wasm3?: string;

        /**
         * SQLite3 版本
         */
        sqlite3: string;

        /**
         * mimalloc 版本（如可用）
         */
        mimalloc?: number;
    }

    /**
     * 设置引擎内存限制
     * @param limit 内存限制大小（单位：字节）
     */
    export function setMemoryLimit(limit: number): void;

    /**
     * 设置引擎最大栈大小
     * @param size 栈大小（单位：字节）
     */
    export function setMaxStackSize(size: number): void;

    /**
     * 编译 JavaScript 代码为字节码
     * @param code 要编译的代码（Uint8Array 形式）
     * @param moduleName 模块名称（用于错误提示）
     * @returns 编译后的字节码
     */
    export function compile(code: Uint8Array, moduleName: string): Uint8Array;

    /**
     * 序列化 JavaScript 对象为字节码
     * @param obj 要序列化的对象
     * @returns 序列化后的字节码
     */
    export function serialize(obj: any): Uint8Array;

    /**
     * 反序列化字节码为 JavaScript 对象
     * @param bytecode 序列化后的字节码
     * @returns 反序列化后的对象
     */
    export function deserialize(bytecode: Uint8Array): any;

    /**
     * 执行预编译的字节码
     * @param bytecode 要执行的字节码
     * @returns 执行结果
     */
    export function evalBytecode(bytecode: Uint8Array): any;

    /**
     * 垃圾回收控制模块
     */
    export const gc: GarbageCollector;

    /**
     * 引擎版本信息
     */
    export const versions: EngineVersions;
}
