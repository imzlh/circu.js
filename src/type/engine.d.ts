declare namespace CModuleEngine {
    interface Promise<T = any> extends globalThis.Promise<T> {
        /**
         * 创建promise时的堆栈信息，用于调试<br>
         * 在event内返回true可以阻止cjs创建stack
         */
        readonly stack: string;
    }

    enum PromiseState {
        CONSTRUCT,
        BEFORE_THEN,
        AFTER_THEN,
        FULFILLED
    }

    interface GlobalEvents {
        unhandledrejection: [this: Promise, error: Error | any],
        exit: [exitCode: number],
        promise: [this: Promise, state: PromiseState, parent: Promise],
    }

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
         * circu.js 自身版本
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

    
    /**
     * 类似于`new TextEncoder().encode(str)`
     * 编码为buffer
     * @param str 文本
     */
    export function encodeString(str: string): Uint8Array;

    /**
     * 类似于`new TextDecoder().decode(buffer)` 
     * 解码为文本
     * @param buffer 包含文本的buffer
     */
    export function decodeString(buffer: Uint8Array | ArrayBuffer): string;
    
    /**
     * (不安全，谨慎使用) 模块类
     */
    export class Module {
        /**
         * 将传入的模块内容编译
         */
        constructor(content: string);

        /**
         * 获取模块(JSModuleDef)指针位置
         */
        get ptr(): number | bigint;

        /**
         * 获取模块的import.meta对象
         */
        get meta(): ImportMeta;

        /**
         * 导出模块为字节码
         */
        dump(): ArrayBuffer;
    }
 
    /**
     * 设置虚拟机选项
     * @param options 选项对象
     * @returns 返回一个 Promise，解析为 undefined。
     */
    export function onModule(options: {
        /**
         * 模块加载器函数
         */
        load?: (resolvedName: string) => Module | string;

        /**
         * 模块解析器函数
         */
        resolve?: (name: string, parent: string) => string;

        /**
         * 模块初始化函数
         */
        init?: (name: string, importMeta: Record<string, any>) => void;
    }): void;

        /**
         * 事件接收器函数，返回true表示事件已处理，否则可能被底层处理，如退出
         */
    export function eventReceiver(cb: 
        <T extends keyof GlobalEvents>(eventName: T, eventData: GlobalEvents[T]) => boolean
    ): void;
}
