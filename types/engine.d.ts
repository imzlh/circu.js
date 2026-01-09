declare namespace CModuleEngine {
    type Promise = globalThis.Promise<any>;
    type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;   // not shared

    /**
     * dump function opcode
     */
    export const DUMP_BYTECODE: number;

    /**
     * disable debug info in dump function
     */
    export const DUMP_NODEBUG: number;

    /**
     * disable source code in dump function
     */
    export const DUMP_NOSOURCE: number;

    /**
     * deep dump object to handle complex objects
     */
    export const DUMP_DEEP: number;

    /**
     * USE with cautious, dump shared array buffer
     * will cause memory access error if program died
     */
    export const DUMP_LOCAL: number;

    /**
     * default dump, include bytecode, deep dump
     */
    export const DUMP_DEFAULT: number;

    export enum PromiseState {
        CONSTRUCT,
        BEFORE_THEN,
        AFTER_THEN,
        FULFILLED
    }

    interface GlobalEvents {
        unhandledrejection: [this: Promise, error: Error | any],
        exit: [exitCode: number],
        promise: [this: Promise, state: PromiseState, parent: Promise],
        jobexception: [error: Error | any],
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
        /** QuickJS 引擎版本 */
        quickjs: string;
        /** txiki.js 自身版本 */
        tjs: string;
        /** libuv 版本 */
        uv: string;
        /** libcurl 版本 */
        curl: string;
        /** SQLite3 版本 */
        sqlite3: string;
        /** zlib 版本 */
        zlib: string;
        /** OpenSSL 版本 */
        openssl: string;
        /** Expat XML 解析器版本 */
        expat: string;

        /** 若编译时包含 llhttp，则存在 */
        llhttp?: string;
        /** 若编译时包含 wasm3，则存在 */
        wasm3?: string;
        /** 若编译时包含 mimalloc，则存在（值为 number） */
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
     * @param flag 序列化选项，默认为 `DUMP_DEFAULT`
     * @returns 序列化后的字节码
     */
    export function serialize(obj: any, flag?: number): Uint8Array;

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
     * 类似于`new TextEncoder('utf-16').encode(str)`
     * 编码为buffer，注意是`Uint16Array`，每个字符占用2个字节
     * @param str 文本
     */
    export function encodeU16String(str: string): Uint16Array;

    /**
     * 类似于`new TextDecoder('utf-16').decode(buffer)` 
     * 解码为文本
     * 
     * **注意** 虽然Circu.js支持传入`Uint8Array`且效果一致，但是为了区分不建议这么做
     * @param buffer 包含文本的buffer
     */
    export function decodeU16String(buffer: Uint16Array | ArrayBuffer): string;

    /**
     * (不安全，谨慎使用) 模块类
     */
    export class Module {
        /**
         * 将传入的模块内容编译
         */
        constructor(content: string, filename: string);

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
         * @param flag 序列化选项，默认为 `DUMP_DEFAULT`
         */
        dump(flag?: number): ArrayBuffer;

        /**
         * 作为模块执行
         */
        eval(): Promise;
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
         * **NOTE**: qjs-ng支持了import attribute，可以从`attr`中获取import attribute列表
         */
        resolve?: (name: string, parent: string, attr: Record<string, any>) => string;

        /**
         * 模块初始化函数
         */
        init?: (name: string, importMeta: Record<string, any>) => void;

        /**
         * import attribute 内容检查函数
         * 只检查是否支持，完整检查应该在`resolve`中进行
         */
        attrchk?: (attr: Record<string, any>) => void;
    }): void;

    /**
     * 事件接收器函数，返回true表示事件已处理，否则可能被底层处理，如退出
     */
    export function onEvent(cb:
        <T extends keyof GlobalEvents>(eventName: T, eventData: GlobalEvents[T]) => boolean
    ): void;

    /**
     * 直接获取Promise的结果，若Promise未完成，则返回null
     * @param promise 获取的Promise
     */
    export function promiseResult<T>(promise: globalThis.Promise<T>): T | null;
}
