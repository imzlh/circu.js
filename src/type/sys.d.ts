declare namespace CModuleSys {

    interface Promise<T = any> extends globalThis.Promise<T> {
        /**
         * 创建promise时的堆栈信息，用于调试<br>
         * 在event内返回true可以阻止cjs创建stack
         */
        readonly stack: string;

        /**
         * 对应cjs内部的uv tick id，在event内对比即可以得出当前事件是否是异步导致的
         */
        readonly index: number;
    }

    interface GlobalEvents {
        unhandledrejection: [Promise, Error | any, number],
        exit: [number],
    }

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
     * 评估文件并返回结果
     * @param filename 文件路径
     * @returns 返回一个 Promise，解析为评估结果。
     */
    function evalFile(filename: string): Promise<any>;

    /**
     * 加载脚本文件
     * @param filename 文件路径
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function loadScript(filename: string): Promise<void>;

    /**
     * 评估脚本字符串
     * @param script 脚本字符串
     * @returns 返回一个 Promise，解析为评估结果。
     */
    function evalScript(script: string): Promise<any>;

    /**
     * 检查值是否为 ArrayBuffer
     * @param value 要检查的值
     * @returns 返回布尔值，表示值是否为 ArrayBuffer。
     */
    function isArrayBuffer(value: any): boolean;

    /**
     * 分离 ArrayBuffer
     * @param buffer ArrayBuffer 对象
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function detachArrayBuffer(buffer: ArrayBuffer): Promise<void>;

    /**
     * 获取当前可执行文件的路径
     * @returns 返回当前可执行文件的路径。
     */
    function exepath(): Promise<string>;

    /**
     * 生成随机的 UUID
     * @returns 返回随机的 UUID 字符串。
     */
    function randomUUID(): Promise<string>;

    /**
     * 设置虚拟机选项
     * @param options 选项对象
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function setOptions(options: {
        /**
         * 最大内存限制（字节）
         */
        maxMemory?: number;

        /**
         * 最大栈大小限制（字节）
         */
        maxStackSize?: number;

        /**
         * 模块加载器函数
         */
        moduleLoader?: (resolvedName: string) => Module | string;

        /**
         * 模块解析器函数
         */
        moduleResolver?: (name: string, parent: string) => string;

        /**
         * 模块初始化函数
         */
        moduleInit?: (name: string, importMeta: Record<string, any>) => void;

        /**
         * 事件接收器函数，返回true表示事件已处理，否则可能被底层处理，如退出
         */
        eventReceiver?: <T extends keyof GlobalEvents>(eventName: T, eventData: GlobalEvents[T]) => boolean;

        /**
         * Promise 构造函数
         */
        promiseConstruct?: () => any;
    }): Promise<void>;

    /**
     * 当前命令行参数数组
     */
    const args: string[];

    /**
     * 版本信息
     */
    const version: string;

    /**
     * 平台信息
     */
    const platform: string;

    // 导出所有内容
    export {
        evalFile,
        loadScript,
        evalScript,
        isArrayBuffer,
        detachArrayBuffer,
        exepath,
        randomUUID,
        setOptions,
        args,
        version,
        platform
    };
}