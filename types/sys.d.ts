declare namespace CModuleSys {
    /**
     * 加载模块文件
     * @param filename 文件路径
     * @returns 返回一个 Promise。
     */
    function loadModule(filename: string): Promise<any>;

    /**
     * 加载脚本文件
     * @param filename 文件路径
     * @returns 返回脚本返回内容
     */
    function loadScript(filename: string): any;

    /**
     * 执行异步脚本。允许全局await。
     * @param script 脚本字符串
     * @returns 返回一个 脚本返回内容的Promise。
     */
    function loadAsyncScript(script: string): Promise<any>;

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
    const exePath: string;

    /**
     * 生成随机的 UUID
     * @returns 返回随机的 UUID 字符串。
     */
    function randomUUID(): Promise<string>;

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
        loadModule,
        loadScript,
        loadAsyncScript,
        isArrayBuffer,
        detachArrayBuffer,
        exePath,
        randomUUID,
        args,
        version,
        platform
    };
}