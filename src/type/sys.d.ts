declare namespace CModuleSys {
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
        evalFile,
        loadScript,
        evalScript,
        isArrayBuffer,
        detachArrayBuffer,
        exePath,
        randomUUID,
        args,
        version,
        platform
    };
}