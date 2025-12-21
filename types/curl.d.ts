// curl.d.ts
declare namespace CModuleCURL {
    /**
     * CURL模块版本信息
     */
    export interface VersionInfo {
        /** LibCURL 版本字符串 */
        curl: string;
        /** 支持的协议列表（以逗号分隔） */
        protocols: string;
        /** 功能特性位掩码 */
        features: number;
    }

    /**
     * HTTP响应对象
     */
    export interface Response {
        /** 响应体内容 */
        body?: string;
        /** 原始响应头 */
        headers: string;
        /** HTTP状态码 */
        status: number;
        /** 最终请求URL（可能经过重定向） */
        url?: string;
        /** 是否流式模式，此时body没内容 */
        streamed: boolean;
    }

    /**
     * HTTP请求错误对象
     */
    export interface CURLException {
        /** 错误消息 */
        message: string;
        /** LibCURL错误码 */
        code: number;
    }

    /**
     * 进度回调函数参数
     * @param dltotal 总下载字节数（未知时为0）
     * @param dlnow 已下载字节数
     * @param ultotal 总上传字节数（未知时为0）
     * @param ulnow 已上传字节数
     * @returns 返回true继续传输，false中止传输
     */
    export type ProgressCallback = (dltotal: number, dlnow: number, ultotal: number, ulnow: number) => boolean;

    /**
     * HTTP头部回调函数
     * @param header 单行HTTP头部（包含结尾CRLF）
     * @returns 处理的字节数，返回0表示中止
     */
    export type HeaderCallback = (header: string) => number;

    /**
     * 连接池配置选项
     */
    export interface ConnPoolOptions {
        /** 最大总连接数 */
        maxConnections?: number;
        /** 每个主机的最大连接数 */
        maxConnectionsPerHost?: number;
        /** 是否启用HTTP/2多路复用管道 */
        pipelining?: boolean;
    }

    /**
     * HTTP请求选项（用于便捷方法）
     */
    export interface RequestOptions {
        /** HTTP请求头 */
        headers?: Record<string, string>;
        /** 超时时间（毫秒） */
        timeout?: number;
    }

    /**
     * CURL请求信息统计
     */
    export interface RequestInfo {
        /** HTTP状态码 */
        status: number;
        /** 最终请求URL */
        url?: string;
        /** 总请求时间（秒） */
        totalTime: number;
        /** 下载数据大小（字节） */
        downloadSize: number;
        /** 上传数据大小（字节） */
        uploadSize: number;
    }

    /**
     * 连接池类 - 管理多个CURL连接的复用
     */
    export class ConnPool {
        /**
         * 创建新的连接池
         * @param options 连接池配置选项
         */
        constructor(options?: ConnPoolOptions);

        /**
         * 获取当前活跃的连接数
         */
        getActiveCount(): number;

        /**
         * 处理所有挂起的异步操作
         * 需要在事件循环中定期调用以确保回调被执行
         */
        process(): void;

        /**
         * 关闭连接池并释放所有资源
         */
        close(): void;

        /**
         * 设置HTTP管道最大长度（仅HTTP/2）
         * @param length 管道最大长度
         */
        setMaxPipelineLength(length: number): void;

        /**
         * 设置HTTP/2最大并发流数
         * @param streams 最大并发流数
         */
        setMaxConcurrentStreams(streams: number): void;
    }

    /**
     * CURL类 - 表示单个HTTP请求
     */
    export class CURL {
        /**
         * 创建新的CURL实例
         * @param pool 连接池，必选
         */
        constructor(pool: ConnPool);

        /**
         * 设置请求URL
         * @param url 请求的URL地址
         * @returns 当前CURL实例（支持链式调用）
         */
        setUrl(url: string): this;

        /**
         * 设置HTTP方法
         * @param method HTTP方法（GET, POST, PUT, HEAD, DELETE等）
         * @returns 当前CURL实例（支持链式调用）
         */
        setMethod(method: string): this;

        /**
         * 设置HTTP请求头
         * @param headers 请求头对象
         * @returns 当前CURL实例（支持链式调用）
         */
        setHeaders(headers: Record<string, string>): this;

        /**
         * 设置请求体（用于POST/PUT等）
         * @param body 请求体字符串
         * @returns 当前CURL实例（支持链式调用）
         */
        setBody(body: string): this;

        /**
         * 设置超时时间（毫秒）
         * @param timeout 超时时间（毫秒）
         * @returns 当前CURL实例（支持链式调用）
         */
        setTimeout(timeout: number): this;

        /**
         * 设置是否跟随重定向
         * @param follow 是否跟随重定向
         * @returns 当前CURL实例（支持链式调用）
         */
        setFollowRedirects(follow: boolean): this;

        /**
         * 设置SSL/TLS验证
         * @param verifyPeer 是否验证对等证书
         * @param verifyHost 是否验证主机名（默认与verifyPeer相同）
         * @returns 当前CURL实例（支持链式调用）
         */
        setSSLVerify(verifyPeer: boolean, verifyHost?: boolean): this;

        /**
         * 设置CA证书包路径
         * @param path CA证书文件路径
         * @returns 当前CURL实例（支持链式调用）
         */
        setCABundle(path: string): this;

        /**
         * 设置代理服务器
         * @param proxy 代理服务器地址（如：http://proxy.example.com:8080）
         * @param type 代理类型（http, https, socks4, socks5）
         * @returns 当前CURL实例（支持链式调用）
         */
        setProxy(proxy: string, type?: 'http' | 'https' | 'socks4' | 'socks5'): this;

        /**
         * 设置用户代理字符串
         * @param userAgent 用户代理字符串
         * @returns 当前CURL实例（支持链式调用）
         */
        setUserAgent(userAgent: string): this;

        /**
         * 设置Cookie字符串
         * @param cookie Cookie字符串
         * @returns 当前CURL实例（支持链式调用）
         */
        setCookie(cookie: string): this;

        /**
         * 设置Cookie文件路径
         * @param path Cookie文件路径
         * @returns 当前CURL实例（支持链式调用）
         */
        setCookieFile(path: string): this;

        /**
         * 设置Referer头
         * @param referer Referer值
         * @returns 当前CURL实例（支持链式调用）
         */
        setReferer(referer: string): this;

        /**
         * 设置最大重定向次数
         * @param max 最大重定向次数
         * @returns 当前CURL实例（支持链式调用）
         */
        setMaxRedirects(max: number): this;

        /**
         * 设置连接超时时间（毫秒）
         * @param timeout 连接超时时间（毫秒）
         * @returns 当前CURL实例（支持链式调用）
         */
        setConnectTimeout(timeout: number): this;

        /**
         * 设置是否启用详细输出
         * @param verbose 是否启用详细输出
         * @returns 当前CURL实例（支持链式调用）
         */
        setVerbose(verbose: boolean): this;

        /**
         * 设置HTTP协议版本
         * @param version HTTP版本（1.0, 1.1, 2, 2TLS, 3）
         * @returns 当前CURL实例（支持链式调用）
         */
        setHTTPVersion(version: '1.0' | '1.1' | '2' | '2.0' | '2TLS' | '3'): this;

        /**
         * 设置请求范围（用于断点续传）
         * @param start 起始字节位置
         * @param end 结束字节位置（可选，不指定则到文件末尾）
         * @returns 当前CURL实例（支持链式调用）
         */
        setRange(start: number, end?: number): this;

        /**
         * 设置DNS服务器列表（以逗号分隔）
         * @param servers DNS服务器列表（如："8.8.8.8,1.1.1.1"）
         * @returns 当前CURL实例（支持链式调用）
         */
        setDNSServers(servers: string): this;

        /**
         * 设置网络接口
         * @param interfaceName 网络接口名或IP地址
         * @returns 当前CURL实例（支持链式调用）
         */
        setInterface(interfaceName: string): this;

        /**
         * 设置进度回调函数
         * @param callback 进度回调函数
         * @returns 当前CURL实例（支持链式调用）
         */
        onProgress(callback: ProgressCallback): this;

        /**
         * 设置头部回调函数
         * @param callback 头部回调函数
         * @returns 当前CURL实例（支持链式调用）
         */
        onHeader(callback: HeaderCallback): this;

        /**
         * 异步执行HTTP请求
         * @returns Promise<Response> HTTP响应
         * @throws CURLException 请求失败时抛出异常
         */
        perform(): Promise<Response>;

        /**
         * 同步执行HTTP请求
         * @returns Response HTTP响应
         * @throws CURLException 请求失败时抛出异常
         */
        performSync(): Response;

        /**
         * 获取请求统计信息
         * @returns RequestInfo 请求信息统计
         */
        getInfo(): RequestInfo;

        /**
         * 重置CURL实例到初始状态
         */
        reset(): void;

        /**
         * 设置流式模式。不保存body而是触发`ondata`
         * @param mode 流式模式
         */
        setStreamMode(mode: boolean): void;

        /**
         * 流式回调。当回调返回`true`表示终止读取。
         */
        onData(cb: (buf: ArrayBuffer) => boolean): void;
    }
    
    /**
     * 获取模块版本信息
     */
    export const version: VersionInfo;
}