declare module 'txiki.ts/xhr' {
    /**
     * XMLHttpRequest 模块
     */

    /**
     * XMLHttpRequest 对象状态常量
     */
    const enum ReadyState {
        UNSENT = 0,
        OPENED = 1,
        HEADERS_RECEIVED = 2,
        LOADING = 3,
        DONE = 4
    }

    /**
     * XMLHttpRequest 对象响应类型常量
     */
    const enum ResponseType {
        DEFAULT = '',
        TEXT = 'text',
        ARRAY_BUFFER = 'arraybuffer',
        JSON = 'json'
    }

    /**
     * XMLHttpRequest 对象
     */
    interface XMLHttpRequest {
        /**
         * 中止请求
         * @returns 返回 undefined。
         */
        abort(): void;

        /**
         * 获取所有响应头
         * @returns 返回所有响应头的字符串。
         */
        getAllResponseHeaders(): string;

        /**
         * 获取指定响应头
         * @param headerName 响应头名称
         * @returns 返回指定响应头的值。
         */
        getResponseHeader(headerName: string): string;

        /**
         * 打开一个新的请求
         * @param method 请求方法
         * @param url 请求 URL
         * @param async 是否异步请求（可选）
         * @returns 返回 undefined。
         */
        open(method: string, url: string, async?: boolean): void;

        /**
         * 发送请求
         * @param data 请求数据（可选）
         * @returns 返回 undefined。
         */
        send(data?: string | ArrayBuffer): void;

        /**
         * 设置请求头
         * @param headerName 请求头名称
         * @param headerValue 请求头值
         * @returns 返回 undefined。
         */
        setRequestHeader(headerName: string, headerValue: string): void;

        /**
         * 设置 Cookie 文件路径
         * @param jarPath Cookie 文件路径
         * @returns 返回 undefined。
         */
        setCookieJar(jarPath: string): void;

        /**
         * 获取当前连接状态
         * @returns 返回当前连接状态。
         */
        readonly readyState: ReadyState;

        /**
         * 获取响应数据
         * @returns 返回响应数据。
         */
        readonly response: string | ArrayBuffer | any;

        /**
         * 获取响应文本
         * @returns 返回响应文本。
         */
        readonly responseText: string;

        /**
         * 设置或获取响应类型
         * @returns 返回响应类型。
         */
        responseType: ResponseType;

        /**
         * 获取响应 URL
         * @returns 返回响应 URL。
         */
        readonly responseURL: string;

        /**
         * 获取响应状态码
         * @returns 返回响应状态码。
         */
        readonly status: number;

        /**
         * 获取响应状态文本
         * @returns 返回响应状态文本。
         */
        readonly statusText: string;

        /**
         * 设置或获取请求超时时间（毫秒）
         * @returns 返回请求超时时间（毫秒）。
         */
        timeout: number;

        /**
         * 获取上传对象
         * @returns 返回上传对象。
         */
        readonly upload: any;

        /**
         * 设置或获取是否包含凭证（如 Cookies）
         * @returns 返回是否包含凭证。
         */
        withCredentials: boolean;

        /**
         * 中止事件处理函数
         */
        onabort: ((event: undefined) => void) | undefined;

        /**
         * 错误事件处理函数
         */
        onerror: ((event: undefined) => void) | undefined;

        /**
         * 加载事件处理函数
         */
        onload: ((event: undefined) => void) | undefined;

        /**
         * 加载结束事件处理函数
         */
        onloadend: ((event: undefined) => void) | undefined;

        /**
         * 加载开始事件处理函数
         */
        onloadstart: ((event: undefined) => void) | undefined;

        /**
         * 进度事件处理函数
         */
        onprogress: ((event: ProgressEvent) => void) | undefined;

        /**
         * 就绪状态改变事件处理函数
         */
        onreadystatechange: ((event: undefined) => void) | undefined;

        /**
         * 超时事件处理函数
         */
        ontimeout: ((event: undefined) => void) | undefined;

        /**
         * XMLHttpRequest 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'XMLHttpRequest';
    }

    /**
     * 自定义进度事件对象
     */
    interface ProgressEvent {
        /**
         * 是否可计算总进度
         */
        readonly lengthComputable: boolean;

        /**
         * 已加载的数据量
         */
        readonly loaded: number;

        /**
         * 总数据量
         */
        readonly total: number;
    }

    /**
     * 创建 XMLHttpRequest 对象
     * @returns 返回一个 Promise，解析为 XMLHttpRequest 对象。
     */
    function create(): Promise<XMLHttpRequest>;

    // 导出所有内容
    export {
        ReadyState,
        ResponseType,
        XMLHttpRequest,
        create,
        ProgressEvent
    };
}
