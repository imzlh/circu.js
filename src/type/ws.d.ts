declare namespace CModuleWebSocket {
    export interface CloseEvent {
        /**
         * WebSocket 连接关闭的状态码
         */
        code: number;

        /**
         * 错误原因
         */
        reason: string;
    }

    /**
     * WebSocket 对象状态常量
     */
    const enum ReadyState {
        CONNECTING = 0,
        OPEN = 1,
        CLOSING = 2,
        CLOSED = 3
    }

    /**
     * WebSocket 对象
     */
    interface WebSocket {
        /**
         * 关闭 WebSocket 连接
         * @param code 关闭状态码（可选）
         * @param reason 关闭原因（可选）
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(code?: number, reason?: string): Promise<void>;

        /**
         * 发送二进制数据
         * @param data 包含要发送二进制数据的 ArrayBuffer
         * @param offset 数据起始偏移量（可选）
         * @param length 数据长度（可选）
         * @returns 返回一个 Promise，解析为 undefined。
         */
        sendBinary(data: ArrayBuffer, offset?: number, length?: number): Promise<void>;

        /**
         * 发送文本数据
         * @param data 文本数据字符串
         * @returns 返回一个 Promise，解析为 undefined。
         */
        sendText(data: string): Promise<void>;

        /**
         * 获取当前连接状态
         * @returns 返回当前连接状态。
         */
        readonly readyState: ReadyState;

        /**
         * 连接关闭事件处理函数
         */
        onclose: () => void;

        /**
         * 错误事件处理函数
         */
        onerror: (event: ErrorEvent) => void;

        /**
         * 消息事件处理函数
         */
        onmessage: (event: string | ArrayBuffer) => void;

        /**
         * 连接打开事件处理函数
         */
        onopen: (protocols: string) => void;

        /**
         * WebSocket 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'WebSocket';
    }

    /**
     * 创建 WebSocket 对象
     * @param url WebSocket 连接的 URL
     * @param protocols 子协议字符串（可选）
     * @returns 返回一个 Promise，解析为 WebSocket 对象。
     */
    function create(url: string, protocols?: string): Promise<WebSocket>;

    // 导出所有内容
    export {
        ReadyState,
        WebSocket,
        create
    };
}