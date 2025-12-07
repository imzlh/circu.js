// txiki.d.ts
declare namespace CModuleWS {
    /**
     * WebSocket 客户端实现
     * 
     * @example
     * ```typescript
     * // 创建 WebSocket 连接
     * const ws = new WebSocket('wss://echo.websocket.org');
     * 
     * ws.onopen = (protocols) => {
     *   console.log('连接已建立，协议:', protocols);
     *   ws.sendText('Hello Server!');
     * };
     * 
     * ws.onmessage = (data) => {
     *   if (typeof data === 'string') {
     *     console.log('收到文本消息:', data);
     *   } else {
     *     console.log('收到二进制数据，长度:', data.byteLength);
     *   }
     * };
     * 
     * ws.onclose = () => {
     *   console.log('连接已关闭');
     * };
     * 
     * ws.onerror = (error) => {
     *   console.error('WebSocket 错误:', error.code, error.reason);
     * };
     * ```
     */
    class WebSocket {
        /**
         * 连接状态：正在连接中，值为 0
         */
        static readonly CONNECTING: 0;

        /**
         * 连接状态：已连接并可以通信，值为 1
         */
        static readonly OPEN: 1;

        /**
         * 连接状态：正在关闭中，值为 2
         */
        static readonly CLOSING: 2;

        /**
         * 连接状态：已关闭，值为 3
         */
        static readonly CLOSED: 3;

        /**
         * 当前 WebSocket 连接状态
         * 
         * @example
         * ```typescript
         * if (ws.readyState === WebSocket.OPEN) {
         *   ws.sendText('only send when open');
         * }
         * ```
         */
        readonly readyState: number;

        /**
         * 连接成功打开时触发
         * @param protocols - 服务器选择的子协议字符串，如果没有则为空字符串
         * 
         * @example
         * ```typescript
         * ws.onopen = (protocols) => {
         *   console.log('使用协议:', protocols || 'none');
         * };
         * ```
         */
        onopen: ((protocols: string) => void) | null;

        /**
         * 收到消息时触发
         * @param data - 文本字符串或 ArrayBuffer 二进制数据
         * 
         * @example
         * ```typescript
         * ws.onmessage = (data) => {
         *   if (typeof data === 'string') {
         *     console.log('文本:', data);
         *   } else {
         *     const view = new Uint8Array(data);
         *     console.log('二进制:', view);
         *   }
         * };
         * ```
         */
        onmessage: ((data: string | ArrayBuffer) => void) | null;

        /**
         * 连接关闭时触发
         * 
         * @example
         * ```typescript
         * ws.onclose = () => {
         *   console.log('连接关闭，状态:', ws.readyState);
         * };
         * ```
         */
        onclose: (() => void) | null;

        /**
         * 发生错误时触发
         * @param error - 错误事件对象，包含错误码和原因
         * 
         * @example
         * ```typescript
         * ws.onerror = (error) => {
         *   console.error('错误码:', error.code);
         *   console.error('原因:', error.reason);
         * };
         * ```
         */
        onerror: ((error: WebSocket.ErrorEvent) => void) | null;

        /**
         * 创建 WebSocket 连接
         * @param url - WebSocket 服务器地址，如 'ws://localhost:8080' 或 'wss://secure.example.com'
         * @param protocols - 可选的子协议字符串
         * 
         * @example
         * ```typescript
         * // 基本用法
         * const ws1 = new WebSocket('ws://localhost:8080');
         * 
         * // 指定子协议
         * const ws2 = new WebSocket('wss://api.example.com', 'chat-protocol');
         * ```
         */
        constructor(url: string, protocols?: string | null);

        /**
         * 关闭 WebSocket 连接
         * @param code - 可选的关闭状态码（默认为 1000）
         * @param reason - 可选的关闭原因字符串
         * 
         * @example
         * ```typescript
         * // 正常关闭
         * ws.close();
         * 
         * // 带状态码和原因关闭
         * ws.close(1000, 'Normal closure');
         * ws.close(1001, 'Going away');
         * ```
         */
        close(code?: number, reason?: string): void;

        /**
         * 发送文本消息
         * @param text - 要发送的字符串
         * 
         * @example
         * ```typescript
         * ws.onopen = () => {
         *   ws.sendText('Hello World!');
         *   ws.sendText(JSON.stringify({ type: 'greeting', message: 'Hi!' }));
         * };
         * ```
         */
        sendText(text: string): void;

        /**
         * 发送二进制数据
         * @param buffer - ArrayBuffer 对象
         * @param offset - 可选的起始偏移量（字节），默认为 0
         * @param length - 可选的发送长度（字节），默认为 buffer.byteLength - offset
         * 
         * @example
         * ```typescript
         * ws.onopen = () => {
         *   // 发送整个 ArrayBuffer
         *   const buffer1 = new Uint8Array([1, 2, 3, 4]).buffer;
         *   ws.sendBinary(buffer1);
         * 
         *   // 发送部分数据
         *   const buffer2 = new Uint8Array([0, 1, 2, 3, 4, 5]).buffer;
         *   ws.sendBinary(buffer2, 2, 3); // 发送索引 2-4 的数据 [2, 3, 4]
         * 
         *   // 发送 Float32Array 数据
         *   const floats = new Float32Array([1.5, 2.5, 3.5]);
         *   ws.sendBinary(floats.buffer);
         * };
         * ```
         */
        sendBinary(buffer: ArrayBuffer, offset?: number, length?: number): void;
    }

    declare namespace WebSocket {
        /**
         * WebSocket 错误事件对象
         */
        interface ErrorEvent {
            /** 关闭原因码 */
            code: number;
            /** 关闭原因描述 */
            reason: string;
        }
    }
}