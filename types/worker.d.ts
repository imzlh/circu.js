declare namespace CModuleWorker {
    /**
     * MessagePipe 对象
     */
    export interface MessagePipe {
        /**
         * 发送消息
         * @param data 要发送的数据
         * @returns 返回一个 Promise，解析为 undefined。
         */
        postMessage(data: any): Promise<void>;

        /**
         * 消息事件处理函数
         */
        onmessage: ((data: any) => void) | undefined;

        /**
         * 消息错误事件处理函数
         */
        onmessageerror: ((error: Error) => void) | undefined;

        /**
         * MessagePipe 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'MessagePipe';
    }

    /**
     * Worker 对象
     */
    export class Worker {
        /**
         * 创建一个 Worker
         * @param user_data 任意object，包括函数也被允许（但危险！）
         */
        constructor(user_data: any);

        /**
         * 终止 Worker
         * @returns 返回一个 Promise，解析为 undefined。
         */
        terminate(): Promise<void>;

        /**
         * 获取 MessagePipe 对象
         * @returns 返回 MessagePipe 对象。
         */
        readonly messagePipe: MessagePipe;

        /**
         * Worker 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'Worker';
    }

    /**
     * Worker 是否在 Worker 线程中
     */
    export const isWorker: boolean;

    /**
     * 获取当前 Worker 的 MessagePipe 对象
     */
    export const pipe: MessagePipe | undefined;

    /**
     * 获取当前 Worker 的用户数据(constructor中传入)
     */
    export const workerData: any;
}
