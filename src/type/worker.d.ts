declare namespace CModuleWorker {
  /**
   * Worker 模块
   */

  /**
   * MessagePipe 对象
   */
  interface MessagePipe {
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
  interface Worker {
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
   * 创建 Worker 对象
   * @param specifier 模块路径
   * @param source 模块源码（可选）
   * @returns 返回一个 Promise，解析为 Worker 对象。
   */
  function create(specifier: string, source?: string): Promise<Worker>;

  /**
   * Worker 是否在 Worker 线程中
   */
  const isWorker: boolean;

  /**
   * 获取当前 Worker 的 MessagePipe 对象
   */
  const messagePipe: MessagePipe | undefined;

  // 导出所有内容
  export {
    Worker,
    MessagePipe,
    create,
    isWorker,
    messagePipe
  };
}
