declare namespace CModuleStreams {
    /**
     * Streams 模块
     */

    /**
     * 错误对象
     */
    interface TJSError {
        readonly message: string;
        readonly errno: number;
    }

    /**
     * Stream 原型对象
     */
    interface Stream {
        /**
         * 监听连接
         * @param backlog 最大挂起连接数
         * @returns 返回一个 Promise，解析为 undefined。
         */
        listen(backlog?: number): Promise<void>;

        /**
         * 接受连接
         * @returns 返回一个 Promise，解析为 Stream 对象。
         */
        accept(): Promise<Stream>;

        /**
         * 关闭连接
         * @returns 返回一个 Promise，解析为 undefined。
         */
        shutdown(): Promise<void>;

        /**
         * 设置阻塞模式
         * @param blocking 是否阻塞
         * @returns 返回一个 Promise，解析为 undefined。
         */
        setBlocking(blocking: boolean): Promise<void>;

        /**
         * 关闭 Stream
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(): Promise<void>;

        /**
         * 从 Stream 读取数据
         * @param buffer 用于存储读取数据的 Uint8Array
         * @returns 返回一个 Promise，解析为读取的数据长度或 null 如果没有数据。
         */
        read(buffer: Uint8Array): Promise<number | null>;

        /**
         * 向 Stream 写入数据
         * @param buffer 包含要写入数据的 Uint8Array
         * @returns 返回一个 Promise，解析为写入的数据长度。
         */
        write(buffer: Uint8Array): Promise<number>;

        /**
         * 获取文件描述符
         * @returns 返回文件描述符。
         */
        fileno(): Promise<number>;

        /**
         * Stream 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'Stream';
    }

    /**
     * TCP 类
     */
    interface TCP extends Stream {
        /**
         * 获取套接字名称
         * @returns 返回一个 Promise，解析为包含套接字名称的对象。
         */
        getsockname(): Promise<Record<string, any>>;

        /**
         * 获取对等名称
         * @returns 返回一个 Promise，解析为包含对等名称的对象。
         */
        getpeername(): Promise<Record<string, any>>;

        /**
         * 连接到地址
         * @param addr 地址对象
         * @returns 返回一个 Promise，解析为 undefined。
         */
        connect(addr: Record<string, any>): Promise<void>;

        /**
         * 绑定到地址
         * @param addr 地址对象
         * @param flags 绑定标志（可选）
         * @returns 返回一个 Promise，解析为 undefined。
         */
        bind(addr: Record<string, any>, flags?: number): Promise<void>;

        /**
         * 设置 keepalive
         * @param enable 是否启用 keepalive
         * @param delay 延迟时间（毫秒）
         * @returns 返回一个 Promise，解析为 undefined。
         */
        setKeepAlive(enable: boolean, delay: number): Promise<void>;

        /**
         * 设置 nodelay
         * @param enable 是否启用 nodelay
         * @returns 返回一个 Promise，解析为 undefined。
         */
        setNoDelay(enable: boolean): Promise<void>;
    }

    /**
     * TTY 类
     */
    interface TTY extends Stream {
        /**
         * 设置 TTY 模式
         * @param mode 模式（如 TTY_MODE_NORMAL, TTY_MODE_RAW）
         * @returns 返回一个 Promise，解析为 undefined。
         */
        setMode(mode: number): Promise<void>;

        /**
         * 获取窗口大小
         * @returns 返回一个 Promise，解析为包含窗口大小的对象。
         */
        getWinSize(): Promise<{ width: number; height: number }>;
    }

    /**
     * Pipe 类
     */
    interface Pipe extends Stream {
        /**
         * 打开 Pipe
         * @param fd 文件描述符
         * @returns 返回一个 Promise，解析为 undefined。
         */
        open(fd: number): Promise<void>;

        /**
         * 获取套接字名称
         * @returns 返回一个 Promise，解析为套接字名称字符串。
         */
        getsockname(): Promise<string>;

        /**
         * 获取对等名称
         * @returns 返回一个 Promise，解析为对等名称字符串。
         */
        getpeername(): Promise<string>;

        /**
         * 连接到 Pipe
         * @param name Pipe 名称
         * @returns 返回一个 Promise，解析为 undefined。
         */
        connect(name: string): Promise<void>;

        /**
         * 绑定到 Pipe
         * @param name Pipe 名称
         * @returns 返回一个 Promise，解析为 undefined。
         */
        bind(name: string): Promise<void>;
    }

    /**
     * 创建 TCP 对象
     * @param af 地址族（如 AF_UNSPEC, AF_INET, AF_INET6）
     * @returns 返回一个 Promise，解析为 TCP 对象。
     */
    function createTCP(af: number): Promise<TCP>;

    /**
     * 创建 TTY 对象
     * @param fd 文件描述符
     * @param readable 是否可读
     * @returns 返回一个 Promise，解析为 TTY 对象。
     */
    function createTTY(fd: number, readable: boolean): Promise<TTY>;

    /**
     * 创建 Pipe 对象
     * @returns 返回一个 Promise，解析为 Pipe 对象。
     */
    function createPipe(): Promise<Pipe>;

    /**
     * 常量定义
     */
    const enum Constants {
        /** TCP 使用 IPv6 */
        TCP_IPV6ONLY = 1,
        /** TTY 模式正常 */
        TTY_MODE_NORMAL = 0,
        /** TTY 模式原始 */
        TTY_MODE_RAW = 1
    }

    // 导出所有内容
    export {
        Stream,
        TCP,
        TTY,
        Pipe,
        createTCP,
        createTTY,
        createPipe,
        Constants
    };
}
