declare namespace CModuleUDP {
    /**
     * UDP 对象
     */
    interface UDP {
        /**
         * 关闭 UDP 连接
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(): Promise<void>;

        /**
         * 接收数据
         * @param buffer 用于存储接收数据的 Uint8Array
         * @returns 返回一个 Promise，解析为包含接收信息的对象。
         */
        recv(buffer: Uint8Array): Promise<{
            /**
             * 接收的数据长度
             */
            readonly nread: number;

            /**
             * 是否部分数据
             */
            readonly partial: boolean;

            /**
             * 发送方地址信息
             */
            readonly addr: Record<string, any>;
        }>;

        /**
         * 发送数据
         * @param buffer 包含要发送数据的 Uint8Array
         * @param addr 目标地址对象
         * @returns 返回一个 Promise，解析为发送的数据长度。
         */
        send(buffer: Uint8Array, addr?: Record<string, any>): Promise<number>;

        /**
         * 获取文件描述符
         * @returns 返回文件描述符。
         */
        fileno(): Promise<number>;

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
         * UDP 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'UDP';
    }

    /**
     * 创建 UDP 对象
     * @param af 地址族（如 AF_UNSPEC, AF_INET, AF_INET6）
     * @returns 返回一个 Promise，解析为 UDP 对象。
     */
    function create(af?: number): Promise<UDP>;

    /**
     * 常量定义
     */
    const enum Constants {
        /** 使用 IPv6 */
        UDP_IPV6ONLY = 1,
        /** 重用地址 */
        UDP_REUSEADDR = 2
    }

    // 导出所有内容
    export {
        UDP,
        create,
        Constants
    };
}
