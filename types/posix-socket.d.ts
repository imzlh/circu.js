declare namespace CModulePosixSocket {
    /**
     * 地址族常量
     */
    const enum AddressFamily {
        /** IPv4 地址族 */
        AF_INET = 2,
        /** IPv6 地址族 */
        AF_INET6 = 10,
        /** 自动选择地址族 */
        AF_UNSPEC = 0,

        /** 网络链接地址族 */
        AF_NETLINK = 16,
        /** 数据包地址族 */
        AF_PACKET = 17,
        /** UNIX 域地址族 */
        AF_UNIX = 1
    }

    /**
     * 套接字类型常量
     */
    const enum SocketType {
        /** 流套接字 */
        SOCK_STREAM = 1,
        /** 数据报套接字 */
        SOCK_DGRAM = 2,
        /** 生原套接字 */
        SOCK_RAW = 3,
        /** 序列化数据包套接字 */
        SOCK_SEQPACKET = 5,
        /** 可靠数据报套接字 */
        SOCK_RDM = 4
    }

    /**
     * 套接字选项级别常量
     */
    const enum SocketOptionLevel {
        /** 套接字级别选项 */
        SOL_SOCKET = 1,

        /** 数据包级别选项 */
        SOL_PACKET = 263,
        /** 网络链接级别选项 */
        SOL_NETLINK = 270
    }

    /**
     * 套接字选项常量
     */
    const enum SocketOption {
        /** 重用地址 */
        SO_REUSEADDR = 2,
        /** 保持活动连接 */
        SO_KEEPALIVE = 9,
        /** 延迟关闭 */
        SO_LINGER = 13,
        /** 允许广播 */
        SO_BROADCAST = 6,
        /** 内联带外数据 */
        SO_OOBINLINE = 10,
        /** 接收缓冲区大小 */
        SO_RCVBUF = 8,
        /** 发送缓冲区大小 */
        SO_SNDBUF = 7,
        /** 接收超时 */
        SO_RCVTIMEO = 20,
        /** 发送超时 */
        SO_SNDTIMEO = 19,
        /** 获取错误 */
        SO_ERROR = 4,
        /** 获取套接字类型 */
        SO_TYPE = 3,
        /** 调试 */
        SO_DEBUG = 1,
        /** 不路由 */
        SO_DONTROUTE = 5,
        /** 重用端口 */
        SO_REUSEPORT = 15,
        /** 强制发送缓冲区大小 */
        SO_SNDBUFFORCE = 32,
        /** 强制接收缓冲区大小 */
        SO_RCVBUFFORCE = 33,
        /** 无校验 */
        SO_NO_CHECK = 11,
        /** 优先级 */
        SO_PRIORITY = 12,
        /** BSD 兼容 */
        SO_BSDCOMPAT = 14,

        /** IP 协议 */
        IPPROTO_IP = 0,
        /** IPv6 协议 */
        IPPROTO_IPV6 = 41,
        /** ICMP 协议 */
        IPPROTO_ICMP = 1,
        /** TCP 协议 */
        IPPROTO_TCP = 6,
        /** UDP 协议 */
        IPPROTO_UDP = 17
    }

    /**
     * 套接字事件常量
     */
    const enum SocketEvent {
        /** 可读事件 */
        READABLE = 1,
        /** 可写事件 */
        WRITABLE = 2,
        /** 断开连接事件 */
        DISCONNECT = 4,
        /** 优先事件 */
        PRIORITIZED = 8
    }

    /**
     * 套接字对象
     */
    interface PosixSocket {
        /**
         * 绑定套接字到地址
         * @param sockaddr 地址缓冲区
         */
        bind(sockaddr: Uint8Array): Promise<void>;

        /**
         * 关闭套接字
         */
        close(): Promise<void>;

        /**
         * 接受连接
         * @returns 返回新的套接字对象
         */
        accept(): Promise<PosixSocket>;

        /**
         * 连接到地址
         * @param sockaddr 地址缓冲区
         */
        connect(sockaddr: Uint8Array): Promise<void>;

        /**
         * 设置套接字选项
         * @param level 选项级别
         * @param optname 选项名称
         * @param optval 选项值
         */
        setopt(level: SocketOptionLevel, optname: SocketOption, optval: Uint8Array): Promise<void>;

        /**
         * 获取套接字选项
         * @param level 选项级别
         * @param optname 选项名称
         * @param optlen 选项值长度（可选）
         * @returns 返回选项值缓冲区
         */
        getopt(level: SocketOptionLevel, optname: SocketOption, optlen?: number): Promise<Uint8Array>;

        /**
         * 监听连接
         * @param backlog 最大挂起连接数
         */
        listen(backlog: number): Promise<void>;

        /**
         * 从套接字读取数据
         * @param count 读取的数据长度
         * @returns 返回包含读取数据的 Uint8Array 或 null 如果没有数据
         */
        read(count: number): Promise<Uint8Array | null>;

        /**
         * 向套接字写入数据
         * @param buffer 包含要写入数据的缓冲区
         * @returns 返回写入的数据长度
         */
        write(buffer: Uint8Array): Promise<number>;

        /**
         * 关闭套接字的发送或接收
         * @param how 关闭方式（如 0: 关闭接收，1: 关闭发送，2: 关闭发送和接收）
         */
        shutdown(how: number): Promise<void>;

        /**
         * 从套接字接收数据
         * @param bufsz 缓冲区大小
         * @param flags 接收标志
         * @returns 返回包含接收数据的 Uint8Array 或 null 如果没有数据
         */
        recv(bufsz: number, flags: number): Promise<Uint8Array | null>;

        /**
         * 从套接字接收消息
         * @param bufsz 缓冲区大小
         * @param controlsz 控制信息大小（可选）
         * @returns 返回包含消息信息的对象
         */
        recvmsg(bufsz: number, controlsz?: number): Promise<{
            /** 发送方地址 */
            readonly addr: Uint8Array;
            /** 控制信息 */
            readonly control?: Uint8Array;
            /** 消息数据 */
            readonly data: Uint8Array;
        }>;

        /**
         * 向套接字发送消息
         * @param addr 地址缓冲区（可选）
         * @param control 控制信息缓冲区（可选）
         * @param flags 发送标志
         * @param data 数据缓冲区数组
         * @returns 返回发送的数据长度
         */
        // @ts-ignore
        sendmsg(addr?: Uint8Array, control?: Uint8Array, flags: number, ...data: Uint8Array[]): Promise<number>;

        /**
         * 启动轮询
         * @param events 轮询事件
         * @param callback 回调函数
         */
        poll(events: number, callback: () => void): Promise<void>;

        /**
         * 停止轮询
         */
        pollStop(): Promise<void>;

        /**
         * 检查是否正在轮询
         */
        readonly polling: boolean;

        /**
         * 获取套接字文件描述符
         */
        readonly fileno: number;

        /**
         * 获取套接字信息
         */
        readonly info: {
            /**
             * 套接字类型
             */
            readonly type: number;

            /**
             * 地址族
             */
            readonly domain: number;

            /**
             * 协议
             */
            readonly protocol: number;
        };
    }

    /**
     * 创建套接字
     * @param domain 地址族
     * @param type 套接字类型
     * @param protocol 协议
     * @returns 返回套接字对象
     */
    function create(domain: number, type: number, protocol: number): Promise<PosixSocket>;

    /**
     * 从文件描述符创建套接字
     * @param fd 文件描述符
     * @returns 返回套接字对象
     */
    function createFromFd(fd: number): Promise<PosixSocket>;

    /**
     * 获取 sockaddr_inet 缓冲区
     * @param addr 地址对象
     * @returns 返回 Uint8Array 表示的 sockaddr_inet
     */
    function createSockaddrInet(addr: any): Promise<Uint8Array>;

    /**
     * 获取错误描述
     * @param errnum 错误码
     * @returns 返回错误描述字符串
     */
    function uv_strerror(errnum: number): Promise<string>;

    /**
     * 生成 IP 校验和
     * @param data 数据缓冲区
     * @returns 返回 IP 校验和
     */
    function checksum(data: Uint8Array): Promise<number>;

    /**
     * 获取网络接口索引
     * @param name 接口名称
     * @returns 返回接口索引
     */
    function ifNametoindex(name: string): Promise<number>;

    /**
     * 获取网络接口名称
     * @param index 接口索引
     * @returns 返回接口名称
     */
    function ifIndextoname(index: number): Promise<string>;

    /**
     * 加载 POSIX 套接字模块
     * @returns 返回 POSIX 套接字模块对象
     */
    const posixSocketLoad: () => Promise<{
        /**
         * 创建套接字对象
         */
        create: typeof create;

        /**
         * 从文件描述符创建套接字对象
         */
        createFromFd: typeof createFromFd;

        /**
         * 获取 sockaddr_inet 缓冲区
         */
        createSockaddrInet: typeof createSockaddrInet;

        /**
         * 获取错误描述
         */
        uv_strerror: typeof uv_strerror;

        /**
         * 生成 IP 校验和
         */
        checksum: typeof checksum;

        /**
         * 获取网络接口索引
         */
        ifNametoindex: typeof ifNametoindex;

        /**
         * 获取网络接口名称
         */
        ifIndextoname: typeof ifIndextoname;

        /**
         * 套接字类型的大小
         */
        readonly sizeof_struct_sockaddr: number;

        /**
         * 常量定义
         */
        readonly defines: {
            [key in keyof typeof SocketOption | keyof typeof SocketOptionLevel | keyof typeof AddressFamily |
            keyof typeof SocketType]: number;
        };

        /**
         * 套接字事件标志
         */
        readonly uv_poll_event_bits: {
            [key in keyof typeof SocketEvent]: number;
        };
    }>;

    // 导出所有内容
    export {
        AddressFamily,
        SocketType,
        SocketOptionLevel,
        SocketOption,
        SocketEvent,
        PosixSocket,
        create,
        createFromFd,
        createSockaddrInet,
        uv_strerror,
        checksum,
        ifNametoindex,
        ifIndextoname,
        posixSocketLoad
    };
}
