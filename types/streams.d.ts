/**
 * @module tjs:streams
 * 
 * txiki.js Streams 模块 - 提供TCP、Pipe和TTY流操作API
 */

declare namespace CModuleStreams {
    /**
     * 基础Stream接口
     */
    export interface Stream {
        /**
         * 读取数据回调
         */
        onread:
            ((result: null, error: undefined) => void) |
            ((result: undefined, error: CModuleError.Error) => void) |
            ((result: Uint8Array, error: undefined) => void);

        /**
         * 写入完成回调
         */
        onwrite:
            ((error: undefined) => void) |
            ((error: CModuleError.Error) => void);

        /**
         * 连接完成回调
         */
        onconnect:
            ((error: undefined) => void) |
            ((error: CModuleError.Error) => void);

        /**
         * 新连接到达回调（服务器模式）
         */
        onconnection:
            ((error: undefined, client: Stream) => void) |
            ((error: CModuleError.Error, client: undefined) => void);

        /**
         * 关闭完成回调
         */
        onshutdown:
            ((error: undefined) => void) |
            ((error: CModuleError.Error) => void);

        /**
         * 开始监听传入连接（仅服务器模式）
         * @param backlog 挂起连接队列的最大长度，默认511
         * @throws 同步抛出错误（如已监听、无效句柄等）
         */
        listen(backlog?: number): void;

        /**
         * 接受一个传入连接（仅服务器模式）
         * @returns Promise解析为新的Stream对象
         * @throws 通过Promise拒绝错误（如未监听、接受失败等）
         */
        accept(): Promise<Stream>;

        /**
         * 关闭写入/读取方向
         * @returns Promise在关闭完成时解析
         */
        shutdown(): Promise<void>;

        /**
         * 设置流为阻塞或非阻塞模式
         * @param blocking true为阻塞模式，false为非阻塞
         * @throws 同步抛出错误
         */
        setBlocking(blocking: boolean): void;

        /**
         * 完全关闭流并释放资源
         * @throws 同步抛出错误
         */
        close(): void;

        /**
         * 开始读取数据
         */
        startRead(): void;

        /**
         * 停止读取数据
         */
        stopRead(): void;

        /**
         * 向流中写入数据
         * @param buffer 包含要写入数据的Uint8Array
         * @returns true=全部内联写入, false=部分或全部异步写入
         */
        write(buffer: Uint8Array): boolean;

        /**
         * 同步从流中读取数据，使用OS级别的阻塞read()/recv()
         * @param buffer 用于存放读取数据的Uint8Array
         * @returns 读取的字节数，null表示EOF
         * @throws 同步抛出错误
         */
        readSync(buffer: Uint8Array): number | null;

        /**
         * 同步向流中写入数据，使用OS级别的阻塞write()/send()
         * @param buffer 包含要写入数据的Uint8Array
         * @returns 实际写入的字节数
         * @throws 同步抛出错误
         */
        writeSync(buffer: Uint8Array): number;

        /**
         * 获取底层的文件描述符
         * @returns 文件描述符数值（同步返回）
         */
        fileno(): number;

        /**
         * 增加事件循环引用计数，防止句柄被回收
         */
        ref(): void;

        /**
         * 减少事件循环引用计数，允许句柄被回收
         */
        unref(): void;

        readonly [Symbol.toStringTag]: 'Stream';
    }

    export type AddressInfo = {
        /**
         * IP 地址 (如 "127.0.0.1")
         */
        ip: string;

        /**
         * 端口号
         */
        port: number;
    } & ({
        /**
         * 地址族类型， IPV4
         */
        family: 4;
    } | {
        /**
         * 地址族类型， IPV6
         */
        family: 6;

        /**
         * 流信息
         */
        flowInfo: number;

        /**
         * 地址范围
         */
        scopeId: number;
    })

    /**
     * TCP流接口
     */
    export interface TCP extends Stream {
        /**
         * 获取本地套接字地址信息
         * @returns 包含address、port、family等信息的对象
         */
        getsockname(): AddressInfo;

        /**
         * 获取远端对端地址信息
         * @returns 包含address、port、family等信息的对象
         */
        getpeername(): AddressInfo;

        /**
         * 连接到指定地址
         * @param addr 地址对象（如{ip: '127.0.0.1', port: 8080}）
         * @returns Promise在连接建立时解析
         */
        connect(addr: {
            ip: string;
            port: number;
        }): Promise<void>;

        /**
         * 同步连接到指定地址，使用OS级别的阻塞connect()
         * @param addr 地址对象（如{ip: '127.0.0.1', port: 8080}）
         * @throws 同步抛出错误
         */
        connectSync(addr: {
            ip: string;
            port: number;
        }): void;

        /**
         * 绑定到本地地址
         * @param addr 地址对象
         * @param flags 绑定标志（如TCP_IPV6ONLY）
         * @throws 同步抛出错误
         */
        bind(addr: {
            ip: string;
            port: number;
        }): void;

        /**
         * 设置TCP keepalive选项
         * @param enable 是否启用
         * @param delay 探测间隔（毫秒）
         * @throws 同步抛出错误
         */
        setKeepAlive(enable: boolean, delay: number): void;

        /**
         * 设置TCP_NODELAY选项（禁用Nagle算法）
         * @param enable 是否启用
         * @throws 同步抛出错误
         */
        setNoDelay(enable: boolean): void;
    }

    /**
     * TTY流接口
     */
    export interface TTY extends Stream {
        /**
         * 设置TTY模式
         * @param mode TTY_MODE_NORMAL或TTY_MODE_RAW
         * @throws 同步抛出错误
         */
        setMode(mode: number): void;

        /**
         * 获取终端窗口大小
         * @returns 包含width和height的对象
         */
        getWinSize(): { width: number; height: number };
    }

    /**
     * Pipe流接口（Unix域套接字/命名管道）
     */
    export interface Pipe extends Stream {
        /**
         * 同步连接到指定Pipe，使用OS级别的阻塞connect()
         * @param name Pipe路径或名称
         * @throws 同步抛出错误
         */
        connectSync(name: string): void;

        /**
         * 用现有文件描述符初始化Pipe
         * @param fd 文件描述符
         * @throws 同步抛出错误
         */
        open(fd: number): void;

        /**
         * 获取本地Pipe名称/路径
         * @returns 名称字符串
         */
        getsockname(): string;

        /**
         * 获取远端Pipe名称/路径
         * @returns 名称字符串
         */
        getpeername(): string;

        /**
         * 连接到指定Pipe
         * @param name Pipe路径或名称
         * @returns Promise在连接建立时解析
         */
        connect(name: string): Promise<void>;

        /**
         * 绑定到本地Pipe名称
         * @param name Pipe路径或名称
         * @throws 同步抛出错误
         */
        bind(name: string): void;
    }

    /**
     * TCP构造函数
     * @example const tcp = new TCP();
     */
    export const TCP: {
        new(af?: number): TCP;
        readonly prototype: TCP;
    };

    /**
     * TTY构造函数
     * @example const tty = new TTY(fd, true);
     */
    export const TTY: {
        new(fd: number, readable: boolean): TTY;
        readonly prototype: TTY;
    };

    /**
     * Pipe构造函数
     * @example const pipe = new Pipe();
     */
    export const Pipe: {
        new(): Pipe;
        readonly prototype: Pipe;
    };

    /**
     * 常量定义
     */
    /** TCP绑定选项：仅使用IPv6 */
    export const TCP_IPV6ONLY: number;

    /** TTY模式：正常行缓冲模式 */
    export const TTY_MODE_NORMAL: number;

    /** TTY模式：原始无缓冲模式 */
    export const TTY_MODE_RAW: number;
}