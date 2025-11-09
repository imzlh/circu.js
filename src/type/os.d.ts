declare namespace CModuleOS {
    /**
     * 地址族常量
     */
    const enum AddressFamily {
        /** IPv4 地址族 */
        AF_INET = 2,
        /** IPv6 地址族 */
        AF_INET6 = 10,
        /** 自动选择地址族 */
        AF_UNSPEC = 0
    }

    /**
     * 标准文件描述符常量
     */
    const enum StandardFileDescriptor {
        /** 标准输入 */
        STDIN_FILENO = 0,
        /** 标准输出 */
        STDOUT_FILENO = 1,
        /** 标准错误 */
        STDERR_FILENO = 2
    }

    /**
     * 获取当前进程的用户名、用户ID、组ID等信息
     */
    interface UserInfo {
        /**
         * 用户名
         */
        readonly userName: string;

        /**
         * 用户ID
         */
        readonly userId: number;

        /**
         * 组ID
         */
        readonly groupId: number;

        /**
         * 用户的 shell 路径
         */
        readonly shell: string | null;

        /**
         * 用户的主目录路径
         */
        readonly homeDir: string | null;
    }

    /**
     * 获取系统信息
     */
    interface SystemInfo {
        /**
         * 系统名称
         */
        readonly sysname: string;

        /**
         * 系统发行版
         */
        readonly release: string;

        /**
         * 系统版本
         */
        readonly version: string;

        /**
         * 系统机器架构
         */
        readonly machine: string;
    }

    /**
     * 获取网络接口信息
     */
    interface NetworkInterface {
        /**
         * 接口名称
         */
        readonly name: string;

        /**
         * 物理地址（MAC 地址）
         */
        readonly mac: string;

        /**
         * 接口地址
         */
        readonly address: string;

        /**
         * 接口子网掩码
         */
        readonly netmask: string;

        /**
         * 是否为内部接口
         */
        readonly internal: boolean;

        /**
         * 接口作用域 ID（仅在 IPv6 中有效）
         */
        readonly scopeId?: number;
    }

    /**
     * 退出当前进程
     * @param status 退出码
     */
    function exit(status: number): void;

    /**
     * 获取系统信息
     * @returns 返回系统信息对象
     */
    function uname(): Promise<SystemInfo>;

    /**
     * 获取系统运行时间（以秒为单位）
     * @returns 返回系统运行时间
     */
    function uptime(): Promise<number>;

    /**
     * 猜测文件描述符的类型
     * @param fd 文件描述符
     * @returns 返回文件描述符的类型字符串（如 'tty', 'pipe', 'file', 'tcp', 'udp', 'unknown'）
     */
    function guessHandle(fd: number): string;

    /**
     * 获取环境变量
     * @param name 环境变量名称
     * @returns 返回环境变量值
     */
    function getenv(name: string): Promise<string>;

    /**
     * 设置环境变量
     * @param name 环境变量名称
     * @param value 环境变量值
     */
    function setenv(name: string, value: string): Promise<void>;

    /**
     * 删除环境变量
     * @param name 环境变量名称
     */
    function unsetenv(name: string): Promise<void>;

    /**
     * 获取所有环境变量
     * @returns 返回包含所有环境变量的对象
     */
    function environ(): Promise<Record<string, string>>;

    /**
     * 获取所有环境变量的键
     * @returns 返回包含所有环境变量键的数组
     */
    function envKeys(): Promise<string[]>;

    /**
     * 更改当前工作目录
     * @param dir 目录路径
     */
    function chdir(dir: string): Promise<void>;

    /**
     * 获取当前工作目录
     * @returns 返回当前工作目录路径
     */
    function cwd(): Promise<string>;

    /**
     * 获取用户主目录
     * @returns 返回用户主目录路径
     */
    function homedir(): Promise<string>;

    /**
     * 获取临时目录
     * @returns 返回临时目录路径
     */
    function tmpdir(): Promise<string>;

    /**
     * 生成随机数据
     * @param buffer ArrayBuffer 或 Uint8Array 用于存储生成的随机数据
     * @param offset 偏移量（可选）
     * @param len 长度（可选）
     */
    function random(buffer: ArrayBuffer | Uint8Array, offset?: number, len?: number): Promise<void>;

    /**
     * 获取 CPU 信息
     * @returns 返回包含 CPU 信息的数组
     */
    function cpuInfo(): Promise<{
        /**
         * CPU 模型
         */
        readonly model: string;

        /**
         * CPU 速度（MHz）
         */
        readonly speed: number;

        /**
         * CPU 时间信息
         */
        readonly times: {
            /**
             * 用户模式时间
             */
            readonly user: number;

            /**
             * 用户模式 nice 时间
             */
            readonly nice: number;

            /**
             * 系统模式时间
             */
            readonly sys: number;

            /**
             * 空闲时间
             */
            readonly idle: number;

            /**
             * 中断请求时间
             */
            readonly irq: number;
        };
    }[]>;

    /**
     * 获取系统负载平均值
     * @returns 返回包含负载平均值的数组
     */
    function loadavg(): Promise<[number, number, number]>;

    /**
     * 获取网络接口信息
     * @returns 返回包含网络接口信息的数组
     */
    function networkInterfaces(): Promise<NetworkInterface[]>;

    /**
     * 获取可用的并行度
     * @returns 返回可用的并行度
     */
    function availableParallelism(): Promise<number>;

    /**
     * 获取主机名
     * @returns 返回主机名
     */
    function gethostname(): Promise<string>;

    /**
     * 获取当前进程的进程ID
     * @returns 返回进程ID
     */
    function getpid(): Promise<number>;

    /**
     * 获取当前进程的父进程ID
     * @returns 返回父进程ID
     */
    function getppid(): Promise<number>;

    /**
     * 获取当前进程的用户信息
     * @returns 返回用户信息对象
     */
    function userInfo(): Promise<UserInfo>;

    // 导出所有内容
    export {
        AddressFamily,
        StandardFileDescriptor,
        UserInfo,
        SystemInfo,
        NetworkInterface,
        exit,
        uname,
        uptime,
        guessHandle,
        getenv,
        setenv,
        unsetenv,
        environ,
        envKeys,
        chdir,
        cwd,
        homedir,
        tmpdir,
        random,
        cpuInfo,
        loadavg,
        networkInterfaces,
        availableParallelism,
        gethostname,
        getpid,
        getppid,
        userInfo
    };
}
