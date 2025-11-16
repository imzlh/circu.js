/**
 * OS 模块 - 提供系统级操作和信息查询
 * 
 * @remarks
 * 此模块封装了 libuv 的系统调用，提供跨平台能力。
 * 所有操作均为**同步**，因为底层操作系统调用本身是同步的。
 */
declare namespace CModuleOS {
    /**
     * 地址族常量（来自 libuv）
     * @remarks 实际值由 libuv 定义，可能因平台而异。
     */
    const AF_INET: number;
    const AF_INET6: number;
    const AF_UNSPEC: number;

    /**
     * 标准文件描述符常量
     */
    const STDIN_FILENO: 0;
    const STDOUT_FILENO: 1;
    const STDERR_FILENO: 2;

    /**
     * 当前进程的用户信息
     */
    interface UserInfo {
        /** 用户名（如 'root'） */
        readonly userName: string;
        /** 用户ID（uid） */
        readonly userId: number;
        /** 组ID（gid） */
        readonly groupId: number;
        /** Shell路径，可能为 null（如 '/bin/bash'） */
        readonly shell: string | null;
        /** 主目录路径，可能为 null（如 '/home/user'） */
        readonly homeDir: string | null;
    }

    /**
     * 系统信息（uname 结果）
     */
    interface SystemInfo {
        /** 操作系统名称（如 'Linux', 'Darwin'） */
        readonly sysname: string;
        /** 发行版（如 '5.10.0-21-amd64'） */
        readonly release: string;
        /** 版本信息 */
        readonly version: string;
        /** 机器架构（如 'x86_64', 'arm64'） */
        readonly machine: string;
    }

    /**
     * 网络接口信息
     */
    interface NetworkInterface {
        /** 接口名称（如 'eth0', 'lo'） */
        readonly name: string;
        /** MAC地址（如 '00:11:22:33:44:55'） */
        readonly mac: string;
        /** IP地址（IPv4或IPv6） */
        readonly address: string;
        /** 子网掩码 */
        readonly netmask: string;
        /** 是否为内部接口（回环） */
        readonly internal: boolean;
        /** IPv6作用域ID（仅IPv6接口有） */
        readonly scopeId?: number;
    }

    /**
     * 系统负载平均值
     * @example [1.5, 1.2, 0.8] // 1分钟, 5分钟, 15分钟平均值
     */
    type LoadAverage = [number, number, number];

    // ==================== 进程控制 ====================

    /**
     * **立即退出**当前进程（同步）
     * @param status 退出码（0表示成功）
     * @warning **危险操作**：此调用不可撤销，会立即终止所有执行
     * @example
     * exit(0);  // 正常退出
     * exit(1);  // 异常退出
     */
    function exit(status: number): never;

    // ==================== 系统信息 ====================

    /**
     * 获取系统信息（同步）
     * @returns 系统详细信息
     */
    function uname(): SystemInfo;

    /**
     * 获取系统运行时间（秒）（同步）
     * @returns 自启动以来的秒数（浮点数）
     */
    function uptime(): number;

    // ==================== 文件描述符 ====================

    /**
     * 猜测文件描述符的类型（同步）
     * @param fd 文件描述符（如 0, 1, 2）
     * @returns 描述符类型
     */
    function guessHandle(fd: number): 'tty' | 'pipe' | 'file' | 'tcp' | 'udp' | 'unknown';

    // ==================== 环境变量 ====================

    /**
     * 获取环境变量（同步）
     * @param name 变量名（如 'PATH'）
     * @returns 变量值，不存在则返回 null
     */
    function getenv(name: string): string | null;

    /**
     * 设置环境变量（同步）
     * @param name 变量名
     * @param value 变量值
     * @throws {Error} 设置失败（如内存不足）
     */
    function setenv(name: string, value: string): void;

    /**
     * 删除环境变量（同步）
     * @param name 变量名
     */
    function unsetenv(name: string): void;

    /**
     * 获取所有环境变量（同步）
     * @returns 键值对对象
     */
    function environ(): Record<string, string>;

    /**
     * 获取所有环境变量名（同步）
     * @returns 变量名数组
     */
    function envKeys(): string[];

    // ==================== 目录操作 ====================

    /**
     * 更改当前工作目录（同步）
     * @param dir 新目录路径
     */
    function chdir(dir: string): void;

    /**
     * 当前工作目录（getter属性）
     */
    const cwd: string;

    // ==================== 路径信息 ====================

    /**
     * 用户主目录路径（getter属性）
     */
    const homedir: string;

    /**
     * 系统临时目录路径（getter属性）
     */
    const tmpdir: string;

    // ==================== 随机数 ====================

    /**
     * 生成密码学安全随机数据（同步）
     * @param buffer 目标缓冲区（Uint8Array或ArrayBuffer）
     * @param offset 起始偏移（默认0）
     * @param length 生成长度（默认buffer长度）
     * @throws {RangeError} offset+length超出边界
     * @example
     * const buf = new Uint8Array(32);
     * random(buf);
     */
    function random(
        buffer: ArrayBuffer | Uint8Array,
        offset?: number,
        length?: number
    ): void;

    // ==================== 系统资源 ====================

    /**
     * 获取CPU信息（同步）
     * @returns 每个CPU核心的详细信息
     */
    function cpuInfo(): Array<{
        model: string;
        speed: number; // MHz
        times: {
            user: number;
            nice: number;
            sys: number;
            idle: number;
            irq: number;
        };
    }>;

    /**
     * 获取系统负载平均值（同步）
     * @returns [1分钟, 5分钟, 15分钟]平均值
     */
    function loadavg(): LoadAverage;

    /**
     * 获取所有网络接口信息（同步）
     * @returns 接口数组
     */
    function networkInterfaces(): NetworkInterface[];

    /**
     * 获取可用并行度（逻辑CPU数）（同步）
     * @returns 可用于并行执行的CPU核心数
     */
    function availableParallelism(): number;

    // ==================== 网络信息 ====================

    /**
     * 主机名（getter属性）
     */
    const hostname: string;

    // ==================== 进程信息 ====================

    /**
     * 当前进程ID（getter属性）
     */
    const pid: number;

    /**
     * 父进程ID（getter属性）
     */
    const ppid: number;

    /**
     * 当前进程用户信息（getter属性）
     */
    const userInfo: UserInfo;
}