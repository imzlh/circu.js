declare namespace CModuleProcess {
    type Pipe = CModuleStreams.Pipe;

    /**
     * 进程信号
     */
    export type Signal =
        | 'SIGHUP' | 'SIGINT' | 'SIGQUIT' | 'SIGILL' | 'SIGTRAP'
        | 'SIGABRT' | 'SIGBUS' | 'SIGFPE' | 'SIGKILL' | 'SIGUSR1'
        | 'SIGSEGV' | 'SIGUSR2' | 'SIGPIPE' | 'SIGALRM' | 'SIGTERM'
        | 'SIGSTKFLT' | 'SIGCHLD' | 'SIGCONT' | 'SIGSTOP' | 'SIGTSTP'
        | 'SIGBREAK' | 'SIGTTIN' | 'SIGTTOU' | 'SIGURG' | 'SIGXCPU'
        | 'SIGXFSZ' | 'SIGVTALRM' | 'SIGPROF' | 'SIGWINCH' | 'SIGPOLL'
        | 'SIGLOST' | 'SIGPWR' | 'SIGINFO' | 'SIGSYS';

    /**
     * spawn 配置选项
     */
    export interface SpawnOptions<T> {
        /** 标准输入文件描述符或模式 */
        stdin?: number | 'inherit' | 'pipe' | 'ignore';
        /** 标准输出文件描述符或模式 */
        stdout?: number | 'inherit' | 'pipe' | 'ignore';
        /** 标准错误文件描述符或模式 */
        stderr?: number | 'inherit' | 'pipe' | 'ignore';
        /** 工作目录 */
        cwd?: string;
        /** 环境变量 */
        env?: Record<string, string>;
        /** 用户ID */
        uid?: number;
        /** 组ID */
        gid?: number;
        /** 是否独立运行 */
        detached?: boolean;
        /** 是否使用 PTY 模式（默认 false） */
        pty?: T;
        /** PTY 列数（默认 80） */
        cols?: number;
        /** PTY 行数（默认 24） */
        rows?: number;
    }

    /**
     * 子进程退出信息
     */
    export interface ExitInfo {
        exit_status: number;
        term_signal: string | null;
    }

    /**
     * PTY 窗口大小
     */
    export interface WinSize {
        readonly cols: number;
        readonly rows: number;
        readonly xpixel: number;
        readonly ypixel: number;
    }

    /**
     * 子进程对象
     */
    export interface ChildProcess<PTY = false> {
        /** 进程ID */
        readonly pid: number;
        /** 标准输入流（如果配置为 pipe） */
        readonly stdin: PTY extends true ? undefined : Pipe;
        /** 标准输出流（如果配置为 pipe） */
        readonly stdout?: PTY extends true ? undefined : Pipe;
        /** 标准错误流（如果配置为 pipe） */
        readonly stderr?: PTY extends true ? undefined : Pipe;

        /**
         * PTY 可读流（仅 PTY 模式可用）
         * 在 Linux 上与 writable 是同一个对象
         */
        readonly readable?: PTY extends true ? Pipe : undefined;
        /**
         * PTY 可写流（仅 PTY 模式可用）
         * 在 Linux 上与 readable 是同一个对象
         */
        readonly writable?: PTY extends true ? Pipe : undefined;

        /**
         * 等待进程退出
         * @returns 返回退出码和终止信号
         */
        wait(): Promise<ExitInfo>;

        /**
         * 阻塞等待进程退出
         * @returns 返回退出码和终止信号
         */
        waitSync(): ExitInfo;

        /**
         * 向进程发送信号
         * @param signal 要发送的信号，默认 SIGTERM（可以是字符串或数字）
         */
        kill(signal?: Signal | number): void;

        /**
         * 调整 PTY 窗口大小（仅 PTY 模式可用）
         * @param cols 列数
         * @param rows 行数
         */
        resize(cols: number, rows: number): PTY extends true ? void : never;

        /**
         * 获取 PTY 窗口大小（仅 PTY 模式可用）
         * @returns 包含 cols, rows, xpixel, ypixel 的窗口大小对象
         */
        get size():  PTY extends true ? WinSize : never;
    }

    /**
     * 创建子进程
     * @param args 命令字符串或参数数组（第一个元素是要执行的命令）
     * @param options 可选配置
     */
    export function spawn<T>(args: string | string[], options?: SpawnOptions<T>): ChildProcess<T>;

    /**
     * 执行命令（spawn + wait 的简写）
     * @param args 命令字符串或参数数组
     * @param options 可选配置
     */
    export function exec(args: string | string[], options?: SpawnOptions<false>): ChildProcess;

    /**
     * 向指定进程发送信号
     * @param pid 进程ID
     * @param signal 信号（字符串或数字），默认 SIGTERM
     */
    export function kill(pid: number, signal?: Signal | number): void;
}
