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
    export interface SpawnOptions {
        stdin?: number | 'inherit' | 'pipe' | 'ignore';
        stdout?: number | 'inherit' | 'pipe' | 'ignore';
        stderr?: number | 'inherit' | 'pipe' | 'ignore';
        cwd?: string;
        env?: Record<string, string>;
        uid?: number;
        gid?: number;
        detached?: boolean;
        /** When true, spawn the process in a PTY */
        pty?: boolean;
        /** PTY columns (default 80) */
        cols?: number;
        /** PTY rows (default 24) */
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
    export interface ChildProcess {
        /** 进程ID */
        readonly pid: number;
        /** 标准输入流（normal mode, stdin: pipe） */
        readonly stdin?: Pipe;
        /** 标准输出流（normal mode, stdout: pipe） */
        readonly stdout?: Pipe;
        /** 标准错误流（normal mode, stderr: pipe） */
        readonly stderr?: Pipe;

        /**
         * PTY 可读流（仅 PTY 模式可用）
         * 在 Linux 上与 writable 是同一个对象
         */
        readonly readable?: Pipe;
        /**
         * PTY 可写流（仅 PTY 模式可用）
         * 在 Linux 上与 readable 是同一个对象
         */
        readonly writable?: Pipe;

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
        resize(cols: number, rows: number): void;

        /**
         * 获取 PTY 窗口大小（仅 PTY 模式可用）
         * @returns 包含 cols, rows 的窗口大小对象
         */
        getwinsize(): WinSize;
    }

    /**
     * 创建子进程
     * @param args 命令字符串或参数数组（第一个元素是要执行的命令）
     * @param options 可选配置
     * @returns 子进程对象
     */
    export function spawn(args: string | string[], options?: SpawnOptions): ChildProcess;

    /**
     * 向指定进程发送信号
     * @param pid 进程ID
     * @param signal 信号（字符串或数字），默认 SIGTERM
     */
    export function kill(pid: number, signal?: Signal | number): void;
}
