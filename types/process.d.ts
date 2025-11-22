declare namespace CModuleProcess {
    type Pipe = CModuleStreams.Pipe;

    /**
     * 进程退出码
     */
    export const enum ExitCode {
        /** 成功退出 */
        SUCCESS = 0,
        /** 通用错误 */
        FAILURE = 1
    }

    /**
     * 进程信号
     */
    export const enum Signal {
        /** 终止信号 */
        SIGTERM = 'SIGTERM',
        /** 中断信号 */
        SIGINT = 'SIGINT',
        /** 退出信号 */
        SIGQUIT = 'SIGQUIT',
        /** 挂起信号 */
        SIGHUP = 'SIGHUP',
        /** 终止信号（不可捕获） */
        SIGKILL = 'SIGKILL'
    }

    /**
     * spawn 配置选项
     */
    export interface SpawnOptions {
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
    }

    /**
     * 子进程退出信息
     */
    export interface ExitInfo {
        exit_status: number;
        term_signal: string | null;
    }

    /**
     * 子进程对象（对应 C 代码中的 Process 类）
     */
    export interface ChildProcess {
        /** 进程ID */
        readonly pid: number;
        /** 标准输入流（如果配置为 pipe） */
        readonly stdin?: Pipe;
        /** 标准输出流（如果配置为 pipe） */
        readonly stdout?: Pipe;
        /** 标准错误流（如果配置为 pipe） */
        readonly stderr?: Pipe;
        /** 类型标签 */
        readonly [Symbol.toStringTag]: 'Process';

        /**
         * 等待进程退出
         * @returns 返回退出码和终止信号
         */
        wait(): Promise<ExitInfo>;

        /**
         * 向进程发送信号
         * @param signal 要发送的信号，默认 SIGTERM
         */
        kill(signal?: Signal | string): void;
    }

    /**
     * 当前进程接口（对应全局 process 对象）
     */
    export interface CurrentProcess {
        /** 当前进程ID */
        readonly pid: number;
        /** 父进程ID */
        readonly ppid: number;
        /** 平台名称 */
        readonly platform: string;
        /** 当前工作目录 */
        readonly cwd: string;
        /** 环境变量 */
        readonly env: Record<string, string>;
        /** 进程标题 */
        title: string;

        /**
         * 退出当前进程
         * @param code 退出码
         */
        exit(code?: ExitCode | number): never;

        /**
         * 添加信号监听器
         */
        on(signal: Signal | string, listener: () => void): void;

        /**
         * 移除信号监听器
         */
        off(signal: Signal | string, listener: () => void): void;
    }

    /**
     * 创建子进程
     */
    export function spawn(command: string, args?: string[], options?: SpawnOptions): ChildProcess;

    /**
     * 执行命令并返回输出
     */
    export function exec(command: string, args?: string[], options?: SpawnOptions): Promise<string>;

    /**
     * 向指定进程发送信号（全局函数）
     */
    export function kill(pid: number, signal?: Signal | string): void;

    /**
     * 当前进程实例
     */
    export const process: CurrentProcess;
}