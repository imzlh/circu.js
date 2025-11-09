declare namespace CModuleProcess {
    type Pipe = CModuleStreams.Pipe;

    /**
     * 进程退出码
     */
    const enum ExitCode {
        /** 成功退出 */
        SUCCESS = 0,
        /** 通用错误 */
        FAILURE = 1
    }

    /**
     * 进程信号
     */
    const enum ProcessSignal {
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
     * 进程配置选项
     */
    interface ProcessOptions {
        /** 标准输入文件描述符 */
        stdin?: number;
        /** 标准输出文件描述符 */
        stdout?: number;
        /** 标准错误文件描述符 */
        stderr?: number;
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
        /** 是否继承标准输入输出 */
        stdio?: 'inherit' | 'pipe' | 'ignore';
    }

    /**
     * 子进程对象
     */
    interface ChildProcess {
        /**
         * 进程ID
         */
        readonly pid: number;

        /**
         * 标准输入流（如果配置为管道）
         */
        readonly stdin?: Pipe;

        /**
         * 标准输出流（如果配置为管道）
         */
        readonly stdout?: Pipe;

        /**
         * 标准错误流（如果配置为管道）
         */
        readonly stderr?: Pipe;

        /**
         * 等待进程退出
         * @returns 返回一个 Promise，解析为退出码
         */
        wait(): Promise<number>;

        /**
         * 向进程发送信号
         * @param signal 要发送的信号
         */
        kill(signal?: ProcessSignal | string): void;

        /**
         * 子进程对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'ChildProcess';
    }

    /**
     * 进程模块
     */
    interface ProcessModule {
        /**
         * 当前进程ID
         */
        readonly pid: number;

        /**
         * 父进程ID
         */
        readonly ppid: number;

        /**
         * 平台名称
         */
        readonly platform: string;

        /**
         * 当前工作目录
         */
        readonly cwd: string;

        /**
         * 环境变量
         */
        readonly env: Record<string, string>;

        /**
         * 进程标题
         */
        title: string;

        /**
         * 退出当前进程
         * @param code 退出码
         */
        exit(code?: ExitCode | number): never;

        /**
         * 创建子进程
         * @param command 要执行的命令
         * @param args 命令参数数组
         * @param options 进程选项
         * @returns 返回子进程对象
         */
        spawn(command: string, args?: string[], options?: ProcessOptions): ChildProcess;

        /**
         * 执行命令并返回输出
         * @param command 要执行的命令
         * @param options 进程选项
         * @returns 返回一个 Promise，解析为命令输出
         */
        exec(command: string, options?: ProcessOptions): Promise<string>;

        /**
         * 添加信号监听器
         * @param signal 信号名称
         * @param listener 信号处理函数
         */
        on(signal: ProcessSignal | string, listener: () => void): void;

        /**
         * 移除信号监听器
         * @param signal 信号名称
         * @param listener 信号处理函数
         */
        off(signal: ProcessSignal | string, listener: () => void): void;
    }

    // 导出进程模块
    const process: ProcessModule;

    // 导出所有内容
    export {
        ExitCode,
        ProcessSignal,
        ProcessOptions,
        ChildProcess,
        process
    };
}
