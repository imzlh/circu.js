declare namespace CModulePty {
    /**
     * 打开 PTY 的选项
     */
    interface OpenptyOptions {
        /**
         * 列数（可选，默认为 80）
         */
        cols?: number;

        /**
         * 行数（可选，默认为 24）
         */
        rows?: number;

        /**
         * 要执行的命令名称（可选，默认为系统默认 shell）
         */
        name?: string;

        /**
         * 工作目录（可选）
         */
        cwd?: string;

        /**
         * 环境变量对象（可选）
         */
        env?: Record<string, string>;

        /**
         * 命令参数数组（可选）
         */
        argv?: string[];
    }

    /**
     * 打开 PTY 并返回 PTY 信息
     * @param options 打开 PTY 的选项
     * @returns 返回包含文件描述符和进程ID的对象
     */
    function openpty(options?: OpenptyOptions): Promise<{
        /**
         * 文件描述符
         */
        readonly fd: number;

        /**
         * 进程ID
         */
        readonly pid: number;

        /**
         * PTY 句柄（仅在 Windows 上有效）
         */
        readonly pty?: bigint;
    }>;

    /**
     * 调整 PTY 的大小
     * @param fd 文件描述符或 PTY 句柄
     * @param cols 列数
     * @param rows 行数
     */
    function resize(fd: number | bigint, cols: number, rows: number): Promise<void>;

    // 导出所有内容
    export {
        openpty,
        resize
    };
}
