declare namespace CModulePty {
    /**
     * 打开 PTY 的选项
     */
    export interface OpenptyOptions {
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
     * PTY 信息
     */
    export interface PtyInfo {
        /**
         * 文件描述符（CRT fd，跨平台统一）
         */
        readonly fd: number;

        /**
         * 进程ID
         */
        readonly pid: number;

        /**
         * ConPTY 句柄（仅 Windows 上存在，用于 resize）
         */
        readonly pty?: number;
    }

    /**
     * 打开 PTY 并返回 PTY 信息
     * @param options 打开 PTY 的选项
     * @returns 返回包含 fd、pid 的对象（Windows 上额外包含 pty）
     */
    export function openpty(options?: OpenptyOptions): PtyInfo;

    /**
     * 调整 PTY 的窗口大小
     * @param fd 文件描述符
     * @param cols 列数
     * @param rows 行数
     * @param pty ConPTY 句柄（仅 Windows 上需要）
     */
    export function resize(fd: number, cols: number, rows: number, pty?: number): void;

    /**
     * 窗口大小信息
     */
    export interface WinSize {
        /**
         * 列数（字符宽度）
         */
        readonly cols: number;

        /**
         * 行数（字符高度）
         */
        readonly rows: number;

        /**
         * 水平像素数
         */
        readonly xpixel: number;

        /**
         * 垂直像素数
         */
        readonly ypixel: number;
    }

    /**
     * 获取 PTY 的当前窗口大小
     * @param fd 文件描述符
     * @returns 包含 cols, rows, xpixel, ypixel 的窗口大小对象
     */
    export function getwinsize(fd: number): WinSize;
}
