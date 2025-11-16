declare namespace TJSFsModule {
    /**
     * 文件打开模式标志（对应C字符串标志）
     * @example 'r' (只读), 'w' (只写创建), 'r+' (读写), 'a' (追加)
     */
    const enum OpenMode {
        /** 只读 */
        READ = 'r',
        /** 只写（创建或截断） */
        WRITE = 'w',
        /** 读写（创建或截断） */
        READ_WRITE = 'r+',
        /** 只写（追加） */
        APPEND = 'a',
        /** 读写（追加） */
        READ_APPEND = 'a+',
        /** 只写（独占创建） */
        EXCLUSIVE = 'wx',
        /** 读写（独占创建） */
        READ_EXCLUSIVE = 'w+x'
    }

    /**
     * 符号链接类型（位标志）
     * @internal 主要用于 Windows 平台
     */
    const enum SymlinkType {
        /** 目录符号链接 */
        DIR = 1,
        /** 连接点（Windows） */
        JUNCTION = 2
    }

    /**
     * 文件类型枚举
     */
    const enum FileType {
        BLOCK = 'block',
        CHAR = 'char',
        DIRECTORY = 'directory',
        FIFO = 'fifo',
        FILE = 'file',
        SOCKET = 'socket',
        SYMLINK = 'symlink'
    }

    /**
     * 文件对象（基于文件描述符）
     * @warning **资源管理警告**：
     * - 必须调用 `close()` 显式关闭，否则将泄漏文件描述符
     * - 未关闭的文件在GC时会同步关闭，可能阻塞事件循环
     */
    class FileHandle {
        /**
         * 从文件读取数据（异步）
         * @param buffer 写入数据的缓冲区（会被修改）
         * @param position 文件读取位置，null表示当前偏移
         * @returns 实际读取字节数，0表示EOF
         * @throws {RangeError} position < 0
         */
        read(buffer: Uint8Array, position?: number | null): Promise<number>;

        /**
         * 向文件写入数据（异步）
         * @param buffer 要写入的数据
         * @param position 文件写入位置，null表示当前偏移
         * @returns 实际写入字节数
         * @throws {RangeError} position < 0
         */
        write(buffer: Uint8Array, position?: number | null): Promise<number>;

        /** 关闭文件（强制释放资源） */
        close(): Promise<void>;

        /** 获取底层文件描述符（用于调试） */
        fileno(): number;

        /** 获取文件元数据（异步） */
        stat(): Promise<StatResult>;

        /** 截断文件到指定大小 */
        truncate(offset?: number): Promise<void>;

        /** 同步文件数据到磁盘（包含元数据） */
        sync(): Promise<void>;

        /** 同步文件数据到磁盘（不包含元数据） */
        datasync(): Promise<void>;

        /** 修改文件权限（如 0o644） */
        chmod(mode: number): Promise<void>;

        /** 修改文件所有者和组 */
        chown(uid: number, gid: number): Promise<void>;

        /** 修改文件访问和修改时间 */
        utime(atime: number, mtime: number): Promise<void>;

        /** 文件路径（创建时传入） */
        readonly path: string;

        readonly [Symbol.toStringTag]: 'FileHandle';
    }

    /**
     * 目录对象（支持异步迭代）
     * @example
     * for await (const ent of dir) {
     *   console.log(ent.name);
     * }
     */
    class DirHandle {
        /** 关闭目录 */
        close(): Promise<void>;

        /** 目录路径 */
        readonly path: string;

        /** 读取下一个目录项（内部使用） */
        next(): Promise<{ value: DirEnt, done: false } | { done: true, value: undefined }>;

        /** 获取异步迭代器 */
        [Symbol.asyncIterator](): AsyncIterableIterator<DirEnt>;

        readonly [Symbol.toStringTag]: 'DirHandle';
    }

    /**
     * 目录项对象（readdir结果）
     */
    interface DirEnt {
        readonly name: string;
        readonly isBlockDevice: boolean;
        readonly isCharacterDevice: boolean;
        readonly isDirectory: boolean;
        readonly isFIFO: boolean;
        readonly isFile: boolean;
        readonly isSocket: boolean;
        readonly isSymbolicLink: boolean;
        readonly [Symbol.toStringTag]: 'DirEnt';
    }

    /**
     * 文件统计信息（stat结果）
     */
    interface StatResult {
        readonly isBlockDevice: boolean;
        readonly isCharacterDevice: boolean;
        readonly isDirectory: boolean;
        readonly isFIFO: boolean;
        readonly isFile: boolean;
        readonly isSocket: boolean;
        readonly isSymbolicLink: boolean;
        readonly dev: number;
        readonly mode: number;
        readonly nlink: number;
        readonly uid: number;
        readonly gid: number;
        readonly rdev: number;
        readonly ino: number;
        readonly size: number;
        readonly blksize: number;
        readonly blocks: number;
        readonly flags: number;
        readonly atime: Date;
        readonly mtime: Date;
        readonly ctime: Date;
        readonly birthtime: Date;
        readonly [Symbol.toStringTag]: 'StatResult';
    }

    /**
     * 文件系统统计信息
     */
    interface StatFsResult {
        readonly type: number;
        readonly bsize: number;
        readonly blocks: number;
        readonly bfree: number;
        readonly bavail: number;
        readonly files: number;
        readonly ffree: number;
    }

    /* ==================== 文件操作 ==================== */

    /**
     * 打开文件（异步）
     * @param path 文件路径
     * @param flags 打开模式（如 OpenMode.READ）
     * @param mode 权限（默认0o666）
     */
    function open(path: string, flags: OpenMode | string, mode?: number): Promise<FileHandle>;

    /** 获取文件元数据（异步） */
    function stat(path: string): Promise<StatResult>;

    /** 获取符号链接本身元数据（异步） */
    function lstat(path: string): Promise<StatResult>;

    /** 
     * 获取文件的绝对路径（异步）
     * @throws {Error} 路径不存在或权限不足
     */
    function realPath(path: string): Promise<string>;

    /** 删除文件（异步） */
    function unlink(path: string): Promise<void>;

    /** 重命名文件（异步） */
    function rename(path: string, newPath: string): Promise<void>;

    /** 复制文件（异步） */
    function copyFile(path: string, newPath: string): Promise<void>;

    /** 读取文件全部内容到内存（异步）
     * @warning **内存警告**：大文件会消耗大量内存
     * @param path 文件路径
     * @returns 文件内容的Uint8Array视图
     */
    function readFile(path: string): Promise<Uint8Array>;

    /* ==================== 目录操作 ==================== */

    /** 创建目录（异步） */
    function mkdir(path: string, mode?: number): Promise<void>;

    /** 创建目录（同步） */
    function mkdirSync(path: string, mode?: number): void;

    /** 删除空目录（异步） */
    function rmdir(path: string): Promise<void>;

    /** 打开目录（支持迭代） */
    function readDir(path: string): Promise<DirHandle>;

    /** 创建临时目录（异步） */
    function makeTempDir(template: string): Promise<string>;

    /* ==================== 链接操作 ==================== */

    /** 读取符号链接目标（异步） */
    function readLink(path: string): Promise<string>;

    /** 创建硬链接（异步） */
    function link(path: string, newPath: string): Promise<void>;

    /** 创建符号链接（异步） */
    function symlink(path: string, newPath: string, type: SymlinkType): Promise<void>;

    /* ==================== 权限操作 ==================== */

    /** 修改文件权限（异步） */
    function chmod(path: string, mode: number): Promise<void>;

    /** 修改文件所有者和组（异步） */
    function chown(path: string, uid: number, gid: number): Promise<void>;

    /** 修改符号链接本身所有者和组（异步） */
    function lchown(path: string, uid: number, gid: number): Promise<void>;

    /** 修改文件时间戳（异步） */
    function utime(path: string, atime: number, mtime: number): Promise<void>;

    /** 修改符号链接本身时间戳（异步） */
    function lutime(path: string, atime: number, mtime: number): Promise<void>;

    /* ==================== 文件系统信息 ==================== */

    /** 获取文件系统统计信息（异步） */
    function statFs(path: string): Promise<StatFsResult>;

    /* ==================== 内部API（不推荐） ==================== */

    /**
     * 从已打开的文件描述符创建FileHandle（内部使用）
     * @internal
     */
    function newStdioFile(path: string, fd: number): FileHandle;

    /**
     * 获取文件元数据（同步）
     * @internal 仅用于特殊场景，避免阻塞事件循环
     */
    function statSync(path: string): StatResult;
}