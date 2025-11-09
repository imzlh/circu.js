declare namespace CModuleFS {
    /**
     * 文件打开模式标志
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
     * 符号链接标志
     */
    const enum SymlinkType {
        /** 目录符号链接 */
        DIR = 1,
        /** 连接点符号链接（Windows） */
        JUNCTION = 2
    }

    /**
     * 文件类型枚举
     */
    const enum FileType {
        /** 块设备 */
        BLOCK = 'block',
        /** 字符设备 */
        CHAR = 'char',
        /** 目录 */
        DIRECTORY = 'directory',
        /** FIFO 管道 */
        FIFO = 'fifo',
        /** 普通文件 */
        FILE = 'file',
        /** 套接字 */
        SOCKET = 'socket',
        /** 符号链接 */
        SYMLINK = 'symlink'
    }

    /**
     * 文件对象
     */
    interface FileHandle {
        /**
         * 从文件中读取数据。
         * @param buffer 用于存储读取数据的缓冲区。
         * @param position 文件中读取数据的起始位置（可选）。
         * @returns 返回一个 Promise，解析为读取的数据长度。
         */
        read(buffer: Uint8Array, position?: number): Promise<number>;

        /**
         * 向文件中写入数据。
         * @param buffer 包含要写入数据的缓冲区。
         * @param position 文件中写入数据的起始位置（可选）。
         * @returns 返回一个 Promise，解析为写入的数据长度。
         */
        write(buffer: Uint8Array, position?: number): Promise<number>;

        /**
         * 关闭文件。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(): Promise<void>;

        /**
         * 获取文件的文件描述符。
         * @returns 返回文件描述符。
         */
        fileno(): number;

        /**
         * 获取文件的统计信息。
         * @returns 返回一个 Promise，解析为 StatResult 对象。
         */
        stat(): Promise<StatResult>;

        /**
         * 截断文件到指定长度。
         * @param offset 截断后的文件长度。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        truncate(offset?: number): Promise<void>;

        /**
         * 同步文件内容到磁盘。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        sync(): Promise<void>;

        /**
         * 同步文件内容到磁盘，忽略文件的修改时间。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        datasync(): Promise<void>;

        /**
         * 更改文件的权限。
         * @param mode 新的权限模式。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        chmod(mode: number): Promise<void>;

        /**
         * 更改文件的所有者和组。
         * @param uid 新的所有者ID。
         * @param gid 新的组ID。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        chown(uid: number, gid: number): Promise<void>;

        /**
         * 更改文件的访问和修改时间。
         * @param atime 新的访问时间（Unix 时间戳，毫秒）。
         * @param mtime 新的修改时间（Unix 时间戳，毫秒）。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        utime(atime: number, mtime: number): Promise<void>;

        /**
         * 获取文件的路径。
         */
        readonly path: string;

        /**
         * 文件对象的类型标签。
         */
        readonly [Symbol.toStringTag]: 'FileHandle';
    }

    /**
     * 目录对象
     */
    interface DirHandle {
        /**
         * 关闭目录。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(): Promise<void>;

        /**
         * 获取目录的路径。
         */
        readonly path: string;

        /**
         * 读取目录中的下一项。
         * @returns 返回一个 Promise，解析为 DirEnt 对象或 undefined。
         */
        next(): Promise<DirEnt | undefined>;

        /**
         * 获取目录对象的异步迭代器。
         * @returns 返回一个迭代器对象。
         */
        [Symbol.asyncIterator](): AsyncIterableIterator<DirEnt>;

        /**
         * 目录对象的类型标签。
         */
        readonly [Symbol.toStringTag]: 'DirHandle';
    }

    /**
     * 目录项对象
     */
    interface DirEnt {
        /**
         * 目录项的名称。
         */
        readonly name: string;

        /**
         * 检查目录项是否为块设备。
         * @returns 返回布尔值，表示是否为块设备。
         */
        readonly isBlockDevice: boolean;

        /**
         * 检查目录项是否为字符设备。
         * @returns 返回布尔值，表示是否为字符设备。
         */
        readonly isCharacterDevice: boolean;

        /**
         * 检查目录项是否为目录。
         * @returns 返回布尔值，表示是否为目录。
         */
        readonly isDirectory: boolean;

        /**
         * 检查目录项是否为 FIFO 管道。
         * @returns 返回布尔值，表示是否为 FIFO 管道。
         */
        readonly isFIFO: boolean;

        /**
         * 检查目录项是否为普通文件。
         * @returns 返回布尔值，表示是否为普通文件。
         */
        readonly isFile: boolean;

        /**
         * 检查目录项是否为套接字。
         * @returns 返回布尔值，表示是否为套接字。
         */
        readonly isSocket: boolean;

        /**
         * 检查目录项是否为符号链接。
         * @returns 返回布尔值，表示是否为符号链接。
         */
        readonly isSymbolicLink: boolean;

        /**
         * 目录项对象的类型标签。
         */
        readonly [Symbol.toStringTag]: 'DirEnt';
    }

    /**
     * 文件统计信息对象
     */
    interface StatResult {
        /**
         * 检查是否为块设备。
         * @returns 返回布尔值，表示是否为块设备。
         */
        readonly isBlockDevice: boolean;

        /**
         * 检查是否为字符设备。
         * @returns 返回布尔值，表示是否为字符设备。
         */
        readonly isCharacterDevice: boolean;

        /**
         * 检查是否为目录。
         * @returns 返回布尔值，表示是否为目录。
         */
        readonly isDirectory: boolean;

        /**
         * 检查是否为 FIFO 管道。
         * @returns 返回布尔值，表示是否为 FIFO 管道。
         */
        readonly isFIFO: boolean;

        /**
         * 检查是否为普通文件。
         * @returns 返回布尔值，表示是否为普通文件。
         */
        readonly isFile: boolean;

        /**
         * 检查是否为套接字。
         * @returns 返回布尔值，表示是否为套接字。
         */
        readonly isSocket: boolean;

        /**
         * 检查是否为符号链接。
         * @returns 返回布尔值，表示是否为符号链接。
         */
        readonly isSymbolicLink: boolean;

        /**
         * 文件的设备ID。
         */
        readonly dev: number;

        /**
         * 文件的模式（权限）。
         */
        readonly mode: number;

        /**
         * 文件的链接数。
         */
        readonly nlink: number;

        /**
         * 文件的所有者ID。
         */
        readonly uid: number;

        /**
         * 文件的组ID。
         */
        readonly gid: number;

        /**
         * 文件的设备ID（特殊文件）。
         */
        readonly rdev: number;

        /**
         * 文件的 inode 编号。
         */
        readonly ino: number;

        /**
         * 文件大小（字节）。
         */
        readonly size: number;

        /**
         * 文件块大小。
         */
        readonly blksize: number;

        /**
         * 文件的块数。
         */
        readonly blocks: number;

        /**
         * 文件标志。
         */
        readonly flags: number;

        /**
         * 文件的访问时间。
         */
        readonly atime: Date;

        /**
         * 文件的修改时间。
         */
        readonly mtime: Date;

        /**
         * 文件的更改时间。
         */
        readonly ctime: Date;

        /**
         * 文件的创建时间（仅在某些系统上可用）。
         */
        readonly birthtime: Date;

        /**
         * 文件统计信息对象的类型标签。
         */
        readonly [Symbol.toStringTag]: 'StatResult';
    }

    /**
     * 打开文件并返回文件句柄。
     * @param path 文件路径。
     * @param flags 打开模式标志（如 'r', 'w', 'r+', 'a', 'a+', 'wx', 'w+x'）。
     * @param mode 文件权限模式（可选，默认为 0666）。
     * @returns 返回一个 Promise，解析为 FileHandle 对象。
     */
    function open(path: string, flags: OpenMode | string, mode?: number): Promise<FileHandle>;

    /**
     * 创建一个新的 stdio 文件句柄。
     * @param path 文件路径。
     * @param fd 文件描述符。
     * @returns 返回 FileHandle 对象。
     */
    function newStdioFile(path: string, fd: number): FileHandle;

    /**
     * 获取文件的统计信息。
     * @param path 文件路径。
     * @returns 返回一个 Promise，解析为 StatResult 对象。
     */
    function stat(path: string): Promise<StatResult>;

    /**
     * 获取文件的链接统计信息。
     * @param path 文件路径。
     * @returns 返回一个 Promise，解析为 StatResult 对象。
     */
    function lstat(path: string): Promise<StatResult>;

    /**
     * 获取文件的绝对路径。
     * @param path 文件路径。
     * @returns 返回一个 Promise，解析为绝对路径字符串。
     */
    function realPath(path: string): Promise<string>;

    /**
     * 删除文件。
     * @param path 文件路径。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function unlink(path: string): Promise<void>;

    /**
     * 重命名文件。
     * @param path 当前文件路径。
     * @param newPath 新文件路径。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function rename(path: string, newPath: string): Promise<void>;

    /**
     * 创建临时目录。
     * @param template 模板路径（包含 'X' 字符）。
     * @returns 返回一个 Promise，解析为临时目录路径字符串。
     */
    function makeTempDir(template: string): Promise<string>;

    /**
     * 创建临时文件。
     * @param template 模板路径（包含 'X' 字符）。
     * @returns 返回一个 Promise，解析为 FileHandle 对象。
     */
    function mkstemp(template: string): Promise<FileHandle>;

    /**
     * 删除目录。
     * @param path 目录路径。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function rmdir(path: string): Promise<void>;

    /**
     * 创建目录。
     * @param path 目录路径。
     * @param mode 目录权限模式（可选，默认为 0777）。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function mkdir(path: string, mode?: number): Promise<void>;

    /**
     * 同步创建目录。
     * @param path 目录路径。
     * @param mode 目录权限模式（可选，默认为 0777）。
     */
    function mkdirSync(path: string, mode?: number): void;

    /**
     * 复制文件。
     * @param path 源文件路径。
     * @param newPath 目标文件路径。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function copyFile(path: string, newPath: string): Promise<void>;

    /**
     * 读取目录内容。
     * @param path 目录路径。
     * @returns 返回一个 Promise，解析为 DirHandle 对象。
     */
    function readDir(path: string): Promise<DirHandle>;

    /**
     * 读取文件内容。
     * @param path 文件路径。
     * @returns 返回一个 Promise，解析为文件内容的 Uint8Array。
     */
    function readFile(path: string): Promise<Uint8Array>;

    /**
     * 获取文件的统计信息（同步）。
     * @param path 文件路径。
     * @returns 返回 StatResult 对象。
     */
    function statSync(path: string): StatResult;

    /**
     * 更改文件的所有者和组。
     * @param path 文件路径。
     * @param uid 新的所有者ID。
     * @param gid 新的组ID。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function chown(path: string, uid: number, gid: number): Promise<void>;

    /**
     * 更改符号链接的所有者和组。
     * @param path 符号链接路径。
     * @param uid 新的所有者ID。
     * @param gid 新的组ID。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function lchown(path: string, uid: number, gid: number): Promise<void>;

    /**
     * 更改文件的权限。
     * @param path 文件路径。
     * @param mode 新的权限模式。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function chmod(path: string, mode: number): Promise<void>;

    /**
     * 更改文件的访问和修改时间。
     * @param path 文件路径。
     * @param atime 新的访问时间（Unix 时间戳，毫秒）。
     * @param mtime 新的修改时间（Unix 时间戳，毫秒）。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function utime(path: string, atime: number, mtime: number): Promise<void>;

    /**
     * 更改符号链接的访问和修改时间。
     * @param path 符号链接路径。
     * @param atime 新的访问时间（Unix 时间戳，毫秒）。
     * @param mtime 新的修改时间（Unix 时间戳，毫秒）。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function lutime(path: string, atime: number, mtime: number): Promise<void>;

    /**
     * 读取符号链接的目标路径。
     * @param path 符号链接路径。
     * @returns 返回一个 Promise，解析为符号链接的目标路径字符串。
     */
    function readLink(path: string): Promise<string>;

    /**
     * 创建硬链接。
     * @param path 现有文件路径。
     * @param newPath 新的硬链接路径。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function link(path: string, newPath: string): Promise<void>;

    /**
     * 创建符号链接。
     * @param path 现有文件路径。
     * @param newPath 新的符号链接路径。
     * @param type 符号链接类型（如 SymlinkType.DIR 或 SymlinkType.JUNCTION）。
     * @returns 返回一个 Promise，解析为 undefined。
     */
    function symlink(path: string, newPath: string, type: SymlinkType): Promise<void>;

    /**
     * 获取文件系统的统计信息。
     * @param path 文件路径（用于确定文件系统）。
     * @returns 返回一个 Promise，解析为文件系统统计信息对象。
     */
    function statFs(path: string): Promise<StatFsResult>;

    /**
     * 文件系统统计信息对象
     */
    interface StatFsResult {
        /**
         * 文件系统类型。
         */
        readonly type: number;

        /**
         * 文件系统块大小。
         */
        readonly bsize: number;

        /**
         * 文件系统总块数。
         */
        readonly blocks: number;

        /**
         * 文件系统空闲块数。
         */
        readonly bfree: number;

        /**
         * 文件系统可用块数。
         */
        readonly bavail: number;

        /**
         * 文件系统总文件数。
         */
        readonly files: number;

        /**
         * 文件系统空闲文件数。
         */
        readonly ffree: number;
    }

    // 导出所有内容
    export {
        OpenMode,
        SymlinkType,
        FileType,
        FileHandle,
        DirHandle,
        DirEnt,
        StatResult,
        StatFsResult,
        open,
        newStdioFile,
        stat,
        lstat,
        realPath,
        unlink,
        rename,
        makeTempDir,
        mkstemp,
        rmdir,
        mkdir,
        mkdirSync,
        chmod,
        copyFile,
        readDir,
        readFile,
        statSync,
        chown,
        lchown,
        utime,
        lutime,
        readLink,
        link,
        symlink,
        statFs
    };
}
