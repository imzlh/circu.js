declare namespace CModuleAsyncFS {
    type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

    /**
     * File open mode flags (corresponding to C string flags)
     * @example 'r' (read-only), 'w' (write-create), 'r+' (read-write), 'a' (append)
     */
    const enum OpenMode {
        /** Read-only */
        READ = 'r',
        /** Write-only (create or truncate) */
        WRITE = 'w',
        /** Read-write (create or truncate) */
        READ_WRITE = 'r+',
        /** Write-only (append) */
        APPEND = 'a',
        /** Read-write (append) */
        READ_APPEND = 'a+',
        /** Write-only (exclusive create) */
        EXCLUSIVE = 'wx',
        /** Read-write (exclusive create) */
        READ_EXCLUSIVE = 'w+x'
    }

    /**
     * Symlink type (bit flags)
     * @internal Mainly used on Windows platform
     */
    enum SymlinkType {
        /** Directory symlink */
        DIR = 1,
        /** Junction point (Windows) */
        JUNCTION = 2
    }

    /**
     * File type enumeration
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
     * File handle object (based on file descriptor)
     * @warning **Resource management warning**:
     * - Must call `close()` explicitly, otherwise file descriptor will leak
     * - Unclosed files are closed synchronously during GC, which may block the event loop
     */
    class FileHandle {
        /**
         * Read data from file (async)
         * @param buffer Buffer to write data into (will be modified)
         * @param position File read position, null means current offset
         * @returns Actual bytes read, 0 indicates EOF
         * @throws {RangeError} position < 0
         */
        read(buffer: Uint8Array, position?: number | null): Promise<number>;

        /**
         * Write data to file (async)
         * @param buffer Data to write
         * @param position File write position, null means current offset
         * @returns Actual bytes written
         * @throws {RangeError} position < 0
         */
        write(buffer: Uint8Array, position?: number | null): Promise<number>;

        /** Close file (force release resource) */
        close(): void;

        /** Get underlying file descriptor (for debugging) */
        fileno(): number;

        /** Get file metadata (async) */
        stat(): Promise<StatResult>;

        /** Truncate file to specified size */
        truncate(offset?: number): Promise<void>;

        /** Sync file data to disk (including metadata) */
        sync(): Promise<void>;

        /** Sync file data to disk (excluding metadata) */
        datasync(): Promise<void>;

        /** Change file permissions (e.g., 0o644) */
        chmod(mode: number): Promise<void>;

        /** Change file owner and group */
        chown(uid: number, gid: number): Promise<void>;

        /** Change file access and modification times */
        utime(atime: number, mtime: number): Promise<void>;

        /** File path (passed during creation) */
        readonly path: string;

        readonly [Symbol.toStringTag]: 'FileHandle';
    }

    /**
     * Directory handle object (supports async iteration)
     * @example
     * for await (const ent of dir) {
     *   console.log(ent.name);
     * }
     */
    class DirHandle {
        /** Close directory */
        close(): Promise<void>;

        /** Directory path */
        readonly path: string;

        /** Read next directory entry (internal use) */
        next(): Promise<{ value: DirEnt, done: false } | { done: true, value: undefined }>;

        /** Get async iterator */
        [Symbol.asyncIterator](): AsyncIterableIterator<DirEnt>;

        readonly [Symbol.toStringTag]: 'DirHandle';
    }

    /**
     * Directory entry object (readdir result)
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
     * File statistics (stat result)
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
     * Filesystem statistics
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

    /* ==================== File Operations ==================== */

    /**
     * Open file (async)
     * @param path File path
     * @param flags Open mode (e.g., OpenMode.READ)
     * @param mode Permissions (default 0o666)
     */
    function open(path: string, flags: OpenMode | string, mode?: number): Promise<FileHandle>;

    /** Get file metadata (async) */
    function stat(path: string): Promise<StatResult>;

    /** Get symlink itself metadata (async) */
    function lstat(path: string): Promise<StatResult>;

    /** 
     * Get file absolute path (async)
     * @throws {Error} Path does not exist or permission denied
     */
    function realPath(path: string): Promise<string>;

    /** Delete file (async) */
    function unlink(path: string): Promise<void>;

    /** Rename file (async) */
    function rename(path: string, newPath: string): Promise<void>;

    /** Copy file (async) */
    function copyFile(path: string, newPath: string): Promise<void>;

    /** 
     * Read entire file into memory (async)
     * @warning **Memory warning**: Large files consume significant memory
     * @param path File path
     * @returns Uint8Array view of file contents
     */
    function readFile(path: string): Promise<Uint8Array>;

    /* ==================== Directory Operations ==================== */

    /** Create directory (async) */
    function mkdir(path: string, mode?: number): Promise<void>;

    /** Create directory (sync) */
    function mkdirSync(path: string, mode?: number): void;

    /** Remove empty directory (async) */
    function rmdir(path: string): Promise<void>;

    /** Open directory (supports iteration) */
    function readDir(path: string): Promise<DirHandle>;

    /** Create temporary directory (async) */
    function makeTempDir(template: string): Promise<string>;

    /* ==================== Link Operations ==================== */

    /** Read symlink target (async) */
    function readLink(path: string): Promise<string>;

    /** Create hard link (async) */
    function link(path: string, newPath: string): Promise<void>;

    /** Create symbolic link (async) */
    function symlink(path: string, newPath: string, type: SymlinkType): Promise<void>;

    /* ==================== Permission Operations ==================== */

    /** Change file permissions (async) */
    function chmod(path: string, mode: number): Promise<void>;

    /** Change file owner and group (async) */
    function chown(path: string, uid: number, gid: number): Promise<void>;

    /** Change symlink itself owner and group (async) */
    function lchown(path: string, uid: number, gid: number): Promise<void>;

    /** Change file timestamps (async) */
    function utime(path: string, atime: number, mtime: number): Promise<void>;

    /** Change symlink itself timestamps (async) */
    function lutime(path: string, atime: number, mtime: number): Promise<void>;

    /* ==================== Filesystem Information ==================== */

    /** Get filesystem statistics (async) */
    function statFs(path: string): Promise<StatFsResult>;

    /* ==================== Internal API (not recommended) ==================== */

    /**
     * Create FileHandle from opened file descriptor (internal use)
     * @internal
     */
    function newStdioFile(path: string, fd: number): FileHandle;

    /**
     * Get file metadata (sync)
     * @internal Only for special scenarios, avoid blocking event loop
     */
    function statSync(path: string): StatResult;
}