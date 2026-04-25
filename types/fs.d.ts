/**
 * txiki.js syncfs module type definitions
 * Synchronous filesystem operations for IO-intensive scripts and module loading
 * Cross-platform: POSIX + Windows
 * 
 * @example Read and write files
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * // Read entire file
 * const content = fs.readFile('input.txt');
 * const text = new TextDecoder().decode(content);
 * 
 * // Write entire file
 * const data = new TextEncoder().encode('Hello, World!');
 * fs.writeFile('output.txt', data);
 * ```
 * @example  Check file existence and stats
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * if (fs.exists('file.txt')) {
 *   const stats = fs.stat('file.txt');
 *   console.log(`Size: ${stats.size} bytes`);
 *   console.log(`Modified: ${new Date(stats.mtime)}`);
 *   console.log(`Is file: ${stats.isFile}`);
 *   console.log(`Is directory: ${stats.isDirectory}`);
 * }
 * ```
 * @example  Low-level file operations
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * // Open file for reading
 * const fd = fs.open('data.bin', 'r');
 * 
 * // Read into buffer
 * const buffer = new Uint8Array(1024);
 * const bytesRead = fs.read(fd, buffer);
 * // or positioned read
 * const bytesRead = fs.pread(fd, buffer, 100, 1024);
 * console.log(`Read ${bytesRead} bytes`);
 * 
 * // Close file
 * fs.close(fd);
 * ```
 * @example  Write file in chunks
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * const fd = fs.open('output.bin', 'w', 0o644);
 * 
 * const chunk1 = new Uint8Array([1, 2, 3, 4]);
 * const chunk2 = new Uint8Array([5, 6, 7, 8]);
 * 
 * fs.write(fd, chunk1);
 * fs.write(fd, chunk2);
 * // or positioned write
 * fs.pwrite(fd, chunk1, 100);
 * 
 * fs.close(fd);
 * ```
 * @example  Directory operations
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * // Create directory
 * fs.mkdir('mydir', 0o755);
 * 
 * // List directory contents
 * const files = fs.readdir('mydir');
 * for (const file of files) {
 *   console.log(file);
 * }
 * 
 * // Remove directory
 * fs.rmdir('mydir');
 * ```
 * @example  File management
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * // Rename/move file
 * fs.rename('old.txt', 'new.txt');
 * 
 * // Delete file
 * fs.unlink('temp.txt');
 * ```
 * @example  Custom module loader using syncfs
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function loadModule(path: string): any {
 *   // Resolve absolute path
 *   const absPath = fs.realpath(path);
 *   
 *   // Check if file exists
 *   if (!fs.exists(absPath)) {
 *     throw new Error(`Module not found: ${path}`);
 *   }
 *   
 *   // Read module source
 *   const source = fs.readFile(absPath);
 *   const code = new TextDecoder().decode(source);
 *   
 *   // Compile and execute
 *   const module = { exports: {} };
 *   const func = new Function('module', 'exports', code);
 *   func(module, module.exports);
 *   
 *   return module.exports;
 * }
 * ```
 * @example  File copy implementation
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function copyFile(src: string, dest: string): void {
 *   const data = fs.readFile(src);
 *   const stats = fs.stat(src);
 *   fs.writeFile(dest, data, stats.mode & 0o777);
 * }
 * 
 * copyFile('source.txt', 'destination.txt');
 * ```
 * @example  Directory tree walker
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function walkDir(dir: string, callback: (path: string, stats: Stats) => void): void {
 *   const entries = fs.readdir(dir);
 *   
 *   for (const entry of entries) {
 *     const fullPath = `${dir}/${entry}`;
 *     const stats = fs.stat(fullPath);
 *     
 *     callback(fullPath, stats);
 *     
 *     if (stats.isDirectory) {
 *       walkDir(fullPath, callback);
 *     }
 *   }
 * }
 * 
 * // Usage
 * walkDir('.', (path, stats) => {
 *   console.log(`${path}: ${stats.size} bytes`);
 * });
 * ```
 * @example  Atomic file write
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function writeFileAtomic(path: string, data: ArrayBuffer | Uint8Array): void {
 *   const tmpPath = `${path}.tmp`;
 *   
 *   // Write to temporary file
 *   fs.writeFile(tmpPath, data);
 *   
 *   // Atomic rename
 *   fs.rename(tmpPath, path);
 * }
 * 
 * const data = new TextEncoder().encode('Important data');
 * writeFileAtomic('config.json', data);
 * ```
 * @example  Check write permissions
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function canWrite(path: string): boolean {
 *   try {
 *     const stats = fs.stat(path);
 *     // Check user write permission
 *     return (stats.mode & fs.S_IWUSR) !== 0;
 *   } catch (e) {
 *     return false;
 *   }
 * }
 * ```
 * @example  Read file with specific encoding
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function readTextFile(path: string, encoding: string = 'utf-8'): string {
 *   const buffer = fs.readFile(path);
 *   const decoder = new TextDecoder(encoding);
 *   return decoder.decode(buffer);
 * }
 * 
 * const content = readTextFile('data.txt', 'utf-8');
 * ```
 * @example  Safe directory creation (recursive)
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * function mkdirRecursive(path: string, mode: number = 0o777): void {
 *   const parts = path.split('/').filter(p => p);
 *   let current = path.startsWith('/') ? '/' : '';
 *   
 *   for (const part of parts) {
 *     current += part;
 *     
 *     if (!fs.exists(current)) {
 *       fs.mkdir(current, mode);
 *     }
 *     
 *     current += '/';
 *   }
 * }
 * 
 * mkdirRecursive('path/to/nested/dir');
 * ```
 * @example Use with flags constants
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * // Open with explicit flags
 * const fd = fs.open('file.bin', fs.O_RDWR | fs.O_CREAT, 0o644);
 * 
 * const buffer = new Uint8Array(100);
 * fs.read(fd, buffer);
 * 
 * fs.close(fd);
 * ```
 * @example Blocking STDIN read
 * ```typescript
 * const fs = import.meta.use('fs')
 * 
 * fs.setBlocking(0, true); // Set stdin to blocking mode
 * const buffer = new Uint8Array(1024);
 * const bytesRead = fs.read(0, buffer);
 * console.log(`Read ${bytesRead} bytes`);
 * ```
 */
declare namespace CModuleFS {
    // ============================================================================
    // File Open Flags
    // ============================================================================

    /** Open for reading only */
    export const OPEN_RDONLY: number;
    /** Open for writing only */
    export const OPEN_WRONLY: number;
    /** Open for reading and writing */
    export const OPEN_RDWR: number;
    /** Create file if it doesn't exist */
    export const OPEN_CREAT: number;
    /** Error if O_CREAT and file exists */
    export const OPEN_EXCL: number;
    /** Truncate file to zero length */
    export const OPEN_TRUNC: number;
    /** Append to file */
    export const OPEN_APPEND: number;

    // ============================================================================
    // File Mode Constants
    // ============================================================================

    /** File type mask */
    export const S_IFMT: number;
    /** Regular file */
    export const S_IFREG: number;
    /** Directory */
    export const S_IFDIR: number;
    /** User read/write/execute */
    export const S_IRWXU: number;
    /** User read permission */
    export const S_IRUSR: number;
    /** User write permission */
    export const S_IWUSR: number;
    /** User execute permission */
    export const S_IXUSR: number;
    /** Group read/write/execute */
    export const S_IRWXG: number;
    /** Group read permission */
    export const S_IRGRP: number;
    /** Group write permission */
    export const S_IWGRP: number;
    /** Group execute permission */
    export const S_IXGRP: number;
    /** Other read/write/execute */
    export const S_IRWXO: number;
    /** Other read permission */
    export const S_IROTH: number;
    /** Other write permission */
    export const S_IWOTH: number;
    /** Other execute permission */
    export const S_IXOTH: number;

    // ============================================================================
    // File Locking Constants
    // ============================================================================

    /** Shared lock */
    export const LOCK_SH: number;
    /** Exclusive lock */
    export const LOCK_EX: number;
    /** Non-blocking lock */
    export const LOCK_NB: number;
    /** Unlock */
    export const LOCK_UN: number;

    // ============================================================================
    // Access Mode Constants
    // ============================================================================

    /** File exists */
    export const F_OK: number;
    /** Read permission */
    export const R_OK: number;
    /** Write permission */
    export const W_OK: number;
    /** Execute permission */
    export const X_OK: number;

    // ============================================================================
    // Types
    // ============================================================================

    /**
     * File statistics information
     */
    type Stats = CModuleAsyncFS.StatResult;

    /**
     * File open flags - string shortcuts
     */
    export type OpenFlags =
        | 'r'    // Read only
        | 'r+'   // Read and write
        | 'w'    // Write (create/truncate)
        | 'w+'   // Read and write (create/truncate)
        | 'a'    // Append (create if not exists)
        | 'a+'   // Read and append (create if not exists)
        | 'wx'   // Write exclusive (fail if exists)
        | 'wx+'  // Read and write exclusive (fail if exists)
        | number; // Raw flag value

    // ============================================================================
    // File Status Functions
    // ============================================================================

    /**
     * Get file status (follows symlinks)
     * @param path - File path
     * @returns File statistics
     * @throws Error if file doesn't exist or access denied
     */
    export function stat(path: string): Stats;

    /**
     * Get file status (doesn't follow symlinks)
     * @param path - File path
     * @returns File statistics
     * @throws Error if file doesn't exist or access denied
     */
    export function lstat(path: string): Stats;

    /**
     * Check if file or directory exists
     * @param path - File path
     * @returns true if exists, false otherwise
     */
    export function exists(path: string): boolean;

    // ============================================================================
    // Low-Level File Operations
    // ============================================================================

    /**
     * Open a file and return file descriptor
     * @param path - File path
     * @param flags - Open flags (string or number)
     * @param mode - File permissions (default: 0o666)
     * @returns File descriptor (integer)
     * @throws Error if open fails
     */
    export function open(path: string, flags: OpenFlags, mode?: number): number;

    /**
     * Close a file descriptor
     * @param fd - File descriptor
     * @throws Error if close fails
     */
    export function close(fd: number): void;

    /**
     * Read data from file descriptor into buffer
     * @param fd - File descriptor
     * @param buffer - Buffer to read into
     * @returns Number of bytes actually read
     * @throws Error if read fails
     */
    export function read(
        fd: number,
        buffer: ArrayBuffer | Uint8Array,
    ): number;

    /**
     * Read data from file descriptor into buffer at specified offset
     * @param fd - File descriptor
     * @param buffer - Buffer to read into
     * @param offset - Offset in buffer to start reading
     * @returns Number of bytes actually read
     * @throws Error if read fails
     */
    export function pread(
        fd: number,
        buffer: ArrayBuffer | Uint8Array,
        offset: number
    ): number;

    /**
     * Write data from buffer to file descriptor
     * @param fd - File descriptor
     * @param buffer - Buffer to write from
     * @returns Number of bytes actually written
     * @throws Error if write fails
     */
    export function write(
        fd: number,
        buffer: ArrayBuffer | Uint8Array
    ): number;

    /**
     * Write data from buffer to file descriptor at specified offset
     * @param fd - File descriptor
     * @param buffer - Buffer to write from
     * @param offset - Offset in buffer to start writing
     * @returns Number of bytes actually written
     * @throws Error if write fails
     */
    export function pwrite(
        fd: number,
        buffer: ArrayBuffer | Uint8Array,
        offset: number
    ): number;

    // ============================================================================
    // High-Level File Operations
    // ============================================================================

    /**
     * Set file blocking mode (non-blocking/blocking)
     * Note that this is a no-op on Windows.
     * @param fd - File descriptor
     * @param blocking - true for blocking mode, false for non-blocking mode
     * @throws Error if operation fails (not supported on Windows)
     */
    export function setBlocking(fd: number, blocking: boolean): void;

    /**
     * Read entire file synchronously
     * @param path - File path
     * @returns File contents as ArrayBuffer
     * @throws Error if file doesn't exist or read fails
     */
    export function readFile(path: string): ArrayBuffer;

    /**
     * Write entire file synchronously
     * @param path - File path
     * @param data - Data to write
     * @param mode - File permissions (default: 0o666)
     * @throws Error if write fails
     */
    export function writeFile(
        path: string,
        data: ArrayBuffer | Uint8Array,
        mode?: number
    ): void;

    /**
     * High-performance file copy (OS-level optimization)
     * @param srcPath - Source file path
     * @param destPath - Destination file path
     * @throws Error if copy fails
     */
    export function copy(
        srcPath: string,
        destPath: string
    ): void;

    // ============================================================================
    // Directory Operations
    // ============================================================================

    /**
     * Create a directory
     * @param path - Directory path
     * @param mode - Directory permissions (default: 0o777)
     * @throws Error if directory already exists or creation fails
     */
    export function mkdir(path: string, mode?: number): void;

    /**
     * Remove an empty directory
     * @param path - Directory path
     * @throws Error if directory doesn't exist, not empty, or removal fails
     */
    export function rmdir(path: string): void;

    /**
     * Read directory contents
     * @param path - Directory path
     * @returns Array of filenames (excluding '.' and '..')
     * @throws Error if directory doesn't exist or read fails
     */
    export function readdir(path: string): string[];

    // ============================================================================
    // File Management
    // ============================================================================

    /**
     * Delete a file
     * @param path - File path
     * @throws Error if file doesn't exist or deletion fails
     */
    export function unlink(path: string): void;

    /**
     * Rename or move a file/directory
     * @param oldPath - Current path
     * @param newPath - New path
     * @throws Error if operation fails
     */
    export function rename(oldPath: string, newPath: string): void;

    /**
     * Create a hard link
     * @param existingPath - Existing file path
     * @param newPath - New hard link path
     * @throws Error if operation fails
     */
    export function link(existingPath: string, newPath: string): void;

    /**
     * Create a symbolic link
     * @param targetPath - Target file/directory path
     * @param linkPath - Symlink path
     * @throws Error if operation fails
     */
    export function symlink(targetPath: string, linkPath: string): void;

    // ============================================================================
    // File Locking and Synchronization
    // ============================================================================

    /**
     * Apply/remove an advisory lock on an open file
     * @param fd - File descriptor
     * @param operation - Lock operation (LOCK_SH/LOCK_EX + LOCK_NB, or LOCK_UN)
     * @throws Error if lock operation fails
     */
    export function flock(fd: number, operation: number): void;

    /**
     * Synchronize file data to disk (flush all buffers)
     * @param fd - File descriptor
     * @throws Error if synchronization fails
     */
    export function fsync(fd: number): void;

    /**
     * Synchronize file data (not metadata) to disk
     * @param fd - File descriptor
     * @throws Error if synchronization fails
     */
    export function fdatasync(fd: number): void;

    // ============================================================================
    // File Size Manipulation
    // ============================================================================

    /**
     * Truncate file to specified length
     * @param path - File path
     * @param length - New file length in bytes
     * @throws Error if truncate fails
     */
    export function truncate(path: string, length: number): void;

    /**
     * Truncate open file to specified length
     * @param fd - File descriptor
     * @param length - New file length in bytes
     * @throws Error if truncate fails
     */
    export function ftruncate(fd: number, length: number): void;

    // ============================================================================
    // Permissions and Ownership
    // ============================================================================

    /**
     * Change file permissions
     * @param path - File path
     * @param mode - New permissions (e.g., 0o755)
     * @throws Error if chmod fails
     */
    export function chmod(path: string, mode: number): void;

    /**
     * Change permissions of open file
     * @param fd - File descriptor
     * @param mode - New permissions (e.g., 0o755)
     * @throws Error if fchmod fails (not supported on Windows)
     */
    export function fchmod(fd: number, mode: number): void;

    /**
     * Change file owner and group
     * @param path - File path
     * @param uid - User ID
     * @param gid - Group ID
     * @throws Error if chown fails (not supported on Windows)
     */
    export function chown(path: string, uid: number, gid: number): void;

    /**
     * Change owner of open file
     * @param fd - File descriptor
     * @param uid - User ID
     * @param gid - Group ID
     * @throws Error if fchown fails (not supported on Windows)
     */
    export function fchown(fd: number, uid: number, gid: number): void;

    // ============================================================================
    // Time Manipulation
    // ============================================================================

    /**
     * Change file access and modification times
     * @param path - File path
     * @param atime - Access time (seconds since epoch)
     * @param mtime - Modification time (seconds since epoch)
     * @throws Error if utimes fails
     */
    export function utimes(path: string, atime: number, mtime: number): void;

    // ============================================================================
    // Access Checks
    // ============================================================================

    /**
     * Check file accessibility
     * @param path - File path
     * @param mode - Accessibility check (F_OK/R_OK/W_OK/X_OK combination)
     * @throws Error if file is not accessible
     */
    export function access(path: string, mode?: number): void;

    // ============================================================================
    // Path Operations
    // ============================================================================

    /**
     * Resolve canonical absolute path
     * @param path - Path to resolve (can be relative)
     * @returns Absolute path with symlinks resolved
     * @throws Error if path doesn't exist or resolution fails
     */
    export function realpath(path: string): string;

    /**
     * Read symbolic link contents
     * @param path - Symbolic link path
     * @returns Target path of symbolic link
     * @throws Error if readlink fails
     */
    export function readlink(path: string): string;
}