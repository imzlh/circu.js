/**
 * OS module - System-level operations and information queries
 * 
 * @remarks
 * Wraps libuv syscalls for cross-platform capability.
 * All operations are **synchronous** as underlying OS calls are sync.
 * 
 * @example
 * const os = import.meta.use('os');
 * 
 * console.log('Platform:', os.platform);
 * console.log('Hostname:', os.hostName);
 * console.log('PID:', os.pid);
 * console.log('Memory:', os.memoryUsage());
 */
declare namespace CModuleOS {
    /**
     * Address family constants (from libuv)
     * @remarks Actual values defined by libuv, may vary by platform.
     */
    const AF_INET: number;
    const AF_INET6: number;
    const AF_UNSPEC: number;

    /**
     * Standard file descriptor constants
     */
    const STDIN_FILENO: 0;
    const STDOUT_FILENO: 1;
    const STDERR_FILENO: 2;

    /**
     * Current process user info
     */
    interface UserInfo {
        /** Username (e.g., 'root') */
        readonly userName: string;
        /** User ID (uid) */
        readonly userId: number;
        /** Group ID (gid) */
        readonly groupId: number;
        /** Shell path, may be null (e.g., '/bin/bash') */
        readonly shell: string | null;
        /** Home directory path, may be null (e.g., '/home/user') */
        readonly homeDir: string | null;
    }

    /**
     * System info (uname result)
     */
    interface SystemInfo {
        /**
         * OS name
         * - Windows (MSVC): `'Windows_NT'`
         * - Windows (MinGW): `'MINGW32_NT-{major}.{minor}'`
         * - Linux: `'Linux'`
         * - macOS: `'Darwin'`
         */
        readonly sysname: string;
        /**
         * Kernel version
         * - Windows: `'{major}.{minor}.{build}'` (e.g., `'10.0.19041'`)
         * - Linux: Kernel version string (e.g., `'5.10.0-21-amd64'`)
         * - macOS: Darwin kernel version (e.g., `'21.6.0'`)
         */
        readonly release: string;
        /**
         * Version/distribution info
         * - Windows: Registry ProductName (e.g., `'Windows 10 Pro'`, `'Windows 11 Home'`),
         *   Build >= 22000 auto-corrects "Windows 10" to "Windows 11"; may include Service Pack
         * - Linux: `#version SMP ...` format kernel build info
         * - macOS: `'Mac OS X 12.x'` or similar
         */
        readonly version: string;
        /**
         * Machine hardware architecture
         * - `'x86_64'` / `'ia64'` / `'i386'`~`'i686'` / `'mips'` / `'alpha'` / `'powerpc'` / `'sh'` / `'arm'` / `'unknown'`
         * - Linux/macOS may also be `'aarch64'`, `'arm64'`, etc.
         */
        readonly machine: string;
    }

    /**
     * Network interface info
     */
    interface NetworkInterface {
        /** Interface name (e.g., 'eth0', 'lo') */
        readonly name: string;
        /** MAC address (e.g., '00:11:22:33:44:55') */
        readonly mac: string;
        /** IP address (IPv4 or IPv6) */
        readonly address: string;
        /** Subnet mask */
        readonly netmask: string;
        /** Whether internal interface (loopback) */
        readonly internal: boolean;
        /** IPv6 scope ID (IPv6 interfaces only) */
        readonly scopeId?: number;
    }

    /**
     * Memory usage info
     * All values in bytes
     */
    interface MemoryUsage {
        /** OS available memory (uv_get_available_memory) */
        "os.free": number;
        /** OS total memory (uv_get_total_memory) */
        "os.total": number;
        /** OS constrained memory (uv_get_constrained_memory) */
        "os.constrained": number;
        /** Process resident set memory (uv_resident_set_memory) */
        "os.rss": number;
        /** OS used memory (total - free) */
        "os.used": number;

        /** QuickJS VM used memory (memory_used_size) */
        "vm.used": number;

        /** Heap memory usage (malloc_size) */
        "used": number;
        /** Heap memory limit (malloc_limit) */
        "limit": number;

        /** String bytes used (str_size) */
        "string.used": number;
        /** String count (str_count) */
        "string.count": number;

        /** Binary object bytes used (binary_object_size) */
        "buffer.used": number;
        /** Binary object count (binary_object_count) */
        "buffer.count": number;

        /** JS object count (obj_count) */
        "object.count": number;
        /** JS object bytes used (obj_size) */
        "object.used": number;
    }

    /**
     * CPU core info
     */
    interface CpuInfo {
        /** CPU model (e.g., 'AMD Ryzen 9 5950X 16-Core Processor') */
        readonly model: string;
        /** Clock speed (MHz) */
        readonly speed: number;
        /** Cumulative times per state (milliseconds) */
        readonly times: {
            /** User mode time */
            readonly user: number;
            /** Nice low-priority user mode time */
            readonly nice: number;
            /** Kernel mode time */
            readonly sys: number;
            /** Idle time */
            readonly idle: number;
            /** Hardware interrupt time */
            readonly irq: number;
        };
    }

    /**
     * System load average
     * @example [1.5, 1.2, 0.8] // 1min, 5min, 15min average
     * @remarks Always returns [0, 0, 0] on Windows
     */
    type LoadAverage = [number, number, number];

    /**
     * File descriptor type from guessHandle
     */
    type HandleType = 'tty' | 'pipe' | 'file' | 'tcp' | 'udp' | 'unknown';

    /**
     * Platform identifier string
     * - Windows: `'windows'`
     * - Linux: `'linux'`
     * - macOS: `'darwin'`
     * - FreeBSD: `'freebsd'`
     * - Others: Lowercase CMAKE_SYSTEM_NAME
     */
    const platform: string;

    // ==================== Process Control ====================

    /**
     * **Immediately exit** current process (sync)
     * @param status Exit code (0 = success)
     * @warning **Dangerous**: Cannot be undone, terminates all execution immediately
     */
    function exit(status: number): never;

    // ==================== System Info ====================

    /**
     * Get system info (sync)
     * @returns Detailed system info
     */
    function uname(): SystemInfo;

    /**
     * Get system uptime (seconds) (sync)
     * @returns Seconds since boot (float)
     */
    function uptime(): number;

    // ==================== File Descriptors ====================

    /**
     * Guess file descriptor type (sync)
     * @param fd File descriptor (e.g., 0, 1, 2)
     * @returns Descriptor type
     */
    function guessHandle(fd: number): HandleType;

    // ==================== Environment Variables ====================

    /**
     * Get environment variable (sync)
     * @param name Variable name (e.g., 'PATH')
     * @returns Variable value
     * @throws {Error} Throws errno exception if variable doesn't exist
     */
    function getenv(name: string): string;

    /**
     * Set environment variable (sync)
     * @param name Variable name
     * @param value Variable value
     * @throws {Error} Throws on failure (e.g., out of memory)
     */
    function setenv(name: string, value: string): void;

    /**
     * Delete environment variable (sync)
     * @param name Variable name
     * @throws {Error} Throws on failure
     */
    function unsetenv(name: string): void;

    /**
     * Get all environment variables (sync)
     * @returns Key-value object
     */
    function environ(): Record<string, string>;

    /**
     * Get all environment variable names (sync)
     * @returns Variable name array
     */
    function envKeys(): string[];

    // ==================== Directory Operations ====================

    /**
     * Change current working directory (sync)
     * @param dir New directory path
     * @throws {Error} Throws if directory doesn't exist or no permission
     */
    function chdir(dir: string): void;

    /** Current working directory (getter property) */
    const cwd: string;

    // ==================== Path Info ====================

    /** User home directory path (getter property) */
    const homeDir: string;

    /** System temp directory path (getter property) */
    const tmpDir: string;

    // ==================== Random ====================

    /**
     * Generate cryptographically secure random data (sync)
     * @param buffer Target buffer (Uint8Array or ArrayBuffer)
     * @param offset Start offset (default 0)
     * @param length Generate length (default buffer length - offset)
     * @throws {RangeError} offset+length out of bounds
     */
    function random(
        buffer: ArrayBuffer | Uint8Array,
        offset?: number,
        length?: number
    ): void;

    // ==================== System Resources ====================

    /**
     * Get CPU info (sync)
     * @returns Info for each CPU core
     */
    function cpuInfo(): CpuInfo[];

    /**
     * Get JS/OS memory info (sync)
     * @returns Memory usage details, all values in bytes
     */
    function memoryUsage(): MemoryUsage;

    /**
     * Get system load average (sync)
     * @returns [1min, 5min, 15min] average
     * @remarks Always returns [0, 0, 0] on Windows
     */
    function loadavg(): LoadAverage;

    /**
     * Get all network interfaces (sync)
     * @returns Interface array
     */
    function networkInterfaces(): NetworkInterface[];

    /**
     * Get available parallelism (logical CPU count) (sync)
     * @returns CPU cores available for parallel execution
     */
    function availableParallelism(): number;

    /**
     * Sleep for specified time. Thread-level sleep, jobs won't run
     */
    function sleep(ms: number): void;

    // ==================== Network Info ====================

    /** Hostname (getter property) */
    const hostName: string;

    // ==================== Process Info ====================

    /** Current process ID (getter property) */
    const pid: number;

    /** Parent process ID (getter property) */
    const ppid: number;

    /** Current process user info (getter property) */
    const userInfo: UserInfo;

    /** Current executable file path (getter property) */
    const exePath: string;

    /** Current command line arguments array */
    const args: string[];

    // ==================== IPC Helpers ====================

    /**
     * Create a pipe pair for IPC communication.
     * Returns [readable_fd, writable_fd].
     *
     * @example
     * const [readFd, writeFd] = os.ipcPipe();
     */
    function ipcPipe(): [number, number];

    /**
     * Send a file descriptor over a Unix domain socket.
     * Uses sendmsg with SCM_RIGHTS ancillary data.
     * (POSIX only, throws on Windows)
     *
     * @param socketFd - Unix domain socket file descriptor
     * @param fdToSend - File descriptor to send
     * @returns bytes sent (>= 0) on success
     */
    function sendfd(socketFd: number, fdToSend: number): number;

    /**
     * Receive a file descriptor from a Unix domain socket.
     * Uses recvmsg with SCM_RIGHTS ancillary data.
     * (POSIX only, throws on Windows)
     *
     * @param socketFd - Unix domain socket file descriptor
     * @returns received file descriptor (>= 0) on success
     */
    function recvfd(socketFd: number): number;
}
