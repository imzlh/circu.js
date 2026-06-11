/**
 * Process module - Child process management
 * 
 * @example
 * const process = import.meta.use('process');
 * 
 * // Spawn a child process
 * const child = process.spawn(['ls', '-la'], { cwd: '/tmp' });
 * 
 * child.stdout.onread = (data) => console.log(data);
 * const { exit_status } = await child.wait();
 */
declare namespace CModuleProcess {
    type Pipe = CModuleStreams.Pipe;

    /**
     * Process signals
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
     * Spawn options
     */
    export interface SpawnOptions<T> {
        /** Stdin file descriptor or mode */
        stdin?: number | 'inherit' | 'pipe' | 'ignore';
        /** Stdout file descriptor or mode */
        stdout?: number | 'inherit' | 'pipe' | 'ignore';
        /** Stderr file descriptor or mode */
        stderr?: number | 'inherit' | 'pipe' | 'ignore';
        /** Working directory */
        cwd?: string;
        /** Environment variables */
        env?: Record<string, string>;
        /** User ID */
        uid?: number;
        /** Group ID */
        gid?: number;
        /** Detached mode */
        detached?: boolean;
        /** Use PTY mode (default false) */
        pty?: T;
        /** PTY columns (default 80) */
        cols?: number;
        /** PTY rows (default 24) */
        rows?: number;
        /** Data written to stdin then closed (spawnSync only) */
        input?: string | ArrayBuffer | Uint8Array;
    }

    /**
     * Synchronous spawn result. stdout/stderr are ArrayBuffers when captured.
     */
    export interface SpawnSyncResult {
        pid: number;
        output: [null, ArrayBuffer | null, ArrayBuffer | null];
        stdout: ArrayBuffer | null;
        stderr: ArrayBuffer | null;
        status: number | null;
        signal: string | null;
        error?: Error;
    }

    /**
     * Child process exit info
     */
    export interface ExitInfo {
        exit_status: number;
        term_signal: string | null;
    }

    /**
     * PTY window size
     */
    export interface WinSize {
        readonly cols: number;
        readonly rows: number;
        readonly xpixel: number;
        readonly ypixel: number;
    }

    /**
     * Child process object
     */
    export interface ChildProcess<PTY = false> {
        /** Process ID */
        readonly pid: number;
        /** Stdin stream (non-PTY mode only, undefined in PTY mode) */
        readonly stdin: PTY extends true ? undefined : Pipe;
        /** Stdout stream (non-PTY mode only, undefined in PTY mode) */
        readonly stdout: PTY extends true ? undefined : Pipe;
        /** Stderr stream (non-PTY mode only, undefined in PTY mode) */
        readonly stderr: PTY extends true ? undefined : Pipe;

        /**
         * PTY readable stream (PTY mode only, undefined in non-PTY mode)
         * On Linux, same object as writable
         */
        readonly readable: PTY extends true ? Pipe : undefined;
        /**
         * PTY writable stream (PTY mode only, undefined in non-PTY mode)
         * On Linux, same object as readable
         */
        readonly writable: PTY extends true ? Pipe : undefined;

        /**
         * Wait for process exit
         * @returns Exit code and termination signal
         */
        wait(): Promise<ExitInfo>;

        /**
         * Block wait for process exit
         * @returns Exit code and termination signal
         */
        waitSync(): ExitInfo;

        /**
         * Send signal to process
         * @param signal Signal to send (default SIGTERM, can be string or number)
         */
        kill(signal?: Signal | number): void;

        /**
         * Resize PTY window (PTY mode only)
         * @param cols Columns
         * @param rows Rows
         */
        resize(cols: number, rows: number): PTY extends true ? void : never;

        /**
         * Get PTY window size (PTY mode only)
         * @returns Window size object with cols, rows, xpixel, ypixel
         */
        get size():  PTY extends true ? WinSize : never;
    }

    /**
     * Spawn child process
     * @param args Command string or argument array (first element is command to execute)
     * @param options Optional configuration
     */
    export function spawn<T>(args: string | string[], options?: SpawnOptions<T>): ChildProcess<T>;

    /**
     * Synchronously spawn a child process using platform-native process APIs.
     * @param args Command string or argument array (first element is command to execute)
     * @param options Optional configuration
     */
    export function spawnSync(args: string | string[], options?: SpawnOptions<false>): SpawnSyncResult;

    /**
     * Node-style overload: command plus argument array.
     */
    export function spawnSync(command: string, args?: string[], options?: SpawnOptions<false>): SpawnSyncResult;

    /**
     * Execute command (shorthand for spawn + wait)
     * @param args Command string or argument array
     * @param options Optional configuration
     */
    export function exec(args: string | string[], options?: SpawnOptions<false>): ChildProcess;

    /**
     * Send signal to specified process
     * @param pid Process ID
     * @param signal Signal (string or number, default SIGTERM)
     */
    export function kill(pid: number, signal?: Signal | number): void;
}
