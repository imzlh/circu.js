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
    export type Pipe = CModuleStreams.Pipe;
    export type BufferSource = ArrayBuffer | ArrayBufferView;
    export type StdioOption = 'inherit' | 'pipe' | 'ignore' | number;

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
    export interface SpawnOptions<T extends boolean = false> {
        /** Stdin mode */
        stdin?: StdioOption;
        /** Stdout mode */
        stdout?: StdioOption;
        /** Stderr mode */
        stderr?: StdioOption;
        /** Extra stdio modes, indexed from child fd 3 */
        stdioExtra?: Array<StdioOption | null | undefined>;
        /** Working directory */
        cwd?: string;
        /** Environment variables */
        env?: Record<string, string>;
        /** Clear inherited environment before applying env */
        clearEnv?: boolean;
        /** User ID */
        uid?: number;
        /** Group ID */
        gid?: number;
        /** Detached mode */
        detached?: boolean;
        /** Hide the process window on Windows */
        background?: boolean;
        /** Use PTY mode (default false) */
        pty?: T;
        /** PTY command; defaults to SHELL/COMSPEC when omitted */
        name?: string;
        /** PTY argv passed to the command on Unix */
        argv?: string[];
        /** PTY columns (default 80) */
        cols?: number;
        /** PTY rows (default 24) */
        rows?: number;
        /** Data written to stdin then closed (spawnSync only) */
        input?: string | BufferSource;
        /** Enable IPC channel */
        ipc?: boolean;
        /** Child stdio fd used for IPC when ipc is enabled */
        ipcFd?: number;
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
        /** Extra stdio streams indexed by child fd; non-pipe entries are null. */
        readonly stdioExtra: PTY extends true ? undefined : Array<Pipe | null>;

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
         * IPC pipe (non-PTY mode only, undefined in PTY mode)
         * Used for inter-process communication
         */
        readonly ipc: Pipe | null;

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
         * Get PTY window size (PTY mode only).
         *
         * Native property name is `getwinsize` for compatibility with the C
         * module export table.
         *
         * @returns Window size object with cols, rows, xpixel, ypixel
         */
        readonly getwinsize: PTY extends true ? WinSize : never;

    }

    /**
     * Spawn child process
     * @param args Command string or argument array (first element is command to execute)
     * @param options Optional configuration
     */
    export function spawn<T extends boolean = false>(args: string | string[], options?: SpawnOptions<T>): ChildProcess<T>;

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
     * Replace the current process image with a command using `execvp`.
     *
     * On success this function never returns. It returns only by throwing when
     * `execvp` fails, and it is not supported on Windows.
     * @param args Command string or argument array
     */
    export function exec(args: string | string[]): never;

    /**
     * Send signal to specified process
     * @param pid Process ID
     * @param signal Signal (string or number, default SIGTERM)
     */
    export function kill(pid: number, signal?: Signal | number): void;
}
