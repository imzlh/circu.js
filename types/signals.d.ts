/**
 * POSIX/libuv signal handling.
 *
 * `signals` is not worker-safe; `import.meta.use('signals')` returns `null`
 * inside workers.
 */
declare namespace CModuleSignals {
    export interface SignalHandler {
        /**
         * Stop monitoring this signal. Calling `close()` more than once is safe.
         */
        close(): void;

        /**
         * Signal name for this handler, or `null` when the number is unknown.
         */
        readonly signal: string | null;

        readonly [Symbol.toStringTag]: "Signal Handler";
    }

    /**
     * Signal numbers exposed by the native runtime.
     *
     * The object is populated from the platform signal map at startup. Common
     * POSIX names are listed here, and less common/platform-specific names may
     * also be present.
     */
    export const signals: {
        readonly SIGHUP: number;
        readonly SIGINT: number;
        readonly SIGQUIT: number;
        readonly SIGILL: number;
        readonly SIGTRAP: number;
        readonly SIGABRT: number;
        readonly SIGBUS: number;
        readonly SIGFPE: number;
        readonly SIGKILL: number;
        readonly SIGUSR1: number;
        readonly SIGSEGV: number;
        readonly SIGUSR2: number;
        readonly SIGPIPE: number;
        readonly SIGALRM: number;
        readonly SIGTERM: number;
        readonly SIGCHLD: number;
        readonly SIGCONT: number;
        readonly SIGSTOP: number;
        readonly SIGTSTP: number;
        readonly SIGTTIN: number;
        readonly SIGTTOU: number;
        readonly SIGURG: number;
        readonly SIGXCPU: number;
        readonly SIGXFSZ: number;
        readonly SIGVTALRM: number;
        readonly SIGPROF: number;
        readonly SIGWINCH: number;
        readonly SIGPWR: number;
        readonly SIGSYS: number;
        readonly SIGBREAK?: number;
        readonly SIGSTKFLT?: number;
        readonly SIGPOLL?: number;
        readonly SIGLOST?: number;
        readonly SIGINFO?: number;
        readonly [name: string]: number | undefined;
    };

    /**
     * Register a callback for a signal number.
     *
     * The native handle is immediately `uv_unref()`'d, so it does not keep the
     * runtime alive by itself.
     *
     * @example
     * const signalsMod = import.meta.use('signals');
     * if (!signalsMod) throw new Error('signals are unavailable in workers');
     *
     * const sigint = signalsMod.signal(signalsMod.signals.SIGINT, () => {
     *   sigint.close();
     * });
     */
    export function signal(sigNum: number, handler: () => void): SignalHandler;
}
