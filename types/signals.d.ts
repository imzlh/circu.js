/**
 * POSIX/libuv signal handling.
 *
 * Workers can read `signals`, but cannot register a process-level handler with
 * `signal()`.
 */
declare namespace CModuleSignals {
    const signalBrand: unique symbol;

    /** A native signal number obtained from `signals.*`. */
    export type Signal = number & { readonly [signalBrand]: never };

    export interface SignalHandler {
        /**
         * Stop monitoring this signal. Calling `close()` more than once is safe.
         */
        close(): void;

        /**
         * Signal number monitored by this handler.
         */
        readonly signal: Signal;

        readonly [Symbol.toStringTag]: "Signal Handler";
    }

    /**
     * Signal numbers exposed by the native runtime.
     *
     * The object is populated from the platform signal map at startup. Common
     * POSIX names are listed here, and less common/platform-specific names may
     * also be present. Linux realtime signals (SIGRTMIN..SIGRTMAX) are NOT in
     * the map and are rejected by `kill()`/`signal()`.
     */
    export const signals: {
        readonly SIGHUP: Signal;
        readonly SIGINT: Signal;
        readonly SIGQUIT: Signal;
        readonly SIGILL: Signal;
        readonly SIGTRAP: Signal;
        readonly SIGABRT: Signal;
        readonly SIGBUS: Signal;
        readonly SIGFPE: Signal;
        readonly SIGKILL: Signal;
        readonly SIGUSR1: Signal;
        readonly SIGSEGV: Signal;
        readonly SIGUSR2: Signal;
        readonly SIGPIPE: Signal;
        readonly SIGALRM: Signal;
        readonly SIGTERM: Signal;
        readonly SIGCHLD: Signal;
        readonly SIGCONT: Signal;
        readonly SIGSTOP: Signal;
        readonly SIGTSTP: Signal;
        readonly SIGTTIN: Signal;
        readonly SIGTTOU: Signal;
        readonly SIGURG: Signal;
        readonly SIGXCPU: Signal;
        readonly SIGXFSZ: Signal;
        readonly SIGVTALRM: Signal;
        readonly SIGPROF: Signal;
        readonly SIGWINCH: Signal;
        readonly SIGPWR: Signal;
        readonly SIGSYS: Signal;
        readonly SIGBREAK?: Signal;
        readonly SIGSTKFLT?: Signal;
        readonly SIGPOLL?: Signal;
        readonly SIGLOST?: Signal;
        readonly SIGINFO?: Signal;
        readonly [name: string]: Signal | undefined;
    };

    /**
     * Register a callback for a signal number.
     *
     * @throws {TypeError} When called inside a worker.
     *
     * The native handle is immediately `uv_unref()`'d, so it does not keep the
     * runtime alive by itself.
     *
     * @example
     * const signalsMod = import.meta.use('signals');
     * const sigint = signalsMod.signal(signalsMod.signals.SIGINT, () => {
     *   sigint.close();
     * });
     */
    export function signal(sigNum: Signal, handler: () => void): SignalHandler;
}
