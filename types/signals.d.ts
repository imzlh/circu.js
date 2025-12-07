/**
 * Type definitions for the signals module.
 * Provides Unix signal handling capabilities for the QuickJS runtime.
 * Compatible with txiki.js and similar QuickJS-based runtimes.
 * 
 * @module signals
 */

declare namespace CModuleSignals {
    /**
     * Interface representing a signal handler object.
     * Returned by the `signal()` function to manage a registered signal listener.
     * The handler remains active until explicitly closed.
     */
    export interface SignalHandler {
        /**
         * Closes the signal handler, stopping further signal monitoring.
         * Once closed, the handler cannot be reused and resources are freed.
         * 
         * @example
         * ```typescript
         * const handler = signal(signals.SIGTERM, () => {
         *     console.log('Shutting down...');
         *     handler.close();
         * });
         * 
         * // Manually close after 5 seconds if not triggered
         * setTimeout(() => {
         *     if (handler.signal) { // Check if still active
         *         console.log('Timeout reached, closing handler');
         *         handler.close();
         *     }
         * }, 5000);
         * ```
         */
        close(): void;

        /**
         * The name of the signal being handled (e.g., "SIGINT", "SIGTERM").
         * Returns null if the signal number is not recognized or if the handler is closed.
         * 
         * @example
         * ```typescript
         * const handler = signal(signals.SIGINT, () => { /* ... * / });
         * console.log(`Monitoring: ${handler.signal}`); // "SIGINT"
         * ```
         */
        readonly signal: string | null;

        /**
         * Internal tag for object identification.
         * Always returns "Signal Handler".
         */
        readonly [Symbol.toStringTag]: "Signal Handler";
    }

    /**
     * Standard Unix signal constants.
     * Maps signal names to their numeric values. Values may vary by platform.
     * 
     * @example
     * ```typescript
     * import { signals } from 'signals';
     * 
     * console.log(signals.SIGINT); // 2 (on most Unix systems)
     * console.log(signals.SIGTERM); // 15
     * 
     * // Iterate over available signals
     * Object.entries(signals).forEach(([name, num]) => {
     *     console.log(`${name}: ${num}`);
     * });
     * ```
     */
    export const signals: {
        /** Hangup detected on controlling terminal or death of controlling process */
        readonly SIGHUP: number;
        /** Interrupt from keyboard (Ctrl+C) */
        readonly SIGINT: number;
        /** Quit from keyboard */
        readonly SIGQUIT: number;
        /** Illegal Instruction */
        readonly SIGILL: number;
        /** Trace/breakpoint trap */
        readonly SIGTRAP: number;
        /** Abort signal from abort(3) */
        readonly SIGABRT: number;
        /** Bus error (bad memory access) */
        readonly SIGBUS: number;
        /** Floating point exception */
        readonly SIGFPE: number;
        /** Kill signal (cannot be caught or ignored) */
        readonly SIGKILL: number;
        /** User-defined signal 1 */
        readonly SIGUSR1: number;
        /** Invalid memory reference */
        readonly SIGSEGV: number;
        /** User-defined signal 2 */
        readonly SIGUSR2: number;
        /** Broken pipe: write to pipe with no readers */
        readonly SIGPIPE: number;
        /** Timer signal from alarm(2) */
        readonly SIGALRM: number;
        /** Termination signal (default for kill command) */
        readonly SIGTERM: number;
        /** Child stopped or terminated */
        readonly SIGCHLD: number;
        /** Continue if stopped */
        readonly SIGCONT: number;
        /** Stop process (cannot be caught or ignored) */
        readonly SIGSTOP: number;
        /** Stop typed at terminal */
        readonly SIGTSTP: number;
        /** Terminal input for background process */
        readonly SIGTTIN: number;
        /** Terminal output for background process */
        readonly SIGTTOU: number;
        /** Urgent condition on socket */
        readonly SIGURG: number;
        /** CPU time limit exceeded */
        readonly SIGXCPU: number;
        /** File size limit exceeded */
        readonly SIGXFSZ: number;
        /** Virtual alarm clock */
        readonly SIGVTALRM: number;
        /** Profiling timer expired */
        readonly SIGPROF: number;
        /** Window resize signal */
        readonly SIGWINCH: number;
        /** I/O now possible */
        readonly SIGIO: number;
        /** Power failure */
        readonly SIGPWR: number;
        /** Bad argument to routine */
        readonly SIGSYS: number;
    };

    /**
     * Registers a callback to be invoked when a specific Unix signal is received.
     * The handler automatically unrefs the libuv handle, so it won't prevent process exit.
     * 
     * @param sigNum - The numeric signal identifier to listen for. Use constants from the `signals` object.
     * @param handler - The function to call when the signal is received. The function receives no arguments.
     * @returns A SignalHandler object that can be used to manually close the signal listener.
     * 
     * @throws {TypeError} If the second argument is not a function.
     * @throws {InternalError} If the signal handle cannot be initialized.
     * @throws {Error} If the signal cannot be started (with system error code).
     * 
     * @example
     * ```typescript
     * import { signal, signals } from 'signals';
     * 
     * // Example 1: Graceful shutdown with SIGINT (Ctrl+C)
     * const sigintHandler = signal(signals.SIGINT, () => {
     *     console.log('\nReceived SIGINT. Performing graceful shutdown...');
     *     
     *     // Perform cleanup operations
     *     cleanupDatabaseConnections();
     *     saveState();
     *     
     *     // Close the handler
     *     sigintHandler.close();
     *     
     *     // Exit the application
     *     // In txiki.js: tjs.exit(0)
     *     // In other contexts: use appropriate exit method
     *     exit(0);
     * });
     * 
     * console.log('Press Ctrl+C to test signal handling');
     * 
     * // Example 2: Daemon cleanup with SIGTERM
     * const sigtermHandler = signal(signals.SIGTERM, () => {
     *     console.log('Received SIGTERM, performing graceful shutdown...');
     *     
     *     // Cleanup logic
     *     stopServer();
     *     sigtermHandler.close();
     *     exit(0);
     * });
     * 
     * // Example 3: Check which signal is being monitored
     * console.log(`Monitoring signal: ${sigintHandler.signal}`); // "SIGINT"
     * 
     * // Example 4: Multiple signals sharing one handler
     * function handleShutdown() {
     *     console.log('Shutdown signal received');
     *     sigintHandler.close();
     *     sigtermHandler.close();
     *     exit(0);
     * }
     * 
     * signal(signals.SIGINT, handleShutdown);
     * signal(signals.SIGTERM, handleShutdown);
     * 
     * // Example 5: Temporary signal handler with auto-cleanup
     * const tempHandler = signal(signals.SIGUSR1, () => {
     *     console.log('Received SIGUSR1');
     *     tempHandler.close(); // Close after first trigger
     * });
     * 
     * // Example 6: Cleanup on error
     * try {
     *     const handler = signal(99999, () => {}); // Invalid signal
     * } catch (error) {
     *     console.error(`Failed to register signal handler: ${error.message}`);
     * }
     * ```
     */
    export function signal(sigNum: number, handler: () => void): SignalHandler;
}