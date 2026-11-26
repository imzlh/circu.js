/**
 * Timers module - timeout, interval, and check-phase immediate callbacks
 * 
 * @example
 * const timers = import.meta.use('timers');
 * 
 * const id = timers.setTimeout(() => {
 *   console.log('Timeout!');
 * }, 1000);
 * 
 * timers.clearTimeout(id);
 */
declare namespace CModuleTimers {
    /**
     * Set timeout timer
     * @param func Callback function
     * @param delay Delay time (milliseconds)
     * @param args Callback arguments (optional)
     * @returns Timer ID
     */
    export function setTimeout<TArgs extends any[]>(
        func: (...args: TArgs) => any,
        delay?: number,
        ...args: TArgs
    ): number;

    /**
     * Clear timeout timer
     * @param timerId Timer ID
     */
    export function clearTimeout(timerId: number): void;

    /**
     * Set interval timer
     * @param func Callback function
     * @param interval Interval time (milliseconds)
     * @param args Callback arguments (optional)
     * @returns Interval timer ID
     */
    export function setInterval<TArgs extends any[]>(
        func: (...args: TArgs) => any,
        interval?: number,
        ...args: TArgs
    ): number;

    /**
     * Clear interval timer
     * @param timerId Interval timer ID
     */
    export function clearInterval(timerId: number): void;

    /**
     * Schedule a callback for the next check phase
     * @param func Callback function
     * @param args Callback arguments (optional)
     * @returns Immediate ID
     */
    export function setImmediate<TArgs extends any[]>(
        func: (...args: TArgs) => any,
        ...args: TArgs
    ): number;

    /**
     * Clear an immediate callback
     * @param immediateId Immediate ID
     */
    export function clearImmediate(immediateId: number): void;

    /**
     * Reference timer
     * @param timerId Timer ID
     */
    export function refTimer(timerId: number): void;

    /**
     * Unreference timer
     * @param timerId Timer ID
     */
    export function unrefTimer(timerId: number): void;

    /**
     * Check if timer is referenced
     * @param timerId Timer ID
     * @returns True if timer is referenced
     */
    export function hasRef(timerId: number): boolean;

    /**
     * Reference an immediate callback
     * @param immediateId Immediate ID
     */
    export function refImmediate(immediateId: number): void;

    /**
     * Unreference an immediate callback
     * @param immediateId Immediate ID
     */
    export function unrefImmediate(immediateId: number): void;

    /**
     * Check if an immediate callback is referenced
     * @param immediateId Immediate ID
     * @returns True if the immediate is referenced
     */
    export function hasRefImmediate(immediateId: number): boolean;
}
