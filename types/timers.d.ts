/**
 * Timers module - setTimeout and setInterval
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
}
