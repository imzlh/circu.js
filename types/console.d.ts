/**
 * Console module - WebAPI Console partial implementation
 * Provides console.log, console.error, console.assert, etc.
 */
declare namespace CModuleConsole {

    export interface InspectOption {
        depth?: number;
        colors?: boolean;
        showHidden?: boolean;
        customInspect?: boolean;
        compact?: boolean;
    }

    /**
     * non-standard console.inspect() method, returns a string representation of the objects.
     */
    export function inspect(data?: unknown, options?: InspectOption): string;

    /**
     * non-standard console.format() method, accept arguments and returns a string like `inspect`
     * but also accept multiple arguments to provide full `console.log` behavior. 
     */
    export function format(...data: unknown[]): string;

    /**
     * The **`console.assert()`** static method writes an error message to the console if the assertion is false.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/assert_static)
     */
    export function assert(condition?: boolean, ...data: unknown[]): void;
    /**
     * The **`console.clear()`** static method clears the console if possible.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/clear_static)
     */
    export function clear(): void;
    /**
     * The **`console.debug()`** static method outputs a message to the console at the 'debug' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/debug_static)
     */
    export function debug(...data: unknown[]): void;
    /**
     * The **`console.dir()`** static method displays a list of the properties of the specified JavaScript object.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/dir_static)
     */
    export function dir(item?: unknown, options?: InspectOption): void;
    export function dirxml(...data: unknown[]): void;
    /**
     * The **`console.error()`** static method outputs a message to the console at the 'error' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/error_static)
     */
    export function error(...data: unknown[]): void;
    /**
     * The **`console.info()`** static method outputs a message to the console at the 'info' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/info_static)
     */
    export function info(...data: unknown[]): void;
    /**
     * The **`console.log()`** static method outputs a message to the console.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/log_static)
     */
    export function log(...data: unknown[]): void;
    export function table(tabularData?: unknown, properties?: readonly string[]): void;
    export function count(label?: string): void;
    export function countReset(label?: string): void;
    export function time(label?: string): void;
    export function timeLog(label?: string, ...data: unknown[]): void;
    export function timeEnd(label?: string): void;
    export function timeStamp(label?: string): void;
    export function group(...label: unknown[]): void;
    export function groupCollapsed(...label: unknown[]): void;
    export function groupEnd(): void;
    /**
     * The **`console.trace()`** static method outputs a stack trace to the console.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/trace_static)
     */
    export function trace(...data: unknown[]): void;
    /**
     * The **`console.warn()`** static method outputs a warning message to the console at the 'warning' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/warn_static)
     */
    export function warn(...data: unknown[]): void;
}
