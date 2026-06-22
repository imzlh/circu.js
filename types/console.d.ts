/**
 * Console module - WebAPI Console partial implementation
 * Provides console.log, console.error, console.assert, etc.
 */
declare namespace CModuleConsole {

    interface InspectOption {
        depth?: number;
        colors?: boolean;
        showHidden?: boolean;
    }

    /**
     * non-standard console.inspect() method, returns a string representation of the objects.
     */
    export function inspect(data: any, options?: InspectOption): string;

    /**
     * The **`console.assert()`** static method writes an error message to the console if the assertion is false.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/assert_static)
     */
    export function assert(condition?: boolean, ...data: any[]): void;
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
    export function debug(...data: any[]): void;
    /**
     * The **`console.dir()`** static method displays a list of the properties of the specified JavaScript object.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/dir_static)
     */
    export function dir(item?: any, options?: any): void;
    export function dirxml(...data: any[]): void;
    /**
     * The **`console.error()`** static method outputs a message to the console at the 'error' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/error_static)
     */
    export function error(...data: any[]): void;
    /**
     * The **`console.info()`** static method outputs a message to the console at the 'info' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/info_static)
     */
    export function info(...data: any[]): void;
    /**
     * The **`console.log()`** static method outputs a message to the console.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/log_static)
     */
    export function log(...data: any[]): void;
    export function table(tabularData?: any, properties?: readonly string[]): void;
    export function count(label?: string): void;
    export function countReset(label?: string): void;
    export function time(label?: string): void;
    export function timeLog(label?: string, ...data: any[]): void;
    export function timeEnd(label?: string): void;
    export function timeStamp(label?: string): void;
    export function group(...label: any[]): void;
    export function groupCollapsed(...label: any[]): void;
    export function groupEnd(): void;
    /**
     * The **`console.trace()`** static method outputs a stack trace to the console.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/trace_static)
     */
    export function trace(...data: any[]): void;
    /**
     * The **`console.warn()`** static method outputs a warning message to the console at the 'warning' log level.
     *
     * [MDN Reference](https://developer.mozilla.org/docs/Web/API/console/warn_static)
     */
    export function warn(...data: any[]): void;
}
