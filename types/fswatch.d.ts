/**
 * FSWatch module - File system event monitoring
 * 
 * @example
 * const fswatch = import.meta.use('fswatch');
 * 
 * const watcher = fswatch.watch('./src', (filename, event) => {
 *   console.log(`${filename ?? '<unknown>'}: ${event}`);
 * });
 */
declare namespace CModuleFSWatch {
    /**
     * File system event types
     */
    export type FsEvent = 'rename' | 'change'; 

    /**
     * File system watcher object
     */
    export interface FsWatcher {
        /**
         * Close file system watcher
         */
        close(): void;

        /**
         * Watched file or directory path
         */
        readonly path: string;

        readonly [Symbol.toStringTag]: 'FsWatcher';
    }

    /**
     * Start file system watcher
     * @param path File or directory path to watch
     * @param callback Event handler callback
     * @param recursive Whether to request platform recursive watching
     * @returns FsWatcher object
     */
    export function watch(path: string, callback: (filename: string | null, event: FsEvent) => void, recursive?: boolean): FsWatcher;
}
