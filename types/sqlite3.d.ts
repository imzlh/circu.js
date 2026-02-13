/**
 * SQLite3 module for txiki.js
 * Provides an object-oriented interface to SQLite3 databases
 */

declare namespace CModuleSQLite3 {
    /**
     * SQLite3 database connection handle
     */
    export class Sqlite3Handle {
        /**
         * Close the database connection
         */
        close(): void;

        /**
         * Load an extension into the database connection
         * @param file Path to the extension file
         * @param proc Optional entry point name
         */
        loadExtension(file: string, proc?: string): void;

        /**
         * Execute a SQL statement
         * @param sql The SQL statement to execute
         */
        exec(sql: string): void;

        /**
         * Prepare a SQL statement
         * @param sql The SQL statement to prepare
         * @returns A prepared statement object
         */
        prepare(sql: string): Sqlite3Stmt;

        /**
         * Check if a transaction is active
         * @returns True if a transaction is active
         */
        inTransaction(): boolean;
    }

    /**
     * SQLite3 prepared statement
     */
    export class Sqlite3Stmt {
        /**
         * Finalize the prepared statement
         */
        finalize(): void;

        /**
         * Expand the prepared statement with bound parameters
         * @returns The expanded SQL string
         */
        expand(): string;

        /**
         * Execute the prepared statement and return all rows
         * @param params Optional parameters to bind
         * @returns Array of rows
         */
        all(params?: any): any[];

        /**
         * Execute the prepared statement and return the result
         * @param params Optional parameters to bind
         * @returns The result of the statement
         */
        run(params?: any): any;
    }

    /**
     * Open a SQLite3 database
     * @param filename Path to the database file
     * @param flags Open flags
     * @returns A database connection handle
     */
    export function open(filename: string, flags?: number): Sqlite3Handle;

    /**
     * Open flags
     */
    export const O_CREATE: number;
    export const O_READONLY: number;
    export const O_READWRITE: number;
    export const O_MEMORY: number;
    export const O_URI: number;
    export const O_NOMUTEX: number;
    export const O_FULLMUTEX: number;
    export const O_SHAREDCACHE: number;
    export const O_PRIVATECACHE: number;
    export const O_NOFOLLOW: number;
}