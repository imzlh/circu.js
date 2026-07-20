/**
 * SQLite3 module - SQLite database operations
 * 
 * @example
 * ```typescript
 * const sqlite3 = import.meta.use('sqlite3');
 * 
 * const db = sqlite3.open('test.db', sqlite3.O_CREATE | sqlite3.O_READWRITE);
 * const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
 * const rows = stmt.all([1]);
 * db.close();
 * ```
 */
declare namespace CModuleSQLite3 {
    export type SqliteValue = null | number | bigint | string | boolean | Uint8Array;
    export type SqliteParams = SqliteValue[] | Record<string, SqliteValue>;
    export type SqliteRow = Record<string, null | number | string | Uint8Array>;

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

        /**
         * Number of rows changed by the most recent INSERT, UPDATE, or DELETE.
         */
        changes(): number;

        /**
         * Rowid of the most recent successful INSERT.
         */
        lastInsertRowid(): number;

        /**
         * Interrupt a pending SQLite operation on this connection.
         */
        interrupt(): void;

        /**
         * Set SQLite busy timeout in milliseconds.
         */
        busyTimeout(ms: number): void;

        /**
         * Register a scalar SQL function backed by a JS callback.
         * @param name SQL function name
         * @param nArg Argument count, or -1 for varargs
         * @param func JS function invoked for each call
         * @param options optional { deterministic, useBigIntArguments }
         */
        createFunction(
            name: string,
            nArg: number,
            func: (...args: any[]) => any,
            options?: { deterministic?: boolean; directOnly?: boolean; useBigIntArguments?: boolean },
        ): void;

        /**
         * Register an aggregate (or window) SQL function backed by JS callbacks.
         * @param name SQL function name
         * @param nArg Argument count, or -1 for varargs
         * @param options start, step, optional result/inverse, deterministic, useBigIntArguments
         */
        createAggregate(
            name: string,
            nArg: number,
            options: {
                start: any;
                step: (...args: any[]) => any;
                result?: (acc: any) => any;
                inverse?: (...args: any[]) => any;
                deterministic?: boolean;
                directOnly?: boolean;
                useBigIntArguments?: boolean;
            },
        ): void;

        /**
         * Online backup of this connection to a destination file path.
         * @param destPath Destination database file
         * @param sourceName Source schema name (default "main")
         * @param destName Destination schema name (default "main")
         * @returns Total page count copied (Node backup() resolve value)
         */
        backupTo(destPath: string, sourceName?: string, destName?: string): number;
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
         * Bind parameters without executing the statement.
         *
         * Passing no argument or undefined clears all bindings. Array parameters
         * bind positionally from 1; object keys must match named parameters.
         *
         * @param params Parameters to bind
         */
        bind(params?: SqliteParams): void;

        /**
         * Reset the statement cursor while preserving bindings.
         */
        reset(): void;

        /**
         * Execute the prepared statement and return all rows
         * @param params Optional parameters to bind
         * If params is omitted, existing bindings are preserved.
         *
         * @returns Array of rows with a null prototype
         */
        all(params?: SqliteParams): SqliteRow[];

        /**
         * Execute one step of the prepared statement.
         *
         * If params is omitted, existing bindings are preserved. SELECT rows are
         * not returned; use all() for queries.
         *
         * @param params Optional parameters to bind
         */
        run(params?: SqliteParams): void;
    }

    /**
     * Open a SQLite3 database
     * @param filename Path to the database file
     * @param flags Open flags. The native binding passes this directly to sqlite3_open_v2().
     * @returns A database connection handle
     */
    export function open(filename: string, flags: number): Sqlite3Handle;

    /**
     * Open flags
     */
    export const O_CREATE: number;
    export const O_READONLY: number;
    export const O_READWRITE: number;
    export const O_MEMORY: number;
    export const O_URI: number;
    export const O_URL: number;
    export const O_NOMUTEX: number;
    export const O_FULLMUTEX: number;
    export const O_SHAREDCACHE: number;
    export const O_PRIVATECACHE: number;
    export const O_NOFOLLOW: number;
}
