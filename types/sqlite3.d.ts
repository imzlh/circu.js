/**
 * SQLite3 module - SQLite database operations
 * 
 * @example
 * const sqlite3 = import.meta.use('sqlite3');
 * 
 * const db = sqlite3.open('test.db');
 * const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
 * const rows = stmt.all([1]);
 * db.close();
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
         * @param params Parameters to bind
         */
        bind(params?: any): void;

        /**
         * Reset the statement cursor while preserving bindings.
         */
        reset(): void;

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
    export const O_URL: number;
    export const O_NOMUTEX: number;
    export const O_FULLMUTEX: number;
    export const O_SHAREDCACHE: number;
    export const O_PRIVATECACHE: number;
    export const O_NOFOLLOW: number;
}
