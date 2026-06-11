/**
 * Streams module - TCP, Pipe, and TTY stream operations
 * 
 * @example
 * const { TCP } = import.meta.use('streams');
 * 
 * const server = new TCP();
 * server.bind({ ip: '0.0.0.0', port: 8080 });
 * server.listen(128);
 * server.onconnection = (err, client) => {
 *   if (!err) console.log('New connection');
 * };
 */
declare namespace CModuleStreams {
    /**
     * Base Stream interface
     */
    export interface Stream {
        /**
         * Read data callback - on successful read
         * @param result Read data (Uint8Array)
         * @param error undefined
         */
        onread(result: Uint8Array<ArrayBuffer>, error: undefined): void;
        /**
         * Read data callback - on EOF
         * @param result null (indicates EOF)
         * @param error undefined
         */
        onread(result: null, error: undefined): void;
        /**
         * Read data callback - on read failure
         * @param result undefined
         * @param error Error object
         */
        onread(result: undefined, error: CModuleError.Error): void;

        /**
         * New connection callback - on successful accept
         * @param error undefined
         * @param client New client Stream object
         */
        onconnection(error: undefined, client: Stream): void;
        /**
         * New connection callback - on accept failure
         * @param error Error object
         * @param client undefined
         */
        onconnection(error: CModuleError.Error, client: undefined): void;

        /**
         * Start listening for incoming connections (server mode only)
         * @param backlog Maximum pending connection queue length, default 511
         * @throws Synchronous throw on error (already listening, invalid handle, etc.)
         */
        listen(backlog?: number): void;

        /**
         * Shutdown write/read direction (synchronous, wraps uv_shutdown)
         */
        shutdown(): void;

        /**
         * Set stream to blocking or non-blocking mode
         * @param blocking true for blocking, false for non-blocking
         * @throws Synchronous throw on error
         */
        setBlocking(blocking: boolean): void;

        /**
         * Fully close stream and release resources
         * @throws Synchronous throw on error
         */
        close(): void;

        /**
         * Start reading data
         */
        startRead(): void;

        /**
         * Stop reading data
         */
        stopRead(): void;

        /**
         * Write data to stream
         * @param buffer Uint8Array containing data to write
         * @returns Promise resolves to bytes written, rejects on failure
         */
        write(buffer: Uint8Array): Promise<number>;

        /**
         * Async read data into user buffer (zero-copy)
         * @param buffer Uint8Array to store read data
         * @returns Promise resolves to bytes read (0 = EOF), rejects on failure
         */
        read(buffer: Uint8Array): Promise<number>;

        /**
         * Sync read using OS-level blocking read()/recv()
         * @param buffer Uint8Array to store read data
         * @returns Bytes read, null indicates EOF
         * @throws Synchronous throw on error
         */
        readSync(buffer: Uint8Array): number | null;

        /**
         * Sync write using OS-level blocking write()/send()
         * @param buffer Uint8Array containing data to write
         * @returns Bytes written
         * @throws Synchronous throw on error
         */
        writeSync(buffer: Uint8Array): number;

        /**
         * Get underlying file descriptor
         * @returns File descriptor number
         */
        get fileno(): number;

        /**
         * Increase event loop ref count, prevent handle from being reclaimed
         */
        ref(): void;

        /**
         * Decrease event loop ref count, allow handle to be reclaimed
         */
        unref(): void;

        readonly [Symbol.toStringTag]: 'Stream';
    }

    export type AddressInfo = {
        /**
         * IP address (e.g., "127.0.0.1")
         */
        ip: string;

        /**
         * Port number
         */
        port: number;
    } & ({
        /**
         * Address family, IPv4
         */
        family: 4;
    } | {
        /**
         * Address family, IPv6
         */
        family: 6;

        /**
         * Flow info
         */
        flowInfo: number;

        /**
         * Scope ID
         */
        scopeId: number;
    })

    /**
     * TCP stream interface
     */
    export interface TCP extends Stream {
        /**
         * Get local socket address info
         * @returns Object with address, port, family info
         */
        get sockname(): AddressInfo;

        /**
         * Get remote peer address info
         * @returns Object with address, port, family info
         */
        get peername(): AddressInfo;

        /**
         * Connect to specified address
         * @param addr Address object (e.g., {ip: '127.0.0.1', port: 8080})
         * @returns Promise resolves when connection established
         */
        connect(addr: {
            ip: string;
            port: number;
        }): Promise<void>;

        /**
         * Sync connect using OS-level blocking connect()
         * @param addr Address object (e.g., {ip: '127.0.0.1', port: 8080})
         * @throws Synchronous throw on error
         */
        connectSync(addr: {
            ip: string;
            port: number;
        }): void;

        /**
         * Bind to local address
         * @param addr Address object
         * @param flags Bind flags (e.g., TCP_IPV6ONLY), optional
         * @throws Synchronous throw on error
         */
        bind(addr: {
            ip: string;
            port: number;
        }, flags?: number): void;

        /**
         * Set TCP keepalive option
         * @param enable Enable or disable
         * @param delay Probe interval (milliseconds)
         * @throws Synchronous throw on error
         */
        setKeepAlive(enable: boolean, delay: number): void;

        /**
         * Set TCP_NODELAY option (disable Nagle's algorithm)
         * @param enable Enable or disable
         * @throws Synchronous throw on error
         */
        setNoDelay(enable: boolean): void;
    }

    /**
     * TTY stream interface
     */
    export interface TTY extends Stream {
        /**
         * Set or Get TTY mode (is a getset)
         * @param mode TTY_MODE_NORMAL, TTY_MODE_RAW or TTY_MODE_RAW_VT
         * @throws Synchronous throw on error
         */
        mode: number;

        /**
         * Get terminal window size
         * @returns Object with width and height
         */
        get size(): { width: number; height: number };
    }

    /**
     * Pipe stream interface (Unix domain socket / named pipe)
     */
    export interface Pipe extends Stream {
        /**
         * Sync connect using OS-level blocking connect()
         * @param name Pipe path or name
         * @throws Synchronous throw on error (Windows not supported)
         */
        connectSync(name: string): void;

        /**
         * Initialize Pipe with existing file descriptor
         * @param fd File descriptor
         * @throws Synchronous throw on error
         */
        open(fd: number): void;

        /**
         * Get local Pipe name/path
         * @returns Name string
         */
        get sockname(): string;

        /**
         * Get remote Pipe name/path
         * @returns Name string
         */
        get peername(): string;

        /**
         * Connect to specified Pipe
         * @param name Pipe path or name
         * @returns Promise resolves when connection established
         */
        connect(name: string): Promise<void>;

        /**
         * Bind to local Pipe name
         * @param name Pipe path or name
         * @throws Synchronous throw on error
         */
        bind(name: string): void;
    }

    /**
     * TCP constructor
     * @example const tcp = new TCP();
     */
    export const TCP: {
        new(af?: number): TCP;
        readonly prototype: TCP;
    };

    /**
     * TTY constructor
     * @example const tty = new TTY(fd, true);
     */
    export const TTY: {
        new(fd: number, readable: boolean): TTY;
        readonly prototype: TTY;
    };

    /**
     * Pipe constructor
     * @example const pipe = new Pipe();
     */
    export const Pipe: {
        new(): Pipe;
        readonly prototype: Pipe;
    };

    /**
     * Constants
     */
    /** TCP bind option: IPv6 only */
    export const TCP_IPV6ONLY: number;

    /** TTY mode: normal line-buffered mode */
    export const TTY_MODE_NORMAL: number;

    /** TTY mode: raw unbuffered mode */
    export const TTY_MODE_RAW: number;

    /** TTY mode: raw mode + Windows VT input (supports bracketed paste) */
    export const TTY_MODE_RAW_VT: number;
}