/**
 * UDP module - UDP socket operations
 * 
 * @example
 * const udp = import.meta.use('udp');
 * 
 * const sock = await udp.create();
 * sock.bind({ ip: '0.0.0.0', port: 12345 });
 * 
 * const buffer = new Uint8Array(1024);
 * const { nread, addr } = await sock.recv(buffer);
 */
declare namespace CModuleUDP {
    /**
     * UDP socket object
     */
    export interface UDP {
        /**
         * Close UDP connection (synchronous)
         */
        close(): void;

        /**
         * Receive data (async, returns Promise)
         * @param buffer Uint8Array to store received data
         * @returns Receive info object
         */
        recv(buffer: Uint8Array): Promise<{
            /** Received data length */
            readonly nread: number;
            /** Partial data flag */
            readonly partial: boolean;
            /** Sender address info */
            readonly addr: Record<string, any>;
        }>;

        /**
         * Send data (async, returns Promise)
         * @param buffer Uint8Array containing data to send
         * @param addr Target address object
         * @returns Sent data length
         */
        send(buffer: Uint8Array, addr?: Record<string, any>): Promise<number>;

        /**
         * Get file descriptor (synchronous)
         * @returns File descriptor
         */
        fileno(): number;

        /**
         * Get socket name (synchronous, wraps uv_udp_getsockname)
         * @returns Socket name object
         */
        getsockname(): Record<string, any>;

        /**
         * Get peer name (synchronous, wraps uv_udp_getpeername)
         * @returns Peer name object
         */
        getpeername(): Record<string, any>;

        /**
         * Connect to address (synchronous, wraps uv_udp_connect)
         * @param addr Address object
         */
        connect(addr: Record<string, any>): void;

        /**
         * Bind to address (synchronous, wraps uv_udp_bind)
         * @param addr Address object
         * @param flags Bind flags (optional)
         */
        bind(addr: Record<string, any>, flags?: number): void;

        readonly [Symbol.toStringTag]: 'UDP';
    }

    /**
     * Create UDP socket
     * @param af Address family (e.g., AF_UNSPEC, AF_INET, AF_INET6)
     * @returns UDP socket object
     */
    export function create(af?: number): Promise<UDP>;

    /** Listen on IPv6 only, reject mapped IPv4 addresses */
    export const UDP_IPV6ONLY: number;

    /** Reuse port */
    export const UDP_REUSEADDR: number;
}
