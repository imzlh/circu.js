/**
 * UDP module - UDP socket operations
 * 
 * @example
 * const udp = import.meta.use('udp');
 * 
 * const sock = new udp.UDP();
 * sock.bind({ ip: '0.0.0.0', port: 12345 });
 * 
 * const buffer = new Uint8Array(1024);
 * const { nread, addr } = await sock.recv(buffer);
 */
declare namespace CModuleUDP {
    export type AddressInfo = CModuleStreams.AddressInfo;
    export type Address = { ip: string; port: number };
    /** A `number` POSIX fd or a lossless `bigint` Windows socket handle. */
    export type SocketDescriptor = number | bigint;

    /**
     * UDP socket object
     */
    export interface UDP {
        /**
         * Close UDP connection (synchronous, idempotent — unlike
         * `Socket.close()`, a second call is a no-op)
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
            readonly addr: AddressInfo;
        }>;

        /**
         * Send data (async, returns Promise)
         * @param buffer Uint8Array containing data to send
         * @param addr Target address object
         * @returns Sent data length
         */
        send(buffer: Uint8Array, addr?: Address): Promise<number>;

        /**
         * Get file descriptor (synchronous)
         * @returns File descriptor
         */
        fileno(): SocketDescriptor;

        /**
         * Get socket name (synchronous, wraps uv_udp_getsockname)
         * @returns Socket name object
         */
        getsockname(): AddressInfo;

        /**
         * Get peer name (synchronous, wraps uv_udp_getpeername)
         * @returns Peer name object
         */
        getpeername(): AddressInfo;

        /**
         * Connect to address (synchronous, wraps uv_udp_connect)
         * @param addr Address object
         */
        connect(addr: Address): void;

        /**
         * Disconnect the default UDP peer (synchronous, wraps uv_udp_connect(NULL))
         */
        disconnect(): void;

        /**
         * Bind to address (synchronous, wraps uv_udp_bind)
         * @param addr Address object
         * @param flags Bind flags (optional)
         */
        bind(addr: Address, flags?: number): void;

        readonly [Symbol.toStringTag]: 'UDP';
    }

    /**
     * UDP socket constructor
     * @param af Address family (e.g., AF_UNSPEC, AF_INET, AF_INET6)
     */
    export class UDP {
        constructor(af?: number);
    }

    /** Listen on IPv6 only, reject mapped IPv4 addresses */
    export const UDP_IPV6ONLY: number;

    /** Reuse port */
    export const UDP_REUSEADDR: number;
}
