/**
 * Synchronous socket operations.
 *
 * Prefer `streams.TCP` or `udp.UDP` for ordinary asynchronous networking.
 * This module is intended for raw sockets, polling, ancillary data, and other
 * cases that need direct access to operating-system socket features.
 *
 * @example TCP listener
 * ```ts
 * const socket = import.meta.use('socket');
 *
 * const server = new socket.Socket(socket.AF_INET, socket.SOCK_STREAM);
 * server.bind({ ip: '127.0.0.1', port: 8080 });
 * server.listen();
 *
 * console.log(server.sockname); // { family: 4, ip: '127.0.0.1', port: 8080 }
 * ```
 *
 * @example TCP client
 * ```ts
 * const socket = import.meta.use('socket');
 *
 * const client = new socket.Socket(socket.AF_INET, socket.SOCK_STREAM);
 * client.connect({ ip: '127.0.0.1', port: 8080 });
 * client.send(new TextEncoder().encode('hello'));
 * client.close();
 * ```
 */
declare namespace CModuleSocket {
    /** A `number` POSIX fd or a lossless `bigint` Windows socket handle. */
    export type SocketDescriptor = number | bigint;

    /** IPv4 or IPv6 endpoint accepted by {@link Socket.bind} and {@link Socket.connect}. */
    export type Address = {
        ip: string;
        port: number;
    };

    /** Decoded local or peer endpoint. */
    export type AddressInfo = CModuleStreams.AddressInfo;

    /** Socket properties reported by the operating system when available. */
    export interface SocketInfo {
        readonly type?: number;
        readonly domain?: number;
        readonly protocol?: number;
    }

    export interface CreateFromOptions {
        /** Close the wrapped descriptor when the wrapper closes. Defaults to `false`. */
        closeOnClose?: boolean;
    }

    /** Result of {@link Socket.recvmsg}. */
    export interface RecvMessage {
        /** Sender endpoint. Omitted when the operating system returns no address. */
        readonly address?: AddressInfo;
        readonly data: Uint8Array;
        /** Raw ancillary data requested with `controlSize`. */
        readonly control?: Uint8Array;
    }

    /**
     * Thin synchronous wrapper around a POSIX or Winsock socket.
     *
     * Operations can block unless the socket is configured as non-blocking.
     * Use {@link poll} to integrate readiness notifications with the event loop.
     */
    export class Socket {
        /** Create a socket. `protocol` defaults to `0` (automatic selection). */
        constructor(domain: number, type: number, protocol?: number);

        /** Bind directly from an IP endpoint object. */
        bind(address: Address): void;

        /** Connect directly from an IP endpoint object. */
        connect(address: Address): void;

        /** Mark the socket as passive. The default backlog is `511`. */
        listen(backlog?: number): void;

        /** Accept one connection. The peer endpoint is available as `peername`. */
        accept(): Socket;

        /** Shut down reading, writing, or both (`0`, `1`, or `2`). */
        shutdown(how: 0 | 1 | 2): void;

        /** Close the socket. */
        close(): void;

        /** Receive up to `count` bytes; returns `null` on an orderly peer close. */
        recv(count: number, flags?: number): Uint8Array | null;

        /** Send bytes and return the number accepted by the operating system. */
        send(data: Uint8Array, flags?: number): number;

        /** Receive payload, sender endpoint, and optional ancillary data. POSIX only. */
        recvmsg(bufferSize: number, controlSize?: number): RecvMessage;

        /**
         * Send scatter-gather payload with an optional destination and ancillary
         * data. Pass `null` for `address` on a connected socket. POSIX only.
         */
        sendmsg(
            address: Address | null | undefined,
            control: Uint8Array | null | undefined,
            flags: number,
            ...data: [Uint8Array, ...Uint8Array[]]
        ): number;

        /** Set a platform socket option using its native byte representation. */
        setopt(level: number, option: number, value: Uint8Array): void;

        /** Read a platform socket option using its native byte representation. */
        getopt(level: number, option: number, length?: number): Uint8Array;

        /** Start event-loop polling with a combination of `READABLE`, `WRITABLE`, etc. */
        poll(events: number, callback: (status: number, events: number) => void): void;

        /** Stop polling. */
        stopPoll(): void;

        readonly polling: boolean;
        readonly fileno: SocketDescriptor;
        readonly info: SocketInfo;
        readonly sockname: AddressInfo;
        readonly peername: AddressInfo;
        readonly [Symbol.toStringTag]: 'Socket';
    }

    /**
     * Wrap an existing socket descriptor without taking ownership by default.
     * Set `closeOnClose` only when transferring ownership of the descriptor.
     */
    export function createFrom(fd: SocketDescriptor, options?: CreateFromOptions): Socket;

    /** Compute an IP one's-complement checksum. */
    export function checksum(data: Uint8Array): number;

    /** Convert a network-interface name such as `eth0` to its index. */
    export function ifNameToIndex(name: string): number;

    /** Convert a network-interface index to its name. */
    export function ifIndexToName(index: number): string;

    export const AF_INET: number;
    export const AF_INET6: number;
    export const AF_UNIX: number | undefined;
    export const AF_NETLINK: number | undefined;
    export const AF_PACKET: number | undefined;

    export const SOCK_STREAM: number;
    export const SOCK_DGRAM: number;
    export const SOCK_RAW: number;
    export const SOCK_SEQPACKET: number;
    export const SOCK_RDM: number | undefined;

    export const SOL_SOCKET: number;
    export const SOL_PACKET: number | undefined;
    export const SOL_NETLINK: number | undefined;

    export const SO_REUSEADDR: number;
    export const SO_KEEPALIVE: number;
    export const SO_LINGER: number;
    export const SO_BROADCAST: number;
    export const SO_RCVBUF: number;
    export const SO_SNDBUF: number;
    export const SO_ERROR: number;
    export const SO_TYPE: number;
    export const SO_REUSEPORT: number | undefined;
    export const SO_PRIORITY: number | undefined;

    export const IPPROTO_IP: number;
    export const IPPROTO_IPV6: number;
    export const IPPROTO_ICMP: number;
    export const IPPROTO_TCP: number;
    export const IPPROTO_UDP: number;

    /** libuv readiness flags used by {@link Socket.poll}. */
    export const READABLE: number;
    export const WRITABLE: number;
    export const DISCONNECT: number;
    export const PRIORITIZED: number;
}
