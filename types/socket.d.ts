/**
 * POSIX Socket bindings for TJS
 *
 * @example
 * ```ts
 * const { PosixSocket, defines } = import.meta.use('socket');
 * const { AF_INET, SOCK_STREAM, IPPROTO_TCP, SOL_SOCKET, SO_REUSEADDR } = defines;
 * ```
 */

declare namespace CModuleSocket {
    // ── Defines ───────────────────────────────────────────────────────────────────

    interface SocketDefines {
        // Address families
        readonly AF_INET: number;
        readonly AF_INET6: number;
        readonly AF_UNIX?: number;  // not on Windows
        readonly AF_NETLINK?: number; // Linux only
        readonly AF_PACKET?: number; // Linux only

        // Socket types
        readonly SOCK_STREAM: number;
        readonly SOCK_DGRAM: number;
        readonly SOCK_RAW: number;
        readonly SOCK_SEQPACKET: number;
        readonly SOCK_RDM?: number;

        // Levels
        readonly SOL_SOCKET: number;
        readonly SOL_PACKET?: number; // Linux only
        readonly SOL_NETLINK?: number; // Linux only

        // SO_* options
        readonly SO_REUSEADDR: number;
        readonly SO_KEEPALIVE: number;
        readonly SO_LINGER: number;
        readonly SO_BROADCAST: number;
        readonly SO_RCVBUF: number;
        readonly SO_SNDBUF: number;
        readonly SO_ERROR: number;
        readonly SO_TYPE: number;
        readonly SO_REUSEPORT?: number;
        readonly SO_PRIORITY?: number;

        // Protocols
        readonly IPPROTO_IP: number;
        readonly IPPROTO_IPV6: number;
        readonly IPPROTO_ICMP: number;
        readonly IPPROTO_TCP: number;
        readonly IPPROTO_UDP: number;
    }

    interface UvPollEventBits {
        readonly READABLE: number;
        readonly WRITABLE: number;
        readonly DISCONNECT: number;
        readonly PRIORITIZED: number;
    }

    // ── Socket info ───────────────────────────────────────────────────────────────

    interface SocketSockInfo {
        type?: number;
        domain?: number;
        protocol?: number;
    }

    interface SocketInfo {
        socket?: SocketSockInfo;
    }

    // ── recvmsg result ────────────────────────────────────────────────────────────

    interface RecvMsgResult {
        /** Sender address as raw sockaddr bytes */
        addr: Uint8Array;
        /** Received payload */
        data: Uint8Array;
        /** Control (ancillary) data, present only if controlsize was requested */
        control?: Uint8Array;
    }

    // ── PosixSocket ───────────────────────────────────────────────────────────────

    /**
     * Thin wrapper around a POSIX/Winsock socket file descriptor.
     * All operations are synchronous and non-blocking behaviour must be arranged
     * by the caller (e.g. via {@link PosixSocket.poll}).
     *
     * @example TCP server
     * ```ts
     * const { PosixSocket, create_sockaddr_inet, defines } = import.meta.use('socket');
     * const { AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR } = defines;
     *
     * const srv = new PosixSocket(AF_INET, SOCK_STREAM, 0);
     * const opt = new Uint8Array(4); new DataView(opt.buffer).setUint32(0, 1, true);
     * srv.setopt(SOL_SOCKET, SO_REUSEADDR, opt);
     * srv.bind(create_sockaddr_inet({ host: '0.0.0.0', port: 8080 }));
     * srv.listen(128);
     * // ... poll for READABLE, then srv.accept()
     * ```
     *
     * @example UDP broadcast (Wake-on-LAN)
     * ```ts
     * const { PosixSocket, create_sockaddr_inet, defines } = import.meta.use('socket');
     * const { AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST } = defines;
     *
     * const sock = new PosixSocket(AF_INET, SOCK_DGRAM, 0);
     * const opt = new Uint8Array(4); new DataView(opt.buffer).setUint32(0, 1, true);
     * sock.setopt(SOL_SOCKET, SO_BROADCAST, opt);
     * sock.connect(create_sockaddr_inet({ host: '255.255.255.255', port: 9 }));
     * sock.send(magicPacket);
     * sock.close();
     * ```
     */
    export class PosixSocket {
        /**
         * Create a new socket.
         * @param domain   Address family, e.g. `defines.AF_INET`
         * @param type     Socket type, e.g. `defines.SOCK_STREAM`
         * @param protocol Protocol, usually `0` for auto-select
         */
        constructor(domain: number, type: number, protocol: number);

        // ── Connection lifecycle ──────────────────────────────────────────────────

        /** Bind to a local address (use {@link create_sockaddr_inet} to build the buffer). */
        bind(addr: Uint8Array): void;

        /**
         * Connect to a remote address.
         * On UDP sockets this only sets the default destination (no handshake),
         * enabling {@link send} to work without an explicit address — a portable
         * alternative to `sendto`.
         */
        connect(addr: Uint8Array): void;

        /** Mark socket as passive (server). */
        listen(backlog: number): void;

        /**
         * Accept an incoming connection.
         * The returned socket has a `_sockaddr` property with the peer address bytes.
         */
        accept(): PosixSocket;

        /**
         * Shut down one or both directions.
         * @param how  0 = RD, 1 = WR, 2 = RDWR
         */
        shutdown(how: 0 | 1 | 2): void;

        /** Close the socket. Cannot be called from within a poll callback. */
        close(): void;

        // ── I/O ──────────────────────────────────────────────────────────────────

        /**
         * Receive up to `count` bytes.
         * Returns `null` on EOF / graceful peer close.
         * @param flags  Optional recv flags (e.g. `MSG_PEEK`)
         */
        recv(count: number, flags?: number): Uint8Array | null;

        /**
         * Send bytes.
         * Returns the number of bytes actually sent.
         * @param flags  Optional send flags (e.g. `MSG_DONTWAIT`)
         */
        send(data: Uint8Array, flags?: number): number;

        /**
         * Receive a datagram with ancillary data. **POSIX only.**
         * @param bufsize     Maximum payload size
         * @param controlsize Maximum ancillary data size (omit if not needed)
         */
        recvmsg(bufsize: number, controlsize?: number): RecvMsgResult;

        /**
         * Send a message with optional address and ancillary data. **POSIX only.**
         * @param addr     Destination address bytes, or `undefined` for connected sockets
         * @param control  Ancillary (cmsg) data, or `undefined`
         * @param flags    Send flags
         * @param data     One or more data buffers (scatter-gather)
         */
        sendmsg(
            addr: Uint8Array | undefined,
            control: Uint8Array | undefined,
            flags: number,
            ...data: Uint8Array[]
        ): number;

        // ── Options ───────────────────────────────────────────────────────────────

        /**
         * Set a socket option.
         * @example Enable SO_REUSEADDR
         * ```ts
         * const opt = new Uint8Array(4);
         * new DataView(opt.buffer).setUint32(0, 1, true);
         * sock.setopt(SOL_SOCKET, SO_REUSEADDR, opt);
         * ```
         */
        setopt(level: number, optname: number, optval: Uint8Array): void;

        /**
         * Get a socket option as raw bytes.
         * @param optlen  Expected buffer size (defaults to `sizeof(sockaddr_storage)`)
         */
        getopt(level: number, optname: number, optlen?: number): Uint8Array;

        // ── Poll / event loop ─────────────────────────────────────────────────────

        /**
         * Start polling for I/O readiness via libuv.
         * The callback receives `(status: number, events: number)` where `events`
         * is a bitmask of {@link UvPollEventBits}.
         *
         * @example
         * ```ts
         * const { uv_poll_event_bits } = import.meta.use('socket');
         * srv.poll(uv_poll_event_bits.READABLE, (status, events) => {
         *     if (status < 0) { console.error(uv_strerror(status)); return; }
         *     const client = srv.accept();
         * });
         * ```
         */
        poll(events: number, callback: (status: number, events: number) => void): void;

        /** Stop polling. Cannot be called from within the poll callback. */
        pollStop(): void;

        // ── Getters ───────────────────────────────────────────────────────────────

        /** `true` while a poll is active. */
        readonly polling: boolean;

        /** The underlying file descriptor number. */
        readonly fileno: number;

        /** Type/domain/protocol info queried from the OS. */
        readonly info: SocketInfo;
    }


    /**
     * Build a raw `sockaddr` buffer from a plain address object.
     * Accepts IPv4 and IPv6 addresses.
     * @example
     * ```ts
     * const addr = create_sockaddr_inet({ host: '127.0.0.1', port: 3000 });
     * sock.connect(addr);
     * ```
     */
    export function create_sockaddr_inet(addr: { host: string; port: number }): Uint8Array;

    /**
     * Wrap an existing socket file descriptor.
     * Validates that the fd is a live socket before wrapping.
     */
    export function socket_from_fd(fd: number): PosixSocket;

    /** Compute an IP one's-complement checksum over a buffer. */
    export function checksum(data: Uint8Array): number;

    /** Translate a libuv error code to a human-readable string. */
    export function uv_strerror(code: number): string;

    /** Convert a network interface name (e.g. `"eth0"`) to its index. */
    export function if_nametoindex(name: string): number;

    /** Convert a network interface index to its name. */
    export function if_indextoname(index: number): string;

    /** Size of `struct sockaddr` on this platform. */
    export const sizeof_struct_sockaddr: number;

    /** Socket-related constants (`AF_*`, `SOCK_*`, `SO_*`, `IPPROTO_*`, …). */
    export const defines: SocketDefines;

    /** libuv poll event bit flags (`READABLE`, `WRITABLE`, `DISCONNECT`, `PRIORITIZED`). */
    export const uv_poll_event_bits: UvPollEventBits;
}