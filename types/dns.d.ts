/**
 * DNS resolution module - supports system resolution and raw UDP queries.
 *
 * @example
 * ```ts
 * const dns = import.meta.use('dns');
 *
 * const addresses = await dns.resolve('example.com', { family: 4 });
 * const answers = await dns.query('example.com', dns.CNAME, '8.8.8.8');
 * ```
 */
declare namespace CModuleDNS {
    export type ResolvedAddress = Omit<CModuleStreams.AddressInfo, 'port'>;

    /**
     * DNS resolution options
     */
    export interface GetAddrInfoOptions {
        /**
         * Address family type
         * - `os.AF_INET`   IPv4
         * - `os.AF_INET6`  IPv6
         * - `os.AF_UNSPEC` Auto-select
         */
        family: number;

        /**
         * DNS server
         */
        server?: string;
    }

    /**
     * Resolve hostname or IP address
     * 
     * @param hostname Hostname or IP to resolve
     * @param options Resolution options
     */
    export function resolve(
        hostname: string,
        options: GetAddrInfoOptions
    ): Promise<ResolvedAddress[]>;

    /**
     * Synchronous resolution using getaddrinfo (may garble on Windows)
     * @param hostname Hostname or IP to resolve
     * @param options Resolution options
     */
    export function resolveSync(
        hostname: string,
        options: GetAddrInfoOptions
    ): ResolvedAddress[];

    /** A record (IPv4 address) = 1 */
    export const A: 1;
    /** NS record (name server) = 2 */
    export const NS: 2;
    /** CNAME record (canonical name) = 5 */
    export const CNAME: 5;
    /** SOA record (start of authority) = 6 */
    export const SOA: 6;
    /** PTR record (pointer record) = 12 */
    export const PTR: 12;
    /** MX record (mail exchange) = 15 */
    export const MX: 15;
    /** TXT record (text information) = 16 */
    export const TXT: 16;
    /** AAAA record (IPv6 address) = 28 */
    export const AAAA: 28;
    /** SRV record (service location) = 33 */
    export const SRV: 33;
    export const NAPTR: 35;    // Naming Authority Pointer
    export const CAA: 257;     // Certification Authority Authorization

    /** Base DNS answer record (shared fields) */
    export interface BaseAnswer {
        /** Queried domain name */
        name: string;
        /** Record type (1=A, 5=CNAME, 15=MX, etc.) */
        type: number;
        /** Class (usually 1 for IN) */
        class: number;
        /** Time to live (seconds) */
        ttl: number;
    }

    /** A/AAAA record */
    export interface AddressAnswer extends BaseAnswer {
        type: typeof A | typeof AAAA;
        /** IP address string */
        address: string;
    }

    /** CNAME record */
    export interface CNameAnswer extends BaseAnswer {
        type: typeof CNAME;
        /** Target domain name */
        cname: string;
    }

    /** NS record */
    export interface NsAnswer extends BaseAnswer {
        type: typeof NS;
        /** Name server */
        ns: string;
    }

    /** PTR record */
    export interface PtrAnswer extends BaseAnswer {
        type: typeof PTR;
        /** Reverse resolution result */
        ptr: string;
    }

    /** MX record */
    export interface MxAnswer extends BaseAnswer {
        type: typeof MX;
        /** Priority */
        priority: number;
        /** Mail exchange server */
        exchange: string;
    }

    /** SOA record */
    export interface SoaAnswer extends BaseAnswer {
        type: typeof SOA;
        /** Primary name server */
        primary: string;
        /** Admin email (format: admin@example.com) */
        admin: string;
        /** Serial number */
        serial: number;
        /** Refresh interval (seconds) */
        refresh: number;
        /** Retry interval (seconds) */
        retry: number;
        /** Expire time (seconds) */
        expire: number;
        /** Minimum TTL (seconds) */
        minimum: number;
    }

    /** TXT record */
    export interface TxtAnswer extends BaseAnswer {
        type: typeof TXT;
        /** Text content */
        txt: string;
    }

    /** SRV record */
    export interface SrvAnswer extends BaseAnswer {
        type: typeof SRV;
        /** Priority */
        priority: number;
        /** Weight */
        weight: number;
        /** Port */
        port: number;
        /** Target host */
        target: string;
    }

    /** NAPTR record */
    export interface NaptrAnswer extends BaseAnswer {
        type: typeof NAPTR;
        order: number;
        preference: number;
        flags: string;
        services: string;
        regexp: string;
        replacement: string;
    }

    /** CAA record */
    export interface CaaAnswer extends BaseAnswer {
        type: typeof CAA;
        flags: number;
        tag: string;
        value: string;
    }

    /** Unknown or unresolved record type */
    export interface RawAnswer extends BaseAnswer {
        type: number;
        /** rdata length */
        rdlength: number;
        /** Raw rdata */
        data: Uint8Array;
    }

    /** DNS answer record union type */
    export type DNSAnswer =
        | AddressAnswer
        | CNameAnswer
        | NsAnswer
        | PtrAnswer
        | MxAnswer
        | SoaAnswer
        | TxtAnswer
        | SrvAnswer
        | NaptrAnswer
        | CaaAnswer
        | RawAnswer;

    /**
     * Send a raw UDP DNS query.
     *
     * @warning Avoid wrapping this with `engine.waitIO()` in normal code.
     * `query()` owns a live UDP handle until the promise settles or is aborted,
     * so blocking the runtime can delay other I/O and make cancellation harder.
     *
     * @example
     * ```ts
     * const dns = import.meta.use('dns');
     *
     * const pending = dns.query('example.com', dns.A);
     * // pending.abort?.();
     * const answers = await pending;
     * ```
     *
     * @param hostname - Domain to query
     * @param type - Record type (default DNS.A)
     * @param server - DNS server address (default "8.8.8.8")
     * @param port - DNS server port (default 53)
     * @returns DNS answer array
     */
    export function query(
        hostname: string,
        type?: number,
        server?: string,
        port?: number
    ): Promise<DNSAnswer[]> & { abort?: () => void };
}
