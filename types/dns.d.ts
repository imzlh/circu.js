/**
* DNS resolution module - Supports system resolution and raw UDP queries
* 
* @example
* const dns = import.meta.use('dns');
* 
* // Basic resolution
* const addresses = await dns.resolve('example.com', { family: 4 });
* 
* // Raw DNS query
* const answers = await dns.query('example.com', dns.CNAME, '8.8.8.8');
*/
declare namespace CModuleDNS {
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
    ): Promise<CModuleStreams.AddressInfo[]>;

    /**
     * Synchronous resolution using getaddrinfo (may garble on Windows)
     * @param hostname Hostname or IP to resolve
     * @param options Resolution options
     */
    export function resolveSync(
        hostname: string,
        options: GetAddrInfoOptions
    ): CModuleStreams.AddressInfo[];

    /** A record (IPv4 address) = 1 */
    const A: 1;
    /** NS record (name server) = 2 */
    const NS: 2;
    /** CNAME record (canonical name) = 5 */
    const CNAME: 5;
    /** SOA record (start of authority) = 6 */
    const SOA: 6;
    /** PTR record (pointer record) = 12 */
    const PTR: 12;
    /** MX record (mail exchange) = 15 */
    const MX: 15;
    /** TXT record (text information) = 16 */
    const TXT: 16;
    /** AAAA record (IPv6 address) = 28 */
    const AAAA: 28;
    /** SRV record (service location) = 33 */
    const SRV: 33;
    const NAPTR: 35;    // Naming Authority Pointer
    const CAA: 257;     // Certification Authority Authorization

    /** Base DNS answer record (shared fields) */
    interface BaseAnswer {
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
    interface AddressAnswer extends BaseAnswer {
        type: typeof A | typeof AAAA;
        /** IP address string */
        address: string;
    }

    /** CNAME record */
    interface CNameAnswer extends BaseAnswer {
        type: typeof CNAME;
        /** Target domain name */
        cname: string;
    }

    /** NS record */
    interface NsAnswer extends BaseAnswer {
        type: typeof NS;
        /** Name server */
        ns: string;
    }

    /** PTR record */
    interface PtrAnswer extends BaseAnswer {
        type: typeof PTR;
        /** Reverse resolution result */
        ptr: string;
    }

    /** MX record */
    interface MxAnswer extends BaseAnswer {
        type: typeof MX;
        /** Priority */
        priority: number;
        /** Mail exchange server */
        exchange: string;
    }

    /** SOA record */
    interface SoaAnswer extends BaseAnswer {
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
    interface TxtAnswer extends BaseAnswer {
        type: typeof TXT;
        /** Text content */
        txt: string;
    }

    /** SRV record */
    interface SrvAnswer extends BaseAnswer {
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
    interface NaptrAnswer extends BaseAnswer {
        type: typeof NAPTR;
        order: number;
        preference: number;
        flags: string;
        services: string;
        regexp: string;
        replacement: string;
    }

    /** CAA record */
    interface CaaAnswer extends BaseAnswer {
        type: typeof CAA;
        flags: number;
        tag: string;
        value: string;
    }

    /** Unknown or unresolved record type */
    interface RawAnswer extends BaseAnswer {
        type: number;
        /** rdata length */
        rdlength: number;
        /** Raw rdata */
        data: ArrayBuffer;
    }

    /** DNS answer record union type */
    type DNSAnswer =
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
     * Send raw UDP DNS query
     * Use `engine.waitIO()` for sync behavior
     * 
     * @param hostname - Domain to query
     * @param type - Record type (default DNS.A)
     * @param server - DNS server address (default "8.8.8.8")
     * @param timeout - Timeout in milliseconds (default 5000)
     * @returns DNS answer array
     */
    function query(
        hostname: string,
        type?: number,
        server?: string,
        timeout?: number
    ): Promise<DNSAnswer[]>;
}