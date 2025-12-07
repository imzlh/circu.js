/**
* DNS 解析模块 - 支持系统解析和原始 UDP 查询
* 
* @example
* ```typescript
* // 基础域名解析（A/AAAA记录）
* const addresses = await DNS.resolve('example.com');
* // => [{ address: '93.184.216.34', family: 4 }]
* 
* // 指定查询类型和服务器
* const answers = await DNS.query('example.com', DNS.CNAME, '8.8.8.8', 3000);
* // => [{ name: 'example.com', type: 5, class: 1, ttl: 300, cname: 'www.example.org' }]
* ```
*/
declare namespace CModuleDNS {
    /**
     * DNS 解析选项
     */
    export interface GetAddrInfoOptions {
        /**
         * 地址族类型
         * - 4 表示 IPv4 (对应 AF_INET)
         * - 6 表示 IPv6 (对应 AF_INET6)
         * - 0 表示自动选择 (对应 AF_UNSPEC)
         */
        family: 4 | 6 | 0;

        /**
         * DNS服务器
         */
        server?: string;
    }

    /**
     * 解析主机名或 IP 地址
     * 
     * @param hostname 要解析的主机名或 IP 地址
     * @param options 解析选项
     * 
     * @example
     * // 解析 IPv4 地址
     * dns.getaddrinfo('example.com', { family: 4 })
     *   .then(addresses => {
     *     addresses.forEach(addr => {
     *       console.log(addr.ip); // 如 "93.184.216.34"
     *     });
     *   });
     * 
     * @example
     * // 解析 IPv6 地址
     * dns.getaddrinfo('example.com', { family: 6 })
     *   .then(addresses => {
     *     addresses.forEach(addr => {
     *       console.log(addr.ip); // 如 "2606:2800:220:1:248:1893:25c8:1946"
     *     });
     *   });
     */
    export function resolve(
        hostname: string,
        options: GetAddrInfoOptions
    ): Promise<CModuleStreams.AddressInfo[]>;

    /** A记录 (IPv4地址) = 1 */
    const A: 1;
    /** NS记录 (域名服务器) = 2 */
    const NS: 2;
    /** CNAME记录 (别名) = 5 */
    const CNAME: 5;
    /** SOA记录 (授权开始) = 6 */
    const SOA: 6;
    /** PTR记录 (指针记录) = 12 */
    const PTR: 12;
    /** MX记录 (邮件交换) = 15 */
    const MX: 15;
    /** TXT记录 (文本信息) = 16 */
    const TXT: 16;
    /** AAAA记录 (IPv6地址) = 28 */
    const AAAA: 28;
    /** SRV记录 (服务定位) = 33 */
    const SRV: 33;
    const NAPTR: 35;    // Naming Authority Pointer
    const CAA: 257;     // Certification Authority Authorization

    /** 基础DNS应答记录（所有记录共享的字段） */
    interface BaseAnswer {
        /** 查询的域名 */
        name: string;
        /** 记录类型（1=A, 5=CNAME, 15=MX等） */
        type: number;
        /** 类（通常为1，表示IN） */
        class: number;
        /** 生存时间（秒） */
        ttl: number;
    }

    /** A/AAAA记录 */
    interface AddressAnswer extends BaseAnswer {
        type: typeof A | typeof AAAA;
        /** IP地址字符串 */
        address: string;
    }

    /** CNAME记录 */
    interface CNameAnswer extends BaseAnswer {
        type: typeof CNAME;
        /** 目标域名 */
        cname: string;
    }

    /** NS记录 */
    interface NsAnswer extends BaseAnswer {
        type: typeof NS;
        /** 域名服务器 */
        ns: string;
    }

    /** PTR记录 */
    interface PtrAnswer extends BaseAnswer {
        type: typeof PTR;
        /** 反向解析结果 */
        ptr: string;
    }

    /** MX记录 */
    interface MxAnswer extends BaseAnswer {
        type: typeof MX;
        /** 优先级 */
        priority: number;
        /** 邮件交换服务器 */
        exchange: string;
    }

    /** SOA记录 */
    interface SoaAnswer extends BaseAnswer {
        type: typeof SOA;
        /** 主域名服务器 */
        primary: string;
        /** 管理员邮箱 (格式: admin@example.com) */
        admin: string;
        /** 序列号 */
        serial: number;
        /** 刷新间隔（秒） */
        refresh: number;
        /** 重试间隔（秒） */
        retry: number;
        /** 过期时间（秒） */
        expire: number;
        /** 最小TTL（秒） */
        minimum: number;
    }

    /** TXT记录 */
    interface TxtAnswer extends BaseAnswer {
        type: typeof TXT;
        /** 文本内容 */
        txt: string;
    }

    /** SRV记录 */
    interface SrvAnswer extends BaseAnswer {
        type: typeof SRV;
        /** 优先级 */
        priority: number;
        /** 权重 */
        weight: number;
        /** 端口 */
        port: number;
        /** 目标主机 */
        target: string;
    }

    /** NAPTR记录 */
    interface NaptrAnswer extends BaseAnswer {
        type: typeof NAPTR;
        order: number;
        preference: number;
        flags: string;
        services: string;
        regexp: string;
        replacement: string;
    }

    /** CAA记录 */
    interface CaaAnswer extends BaseAnswer {
        type: typeof CAA;
        flags: number;
        tag: string;
        value: string;
    }

    /** 未知或未解析记录类型 */
    interface RawAnswer extends BaseAnswer {
        type: number;
        /** rdata长度 */
        rdlength: number;
        /** 原始rdata数据 */
        data: ArrayBuffer;
    }

    /** DNS应答记录联合类型 */
    type DNSAnswer = 
        | AddressAnswer 
        | CNameAnswer 
        | NsAnswer 
        | PtrAnswer 
        | MxAnswer 
        | SoaAnswer 
        | TxtAnswer 
        | SrvAnswer 
        | RawAnswer;

    /**
     * 发送原始 UDP DNS 查询请求
     * 
     * @param hostname - 要查询的域名
     * @param type - 记录类型（默认 DNS.A）
     * @param server - DNS服务器地址（默认 "8.8.8.8"）
     * @param timeout - 超时时间毫秒（默认 5000）
     * @returns DNS应答记录数组
     * 
     * @example
     * ```typescript
     * // 查询CNAME记录
     * const cname = await DNS.query('www.example.com', DNS.CNAME);
     * console.log(cname[0].cname); // "example.com"
     * 
     * // 查询TXT记录
     * const txt = await DNS.query('example.com', DNS.TXT, '1.1.1.1', 3000);
     * console.log(txt[0].txt); // "v=spf1 -all"
     * 
     * // 批量查询MX记录
     * const mx = await DNS.query('gmail.com', DNS.MX);
     * mx.forEach(r => console.log(r.name, r.type, r.ttl));
     * ```
     */
    function query(
        hostname: string,
        type?: number,
        server?: string,
        timeout?: number
    ): Promise<DNSAnswer[]>;
}