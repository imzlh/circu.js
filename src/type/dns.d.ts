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
    }

    /**
     * 解析后的地址信息对象
     */
    export interface AddressInfo {
        /**
         * IP 地址 (如 "127.0.0.1")
         */
        ip: string;

        /**
         * 地址族类型
         * - 4 表示 IPv4
         * - 6 表示 IPv6
         */
        family: 4 | 6;

        /**
         * 端口号 (始终为 0，因为只解析地址)
         */
        port: 0;
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
    export function getaddrinfo(
        hostname: string,
        options: GetAddrInfoOptions
    ): Promise<AddressInfo[]>;
}
