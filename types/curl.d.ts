// curl.d.ts
declare namespace CModuleCURL {
    /**
     * CURL module version information
     */
    export interface VersionInfo {
        /** LibCURL version string */
        curl: string;
        /** Supported protocols list (comma-separated) */
        protocols: string;
        /** Feature flags bitmask */
        features: number;
    }

    /**
     * HTTP response object
     */
    export interface Response {
        /** Response body content */
        body?: string;
        /** Raw response headers */
        headers: string;
        /** HTTP status code */
        status: number;
        /** Final request URL (may differ after redirects) */
        url?: string;
        /** Whether streaming mode (body is empty when true) */
        streamed: boolean;
    }

    /**
     * HTTP request error object
     */
    export interface CURLException {
        /** Error message */
        message: string;
        /** LibCURL error code */
        code: number;
    }

    /**
     * Progress callback function
     * @param dltotal Total download bytes (0 if unknown)
     * @param dlnow Downloaded bytes
     * @param ultotal Total upload bytes (0 if unknown)
     * @param ulnow Uploaded bytes
     * @returns Return true to continue, false to abort
     */
    export type ProgressCallback = (dltotal: number, dlnow: number, ultotal: number, ulnow: number) => boolean;

    /**
     * HTTP header callback function
     * @param header Single HTTP header line (includes trailing CRLF)
     * @returns Bytes processed, return 0 to abort
     */
    export type HeaderCallback = (header: string) => number;

    /**
     * Connection pool configuration options
     */
    export interface ConnPoolOptions {
        /** Maximum total connections */
        maxConnections?: number;
        /** Maximum connections per host */
        maxConnectionsPerHost?: number;
        /** Enable HTTP/2 multiplexed pipelining */
        pipelining?: boolean;
    }

    /**
     * HTTP request options (for convenience methods)
     */
    export interface RequestOptions {
        /** HTTP request headers */
        headers?: Record<string, string>;
        /** Timeout (milliseconds) */
        timeout?: number;
    }

    /**
     * CURL request statistics
     */
    export interface RequestInfo {
        /** HTTP status code */
        status: number;
        /** Final request URL */
        url?: string;
        /** Total request time (seconds) */
        totalTime: number;
        /** Downloaded data size (bytes) */
        downloadSize: number;
        /** Uploaded data size (bytes) */
        uploadSize: number;
    }

    /**
     * Connection pool - Manages multiple CURL connections for reuse
     * 
     * @example
     * const { ConnPool, CURL } = import.meta.use('curl');
     * 
     * const pool = new ConnPool({ maxConnections: 10 });
     * const curl = new CURL(pool);
     * 
     * const res = await curl.setUrl('https://example.com')
     *                      .setMethod('GET')
     *                      .perform();
     */
    export class ConnPool {
        /**
         * Create new connection pool
         * @param options Connection pool configuration options
         */
        constructor(options?: ConnPoolOptions);

        /**
         * Get current active connection count
         */
        getActiveCount(): number;

        /**
         * Process all pending async operations
         * Should be called periodically in event loop to ensure callbacks are executed
         */
        process(): void;

        /**
         * Close connection pool and release all resources
         */
        close(): void;

        /**
         * Set HTTP pipeline maximum length (HTTP/2 only)
         * @param length Maximum pipeline length
         */
        setMaxPipelineLength(length: number): void;

        /**
         * Set HTTP/2 maximum concurrent streams
         * @param streams Maximum concurrent streams
         */
        setMaxConcurrentStreams(streams: number): void;
    }

    /**
     * CURL class - Represents a single HTTP request
     * 
     * @example
     * const { ConnPool, CURL } = import.meta.use('curl');
     * 
     * const pool = new ConnPool();
     * const curl = new CURL(pool);
     * 
     * // GET request
     * const res = await curl.setUrl('https://api.example.com/data')
     *                      .setHeaders({ 'Authorization': 'Bearer token' })
     *                      .perform();
     * 
     * // POST request
     * const postRes = await curl.setUrl('https://api.example.com/submit')
     *                         .setMethod('POST')
     *                         .setHeaders({ 'Content-Type': 'application/json' })
     *                         .setBody(JSON.stringify({ key: 'value' }))
     *                         .perform();
     */
    export class CURL {
        /**
         * Create new CURL instance
         * @param pool Connection pool (required)
         */
        constructor(pool: ConnPool);

        /**
         * Set request URL
         * @param url Request URL
         * @returns Current CURL instance (supports chaining)
         */
        setUrl(url: string): this;

        /**
         * Set HTTP method
         * @param method HTTP method (GET, POST, PUT, HEAD, DELETE, etc.)
         * @returns Current CURL instance (supports chaining)
         */
        setMethod(method: string): this;

        /**
         * Set HTTP request headers
         * @param headers Headers object
         * @returns Current CURL instance (supports chaining)
         */
        setHeaders(headers: Record<string, string>): this;

        /**
         * Set request body (for POST/PUT, etc.)
         * @param body Request body string
         * @returns Current CURL instance (supports chaining)
         */
        setBody(body: string): this;

        /**
         * Set timeout (milliseconds)
         * @param timeout Timeout in milliseconds
         * @returns Current CURL instance (supports chaining)
         */
        setTimeout(timeout: number): this;

        /**
         * Set whether to follow redirects
         * @param follow Whether to follow redirects
         * @returns Current CURL instance (supports chaining)
         */
        setFollowRedirects(follow: boolean): this;

        /**
         * Set SSL/TLS verification
         * @param verifyPeer Whether to verify peer certificate
         * @param verifyHost Whether to verify hostname (defaults to verifyPeer)
         * @returns Current CURL instance (supports chaining)
         */
        setSSLVerify(verifyPeer: boolean, verifyHost?: boolean): this;

        /**
         * Set CA certificate bundle path
         * @param path CA certificate file path
         * @returns Current CURL instance (supports chaining)
         */
        setCABundle(path: string): this;

        /**
         * Set proxy server
         * @param proxy Proxy server address (e.g., http://proxy.example.com:8080)
         * @param type Proxy type (http, https, socks4, socks5)
         * @returns Current CURL instance (supports chaining)
         */
        setProxy(proxy: string, type?: 'http' | 'https' | 'socks4' | 'socks5'): this;

        /**
         * Set user agent string
         * @param userAgent User agent string
         * @returns Current CURL instance (supports chaining)
         */
        setUserAgent(userAgent: string): this;

        /**
         * Set cookie string
         * @param cookie Cookie string
         * @returns Current CURL instance (supports chaining)
         */
        setCookie(cookie: string): this;

        /**
         * Set cookie file path
         * @param path Cookie file path
         * @returns Current CURL instance (supports chaining)
         */
        setCookieFile(path: string): this;

        /**
         * Set referer header
         * @param referer Referer value
         * @returns Current CURL instance (supports chaining)
         */
        setReferer(referer: string): this;

        /**
         * Set maximum redirect count
         * @param max Maximum redirects
         * @returns Current CURL instance (supports chaining)
         */
        setMaxRedirects(max: number): this;

        /**
         * Set connection timeout (milliseconds)
         * @param timeout Connection timeout in milliseconds
         * @returns Current CURL instance (supports chaining)
         */
        setConnectTimeout(timeout: number): this;

        /**
         * Set whether to enable verbose output
         * @param verbose Whether to enable verbose output
         * @returns Current CURL instance (supports chaining)
         */
        setVerbose(verbose: boolean): this;

        /**
         * Set HTTP protocol version
         * @param version HTTP version (1.0, 1.1, 2, 2TLS, 3)
         * @returns Current CURL instance (supports chaining)
         */
        setHTTPVersion(version: '1.0' | '1.1' | '2' | '2.0' | '2TLS' | '3'): this;

        /**
         * Set request range (for resumable downloads)
         * @param start Start byte position
         * @param end End byte position (optional, defaults to end of file)
         * @returns Current CURL instance (supports chaining)
         */
        setRange(start: number, end?: number): this;

        /**
         * Set DNS server list (comma-separated)
         * @param servers DNS server list (e.g., "8.8.8.8,1.1.1.1")
         * @returns Current CURL instance (supports chaining)
         */
        setDNSServers(servers: string): this;

        /**
         * Set network interface
         * @param interfaceName Network interface name or IP address
         * @returns Current CURL instance (supports chaining)
         */
        setInterface(interfaceName: string): this;

        /**
         * Set progress callback function
         * @param callback Progress callback function
         * @returns Current CURL instance (supports chaining)
         */
        onProgress(callback: ProgressCallback): this;

        /**
         * Set header callback function
         * @param callback Header callback function
         * @returns Current CURL instance (supports chaining)
         */
        onHeader(callback: HeaderCallback): this;

        /**
         * Execute HTTP request asynchronously
         * @returns Promise<Response> HTTP response
         * @throws CURLException Throws on request failure
         */
        perform(): Promise<Response>;

        /**
         * Execute HTTP request synchronously
         * @returns Response HTTP response
         * @throws CURLException Throws on request failure
         */
        performSync(): Response;

        /**
         * Get request statistics
         * @returns RequestInfo Request statistics
         */
        getInfo(): RequestInfo;

        /**
         * Reset CURL instance to initial state
         */
        reset(): void;

        /**
         * Set streaming mode. Don't save body, trigger `ondata` instead
         * @param mode Streaming mode
         */
        setStreamMode(mode: boolean): void;

        /**
         * Stream callback. Return `true` to abort reading.
         */
        onData(cb: (buf: ArrayBuffer) => boolean): void;
    }
    
    /**
     * Get module version information
     */
    export const version: VersionInfo;
}