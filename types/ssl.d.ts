/**
 * txiki.js SSL Module - TypeScript Definitions
 * Based on OpenSSL for TLS/SSL connections
 */

/**
 * USAGE EXAMPLES
 * @example
 * ```ts
 * // Example 1: HTTPS Server with SSLPipe
 * const { SSLContext, SSLPipe } = import.meta.use('ssl');
 * const { TCP } = import.meta.use('streams');
 *
 * const sslContext = new SSLContext({
 *     mode: "server",
 *     cert: "/path/to/cert.pem",
 *     key: "/path/to/key.pem",
 *     alpn: ["h2", "http/1.1"]
 * });
 *
 * const server = new TCP();
 * server.bind("0.0.0.0", 8443);
 * server.listen(128);
 *
 * server.accept().then(conn => {
 *     const pipe = new SSLPipe(sslContext);
 *
 *     conn.read().then(data => {
 *         pipe.feed(data);
 *         pipe.doHandshake();
 *
 *         const output = pipe.getOutput();
 *         if (output) conn.write(output);
 *     });
 * });
 *
 * // Example 2: HTTPS Client
 * const { SSLContext, SSLPipe } = import.meta.use('ssl');
 * const { TCP } = import.meta.use('streams');
 *
 * const sslContext2 = new SSLContext({
 *     mode: "client",
 *     verify: true,
 *     ca: "/etc/ssl/certs/ca-bundle.crt"
 * });
 *
 * const conn2 = new TCP();
 * await conn2.connect("example.com", 443);
 *
 * const pipe2 = new SSLPipe(sslContext2, { servername: "example.com" });
 *
 * // Start handshake
 * pipe2.doHandshake();
 * const handshake2 = pipe2.getOutput();
 * if (handshake2) await conn2.write(handshake2);
 *
 * // Complete handshake
 * while (!pipe2.handshakeComplete) {
 *     const response2 = await conn2.read();
 *     pipe2.feed(response2);
 *     pipe2.doHandshake();
 *
 *     const output2 = pipe2.getOutput();
 *     if (output2) await conn2.write(output2);
 * }
 *
 * // Send HTTP request
 * const request2 = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
 * pipe2.write(request2);
 * const encrypted2 = pipe2.getOutput();
 * await conn2.write(encrypted2);
 *
 * // Example 3: Generate Self-Signed Certificate
 * const { SSLContext, SSLPipe } = import.meta.use('ssl');
 * const { TCP } = import.meta.use('streams');
 *
 * const { cert, key } = createSelfSignedCert({
 *     commonName: "localhost",
 *     days: 365
 * });
 *
 * await writeFile("cert.pem", cert);
 * await writeFile("key.pem", key);
 *
 * const context3 = new SSLContext({
 *     mode: "server",
 *     cert: "cert.pem",
 *     key: "key.pem"
 * });
 *
 * // Example 4: Inspect Peer Certificate
 * const pipe4 = new SSLPipe(clientContext, { servername: "example.com" });
 * // ... perform handshake ...
 *
 * if (pipe4.handshakeComplete) {
 *     const cert4 = pipe4.getPeerCertificate();
 *     console.log("Subject:", cert4.subject);
 *     console.log("Issuer:", cert4.issuer);
 *     console.log("Valid:", cert4.validFrom, "to", cert4.validTo);
 *     console.log("SANs:", cert4.subjectAltNames);
 *     console.log("Fingerprint:", cert4.fingerprint256);
 *
 *     const verify4 = pipe4.verifyResult();
 *     if (!verify4.ok) {
 *         console.error("Certificate verification failed:", verify4.error);
 *     }
 * }
 *
 * // Example 5: Advanced SSL Context Configuration
 * import { SSLContext } from "@tjs/ssl";
 *
 * const context5 = new SSLContext({
 *     mode: "server",
 *     cert: "cert.pem",
 *     key: "key.pem",
 *     minVersion: "TLSv1.2",
 *     maxVersion: "TLSv1.3",
 *     ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
 *     alpn: ["h2", "http/1.1"],
 *     sessionTickets: true,
 *     sessionCache: true,
 *     compression: false,
 *     dhparam: "dhparam.pem",
 *     ecdhCurve: "prime256v1"
 * });
 * ```
 */
declare namespace CModuleSSL {
    /**
     * SSL Context Options
     */
    export interface SSLContextOptions {
        /** Operation mode: "server" or "client" */
        mode?: "server" | "client";

        /** SSL/TLS version: "TLS", "TLSv1.2", "TLSv1.3" */
        version?: string;

        /** Minimum TLS version */
        minVersion?: "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

        /** Maximum TLS version */
        maxVersion?: "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

        /** Path to certificate file (PEM format) */
        cert?: string;

        /** Path to private key file (PEM format) */
        key?: string;

        /** Path to CA certificate file for verification */
        ca?: string;

        /** Cipher list string */
        ciphers?: string;

        /** Enable peer certificate verification */
        verify?: boolean;

        /** Enable session tickets */
        sessionTickets?: boolean;

        /** Enable session cache */
        sessionCache?: boolean;

        /** Enable compression */
        compression?: boolean;

        /** ALPN protocols to advertise */
        alpn?: string[];

        /** Server name for SNI (client mode) */
        servername?: string;

        /** Path to DH parameters file */
        dhparam?: string;

        /** ECDH curve name */
        ecdhCurve?: string;
    }

    /**
     * SSL Context - Configuration for SSL/TLS connections
     */
    export class SSLContext {
        /**
         * Create a new SSL context
         * @param options Context configuration
         */
        constructor(options?: SSLContextOptions);

        /** Operation mode */
        readonly mode: "server" | "client";
    }

    /**
     * SSL Pipe Options
     */
    export interface SSLPipeOptions {
        /** Server name indication (SNI) for client mode */
        servername?: string;
    }

    /**
     * Certificate Information
     */
    export interface CertificateInfo {
        /** Subject distinguished name */
        subject: string;

        /** Issuer distinguished name */
        issuer: string;

        /** Serial number (hex string) */
        serialNumber: string;

        /** Valid from date */
        validFrom: string;

        /** Valid to date */
        validTo: string;

        /** Subject alternative names */
        subjectAltNames?: string[];

        /** SHA-256 fingerprint */
        fingerprint256: string;
    }

    /**
     * Cipher Information
     */
    export interface CipherInfo {
        /** Cipher name */
        name: string;

        /** Protocol version */
        version: string;

        /** Cipher strength in bits */
        bits: number;
    }

    /**
     * Certificate Verification Result
     */
    export interface VerifyResult {
        /** Verification result code */
        code: number;

        /** Whether verification succeeded */
        ok: boolean;

        /** Error message if verification failed */
        error?: string;
    }

    /**
     * SSL Pipe - Bidirectional SSL/TLS stream processor
     * 
     * Provides memory-based I/O for SSL/TLS handshake and data transfer.
     * Can operate as both client and server.
     */
    export class SSLPipe {
        /**
         * Create a new SSL pipe
         * @param context SSL context to use
         * @param options Pipe options
         */
        constructor(context: SSLContext, options?: SSLPipeOptions);

        /**
         * Feed encrypted data from network to SSL engine
         * @param data Encrypted data received from peer
         * @returns Number of bytes consumed
         */
        feed(data: ArrayBuffer | ArrayBufferView): number;

        /**
         * Read decrypted data from SSL engine
         * @param size Maximum bytes to read (default: 16384)
         * @returns Decrypted data or null if nothing available
         */
        read(size?: number): ArrayBuffer | null;

        /**
         * Write plaintext data to SSL engine for encryption
         * @param data Plaintext data to encrypt
         * @returns Number of bytes written
         */
        write(data: ArrayBuffer | ArrayBufferView): number;

        /**
         * Get encrypted data to send to network
         * @returns Encrypted data or null if nothing to send
         */
        getOutput(): ArrayBuffer | null;

        /**
         * Perform one step of SSL/TLS handshake
         * @returns true if handshake is complete, false if more data needed
         */
        doHandshake(): boolean;

        /**
         * Initiate SSL/TLS connection shutdown
         * @returns Shutdown status code
         */
        shutdown(): number;

        /**
         * Get peer certificate information
         * @returns Certificate info or null if not available
         */
        getPeerCertificate(): CertificateInfo | null;

        /**
         * Get negotiated SSL/TLS version
         * @returns Version string (e.g., "TLSv1.3")
         */
        getVersion(): string;

        /**
         * Get current cipher information
         * @returns Cipher info or null if not established
         */
        getCipher(): CipherInfo | null;

        /**
         * Get negotiated ALPN protocol
         * @returns Protocol name or null if not negotiated
         */
        getALPNProtocol(): string | null;

        /**
         * Get peer certificate verification result
         * @returns Verification result
         */
        verifyResult(): VerifyResult;

        /** Whether SSL handshake is complete */
        readonly handshakeComplete: boolean;

        /** Whether this pipe operates in server mode */
        readonly isServer: boolean;
    }

    /**
     * PEM Data Info
     */
    export interface PEMInfo {
        subject?: string;
        type?: string;
        bits?: number;
    }

    /**
     * Self-Signed Certificate Options
     */
    export interface SelfSignedCertOptions {
        /** Common Name (CN) for certificate */
        commonName?: string;

        /** Certificate validity in days */
        days?: number;
    }

    /**
     * Self-Signed Certificate Result
     */
    export interface SelfSignedCertResult {
        /** Certificate in PEM format */
        cert: string;

        /** Private key in PEM format */
        key: string;
    }

    /**
     * Get OpenSSL version string
     */
    export function getOpenSSLVersion(): string;

    /**
     * Get list of available cipher suites
     */
    export function getCipherList(): string[];

    /**
     * Load and parse PEM data
     * @param data PEM-encoded data
     * @param type Type: "certificate" or "key"
     */
    export function loadPEM(data: string, type?: "certificate" | "key"): PEMInfo | null;

    /**
     * Create a self-signed certificate
     * @param options Certificate options
     */
    export function createSelfSignedCert(options?: SelfSignedCertOptions): SelfSignedCertResult;
}