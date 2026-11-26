/**
 * txiki.js SSL Module - TypeScript Definitions
 * Based on OpenSSL for TLS/SSL connections
 */

/**
 * USAGE EXAMPLES
 * @example
 * ```ts
 * const ssl = import.meta.use('ssl');
 * const streams = import.meta.use('streams');
 *
 * const ctx = new ssl.Context({ mode: 'client', verify: true });
 * const tcp = new streams.TCP();
 * await tcp.connect({ ip: '93.184.216.34', port: 443 });
 *
 * const pipe = new ssl.Pipe(ctx, { servername: 'example.com' });
 * pipe.handshake();
 * const hello = pipe.getOutput();
 * if (hello) await tcp.write(hello);
 *
 * const incoming = new Uint8Array(16384);
 * const nread = await tcp.read(incoming);
 * pipe.feed(incoming.subarray(0, nread));
 * pipe.handshake();
 * ```
 */
declare namespace CModuleSSL {
    /**
     * SSL Context Options
     */
    export interface ContextOptions {
        /** Operation mode: "server" or "client" */
        mode?: "server" | "client";

        /** SSL/TLS method */
        version?: "TLS" | "TLSv1.2" | "TLSv1.3";

        /** Minimum TLS version */
        minVersion?: "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

        /** Maximum TLS version */
        maxVersion?: "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

        /** Certificate PEM data, or a parsed Certificate */
        cert?: string | Certificate;

        /** Private key PEM data */
        key?: string;

        /** CA certificate PEM data for verification */
        ca?: string;

        /** Cipher list string */
        ciphers?: string;

        /** Enable peer certificate verification. circu.js does not load system
         * trust anchors implicitly: pass `ca` PEM data, otherwise every
         * verified handshake fails. */
        verify?: boolean;

        /** Check the peer certificate name against the pipe servername */
        verifyHostname?: boolean;

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

        /** DH parameters in PEM format */
        dhparam?: string;

        /** ECDH curve name */
        ecdhCurve?: string;
    }

    /**
     * SSL Context - Configuration for SSL/TLS connections
     */
    export class Context {
        /**
         * Create a new SSL context
         * @param options Context configuration
         */
        constructor(options?: ContextOptions);

        /** Operation mode */
        readonly mode: "server" | "client";
    }

    /**
     * SSL Pipe Options
     */
    export interface PipeOptions {
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

        /** Valid from as Unix epoch milliseconds */
        validFromMs: number;

        /** Valid to as Unix epoch milliseconds */
        validToMs: number;

        /** Is this a CA certificate */
        ca: boolean;

        /** Subject alternative names (comma-separated, typed) */
        subjectAltName?: string;

        /** Authority information access entries */
        infoAccess?: string;

        /** Extended key usage OIDs */
        keyUsage?: string[];

        /** Signature algorithm long name */
        signatureAlgorithm?: string;

        /** Signature algorithm OID */
        signatureAlgorithmOid?: string;
    }

    /**
     * Certificate - X.509 certificate wrapper
     *
     * Owns a parsed certificate. Instances come from `new Certificate(data)`,
     * `loadPEM(data, 'certificate')` or `pipe.certificate`.
     */
    export class Certificate {
        /** Parse a certificate from PEM or DER data */
        constructor(data: ArrayBuffer | ArrayBufferView);

        /** Structured certificate metadata */
        get info(): CertificateInfo;

        /** DER encoding */
        readonly raw: ArrayBuffer;

        /** Subject public key, SPKI DER */
        readonly publicKey: ArrayBuffer;

        /** PEM encoding */
        readonly pem: string;

        /** SHA-1 fingerprint (colon-separated hex) */
        readonly fingerprint: string;

        /** SHA-256 fingerprint (colon-separated hex) */
        readonly fingerprint256: string;

        /** SHA-512 fingerprint (colon-separated hex) */
        readonly fingerprint512: string;

        /** Check the certificate against a hostname; returns the matched name */
        checkHost(name: string, options?: {
            subject?: 'default' | 'always' | 'never';
            wildcards?: boolean;
            partialWildcards?: boolean;
            multiLabelWildcards?: boolean;
            singleLabelSubdomains?: boolean;
        }): string | undefined;

        /** Check the certificate against an email address */
        checkEmail(email: string, options?: { subject?: 'default' | 'always' | 'never' }): string | undefined;

        /** Check the certificate against an IP address */
        checkIP(ip: string): string | undefined;

        /** Whether this certificate was issued by |issuer| */
        checkIssued(issuer: Certificate): boolean;

        /** Whether the certificate signature verifies with |publicKey| (SPKI DER) */
        verify(publicKey: ArrayBuffer | ArrayBufferView): boolean;

        /** Whether |privateKey| (DER) matches the certificate's public key */
        checkPrivateKey(privateKey: ArrayBuffer | ArrayBufferView): boolean;
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
    export class Pipe {
        /**
         * Create a new SSL pipe
         * @param context SSL context to use
         * @param options Pipe options
         */
        constructor(context: Context, options?: PipeOptions);

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
        handshake(): boolean;

        /**
         * Initiate SSL/TLS connection shutdown
         * @returns Shutdown status code
         */
        shutdown(): number;

        /**
         * Get the peer certificate
         * @returns Certificate instance, or null if not available
         */
        readonly certificate: Certificate | null;

        /**
         * Get negotiated SSL/TLS version
         * @returns Version string (e.g., "TLSv1.3")
         */
        readonly version: string;

        /**
         * Get current cipher information
         * @returns Cipher info or null if not established
         */
        readonly cipher: CipherInfo | null;

        /**
         * Get negotiated ALPN protocol
         * @returns Protocol name or null if not negotiated
         */
        readonly alpnProtocol: string | null;

        /**
         * Get peer certificate verification result
         * @returns Verification result
         */
        readonly verifyResult: VerifyResult;

        /** Whether SSL handshake is complete */
        readonly handshakeComplete: boolean;

        /** Whether this pipe operates in server mode */
        readonly isServer: boolean;
    }

    /**
     * Private key summary returned by `loadPEM(data, 'key')`.
     */
    export interface KeyInfo {
        /** Key algorithm name ("RSA", "EC", "Ed25519" or "unknown") */
        type?: string;

        /** Key size in bits */
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
    export const version: string;

    /**
     * Get list of available cipher suites
     */
    export const ciphers: string[];

    /**
     * Load and parse PEM data
     * @param data PEM-encoded data
     * @param type Type: "certificate" or "key"
     */
    export function loadPEM(data: string, type?: "certificate"): Certificate | null;
    export function loadPEM(data: string, type: "key"): KeyInfo | null;

    /**
     * Create a self-signed certificate
     * @param options Certificate options
     */
    export function createSelfSignedCert(options?: SelfSignedCertOptions): SelfSignedCertResult;
}
