/**
 * txiki.js crypto module type definitions
 * OpenSSL-based cryptographic operations
 */


/**
 * Example: Hash data
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const data = new Encoder().encode('hello world');
 * const hash = crypto.sha256(data);
 * const hex = crypto.hexEncode(hash);
 * console.log(hex); // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
 * ```
 * @example Streaming hash
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const hash = crypto.createSha256();
 * hash.update(new Encoder().encode('hello '));
 * hash.update(new Encoder().encode('world'));
 * const digest = hash.digest();
 * ```
 * @example HMAC
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const key = crypto.randomBytes(32);
 * const data = new Encoder().encode('message');
 * const hmac = crypto.hmacSha256(key, data);
 * ```
 * @example AES encryption
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const key = crypto.randomBytes(32);
 * const iv = crypto.randomBytes(16);
 * const plaintext = new Encoder().encode('secret message');
 * const ciphertext = crypto.aes256CbcEncrypt(key, iv, plaintext);
 * const decrypted = crypto.aes256CbcDecrypt(key, iv, ciphertext);
 * ```
 * @example RSA signing
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const keypair = crypto.generateRsaKey(2048);
 * const data = new Encoder().encode('document');
 * const signature = crypto.signSha256(keypair.privateKey, data);
 * const valid = crypto.verifySha256(keypair.publicKey, data, signature);
 * console.log(valid); // true
 * ```
 * @example PBKDF2 key derivation
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const password = new Encoder().encode('mypassword');
 * const salt = crypto.randomBytes(16);
 * const key = crypto.pbkdf2Sha256(password, salt, 100000, 32);
 * ```
 * @example ECC P-256 key generation
 * ```typescript
 * const crypto = import.meta.use('crypto')
 * const { Encoder, Decoder } = import.meta.use('text');
 * 
 * const ecKey = crypto.generateEcKeyP256();
 * const data = new Encoder().encode('message to sign');
 * const signature = crypto.ecdsaSignP256(ecKey.privateKey, data);
 * const isValid = crypto.ecdsaVerifyP256(ecKey.publicKey, data, signature);
 * console.log('ECC signature valid:', isValid); // true
 * ```
 */
declare namespace CModuleCrypto {
    // ============================================================================
    // Hash Functions (One-shot)
    // ============================================================================

    /**
     * Compute MD5 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function md5(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA-1 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha1(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA-224 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha224(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA-256 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha256(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA-384 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha384(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA-512 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha512(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA3-224 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_224(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA3-256 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_256(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA3-384 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_384(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Compute SHA3-512 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_512(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    // ============================================================================
    // HMAC Functions (One-shot)
    // ============================================================================

    /**
     * Compute HMAC-MD5 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacMd5(
        key: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Compute HMAC-SHA1 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacSha1(
        key: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Compute HMAC-SHA256 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacSha256(
        key: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Compute HMAC-SHA512 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacSha512(
        key: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    // ============================================================================
    // Streaming Hash
    // ============================================================================

    /**
     * Hash object for streaming hash computation
     */
    export interface Hash {
        /**
         * Update hash with new data
         * @param data - Data to hash
         * @returns this for chaining
         */
        update(data: ArrayBuffer | Uint8Array): this;

        /**
         * Finalize hash and return digest
         * @returns Hash digest as ArrayBuffer
         */
        digest(): ArrayBuffer;
    }

    /**
     * Create MD5 hash object for streaming
     * @returns Hash object
     */
    export function createMd5(): Hash;

    /**
     * Create SHA-1 hash object for streaming
     * @returns Hash object
     */
    export function createSha1(): Hash;

    /**
     * Create SHA-256 hash object for streaming
     * @returns Hash object
     */
    export function createSha256(): Hash;

    /**
     * Create SHA-512 hash object for streaming
     * @returns Hash object
     */
    export function createSha512(): Hash;

    // ============================================================================
    // Streaming HMAC
    // ============================================================================

    /**
     * HMAC object for streaming HMAC computation
     */
    export interface Hmac {
        /**
         * Update HMAC with new data
         * @param data - Data to authenticate
         * @returns this for chaining
         */
        update(data: ArrayBuffer | Uint8Array): this;

        /**
         * Finalize HMAC and return digest
         * @returns HMAC digest as ArrayBuffer
         */
        digest(): ArrayBuffer;
    }

    /**
     * Create HMAC-SHA256 object for streaming
     * @param key - Secret key
     * @returns HMAC object
     */
    export function createHmacSha256(key: ArrayBuffer | Uint8Array): Hmac;

    /**
     * Create HMAC-SHA512 object for streaming
     * @param key - Secret key
     * @returns HMAC object
     */
    export function createHmacSha512(key: ArrayBuffer | Uint8Array): Hmac;

    // ============================================================================
    // Symmetric Encryption (One-shot)
    // ============================================================================

    /**
     * Encrypt data using AES-128-CBC
     * @param key - Encryption key (16 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Plaintext data
     * @returns Encrypted ciphertext
     */
    export function aes128CbcEncrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-128-CBC
     * @param key - Decryption key (16 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Ciphertext data
     * @returns Decrypted plaintext
     */
    export function aes128CbcDecrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Encrypt data using AES-256-CBC
     * @param key - Encryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Plaintext data
     * @returns Encrypted ciphertext
     */
    export function aes256CbcEncrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-256-CBC
     * @param key - Decryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Ciphertext data
     * @returns Decrypted plaintext
     */
    export function aes256CbcDecrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Encrypt data using AES-128-GCM
     * @param key - Encryption key (16 bytes)
     * @param iv - Initialization vector
     * @param data - Plaintext data
     * @returns Encrypted ciphertext with authentication tag
     */
    export function aes128GcmEncrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-128-GCM
     * @param key - Decryption key (16 bytes)
     * @param iv - Initialization vector
     * @param data - Ciphertext data with authentication tag
     * @returns Decrypted plaintext
     */
    export function aes128GcmDecrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Encrypt data using AES-256-GCM
     * @param key - Encryption key (32 bytes)
     * @param iv - Initialization vector
     * @param data - Plaintext data
     * @returns Encrypted ciphertext with authentication tag
     */
    export function aes256GcmEncrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-256-GCM
     * @param key - Decryption key (32 bytes)
     * @param iv - Initialization vector
     * @param data - Ciphertext data with authentication tag
     * @returns Decrypted plaintext
     */
    export function aes256GcmDecrypt(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    // ============================================================================
    // Streaming Cipher
    // ============================================================================

    /**
     * Cipher object for streaming encryption/decryption
     */
    export interface Cipher {
        /**
         * Update cipher with new data
         * @param data - Data to encrypt/decrypt
         * @returns Processed data as ArrayBuffer
         */
        update(data: ArrayBuffer | Uint8Array): ArrayBuffer;

        /**
         * Finalize cipher and return remaining data
         * @returns Final block as ArrayBuffer
         */
        final(): ArrayBuffer;
    }

    /**
     * Create AES-256-CBC cipher for streaming encryption
     * @param key - Encryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @returns Cipher object
     */
    export function createCipherAes256Cbc(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array
    ): Cipher;

    /**
     * Create AES-256-CBC decipher for streaming decryption
     * @param key - Decryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @returns Cipher object
     */
    export function createDecipherAes256Cbc(
        key: ArrayBuffer | Uint8Array,
        iv: ArrayBuffer | Uint8Array
    ): Cipher;

    // ============================================================================
    // Key Derivation
    // ============================================================================

    /**
     * Derive key using PBKDF2-HMAC-SHA256
     * @param password - Password
     * @param salt - Salt
     * @param iterations - Number of iterations
     * @param keylen - Desired key length in bytes
     * @returns Derived key as ArrayBuffer
     */
    export function pbkdf2Sha256(
        password: ArrayBuffer | Uint8Array,
        salt: ArrayBuffer | Uint8Array,
        iterations: number,
        keylen: number
    ): ArrayBuffer;

    /**
     * Derive key using PBKDF2-HMAC-SHA512
     * @param password - Password
     * @param salt - Salt
     * @param iterations - Number of iterations
     * @param keylen - Desired key length in bytes
     * @returns Derived key as ArrayBuffer
     */
    export function pbkdf2Sha512(
        password: ArrayBuffer | Uint8Array,
        salt: ArrayBuffer | Uint8Array,
        iterations: number,
        keylen: number
    ): ArrayBuffer;

    // ============================================================================
    // Asymmetric Cryptography (RSA)
    // ============================================================================

    /**
     * RSA key pair
     */
    export interface RsaKeyPair {
        /** Public key in PEM format */
        publicKey: ArrayBuffer;
        /** Private key in PEM format */
        privateKey: ArrayBuffer;
    }

    /**
     * Generate RSA key pair
     * @param bits - Key size in bits (default: 2048)
     * @returns RSA key pair
     */
    export function generateRsaKey(bits?: number): RsaKeyPair;

    /**
     * Sign data with RSA private key using SHA-256
     * @param privateKey - Private key in PEM format
     * @param data - Data to sign
     * @returns Signature as ArrayBuffer
     */
    export function signSha256(
        privateKey: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Sign data with RSA private key using SHA-512
     * @param privateKey - Private key in PEM format
     * @param data - Data to sign
     * @returns Signature as ArrayBuffer
     */
    export function signSha512(
        privateKey: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array
    ): ArrayBuffer;

    /**
     * Verify signature with RSA public key using SHA-256
     * @param publicKey - Public key in PEM format
     * @param data - Original data
     * @param signature - Signature to verify
     * @returns true if signature is valid
     */
    export function verifySha256(
        publicKey: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array,
        signature: ArrayBuffer | Uint8Array
    ): boolean;

    /**
     * Verify signature with RSA public key using SHA-512
     * @param publicKey - Public key in PEM format
     * @param data - Original data
     * @param signature - Signature to verify
     * @returns true if signature is valid
     */
    export function verifySha512(
        publicKey: ArrayBuffer | Uint8Array,
        data: ArrayBuffer | Uint8Array,
        signature: ArrayBuffer | Uint8Array
    ): boolean;

    // ============================================================================
    // Utility Functions
    // ============================================================================

    /**
     * Compute CRC32 checksum
     * @param data - Input data
     * @returns CRC32 checksum as 32-bit unsigned integer
     */
    export function crc32(data: ArrayBuffer | Uint8Array): number;

    /**
     * Generate cryptographically secure random bytes
     * @param length - Number of bytes to generate (max: 65536)
     * @returns Random bytes as ArrayBuffer
     */
    export function randomBytes(length: number): ArrayBuffer;

    /**
     * Encode data to Base64 string
     * @param data - Input data
     * @returns Base64 encoded string
     */
    export function base64Encode(data: ArrayBuffer | Uint8Array): string;

    /**
     * Decode Base64 string to data
     * @param str - Base64 encoded string
     * @returns Decoded data as ArrayBuffer
     */
    export function base64Decode(str: string): ArrayBuffer;

    /**
     * Encode data to hexadecimal string
     * @param data - Input data
     * @returns Hex encoded string (lowercase)
     */
    export function hexEncode(data: ArrayBuffer | Uint8Array): string;

    /**
     * Decode hexadecimal string to data
     * @param str - Hex encoded string
     * @returns Decoded data as ArrayBuffer
     */
    export function hexDecode(str: string): ArrayBuffer;

    export interface EcKeyPair {
        /** Public key in raw uncompressed format (0x04 + x + y) */
        publicKey: ArrayBuffer;
        /** Private key in raw format */
        privateKey: ArrayBuffer;
    }

    /** Generate P-256 (secp256r1) key pair */
    export function generateEcKeyP256(): EcKeyPair;
    /** Generate P-384 (secp384r1) key pair */
    export function generateEcKeyP384(): EcKeyPair;
    /** Generate P-521 (secp521r1) key pair */
    export function generateEcKeyP521(): EcKeyPair;

    /** ECDSA sign with P-256 (uses SHA-256) */
    export function ecdsaSignP256(privateKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** ECDSA sign with P-384 (uses SHA-384) */
    export function ecdsaSignP384(privateKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** ECDSA sign with P-521 (uses SHA-512) */
    export function ecdsaSignP521(privateKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /** ECDSA verify with P-256 */
    export function ecdsaVerifyP256(publicKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, signature: ArrayBuffer | Uint8Array): boolean;
    /** ECDSA verify with P-384 */
    export function ecdsaVerifyP384(publicKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, signature: ArrayBuffer | Uint8Array): boolean;
    /** ECDSA verify with P-521 */
    export function ecdsaVerifyP521(publicKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, signature: ArrayBuffer | Uint8Array): boolean;

    /** ECDH derive shared secret with P-256 */
    export function ecdhDeriveP256(privateKey: ArrayBuffer | Uint8Array, publicKey: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** ECDH derive shared secret with P-384 */
    export function ecdhDeriveP384(privateKey: ArrayBuffer | Uint8Array, publicKey: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** ECDH derive shared secret with P-521 */
    export function ecdhDeriveP521(privateKey: ArrayBuffer | Uint8Array, publicKey: ArrayBuffer | Uint8Array): ArrayBuffer;

    // ============================================================================
    // RSA-OAEP - NEW
    // ============================================================================

    /** RSA-OAEP encrypt with SHA-256 */
    export function rsaOaepSha256Encrypt(publicKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, label?: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** RSA-OAEP decrypt with SHA-256 */
    export function rsaOaepSha256Decrypt(privateKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, label?: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** RSA-OAEP encrypt with SHA-512 */
    export function rsaOaepSha512Encrypt(publicKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, label?: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** RSA-OAEP decrypt with SHA-512 */
    export function rsaOaepSha512Decrypt(privateKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, label?: ArrayBuffer | Uint8Array): ArrayBuffer;

    // ============================================================================
    // RSA-PSS - NEW
    // ============================================================================

    /** RSA-PSS sign with SHA-256 */
    export function rsaPssSha256Sign(privateKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, saltLength?: number): ArrayBuffer;
    /** RSA-PSS verify with SHA-256 */
    export function rsaPssSha256Verify(publicKey: ArrayBuffer | Uint8Array, data: ArrayBuffer | Uint8Array, signature: ArrayBuffer | Uint8Array, saltLength?: number): boolean;

    // ============================================================================
    // HKDF - NEW
    // ============================================================================

    /** HKDF key derivation with SHA-256 */
    export function hkdfSha256(ikm: ArrayBuffer | Uint8Array, keylen: number, salt?: ArrayBuffer | Uint8Array, info?: ArrayBuffer | Uint8Array): ArrayBuffer;
    /** HKDF key derivation with SHA-512 */
    export function hkdfSha512(ikm: ArrayBuffer | Uint8Array, keylen: number, salt?: ArrayBuffer | Uint8Array, info?: ArrayBuffer | Uint8Array): ArrayBuffer;

    // ============================================================================
    // Streaming GCM Cipher - NEW
    // ============================================================================

    export interface CipherGCM extends Cipher {
        /** Get authentication tag (after encryption final) */
        getAuthTag(): ArrayBuffer;
        /** Set authentication tag (for decryption) */
        setAuthTag(tag: ArrayBuffer | Uint8Array): void;
    }

    /** Create AES-256-GCM cipher for streaming encryption */
    export function gcmEncrypt(key: ArrayBuffer, iv: ArrayBuffer, plaintext: ArrayBuffer, aad?: ArrayBuffer, tagLength?: number): { ciphertext: ArrayBuffer, tag: ArrayBuffer };
    /** Create AES-256-GCM decipher for streaming decryption */
    export function gcmDecrypt(key: ArrayBuffer, iv: ArrayBuffer, ciphertext: ArrayBuffer, aad?: ArrayBuffer, tagLength?: number): { plaintext: ArrayBuffer, verified: boolean };

    /** StreamCipherGCM */
    export class GCM {
        /** note: key: ArrayBuffer (16/24/32 bytes for AES-128/192/256) */
        constructor(mode: 'encrypt' | 'decrypt', key: ArrayBuffer, iv: ArrayBuffer);
        /** set aad */
        setAAD(aad: ArrayBuffer): void;
        /** update data */
        update(data: ArrayBuffer): ArrayBuffer;
        /** final */
        final(): { ciphertext: ArrayBuffer, tag: ArrayBuffer };
    }
    
    /**
     * Generate random UUID string
     */
    function randomUUID(): Promise<string>;
}