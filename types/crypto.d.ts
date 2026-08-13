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
    /** Any ArrayBuffer-backed byte range accepted by the native crypto module. */
    export type BufferSource = ArrayBuffer | ArrayBufferView;

    // ============================================================================
    // Hash Functions (One-shot)
    // ============================================================================

    /**
     * Compute MD5 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function md5(data: BufferSource): ArrayBuffer;

    export function ripemd160(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA-1 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha1(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA-224 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha224(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA-256 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha256(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA-384 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha384(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA-512 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha512(data: BufferSource): ArrayBuffer;

    export function sha512_224(data: BufferSource): ArrayBuffer;

    export function sha512_256(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA3-224 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_224(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA3-256 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_256(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA3-384 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_384(data: BufferSource): ArrayBuffer;

    /**
     * Compute SHA3-512 hash of data
     * @param data - Input data
     * @returns Hash digest as ArrayBuffer
     */
    export function sha3_512(data: BufferSource): ArrayBuffer;

    export function blake2b512(data: BufferSource): ArrayBuffer;

    export function blake2s256(data: BufferSource): ArrayBuffer;

    export function shake128(data: BufferSource, outputLength?: number): ArrayBuffer;

    export function shake256(data: BufferSource, outputLength?: number): ArrayBuffer;

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
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacRipemd160(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Compute HMAC-SHA1 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacSha1(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha224(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Compute HMAC-SHA256 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacSha256(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha384(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Compute HMAC-SHA512 of data
     * @param key - Secret key
     * @param data - Input data
     * @returns HMAC digest as ArrayBuffer
     */
    export function hmacSha512(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha512_224(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha512_256(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha3_224(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha3_256(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha3_384(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacSha3_512(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacBlake2b512(
        key: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    export function hmacBlake2s256(
        key: BufferSource,
        data: BufferSource
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
        update(data: BufferSource): this;

        /** Clone the current digest state. */
        copy(): Hash;

        /**
         * Finalize hash and return digest
         *
         * The native context is reinitialized after digest(), so the same Hash
         * object can be reused for a new digest with the same algorithm.
         *
         * @returns Hash digest as ArrayBuffer
         */
        digest(): ArrayBuffer;
    }

    /**
     * Create MD5 hash object for streaming
     * @returns Hash object
     */
    export function createMd5(): Hash;

    export function createRipemd160(): Hash;

    /**
     * Create SHA-1 hash object for streaming
     * @returns Hash object
     */
    export function createSha1(): Hash;

    /**
     * Create SHA-224 hash object for streaming
     * @returns Hash object
     */
    export function createSha224(): Hash;

    /**
     * Create SHA-256 hash object for streaming
     * @returns Hash object
     */
    export function createSha256(): Hash;

    /**
     * Create SHA-384 hash object for streaming
     * @returns Hash object
     */
    export function createSha384(): Hash;

    /**
     * Create SHA-512 hash object for streaming
     * @returns Hash object
     */
    export function createSha512(): Hash;

    export function createSha512_224(): Hash;

    export function createSha512_256(): Hash;

    /** Create SHA3-224 hash object for streaming. */
    export function createSha3_224(): Hash;

    /** Create SHA3-256 hash object for streaming. */
    export function createSha3_256(): Hash;

    /** Create SHA3-384 hash object for streaming. */
    export function createSha3_384(): Hash;

    /** Create SHA3-512 hash object for streaming. */
    export function createSha3_512(): Hash;

    export function createBlake2b512(): Hash;

    export function createBlake2s256(): Hash;

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
        update(data: BufferSource): this;

        /**
         * Finalize HMAC and return digest
         *
         * The native context is reinitialized after digest(), so the same Hmac
         * object can be reused for a new digest with the same key and algorithm.
         *
         * @returns HMAC digest as ArrayBuffer
         */
        digest(): ArrayBuffer;
    }

    /**
     * Create HMAC-SHA256 object for streaming
     * @param key - Secret key
     * @returns HMAC object
     */
    export function createHmacSha256(key: BufferSource): Hmac;

    /**
     * Create HMAC-SHA512 object for streaming
     * @param key - Secret key
     * @returns HMAC object
     */
    export function createHmacSha512(key: BufferSource): Hmac;

    // ============================================================================
    // Symmetric Encryption (One-shot)
    // ============================================================================

    /** AES-ECB one-shot operations. The IV must be null. */
    export function aes128EcbEncrypt(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes128EcbDecrypt(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes192EcbEncrypt(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes192EcbDecrypt(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes256EcbEncrypt(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes256EcbDecrypt(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;

    /**
     * Encrypt data using AES-128-CBC
     * @param key - Encryption key (16 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Plaintext data
     * @returns Encrypted ciphertext
     */
    export function aes128CbcEncrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-128-CBC
     * @param key - Decryption key (16 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Ciphertext data
     * @returns Decrypted plaintext
     */
    export function aes128CbcDecrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Encrypt data using AES-192-CBC
     * @param key - Encryption key (24 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Plaintext data
     * @returns Encrypted ciphertext
     */
    export function aes192CbcEncrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-192-CBC
     * @param key - Decryption key (24 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Ciphertext data
     * @returns Decrypted plaintext
     */
    export function aes192CbcDecrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Encrypt data using AES-256-CBC
     * @param key - Encryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Plaintext data
     * @returns Encrypted ciphertext
     */
    export function aes256CbcEncrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Decrypt data using AES-256-CBC
     * @param key - Decryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @param data - Ciphertext data
     * @returns Decrypted plaintext
     */
    export function aes256CbcDecrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Encrypt data using the legacy AES-128-GCM wrapper.
     *
     * This low-level wrapper does not expose an authentication tag. Prefer
     * gcmEncrypt() for authenticated AES-GCM data.
     * @param key - Encryption key (16 bytes)
     * @param iv - Initialization vector
     * @param data - Plaintext data
     * @returns Encrypted ciphertext without an exposed authentication tag
     */
    export function aes128GcmEncrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Decrypt data using the legacy AES-128-GCM wrapper.
     *
     * This low-level wrapper has no tag parameter. Prefer gcmDecrypt() for
     * authenticated AES-GCM data.
     * @param key - Decryption key (16 bytes)
     * @param iv - Initialization vector
     * @param data - Ciphertext data
     * @returns Decrypted plaintext if OpenSSL accepts the operation
     */
    export function aes128GcmDecrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Encrypt data using the legacy AES-192-GCM wrapper.
     *
     * This low-level wrapper does not expose an authentication tag. Prefer
     * gcmEncrypt() for authenticated AES-GCM data.
     * @param key - Encryption key (24 bytes)
     * @param iv - Initialization vector
     * @param data - Plaintext data
     * @returns Encrypted ciphertext without an exposed authentication tag
     */
    export function aes192GcmEncrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Decrypt data using the legacy AES-192-GCM wrapper.
     *
     * This low-level wrapper has no tag parameter. Prefer gcmDecrypt() for
     * authenticated AES-GCM data.
     * @param key - Decryption key (24 bytes)
     * @param iv - Initialization vector
     * @param data - Ciphertext data
     * @returns Decrypted plaintext if OpenSSL accepts the operation
     */
    export function aes192GcmDecrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Encrypt data using the legacy AES-256-GCM wrapper.
     *
     * This low-level wrapper does not expose an authentication tag. Prefer
     * gcmEncrypt() for authenticated AES-GCM data.
     * @param key - Encryption key (32 bytes)
     * @param iv - Initialization vector
     * @param data - Plaintext data
     * @returns Encrypted ciphertext without an exposed authentication tag
     */
    export function aes256GcmEncrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /**
     * Decrypt data using the legacy AES-256-GCM wrapper.
     *
     * This low-level wrapper has no tag parameter. Prefer gcmDecrypt() for
     * authenticated AES-GCM data.
     * @param key - Decryption key (32 bytes)
     * @param iv - Initialization vector
     * @param data - Ciphertext data
     * @returns Decrypted plaintext if OpenSSL accepts the operation
     */
    export function aes256GcmDecrypt(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
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
        update(data: BufferSource): ArrayBuffer;

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
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /** AES-256-CBC streaming cipher, no PKCS7 padding (raw blocks). */
    export function createCipherAes256CbcRaw(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /**
     * Create AES-192-CBC cipher for streaming encryption
     * @param key - Encryption key (24 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @returns Cipher object
     */
    export function createCipherAes192Cbc(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /** AES-192-CBC streaming cipher, no PKCS7 padding (raw blocks). */
    export function createCipherAes192CbcRaw(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /**
     * Create AES-256-CBC decipher for streaming decryption
     * @param key - Decryption key (32 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @returns Cipher object
     */
    export function createDecipherAes256Cbc(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /** AES-256-CBC streaming decipher, no PKCS7 padding (raw blocks). */
    export function createDecipherAes256CbcRaw(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /**
     * Create AES-192-CBC decipher for streaming decryption
     * @param key - Decryption key (24 bytes)
     * @param iv - Initialization vector (16 bytes)
     * @returns Cipher object
     */
    export function createDecipherAes192Cbc(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /** AES-192-CBC streaming decipher, no PKCS7 padding (raw blocks). */
    export function createDecipherAes192CbcRaw(
        key: BufferSource,
        iv: BufferSource
    ): Cipher;

    /** AES-ECB one-shot operations without PKCS7 padding. */
    export function aes128EcbEncryptRaw(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes128EcbDecryptRaw(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes192EcbEncryptRaw(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes192EcbDecryptRaw(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes256EcbEncryptRaw(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;
    export function aes256EcbDecryptRaw(key: BufferSource, iv: null, data: BufferSource): ArrayBuffer;

    /** AES-128-CBC one-shot encrypt, no PKCS7 padding. Data must be a multiple of 16 bytes. */
    export function aes128CbcEncryptRaw(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** AES-128-CBC one-shot decrypt, no PKCS7 padding. Data must be a multiple of 16 bytes. */
    export function aes128CbcDecryptRaw(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** AES-192-CBC one-shot encrypt, no PKCS7 padding. Data must be a multiple of 16 bytes. */
    export function aes192CbcEncryptRaw(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** AES-192-CBC one-shot decrypt, no PKCS7 padding. Data must be a multiple of 16 bytes. */
    export function aes192CbcDecryptRaw(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** AES-256-CBC one-shot encrypt, no PKCS7 padding. Data must be a multiple of 16 bytes. */
    export function aes256CbcEncryptRaw(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** AES-256-CBC one-shot decrypt, no PKCS7 padding. Data must be a multiple of 16 bytes. */
    export function aes256CbcDecryptRaw(
        key: BufferSource,
        iv: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

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
        password: BufferSource,
        salt: BufferSource,
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
        password: BufferSource,
        salt: BufferSource,
        iterations: number,
        keylen: number
    ): ArrayBuffer;

    /**
     * Derive key using scrypt.
     * Internal low-level entry point used by the Node compatibility layer.
     */
    export function scrypt(
        password: BufferSource,
        salt: BufferSource,
        keylen: number,
        N: number,
        r: number,
        p: number,
        maxmem: number
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

    /** Sign data with an asymmetric private key using SHA-224. */
    export function signSha224(
        privateKey: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** Sign data with an asymmetric private key using SHA-256. */
    export function signSha256(
        privateKey: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** Sign data with an asymmetric private key using SHA-384. */
    export function signSha384(
        privateKey: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** Sign data with an asymmetric private key using SHA-512. */
    export function signSha512(
        privateKey: BufferSource,
        data: BufferSource
    ): ArrayBuffer;

    /** Verify a SHA-224 asymmetric signature. */
    export function verifySha224(
        publicKey: BufferSource,
        data: BufferSource,
        signature: BufferSource
    ): boolean;

    /** Verify a SHA-256 asymmetric signature. */
    export function verifySha256(
        publicKey: BufferSource,
        data: BufferSource,
        signature: BufferSource
    ): boolean;

    /** Verify a SHA-384 asymmetric signature. */
    export function verifySha384(
        publicKey: BufferSource,
        data: BufferSource,
        signature: BufferSource
    ): boolean;

    /** Verify a SHA-512 asymmetric signature. */
    export function verifySha512(
        publicKey: BufferSource,
        data: BufferSource,
        signature: BufferSource
    ): boolean;

    /**
     * Inspect the asymmetric algorithm of a private key.
     * Returns "rsa" or "ec".
     */
    export function getPrivateKeyType(
        privateKey: BufferSource
    ): 'rsa' | 'ec';

    /**
     * Inspect the asymmetric algorithm of a public key.
     * Returns "rsa" or "ec".
     */
    export function getPublicKeyType(
        publicKey: BufferSource
    ): 'rsa' | 'ec';

    /** Export a private key as PEM bytes. */
    export function exportPrivateKeyPem(
        privateKey: BufferSource
    ): ArrayBuffer;

    /** Export a private key as DER bytes. */
    export function exportPrivateKeyDer(
        privateKey: BufferSource
    ): ArrayBuffer;

    /** Export a public key as PEM bytes. */
    export function exportPublicKeyPem(
        publicKey: BufferSource
    ): ArrayBuffer;

    /** Export a public key as DER bytes. */
    export function exportPublicKeyDer(
        publicKey: BufferSource
    ): ArrayBuffer;

    /** Derive and export the public key from a private key as PEM bytes. */
    export function derivePublicKeyPem(
        privateKey: BufferSource
    ): ArrayBuffer;

    /** Derive and export the public key from a private key as DER bytes. */
    export function derivePublicKeyDer(
        privateKey: BufferSource
    ): ArrayBuffer;

    // ============================================================================
    // Utility Functions
    // ============================================================================

    /**
     * Compute CRC32 checksum
     * @param data - Input data
     * @returns CRC32 checksum as 32-bit unsigned integer
     */
    export function crc32(data: BufferSource): number;

    /**
     * Generate cryptographically secure random bytes
     * @param length - Number of bytes to generate (max: 65536)
     * @returns Random bytes as ArrayBuffer
     */
    export function randomBytes(length: number): ArrayBuffer;

    /**
     * Fill an existing buffer with cryptographically secure random bytes
     * @param buffer - Target buffer or view
     * @param offset - Byte offset within the target view
     * @param size - Number of bytes to fill
     * @returns The original target buffer or view
     */
    export function randomFill<T extends BufferSource>(buffer: T, offset?: number, size?: number): T;

    /**
     * Encode data to Base64 string
     * @param data - Input data
     * @returns Base64 encoded string
     */
    export function base64Encode(data: BufferSource): string;

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
    export function hexEncode(data: BufferSource): string;

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
    export function generateEcKeySecp256k1(): EcKeyPair;

    /** ECDSA sign with P-256 (uses SHA-256) */
    export function ecdsaSignP256(privateKey: BufferSource, data: BufferSource): ArrayBuffer;
    /** ECDSA sign with P-384 (uses SHA-384) */
    export function ecdsaSignP384(privateKey: BufferSource, data: BufferSource): ArrayBuffer;
    /** ECDSA sign with P-521 (uses SHA-512) */
    export function ecdsaSignP521(privateKey: BufferSource, data: BufferSource): ArrayBuffer;

    /** ECDSA verify with P-256 */
    export function ecdsaVerifyP256(publicKey: BufferSource, data: BufferSource, signature: BufferSource): boolean;
    /** ECDSA verify with P-384 */
    export function ecdsaVerifyP384(publicKey: BufferSource, data: BufferSource, signature: BufferSource): boolean;
    /** ECDSA verify with P-521 */
    export function ecdsaVerifyP521(publicKey: BufferSource, data: BufferSource, signature: BufferSource): boolean;

    /** ECDH derive shared secret with P-256 */
    export function ecdhDeriveP256(privateKey: BufferSource, publicKey: BufferSource): ArrayBuffer;
    /** ECDH derive shared secret with P-384 */
    export function ecdhDeriveP384(privateKey: BufferSource, publicKey: BufferSource): ArrayBuffer;
    /** ECDH derive shared secret with P-521 */
    export function ecdhDeriveP521(privateKey: BufferSource, publicKey: BufferSource): ArrayBuffer;
    export function ecdhDeriveSecp256k1(privateKey: BufferSource, publicKey: BufferSource): ArrayBuffer;

    /**
     * Key agreement over ENCODED keys, with the algorithm taken from the key
     * material: PKCS#8/SEC1/PEM private, SPKI/PEM public. Covers X25519, X448,
     * the named EC curves and DH -- the whole surface of node's
     * `crypto.diffieHellman()`. Raw EC bytes are also accepted.
     */
    export function deriveSharedSecret(privateKey: BufferSource, publicKey: BufferSource): ArrayBuffer;

    export function ecPublicFromPrivateP256(privateKey: BufferSource, format?: number): ArrayBuffer;
    export function ecPublicFromPrivateP384(privateKey: BufferSource, format?: number): ArrayBuffer;
    export function ecPublicFromPrivateP521(privateKey: BufferSource, format?: number): ArrayBuffer;
    export function ecPublicFromPrivateSecp256k1(privateKey: BufferSource, format?: number): ArrayBuffer;

    export function ecConvertPublicP256(publicKey: BufferSource, format?: number): ArrayBuffer;
    export function ecConvertPublicP384(publicKey: BufferSource, format?: number): ArrayBuffer;
    export function ecConvertPublicP521(publicKey: BufferSource, format?: number): ArrayBuffer;
    export function ecConvertPublicSecp256k1(publicKey: BufferSource, format?: number): ArrayBuffer;

    // ============================================================================
    // RSA-OAEP - NEW
    // ============================================================================

    /** RSA-OAEP encrypt with SHA-256 */
    export function rsaOaepSha256Encrypt(publicKey: BufferSource, data: BufferSource, label?: BufferSource): ArrayBuffer;
    /** RSA-OAEP decrypt with SHA-256 */
    export function rsaOaepSha256Decrypt(privateKey: BufferSource, data: BufferSource, label?: BufferSource): ArrayBuffer;
    /** RSA-OAEP encrypt with SHA-512 */
    export function rsaOaepSha512Encrypt(publicKey: BufferSource, data: BufferSource, label?: BufferSource): ArrayBuffer;
    /** RSA-OAEP decrypt with SHA-512 */
    export function rsaOaepSha512Decrypt(privateKey: BufferSource, data: BufferSource, label?: BufferSource): ArrayBuffer;

    // ============================================================================
    // RSA-PSS - NEW
    // ============================================================================

    /** RSA-PSS sign with SHA-256 */
    export function rsaPssSha256Sign(privateKey: BufferSource, data: BufferSource, saltLength?: number): ArrayBuffer;
    /** RSA-PSS verify with SHA-256 */
    export function rsaPssSha256Verify(publicKey: BufferSource, data: BufferSource, signature: BufferSource, saltLength?: number): boolean;

    // ============================================================================
    // HKDF - NEW
    // ============================================================================

    /** HKDF key derivation with SHA-256 */
    export function hkdfSha256(ikm: BufferSource, keylen: number, salt?: BufferSource, info?: BufferSource): ArrayBuffer;
    /** HKDF key derivation with SHA-512 */
    export function hkdfSha512(ikm: BufferSource, keylen: number, salt?: BufferSource, info?: BufferSource): ArrayBuffer;

    // ============================================================================
    // GCM with AAD Support
    // ============================================================================

    /**
     * Result of GCM encryption
     */
    export interface GcmEncryptResult {
        /** Encrypted ciphertext */
        ciphertext: ArrayBuffer;
        /** Authentication tag (default 16 bytes) */
        tag: ArrayBuffer;
    }

    /**
     * Result of GCM decryption
     */
    export interface GcmDecryptResult {
        /** Decrypted plaintext */
        plaintext: ArrayBuffer;
        /** true if authentication tag is valid */
        verified: boolean;
    }

    /**
     * Encrypt data using AES-GCM with optional AAD (Additional Authenticated Data)
     *
     * @param key - Encryption key (16/24/32 bytes for AES-128/192/256)
     * @param iv - Initialization vector (recommended 12 bytes)
     * @param plaintext - Data to encrypt
     * @param aad - Optional additional authenticated data (authenticated but not encrypted)
     * @param tagLength - Optional authentication tag length in bytes (default: 16, range: 4-16)
     * @returns Object containing ciphertext and authentication tag
     *
     * @example
     * ```typescript
     * const crypto = import.meta.use('crypto');
     * const { Encoder } = import.meta.use('text');
     * const encoder = new Encoder();
     *
     * const key = crypto.randomBytes(32);  // AES-256
     * const iv = crypto.randomBytes(12);   // 12 bytes IV for GCM
     * const plaintext = encoder.encode('Hello, World!');
     * const aad = encoder.encode('Additional authenticated data');
     *
     * // Without AAD
     * const encrypted1 = crypto.gcmEncrypt(key, iv, plaintext);
     *
     * // With AAD
     * const encrypted2 = crypto.gcmEncrypt(key, iv, plaintext, aad);
     *
     * // With custom tag length
     * const encrypted3 = crypto.gcmEncrypt(key, iv, plaintext, aad, 12);
     * ```
     */
    export function gcmEncrypt(
        key: BufferSource,
        iv: BufferSource,
        plaintext: BufferSource,
        aad?: BufferSource,
        tagLength?: number
    ): GcmEncryptResult;

    /**
     * Decrypt data using AES-GCM with optional AAD (Additional Authenticated Data)
     *
     * @param key - Decryption key (16/24/32 bytes for AES-128/192/256)
     * @param iv - Initialization vector (must match encryption)
     * @param ciphertext - Encrypted data
     * @param tag - Authentication tag from encryption
     * @param aad - Optional additional authenticated data (must match encryption)
     * @returns Object containing plaintext and verification status
     *
     * @example
     * ```typescript
     * const crypto = import.meta.use('crypto');
     * const { Encoder, Decoder } = import.meta.use('text');
     * const encoder = new Encoder();
     * const decoder = new Decoder();
     *
     * const key = crypto.randomBytes(32);
     * const iv = crypto.randomBytes(12);
     * const plaintext = encoder.encode('Hello, World!');
     * const aad = encoder.encode('Additional authenticated data');
     *
     * // Encrypt
     * const encrypted = crypto.gcmEncrypt(key, iv, plaintext, aad);
     *
     * // Decrypt
     * const decrypted = crypto.gcmDecrypt(key, iv, encrypted.ciphertext, encrypted.tag, aad);
     *
     * if (decrypted.verified) {
     *     console.log('Decryption successful:', decoder.decode(decrypted.plaintext));
     * } else {
     *     console.log('Authentication failed!');
     * }
     * ```
     */
    export function gcmDecrypt(
        key: BufferSource,
        iv: BufferSource,
        ciphertext: BufferSource,
        tag: BufferSource,
        aad?: BufferSource
    ): GcmDecryptResult;

    /**
     * Streaming GCM cipher class
     *
     * @example
     * ```typescript
     * const crypto = import.meta.use('crypto');
     * const { Encoder } = import.meta.use('text');
     * const encoder = new Encoder();
     *
     * const key = crypto.randomBytes(32);
     * const iv = crypto.randomBytes(12);
     * const aad = encoder.encode('Additional authenticated data');
     *
     * // Encryption
     * const encryptor = new crypto.GCM('encrypt', key, iv);
     * encryptor.setAAD(aad);
     * const ciphertext1 = encryptor.update(encoder.encode('Hello '));
     * const ciphertext2 = encryptor.update(encoder.encode('World'));
     * const result = encryptor.final();
     * // result = { data: ArrayBuffer, tag: ArrayBuffer }
     *
     * // Decryption
     * const decryptor = new crypto.GCM('decrypt', key, iv);
     * decryptor.setAAD(aad);
     * const plaintext1 = decryptor.update(ciphertext1);
     * const plaintext2 = decryptor.update(ciphertext2);
     * const decryptResult = decryptor.final(result.tag);
     * // decryptResult = { data: ArrayBuffer, verified: boolean }
     * ```
     */
    export class GCM {
        /**
         * Create GCM cipher instance
         * @param mode - 'encrypt' or 'decrypt'
         * @param key - Encryption/decryption key (16/24/32 bytes for AES-128/192/256)
         * @param iv - Initialization vector (recommended 12 bytes)
         */
        constructor(mode: 'encrypt' | 'decrypt', key: BufferSource, iv: BufferSource);

        /**
         * Set Additional Authenticated Data (AAD)
         * Must be called before update() for the data to be authenticated
         * @param aad - Additional authenticated data
         * @returns true when OpenSSL accepted the AAD
         */
        setAAD(aad: BufferSource): boolean;

        /**
         * Process data (encrypt or decrypt)
         * @param data - Data to process
         * @returns Processed data
         */
        update(data: BufferSource): ArrayBuffer;

        /**
         * Finalize encryption or decryption
         *
         * For encryption: returns { data: ArrayBuffer, tag: ArrayBuffer }
         * For decryption: requires tag parameter, returns { data: ArrayBuffer, verified: boolean }
         *
         * @param tag - Authentication tag (required for decryption)
         * @returns Encryption result when called without a tag, decryption result when a tag is passed
         */
        final(): { data: ArrayBuffer; tag: ArrayBuffer };
        final(tag: BufferSource): { data: ArrayBuffer; verified: boolean };
    }
    
    /**
     * Generate a random RFC 4122 version 4 UUID string synchronously.
     */
    export function randomUUID(): `${string}-${string}-${string}-${string}-${string}`;
}
