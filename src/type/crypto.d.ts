/**
 * txiki.js crypto module type definitions
 * OpenSSL-based cryptographic operations
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
}

// ============================================================================
// Usage Examples
// ============================================================================

/**
 * Example: Hash data
 * ```typescript
 * import * as crypto from '@tjs/crypto';
 * 
 * const data = new TextEncoder().encode('hello world');
 * const hash = crypto.sha256(data);
 * const hex = crypto.hexEncode(hash);
 * console.log(hex); // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
 * ```
 */

/**
 * Example: Streaming hash
 * ```typescript
 * import * as crypto from '@tjs/crypto';
 * 
 * const hash = crypto.createSha256();
 * hash.update(new TextEncoder().encode('hello '));
 * hash.update(new TextEncoder().encode('world'));
 * const digest = hash.digest();
 * ```
 */

/**
 * Example: HMAC
 * ```typescript
 * import * as crypto from '@tjs/crypto';
 * 
 * const key = crypto.randomBytes(32);
 * const data = new TextEncoder().encode('message');
 * const hmac = crypto.hmacSha256(key, data);
 * ```
 */

/**
 * Example: AES encryption
 * ```typescript
 * import * as crypto from '@tjs/crypto';
 * 
 * const key = crypto.randomBytes(32);
 * const iv = crypto.randomBytes(16);
 * const plaintext = new TextEncoder().encode('secret message');
 * const ciphertext = crypto.aes256CbcEncrypt(key, iv, plaintext);
 * const decrypted = crypto.aes256CbcDecrypt(key, iv, ciphertext);
 * ```
 */

/**
 * Example: RSA signing
 * ```typescript
 * import * as crypto from '@tjs/crypto';
 * 
 * const keypair = crypto.generateRsaKey(2048);
 * const data = new TextEncoder().encode('document');
 * const signature = crypto.signSha256(keypair.privateKey, data);
 * const valid = crypto.verifySha256(keypair.publicKey, data, signature);
 * console.log(valid); // true
 * ```
 */

/**
 * Example: PBKDF2 key derivation
 * ```typescript
 * import * as crypto from '@tjs/crypto';
 * 
 * const password = new TextEncoder().encode('mypassword');
 * const salt = crypto.randomBytes(16);
 * const key = crypto.pbkdf2Sha256(password, salt, 100000, 32);
 * ```
 */