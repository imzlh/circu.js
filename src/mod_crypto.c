/*
 * circu.js
 * OpenSSL-style comprehensive cryptographic API
 *
 * Copyright (c) 2025 iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "private.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

/* Magic values for hash algorithms */
enum {
    HASH_MD5 = 0,
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,

	HASM_END
};

/* Magic values for cipher algorithms */
enum {
    CIPHER_AES_128_ECB = 0,
    CIPHER_AES_128_CBC,
    CIPHER_AES_128_CFB,
    CIPHER_AES_128_OFB,
    CIPHER_AES_128_CTR,
    CIPHER_AES_128_GCM,
    CIPHER_AES_192_ECB,
    CIPHER_AES_192_CBC,
    CIPHER_AES_192_CFB,
    CIPHER_AES_192_OFB,
    CIPHER_AES_192_CTR,
    CIPHER_AES_192_GCM,
    CIPHER_AES_256_ECB,
    CIPHER_AES_256_CBC,
    CIPHER_AES_256_CFB,
    CIPHER_AES_256_OFB,
    CIPHER_AES_256_CTR,
    CIPHER_AES_256_GCM,
    CIPHER_DES_ECB,
    CIPHER_DES_CBC,
    CIPHER_DES_EDE3,
    CIPHER_DES_EDE3_CBC,

	CIPHER_END
};

/* Get EVP_MD from magic value */
static const EVP_MD* get_md_from_magic(int magic) {
    switch (magic) {
        case HASH_MD5: return EVP_md5();
        case HASH_SHA1: return EVP_sha1();
        case HASH_SHA224: return EVP_sha224();
        case HASH_SHA256: return EVP_sha256();
        case HASH_SHA384: return EVP_sha384();
        case HASH_SHA512: return EVP_sha512();
        case HASH_SHA3_224: return EVP_sha3_224();
        case HASH_SHA3_256: return EVP_sha3_256();
        case HASH_SHA3_384: return EVP_sha3_384();
        case HASH_SHA3_512: return EVP_sha3_512();
        default: return NULL;
    }
}

/* Get EVP_CIPHER from magic value */
static const EVP_CIPHER* get_cipher_from_magic(int magic) {
    switch (magic) {
        case CIPHER_AES_128_ECB: return EVP_aes_128_ecb();
        case CIPHER_AES_128_CBC: return EVP_aes_128_cbc();
        case CIPHER_AES_128_CFB: return EVP_aes_128_cfb();
        case CIPHER_AES_128_OFB: return EVP_aes_128_ofb();
        case CIPHER_AES_128_CTR: return EVP_aes_128_ctr();
        case CIPHER_AES_128_GCM: return EVP_aes_128_gcm();
        case CIPHER_AES_192_ECB: return EVP_aes_192_ecb();
        case CIPHER_AES_192_CBC: return EVP_aes_192_cbc();
        case CIPHER_AES_192_CFB: return EVP_aes_192_cfb();
        case CIPHER_AES_192_OFB: return EVP_aes_192_ofb();
        case CIPHER_AES_192_CTR: return EVP_aes_192_ctr();
        case CIPHER_AES_192_GCM: return EVP_aes_192_gcm();
        case CIPHER_AES_256_ECB: return EVP_aes_256_ecb();
        case CIPHER_AES_256_CBC: return EVP_aes_256_cbc();
        case CIPHER_AES_256_CFB: return EVP_aes_256_cfb();
        case CIPHER_AES_256_OFB: return EVP_aes_256_ofb();
        case CIPHER_AES_256_CTR: return EVP_aes_256_ctr();
        case CIPHER_AES_256_GCM: return EVP_aes_256_gcm();
        case CIPHER_DES_ECB: return EVP_des_ecb();
        case CIPHER_DES_CBC: return EVP_des_cbc();
        case CIPHER_DES_EDE3: return EVP_des_ede3();
        case CIPHER_DES_EDE3_CBC: return EVP_des_ede3_cbc();
        default: return NULL;
    }
}

/* Generic hash function using magic */
static JSValue tjs_crypto_hash(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t data_len;
    const uint8_t* data;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "hash() requires 1 argument: data");
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid hash algorithm");
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return JS_ThrowInternalError(ctx, "Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return JS_ThrowInternalError(ctx, "Hash computation failed");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    return JS_NewArrayBufferCopy(ctx, hash, hash_len);
}

/* HMAC function using magic */
static JSValue tjs_crypto_hmac(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len;
    const uint8_t *key, *data;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "hmac() requires 2 arguments: key and data");
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid HMAC algorithm");
    }
    
    key = JS_GetArrayBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    
    if (!HMAC(md, key, key_len, data, data_len, hmac, &hmac_len)) {
        return JS_ThrowInternalError(ctx, "HMAC computation failed");
    }
    
    return JS_NewArrayBufferCopy(ctx, hmac, hmac_len);
}

/* CRC32 implementation */
static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

static void init_crc32_table(void) {
    if (crc32_table_initialized) return;
    
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_initialized = 1;
}

static JSValue tjs_crypto_crc32(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t data_len;
    const uint8_t* data;
    uint32_t crc = 0xFFFFFFFF;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "crc32() requires 1 argument: data");
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    init_crc32_table();
    
    for (size_t i = 0; i < data_len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    
    crc ^= 0xFFFFFFFF;
    
    return JS_NewUint32(ctx, crc);
}

/* Random bytes generation */
static JSValue tjs_crypto_random_bytes(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t length;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "randomBytes() requires 1 argument: length");
    }
    
    if (JS_ToInt32(ctx, &length, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (length < 0 || length > 65536) {
        return JS_ThrowRangeError(ctx, "Length must be between 0 and 65536");
    }
    
    uint8_t* buf = js_malloc(ctx, length);
    if (!buf) {
        return JS_EXCEPTION;
    }
    
    if (RAND_bytes(buf, length) != 1) {
        js_free(ctx, buf);
        return JS_ThrowInternalError(ctx, "Failed to generate random bytes");
    }
    
    JSValue result = JS_NewArrayBufferCopy(ctx, buf, length);
    js_free(ctx, buf);
    
    return result;
}

/* Cipher encryption/decryption using magic */
static JSValue tjs_crypto_cipher(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, iv_len = 0, data_len;
    const uint8_t *key, *iv = NULL, *data;
    int encrypt = (magic >> 16) & 1;  // High bit indicates encrypt/decrypt
    int cipher_magic = magic & 0xFFFF;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "cipher() requires at least 2 arguments: key and data");
    }
    
    const EVP_CIPHER* cipher = get_cipher_from_magic(cipher_magic);
    if (!cipher) {
        return JS_ThrowInternalError(ctx, "Invalid cipher algorithm");
    }
    
    key = JS_GetArrayBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    // IV is optional for some modes
    if (argc >= 3 && !JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        iv = JS_GetArrayBuffer(ctx, &iv_len, argv[1]);
        if (!iv) {
            return JS_EXCEPTION;
        }
        data = JS_GetArrayBuffer(ctx, &data_len, argv[2]);
    } else {
        data = JS_GetArrayBuffer(ctx, &data_len, argv[1]);
    }
    
    if (!data) {
        return JS_EXCEPTION;
    }
    
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) {
        return JS_ThrowInternalError(ctx, "Failed to create cipher context");
    }
    
    int out_len = data_len + EVP_CIPHER_block_size(cipher);
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        EVP_CIPHER_CTX_free(cctx);
        return JS_EXCEPTION;
    }
    
    int len, final_len;
    
    if (EVP_CipherInit_ex(cctx, cipher, NULL, key, iv, encrypt) != 1 ||
        EVP_CipherUpdate(cctx, out, &len, data, data_len) != 1 ||
        EVP_CipherFinal_ex(cctx, out + len, &final_len) != 1) {
        js_free(ctx, out);
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "Cipher operation failed");
    }
    
    EVP_CIPHER_CTX_free(cctx);
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, len + final_len);
    js_free(ctx, out);
    
    return result;
}

/* PBKDF2 key derivation */
static JSValue tjs_crypto_pbkdf2(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t password_len, salt_len;
    const uint8_t *password, *salt;
    int32_t iterations, keylen;
    
    if (argc < 4) {
        return JS_ThrowTypeError(ctx, "pbkdf2() requires 4 arguments: password, salt, iterations, keylen");
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid hash algorithm");
    }
    
    password = JS_GetArrayBuffer(ctx, &password_len, argv[0]);
    if (!password) {
        return JS_EXCEPTION;
    }
    
    salt = JS_GetArrayBuffer(ctx, &salt_len, argv[1]);
    if (!salt) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &iterations, argv[2]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &keylen, argv[3]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (iterations < 1 || keylen < 1 || keylen > 65536) {
        return JS_ThrowRangeError(ctx, "Invalid iterations or keylen");
    }
    
    uint8_t* key = js_malloc(ctx, keylen);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    if (PKCS5_PBKDF2_HMAC((const char*)password, password_len, salt, salt_len, 
                          iterations, md, keylen, key) != 1) {
        js_free(ctx, key);
        return JS_ThrowInternalError(ctx, "PBKDF2 failed");
    }
    
    JSValue result = JS_NewArrayBufferCopy(ctx, key, keylen);
    js_free(ctx, key);
    
    return result;
}

/* RSA key generation */
static JSValue tjs_crypto_generate_rsa_key(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int32_t bits = 2048;
    
    if (argc >= 1) {
        if (JS_ToInt32(ctx, &bits, argv[0]) < 0) {
            return JS_EXCEPTION;
        }
    }
    
    if (bits < 512 || bits > 8192) {
        return JS_ThrowRangeError(ctx, "Key size must be between 512 and 8192");
    }
    
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!pkey || !pctx) {
        if (pkey) EVP_PKEY_free(pkey);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        return JS_ThrowInternalError(ctx, "Failed to create RSA context");
    }
    
    if (EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) != 1 ||
        EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return JS_ThrowInternalError(ctx, "RSA key generation failed");
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    BIO* bio_pub = BIO_new(BIO_s_mem());
    BIO* bio_priv = BIO_new(BIO_s_mem());
    
    PEM_write_bio_PUBKEY(bio_pub, pkey);
    PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL);
    
    char* pub_data;
    char* priv_data;
    long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
    long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
    
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "publicKey", JS_NewArrayBufferCopy(ctx, (uint8_t*)pub_data, pub_len));
    JS_SetPropertyStr(ctx, result, "privateKey", JS_NewArrayBufferCopy(ctx, (uint8_t*)priv_data, priv_len));
    
    BIO_free(bio_pub);
    BIO_free(bio_priv);
    EVP_PKEY_free(pkey);
    
    return result;
}

/* Sign data with RSA private key */
static JSValue tjs_crypto_sign(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len;
    const uint8_t *key_data, *data;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "sign() requires 2 arguments: privateKey and data");
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid hash algorithm");
    }
    
    key_data = JS_GetArrayBuffer(ctx, &key_len, argv[0]);
    if (!key_data) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return JS_ThrowInternalError(ctx, "Failed to parse private key");
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    size_t sig_len;
    
    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) != 1 ||
        EVP_DigestSignUpdate(mdctx, data, data_len) != 1 ||
        EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Signature failed");
    }
    
    uint8_t* sig = js_malloc(ctx, sig_len);
    if (!sig) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return JS_EXCEPTION;
    }
    
    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) != 1) {
        js_free(ctx, sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Signature failed");
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    JSValue result = JS_NewArrayBufferCopy(ctx, sig, sig_len);
    js_free(ctx, sig);
    
    return result;
}

/* Verify signature with RSA public key */
static JSValue tjs_crypto_verify(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len, sig_len;
    const uint8_t *key_data, *data, *sig;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "verify() requires 3 arguments: publicKey, data, and signature");
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid hash algorithm");
    }
    
    key_data = JS_GetArrayBuffer(ctx, &key_len, argv[0]);
    if (!key_data) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    sig = JS_GetArrayBuffer(ctx, &sig_len, argv[2]);
    if (!sig) {
        return JS_EXCEPTION;
    }
    
    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return JS_ThrowInternalError(ctx, "Failed to parse public key");
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    int result = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(mdctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(mdctx, sig, sig_len) == 1) {
        result = 1;
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return JS_NewBool(ctx, result);
}

/* Class IDs */
static JSClassID tjs_hash_class_id;
static JSClassID tjs_hmac_class_id;
static JSClassID tjs_cipher_class_id;

/* Hash object for streaming */
typedef struct {
    EVP_MD_CTX* ctx;
    const EVP_MD* md;
} TJSHash;

static void tjs_hash_finalizer(JSRuntime* rt, JSValue val) {
    TJSHash* h = JS_GetOpaque(val, tjs_hash_class_id);
    if (h) {
        if (h->ctx) {
            EVP_MD_CTX_free(h->ctx);
        }
        js_free_rt(rt, h);
    }
}

static JSClassDef tjs_hash_class = {
    "Hash",
    .finalizer = tjs_hash_finalizer,
};

/* Create hash object */
static JSValue tjs_crypto_create_hash(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid hash algorithm");
    }
    
    TJSHash* h = js_mallocz(ctx, sizeof(*h));
    if (!h) {
        return JS_EXCEPTION;
    }
    
    h->md = md;
    h->ctx = EVP_MD_CTX_new();
    if (!h->ctx || EVP_DigestInit_ex(h->ctx, md, NULL) != 1) {
        if (h->ctx) EVP_MD_CTX_free(h->ctx);
        js_free(ctx, h);
        return JS_ThrowInternalError(ctx, "Failed to initialize hash");
    }
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_hash_class_id);
    if (JS_IsException(obj)) {
        EVP_MD_CTX_free(h->ctx);
        js_free(ctx, h);
        return obj;
    }
    
    JS_SetOpaque(obj, h);
    return obj;
}

/* Hash.update() */
static JSValue tjs_hash_update(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSHash* h = JS_GetOpaque2(ctx, this_val, tjs_hash_class_id);
    if (!h) {
        return JS_EXCEPTION;
    }
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "update() requires 1 argument: data");
    }
    
    size_t data_len;
    const uint8_t* data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    if (EVP_DigestUpdate(h->ctx, data, data_len) != 1) {
        return JS_ThrowInternalError(ctx, "Hash update failed");
    }
    
    return JS_DupValue(ctx, this_val);
}

/* Hash.digest() */
static JSValue tjs_hash_digest(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSHash* h = JS_GetOpaque2(ctx, this_val, tjs_hash_class_id);
    if (!h) {
        return JS_EXCEPTION;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    if (EVP_DigestFinal_ex(h->ctx, hash, &hash_len) != 1) {
        return JS_ThrowInternalError(ctx, "Hash finalization failed");
    }
    
    // Reinitialize for potential reuse
    EVP_DigestInit_ex(h->ctx, h->md, NULL);
    
    return JS_NewArrayBufferCopy(ctx, hash, hash_len);
}

static const JSCFunctionListEntry tjs_hash_proto_funcs[] = {
    JS_CFUNC_DEF("update", 1, tjs_hash_update),
    JS_CFUNC_DEF("digest", 0, tjs_hash_digest),
};

/* HMAC object for streaming */
typedef struct {
    EVP_MD_CTX* ctx;
    EVP_PKEY* pkey;
    const EVP_MD* md;
} TJSHMAC;

static void tjs_hmac_finalizer(JSRuntime* rt, JSValue val) {
    TJSHMAC* h = JS_GetOpaque(val, tjs_hmac_class_id);
    if (h) {
        if (h->ctx) EVP_MD_CTX_free(h->ctx);
        if (h->pkey) EVP_PKEY_free(h->pkey);
        js_free_rt(rt, h);
    }
}

static JSClassDef tjs_hmac_class = {
    "Hmac",
    .finalizer = tjs_hmac_finalizer,
};

/* Create HMAC object */
static JSValue tjs_crypto_create_hmac(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len;
    const uint8_t* key;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "createHmac() requires 1 argument: key");
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid HMAC algorithm");
    }
    
    key = JS_GetArrayBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    TJSHMAC* h = js_mallocz(ctx, sizeof(*h));
    if (!h) {
        return JS_EXCEPTION;
    }
    
    h->md = md;
    h->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
    h->ctx = EVP_MD_CTX_new();
    
    if (!h->pkey || !h->ctx || EVP_DigestSignInit(h->ctx, NULL, md, NULL, h->pkey) != 1) {
        if (h->ctx) EVP_MD_CTX_free(h->ctx);
        if (h->pkey) EVP_PKEY_free(h->pkey);
        js_free(ctx, h);
        return JS_ThrowInternalError(ctx, "Failed to initialize HMAC");
    }
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_hmac_class_id);
    if (JS_IsException(obj)) {
        EVP_MD_CTX_free(h->ctx);
        EVP_PKEY_free(h->pkey);
        js_free(ctx, h);
        return obj;
    }
    
    JS_SetOpaque(obj, h);
    return obj;
}

/* Hmac.update() */
static JSValue tjs_hmac_update(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSHMAC* h = JS_GetOpaque2(ctx, this_val, tjs_hmac_class_id);
    if (!h) {
        return JS_EXCEPTION;
    }
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "update() requires 1 argument: data");
    }
    
    size_t data_len;
    const uint8_t* data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    if (EVP_DigestSignUpdate(h->ctx, data, data_len) != 1) {
        return JS_ThrowInternalError(ctx, "HMAC update failed");
    }
    
    return JS_DupValue(ctx, this_val);
}

/* Hmac.digest() */
static JSValue tjs_hmac_digest(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSHMAC* h = JS_GetOpaque2(ctx, this_val, tjs_hmac_class_id);
    if (!h) {
        return JS_EXCEPTION;
    }
    
    size_t hmac_len;
    if (EVP_DigestSignFinal(h->ctx, NULL, &hmac_len) != 1) {
        return JS_ThrowInternalError(ctx, "HMAC finalization failed");
    }
    
    uint8_t* hmac = js_malloc(ctx, hmac_len);
    if (!hmac) {
        return JS_EXCEPTION;
    }
    
    if (EVP_DigestSignFinal(h->ctx, hmac, &hmac_len) != 1) {
        js_free(ctx, hmac);
        return JS_ThrowInternalError(ctx, "HMAC finalization failed");
    }
    
    // Reinitialize for potential reuse
    EVP_DigestSignInit(h->ctx, NULL, h->md, NULL, h->pkey);
    
    JSValue result = JS_NewArrayBufferCopy(ctx, hmac, hmac_len);
    js_free(ctx, hmac);
    
    return result;
}

static const JSCFunctionListEntry tjs_hmac_proto_funcs[] = {
    JS_CFUNC_DEF("update", 1, tjs_hmac_update),
    JS_CFUNC_DEF("digest", 0, tjs_hmac_digest),
};

/* Cipher object for streaming */
typedef struct {
    EVP_CIPHER_CTX* ctx;
    int initialized;
} TJSCipher;

static void tjs_cipher_finalizer(JSRuntime* rt, JSValue val) {
    TJSCipher* c = JS_GetOpaque(val, tjs_cipher_class_id);
    if (c) {
        if (c->ctx) EVP_CIPHER_CTX_free(c->ctx);
        js_free_rt(rt, c);
    }
}

static JSClassDef tjs_cipher_class = {
    "Cipher",
    .finalizer = tjs_cipher_finalizer,
};

/* Create cipher object */
static JSValue tjs_crypto_create_cipher(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, iv_len = 0;
    const uint8_t *key, *iv = NULL;
    int encrypt = (magic >> 16) & 1;
    int cipher_magic = magic & 0xFFFF;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "createCipher() requires at least 1 argument: key");
    }
    
    const EVP_CIPHER* cipher = get_cipher_from_magic(cipher_magic);
    if (!cipher) {
        return JS_ThrowInternalError(ctx, "Invalid cipher algorithm");
    }
    
    key = JS_GetArrayBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 2 && !JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        iv = JS_GetArrayBuffer(ctx, &iv_len, argv[1]);
        if (!iv) {
            return JS_EXCEPTION;
        }
    }
    
    TJSCipher* c = js_mallocz(ctx, sizeof(*c));
    if (!c) {
        return JS_EXCEPTION;
    }
    
    c->ctx = EVP_CIPHER_CTX_new();
    if (!c->ctx || EVP_CipherInit_ex(c->ctx, cipher, NULL, key, iv, encrypt) != 1) {
        if (c->ctx) EVP_CIPHER_CTX_free(c->ctx);
        js_free(ctx, c);
        return JS_ThrowInternalError(ctx, "Failed to initialize cipher");
    }
    
    c->initialized = 1;
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_cipher_class_id);
    if (JS_IsException(obj)) {
        EVP_CIPHER_CTX_free(c->ctx);
        js_free(ctx, c);
        return obj;
    }
    
    JS_SetOpaque(obj, c);
    return obj;
}

/* Cipher.update() */
static JSValue tjs_cipher_update(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSCipher* c = JS_GetOpaque2(ctx, this_val, tjs_cipher_class_id);
    if (!c) {
        return JS_EXCEPTION;
    }
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "update() requires 1 argument: data");
    }
    
    size_t data_len;
    const uint8_t* data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    int out_len = data_len + EVP_CIPHER_CTX_block_size(c->ctx);
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    if (EVP_CipherUpdate(c->ctx, out, &out_len, data, data_len) != 1) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Cipher update failed");
    }
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, out_len);
    js_free(ctx, out);
    
    return result;
}

/* Cipher.final() */
static JSValue tjs_cipher_final(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    TJSCipher* c = JS_GetOpaque2(ctx, this_val, tjs_cipher_class_id);
    if (!c) {
        return JS_EXCEPTION;
    }
    
    int out_len = EVP_CIPHER_CTX_block_size(c->ctx);
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    if (EVP_CipherFinal_ex(c->ctx, out, &out_len) != 1) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Cipher finalization failed");
    }
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, out_len);
    js_free(ctx, out);
    
    return result;
}

static const JSCFunctionListEntry tjs_cipher_proto_funcs[] = {
    JS_CFUNC_DEF("update", 1, tjs_cipher_update),
    JS_CFUNC_DEF("final", 0, tjs_cipher_final),
};

/* Base64 encoding/decoding */
static JSValue tjs_crypto_base64_encode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t data_len;
    const uint8_t* data;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "base64Encode() requires 1 argument: data");
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    int out_len = ((data_len + 2) / 3) * 4;
    char* out = js_malloc(ctx, out_len + 1);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    EVP_EncodeBlock((uint8_t*)out, data, data_len);
    out[out_len] = '\0';
    
    JSValue result = JS_NewStringLen(ctx, out, out_len);
    js_free(ctx, out);
    
    return result;
}

static JSValue tjs_crypto_base64_decode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* str;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "base64Decode() requires 1 argument: string");
    }
    
    str = JS_ToCString(ctx, argv[0]);
    if (!str) {
        return JS_EXCEPTION;
    }
    
    size_t str_len = strlen(str);
    int out_len = (str_len / 4) * 3;
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    int decoded = EVP_DecodeBlock(out, (const uint8_t*)str, str_len);
    JS_FreeCString(ctx, str);
    
    if (decoded < 0) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Base64 decode failed");
    }
    
    // Remove padding
    if (str_len >= 2 && str[str_len - 1] == '=') {
        decoded--;
        if (str[str_len - 2] == '=') {
            decoded--;
        }
    }
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, decoded);
    js_free(ctx, out);
    
    return result;
}

/* Hex encoding/decoding */
static JSValue tjs_crypto_hex_encode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t data_len;
    const uint8_t* data;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "hexEncode() requires 1 argument: data");
    }
    
    data = JS_GetArrayBuffer(ctx, &data_len, argv[0]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    char* out = js_malloc(ctx, data_len * 2 + 1);
    if (!out) {
        return JS_EXCEPTION;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[data_len * 2] = '\0';
    
    JSValue result = JS_NewString(ctx, out);
    js_free(ctx, out);
    
    return result;
}

static JSValue tjs_crypto_hex_decode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    const char* str;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "hexDecode() requires 1 argument: string");
    }
    
    str = JS_ToCString(ctx, argv[0]);
    if (!str) {
        return JS_EXCEPTION;
    }
    
    size_t str_len = strlen(str);
    if (str_len % 2 != 0) {
        JS_FreeCString(ctx, str);
        return JS_ThrowTypeError(ctx, "Hex string must have even length");
    }
    
    size_t out_len = str_len / 2;
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    for (size_t i = 0; i < out_len; i++) {
        char byte[3] = {str[i * 2], str[i * 2 + 1], '\0'};
        out[i] = (uint8_t)strtol(byte, NULL, 16);
    }
    
    JS_FreeCString(ctx, str);
    
    JSValue result = JS_NewArrayBufferCopy(ctx, out, out_len);
    js_free(ctx, out);
    
    return result;
}

/* Module function list with magic values */
static const JSCFunctionListEntry tjs_crypto_funcs[] = {
    /* Hash functions */
    JS_CFUNC_MAGIC_DEF("md5", 1, tjs_crypto_hash, HASH_MD5),
    JS_CFUNC_MAGIC_DEF("sha1", 1, tjs_crypto_hash, HASH_SHA1),
    JS_CFUNC_MAGIC_DEF("sha224", 1, tjs_crypto_hash, HASH_SHA224),
    JS_CFUNC_MAGIC_DEF("sha256", 1, tjs_crypto_hash, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("sha384", 1, tjs_crypto_hash, HASH_SHA384),
    JS_CFUNC_MAGIC_DEF("sha512", 1, tjs_crypto_hash, HASH_SHA512),
    JS_CFUNC_MAGIC_DEF("sha3_224", 1, tjs_crypto_hash, HASH_SHA3_224),
    JS_CFUNC_MAGIC_DEF("sha3_256", 1, tjs_crypto_hash, HASH_SHA3_256),
    JS_CFUNC_MAGIC_DEF("sha3_384", 1, tjs_crypto_hash, HASH_SHA3_384),
    JS_CFUNC_MAGIC_DEF("sha3_512", 1, tjs_crypto_hash, HASH_SHA3_512),
    
    /* HMAC functions */
    JS_CFUNC_MAGIC_DEF("hmacMd5", 2, tjs_crypto_hmac, HASH_MD5),
    JS_CFUNC_MAGIC_DEF("hmacSha1", 2, tjs_crypto_hmac, HASH_SHA1),
    JS_CFUNC_MAGIC_DEF("hmacSha256", 2, tjs_crypto_hmac, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("hmacSha512", 2, tjs_crypto_hmac, HASH_SHA512),
    
    /* Streaming hash */
    JS_CFUNC_MAGIC_DEF("createMd5", 0, tjs_crypto_create_hash, HASH_MD5),
    JS_CFUNC_MAGIC_DEF("createSha1", 0, tjs_crypto_create_hash, HASH_SHA1),
    JS_CFUNC_MAGIC_DEF("createSha256", 0, tjs_crypto_create_hash, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("createSha512", 0, tjs_crypto_create_hash, HASH_SHA512),
    
    /* Streaming HMAC */
    JS_CFUNC_MAGIC_DEF("createHmacSha256", 1, tjs_crypto_create_hmac, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("createHmacSha512", 1, tjs_crypto_create_hmac, HASH_SHA512),
    
    /* Cipher functions - encrypt (high bit set) */
    JS_CFUNC_MAGIC_DEF("aes128CbcEncrypt", 3, tjs_crypto_cipher, (1 << 16) | CIPHER_AES_128_CBC),
    JS_CFUNC_MAGIC_DEF("aes256CbcEncrypt", 3, tjs_crypto_cipher, (1 << 16) | CIPHER_AES_256_CBC),
    JS_CFUNC_MAGIC_DEF("aes128GcmEncrypt", 3, tjs_crypto_cipher, (1 << 16) | CIPHER_AES_128_GCM),
    JS_CFUNC_MAGIC_DEF("aes256GcmEncrypt", 3, tjs_crypto_cipher, (1 << 16) | CIPHER_AES_256_GCM),
    
    /* Cipher functions - decrypt */
    JS_CFUNC_MAGIC_DEF("aes128CbcDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_128_CBC),
    JS_CFUNC_MAGIC_DEF("aes256CbcDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_256_CBC),
    JS_CFUNC_MAGIC_DEF("aes128GcmDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_128_GCM),
    JS_CFUNC_MAGIC_DEF("aes256GcmDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_256_GCM),
    
    /* Streaming cipher */
    JS_CFUNC_MAGIC_DEF("createCipherAes256Cbc", 2, tjs_crypto_create_cipher, (1 << 16) | CIPHER_AES_256_CBC),
    JS_CFUNC_MAGIC_DEF("createDecipherAes256Cbc", 2, tjs_crypto_create_cipher, CIPHER_AES_256_CBC),
    
    /* PBKDF2 */
    JS_CFUNC_MAGIC_DEF("pbkdf2Sha256", 4, tjs_crypto_pbkdf2, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("pbkdf2Sha512", 4, tjs_crypto_pbkdf2, HASH_SHA512),
    
    /* RSA */
    JS_CFUNC_DEF("generateRsaKey", 1, tjs_crypto_generate_rsa_key),
    JS_CFUNC_MAGIC_DEF("signSha256", 2, tjs_crypto_sign, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("signSha512", 2, tjs_crypto_sign, HASH_SHA512),
    JS_CFUNC_MAGIC_DEF("verifySha256", 3, tjs_crypto_verify, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("verifySha512", 3, tjs_crypto_verify, HASH_SHA512),
    
    /* Utility functions */
    JS_CFUNC_DEF("crc32", 1, tjs_crypto_crc32),
    JS_CFUNC_DEF("randomBytes", 1, tjs_crypto_random_bytes),
    JS_CFUNC_DEF("base64Encode", 1, tjs_crypto_base64_encode),
    JS_CFUNC_DEF("base64Decode", 1, tjs_crypto_base64_decode),
    JS_CFUNC_DEF("hexEncode", 1, tjs_crypto_hex_encode),
    JS_CFUNC_DEF("hexDecode", 1, tjs_crypto_hex_decode),
};

void tjs__mod_crypto_init(JSContext* ctx, JSValue ns) {
	JSRuntime* rt = JS_GetRuntime(ctx);

    /* Initialize Hash class */
    JS_NewClassID(rt, &tjs_hash_class_id);
    JS_NewClass(rt, tjs_hash_class_id, &tjs_hash_class);
    JSValue hash_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, hash_proto, tjs_hash_proto_funcs, countof(tjs_hash_proto_funcs));
    JS_SetClassProto(ctx, tjs_hash_class_id, hash_proto);
    
    /* Initialize HMAC class */
    JS_NewClassID(rt, &tjs_hmac_class_id);
    JS_NewClass(rt, tjs_hmac_class_id, &tjs_hmac_class);
    JSValue hmac_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, hmac_proto, tjs_hmac_proto_funcs, countof(tjs_hmac_proto_funcs));
    JS_SetClassProto(ctx, tjs_hmac_class_id, hmac_proto);
    
    /* Initialize Cipher class */
    JS_NewClassID(rt, &tjs_cipher_class_id);
    JS_NewClass(rt, tjs_cipher_class_id, &tjs_cipher_class);
    JSValue cipher_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, cipher_proto, tjs_cipher_proto_funcs, countof(tjs_cipher_proto_funcs));
    JS_SetClassProto(ctx, tjs_cipher_class_id, cipher_proto);
    
    /* Set crypto functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_crypto_funcs, countof(tjs_crypto_funcs));
}