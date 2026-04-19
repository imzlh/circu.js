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
#include <openssl/kdf.h>

/* OpenSSL 3.x has many deprecated functions, we ignore them for now */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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

/* Magic values for ECC curves */
enum {
    ECC_CURVE_P256 = 0,
    ECC_CURVE_P384,
    ECC_CURVE_P521,
    ECC_END
};

/* Get EC_GROUP from magic */
static const EC_GROUP* get_ec_group_from_magic(int magic) {
    switch (magic) {
        case ECC_CURVE_P256: return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        case ECC_CURVE_P384: return EC_GROUP_new_by_curve_name(NID_secp384r1);
        case ECC_CURVE_P521: return EC_GROUP_new_by_curve_name(NID_secp521r1);
        default: return NULL;
    }
}

/* Helper: free js_malloc allocated memory */
static void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr){
	js_free_rt(rt, ptr);
}
#define js_fastab(ctx, buf, len) JS_NewArrayBuffer(ctx, buf, len, free_js_malloc, NULL, false)

/* Generate ECC key pair */
/* Generate ECC key pair */
static JSValue tjs_crypto_generate_ec_key(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    EC_GROUP* group = (EC_GROUP*)get_ec_group_from_magic(magic);
    if (!group) {
        return JS_ThrowInternalError(ctx, "Invalid ECC curve");
    }
    
    EC_KEY* eckey = EC_KEY_new();
    if (!eckey) {
        EC_GROUP_free(group);
        return JS_ThrowInternalError(ctx, "EC_KEY allocation failed");
    }
    
    if (EC_KEY_set_group(eckey, group) != 1) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        return JS_ThrowInternalError(ctx, "EC_KEY_set_group failed");
    }
    
    if (EC_KEY_generate_key(eckey) != 1) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        return JS_ThrowInternalError(ctx, "ECC key generation failed");
    }
    
    const BIGNUM* priv_bn = EC_KEY_get0_private_key(eckey);
    const EC_POINT* pub_point = EC_KEY_get0_public_key(eckey);
    
    if (!priv_bn || !pub_point) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        return JS_ThrowInternalError(ctx, "Failed to get key components");
    }
    
    size_t priv_len = BN_num_bytes(priv_bn);
    size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    
    if (pub_len == 0) {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        return JS_ThrowInternalError(ctx, "Failed to get public key length");
    }
    
    uint8_t* priv_buf = js_malloc(ctx, priv_len);
    uint8_t* pub_buf = js_malloc(ctx, pub_len);
    
    if (!priv_buf || !pub_buf) {
        js_free(ctx, priv_buf);
        js_free(ctx, pub_buf);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
        return JS_EXCEPTION;
    }
    
    BN_bn2bin(priv_bn, priv_buf);
    EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_buf, pub_len, NULL);
    
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "publicKey", js_fastab(ctx, pub_buf, pub_len));
    JS_SetPropertyStr(ctx, result, "privateKey", js_fastab(ctx, priv_buf, priv_len));
    
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    
    return result;
}

/* ECDSA Sign */
static JSValue tjs_crypto_ecdsa_sign(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len;
    const uint8_t *key_data, *data;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "ecdsaSign() requires 2 arguments: privateKey and data");
    }
    
    // Determine curve and hash algorithm based on magic value
    int nid;
    const EVP_MD* md;
    
    if (magic == HASH_SHA256) {
        nid = NID_X9_62_prime256v1;  // P-256
        md = EVP_sha256();
    } else if (magic == HASH_SHA384) {
        nid = NID_secp384r1;  // P-384
        md = EVP_sha384();
    } else if (magic == HASH_SHA512) {
        nid = NID_secp521r1;  // P-521
        md = EVP_sha512();
    } else {
        return JS_ThrowInternalError(ctx, "Invalid ECDSA sign algorithm");
    }
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    if (!key_data || key_len == 0) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    // Import private key
    EC_KEY* eckey = EC_KEY_new_by_curve_name(nid);
    if (!eckey) {
        return JS_ThrowInternalError(ctx, "EC_KEY allocation failed");
    }
    
    BIGNUM* priv_bn = BN_bin2bn(key_data, key_len, NULL);
    if (!priv_bn) {
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Failed to convert private key");
    }
    
    if (EC_KEY_set_private_key(eckey, priv_bn) != 1) {
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Failed to set private key");
    }
    
    // Hash the data
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (!EVP_Digest(data, data_len, hash, &hash_len, md, NULL)) {
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Hash computation failed");
    }
    
    // Compute signature
    ECDSA_SIG* sig = ECDSA_do_sign(hash, hash_len, eckey);
    if (!sig) {
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "ECDSA sign failed");
    }
    
    // Serialize to DER
    int sig_len = i2d_ECDSA_SIG(sig, NULL);
    if (sig_len <= 0) {
        ECDSA_SIG_free(sig);
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Failed to encode signature");
    }
    
    uint8_t* sig_buf = js_malloc(ctx, sig_len);
    if (!sig_buf) {
        ECDSA_SIG_free(sig);
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return JS_EXCEPTION;
    }
    
    uint8_t* p = sig_buf;
    i2d_ECDSA_SIG(sig, &p);
    
    JSValue result = js_fastab(ctx, sig_buf, sig_len);
    
    ECDSA_SIG_free(sig);
    BN_free(priv_bn);
    EC_KEY_free(eckey);
    
    return result;
}

/* ECDSA Verify */
static JSValue tjs_crypto_ecdsa_verify(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t pub_len, data_len, sig_len;
    const uint8_t *pub_data, *data, *sig_data;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "ecdsaVerify() requires 3 arguments: publicKey, data, signature");
    }
    
    // Determine curve and hash algorithm based on magic value
    int nid;
    const EVP_MD* md;
    
    if (magic == ECC_CURVE_P256) {
        nid = NID_X9_62_prime256v1;  // P-256
        md = EVP_sha256();
    } else if (magic == ECC_CURVE_P384) {
        nid = NID_secp384r1;  // P-384
        md = EVP_sha384();
    } else if (magic == ECC_CURVE_P521) {
        nid = NID_secp521r1;  // P-521
        md = EVP_sha512();
    } else {
        return JS_ThrowInternalError(ctx, "Invalid ECDSA verify algorithm");
    }
    
    pub_data = JS_GetAnyBuffer(ctx, &pub_len, argv[0]);
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    sig_data = JS_GetAnyBuffer(ctx, &sig_len, argv[2]);
    
    if (!pub_data || !data || !sig_data) {
        return JS_EXCEPTION;
    }
    
    // Parse public key
    const EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        return JS_ThrowInternalError(ctx, "Failed to create EC_GROUP");
    }
    
    EC_KEY* eckey = EC_KEY_new();
    if (!eckey) {
        return JS_ThrowInternalError(ctx, "EC_KEY allocation failed");
    }
    
    if (EC_KEY_set_group(eckey, group) != 1) {
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "EC_KEY_set_group failed");
    }
    
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point) {
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "EC_POINT allocation failed");
    }
    
    if (EC_POINT_oct2point(group, pub_point, pub_data, pub_len, NULL) != 1) {
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Failed to parse public key");
    }
    
    if (EC_KEY_set_public_key(eckey, pub_point) != 1) {
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Failed to set public key");
    }
    
    // Hash the data
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (!EVP_Digest(data, data_len, hash, &hash_len, md, NULL)) {
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Hash computation failed");
    }
    
    // Parse signature
    const uint8_t* p = sig_data;
    ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &p, sig_len);
    if (!sig) {
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return JS_ThrowInternalError(ctx, "Failed to parse signature");
    }
    
    // Verify
    int verified = ECDSA_do_verify(hash, hash_len, sig, eckey);
    
    ECDSA_SIG_free(sig);
    EC_POINT_free(pub_point);
    EC_KEY_free(eckey);
    
    return JS_NewBool(ctx, verified == 1);
}

/* ECDH Derive Bits */
static JSValue tjs_crypto_ecdh_derive(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t priv_len, pub_len;
    const uint8_t *priv_data, *pub_data;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "ecdhDerive() requires 2 arguments: privateKey and publicKey");
    }
    
    priv_data = JS_GetAnyBuffer(ctx, &priv_len, argv[0]);
    pub_data = JS_GetAnyBuffer(ctx, &pub_len, argv[1]);
    
    if (!priv_data || !pub_data) {
        return JS_EXCEPTION;
    }
    
    // Determine curve NID
    int nid;
    if (magic == ECC_CURVE_P256) {
        nid = NID_X9_62_prime256v1;
    } else if (magic == ECC_CURVE_P384) {
        nid = NID_secp384r1;
    } else {
        nid = NID_secp521r1;
    }
    
    const EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        return JS_ThrowInternalError(ctx, "Failed to create EC_GROUP");
    }
    
    EC_KEY* priv_key = EC_KEY_new();
    if (!priv_key) {
        return JS_ThrowInternalError(ctx, "EC_KEY allocation failed");
    }
    
    if (EC_KEY_set_group(priv_key, group) != 1) {
        EC_KEY_free(priv_key);
        return JS_ThrowInternalError(ctx, "EC_KEY_set_group failed");
    }
    
    // Import private key
    BIGNUM* priv_bn = BN_bin2bn(priv_data, priv_len, NULL);
    if (!priv_bn) {
        EC_KEY_free(priv_key);
        return JS_ThrowInternalError(ctx, "Failed to convert private key");
    }
    
    if (EC_KEY_set_private_key(priv_key, priv_bn) != 1) {
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        return JS_ThrowInternalError(ctx, "Failed to set private key");
    }
    
    // Import public key
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point) {
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        return JS_ThrowInternalError(ctx, "EC_POINT allocation failed");
    }
    
    if (EC_POINT_oct2point(group, pub_point, pub_data, pub_len, NULL) != 1) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        return JS_ThrowInternalError(ctx, "Failed to parse public key");
    }
    
    // Compute shared secret
    size_t secret_len = (EC_GROUP_get_degree(group) + 7) / 8;
    uint8_t* secret = js_malloc(ctx, secret_len);
    if (!secret) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        return JS_EXCEPTION;
    }
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x: ECDH_compute_key is deprecated, use EVP_PKEY_derive
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_set1_EC_KEY(pkey, priv_key) != 1) {
        js_free(ctx, secret);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        if (pkey) EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Failed to create EVP_PKEY");
    }
    
    EC_KEY* peer_key = EC_KEY_new();
    if (!peer_key || EC_KEY_set_group(peer_key, group) != 1 || 
        EC_KEY_set_public_key(peer_key, pub_point) != 1) {
        EVP_PKEY_free(pkey);
        js_free(ctx, secret);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        if (peer_key) EC_KEY_free(peer_key);
        return JS_ThrowInternalError(ctx, "Failed to create peer key");
    }
    
    EVP_PKEY* peer_pkey = EVP_PKEY_new();
    if (!peer_pkey || EVP_PKEY_set1_EC_KEY(peer_pkey, peer_key) != 1) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(peer_key);
        js_free(ctx, secret);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        if (peer_pkey) EVP_PKEY_free(peer_pkey);
        return JS_ThrowInternalError(ctx, "Failed to create peer EVP_PKEY");
    }
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_derive_init(pctx) != 1 || 
        EVP_PKEY_derive_set_peer(pctx, peer_pkey) != 1) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        EC_KEY_free(peer_key);
        js_free(ctx, secret);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(priv_key);
        return JS_ThrowInternalError(ctx, "ECDH derive init failed");
    }
    
    size_t out_len = secret_len;
    int derived = EVP_PKEY_derive(pctx, secret, &out_len);
    
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(pkey);
    EC_KEY_free(peer_key);
#else
    // OpenSSL 1.x: Use ECDH_compute_key
    int derived = ECDH_compute_key(secret, secret_len, pub_point, priv_key, NULL);
    size_t out_len = (derived > 0) ? derived : 0;
#endif
    
    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_KEY_free(priv_key);
    
    if (derived <= 0 || out_len != secret_len) {
        js_free(ctx, secret);
        return JS_ThrowInternalError(ctx, "ECDH derivation failed");
    }
    
    JSValue result = js_fastab(ctx, secret, secret_len);
    return result;
}

/* RSA-OAEP encrypt */
static JSValue tjs_crypto_rsa_oaep_encrypt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len, label_len = 0;
    const uint8_t *key_data, *data, *label = NULL;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "rsaOaepEncrypt() requires 2 arguments: publicKey and data");
    }
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    
    if (!key_data || !data) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        label = JS_GetAnyBuffer(ctx, &label_len, argv[2]);
    }
    
    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return JS_ThrowInternalError(ctx, "Failed to parse public key");
    }
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) != 1) {
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Failed to init encrypt");
    }
    
    // Set OAEP padding and hash
    const EVP_MD* md = get_md_from_magic(magic);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(pctx, md);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md);
    
    if (label) {
        EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, (unsigned char*)label, label_len);
    }
    
    size_t out_len;
    if (EVP_PKEY_encrypt(pctx, NULL, &out_len, data, data_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Encrypt failed");
    }
    
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return JS_EXCEPTION;
    }
    
    int ret = EVP_PKEY_encrypt(pctx, out, &out_len, data, data_len);
    
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    if (ret != 1) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Encrypt failed");
    }
    
    JSValue result = js_fastab(ctx, out, out_len);
    return result;
}

/* RSA-OAEP decrypt */
static JSValue tjs_crypto_rsa_oaep_decrypt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len, label_len = 0;
    const uint8_t *key_data, *data, *label = NULL;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "rsaOaepDecrypt() requires 2 arguments: privateKey and data");
    }
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    
    if (!key_data || !data) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        label = JS_GetAnyBuffer(ctx, &label_len, argv[2]);
    }
    
    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return JS_ThrowInternalError(ctx, "Failed to parse private key");
    }
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_decrypt_init(pctx) != 1) {
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Failed to init decrypt");
    }
    
    // Set OAEP padding
    const EVP_MD* md = get_md_from_magic(magic);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(pctx, md);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md);
    
    if (label) {
        EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, (unsigned char*)label, label_len);
    }
    
    size_t out_len;
    if (EVP_PKEY_decrypt(pctx, NULL, &out_len, data, data_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Decrypt failed");
    }
    
    uint8_t* out = js_malloc(ctx, out_len);
    if (!out) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return JS_EXCEPTION;
    }
    
    int ret = EVP_PKEY_decrypt(pctx, out, &out_len, data, data_len);
    
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    if (ret != 1) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Decrypt failed");
    }
    
    JSValue result = js_fastab(ctx, out, out_len);
    return result;
}

/* RSA-PSS sign */
static JSValue tjs_crypto_rsa_pss_sign(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len;
    const uint8_t *key_data, *data;
    int32_t salt_len = -1; // auto
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "rsaPssSign() requires 2 arguments: privateKey and data");
    }
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    
    if (!key_data || !data) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        JS_ToInt32(ctx, &salt_len, argv[2]);
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    
    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return JS_ThrowInternalError(ctx, "Failed to parse private key");
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = NULL;
    
    if (EVP_DigestSignInit(mdctx, &pctx, md, NULL, pkey) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "PSS setup failed");
    }
    
    size_t sig_len;
    if (EVP_DigestSign(mdctx, NULL, &sig_len, data, data_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return JS_ThrowInternalError(ctx, "Sign failed");
    }
    
    uint8_t* sig = js_malloc(ctx, sig_len);
    if (!sig) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return JS_EXCEPTION;
    }
    
    int ret = EVP_DigestSign(mdctx, sig, &sig_len, data, data_len);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    if (ret != 1) {
        js_free(ctx, sig);
        return JS_ThrowInternalError(ctx, "Sign failed");
    }
    
    JSValue result = js_fastab(ctx, sig, sig_len);
    return result;
}

/* RSA-PSS verify */
static JSValue tjs_crypto_rsa_pss_verify(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, data_len, sig_len;
    const uint8_t *key_data, *data, *sig;
    int32_t salt_len = -1;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "rsaPssVerify() requires 3 arguments: publicKey, data, signature");
    }
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    sig = JS_GetAnyBuffer(ctx, &sig_len, argv[2]);
    
    if (!key_data || !data || !sig) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 4 && !JS_IsUndefined(argv[3])) {
        JS_ToInt32(ctx, &salt_len, argv[3]);
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    
    BIO* bio = BIO_new_mem_buf(key_data, key_len);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return JS_ThrowInternalError(ctx, "Failed to parse public key");
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = NULL;
    
    int verified = 0;
    if (EVP_DigestVerifyInit(mdctx, &pctx, md, NULL, pkey) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len) == 1 &&
        EVP_DigestVerify(mdctx, sig, sig_len, data, data_len) == 1) {
        verified = 1;
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return JS_NewBool(ctx, verified);
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
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    
    key = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
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

/* HKDF key derivation */
static JSValue tjs_crypto_hkdf(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t ikm_len, salt_len = 0, info_len = 0;
    const uint8_t *ikm, *salt = NULL, *info = NULL;
    int32_t keylen;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "hkdf() requires 2 arguments: ikm and keylen");
    }
    
    ikm = JS_GetAnyBuffer(ctx, &ikm_len, argv[0]);
    if (!ikm) {
        return JS_EXCEPTION;
    }
    
    if (JS_ToInt32(ctx, &keylen, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    
    if (keylen < 1 || keylen > 65536) {
        return JS_ThrowRangeError(ctx, "Invalid keylen");
    }
    
    // Optional salt and info
    if (argc >= 3 && !JS_IsUndefined(argv[2])) {
        salt = JS_GetAnyBuffer(ctx, &salt_len, argv[2]);
        if (!salt && salt_len > 0) {
            return JS_EXCEPTION;
        }
    }
    if (argc >= 4 && !JS_IsUndefined(argv[3])) {
        info = JS_GetAnyBuffer(ctx, &info_len, argv[3]);
        if (!info && info_len > 0) {
            return JS_EXCEPTION;
        }
    }
    
    const EVP_MD* md = get_md_from_magic(magic);
    if (!md) {
        return JS_ThrowInternalError(ctx, "Invalid hash algorithm");
    }
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x: Use EVP_KDF
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        return JS_ThrowInternalError(ctx, "HKDF not available");
    }
    
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return JS_ThrowInternalError(ctx, "HKDF context creation failed");
    }
    
    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_get0_name(md), 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void*)ikm, ikm_len);
    if (salt && salt_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len);
    }
    if (info && info_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("info", (void*)info, info_len);
    }
    *p = OSSL_PARAM_construct_end();
    
    uint8_t* out = js_malloc(ctx, keylen);
    if (!out) {
        EVP_KDF_CTX_free(kctx);
        return JS_EXCEPTION;
    }
    
    if (EVP_KDF_derive(kctx, out, keylen, params) != 1) {
        js_free(ctx, out);
        EVP_KDF_CTX_free(kctx);
        return JS_ThrowInternalError(ctx, "HKDF derivation failed");
    }
    
    EVP_KDF_CTX_free(kctx);
#else
    // OpenSSL 1.x: Use EVP_PKEY_derive with HKDF
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx || EVP_PKEY_derive_init(pctx) != 1) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        return JS_ThrowInternalError(ctx, "HKDF init failed");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return JS_ThrowInternalError(ctx, "HKDF set md failed");
    }
    
    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) != 1) {
            EVP_PKEY_CTX_free(pctx);
            return JS_ThrowInternalError(ctx, "HKDF set salt failed");
        }
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return JS_ThrowInternalError(ctx, "HKDF set key failed");
    }
    
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) != 1) {
            EVP_PKEY_CTX_free(pctx);
            return JS_ThrowInternalError(ctx, "HKDF set info failed");
        }
    }
    
    uint8_t* out = js_malloc(ctx, keylen);
    if (!out) {
        EVP_PKEY_CTX_free(pctx);
        return JS_EXCEPTION;
    }
    
    size_t out_len = keylen;
    if (EVP_PKEY_derive(pctx, out, &out_len) != 1) {
        js_free(ctx, out);
        EVP_PKEY_CTX_free(pctx);
        return JS_ThrowInternalError(ctx, "HKDF derivation failed");
    }
    
    EVP_PKEY_CTX_free(pctx);
#endif
    
    JSValue result = js_fastab(ctx, out, keylen);
    return result;
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
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    
    JSValue result = js_fastab(ctx, buf, length);
    return result;
}

/* Cipher encryption/decryption using magic */
static JSValue tjs_crypto_cipher(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    size_t key_len, iv_len = 0, data_len;
    const uint8_t *key, *iv = NULL, *data;
    int encrypt = (magic >> 8) & 1;  // High bit indicates encrypt/decrypt
    int cipher_magic = magic & 0xFF;
    
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "cipher() requires at least 2 arguments: key and data");
    }
    
    const EVP_CIPHER* cipher = get_cipher_from_magic(cipher_magic);
    if (!cipher) {
        return JS_ThrowInternalError(ctx, "Invalid cipher algorithm");
    }
    
    key = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    // IV is optional for some modes
    if (argc >= 3 && !JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        iv = JS_GetAnyBuffer(ctx, &iv_len, argv[1]);
        if (!iv) {
            return JS_EXCEPTION;
        }
        data = JS_GetAnyBuffer(ctx, &data_len, argv[2]);
    } else {
        data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
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
    
    JSValue result = js_fastab(ctx, out, len + final_len);
    return result;
}

/* GCM encrypt with AAD support - one-shot function
 * Arguments: key, iv, plaintext, aad (optional), tagLength (optional, default 16)
 * Returns: {ciphertext: ArrayBuffer, tag: ArrayBuffer}
 */
static JSValue tjs_crypto_gcm_encrypt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t key_len, iv_len, plaintext_len, aad_len = 0;
    const uint8_t *key, *iv, *plaintext, *aad = NULL;
    
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "gcmEncrypt requires at least 3 arguments: key, iv, plaintext");
    }
    
    key = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    iv = JS_GetAnyBuffer(ctx, &iv_len, argv[1]);
    plaintext = JS_GetAnyBuffer(ctx, &plaintext_len, argv[2]);
    
    if (!key || !iv || !plaintext) {
        return JS_EXCEPTION;
    }
    
    // Optional AAD (4th argument)
    if (argc >= 4 && !JS_IsUndefined(argv[3]) && !JS_IsNull(argv[3])) {
        aad = JS_GetAnyBuffer(ctx, &aad_len, argv[3]);
        if (!aad && aad_len > 0) {
            return JS_EXCEPTION;
        }
    }
    
    // Optional tag length (5th argument, default 16)
    int tag_len = 16;
    if (argc >= 5 && !JS_IsUndefined(argv[4])) {
        int32_t tl;
        if (JS_ToInt32(ctx, &tl, argv[4]) < 0) {
            return JS_EXCEPTION;
        }
        if (tl < 4 || tl > 16) {
            return JS_ThrowRangeError(ctx, "tagLength must be between 4 and 16");
        }
        tag_len = tl;
    }
    
    // Determine cipher based on key length
    const EVP_CIPHER* cipher = NULL;
    switch (key_len) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            return JS_ThrowTypeError(ctx, "key must be 16, 24, or 32 bytes for AES-GCM");
    }
    
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) {
        return JS_ThrowOutOfMemory(ctx);
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(cctx, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "Failed to initialize GCM encryption");
    }
    
    // Set AAD if provided
    int len;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(cctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(cctx);
            return JS_ThrowInternalError(ctx, "Failed to set AAD");
        }
    }
    
    // Allocate output buffer
    uint8_t* ciphertext = js_malloc(ctx, plaintext_len);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(cctx);
        return JS_EXCEPTION;
    }
    
    // Encrypt plaintext
    int ciphertext_len;
    if (EVP_EncryptUpdate(cctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) != 1) {
        js_free(ctx, ciphertext);
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "GCM encryption failed");
    }
    
    // Finalize encryption
    int final_len;
    if (EVP_EncryptFinal_ex(cctx, ciphertext + ciphertext_len, &final_len) != 1) {
        js_free(ctx, ciphertext);
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "GCM encryption finalization failed");
    }
    ciphertext_len += final_len;
    
    // Get authentication tag
    uint8_t* tag = js_malloc(ctx, tag_len);
    if (!tag || EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != 1) {
        js_free(ctx, ciphertext);
        if (tag) js_free(ctx, tag);
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(cctx);
    
    // Return result object
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "ciphertext", js_fastab(ctx, ciphertext, ciphertext_len));
    JS_SetPropertyStr(ctx, result, "tag", js_fastab(ctx, tag, tag_len));
    
    return result;
}

/* GCM decrypt with AAD support - one-shot function
 * Arguments: key, iv, ciphertext, tag, aad (optional)
 * Returns: {plaintext: ArrayBuffer, verified: boolean}
 */
static JSValue tjs_crypto_gcm_decrypt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t key_len, iv_len, ciphertext_len, tag_len, aad_len = 0;
    const uint8_t *key, *iv, *ciphertext, *tag, *aad = NULL;
    
    if (argc < 4) {
        return JS_ThrowTypeError(ctx, "gcmDecrypt requires at least 4 arguments: key, iv, ciphertext, tag");
    }
    
    key = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    iv = JS_GetAnyBuffer(ctx, &iv_len, argv[1]);
    ciphertext = JS_GetAnyBuffer(ctx, &ciphertext_len, argv[2]);
    tag = JS_GetAnyBuffer(ctx, &tag_len, argv[3]);
    
    if (!key || !iv || !ciphertext || !tag) {
        return JS_EXCEPTION;
    }
    
    // Optional AAD (5th argument)
    if (argc >= 5 && !JS_IsUndefined(argv[4]) && !JS_IsNull(argv[4])) {
        aad = JS_GetAnyBuffer(ctx, &aad_len, argv[4]);
        if (!aad && aad_len > 0) {
            return JS_EXCEPTION;
        }
    }
    
    // Determine cipher based on key length
    const EVP_CIPHER* cipher = NULL;
    switch (key_len) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            return JS_ThrowTypeError(ctx, "key must be 16, 24, or 32 bytes for AES-GCM");
    }
    
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) {
        return JS_ThrowOutOfMemory(ctx);
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(cctx, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1 ||
        EVP_DecryptInit_ex(cctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "Failed to initialize GCM decryption");
    }
    
    // Set AAD if provided
    int len;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(cctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(cctx);
            return JS_ThrowInternalError(ctx, "Failed to set AAD");
        }
    }
    
    // Allocate output buffer
    uint8_t* plaintext = js_malloc(ctx, ciphertext_len);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(cctx);
        return JS_EXCEPTION;
    }
    
    // Decrypt ciphertext
    int plaintext_len;
    if (EVP_DecryptUpdate(cctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) != 1) {
        js_free(ctx, plaintext);
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "GCM decryption failed");
    }
    
    // Set expected tag for verification
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag) != 1) {
        js_free(ctx, plaintext);
        EVP_CIPHER_CTX_free(cctx);
        return JS_ThrowInternalError(ctx, "Failed to set authentication tag");
    }
    
    // Verify and finalize
    int final_len;
    int verified = EVP_DecryptFinal_ex(cctx, plaintext + plaintext_len, &final_len);
    
    EVP_CIPHER_CTX_free(cctx);
    
    // Return result object
    JSValue result = JS_NewObject(ctx);
    
    if (verified == 1) {
        plaintext_len += final_len;
        JS_SetPropertyStr(ctx, result, "plaintext", js_fastab(ctx, plaintext, plaintext_len));
        JS_SetPropertyStr(ctx, result, "verified", JS_NewBool(ctx, 1));
    } else {
        // Verification failed - still return plaintext but mark as unverified
        plaintext_len += final_len;
        JS_SetPropertyStr(ctx, result, "plaintext", js_fastab(ctx, plaintext, plaintext_len));
        JS_SetPropertyStr(ctx, result, "verified", JS_NewBool(ctx, 0));
    }
    
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
    
    password = JS_GetAnyBuffer(ctx, &password_len, argv[0]);
    if (!password) {
        return JS_EXCEPTION;
    }
    
    salt = JS_GetAnyBuffer(ctx, &salt_len, argv[1]);
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
    
    JSValue result = js_fastab(ctx, key, keylen);
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
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    if (!key_data) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
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
    
    JSValue result = js_fastab(ctx, sig, sig_len);
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
    
    key_data = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    if (!key_data) {
        return JS_EXCEPTION;
    }
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[1]);
    if (!data) {
        return JS_EXCEPTION;
    }
    
    sig = JS_GetAnyBuffer(ctx, &sig_len, argv[2]);
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
static JSClassID tjs_gcm_class_id;

typedef struct {
    EVP_CIPHER_CTX *ctx;
    int encrypting;  // 1 for encrypt, 0 for decrypt
    int finalized;
} TJSGCMContext;

// Finalizer for GCM context
static void tjs_gcm_finalizer(JSRuntime *rt, JSValue val) {
    TJSGCMContext *gctx = JS_GetOpaque(val, tjs_gcm_class_id);
    if (gctx) {
        if (gctx->ctx) {
            EVP_CIPHER_CTX_free(gctx->ctx);
        }
        js_free_rt(rt, gctx);
    }
}

// Class definition
static JSClassDef tjs_gcm_class = {
    "GCM",
    .finalizer = tjs_gcm_finalizer,
};

// Constructor: new GCM(mode, key, iv)
// mode: 'encrypt' or 'decrypt'
// key: ArrayBuffer (16/24/32 bytes for AES-128/192/256)
// iv: ArrayBuffer (recommended 12 bytes)
static JSValue tjs_gcm_constructor(JSContext *ctx, JSValueConst new_target,
                                     int argc, JSValueConst *argv) {
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "GCM requires 3 arguments: mode, key, iv");
    }
    
    // Parse mode
    const char *mode = JS_ToCString(ctx, argv[0]);
    if (!mode) return JS_EXCEPTION;
    
    int encrypting = (strcmp(mode, "encrypt") == 0);
    if (!encrypting && strcmp(mode, "decrypt") != 0) {
        JS_FreeCString(ctx, mode);
        return JS_ThrowTypeError(ctx, "mode must be 'encrypt' or 'decrypt'");
    }
    JS_FreeCString(ctx, mode);
    
    // Get key buffer
    size_t key_len;
    uint8_t *key = JS_GetAnyBuffer(ctx, &key_len, argv[1]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "key must be an ArrayBuffer");
    }
    
    // Get IV buffer
    size_t iv_len;
    uint8_t *iv = JS_GetAnyBuffer(ctx, &iv_len, argv[2]);
    if (!iv) {
        return JS_ThrowTypeError(ctx, "iv must be an ArrayBuffer");
    }
    
    // Create context
    TJSGCMContext *gctx = js_mallocz(ctx, sizeof(*gctx));
    if (!gctx) {
        return JS_EXCEPTION;
    }
    
    gctx->ctx = EVP_CIPHER_CTX_new();
    if (!gctx->ctx) {
        js_free(ctx, gctx);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    // Select cipher based on key length
    const EVP_CIPHER *cipher = NULL;
    switch (key_len) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            EVP_CIPHER_CTX_free(gctx->ctx);
            js_free(ctx, gctx);
            return JS_ThrowTypeError(ctx, "key must be 16, 24, or 32 bytes");
    }
    
    // Initialize encryption/decryption
    int ret;
    if (encrypting) {
        ret = EVP_EncryptInit_ex(gctx->ctx, cipher, NULL, NULL, NULL);
    } else {
        ret = EVP_DecryptInit_ex(gctx->ctx, cipher, NULL, NULL, NULL);
    }
    
    if (ret != 1 ||
        EVP_CIPHER_CTX_ctrl(gctx->ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
        EVP_CIPHER_CTX_free(gctx->ctx);
        js_free(ctx, gctx);
        return JS_ThrowInternalError(ctx, "failed to initialize GCM");
    }
    
    if (encrypting) {
        ret = EVP_EncryptInit_ex(gctx->ctx, NULL, NULL, key, iv);
    } else {
        ret = EVP_DecryptInit_ex(gctx->ctx, NULL, NULL, key, iv);
    }
    
    if (ret != 1) {
        EVP_CIPHER_CTX_free(gctx->ctx);
        js_free(ctx, gctx);
        return JS_ThrowInternalError(ctx, "failed to set key and IV");
    }
    
    gctx->encrypting = encrypting;
    gctx->finalized = 0;
    
    // Create JS object
    JSValue obj = JS_NewObjectClass(ctx, tjs_gcm_class_id);
    if (JS_IsException(obj)) {
        EVP_CIPHER_CTX_free(gctx->ctx);
        js_free(ctx, gctx);
        return obj;
    }
    
    JS_SetOpaque(obj, gctx);
    return obj;
}

// Method: setAAD(aad)
// aad: ArrayBuffer with additional authenticated data
static JSValue tjs_gcm_set_aad(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    TJSGCMContext *gctx = JS_GetOpaque2(ctx, this_val, tjs_gcm_class_id);
    if (!gctx) return JS_EXCEPTION;
    
    if (gctx->finalized) {
        return JS_ThrowTypeError(ctx, "GCM context already finalized");
    }
    
    size_t aad_len;
    uint8_t *aad = JS_GetAnyBuffer(ctx, &aad_len, argv[0]);
    if (!aad) {
        return JS_ThrowTypeError(ctx, "aad must be an ArrayBuffer");
    }
    
    int len;
    int ret;
    if (gctx->encrypting) {
        ret = EVP_EncryptUpdate(gctx->ctx, NULL, &len, aad, aad_len);
    } else {
        ret = EVP_DecryptUpdate(gctx->ctx, NULL, &len, aad, aad_len);
    }
    
    return JS_NewBool(ctx, ret == 1);
}

// Method: update(data)
// data: ArrayBuffer with data to encrypt/decrypt
// Returns: ArrayBuffer with processed data
static JSValue tjs_gcm_update(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv) {
    TJSGCMContext *gctx = JS_GetOpaque2(ctx, this_val, tjs_gcm_class_id);
    if (!gctx) return JS_EXCEPTION;
    
    if (gctx->finalized) {
        return JS_ThrowTypeError(ctx, "GCM context already finalized");
    }
    
    size_t in_len;
    uint8_t *in_data = JS_GetAnyBuffer(ctx, &in_len, argv[0]);
    if (!in_data) {
        return JS_ThrowTypeError(ctx, "data must be an ArrayBuffer");
    }
    
    // Allocate output buffer
    uint8_t *out_data = js_malloc(ctx, in_len +1);
    if (!out_data) {
        return JS_EXCEPTION;
    }
    
    int out_len;
    int ret;
    if (gctx->encrypting) {
        ret = EVP_EncryptUpdate(gctx->ctx, out_data, &out_len, in_data, in_len);
    } else {
        ret = EVP_DecryptUpdate(gctx->ctx, out_data, &out_len, in_data, in_len);
    }
    
    if (ret != 1) {
        js_free(ctx, out_data);
        return JS_ThrowInternalError(ctx, "update failed");
    }
    
    return js_fastab(ctx, out_data, out_len);
}

// Method: final(tag)
// For encryption: returns {data: ArrayBuffer, tag: ArrayBuffer}
// For decryption: tag is required parameter, returns {data: ArrayBuffer, verified: boolean}
static JSValue tjs_gcm_final(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    TJSGCMContext *gctx = JS_GetOpaque2(ctx, this_val, tjs_gcm_class_id);
    if (!gctx) return JS_EXCEPTION;
    
    if (gctx->finalized) {
        return JS_ThrowTypeError(ctx, "GCM context already finalized");
    }
    
    uint8_t out_data[32];  // GCM final should produce little or no data
    int out_len;
    
    JSValue result = JS_NewObject(ctx);
    
    if (gctx->encrypting) {
        // Encryption: finalize and get tag
        if (EVP_EncryptFinal_ex(gctx->ctx, out_data, &out_len) != 1) {
            JS_FreeValue(ctx, result);
            return JS_ThrowInternalError(ctx, "encryption final failed");
        }
        
        // Get authentication tag (16 bytes)
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(gctx->ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            JS_FreeValue(ctx, result);
            return JS_ThrowInternalError(ctx, "failed to get tag");
        }
        
        gctx->finalized = 1;
        
        // Return {data, tag}
        if (out_len > 0) {
            uint8_t *data_copy = js_malloc(ctx, out_len);
            memcpy(data_copy, out_data, out_len);
            JS_SetPropertyStr(ctx, result, "data", 
                js_fastab(ctx, data_copy, out_len));
        } else {
            JS_SetPropertyStr(ctx, result, "data", 
                JS_NewArrayBufferCopy(ctx, NULL, 0));
        }
        
        uint8_t *tag_copy = js_malloc(ctx, 16);
        memcpy(tag_copy, tag, 16);
        JS_SetPropertyStr(ctx, result, "tag", 
            js_fastab(ctx, tag_copy, 16));
        
    } else {
        // Decryption: verify tag
        if (argc < 1) {
            JS_FreeValue(ctx, result);
            return JS_ThrowTypeError(ctx, "tag required for decryption");
        }
        
        size_t tag_len;
        uint8_t *tag = JS_GetAnyBuffer(ctx, &tag_len, argv[0]);
        if (!tag) {
            JS_FreeValue(ctx, result);
            return JS_ThrowTypeError(ctx, "tag must be an ArrayBuffer");
        }
        
        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(gctx->ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag) != 1) {
            JS_FreeValue(ctx, result);
            return JS_ThrowInternalError(ctx, "failed to set tag");
        }
        
        // Verify and finalize
        int verified = EVP_DecryptFinal_ex(gctx->ctx, out_data, &out_len);
        gctx->finalized = 1;
        
        // Return {data, verified}
        if (out_len > 0) {
            uint8_t *data_copy = js_malloc(ctx, out_len);
            memcpy(data_copy, out_data, out_len);
            JS_SetPropertyStr(ctx, result, "data", 
                js_fastab(ctx, data_copy, out_len));
        } else {
            JS_SetPropertyStr(ctx, result, "data", 
                JS_NewArrayBufferCopy(ctx, NULL, 0));
        }
        
        JS_SetPropertyStr(ctx, result, "verified", JS_NewBool(ctx, verified == 1));
    }
    
    return result;
}



// Module initialization
static const JSCFunctionListEntry tjs_gcm_proto_funcs[] = {
    JS_CFUNC_DEF("setAAD", 1, tjs_gcm_set_aad),
    JS_CFUNC_DEF("update", 1, tjs_gcm_update),
    JS_CFUNC_DEF("final", 1, tjs_gcm_final),
};

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
    const uint8_t* data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    
    key = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
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
    const uint8_t* data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    
    JSValue result = js_fastab(ctx, hmac, hmac_len);
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
    int encrypt = (magic >> 8) & 1;
    int cipher_magic = magic & 0xFF;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "createCipher() requires at least 1 argument: key");
    }
    
    const EVP_CIPHER* cipher = get_cipher_from_magic(cipher_magic);
    if (!cipher) {
        return JS_ThrowInternalError(ctx, "Invalid cipher algorithm");
    }
    
    key = JS_GetAnyBuffer(ctx, &key_len, argv[0]);
    if (!key) {
        return JS_EXCEPTION;
    }
    
    if (argc >= 2 && !JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        iv = JS_GetAnyBuffer(ctx, &iv_len, argv[1]);
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
    const uint8_t* data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    
    JSValue result = js_fastab(ctx, out, out_len);
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
    
    JSValue result = js_fastab(ctx, out, out_len);
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
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    uint8_t* out = js_malloc(ctx, out_len +1);
    if (!out) {
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    int decoded = EVP_DecodeBlock(out, (const uint8_t*)str, str_len);

    /* fix: check padding BEFORE freeing str — was UAF */
    int padding = 0;
    if (str_len >= 2 && str[str_len - 1] == '=') {
        padding++;
        if (str[str_len - 2] == '=') padding++;
    }
    JS_FreeCString(ctx, str);

    if (decoded < 0) {
        js_free(ctx, out);
        return JS_ThrowInternalError(ctx, "Base64 decode failed");
    }

    decoded -= padding;

    JSValue result = js_fastab(ctx, out, decoded);
    return result;
}

/* Hex encoding/decoding */
static JSValue tjs_crypto_hex_encode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    size_t data_len;
    const uint8_t* data;
    
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "hexEncode() requires 1 argument: data");
    }
    
    data = JS_GetAnyBuffer(ctx, &data_len, argv[0]);
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
    uint8_t* out = js_malloc(ctx, out_len +1);	// avoid 0byte-alloc
    if (!out) {
        JS_FreeCString(ctx, str);
        return JS_EXCEPTION;
    }
    
    for (size_t i = 0; i < out_len; i++) {
        char byte[3] = {str[i * 2], str[i * 2 + 1], '\0'};
        out[i] = (uint8_t)strtol(byte, NULL, 16);
    }
    
    JS_FreeCString(ctx, str);
    
    JSValue result = js_fastab(ctx, out, out_len);
    return result;
}

static JSValue tjs_randomUUID(JSContext *ctx, JSValue this_val, int argc, JSValue *argv) {
    char v[37];
    unsigned char u[16];

    int r = uv_random(NULL, NULL, u, sizeof(u), 0, NULL);
    if (r != 0) {
        return tjs_throw_errno(ctx, r);
    }

    u[6] &= 15;
    u[6] |= 64;  // '4x'

    u[8] &= 63;
    u[8] |= 128;  // 0b10xxxxxx

    snprintf(v,
             sizeof(v),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0],
             u[1],
             u[2],
             u[3],
             u[4],
             u[5],
             u[6],
             u[7],
             u[8],
             u[9],
             u[10],
             u[11],
             u[12],
             u[13],
             u[14],
             u[15]);

    return JS_NewString(ctx, v);
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
    JS_CFUNC_MAGIC_DEF("aes128CbcEncrypt", 3, tjs_crypto_cipher, (1 << 8) | CIPHER_AES_128_CBC),
    JS_CFUNC_MAGIC_DEF("aes256CbcEncrypt", 3, tjs_crypto_cipher, (1 << 8) | CIPHER_AES_256_CBC),
    JS_CFUNC_MAGIC_DEF("aes128GcmEncrypt", 3, tjs_crypto_cipher, (1 << 8) | CIPHER_AES_128_GCM),
    JS_CFUNC_MAGIC_DEF("aes256GcmEncrypt", 3, tjs_crypto_cipher, (1 << 8) | CIPHER_AES_256_GCM),
    
    /* Cipher functions - decrypt */
    JS_CFUNC_MAGIC_DEF("aes128CbcDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_128_CBC),
    JS_CFUNC_MAGIC_DEF("aes256CbcDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_256_CBC),
    JS_CFUNC_MAGIC_DEF("aes128GcmDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_128_GCM),
    JS_CFUNC_MAGIC_DEF("aes256GcmDecrypt", 3, tjs_crypto_cipher, CIPHER_AES_256_GCM),
    
    /* Streaming cipher */
    JS_CFUNC_MAGIC_DEF("createCipherAes256Cbc", 2, tjs_crypto_create_cipher, (1 << 8) | CIPHER_AES_256_CBC),
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

	/* ECC */
    JS_CFUNC_MAGIC_DEF("generateEcKeyP256", 0, tjs_crypto_generate_ec_key, ECC_CURVE_P256),
    JS_CFUNC_MAGIC_DEF("generateEcKeyP384", 0, tjs_crypto_generate_ec_key, ECC_CURVE_P384),
    JS_CFUNC_MAGIC_DEF("generateEcKeyP521", 0, tjs_crypto_generate_ec_key, ECC_CURVE_P521),
    
    JS_CFUNC_MAGIC_DEF("ecdsaSignP256", 2, tjs_crypto_ecdsa_sign, HASH_SHA256), // P256 uses SHA256
    JS_CFUNC_MAGIC_DEF("ecdsaSignP384", 2, tjs_crypto_ecdsa_sign, HASH_SHA384),
    JS_CFUNC_MAGIC_DEF("ecdsaSignP521", 2, tjs_crypto_ecdsa_sign, HASH_SHA512),
    
    JS_CFUNC_MAGIC_DEF("ecdsaVerifyP256", 3, tjs_crypto_ecdsa_verify, ECC_CURVE_P256),
    JS_CFUNC_MAGIC_DEF("ecdsaVerifyP384", 3, tjs_crypto_ecdsa_verify, ECC_CURVE_P384),
    JS_CFUNC_MAGIC_DEF("ecdsaVerifyP521", 3, tjs_crypto_ecdsa_verify, ECC_CURVE_P521),
    
    JS_CFUNC_MAGIC_DEF("ecdhDeriveP256", 2, tjs_crypto_ecdh_derive, ECC_CURVE_P256),
    JS_CFUNC_MAGIC_DEF("ecdhDeriveP384", 2, tjs_crypto_ecdh_derive, ECC_CURVE_P384),
    JS_CFUNC_MAGIC_DEF("ecdhDeriveP521", 2, tjs_crypto_ecdh_derive, ECC_CURVE_P521),
    
    /* RSA-OAEP */
    JS_CFUNC_MAGIC_DEF("rsaOaepSha256Encrypt", 2, tjs_crypto_rsa_oaep_encrypt, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("rsaOaepSha256Decrypt", 2, tjs_crypto_rsa_oaep_decrypt, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("rsaOaepSha512Encrypt", 2, tjs_crypto_rsa_oaep_encrypt, HASH_SHA512),
    JS_CFUNC_MAGIC_DEF("rsaOaepSha512Decrypt", 2, tjs_crypto_rsa_oaep_decrypt, HASH_SHA512),
    
    /* RSA-PSS */
    JS_CFUNC_MAGIC_DEF("rsaPssSha256Sign", 2, tjs_crypto_rsa_pss_sign, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("rsaPssSha256Verify", 3, tjs_crypto_rsa_pss_verify, HASH_SHA256),
    
    /* HKDF */
    JS_CFUNC_MAGIC_DEF("hkdfSha256", 2, tjs_crypto_hkdf, HASH_SHA256),
    JS_CFUNC_MAGIC_DEF("hkdfSha512", 2, tjs_crypto_hkdf, HASH_SHA512),

	/* GCM with AAD support */
    JS_CFUNC_DEF("gcmEncrypt", 5, tjs_crypto_gcm_encrypt),
    JS_CFUNC_DEF("gcmDecrypt", 5, tjs_crypto_gcm_decrypt),

	/* Others */
    JS_CFUNC_DEF("randomUUID", 0, tjs_randomUUID)
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

	/* Initialize GCM class */
	JS_NewClassID(JS_GetRuntime(ctx), &tjs_gcm_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_gcm_class_id, &tjs_gcm_class);
	JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, tjs_gcm_proto_funcs, 
        sizeof(tjs_gcm_proto_funcs) / sizeof(JSCFunctionListEntry));
    JS_SetClassProto(ctx, tjs_gcm_class_id, proto);
    
	/* GCM constructor */
    JSValue gcm_ctor = JS_NewCFunction2(ctx, tjs_gcm_constructor, "GCM", 3, 
        JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, gcm_ctor, proto);
	JS_SetPropertyStr(ctx, ns, "GCM", gcm_ctor);
    
    /* Set crypto functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_crypto_funcs, countof(tjs_crypto_funcs));
}