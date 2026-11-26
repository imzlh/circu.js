/*
 * circu.js
 *
 * Copyright (c) 2025-2026 iz
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
#include "tjs.h"
#include "capability.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <limits.h>
#include <stdatomic.h>
#include <string.h>

/* Module initialization flag — accessed from multiple worker threads */
static _Atomic(bool) ssl_initialized = false;

/* Error handling macros */
#define SSL_ERROR_CHECK(ctx, result, operation) do { \
    if (!(result)) { \
        unsigned long err = ERR_get_error(); \
        char buf[256]; \
        ERR_error_string_n(err, buf, sizeof(buf)); \
        return JS_ThrowTypeError(ctx, "SSL error in %s: %s", operation, buf); \
    } \
} while(0)

#define SSL_THROW_ERROR(ctx, operation) do { \
    unsigned long err = ERR_get_error(); \
    char buf[256]; \
    ERR_error_string_n(err, buf, sizeof(buf)); \
    return JS_ThrowTypeError(ctx, "SSL error in %s: %s", operation, buf); \
} while(0)

#define CHECK_SSL_ERR(ssl, ret) do { \
	int err = SSL_get_error(ssl, ret); \
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { \
        return JS_NULL; \
    } \
} while(0)

/* Macro for common SSL context configuration */
#define SET_SSL_CTX_OPTION(ctx, ssl_ctx, option, value) do { \
    if ((value)) { \
        SSL_CTX_set_options(ssl_ctx, option); \
    } else { \
        SSL_CTX_clear_options(ssl_ctx, option); \
    } \
} while(0)

#define cstr(ctx, val) JS_IsString(val) ? JS_ToCString(ctx, val) : NULL

/* Constants for SSL modes */
typedef enum {
    TJS_SSL_MODE_SERVER = 0,
    TJS_SSL_MODE_CLIENT = 1
} TJSSSLMode;

/* SSL handshake state */
typedef enum {
    TJS_SSL_HANDSHAKE_NONE = 0,
    TJS_SSL_HANDSHAKE_IN_PROGRESS,
    TJS_SSL_HANDSHAKE_DONE,
    TJS_SSL_HANDSHAKE_ERROR
} TJSSSLHandshakeState;

/* Defined in the Certificate region below; the SSLContext constructor accepts
 * a Certificate in place of a PEM string. */
typedef struct TJSSSLCertificate TJSSSLCertificate;
static TJSSSLCertificate *tjs_ssl_certificate_probe(JSValueConst value);
static JSValue tjs_ssl_certificate_to_pem(JSContext *ctx, JSValueConst this_val);

#pragma region SSLContext
typedef struct {
    JSContext *ctx;
    SSL_CTX *ssl_ctx;
    TJSSSLMode mode;
    char *cert_pem;
    char *key_pem;
    char *ca_pem;
    char *ciphers;
    int verify_mode;
    bool verify_hostname;
    bool session_tickets;
    /* ALPN protocol list (heap-allocated; referenced by SSL_CTX callback for
     * server mode, which doesn't copy the buffer). Owned by this context. */
    uint8_t *alpn_list;
    size_t alpn_list_len;
} TJSSSLContext;

static JSClassID tjs_ssl_context_class_id;

static void tjs_ssl_context_finalizer(JSRuntime *rt, JSValue val) {
    TJSSSLContext *ssl_ctx = JS_GetOpaque(val, tjs_ssl_context_class_id);
    if (ssl_ctx) {
        if (ssl_ctx->ssl_ctx) {
            SSL_CTX_free(ssl_ctx->ssl_ctx);
        }
        if (ssl_ctx->cert_pem) js_free_rt(rt, ssl_ctx->cert_pem);
        if (ssl_ctx->key_pem) js_free_rt(rt, ssl_ctx->key_pem);
        if (ssl_ctx->ca_pem) js_free_rt(rt, ssl_ctx->ca_pem);
        if (ssl_ctx->ciphers) js_free_rt(rt, ssl_ctx->ciphers);
        if (ssl_ctx->alpn_list) js_free_rt(rt, ssl_ctx->alpn_list);
        js_free_rt(rt, ssl_ctx);
    }
}

static JSClassDef tjs_ssl_context_class = {
    "SSLContext",
    .finalizer = tjs_ssl_context_finalizer,
};

static int ssl_ctx_use_certificate_chain_pem(SSL_CTX *ctx, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return 0;

    X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        return 0;
    }

    int ok = SSL_CTX_use_certificate(ctx, cert) == 1;
    X509_free(cert);
    if (!ok) {
        BIO_free(bio);
        return 0;
    }

    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (SSL_CTX_add_extra_chain_cert(ctx, cert) != 1) {
            X509_free(cert);
            BIO_free(bio);
            return 0;
        }
    }

    ERR_clear_error();
    BIO_free(bio);
    return 1;
}

static int ssl_ctx_use_private_key_pem(SSL_CTX *ctx, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return 0;

    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!key) return 0;

    int ok = SSL_CTX_use_PrivateKey(ctx, key) == 1;
    EVP_PKEY_free(key);
    return ok;
}

static int ssl_ctx_load_ca_pem(SSL_CTX *ctx, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return 0;

    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    int count = 0;
    X509 *cert;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (X509_STORE_add_cert(store, cert) != 1) {
            unsigned long err = ERR_peek_last_error();
            if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(cert);
                BIO_free(bio);
                return 0;
            }
            ERR_clear_error();
        }
        X509_free(cert);
        count++;
    }

    ERR_clear_error();
    BIO_free(bio);
    return count > 0;
}

/* Helper: Get SSL method based on version */
static const SSL_METHOD *get_ssl_method(const char *version, TJSSSLMode mode) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!version || strcmp(version, "TLS") == 0) {
#endif
        return mode == TJS_SSL_MODE_SERVER ? TLS_server_method() : TLS_client_method();
#if OPENSSL_VERSION_NUMBER < 0x10100000L // ‘TLSv1_2_server_method’ is deprecated: Since OpenSSL 1.1.0
    } else if (strcmp(version, "TLSv1.2") == 0) {
        return mode == TJS_SSL_MODE_SERVER ? TLSv1_2_server_method() : TLSv1_2_client_method();
    } else if (strcmp(version, "TLSv1.3") == 0) {
        /* TLS 1.3 uses the generic TLS method with min/max version set */
        return mode == TJS_SSL_MODE_SERVER ? TLS_server_method() : TLS_client_method();
    }
    return NULL;
#endif
}

/* Helper: Set min/max TLS version */
static void set_tls_version_range(SSL_CTX *ctx, const char *min_ver, const char *max_ver) {
    if (min_ver) {
        if (strcmp(min_ver, "TLSv1.0") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        } else if (strcmp(min_ver, "TLSv1.1") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
        } else if (strcmp(min_ver, "TLSv1.2") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        } else if (strcmp(min_ver, "TLSv1.3") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        }
    }
    
    if (max_ver) {
        if (strcmp(max_ver, "TLSv1.0") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
        } else if (strcmp(max_ver, "TLSv1.1") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION);
        } else if (strcmp(max_ver, "TLSv1.2") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        } else if (strcmp(max_ver, "TLSv1.3") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        }
    }
}

static int alpn_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen,
	const unsigned char* in, unsigned int inlen, void* arg) {
	/* Pass the full ALPN list to SSL_select_next_proto.
	 * The list format is [len1][proto1][len2][proto2]... with total length */
	unsigned char* list = (unsigned char*) arg;
	/* ALPN list is length-prefixed, not NUL-terminated: strlen reads OOB. */
	TJSSSLContext *ssl_ctx = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
	if (ssl_ctx && ssl_ctx->alpn_list && ssl_ctx->alpn_list_len > 0) {
		if (SSL_select_next_proto((unsigned char**) out, outlen,
			ssl_ctx->alpn_list, (unsigned int)ssl_ctx->alpn_list_len, in, inlen)
			== OPENSSL_NPN_NEGOTIATED) {
			return SSL_TLSEXT_ERR_OK;
		}
	}
	(void) list;
	return SSL_TLSEXT_ERR_NOACK;
}

/* new SSLContext(options) */
static JSValue tjs_ssl_context_constructor(JSContext *ctx, JSValueConst new_target,
                                            int argc, JSValueConst *argv) {
    /* One-time initialization — safe from multiple worker threads */
    bool expected = false;
    if (atomic_compare_exchange_strong(&ssl_initialized, &expected, true)) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_ssl_context_class_id);
    if (JS_IsException(obj)) return obj;
    
    TJSSSLContext *ssl_ctx = js_mallocz(ctx, sizeof(*ssl_ctx));
    if (!ssl_ctx) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    ssl_ctx->ctx = ctx;
    ssl_ctx->verify_mode = SSL_VERIFY_NONE;
    ssl_ctx->verify_hostname = true;
    ssl_ctx->session_tickets = true;
    
    JSValue options = argc > 0 ? argv[0] : JS_UNDEFINED;
    
    /* Parse mode */
    JSValue mode_val = JS_GetPropertyStr(ctx, options, "mode");
    const char *mode_str = cstr(ctx, mode_val);
    if (mode_str) {
        ssl_ctx->mode = strcmp(mode_str, "server") == 0 ? TJS_SSL_MODE_SERVER : TJS_SSL_MODE_CLIENT;
        JS_FreeCString(ctx, mode_str);
    } else {
        ssl_ctx->mode = TJS_SSL_MODE_CLIENT;
    }
    JS_FreeValue(ctx, mode_val);
    
    /* Parse SSL version */
    JSValue version_val = JS_GetPropertyStr(ctx, options, "version");
    const char *version = cstr(ctx, version_val);
    const SSL_METHOD *method = get_ssl_method(version, ssl_ctx->mode);
    if (version) JS_FreeCString(ctx, version);
    JS_FreeValue(ctx, version_val);
    
    if (!method) {
        js_free(ctx, ssl_ctx);
        JS_FreeValue(ctx, obj);
        return JS_ThrowTypeError(ctx, "Invalid SSL version");
    }
    
    ssl_ctx->ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx->ssl_ctx) {
        js_free(ctx, ssl_ctx);
        JS_FreeValue(ctx, obj);
        SSL_THROW_ERROR(ctx, "SSL_CTX_new");
    }
    
    /* Set min/max version */
    JSValue min_ver_val = JS_GetPropertyStr(ctx, options, "minVersion");
    JSValue max_ver_val = JS_GetPropertyStr(ctx, options, "maxVersion");
    const char *min_ver = cstr(ctx, min_ver_val);
    const char *max_ver = cstr(ctx, max_ver_val);
    set_tls_version_range(ssl_ctx->ssl_ctx, min_ver, max_ver);
    if (min_ver) JS_FreeCString(ctx, min_ver);
    if (max_ver) JS_FreeCString(ctx, max_ver);
    JS_FreeValue(ctx, min_ver_val);
    JS_FreeValue(ctx, max_ver_val);
    
    /* Certificate and key. `cert` may be a PEM string or a Certificate. */
    JSValue cert_val = JS_GetPropertyStr(ctx, options, "cert");
    JSValue key_val = JS_GetPropertyStr(ctx, options, "key");
    const char *cert = cstr(ctx, cert_val);
    const char *key = cstr(ctx, key_val);
    JSValue cert_pem_val = JS_UNDEFINED;
    if (!cert && tjs_ssl_certificate_probe(cert_val)) {
        cert_pem_val = tjs_ssl_certificate_to_pem(ctx, cert_val);
        if (!JS_IsException(cert_pem_val))
            cert = JS_ToCString(ctx, cert_pem_val);
        if (!cert) {
            JS_FreeValue(ctx, cert_val);
            JS_FreeValue(ctx, key_val);
            JS_FreeValue(ctx, cert_pem_val);
            if (key) JS_FreeCString(ctx, key);
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            return JS_EXCEPTION;
        }
    }

    if (cert) {
        ssl_ctx->cert_pem = js_strdup(ctx, cert);
        int ret = ssl_ctx_use_certificate_chain_pem(ssl_ctx->ssl_ctx, cert);
        JS_FreeCString(ctx, cert);
        if (ret != 1) {
            JS_FreeValue(ctx, cert_val);
            JS_FreeValue(ctx, key_val);
            JS_FreeValue(ctx, cert_pem_val);
            if (key) JS_FreeCString(ctx, key);
            if (ssl_ctx->cert_pem) js_free(ctx, ssl_ctx->cert_pem);
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            SSL_THROW_ERROR(ctx, "SSL_CTX_use_certificate_chain_pem");
        }
    }
    JS_FreeValue(ctx, cert_pem_val);
    JS_FreeValue(ctx, cert_val);

    if (key) {
        ssl_ctx->key_pem = js_strdup(ctx, key);
        int ret = ssl_ctx_use_private_key_pem(ssl_ctx->ssl_ctx, key);
        JS_FreeCString(ctx, key);
        if (ret != 1) {
            JS_FreeValue(ctx, key_val);
            if (ssl_ctx->cert_pem) js_free(ctx, ssl_ctx->cert_pem);
            if (ssl_ctx->key_pem) js_free(ctx, ssl_ctx->key_pem);
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            SSL_THROW_ERROR(ctx, "SSL_CTX_use_PrivateKey_pem");
        }
    }
    JS_FreeValue(ctx, key_val);
    
    /* CA certificates */
    JSValue ca_val = JS_GetPropertyStr(ctx, options, "ca");
    const char *ca = cstr(ctx, ca_val);
    if (ca) {
        ssl_ctx->ca_pem = js_strdup(ctx, ca);
        int ret = ssl_ctx_load_ca_pem(ssl_ctx->ssl_ctx, ca);
        JS_FreeCString(ctx, ca);
        if (ret != 1) {
            JS_FreeValue(ctx, ca_val);
            if (ssl_ctx->cert_pem) js_free(ctx, ssl_ctx->cert_pem);
            if (ssl_ctx->key_pem)  js_free(ctx, ssl_ctx->key_pem);
            if (ssl_ctx->ca_pem)   js_free(ctx, ssl_ctx->ca_pem);
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            SSL_THROW_ERROR(ctx, "SSL_CTX_load_verify_locations_pem");
        }
    }
    JS_FreeValue(ctx, ca_val);
    
    /* Ciphers */
    JSValue ciphers_val = JS_GetPropertyStr(ctx, options, "ciphers");
    const char *ciphers = cstr(ctx, ciphers_val);
    if (ciphers) {
        ssl_ctx->ciphers = js_strdup(ctx, ciphers);
        SSL_CTX_set_cipher_list(ssl_ctx->ssl_ctx, ciphers);
        JS_FreeCString(ctx, ciphers);
    }
    JS_FreeValue(ctx, ciphers_val);
    
    /* Verify mode */
    JSValue verify_val = JS_GetPropertyStr(ctx, options, "verify");
    if (JS_ToBool(ctx, verify_val)) {
        ssl_ctx->verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(ssl_ctx->ssl_ctx, ssl_ctx->verify_mode, NULL);
    }
    JS_FreeValue(ctx, verify_val);

    JSValue verify_hostname_val = JS_GetPropertyStr(ctx, options, "verifyHostname");
    if (!JS_IsUndefined(verify_hostname_val)) {
        ssl_ctx->verify_hostname = JS_ToBool(ctx, verify_hostname_val);
    }
    JS_FreeValue(ctx, verify_hostname_val);
    
    /* Session tickets */
    JSValue tickets_val = JS_GetPropertyStr(ctx, options, "sessionTickets");
    if (!JS_IsUndefined(tickets_val)) {
        ssl_ctx->session_tickets = JS_ToBool(ctx, tickets_val);
        SET_SSL_CTX_OPTION(ctx, ssl_ctx->ssl_ctx, SSL_OP_NO_TICKET, !ssl_ctx->session_tickets);
    }
    JS_FreeValue(ctx, tickets_val);
    
    /* Session cache */
    JSValue cache_val = JS_GetPropertyStr(ctx, options, "sessionCache");
    if (JS_ToBool(ctx, cache_val)) {
        SSL_CTX_set_session_cache_mode(ssl_ctx->ssl_ctx, SSL_SESS_CACHE_BOTH);
    } else {
        SSL_CTX_set_session_cache_mode(ssl_ctx->ssl_ctx, SSL_SESS_CACHE_OFF);
    }
    JS_FreeValue(ctx, cache_val);
    
    /* Compression */
    JSValue compression_val = JS_GetPropertyStr(ctx, options, "compression");
    if (!JS_ToBool(ctx, compression_val)) {
        SSL_CTX_set_options(ssl_ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);
    }
    JS_FreeValue(ctx, compression_val);
    
    /* ALPN protocols */
    JSValue alpn_val = JS_GetPropertyStr(ctx, options, "alpn");
    if (JS_IsArray(alpn_val)) {
        JSValue len_val = JS_GetPropertyStr(ctx, alpn_val, "length");
        int32_t len;
        JS_ToInt32(ctx, &len, len_val);
        JS_FreeValue(ctx, len_val);

        /* Build ALPN protocol list on the heap. SSL_CTX_set_alpn_select_cb
         * keeps the pointer (no copy), so this must outlive the constructor. */
        uint8_t *alpn_list = js_malloc(ctx, 256);
        size_t alpn_list_len = 0;

        if (alpn_list) {
            for (int32_t i = 0; i < len && alpn_list_len < 255; i++) {
                JSValue proto_val = JS_GetPropertyUint32(ctx, alpn_val, i);
                const char *proto = cstr(ctx, proto_val);
                if (proto) {
                    size_t proto_len = strlen(proto);
                    if (alpn_list_len + proto_len + 1 < 256) {
                        alpn_list[alpn_list_len++] = proto_len;
                        memcpy(alpn_list + alpn_list_len, proto, proto_len);
                        alpn_list_len += proto_len;
                    }
                    JS_FreeCString(ctx, proto);
                }
                JS_FreeValue(ctx, proto_val);
            }

            if (ssl_ctx->mode == TJS_SSL_MODE_SERVER) {
                /* server: callback retains the pointer — keep on ssl_ctx */
                ssl_ctx->alpn_list = alpn_list;
                ssl_ctx->alpn_list_len = alpn_list_len;
                /* Expose the context so alpn_cb can read the authoritative
                 * (binary, non-NUL-terminated) list length. */
                SSL_CTX_set_app_data(ssl_ctx->ssl_ctx, ssl_ctx);
                SSL_CTX_set_alpn_select_cb(ssl_ctx->ssl_ctx, alpn_cb, alpn_list);
            } else {
                /* client: SSL_CTX_set_alpn_protos copies the buffer internally */
                SSL_CTX_set_alpn_protos(ssl_ctx->ssl_ctx, alpn_list, alpn_list_len);
                js_free(ctx, alpn_list);
            }
        }
    }
    JS_FreeValue(ctx, alpn_val);
    
    /* SNI */
    JSValue sni_val = JS_GetPropertyStr(ctx, options, "servername");
    if (ssl_ctx->mode == TJS_SSL_MODE_CLIENT && !JS_IsUndefined(sni_val)) {
        /* SNI will be set when creating SSL object */
    }
    JS_FreeValue(ctx, sni_val);
    
    /* DH parameters */
    JSValue dhparam_val = JS_GetPropertyStr(ctx, options, "dhparam");
    const char *dhparam = cstr(ctx, dhparam_val);
    if (dhparam) {
        BIO *bio = BIO_new_mem_buf(dhparam, -1);
        if (bio) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            EVP_PKEY *dh = PEM_read_bio_Parameters(bio, NULL);
            if (dh) {
                SSL_CTX_set0_tmp_dh_pkey(ssl_ctx->ssl_ctx, dh);
            }
#else
            DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
            if (dh) {
                SSL_CTX_set_tmp_dh(ssl_ctx->ssl_ctx, dh);
                DH_free(dh);
            }
#endif
            BIO_free(bio);
        }
        JS_FreeCString(ctx, dhparam);
    }
    JS_FreeValue(ctx, dhparam_val);
    
    /* ECDH curve */
    JSValue ecdh_val = JS_GetPropertyStr(ctx, options, "ecdhCurve");
    const char *ecdh_curve = cstr(ctx, ecdh_val);
    if (ecdh_curve) {
        SSL_CTX_set_ecdh_auto(ssl_ctx->ssl_ctx, 1);
        JS_FreeCString(ctx, ecdh_curve);
    } else {
        SSL_CTX_set_ecdh_auto(ssl_ctx->ssl_ctx, 1);
    }
    JS_FreeValue(ctx, ecdh_val);
    
    JS_SetOpaque(obj, ssl_ctx);
    return obj;
}

/* Getter: mode */
static JSValue tjs_ssl_context_get_mode(JSContext *ctx, JSValueConst this_val) {
    TJSSSLContext *ssl_ctx = JS_GetOpaque2(ctx, this_val, tjs_ssl_context_class_id);
    if (!ssl_ctx) return JS_EXCEPTION;
    return JS_NewString(ctx, ssl_ctx->mode == TJS_SSL_MODE_SERVER ? "server" : "client");
}

static const JSCFunctionListEntry tjs_ssl_context_proto_funcs[] = {
    JS_CGETSET_DEF("mode", tjs_ssl_context_get_mode, NULL),
};

/* C-side API */
// Warn: lifetime of SSL_CTX* cannot be guaranteed after this function returns
// 		please use it after call immediatly, or dup object
SSL_CTX* tjs__sslctx_get(JSContext *ctx, JSValueConst obj){
	TJSSSLContext *ssl_ctx = JS_GetOpaque(obj, tjs_ssl_context_class_id);
	if (!ssl_ctx) return NULL;
	return ssl_ctx->ssl_ctx;
}

#pragma region Certificate
/* An X.509 certificate wrapper. Owns the X509 and backs both the `ssl.Certificate`
 * constructor and `pipe.certificate`, so peer certs and parsed PEM share one
 * implementation. */
struct TJSSSLCertificate {
    X509 *x509;
};

static JSClassID tjs_ssl_certificate_class_id;

static void tjs_ssl_certificate_finalizer(JSRuntime *rt, JSValue val) {
    TJSSSLCertificate *cert = JS_GetOpaque(val, tjs_ssl_certificate_class_id);
    if (cert) {
        X509_free(cert->x509);
        js_free_rt(rt, cert);
    }
}

static JSClassDef tjs_ssl_certificate_class = {
    "Certificate",
    .finalizer = tjs_ssl_certificate_finalizer,
};

static JSValue tjs_ssl_certificate_error(JSContext *ctx, const char *message) {
    ERR_clear_error();
    return JS_ThrowTypeError(ctx, "%s", message);
}

static JSValue tjs_ssl_certificate_name_error(JSContext *ctx, const char *message) {
    tjs_ssl_certificate_error(ctx, message);
    JSValue error = JS_GetException(ctx);
    if (JS_SetPropertyStr(ctx, error, "code", JS_NewString(ctx, "ERR_INVALID_ARG_VALUE")) < 0) {
        JS_FreeValue(ctx, error);
        return JS_EXCEPTION;
    }
    return JS_Throw(ctx, error);
}

static TJSSSLCertificate *tjs_ssl_certificate_get(JSContext *ctx, JSValueConst value) {
    if (tjs_ssl_certificate_class_id == JS_INVALID_CLASS_ID)
        return NULL;
    TJSSSLCertificate *cert = JS_GetOpaque2(ctx, value, tjs_ssl_certificate_class_id);
    return cert;
}

/* Non-throwing probe for callers that accept several input types. */
static TJSSSLCertificate *tjs_ssl_certificate_probe(JSValueConst value) {
    if (tjs_ssl_certificate_class_id == JS_INVALID_CLASS_ID) return NULL;
    return JS_GetOpaque(value, tjs_ssl_certificate_class_id);
}

/* Attach an X509 to a new instance, taking ownership. |prototype| is used for
 * the constructor path; NULL uses the class prototype. */
static JSValue tjs_ssl_certificate_new(JSContext *ctx, X509 *x509, JSValueConst prototype) {
    if (!x509) return JS_NULL;
    if (tjs_ssl_certificate_class_id == JS_INVALID_CLASS_ID) {
        X509_free(x509);
        return JS_ThrowInternalError(ctx, "Certificate is not initialized");
    }
    TJSSSLCertificate *cert = js_mallocz(ctx, sizeof(*cert));
    if (!cert) {
        X509_free(x509);
        return JS_EXCEPTION;
    }
    cert->x509 = x509;

    JSValue obj = JS_IsNull(prototype)
        ? JS_NewObjectClass(ctx, tjs_ssl_certificate_class_id)
        : JS_NewObjectProtoClass(ctx, prototype, tjs_ssl_certificate_class_id);
    if (JS_IsException(obj)) {
        X509_free(x509);
        js_free(ctx, cert);
        return obj;
    }
    JS_SetOpaque(obj, cert);
    return obj;
}

/* Wrap an X509 from C, taking ownership. */
static JSValue tjs_ssl_certificate_wrap(JSContext *ctx, X509 *x509) {
    return tjs_ssl_certificate_new(ctx, x509, JS_NULL);
}

/* Parse PEM or DER certificate data into a new X509. */
static X509 *tjs_ssl_certificate_parse(const unsigned char *data, size_t length) {
    BIO *input = BIO_new_mem_buf(data, (int)length);
    if (!input) return NULL;
    ERR_clear_error();
    X509 *certificate = PEM_read_bio_X509(input, NULL, NULL, NULL);
    BIO_free(input);
    if (certificate) return certificate;
    ERR_clear_error();
    const unsigned char *cursor = data;
    return d2i_X509(NULL, &cursor, (long)length);
}

static JSValue tjs_ssl_certificate_constructor(JSContext *ctx, JSValueConst new_target,
                                               int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "certificate data is required");
    size_t length;
    const unsigned char *data = JS_GetAnyBuffer(ctx, &length, argv[0]);
    if (!data)
        return JS_HasException(ctx) ? JS_EXCEPTION : tjs_ssl_certificate_error(ctx, "invalid certificate data");
    if (length == 0 || length > INT_MAX)
        return tjs_ssl_certificate_error(ctx, "invalid certificate data");

    X509 *certificate = tjs_ssl_certificate_parse(data, length);
    if (!certificate) return tjs_ssl_certificate_error(ctx, "invalid X.509 certificate");

    JSValue prototype = JS_GetPropertyStr(ctx, new_target, "prototype");
    if (JS_IsException(prototype)) {
        X509_free(certificate);
        return JS_EXCEPTION;
    }
    JSValue result = tjs_ssl_certificate_new(ctx, certificate, prototype);
    JS_FreeValue(ctx, prototype);
    return result;
}

static JSValue tjs_ssl_certificate_bio_string(JSContext *ctx, BIO *output) {
    char *data;
    long length = BIO_get_mem_data(output, &data);
    return JS_NewStringLen(ctx, data, length > 0 ? (size_t)length : 0);
}

static int tjs_ssl_certificate_set_name(JSContext *ctx, JSValue target, const char *key,
                                        X509_NAME *name, BIO *output) {
    BIO_reset(output);
    if (X509_NAME_print_ex(output, name, 0,
            ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_UTF8_CONVERT |
            XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_SN) < 0) {
        tjs_ssl_certificate_error(ctx, "cannot format certificate name");
        return -1;
    }
    return JS_SetPropertyStr(ctx, target, key, tjs_ssl_certificate_bio_string(ctx, output));
}

static int tjs_ssl_certificate_print_alt_name(BIO *output, const unsigned char *data,
                                               size_t length, bool utf8) {
    if ((!data && length) || length > INT_MAX) return 0;
    bool quote = false;
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = data[index];
        if (byte < 32 || byte == 127 || (!utf8 && byte > 126) ||
            byte == ',' || byte == '"' || byte == '\\' || byte == '\'') {
            quote = true;
            break;
        }
    }
    if (!quote) return length == 0 || BIO_write(output, data, (int)length) == (int)length;
    if (BIO_puts(output, "\"") <= 0) return 0;
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = data[index];
        if (byte == '"' || byte == '\\') {
            if (BIO_printf(output, "\\%c", byte) <= 0) return 0;
        } else if (byte < 32 || byte == 127 || (!utf8 && byte > 126) || byte == ',') {
            if (BIO_printf(output, "\\u%04x", byte) <= 0) return 0;
        } else if (BIO_write(output, data + index, 1) != 1) {
            return 0;
        }
    }
    return BIO_puts(output, "\"") > 0;
}

static const unsigned char *tjs_ssl_certificate_asn1_bytes(const ASN1_STRING *value, size_t *length) {
    if (!value) return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    *length = ASN1_STRING_get_length(value);
#else
    int size = ASN1_STRING_length(value);
    if (size < 0) return NULL;
    *length = (size_t)size;
#endif
    return ASN1_STRING_get0_data(value);
}

static int tjs_ssl_certificate_print_name(BIO *output, const GENERAL_NAME *name) {
    if (!name) return 0;
    const ASN1_STRING *value = NULL;
    const char *prefix = NULL;
    switch (name->type) {
        case GEN_DNS: value = name->d.dNSName; prefix = "DNS:"; break;
        case GEN_EMAIL: value = name->d.rfc822Name; prefix = "email:"; break;
        case GEN_URI: value = name->d.uniformResourceIdentifier; prefix = "URI:"; break;
        case GEN_DIRNAME: {
            if (!name->d.dirn || BIO_puts(output, "DirName:") <= 0) return 0;
            BIO *directory = BIO_new(BIO_s_mem());
            if (!directory) return 0;
            int status = X509_NAME_print_ex(directory, name->d.dirn, 0,
                XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB & ~ASN1_STRFLGS_ESC_CTRL);
            char *data;
            long length = BIO_get_mem_data(directory, &data);
            int result = status >= 0 && length >= 0 && length <= INT_MAX &&
                tjs_ssl_certificate_print_alt_name(output, (const unsigned char *)data, (size_t)length, true);
            BIO_free(directory);
            return result;
        }
        case GEN_IPADD: {
            size_t length;
            const unsigned char *address = tjs_ssl_certificate_asn1_bytes(name->d.iPAddress, &length);
            if (!address || (length != 4 && length != 16)) return 0;
            if (BIO_puts(output, "IP Address:") <= 0) return 0;
            for (size_t index = 0; index < length; index += length == 4 ? 1 : 2) {
                int status = length == 4
                    ? BIO_printf(output, index ? ".%u" : "%u", address[index])
                    : BIO_printf(output, index ? ":%X" : "%X", address[index] * 256 + address[index + 1]);
                if (status <= 0) return 0;
            }
            return 1;
        }
        case GEN_RID: {
            char oid[128];
            int length = OBJ_obj2txt(oid, sizeof(oid), name->d.registeredID, 1);
            return length > 0 && (size_t)length < sizeof(oid) &&
                BIO_puts(output, "Registered ID:") > 0 && BIO_write(output, oid, length) == length;
        }
        case GEN_OTHERNAME: return BIO_puts(output, "othername:<unsupported>") > 0;
        case GEN_X400: return BIO_puts(output, "X400Name:<unsupported>") > 0;
        case GEN_EDIPARTY: return BIO_puts(output, "EdiPartyName:<unsupported>") > 0;
        default: return 0;
    }
    if (!value || BIO_puts(output, prefix) <= 0) return 0;
    size_t length;
    const unsigned char *data = tjs_ssl_certificate_asn1_bytes(value, &length);
    return data && tjs_ssl_certificate_print_alt_name(output, data, length, false);
}

static int tjs_ssl_certificate_set_extension(JSContext *ctx, JSValue target, const char *key,
                                             X509 *certificate, int nid, BIO *output) {
    if (X509_get_ext_by_NID(certificate, nid, -1) < 0) return 0;
    BIO_reset(output);
    bool valid = true;
    if (nid == NID_subject_alt_name) {
        GENERAL_NAMES *names = X509_get_ext_d2i(certificate, nid, NULL, NULL);
        int count = names ? sk_GENERAL_NAME_num(names) : 0;
        valid = count > 0;
        for (int index = 0; valid && index < count; index++) {
            valid = (!index || BIO_puts(output, ", ") > 0) &&
                tjs_ssl_certificate_print_name(output, sk_GENERAL_NAME_value(names, index));
        }
        GENERAL_NAMES_free(names);
    } else {
        AUTHORITY_INFO_ACCESS *entries = X509_get_ext_d2i(certificate, nid, NULL, NULL);
        int count = entries ? sk_ACCESS_DESCRIPTION_num(entries) : 0;
        valid = count > 0;
        for (int index = 0; valid && index < count; index++) {
            ACCESS_DESCRIPTION *entry = sk_ACCESS_DESCRIPTION_value(entries, index);
            if (!entry || !entry->method || !entry->location) {
                valid = false;
                break;
            }
            char method[128];
            int length = OBJ_obj2txt(method, sizeof(method), entry->method, 0);
            valid = length > 0 && (size_t)length < sizeof(method) &&
                (!index || BIO_puts(output, "\n") > 0) &&
                BIO_write(output, method, length) == length &&
                BIO_puts(output, " - ") > 0 && tjs_ssl_certificate_print_name(output, entry->location);
        }
        AUTHORITY_INFO_ACCESS_free(entries);
    }
    if (!valid) {
        tjs_ssl_certificate_error(ctx, "invalid or unsupported certificate name extension");
        return -1;
    }
    return JS_SetPropertyStr(ctx, target, key, tjs_ssl_certificate_bio_string(ctx, output));
}

static JSValue tjs_ssl_certificate_build_info(JSContext *ctx, X509 *certificate) {
    BIO *output = BIO_new(BIO_s_mem());
    if (!output) return JS_ThrowOutOfMemory(ctx);
    JSValue result = JS_NewObject(ctx);
    if (JS_IsException(result)) goto fail;

    if (tjs_ssl_certificate_set_name(ctx, result, "subject", X509_get_subject_name(certificate), output) < 0 ||
        tjs_ssl_certificate_set_name(ctx, result, "issuer", X509_get_issuer_name(certificate), output) < 0 ||
        tjs_ssl_certificate_set_extension(ctx, result, "subjectAltName", certificate, NID_subject_alt_name, output) < 0 ||
        tjs_ssl_certificate_set_extension(ctx, result, "infoAccess", certificate, NID_info_access, output) < 0 ||
        JS_SetPropertyStr(ctx, result, "ca", JS_NewBool(ctx, X509_check_ca(certificate) == 1)) < 0)
        goto fail;

    const ASN1_TIME *times[] = { X509_get0_notBefore(certificate), X509_get0_notAfter(certificate) };
    const char *time_names[] = { "validFrom", "validTo" };
    const char *millis_names[] = { "validFromMs", "validToMs" };
    ASN1_TIME *epoch = ASN1_TIME_set(NULL, 0);
    if (!epoch) {
        JS_ThrowOutOfMemory(ctx);
        goto fail;
    }
    for (int index = 0; index < 2; index++) {
        int days, seconds;
        BIO_reset(output);
        if (!ASN1_TIME_print(output, times[index]) ||
            !ASN1_TIME_diff(&days, &seconds, epoch, times[index])) {
            ASN1_TIME_free(epoch);
            tjs_ssl_certificate_error(ctx, "invalid certificate validity time");
            goto fail;
        }
        if (JS_SetPropertyStr(ctx, result, time_names[index], tjs_ssl_certificate_bio_string(ctx, output)) < 0 ||
            JS_SetPropertyStr(ctx, result, millis_names[index],
                JS_NewFloat64(ctx, ((double)days * 86400 + seconds) * 1000)) < 0) {
            ASN1_TIME_free(epoch);
            goto fail;
        }
    }
    ASN1_TIME_free(epoch);

    BIGNUM *serial = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), NULL);
    char *serial_text = serial ? BN_bn2hex(serial) : NULL;
    BN_free(serial);
    if (!serial_text) {
        JS_ThrowOutOfMemory(ctx);
        goto fail;
    }
    int status = JS_SetPropertyStr(ctx, result, "serialNumber", JS_NewString(ctx, serial_text));
    OPENSSL_free(serial_text);
    if (status < 0) goto fail;

    EXTENDED_KEY_USAGE *usage = X509_get_ext_d2i(certificate, NID_ext_key_usage, NULL, NULL);
    if (usage) {
        JSValue values = JS_NewArray(ctx);
        if (JS_IsException(values)) {
            EXTENDED_KEY_USAGE_free(usage);
            goto fail;
        }
        for (int index = 0; index < sk_ASN1_OBJECT_num(usage); index++) {
            char oid[128];
            int length = OBJ_obj2txt(oid, sizeof(oid), sk_ASN1_OBJECT_value(usage, index), 1);
            if (length <= 0 || (size_t)length >= sizeof(oid) ||
                JS_SetPropertyUint32(ctx, values, index, JS_NewStringLen(ctx, oid, length)) < 0) {
                EXTENDED_KEY_USAGE_free(usage);
                JS_FreeValue(ctx, values);
                if (!JS_HasException(ctx)) tjs_ssl_certificate_error(ctx, "invalid certificate key usage");
                goto fail;
            }
        }
        EXTENDED_KEY_USAGE_free(usage);
        if (JS_SetPropertyStr(ctx, result, "keyUsage", values) < 0) goto fail;
    }
    const ASN1_OBJECT *signature;
    X509_ALGOR_get0(&signature, NULL, NULL, X509_get0_tbs_sigalg(certificate));
    char oid[128];
    int length = OBJ_obj2txt(oid, sizeof(oid), signature, 1);
    if (length > 0 && (size_t)length < sizeof(oid) &&
        JS_SetPropertyStr(ctx, result, "signatureAlgorithmOid", JS_NewStringLen(ctx, oid, length)) < 0)
        goto fail;
    const char *signature_name = OBJ_nid2ln(OBJ_obj2nid(signature));
    if (signature_name && JS_SetPropertyStr(ctx, result, "signatureAlgorithm", JS_NewString(ctx, signature_name)) < 0)
        goto fail;

    BIO_free(output);
    return result;
fail:
    BIO_free(output);
    JS_FreeValue(ctx, result);
    return JS_EXCEPTION;
}

/* `info` is rebuilt on each access so a caller can mutate the returned object
 * and arrays without affecting later reads. */
static JSValue tjs_ssl_certificate_info(JSContext *ctx, JSValueConst this_val) {
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) return JS_EXCEPTION;
    return tjs_ssl_certificate_build_info(ctx, cert->x509);
}

/* PEM encoding; also used to accept a Certificate where a PEM string is
 * expected (see the SSLContext constructor). */
static JSValue tjs_ssl_certificate_to_pem(JSContext *ctx, JSValueConst this_val) {
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) return JS_EXCEPTION;
    BIO *output = BIO_new(BIO_s_mem());
    if (!output) return JS_ThrowOutOfMemory(ctx);
    if (!PEM_write_bio_X509(output, cert->x509)) {
        BIO_free(output);
        return tjs_ssl_certificate_error(ctx, "cannot encode certificate");
    }
    JSValue result = tjs_ssl_certificate_bio_string(ctx, output);
    BIO_free(output);
    return result;
}

/* `raw` (DER) and `publicKey` (SPKI DER) as ArrayBuffers. */
static JSValue tjs_ssl_certificate_encode(JSContext *ctx, JSValueConst this_val, int magic) {
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) return JS_EXCEPTION;
    X509 *certificate = cert->x509;
    unsigned char *data = NULL;
    int length;
    bool public_key = magic == 1;
    if (public_key) {
        EVP_PKEY *key = X509_get_pubkey(certificate);
        if (!key) return tjs_ssl_certificate_error(ctx, "invalid certificate public key");
        length = i2d_PUBKEY(key, &data);
        EVP_PKEY_free(key);
    } else {
        length = i2d_X509(certificate, &data);
    }
    if (length <= 0) {
        OPENSSL_free(data);
        return tjs_ssl_certificate_error(ctx, public_key
            ? "cannot encode certificate public key" : "cannot encode certificate");
    }
    JSValue result = JS_NewArrayBufferCopy(ctx, data, length);
    OPENSSL_free(data);
    return result;
}

/* Digest getters: Node exposes fingerprint / fingerprint256 / fingerprint512
 * as properties, not a fingerprint(algorithm) method. */
static JSValue tjs_ssl_certificate_fingerprint(JSContext *ctx, JSValueConst this_val, int magic) {
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) return JS_EXCEPTION;
    const EVP_MD *digest = magic == 0 ? EVP_sha1() : magic == 1 ? EVP_sha256() : EVP_sha512();
    unsigned char bytes[EVP_MAX_MD_SIZE];
    unsigned int length;
    if (!X509_digest(cert->x509, digest, bytes, &length))
        return tjs_ssl_certificate_error(ctx, "cannot digest certificate");
    char result[EVP_MAX_MD_SIZE * 3];
    static const char hex[] = "0123456789ABCDEF";
    for (unsigned int index = 0; index < length; index++) {
        result[index * 3] = hex[bytes[index] >> 4];
        result[index * 3 + 1] = hex[bytes[index] & 15];
        result[index * 3 + 2] = ':';
    }
    return JS_NewStringLen(ctx, result, length ? length * 3 - 1 : 0);
}

static int tjs_ssl_certificate_check_flags(JSContext *ctx, JSValueConst options, bool host,
                                           unsigned int *flags) {
    *flags = 0;
    if (JS_IsUndefined(options)) return 0;
    if (!JS_IsObject(options)) {
        JS_ThrowTypeError(ctx, "certificate check options must be an object");
        return -1;
    }
    JSValue subject = JS_GetPropertyStr(ctx, options, "subject");
    if (JS_IsException(subject)) return -1;
    if (!JS_IsUndefined(subject)) {
        if (!JS_IsString(subject)) {
            JS_FreeValue(ctx, subject);
            JS_ThrowTypeError(ctx, "certificate subject option must be a string");
            return -1;
        }
        const char *mode = JS_ToCString(ctx, subject);
        JS_FreeValue(ctx, subject);
        if (!mode) return -1;
        if (strcmp(mode, "always") == 0) *flags |= X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
        else if (strcmp(mode, "never") == 0) *flags |= X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;
        else if (strcmp(mode, "default") != 0) {
            JS_FreeCString(ctx, mode);
            JS_ThrowTypeError(ctx, "invalid certificate subject option");
            return -1;
        }
        JS_FreeCString(ctx, mode);
    } else {
        JS_FreeValue(ctx, subject);
    }
    if (!host) return 0;
    const char *names[] = { "wildcards", "partialWildcards", "multiLabelWildcards", "singleLabelSubdomains" };
    const unsigned int masks[] = { X509_CHECK_FLAG_NO_WILDCARDS, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
        X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS, X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS };
    for (int index = 0; index < 4; index++) {
        JSValue value = JS_GetPropertyStr(ctx, options, names[index]);
        if (JS_IsException(value)) return -1;
        if (!JS_IsUndefined(value)) {
            if (!JS_IsBool(value)) {
                JS_FreeValue(ctx, value);
                JS_ThrowTypeError(ctx, "%s must be a boolean", names[index]);
                return -1;
            }
            if ((JS_ToBool(ctx, value) != 0) == (index >= 2)) *flags |= masks[index];
        }
        JS_FreeValue(ctx, value);
    }
    return 0;
}

static JSValue tjs_ssl_certificate_check_name(JSContext *ctx, JSValueConst this_val,
                                              int argc, JSValueConst *argv, int magic) {
    if (argc < 1 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "certificate name must be a string");
    unsigned int flags = 0;
    if (magic != 2 && tjs_ssl_certificate_check_flags(ctx, argc > 1 ? argv[1] : JS_UNDEFINED, magic == 0, &flags) < 0)
        return JS_EXCEPTION;
    size_t length;
    const char *name = JS_ToCStringLen(ctx, &length, argv[0]);
    if (!name) return JS_EXCEPTION;
    if (memchr(name, 0, length)) {
        JS_FreeCString(ctx, name);
        return tjs_ssl_certificate_name_error(ctx, "certificate name contains a null byte");
    }
    unsigned char address[16];
    size_t address_length = 0;
    if (magic == 2) {
        if (uv_inet_pton(AF_INET, name, address) == 0) address_length = 4;
        else if (uv_inet_pton(AF_INET6, name, address) == 0) address_length = 16;
        else {
            JS_FreeCString(ctx, name);
            return tjs_ssl_certificate_name_error(ctx, "invalid certificate IP address");
        }
    }
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) {
        JS_FreeCString(ctx, name);
        return JS_EXCEPTION;
    }
    char *matched = NULL;
    int status = magic == 0 ? X509_check_host(cert->x509, name, length, flags, &matched) :
        magic == 1 ? X509_check_email(cert->x509, name, length, flags) :
        X509_check_ip(cert->x509, address, address_length, 0);
    JSValue result = status == 1 ? JS_NewString(ctx, matched ? matched : name) : JS_UNDEFINED;
    OPENSSL_free(matched);
    JS_FreeCString(ctx, name);
    if (status < 0) return tjs_ssl_certificate_name_error(ctx, "invalid certificate name");
    return result;
}

static JSValue tjs_ssl_certificate_check_issued(JSContext *ctx, JSValueConst this_val,
                                                 int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "issuer certificate is required");
    TJSSSLCertificate *issuer = tjs_ssl_certificate_get(ctx, argv[0]);
    if (!issuer) return JS_EXCEPTION;
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) return JS_EXCEPTION;
    return JS_NewBool(ctx, X509_check_issued(issuer->x509, cert->x509) == X509_V_OK);
}

static JSValue tjs_ssl_certificate_check_key(JSContext *ctx, JSValueConst this_val,
                                             int argc, JSValueConst *argv, int private_key) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "key data is required");
    size_t length;
    const unsigned char *data = JS_GetAnyBuffer(ctx, &length, argv[0]);
    if (!data)
        return JS_HasException(ctx) ? JS_EXCEPTION : tjs_ssl_certificate_error(ctx, "invalid key data");
    if (length == 0 || length > LONG_MAX) return tjs_ssl_certificate_error(ctx, "invalid key data");
    const unsigned char *cursor = data;
    ERR_clear_error();
    EVP_PKEY *key = private_key ? d2i_AutoPrivateKey(NULL, &cursor, (long)length) :
        d2i_PUBKEY(NULL, &cursor, (long)length);
    if (!key) return tjs_ssl_certificate_error(ctx, "invalid DER key data");
    TJSSSLCertificate *cert = tjs_ssl_certificate_get(ctx, this_val);
    if (!cert) {
        EVP_PKEY_free(key);
        return JS_EXCEPTION;
    }
    int status = private_key ? X509_check_private_key(cert->x509, key) : X509_verify(cert->x509, key);
    EVP_PKEY_free(key);
    ERR_clear_error();
    return JS_NewBool(ctx, status == 1);
}

static const JSCFunctionListEntry tjs_ssl_certificate_proto_funcs[] = {
    JS_CGETSET_DEF("info", tjs_ssl_certificate_info, NULL),
    JS_CGETSET_MAGIC_DEF("raw", tjs_ssl_certificate_encode, NULL, 0),
    JS_CGETSET_MAGIC_DEF("publicKey", tjs_ssl_certificate_encode, NULL, 1),
    JS_CGETSET_DEF("pem", tjs_ssl_certificate_to_pem, NULL),
    JS_CGETSET_MAGIC_DEF("fingerprint", tjs_ssl_certificate_fingerprint, NULL, 0),
    JS_CGETSET_MAGIC_DEF("fingerprint256", tjs_ssl_certificate_fingerprint, NULL, 1),
    JS_CGETSET_MAGIC_DEF("fingerprint512", tjs_ssl_certificate_fingerprint, NULL, 2),
    JS_CFUNC_MAGIC_DEF("checkHost", 2, tjs_ssl_certificate_check_name, 0),
    JS_CFUNC_MAGIC_DEF("checkEmail", 2, tjs_ssl_certificate_check_name, 1),
    JS_CFUNC_MAGIC_DEF("checkIP", 1, tjs_ssl_certificate_check_name, 2),
    JS_CFUNC_DEF("checkIssued", 1, tjs_ssl_certificate_check_issued),
    JS_CFUNC_MAGIC_DEF("verify", 1, tjs_ssl_certificate_check_key, 0),
    JS_CFUNC_MAGIC_DEF("checkPrivateKey", 1, tjs_ssl_certificate_check_key, 1),
};

#pragma endregion Certificate

#pragma region SSLPipe
typedef struct {
    JSContext *ctx;
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
    TJSSSLContext *ssl_context;
	JSValue ssl_obj;	// hold reference to SSL object
    TJSSSLHandshakeState handshake_state;
    bool handshake_capability_checked;
    bool handshake_capability_checking;
    bool is_server;
    char *hostname;
} TJSSSLPipe;

static JSClassID tjs_ssl_pipe_class_id;

static void tjs_ssl_pipe_finalizer(JSRuntime *rt, JSValue val) {
    TJSSSLPipe *pipe = JS_GetOpaque(val, tjs_ssl_pipe_class_id);
    if (pipe) {
        if (pipe->ssl) {
            SSL_free(pipe->ssl);
        }
        /* BIOs are freed by SSL_free */
        if (pipe->hostname) {
            js_free_rt(rt, pipe->hostname);
        }
        /* Release ssl_obj BEFORE freeing pipe to avoid UAF. */
        JS_FreeValueRT(rt, pipe->ssl_obj);
        js_free_rt(rt, pipe);
    }
}

void tjs_ssl_pipe_gc_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    TJSSSLPipe *pipe = JS_GetOpaque(val, tjs_ssl_pipe_class_id);
    if (pipe && pipe->ssl) {
		JS_MarkValue(rt, pipe->ssl_obj, mark_func);
    }
}

static JSClassDef tjs_ssl_pipe_class = {
    "SSLPipe",
    .finalizer = tjs_ssl_pipe_finalizer,
	.gc_mark = tjs_ssl_pipe_gc_mark,
};

/* new SSLPipe(sslContext, options) */
static JSValue tjs_ssl_pipe_constructor(JSContext *ctx, JSValueConst new_target,
                                         int argc, JSValueConst *argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "SSLContext is required");
    }
    TJSSSLContext *ssl_context = JS_GetOpaque2(ctx, argv[0], tjs_ssl_context_class_id);
    if (!ssl_context) {
        return JS_ThrowTypeError(ctx, "First argument must be SSLContext");
    }
    
    JSValue obj = JS_NewObjectClass(ctx, tjs_ssl_pipe_class_id);
    if (JS_IsException(obj)) return obj;
    
    TJSSSLPipe *pipe = js_mallocz(ctx, sizeof(*pipe));
    if (!pipe) {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    
    pipe->ctx = ctx;
    pipe->ssl_context = ssl_context;
    pipe->ssl_obj = JS_DupValue(ctx, argv[0]);
	pipe->handshake_state = TJS_SSL_HANDSHAKE_NONE;
    pipe->is_server = (ssl_context->mode == TJS_SSL_MODE_SERVER);
    
    /* Create SSL object */
    pipe->ssl = SSL_new(ssl_context->ssl_ctx);
    if (!pipe->ssl) {
        JS_FreeValue(ctx, pipe->ssl_obj);
        js_free(ctx, pipe);
        JS_FreeValue(ctx, obj);
        SSL_THROW_ERROR(ctx, "SSL_new");
    }

    /* Create BIO pair for memory-based I/O */
    pipe->rbio = BIO_new(BIO_s_mem());
    pipe->wbio = BIO_new(BIO_s_mem());
    if (!pipe->rbio || !pipe->wbio) {
        if (pipe->rbio) BIO_free(pipe->rbio);
        if (pipe->wbio) BIO_free(pipe->wbio);
        SSL_free(pipe->ssl);
        JS_FreeValue(ctx, pipe->ssl_obj);
        js_free(ctx, pipe);
        JS_FreeValue(ctx, obj);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    SSL_set_bio(pipe->ssl, pipe->rbio, pipe->wbio);
    
    /* Set server/client mode */
    if (pipe->is_server) {
        SSL_set_accept_state(pipe->ssl);
    } else {
        SSL_set_connect_state(pipe->ssl);
        
        /* Parse options for client */
        if (argc > 1 && JS_IsObject(argv[1])) {
            JSValue hostname_val = JS_GetPropertyStr(ctx, argv[1], "servername");
            const char *hostname = cstr(ctx, hostname_val);
            if (hostname) {
                pipe->hostname = js_strdup(ctx, hostname);
                SSL_set_tlsext_host_name(pipe->ssl, hostname);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                if (ssl_context->verify_hostname) {
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
                    SSL_set1_dnsname(pipe->ssl, hostname);
#else
                    SSL_set1_host(pipe->ssl, hostname);
#endif
                }
#endif
                JS_FreeCString(ctx, hostname);
            }
            JS_FreeValue(ctx, hostname_val);
        }
    }
    
    JS_SetOpaque(obj, pipe);
    return obj;
}

/* pipe.feed(data) - Feed encrypted data to SSL engine */
static JSValue tjs_ssl_pipe_feed(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "encrypted data is required");
    
    size_t size;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &size, argv[0]);
    if (!buf) return JS_EXCEPTION;

    /* Clamp to INT_MAX to prevent truncation */
    if (size > INT_MAX) size = INT_MAX;
    int ret = BIO_write(pipe->rbio, buf, (int)size);
    return JS_NewInt32(ctx, ret);
}

static JSValue tjs_ssl_pipe_handshake_capability(JSContext *ctx,
                                                  JSValueConst this_val,
                                                  TJSSSLPipe **pipe_ptr,
                                                  const char *api) {
    TJSSSLPipe *pipe = *pipe_ptr;
    if (pipe->handshake_capability_checked) return TJS_CAPABILITY_PASS;
    if (pipe->handshake_capability_checking) {
        return JS_ThrowTypeError(ctx, "reentrant SSL handshake capability check");
    }

    /* Nested-hook bypass must not mark this pipe as capability-checked. */
    pipe->handshake_capability_checking = true;
    JSValue result = tjs__capability(ctx, TJS_CAP_OS | TJS_CAP_IO_READ,
                                     TJS_CAP_FLAG_REPLACEABLE, api);
    pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) {
        if (!JS_IsUninitialized(result) && !JS_IsException(result)) {
            JS_FreeValue(ctx, result);
        }
        return JS_EXCEPTION;
    }

    pipe->handshake_capability_checking = false;
    *pipe_ptr = pipe;
    if (JS_IsUninitialized(result)) {
        pipe->handshake_capability_checked = true;
    }
    return result;
}

/* pipe.read(size) - Read decrypted data */
static JSValue tjs_ssl_pipe_read(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;

    int32_t size = 16384;
    if (argc > 0) {
        if (JS_ToInt32(ctx, &size, argv[0]) < 0) {
            return JS_EXCEPTION;
        }
        /* Validate size range */
        if (size <= 0 || size > 1048576) {
            return JS_ThrowRangeError(ctx, "size must be between 1 and 1048576");
        }
    }

    TJS_CAPABILITY(tjs_ssl_pipe_handshake_capability(ctx, this_val, &pipe, "ssl.read"), (void)0);

    uint8_t *buf = js_malloc(ctx, size);
    if (!buf) return JS_EXCEPTION;

    int ret = SSL_read(pipe->ssl, buf, size);
    
    if (ret > 0) {
        JSValue result = JS_NewArrayBufferCopy(ctx, buf, ret);
        js_free(ctx, buf);
        return result;
    } else {
        js_free(ctx, buf);
        int err = SSL_get_error(pipe->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_ZERO_RETURN) {
            return JS_NULL;
        }
        SSL_THROW_ERROR(ctx, "SSL_read");
    }
}

/* pipe.write(data) - Write plaintext data to be encrypted */
static JSValue tjs_ssl_pipe_write(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "plaintext data is required");
    
    size_t size;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &size, argv[0]);
    if (!buf) return JS_EXCEPTION;

    TJS_CAPABILITY_REVALIDATE(tjs_ssl_pipe_handshake_capability(ctx, this_val, &pipe, "ssl.write"), (void)0, do { buf = JS_GetAnyBuffer(ctx, &size, argv[0]); if (!buf) return JS_EXCEPTION; } while (0));

    /* Clamp to INT_MAX to prevent truncation */
    if (size > INT_MAX) size = INT_MAX;
    int ret = SSL_write(pipe->ssl, buf, (int)size);

    if (ret > 0) {
        return JS_NewInt32(ctx, ret);
    } else {
		CHECK_SSL_ERR(pipe->ssl, ret);
		SSL_THROW_ERROR(ctx, "SSL_write");
    }
}

/* pipe.getOutput() - Get encrypted data to send */
static JSValue tjs_ssl_pipe_get_output(JSContext *ctx, JSValueConst this_val,
                                        int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    int pending = BIO_ctrl_pending(pipe->wbio);
    if (pending <= 0) {
        return JS_NULL;
    }
    
    uint8_t *buf = js_malloc(ctx, pending);
    if (!buf) return JS_EXCEPTION;
    
    int ret = BIO_read(pipe->wbio, buf, pending);
    if (ret > 0) {
        JSValue result = JS_NewArrayBufferCopy(ctx, buf, ret);
        js_free(ctx, buf);
        return result;
    }
    
    js_free(ctx, buf);
    return JS_NULL;
}

/* pipe.handshake() - Perform handshake step */
static JSValue tjs_ssl_pipe_do_handshake(JSContext *ctx, JSValueConst this_val,
                                          int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    if (pipe->handshake_state == TJS_SSL_HANDSHAKE_DONE) {
        return JS_NewBool(ctx, true);
    }

    TJS_CAPABILITY(tjs_ssl_pipe_handshake_capability(ctx, this_val, &pipe, "ssl.handshake"), (void)0);
    
    pipe->handshake_state = TJS_SSL_HANDSHAKE_IN_PROGRESS;
    
    int ret = SSL_do_handshake(pipe->ssl);
    
    if (ret == 1) {
        pipe->handshake_state = TJS_SSL_HANDSHAKE_DONE;
        return JS_NewBool(ctx, true);
    }
    
    int err = SSL_get_error(pipe->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return JS_NewBool(ctx, false);
    }
    
    pipe->handshake_state = TJS_SSL_HANDSHAKE_ERROR;
	SSL_THROW_ERROR(ctx, "SSL_do_handshake");
}

/* pipe.shutdown() - Shutdown SSL connection */
static JSValue tjs_ssl_pipe_shutdown(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    int ret = SSL_shutdown(pipe->ssl);
    return JS_NewInt32(ctx, ret);
}

/* pipe.certificate() - Get the peer certificate as a Certificate instance */
static JSValue tjs_ssl_pipe_get_peer_certificate(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    return tjs_ssl_certificate_wrap(ctx, SSL_get_peer_certificate(pipe->ssl));
}

/* pipe.version() - Get SSL/TLS version */
static JSValue tjs_ssl_pipe_get_version(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    const char *version = SSL_get_version(pipe->ssl);
    return JS_NewString(ctx, version);
}

/* pipe.cipher() - Get current cipher */
static JSValue tjs_ssl_pipe_get_cipher(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    const SSL_CIPHER *cipher = SSL_get_current_cipher(pipe->ssl);
    if (!cipher) {
        return JS_NULL;
    }
    
    JSValue cipher_obj = JS_NewObject(ctx);
    
    const char *name = SSL_CIPHER_get_name(cipher);
    if (name) {
        JS_SetPropertyStr(ctx, cipher_obj, "name", JS_NewString(ctx, name));
    }
    
    const char *version = SSL_CIPHER_get_version(cipher);
    if (version) {
        JS_SetPropertyStr(ctx, cipher_obj, "version", JS_NewString(ctx, version));
    }
    
    int bits = SSL_CIPHER_get_bits(cipher, NULL);
    JS_SetPropertyStr(ctx, cipher_obj, "bits", JS_NewInt32(ctx, bits));
    
    return cipher_obj;
}

/* pipe.alpnProtocol() - Get negotiated ALPN protocol */
static JSValue tjs_ssl_pipe_get_alpn_protocol(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    const unsigned char *data;
    unsigned int len;
    
    SSL_get0_alpn_selected(pipe->ssl, &data, &len);
    
    if (len > 0) {
        return JS_NewStringLen(ctx, (const char *)data, len);
    }
    
    return JS_NULL;
}

/* pipe.verifyResult() - Get certificate verification result */
static JSValue tjs_ssl_pipe_verify_result(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    long result = SSL_get_verify_result(pipe->ssl);
    
    JSValue result_obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result_obj, "code", JS_NewInt32(ctx, result));
    JS_SetPropertyStr(ctx, result_obj, "ok", JS_NewBool(ctx, result == X509_V_OK));
    
    const char *error_str = X509_verify_cert_error_string(result);
    if (error_str) {
        JS_SetPropertyStr(ctx, result_obj, "error", JS_NewString(ctx, error_str));
    }
    
    return result_obj;
}

/* Getter: pipe.handshakeComplete */
static JSValue tjs_ssl_pipe_get_handshake_complete(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    return JS_NewBool(ctx, pipe->handshake_state == TJS_SSL_HANDSHAKE_DONE);
}

/* Getter: pipe.isServer */
static JSValue tjs_ssl_pipe_get_is_server(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    return JS_NewBool(ctx, pipe->is_server);
}

static const JSCFunctionListEntry tjs_ssl_pipe_proto_funcs[] = {
    JS_CFUNC_DEF("feed", 1, tjs_ssl_pipe_feed),
	JS_CFUNC_DEF("getOutput", 0, tjs_ssl_pipe_get_output),
    
	JS_CFUNC_DEF("read", 1, tjs_ssl_pipe_read),
    JS_CFUNC_DEF("write", 1, tjs_ssl_pipe_write),
    
    JS_CFUNC_DEF("handshake", 0, tjs_ssl_pipe_do_handshake),
    JS_CFUNC_DEF("shutdown", 0, tjs_ssl_pipe_shutdown),
	
    JS_CGETSET_DEF("certificate", tjs_ssl_pipe_get_peer_certificate, NULL),
    JS_CGETSET_DEF("version", tjs_ssl_pipe_get_version, NULL),
    JS_CGETSET_DEF("cipher", tjs_ssl_pipe_get_cipher, NULL),
    JS_CGETSET_DEF("alpnProtocol", tjs_ssl_pipe_get_alpn_protocol, NULL),
    JS_CGETSET_DEF("verifyResult", tjs_ssl_pipe_verify_result, NULL),
    JS_CGETSET_DEF("handshakeComplete", tjs_ssl_pipe_get_handshake_complete, NULL),
    JS_CGETSET_DEF("isServer", tjs_ssl_pipe_get_is_server, NULL),
};

#pragma region Utility Functions
/* getOpenSSLVersion() */
static int tjs_ssl_static_version(JSContext *ctx, JSValueConst ns) {
    return JS_SetPropertyStr(ctx, ns, "version", JS_NewString(ctx, OpenSSL_version(OPENSSL_VERSION)));
}

/* cipherList() */
static int tjs_ssl_static_ciphers(JSContext *ctx, JSValueConst ns) {
    SSL_CTX *tmp_ctx = SSL_CTX_new(TLS_method());
    if (!tmp_ctx) {
        return JS_SetPropertyStr(ctx, ns, "ciphers", JS_NewArray(ctx));
    }
    
    SSL *tmp_ssl = SSL_new(tmp_ctx);
    if (!tmp_ssl) {
        SSL_CTX_free(tmp_ctx);
		return JS_SetPropertyStr(ctx, ns, "ciphers", JS_NewArray(ctx));
    }
    
    JSValue arr = JS_NewArray(ctx);
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(tmp_ssl);
    int count = sk_SSL_CIPHER_num(ciphers);
    
    for (int i = 0; i < count; i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        const char *name = SSL_CIPHER_get_name(cipher);
        JS_SetPropertyUint32(ctx, arr, i, JS_NewString(ctx, name));
    }
    
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    
    return JS_SetPropertyStr(ctx, ns, "ciphers", arr);
}

/* loadPEM(data, type) - Load certificate or key from PEM */
static JSValue tjs_ssl_static_load_pem(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "PEM data is required");
    const char *data = cstr(ctx, argv[0]);
    if (!data) return JS_ThrowTypeError(ctx, "PEM data must be a string");

    const char *type = argc > 1 ? cstr(ctx, argv[1]) : "certificate";
    if (argc > 1 && !type) {
        JS_FreeCString(ctx, data);
        return JS_ThrowTypeError(ctx, "type must be a string");
    }

    BIO *bio = BIO_new_mem_buf(data, -1);

    if (!bio) {
        JS_FreeCString(ctx, data);
        if (type != NULL && argc > 1) JS_FreeCString(ctx, type);
        return JS_ThrowOutOfMemory(ctx);
    }

    JSValue result = JS_UNDEFINED;

    if (strcmp(type, "certificate") == 0) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        result = cert ? tjs_ssl_certificate_wrap(ctx, cert) : JS_NULL;
    } else if (strcmp(type, "key") == 0) {
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey) {
            result = JS_NewObject(ctx);
            
            int key_type = EVP_PKEY_base_id(pkey);
            const char *type_str = "unknown";
            
            switch (key_type) {
                case EVP_PKEY_RSA: type_str = "RSA"; break;
                case EVP_PKEY_EC: type_str = "EC"; break;
                case EVP_PKEY_ED25519: type_str = "Ed25519"; break;
            }
            
            JS_SetPropertyStr(ctx, result, "type", JS_NewString(ctx, type_str));
            JS_SetPropertyStr(ctx, result, "bits", JS_NewInt32(ctx, EVP_PKEY_bits(pkey)));
            
            EVP_PKEY_free(pkey);
        } else {
            result = JS_NULL;
        }
    }
    
    if (argc > 1) JS_FreeCString(ctx, type);
    BIO_free(bio);
    JS_FreeCString(ctx, data);
    
    return result;
}

/* createSelfSignedCert(options) - Create self-signed certificate */
static JSValue tjs_ssl_static_create_self_signed_cert(JSContext *ctx, JSValueConst this_val,
                                                 int argc, JSValueConst *argv) {
    JSValue options = argc > 0 ? argv[0] : JS_UNDEFINED;

    /* cn_val/days_val owned; free regardless of argc; cn_owned: FreeCString. */
    JSValue cn_val = JS_IsObject(options) ? JS_GetPropertyStr(ctx, options, "commonName") : JS_UNDEFINED;
    if (JS_IsException(cn_val)) return JS_EXCEPTION;
    const char *cn = "localhost";
    bool cn_owned = false;
    if (JS_IsString(cn_val)) {
        cn = JS_ToCString(ctx, cn_val);
        if (!cn) {
            JS_FreeValue(ctx, cn_val);
            return JS_EXCEPTION;
        }
        cn_owned = true;
    }

    JSValue days_val = JS_IsObject(options) ? JS_GetPropertyStr(ctx, options, "days") : JS_UNDEFINED;
    if (JS_IsException(days_val)) {
        if (cn_owned) JS_FreeCString(ctx, cn);
        JS_FreeValue(ctx, cn_val);
        return JS_EXCEPTION;
    }
    int32_t days = 365;
    if (!JS_IsUndefined(days_val) && JS_ToInt32(ctx, &days, days_val) < 0) {
        if (cn_owned) JS_FreeCString(ctx, cn);
        JS_FreeValue(ctx, cn_val);
        JS_FreeValue(ctx, days_val);
        return JS_EXCEPTION;
    }

    TJS_CAPABILITY(tjs__capability(ctx, TJS_CAP_OS | TJS_CAP_IO_READ, TJS_CAP_FLAG_REPLACEABLE, "ssl.createSelfSignedCert"), (cn_owned ? JS_FreeCString(ctx, cn) : (void)0, JS_FreeValue(ctx, cn_val), JS_FreeValue(ctx, days_val)));
    
    /* Generate RSA key. Keep pkey NULL so EVP_PKEY_generate allocates it (passing
     * a pre-allocated EVP_PKEY leaks the original). */
    EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx) {
        if (EVP_PKEY_keygen_init(pctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0 &&
            EVP_PKEY_generate(pctx, &pkey) <= 0) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        EVP_PKEY_CTX_free(pctx);
    } else {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
#else
    pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();

    if (pkey && rsa && bne) {
        BN_set_word(bne, RSA_F4);
        if (RSA_generate_key_ex(rsa, 2048, bne, NULL) > 0) {
            EVP_PKEY_assign_RSA(pkey, rsa);
            rsa = NULL; /* ownership transferred to pkey */
        } else {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    } else {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (rsa) RSA_free(rsa);
    if (bne) BN_free(bne);
#endif
    
    /* Bail out if key generation failed (otherwise the X509_* calls below
     * dereference a NULL pkey and crash). */
    if (!pkey) {
        if (cn_owned) JS_FreeCString(ctx, cn);
        JS_FreeValue(ctx, cn_val);
        JS_FreeValue(ctx, days_val);
        return tjs_throw_plain_error(ctx, "failed to generate RSA key for self-signed certificate");
    }

    /* Create certificate */
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        if (cn_owned) JS_FreeCString(ctx, cn);
        JS_FreeValue(ctx, cn_val);
        JS_FreeValue(ctx, days_val);
        return JS_ThrowOutOfMemory(ctx);
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * days);
    X509_set_pubkey(cert, pkey);
    
    X509_NAME *name = X509_NAME_new();
    if (!name ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)cn, -1, -1, 0) ||
        !X509_set_subject_name(cert, name) ||
        !X509_set_issuer_name(cert, name)) {
        X509_NAME_free(name);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        if (cn_owned) JS_FreeCString(ctx, cn);
        JS_FreeValue(ctx, cn_val);
        JS_FreeValue(ctx, days_val);
        return tjs_throw_plain_error(ctx,
                                     "failed to set certificate subject");
    }
    X509_NAME_free(name);
    
    /* Sign certificate */
    X509_sign(cert, pkey, EVP_sha256());
    
    /* Export to PEM */
    BIO *cert_bio = BIO_new(BIO_s_mem());
    BIO *key_bio = BIO_new(BIO_s_mem());
    
    PEM_write_bio_X509(cert_bio, cert);
    PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL);
    
    char *cert_pem = NULL;
    char *key_pem = NULL;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_pem);
    long key_len = BIO_get_mem_data(key_bio, &key_pem);
    
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "cert", JS_NewStringLen(ctx, cert_pem, cert_len));
    JS_SetPropertyStr(ctx, result, "key", JS_NewStringLen(ctx, key_pem, key_len));
    
    /* Cleanup */
    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    
    if (cn_owned) JS_FreeCString(ctx, cn);
    JS_FreeValue(ctx, cn_val);
    JS_FreeValue(ctx, days_val);

    return result;
}

static const JSCFunctionListEntry tjs_ssl_static_funcs[] = {
    JS_CFUNC_DEF("loadPEM", 2, tjs_ssl_static_load_pem),
    JS_CFUNC_DEF("createSelfSignedCert", 1, tjs_ssl_static_create_self_signed_cert),
};

#pragma region Module Initialization
void tjs__mod_ssl_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);

    /* Register SSLContext */
    if (JS_NewClassID(rt, &tjs_ssl_context_class_id) == JS_INVALID_CLASS_ID) {
        JS_ThrowInternalError(ctx, "failed to allocate SSLContext class ID");
        return;
    }
    if (!JS_IsRegisteredClass(rt, tjs_ssl_context_class_id) &&
        JS_NewClass(rt, tjs_ssl_context_class_id, &tjs_ssl_context_class) < 0) {
        JS_ThrowInternalError(ctx, "failed to register SSLContext class");
        return;
    }
    
    JSValue context_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, context_proto, tjs_ssl_context_proto_funcs,
                              countof(tjs_ssl_context_proto_funcs));
    JS_SetClassProto(ctx, tjs_ssl_context_class_id, context_proto);
    
    JSValue context_ctor = JS_NewCFunction2(ctx, tjs_ssl_context_constructor,
                                           "Context", 1,
                                           JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, context_ctor, context_proto);
    JS_SetPropertyStr(ctx, ns, "Context", context_ctor);

    /* Register Certificate */
    if (JS_NewClassID(rt, &tjs_ssl_certificate_class_id) == JS_INVALID_CLASS_ID) {
        JS_ThrowInternalError(ctx, "failed to allocate Certificate class ID");
        return;
    }
    if (!JS_IsRegisteredClass(rt, tjs_ssl_certificate_class_id) &&
        JS_NewClass(rt, tjs_ssl_certificate_class_id, &tjs_ssl_certificate_class) < 0) {
        JS_ThrowInternalError(ctx, "failed to register Certificate class");
        return;
    }

    JSValue certificate_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, certificate_proto, tjs_ssl_certificate_proto_funcs,
                              countof(tjs_ssl_certificate_proto_funcs));
    JS_SetClassProto(ctx, tjs_ssl_certificate_class_id, certificate_proto);

    JSValue certificate_ctor = JS_NewCFunction2(ctx, tjs_ssl_certificate_constructor,
                                               "Certificate", 1,
                                               JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, certificate_ctor, certificate_proto);
    JS_SetPropertyStr(ctx, ns, "Certificate", certificate_ctor);

    /* Register SSLPipe */
    if (JS_NewClassID(rt, &tjs_ssl_pipe_class_id) == JS_INVALID_CLASS_ID) {
        JS_ThrowInternalError(ctx, "failed to allocate SSLPipe class ID");
        return;
    }
    if (!JS_IsRegisteredClass(rt, tjs_ssl_pipe_class_id) &&
        JS_NewClass(rt, tjs_ssl_pipe_class_id, &tjs_ssl_pipe_class) < 0) {
        JS_ThrowInternalError(ctx, "failed to register SSLPipe class");
        return;
    }
    
    JSValue pipe_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, pipe_proto, tjs_ssl_pipe_proto_funcs,
                              countof(tjs_ssl_pipe_proto_funcs));
    JS_SetClassProto(ctx, tjs_ssl_pipe_class_id, pipe_proto);
    
    JSValue pipe_ctor = JS_NewCFunction2(ctx, tjs_ssl_pipe_constructor,
                                        "Pipe", 2,
                                        JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, pipe_ctor, pipe_proto);
    JS_SetPropertyStr(ctx, ns, "Pipe", pipe_ctor);
    
    /* Register utility functions */
    JS_SetPropertyFunctionList(ctx, ns, tjs_ssl_static_funcs, countof(tjs_ssl_static_funcs));

	/* OpenSSL version and config */
	tjs_ssl_static_version(ctx, ns);
	tjs_ssl_static_ciphers(ctx, ns);
}
