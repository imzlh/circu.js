/*
 * txiki.js SSL Module - OpenSSL wrapper
 * Requires: libssl-dev
 */

#include "private.h"
#include "tjs.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
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

#pragma region SSLContext
typedef struct {
    JSContext *ctx;
    SSL_CTX *ssl_ctx;
    TJSSSLMode mode;
    char *cert_file;
    char *key_file;
    char *ca_file;
    char *ciphers;
    int verify_mode;
    bool session_tickets;
} TJSSSLContext;

static JSClassID tjs_ssl_context_class_id;

static void tjs_ssl_context_finalizer(JSRuntime *rt, JSValue val) {
    TJSSSLContext *ssl_ctx = JS_GetOpaque(val, tjs_ssl_context_class_id);
    if (ssl_ctx) {
        if (ssl_ctx->ssl_ctx) {
            SSL_CTX_free(ssl_ctx->ssl_ctx);
        }
        if (ssl_ctx->cert_file) js_free_rt(rt, ssl_ctx->cert_file);
        if (ssl_ctx->key_file) js_free_rt(rt, ssl_ctx->key_file);
        if (ssl_ctx->ca_file) js_free_rt(rt, ssl_ctx->ca_file);
        if (ssl_ctx->ciphers) js_free_rt(rt, ssl_ctx->ciphers);
        js_free_rt(rt, ssl_ctx);
    }
}

static JSClassDef tjs_ssl_context_class = {
    "SSLContext",
    .finalizer = tjs_ssl_context_finalizer,
};

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
	/* Simple first-match selection */
	unsigned char* list = (unsigned char*) arg;
	if (SSL_select_next_proto((unsigned char**) out, outlen,
		list + 1, list[0], in, inlen)
		== OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_OK;
	}
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
    
    /* Certificate and key */
    JSValue cert_val = JS_GetPropertyStr(ctx, options, "cert");
    JSValue key_val = JS_GetPropertyStr(ctx, options, "key");
    const char *cert = cstr(ctx, cert_val);
    const char *key = cstr(ctx, key_val);
    
    if (cert) {
        ssl_ctx->cert_file = js_strdup(ctx, cert);
        int ret = SSL_CTX_use_certificate_chain_file(ssl_ctx->ssl_ctx, cert);
        JS_FreeCString(ctx, cert);
        if (ret != 1) {
            JS_FreeValue(ctx, cert_val);
            JS_FreeValue(ctx, key_val);
            if (key) JS_FreeCString(ctx, key);
            if (ssl_ctx->cert_file) js_free(ctx, ssl_ctx->cert_file);  /* fix: leaked */
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            SSL_THROW_ERROR(ctx, "SSL_CTX_use_certificate_chain_file");
        }
    }
    JS_FreeValue(ctx, cert_val);

    if (key) {
        ssl_ctx->key_file = js_strdup(ctx, key);
        int ret = SSL_CTX_use_PrivateKey_file(ssl_ctx->ssl_ctx, key, SSL_FILETYPE_PEM);
        JS_FreeCString(ctx, key);
        if (ret != 1) {
            JS_FreeValue(ctx, key_val);
            if (ssl_ctx->cert_file) js_free(ctx, ssl_ctx->cert_file);  /* fix: leaked */
            if (ssl_ctx->key_file) js_free(ctx, ssl_ctx->key_file);    /* fix: leaked */
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            SSL_THROW_ERROR(ctx, "SSL_CTX_use_PrivateKey_file");
        }
    }
    JS_FreeValue(ctx, key_val);
    
    /* CA file */
    JSValue ca_val = JS_GetPropertyStr(ctx, options, "ca");
    const char *ca = cstr(ctx, ca_val);
    if (ca) {
        ssl_ctx->ca_file = js_strdup(ctx, ca);
        int ret = SSL_CTX_load_verify_locations(ssl_ctx->ssl_ctx, ca, NULL);
        JS_FreeCString(ctx, ca);
        if (ret != 1) {
            JS_FreeValue(ctx, ca_val);
            /* fix: all previously strdup'd fields leaked before */
            if (ssl_ctx->cert_file) js_free(ctx, ssl_ctx->cert_file);
            if (ssl_ctx->key_file)  js_free(ctx, ssl_ctx->key_file);
            if (ssl_ctx->ca_file)   js_free(ctx, ssl_ctx->ca_file);
            SSL_CTX_free(ssl_ctx->ssl_ctx);
            js_free(ctx, ssl_ctx);
            JS_FreeValue(ctx, obj);
            SSL_THROW_ERROR(ctx, "SSL_CTX_load_verify_locations");
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
        
        /* Build ALPN protocol list */
        uint8_t alpn_list[256];
        size_t alpn_list_len = 0;
        
        for (int32_t i = 0; i < len && alpn_list_len < sizeof(alpn_list) - 1; i++) {
            JSValue proto_val = JS_GetPropertyUint32(ctx, alpn_val, i);
            const char *proto = cstr(ctx, proto_val);
            if (proto) {
                size_t proto_len = strlen(proto);
                if (alpn_list_len + proto_len + 1 < sizeof(alpn_list)) {
                    alpn_list[alpn_list_len++] = proto_len;
                    memcpy(alpn_list + alpn_list_len, proto, proto_len);
                    alpn_list_len += proto_len;
                }
                JS_FreeCString(ctx, proto);
            }
            JS_FreeValue(ctx, proto_val);
        }
        
        if (ssl_ctx->mode == TJS_SSL_MODE_SERVER) {
            SSL_CTX_set_alpn_select_cb(ssl_ctx->ssl_ctx, alpn_cb, alpn_list);
        } else {
            SSL_CTX_set_alpn_protos(ssl_ctx->ssl_ctx, alpn_list, alpn_list_len);
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
        BIO *bio = BIO_new_file(dhparam, "r");
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

#pragma region SSLPipe
typedef struct {
    JSContext *ctx;
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
    TJSSSLContext *ssl_context;
	JSValue ssl_obj;	// hold reference to SSL object
    TJSSSLHandshakeState handshake_state;
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
        js_free_rt(rt, pipe);
		JS_FreeValueRT(rt, pipe->ssl_obj);
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
    
    size_t size;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &size, argv[0]);
    if (!buf) return JS_EXCEPTION;
    
    int ret = BIO_write(pipe->rbio, buf, size);
    return JS_NewInt32(ctx, ret);
}

/* pipe.read(size) - Read decrypted data */
static JSValue tjs_ssl_pipe_read(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    int32_t size = 16384;
    if (argc > 0) {
        JS_ToInt32(ctx, &size, argv[0]);
    }
    
    uint8_t *buf = js_malloc(ctx, size);
    if (!buf) return JS_EXCEPTION;
    
    int ret = SSL_read(pipe->ssl, buf, size);
    
    if (ret > 0) {
        JSValue result = JS_NewArrayBufferCopy(ctx, buf, ret);
        js_free(ctx, buf);
        return result;
    } else {
        js_free(ctx, buf);
		CHECK_SSL_ERR(pipe->ssl, ret);
        SSL_THROW_ERROR(ctx, "SSL_read");
    }
}

/* pipe.write(data) - Write plaintext data to be encrypted */
static JSValue tjs_ssl_pipe_write(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    size_t size;
    uint8_t *buf = JS_GetAnyBuffer(ctx, &size, argv[0]);
    if (!buf) return JS_EXCEPTION;
    
    int ret = SSL_write(pipe->ssl, buf, size);
    
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

/* pipe.certificate() - Get peer certificate info */
static JSValue tjs_ssl_pipe_get_peer_certificate(JSContext *ctx, JSValueConst this_val) {
    TJSSSLPipe *pipe = JS_GetOpaque2(ctx, this_val, tjs_ssl_pipe_class_id);
    if (!pipe) return JS_EXCEPTION;
    
    X509 *cert = SSL_get_peer_certificate(pipe->ssl);
    if (!cert) {
        return JS_NULL;
    }
    
    JSValue cert_obj = JS_NewObject(ctx);
    
    /* Subject */
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (subj) {
        JS_SetPropertyStr(ctx, cert_obj, "subject", JS_NewString(ctx, subj));
        OPENSSL_free(subj);
    }
    
    /* Issuer */
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    if (issuer) {
        JS_SetPropertyStr(ctx, cert_obj, "issuer", JS_NewString(ctx, issuer));
        OPENSSL_free(issuer);
    }
    
    /* Serial number */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn) {
            char *serial_str = BN_bn2hex(bn);
            if (serial_str) {
                JS_SetPropertyStr(ctx, cert_obj, "serialNumber", JS_NewString(ctx, serial_str));
                OPENSSL_free(serial_str);
            }
            BN_free(bn);
        }
    }
    
    /* Valid from/to */
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    
    if (not_before) {
        BIO *bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, not_before);
        char buf[64];
        int len = BIO_read(bio, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            JS_SetPropertyStr(ctx, cert_obj, "validFrom", JS_NewString(ctx, buf));
        }
        BIO_free(bio);
    }
    
    if (not_after) {
        BIO *bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, not_after);
        char buf[64];
        int len = BIO_read(bio, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            JS_SetPropertyStr(ctx, cert_obj, "validTo", JS_NewString(ctx, buf));
        }
        BIO_free(bio);
    }
    
    /* Subject Alternative Names */
    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        JSValue san_array = JS_NewArray(ctx);
        int san_count = sk_GENERAL_NAME_num(san_names);
        
        for (int i = 0; i < san_count; i++) {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);
            if (name->type == GEN_DNS) {
                ASN1_STRING *dns = name->d.dNSName;
                const char *dns_str = (const char *)ASN1_STRING_get0_data(dns);
                JS_SetPropertyUint32(ctx, san_array, i, JS_NewString(ctx, dns_str));
            }
        }
        
        JS_SetPropertyStr(ctx, cert_obj, "subjectAltNames", san_array);
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }
    
    /* Fingerprint */
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (X509_digest(cert, EVP_sha256(), md, &md_len)) {
        char fingerprint[EVP_MAX_MD_SIZE * 3];
        for (unsigned int i = 0; i < md_len; i++) {
            sprintf(fingerprint + i * 3, "%02X:", md[i]);
        }
        fingerprint[md_len * 3 - 1] = '\0';
        JS_SetPropertyStr(ctx, cert_obj, "fingerprint256", JS_NewString(ctx, fingerprint));
    }
    
    X509_free(cert);
    return cert_obj;
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
static int tjs__ssl_openssl_version(JSContext *ctx, JSValueConst ns) {
    return JS_SetPropertyStr(ctx, ns, "version", JS_NewString(ctx, OpenSSL_version(OPENSSL_VERSION)));
}

/* cipherList() */
static int tjs__ssl_cipher_list(JSContext *ctx, JSValueConst ns) {
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
static JSValue tjs_ssl_load_pem(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv) {
    const char *data = cstr(ctx, argv[0]);
    if (!data) return JS_EXCEPTION;
    
    const char *type = argc > 1 ? cstr(ctx, argv[1]) : "certificate";
    
    BIO *bio = BIO_new_mem_buf(data, -1);
    JS_FreeCString(ctx, data);
    
    if (!bio) {
        if (type != NULL && argc > 1) JS_FreeCString(ctx, type);
        return JS_ThrowOutOfMemory(ctx);
    }
    
    JSValue result = JS_UNDEFINED;
    
    if (strcmp(type, "certificate") == 0) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert) {
            /* Return basic certificate info */
            result = JS_NewObject(ctx);
            
            char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            if (subj) {
                JS_SetPropertyStr(ctx, result, "subject", JS_NewString(ctx, subj));
                OPENSSL_free(subj);
            }
            
            X509_free(cert);
        } else {
            result = JS_NULL;
        }
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
    
    return result;
}

/* createSelfSignedCert(options) - Create self-signed certificate */
static JSValue tjs_ssl_create_self_signed_cert(JSContext *ctx, JSValueConst this_val,
                                                 int argc, JSValueConst *argv) {
    JSValue options = argc > 0 ? argv[0] : JS_UNDEFINED;
    
    /* Parse options */
    JSValue cn_val = JS_GetPropertyStr(ctx, options, "commonName");
    const char *cn = cstr(ctx, cn_val);
    if (!cn) cn = "localhost";
    
    JSValue days_val = JS_GetPropertyStr(ctx, options, "days");
    int32_t days = 365;
    JS_ToInt32(ctx, &days, days_val);
    
    /* Generate RSA key */
    EVP_PKEY *pkey = EVP_PKEY_new();

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
	RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    
    if (rsa && bne) {
        BN_set_word(bne, RSA_F4);
        if (RSA_generate_key_ex(rsa, 2048, bne, NULL) > 0) {
            EVP_PKEY_assign_RSA(pkey, rsa);
        } else {
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    } else {
        if (rsa) RSA_free(rsa);
        if (bne) BN_free(bne);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (bne) BN_free(bne);
#endif
    
    /* Create certificate */
    X509 *cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * days);
    X509_set_pubkey(cert, pkey);
    
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(cert, name);
    
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
    
    if (argc > 0) {
        JS_FreeCString(ctx, cn);
        JS_FreeValue(ctx, cn_val);
        JS_FreeValue(ctx, days_val);
    }
    
    return result;
}

static const JSCFunctionListEntry tjs_ssl_funcs[] = {
    JS_CFUNC_DEF("loadPEM", 2, tjs_ssl_load_pem),
    JS_CFUNC_DEF("createSelfSignedCert", 1, tjs_ssl_create_self_signed_cert),
};

#pragma region Module Initialization
void tjs__mod_ssl_init(JSContext *ctx, JSValue ns) {
    /* Register SSLContext */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_ssl_context_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_ssl_context_class_id, &tjs_ssl_context_class);
    
    JSValue context_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, context_proto, tjs_ssl_context_proto_funcs,
                              countof(tjs_ssl_context_proto_funcs));
    JS_SetClassProto(ctx, tjs_ssl_context_class_id, context_proto);
    
    JSValue context_ctor = JS_NewCFunction2(ctx, tjs_ssl_context_constructor,
                                           "Context", 1,
                                           JS_CFUNC_constructor, 0);
	JS_SetConstructor(ctx, context_ctor, context_proto);
    JS_SetPropertyStr(ctx, ns, "Context", context_ctor);
    
    /* Register SSLPipe */
    JS_NewClassID(JS_GetRuntime(ctx), &tjs_ssl_pipe_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_ssl_pipe_class_id, &tjs_ssl_pipe_class);
    
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
    JS_SetPropertyFunctionList(ctx, ns, tjs_ssl_funcs, countof(tjs_ssl_funcs));

	/* OpenSSL version and config */
	tjs__ssl_openssl_version(ctx, ns);
	tjs__ssl_cipher_list(ctx, ns);
}