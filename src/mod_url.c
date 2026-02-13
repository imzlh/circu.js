#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "private.h"
#include "../quickjs/list.h"

#define MAX_URL_SIZE 4096

static URL_data *default_url;

typedef struct {
    char* key;
    char* value;
    struct list_head link;
} URL_query;

typedef struct{
    char *protocol;
    char *host;
    uint16_t port;
    char *path;
    struct list_head query; // URL_query
    char *hash;
    char* username;
    char* password;
} URL_data;

typedef struct LHTTPData {
    char* method;
    char* path;
    struct list_head headers;
    void* userdata;
    char* __target_host;
    float version;
    uint16_t status;

    char reserved[3];
} LHTTPData;

typedef struct {
    char* key;
    size_t keylen;
    char* value;
    size_t vallen;

    struct list_head link;
} LHttpHeader;

struct JS_URL_struct{
    URL_data* self;
    JSValue template;
    uint8_t dup_count;
};


// Custom strdup that handles NULL
static char* strdup2(const char* s) {
    return s ? strdup(s) : NULL;
}

// Convert string to lowercase (modifies a copy)
static char* strtolower(const char* s) {
    if (!s) return NULL;
    char* lower = strdup(s);
    for (char* p = lower; *p; p++) {
        *p = tolower((unsigned char)*p);
    }
    return lower;
}

// URL decode (%XX, + -> space)
static char* url_decode(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char* decoded = malloc(len + 1);
    if (!decoded) return NULL;
    char* p = decoded;
    for (; *s; s++) {
        if (*s == '%' && s[1] && s[2]) {
            char hex[3] = {s[1], s[2], '\0'};
            *p++ = (char)strtol(hex, NULL, 16);
            s += 2;
        } else if (*s == '+') {
            *p++ = ' ';
        } else {
            *p++ = *s;
        }
    }
    *p = '\0';
    return decoded;
}

// URL encode (encode special chars)
static void url_encode(const char* s, char* buf, size_t bufsize) {
    if (!s || !buf || bufsize == 0) return;
    char* p = buf;
    for (; *s && (size_t)(p - buf) < bufsize - 1; s++) {
        if (isalnum((unsigned char)*s) || *s == '-' || *s == '_' || *s == '.' || *s == '~') {
            *p++ = *s;
        } else {
            if ((size_t)(p - buf) + 3 >= bufsize) break;
            sprintf(p, "%%%02X", (unsigned char)*s);
            p += 3;
        }
    }
    *p = '\0';
}

// Parse query string into list (key=value&...)
static bool url_parse_query(const char* query_str, struct list_head* query_list) {
    if (!query_str) return true;
    char* q = strdup(query_str);
    if (!q) return false;
    char* pair = strtok(q, "&");
    while (pair) {
        URL_query* query = malloc(sizeof(URL_query));
        if (!query) {
            free(q);
            return false;
        }
        char* eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            query->key = url_decode(pair);
            query->value = url_decode(eq + 1);
        } else {
            query->key = url_decode(pair);
            query->value = NULL;
        }
        list_add_tail(&query->link, query_list);
        pair = strtok(NULL, "&");
    }
    free(q);
    return true;
}

// Duplicate query list from src to dst
static void url_query_dup(URL_data* src, URL_data* dst) {
    struct list_head* cur;
    list_for_each(cur, &src->query) {
        URL_query* sq = list_entry(cur, URL_query, link);
        URL_query* dq = malloc(sizeof(URL_query));
        if (dq) {
            dq->key = strdup2(sq->key);
            dq->value = strdup2(sq->value);
            list_add_tail(&dq->link, &dst->query);
        }
    }
}

// Resolve relative path (RFC 3986 style, simplified)
static char* resolve_path(const char* rel_path, const char* base_path) {
    if (!rel_path) return strdup(base_path ? base_path : "/");

    // If relative starts with /, it's absolute
    if (rel_path[0] == '/') {
        return strdup(rel_path);
    }

    // Duplicate base and remove last segment if not /
    char* base = strdup(base_path ? base_path : "/");
    char* last_slash = strrchr(base, '/');
    if (last_slash && last_slash != base) {
        *last_slash = '\0';  // remove filename
    }

    // Concatenate relative to base
    size_t len = strlen(base) + strlen(rel_path) + 2;
    char* resolved = malloc(len);
    if (!resolved) {
        free(base);
        return NULL;
    }
    snprintf(resolved, len, "%s/%s", base, rel_path);
    free(base);

    // Normalize: remove ./ and ../
    char* p = resolved;
    char* q = resolved;
    while (*p) {
        if (p[0] == '/' && p[1] == '.') {
            if (p[2] == '/' || p[2] == '\0') {
                p += 2;  // skip /.
                continue;
            } else if (p[2] == '.' && (p[3] == '/' || p[3] == '\0')) {
                p += 3;  // skip /..
                if (q > resolved && q[-1] == '/') q--;  // backtrack to previous /
                while (q > resolved && q[-1] != '/') q--;
                continue;
            }
        }
        *q++ = *p++;
    }
    *q = '\0';

    return resolved;
}

// Macro or function for deleting HTTP header
#define DEL_HEADER2(header) do { \
    if (header->key) free(header->key); \
    if (header->value) free(header->value); \
    free(header); \
} while (0)

__attribute__((constructor)) static void init_default_url(void) {
    default_url = calloc(1, sizeof(URL_data));
    if (default_url) {
        init_list_head(&default_url->query);
    }
}

// Parse scheme according to RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
static bool parse_scheme(char **url_ptr, URL_data* url_struct) {
    char* url = *url_ptr;
    if (!url || !isalpha((unsigned char)*url)) {
        return false;  // must start with ALPHA
    }
    char* pos = url + 1;
    while (*pos != ':' && *pos != '\0' &&
           (isalnum((unsigned char)*pos) || *pos == '+' || *pos == '-' || *pos == '.')) {
        pos++;
    }
    if (*pos != ':') {
        return false;
    }
    *pos = '\0';
    url_struct->protocol = strtolower(url);
    *url_ptr = pos + 1;
    return true;
}

// Parse authority (userinfo@host:port), supporting IPv6 and multiple @ (last @ wins)
static bool parse_authority(char **url_ptr, URL_data* url_struct) {
    char* url = *url_ptr;
    if (*url != '/' || *(url + 1) != '/') {
        return false;
    }
    url += 2;

    char* user_pass_end = strchr(url, '@');
    if (user_pass_end) {
        char* host_end_temp = strpbrk(user_pass_end, ":/?#");
        if (host_end_temp && user_pass_end > host_end_temp) {
            // invalid, skip userinfo
            goto skip_up;
        }

        char* last_at = user_pass_end;
        char* current = user_pass_end + 1;
        while ((current = strchr(current, '@')) != NULL) {
            if (!host_end_temp || current < host_end_temp) {
                last_at = current;
                current++;
            } else {
                break;
            }
        }

        if (last_at) {
            *last_at = '\0';
            char* colon = strchr(url, ':');
            if (colon) {
                *colon = '\0';
                url_struct->username = url_decode(url);
                url_struct->password = url_decode(colon + 1);
            } else {
                url_struct->username = url_decode(url);
            }
            url = last_at + 1;
        }
    }
skip_up:;

    char* host = url;
    char* host_end = NULL;

    if (*host == '[') {  // IPv6
        char* ipv6_end = strchr(host, ']');
        if (!ipv6_end) {
            return false;
        }
        // Store host WITHOUT brackets (standard practice)
        url_struct->host = strndup(host + 1, ipv6_end - host - 1);
        // Basic IPv6 validation (hex, :, . for IPv4-mapped)
        for (char* p = host + 1; p < ipv6_end; p++) {
            if (!isxdigit((unsigned char)*p) && *p != ':' && *p != '.') {
                free(url_struct->host);
                url_struct->host = NULL;
                return false;
            }
        }
        host_end = ipv6_end + 1;
    }

    if (!host_end) {
        host_end = strpbrk(host, ":/?#");
    }

    // Port handling
    if (host_end && *host_end == ':') {
        *host_end = '\0';
        char* port_str = host_end + 1;
        char* port_end = strpbrk(port_str, "/?#");
        char port_end_chr = port_end ? *port_end : '\0';
        if (port_end) *port_end = '\0';

        if (strlen(port_str) > 5) {
            return false;  // port too long
        }

        char* endp;
        long port = strtol(port_str, &endp, 10);
        if (*endp != '\0' || port < 0 || port > 65535) {
            return false;
        }
        url_struct->port = (uint16_t)port;

        if (port_end) {
            *port_end = port_end_chr;
            *url_ptr = port_end;
        } else {
            *url_ptr = NULL;  // no further path/query/hash
            return true;
        }
    } else if (url_struct->protocol) {
        // Default ports per common schemes (RFC-compliant defaults)
        if (strcmp(url_struct->protocol, "http") == 0) {
            url_struct->port = 80;
        } else if (strcmp(url_struct->protocol, "https") == 0) {
            url_struct->port = 443;
        } else if (strcmp(url_struct->protocol, "ftp") == 0) {
            url_struct->port = 21;
        } else if (strcmp(url_struct->protocol, "ws") == 0) {
            url_struct->port = 80;
        } else if (strcmp(url_struct->protocol, "wss") == 0) {
            url_struct->port = 443;
        } else {
            url_struct->port = 0;
        }
    }

    if (!url_struct->host) {  // non-IPv6 case
        url_struct->host = strndup(host, host_end ? host_end - host : strlen(host));
    }

    if (host_end) {
        *url_ptr = host_end;
    } else {
        *url_ptr = NULL;
    }
    return true;
}

// Parse path, query, hash
static bool parse_path_query_hash(char **url_ptr, URL_data* url_struct, URL_data* base) {
    char* url = *url_ptr;
    if (!url) return true;

    char* path_start = url;
    char* hp_start = strpbrk(url, "?#");

    if (hp_start) {
        if (*hp_start == '#') {
            url_struct->hash = url_decode(hp_start + 1);
        } else {
            char* hash_start = strchr(hp_start, '#');
            if (hash_start) {
                *hash_start = '\0';
                url_struct->hash = url_decode(hash_start + 1);
            }
            char* query_str = hp_start + 1;
            if (!url_parse_query(query_str, &url_struct->query)) {
                return false;
            }
        }
        *hp_start = '\0';
    }

    // Resolve relative path
    if (*path_start != '/') {
        char* bpath = strdup2(base->path ? base->path : "");
        url_struct->path = resolve_path(url_decode(path_start), bpath);
        free(bpath);
        if (!url_struct->path) {
            return false;
        }
    } else {
        char* resolved = resolve_path(path_start, "");
        url_struct->path = url_decode(resolved);
        free(resolved);
    }
    return true;
}

// Improved parse_url with fixes for memory leaks, RFC compliance, IPv6, robustness, and error propagation
// Returns: 0 on success, -1 on error (allows future error code extension)
static int parse_url(const char* _url, URL_data* url_struct, URL_data* base) {
    if (!_url || strlen(_url) == 0 || strlen(_url) > MAX_URL_SIZE) {
        return -1;
    }

    memset(url_struct, 0, sizeof(URL_data));
    init_list_head(&url_struct->query);

    char* __url = strdup(_url);
    if (!__url) return -1;
    char* url = __url;

    // Fallback to default
    if (!base) {
        base = default_url;
    }

#define dup(c) ((c) ? strdup(c) : NULL)

    // Relative URL starters (RFC 3986 section 4.2)
    if (url[0] == '/') {
        if (url[1] == '/') {
            url_struct->protocol = dup(base->protocol);
            if (!parse_authority(&url, url_struct)) {
                goto error;
            }
            if (!parse_path_query_hash(&url, url_struct, base)) {
                goto error;
            }
            free(__url);
            return 0;
        } else {
            url_struct->protocol = dup(base->protocol);
            url_struct->host = dup(base->host);
            url_struct->port = base->port;
            if (!parse_path_query_hash(&url, url_struct, base)) {
                goto error;
            }
            free(__url);
            return 0;
        }
    } else if (url[0] == '.') {
        url_struct->protocol = dup(base->protocol);
        url_struct->host = dup(base->host);
        url_struct->port = base->port;
        if (!parse_path_query_hash(&url, url_struct, base)) {
            goto error;
        }
        free(__url);
        return 0;
    } else if (url[0] == '?') {
        url_struct->protocol = dup(base->protocol);
        url_struct->host = dup(base->host);
        url_struct->port = base->port;
        url_struct->path = dup(base->path);
        url += 1;
        if (!parse_path_query_hash(&url, url_struct, base)) {  // for query and hash
            goto error;
        }
        free(__url);
        return 0;
    } else if (url[0] == '#') {
        url_struct->protocol = dup(base->protocol);
        url_struct->host = dup(base->host);
        url_struct->port = base->port;
        url_struct->path = dup(base->path);
        url_query_dup(base, url_struct);
        url += 1;
        url_struct->hash = url_decode(url);
        free(__url);
        return 0;
    }

    // Scheme parsing (RFC 3986 compliant)
    if (parse_scheme(&url, url_struct)) {
        if (!parse_authority(&url, url_struct)) {
            goto error;
        }
    } else {
        // No scheme, assume relative path
        url_struct->protocol = dup(base->protocol);
        url_struct->host = dup(base->host);
        url_struct->port = base->port;
    }

    if (!parse_path_query_hash(&url, url_struct, base)) {
        goto error;
    }

    free(__url);
    return 0;

error:
    free(__url);
    free_url(url_struct);
    return -1;
#undef dup
}

// free URL struct
void free_url(URL_data* url_struct) {
#define free2(ptr) if (ptr) free(ptr)
    if (!list_empty(&url_struct->query)) {
        struct list_head* cur, * tmp;
        list_for_each_safe(cur, tmp, &url_struct->query) {
            URL_query* query = list_entry(cur, URL_query, link);
            free2(query->key);
            free2(query->value);
            free(query);
        }
    }
    free2(url_struct->protocol);
    free2(url_struct->host);
    free2(url_struct->path);
    free2(url_struct->username);
    free2(url_struct->password);
    free2(url_struct->hash);
#undef free2
}

// format `url_struct` to standard URL string
char* format_url(URL_data* url_struct) {
    char* data = malloc(MAX_URL_SIZE);
    if (!data) return NULL;
    size_t datapos = 0;

    char enctmp[MAX_URL_SIZE]; // for URL encode

#define PUT(str) do { \
        if (!str) break; \
        size_t len = strlen(str); \
        if (datapos + len >= MAX_URL_SIZE - 1) { free(data); return NULL; } \
        memcpy(data + datapos, str, len); datapos += len; \
    } while (0)
#define EPUT(str) do { \
        if (!str) break; \
        url_encode(str, enctmp, sizeof(enctmp)); \
        PUT(enctmp); \
    } while (0)

    if (url_struct->host) {
        if (url_struct->protocol) {
            PUT(url_struct->protocol);
            PUT("://");
        } else {
            PUT("//");
        }

        if (url_struct->username) {
            EPUT(url_struct->username);
            if (url_struct->password) {
                PUT(":");
                EPUT(url_struct->password);
            }
            PUT("@");
        }
        PUT(url_struct->host);
        if (url_struct->port != 0) {
            char port_str[10];
            snprintf(port_str, sizeof(port_str), ":%d", url_struct->port);
            PUT(port_str);
        }
    }

    if (url_struct->path) {
        PUT(url_struct->path);
    } else {
        PUT("/");
    }

    if (!list_empty(&url_struct->query)) {
        PUT("?");
        struct list_head* cur;
        bool first = true;
        list_for_each(cur, &url_struct->query) {
            URL_query* query = list_entry(cur, URL_query, link);
            if (!first) PUT("&");
            EPUT(query->key);
            if (query->value) {
                PUT("=");
                EPUT(query->value);
            }
            first = false;
        }
    }
    if (url_struct->hash) {
        PUT("#");
        EPUT(url_struct->hash);
    }
    data[datapos] = '\0';
#undef PUT
#undef EPUT
    return data;
}

// free HTTP data
void free_http_data(LHTTPData* data) {
    if (!data) return;
    struct list_head* cur, * tmp;
    list_for_each_safe(cur, tmp, &data->headers) {
        LHttpHeader* header = list_entry(cur, LHttpHeader, link);
        DEL_HEADER2(header);
    }

#define free2(ptr) if (ptr) free(ptr)
    free2(data->method);
    free2(data->path);
    free2(data->__target_host);
#undef free2
}

static thread_local JSClassID js_class_url_id;

static JSValue js_url_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    URL_data *url_struct = js_malloc(ctx, sizeof(URL_data));
    struct JS_URL_struct *js_url_struct = js_malloc(ctx, sizeof(struct JS_URL_struct));
    if(url_struct == NULL || js_url_struct == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }
    memset(url_struct, 0, sizeof(URL_data));

    js_url_struct -> dup_count = 0;
    js_url_struct -> template = JS_UNDEFINED;

    if(argc == 1){
        // single URL
        const char *url = JS_ToCString(ctx, argv[0]);
        if(url == NULL || !parse_url(url, url_struct, NULL)){
            JS_FreeCString(ctx, url);
            JS_ThrowTypeError(ctx, "Invalid URL");
            goto error;
        }
        JS_FreeCString(ctx, url);
    }else if(argc == 2){
        // parse by base URL(arg#2)
        const char *url = JS_ToCString(ctx, argv[0]);
        if(!likely(url)) return JS_ThrowTypeError(ctx, "Invalid URL");
        URL_data base_url = { 0 };
        URL_data* burl = &base_url;
        if(JS_IsObject(argv[1])){
            URL_data *burl = JS_GetOpaque(argv[1], js_class_url_id);
            if(burl == NULL){
                JS_ThrowTypeError(ctx, "Invalid base URL");
                goto error;
            }
            // base URL object
            js_url_struct -> template = JS_DupValue(ctx, argv[1]);
        }else{
            // parse base URL string
            const char *base_url_str = JS_ToCString(ctx, argv[1]);
            if(base_url_str == NULL || !parse_url(base_url_str, &base_url, NULL)){
                JS_ThrowTypeError(ctx, "Invalid URL");
                goto error;
            }
            JS_FreeCString(ctx, base_url_str);
        }
        if(!likely(parse_url(url, url_struct, burl))){
            JS_FreeCString(ctx, url);
            JS_ThrowTypeError(ctx, "Invalid base URL");
            goto error;
        }
        JS_FreeCString(ctx, url);
    }else if(unlikely(argc != 0)){
        JS_ThrowTypeError(ctx, "URL constructor takes 0 or 1 argument");
        goto error;
    }
    js_url_struct -> self = url_struct;

    JSValue obj =  JS_NewObjectClass(ctx, js_class_url_id);
    JS_SetOpaque(obj, js_url_struct);
    return obj;

error:
    js_free(ctx, js_url_struct);
    return JS_EXCEPTION;
}

#define GETTER_STRING(func_name, field) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    URL_data *url_struct = js_url_struct -> self; \
    return (url_struct -> field) ? JS_NewString(ctx, url_struct -> field) : JS_UNDEFINED; \
}

#define GETTER_INT(func_name, field, invalid_value) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    URL_data *url_struct = js_url_struct -> self; \
    return (url_struct -> field == invalid_value) ? JS_UNDEFINED : JS_NewInt32(ctx, url_struct -> field); \
}

#define SETTER_STRING_DUP(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return JS_ThrowTypeError(ctx, err_msg); \
    js_url_struct -> self -> field = strdup2(str); \
    return JS_UNDEFINED; \
}

#define SETTER_STRING_COPY(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return JS_ThrowTypeError(ctx, err_msg); \
    free(js_url_struct -> self -> field); \
    js_url_struct -> self -> field = strdup(str); \
    JS_FreeCString(ctx, str); \
    return JS_UNDEFINED; \
}

#define SETTER_INT_RANGE(func_name, field, min, max, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    int32_t val; \
    if (JS_ToInt32(ctx, &val, value) < 0) return JS_ThrowTypeError(ctx, err_msg); \
    if (val < min || val > max) return JS_ThrowRangeError(ctx, #field " out of range"); \
    js_url_struct -> self -> field = val; \
    return JS_UNDEFINED; \
}

// getter methods
GETTER_STRING(js_url_getProtocol, protocol)
GETTER_STRING(js_url_getHost, host)
GETTER_STRING(js_url_getPath, path)
GETTER_STRING(js_url_getHash, hash)
GETTER_STRING(js_url_getUsername, username)
GETTER_STRING(js_url_getPassword, password)
GETTER_INT(js_url_getPort, port, 0)

// setter methods
SETTER_STRING_DUP(js_url_setProtocol, protocol, "Invalid protocol")
SETTER_STRING_DUP(js_url_setHost, host, "Invalid host")
SETTER_STRING_DUP(js_url_setUsername, username, "Invalid username")
SETTER_STRING_DUP(js_url_setPassword, password, "Invalid password")
SETTER_STRING_COPY(js_url_setPath, path, "Invalid path")
SETTER_STRING_COPY(js_url_setHash, hash, "Invalid hash")
SETTER_INT_RANGE(js_url_setPort, port, 0, 65535, "Invalid port")

JSValue js_url_addQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *key = JS_ToCString(ctx, argv[0]);
    if(key == NULL){
        return JS_ThrowTypeError(ctx, "Invalid query key");
    }
    const char *value = NULL;
    if(argc == 2){
        value = JS_ToCString(ctx, argv[1]);
        if(value == NULL){
            return JS_ThrowTypeError(ctx, "Invalid query value");
        }
    }

    URL_query* query = malloc(sizeof(URL_query));
    if(query == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }
    query -> key = js_strdup(ctx, key);
    query -> value = value? js_strdup(ctx, value) : NULL;
    list_add_tail(&query -> link, &url_struct -> query);
    return JS_UNDEFINED;
}

JSValue js_url_delQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }

    uint32_t del_id = -1;
    char* key;
    if(argc == 1){
        key = (char*)JS_ToCString(ctx, argv[0]);
        if(key == NULL){
            return JS_ThrowTypeError(ctx, "Invalid query key");
        }
    }else if(argc == 2){
        key = (char*)JS_ToCString(ctx, argv[0]);
        if(-1 == JS_ToUint32(ctx, &del_id, argv[1]) || key == NULL){
            return JS_ThrowTypeError(ctx, "Invalid arguments");
        }
    }else{
        return JS_ThrowTypeError(ctx, "delQuery takes 1 or 2 arguments");
    }

    uint32_t key_occurrence = 0;
    bool found = false;
    struct list_head* pos;
    list_for_each(pos, &js_url_struct -> self -> query){
        URL_query* query = list_entry(pos, URL_query, link);
        if(strcmp(query -> key, key) == 0){
            if(del_id == -1 || del_id == key_occurrence){
                found = true;
                js_free(ctx, query -> key);
                if(query -> value != NULL){
                    js_free(ctx, query -> value);
                }
                js_free(ctx, query);
                list_del(pos);
                break;
            }
            key_occurrence++;
        }
    }

    if(!found){
        return JS_ThrowTypeError(ctx, "query key not found");
    }
    return JS_UNDEFINED;
}


static JSValue js_url_toString(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    char* data = format_url(url_struct);
    JSValue url_val = JS_NewString(ctx, data);
    free(data);
    return url_val;
}


static JSValue js_url_getQueryStr(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    char *query_str = js_malloc(ctx, 1024);
    
    size_t qoffset = 0;
    if(query_str == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }

#define PUT(str) memcpy(query_str + qoffset, str, strlen(str)); qoffset += strlen(str);
#define PUTC(c) query_str[qoffset++] = c;
    
    struct list_head* pos;
    list_for_each(pos, &url_struct -> query){
        URL_query* query = list_entry(pos, URL_query, link);
        PUT(query -> key);
        if(query -> value){
            PUTC('='); PUT(query -> value);
        }
        PUTC('&');
    }
    if(qoffset > 0){
        qoffset -= 1;    
    }
    query_str[qoffset] = '\0';
    JSValue query_val = JS_NewStringLen(ctx, query_str, qoffset);
    free2(query_str);
    return query_val;
}

static JSValue js_url_getQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    
    const char* search = argc >= 1 ? ToCString(ctx, argv[0], NULL) : NULL;
    JSValue query_obj = search ? JS_NewArray(ctx) : JS_NewObject(ctx);
    size_t arrlen = 0;

    struct list_head* pos;
    list_for_each(pos, &url_struct -> query){
        URL_query* query = list_entry(pos, URL_query, link);

        if(search){
            if(strcmp(query -> key, search) == 0){
                JSValue value_val = JS_NewString(ctx, query -> value);
                JS_SetPropertyUint32(ctx, query_obj, arrlen ++, value_val);
            }
            continue;
        }

        JSValue value_arr;
        int64_t len = 0;
        if(JS_IsUndefined(value_arr = JS_GetPropertyStr(ctx, query_obj, query -> key))){
            value_arr = JS_NewArray(ctx);   // ref=1
            JS_SetPropertyStr(ctx, query_obj, query -> key, JS_DupValue(ctx, value_arr));   //ref+1-1
        }else{
            JS_GetLength(ctx, value_arr, &len);
        }
        if(likely(query -> value)){
            JSValue value_val = JS_NewString(ctx, query -> value);
            JS_SetPropertyUint32(ctx, value_arr, len ++, value_val);
        }
        JS_FreeValue(ctx, value_arr);   // ref=0
        JS_SetLength(ctx, value_arr, len);
    }

    if(search) JS_SetLength(ctx, query_obj, arrlen);
    return query_obj;
}


JSValue js_url_setQueryStr(JSContext *ctx, JSValueConst this_val, JSValue value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *query = JS_ToCString(ctx, value);

    // clear previous query
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &url_struct -> query){
        URL_query* query = list_entry(pos, URL_query, link);
        js_free(ctx, query -> key);
        if(query -> value != NULL){
            js_free(ctx, query -> value);
        }
        js_free(ctx, query);
    }
    init_list_head(&url_struct -> query);   // clear

    // parse
    char* query2 = js_strdup(ctx, query);
    JS_FreeCString(ctx, query);
    if(!url_parse_query(query2, &url_struct -> query)){
        js_free(ctx, query2);
        return JS_ThrowTypeError(ctx, "Invalid query string");
    }
    js_free(ctx, query2);
    return JS_UNDEFINED;
}

static void js_url_finalizer(JSRuntime *rt, JSValue val) {
    struct JS_URL_struct *js_url_struct = JS_GetOpaque( val, js_class_url_id);
    if (!js_url_struct) return;
    
    URL_data *url = js_url_struct -> self;
    free_url(url);

    // free template object refcount
    if(!JS_IsUndefined(js_url_struct -> template)){
        JS_FreeValueRT(rt, js_url_struct -> template);
    }
    
    js_free_rt(rt, js_url_struct);
}

static JSValue js_url_proto_canParse(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0]))
        return JS_ThrowTypeError(ctx, "Invalid arguments");

    // url
    const char *url = JS_ToCString(ctx, argv[0]);
    if(!url) return JS_EXCEPTION;

    // base url
    URL_data url_base_struct;
    char* base_url_str = NULL;
    if(argc == 2){
        const char* base_url = JS_ToCString(ctx, argv[1]);
        if(base_url){
            if(!parse_url(base_url, &url_base_struct, NULL)){
                js_free(ctx, base_url_str);
                return JS_FALSE;
            }
            JS_FreeCString(ctx, base_url);
        }
    }
    
    // parse
    URL_data url_struct;
    bool result = parse_url(url, &url_struct, &url_base_struct);
    JS_FreeCString(ctx, url);

    // free
    free_url(&url_struct);
    free_url(&url_base_struct);
    if(base_url_str) js_free(ctx, base_url_str);
    
    return JS_NewBool(ctx, result);
}

static void js_url_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark) {
    struct JS_URL_struct *js_url_struct = JS_GetOpaque( val, js_class_url_id);
    if (!js_url_struct) return;
    
    JS_MarkValue(rt, js_url_struct -> template, mark);
}

static const JSCFunctionListEntry js_url_funcs[] = {
    JS_CFUNC_DEF("toString", 0, js_url_toString),
    JS_CGETSET_DEF("protocol", js_url_getProtocol, js_url_setProtocol),
    JS_CGETSET_DEF("host", js_url_getHost, js_url_setHost),
    JS_CGETSET_DEF("port", js_url_getPort, js_url_setPort),
    JS_CGETSET_DEF("path", js_url_getPath, js_url_setPath),
    JS_CGETSET_DEF("query", js_url_getQueryStr, js_url_setQueryStr),
    JS_CFUNC_DEF("getQuery", 0, js_url_getQuery),
    JS_CFUNC_DEF("delQuery", 1, js_url_delQuery),
    JS_CFUNC_DEF("addQuery", 1, js_url_addQuery),
    JS_CGETSET_DEF("hash", js_url_getHash, js_url_setHash),
    JS_CGETSET_DEF("username", js_url_getUsername, js_url_setUsername),
    JS_CGETSET_DEF("password", js_url_getPassword, js_url_setPassword),
};

static const JSCFunctionListEntry url_proto_funcs[] = {
    JS_CFUNC_DEF("canParse", 1, js_url_proto_canParse)
};

static const JSClassDef js_url_class = {
    "URL",
    .finalizer = js_url_finalizer,
	.gc_mark = js_url_mark
};

void tjs__mod_url_init(JSContext* ctx, JSValue ns) {
	JSRuntime *rt = JS_GetRuntime(ctx);
	
    JS_NewClassID(rt, &js_class_url_id);
    JS_NewClass(rt, js_class_url_id, &js_url_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_url_funcs, countof(js_url_funcs));
    JS_SetClassProto(ctx, js_class_url_id, proto);

    JSValue url_ctor = JS_NewCFunction2(ctx, js_url_constructor, "URL", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, url_ctor, proto);
    JS_SetPropertyFunctionList(ctx, url_ctor, url_proto_funcs, countof(url_proto_funcs));

    JS_SetPropertyStr(ctx, ns, "URL", url_ctor);
}