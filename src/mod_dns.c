/*
 * circu.js
 *
 * Copyright (c) 2019-present Saúl Ibarra Corretgé <s@saghul.net>
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

#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

typedef struct {
	JSContext* ctx;
	uv_getaddrinfo_t req;
	TJSPromise result;
	struct addrinfo* res;  // For sync operations
	int status;  // For sync operations
	bool done;   // For sync operations
} TJSGetAddrInfoReq;

typedef struct {
	JSContext* ctx;
	uv_getnameinfo_t req;
	TJSPromise result;
	struct sockaddr_storage addr;
} TJSGetNameInfoReq;

static JSValue tjs_addrinfo2obj(JSContext* ctx, struct addrinfo* ai) {
	JSValue obj = JS_NewArray(ctx);

	struct addrinfo* ptr;
	int i = 0;
	for (ptr = ai; ptr; ptr = ptr->ai_next) {
		// Skip non-SOCK_STREAM entries instead of aborting
		if (ptr->ai_socktype != SOCK_STREAM) continue;
		JSValue item = JS_NewObjectProto(ctx, JS_NULL);
		tjs_addr2obj(ctx, item, ptr->ai_addr, true);
		JS_DefinePropertyValueUint32(ctx, obj, i, item, JS_PROP_C_W_E);
		i++;
	}

	return obj;
}

static int dns_ai_flags(int hints) {
	int flags = 0;
#ifdef AI_V4MAPPED
	if (hints & 8) flags |= AI_V4MAPPED;
#endif
#ifdef AI_ALL
	if (hints & 16) flags |= AI_ALL;
#endif
#ifdef AI_ADDRCONFIG
	if (hints & 32) flags |= AI_ADDRCONFIG;
#endif
	return flags;
}

static const char* dns_gai_code(int status) {
#ifdef EAI_NONAME
	if (status == EAI_NONAME) return "ENOTFOUND";
#endif
#ifdef EAI_NODATA
	if (status == EAI_NODATA) return "ENOTFOUND";
#endif
#ifdef EAI_AGAIN
	if (status == EAI_AGAIN) return "EAI_AGAIN";
#endif
#ifdef EAI_ADDRFAMILY
	if (status == EAI_ADDRFAMILY) return "EAI_ADDRFAMILY";
#endif
#ifdef EAI_BADFLAGS
	if (status == EAI_BADFLAGS) return "EAI_BADFLAGS";
#endif
#ifdef EAI_FAIL
	if (status == EAI_FAIL) return "EAI_FAIL";
#endif
#ifdef EAI_FAMILY
	if (status == EAI_FAMILY) return "EAI_FAMILY";
#endif
#ifdef EAI_MEMORY
	if (status == EAI_MEMORY) return "ENOMEM";
#endif
#ifdef EAI_SERVICE
	if (status == EAI_SERVICE) return "EAI_SERVICE";
#endif
#ifdef EAI_SOCKTYPE
	if (status == EAI_SOCKTYPE) return "EAI_SOCKTYPE";
#endif
#ifdef EAI_OVERFLOW
	if (status == EAI_OVERFLOW) return "EAI_OVERFLOW";
#endif
	return "EAI_SYSTEM";
}

static JSValue dns_new_gai_error(JSContext* ctx, int status) {
	JSValue error = JS_NewError(ctx);
	if (JS_IsException(error)) return error;
	const char* message = gai_strerror(status);
	JS_DefinePropertyValueStr(ctx, error, "message",
		JS_NewString(ctx, message ? message : "getaddrinfo failed"),
		JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
	JS_DefinePropertyValueStr(ctx, error, "code",
		JS_NewString(ctx, dns_gai_code(status)),
		JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
	return error;
}

static void uv__getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
	TJSGetAddrInfoReq* gr = req->data;
	CHECK_NOT_NULL(gr);

	JSContext* ctx = gr->ctx;
	TJSRuntime* qrt = TJS_GetRuntime(ctx);

	// Safeguard: if runtime is being freed, don't call JS functions
	if (!qrt || qrt->freeing) {
		if (res) uv_freeaddrinfo(res);
		TJS_FreePromise(ctx, &gr->result);
		js_free(ctx, gr);
		return;
	}

	JSValue arg;
	bool is_reject = status != 0;

	if (status != 0) {
		arg = tjs_new_error(ctx, status);
	}
	else {
		arg = tjs_addrinfo2obj(ctx, res);
	}

	TJS_SettlePromise(ctx, &gr->result, is_reject, 1, &arg);

	if (res) uv_freeaddrinfo(res);
	js_free(ctx, gr);
}

static JSValue tjs_dns_getaddrinfo(JSContext* ctx, JSValue this_val, int argc, JSValue* argv) {
	const char* node = NULL;

	if (!JS_IsUndefined(argv[0])) {
		node = JS_ToCString(ctx, argv[0]);
		if (!node) {
			return JS_EXCEPTION;
		}
	}

	JSValue opts = argv[1];
	JSValue js_family = JS_GetPropertyStr(ctx, opts, "family");
	int family;
	if(-1 == JS_ToInt32(ctx, &family, js_family)) {
		JS_FreeValue(ctx, js_family);
		JS_FreeCString(ctx, node);
		return JS_ThrowTypeError(ctx, "Invalid family option. expected integer.");
	}
	if(family != AF_INET && family != AF_INET6 && family!= AF_UNSPEC) {
		JS_FreeValue(ctx, js_family);
		JS_FreeCString(ctx, node);
		return JS_ThrowTypeError(ctx, "Invalid family option. expected AF_INET, AF_INET6 or AF_UNSPEC.");
	}
	JS_FreeValue(ctx, js_family);

	JSValue js_hints = JS_GetPropertyStr(ctx, opts, "hints");
	int32_t hint_bits = 0;
	if (!JS_IsUndefined(js_hints) && JS_ToInt32(ctx, &hint_bits, js_hints) < 0) {
		JS_FreeValue(ctx, js_hints);
		JS_FreeCString(ctx, node);
		return JS_ThrowTypeError(ctx, "Invalid hints option. expected integer.");
	}
	JS_FreeValue(ctx, js_hints);

	TJSGetAddrInfoReq* gr = js_malloc(ctx, sizeof(*gr));
	if (!gr) {
		JS_FreeCString(ctx, node);
		return JS_EXCEPTION;
	}

	gr->ctx = ctx;
	gr->req.data = gr;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = family;
	hints.ai_flags = dns_ai_flags(hint_bits);

	JSValue promise = TJS_InitPromise(ctx, &gr->result);
	if (JS_IsException(promise)) {
		JS_FreeCString(ctx, node);
		js_free(ctx, gr);
		return promise;
	}
	int r = uv_getaddrinfo(tjs_get_loop(ctx), &gr->req, uv__getaddrinfo_cb, node, NULL, &hints);

	JS_FreeCString(ctx, node);

	if (r != 0) {
		TJS_FreePromise(ctx, &gr->result);
		JS_FreeValue(ctx, promise);
		js_free(ctx, gr);
		return tjs_throw_errno(ctx, r);
	}

	return promise;
}

static JSValue tjs_dns_getaddrinfo_sync(JSContext* ctx, JSValue this_val, int argc, JSValue* argv) {
	const char* node = NULL;

	if (!JS_IsUndefined(argv[0])) {
		node = JS_ToCString(ctx, argv[0]);
		if (!node) {
			return JS_EXCEPTION;
		}
	}

	JSValue opts = argv[1];
	JSValue js_family = JS_GetPropertyStr(ctx, opts, "family");
	int family;
	if(-1 == JS_ToInt32(ctx, &family, js_family)) {
		JS_FreeValue(ctx, js_family);
		JS_FreeCString(ctx, node);
		return JS_ThrowTypeError(ctx, "Invalid family option. expected integer.");
	}
	if(family != AF_INET && family != AF_INET6 && family!= AF_UNSPEC) {
		JS_FreeValue(ctx, js_family);
		JS_FreeCString(ctx, node);
		return JS_ThrowTypeError(ctx, "Invalid family option. expected AF_INET, AF_INET6 or AF_UNSPEC.");
	}
	JS_FreeValue(ctx, js_family);

	JSValue js_hints = JS_GetPropertyStr(ctx, opts, "hints");
	int32_t hint_bits = 0;
	if (!JS_IsUndefined(js_hints) && JS_ToInt32(ctx, &hint_bits, js_hints) < 0) {
		JS_FreeValue(ctx, js_hints);
		JS_FreeCString(ctx, node);
		return JS_ThrowTypeError(ctx, "Invalid hints option. expected integer.");
	}
	JS_FreeValue(ctx, js_hints);

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = family;
	hints.ai_flags = dns_ai_flags(hint_bits);

	// Direct system call instead of using libuv
	struct addrinfo* res = NULL;
	int r = getaddrinfo(node, NULL, &hints, &res);

	JS_FreeCString(ctx, node);

	JSValue result;
	if (r != 0) {
		result = dns_new_gai_error(ctx, r);
		return JS_Throw(ctx, result);
	} else {
		result = tjs_addrinfo2obj(ctx, res);
	}

	if (res) {
		freeaddrinfo(res);
	}

	return result;
}

static void uv__getnameinfo_cb(uv_getnameinfo_t* req, int status,
	const char* hostname, const char* service) {
	TJSGetNameInfoReq* gr = req->data;
	CHECK_NOT_NULL(gr);
	JSContext* ctx = gr->ctx;
	TJSRuntime* qrt = TJS_GetRuntime(ctx);
	if (!qrt || qrt->freeing) {
		TJS_FreePromise(ctx, &gr->result);
		js_free(ctx, gr);
		return;
	}

	JSValue result;
	bool reject = status != 0;
	if (reject) {
		result = tjs_new_error(ctx, status);
	} else {
		result = JS_NewObjectProto(ctx, JS_NULL);
		JS_SetPropertyStr(ctx, result, "hostname", JS_NewString(ctx, hostname ? hostname : ""));
		JS_SetPropertyStr(ctx, result, "service", JS_NewString(ctx, service ? service : ""));
	}
	TJS_SettlePromise(ctx, &gr->result, reject, 1, &result);
	js_free(ctx, gr);
}

static JSValue tjs_dns_lookup_service(JSContext* ctx, JSValue this_val,
	int argc, JSValue* argv) {
	const char* address = JS_ToCString(ctx, argv[0]);
	if (!address) return JS_EXCEPTION;
	int32_t port;
	if (JS_ToInt32(ctx, &port, argv[1]) < 0) {
		JS_FreeCString(ctx, address);
		return JS_ThrowTypeError(ctx, "The \"port\" argument must be an integer");
	}
	if (port < 0 || port > 65535) {
		JS_FreeCString(ctx, address);
		return JS_ThrowRangeError(ctx, "The \"port\" argument is out of range");
	}

	TJSGetNameInfoReq* gr = js_malloc(ctx, sizeof(*gr));
	if (!gr) {
		JS_FreeCString(ctx, address);
		return JS_EXCEPTION;
	}
	memset(gr, 0, sizeof(*gr));
	gr->ctx = ctx;
	gr->req.data = gr;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int r = uv_ip4_addr(address, port, &addr4);
	if (r == 0) {
		memcpy(&gr->addr, &addr4, sizeof(addr4));
	} else {
		r = uv_ip6_addr(address, port, &addr6);
		if (r == 0) memcpy(&gr->addr, &addr6, sizeof(addr6));
	}
	JS_FreeCString(ctx, address);
	if (r != 0) {
		js_free(ctx, gr);
		return JS_ThrowTypeError(ctx, "Invalid IP address");
	}

	JSValue promise = TJS_InitPromise(ctx, &gr->result);
	if (JS_IsException(promise)) {
		js_free(ctx, gr);
		return promise;
	}
	int flags = 0;
#ifdef NI_NAMEREQD
	flags |= NI_NAMEREQD;
#endif
	r = uv_getnameinfo(tjs_get_loop(ctx), &gr->req, uv__getnameinfo_cb,
		(const struct sockaddr*) &gr->addr, flags);
	if (r != 0) {
		TJS_FreePromise(ctx, &gr->result);
		JS_FreeValue(ctx, promise);
		js_free(ctx, gr);
		return tjs_throw_errno(ctx, r);
	}
	return promise;
}

// DNS header structure (RFC 1035)
typedef struct {
	uint16_t id;        // Transaction ID
	uint16_t flags;     // Flags
	uint16_t qdcount;   // Question count
	uint16_t ancount;   // Answer count
	uint16_t nscount;   // Authority count
	uint16_t arcount;   // Additional count
} dns_header_t;

// DNS question structure
typedef struct {
	char* name;
	uint16_t qtype;
	uint16_t qclass;
} dns_question_t;

// DNS answer structure
typedef struct {
	char* name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	uint8_t* rdata;
	const uint8_t* packet;
	size_t packet_len;
	size_t rdata_offset;
} dns_answer_t;

// DNS query context for libuv resolution
typedef struct {
	uv_getaddrinfo_t req;
	JSContext* ctx;
	JSValue promise;
	JSValue resolve_func;
	JSValue reject_func;
} dns_getaddrinfo_ctx_t;

// UDP DNS query context
typedef struct {
	uv_udp_t udp;
	uv_udp_send_t send_req;
	JSContext* ctx;
	JSValue resolve_func;
	JSValue reject_func;
	JSValue controller;
	uint16_t query_id;
	char* hostname;
	struct sockaddr_storage server_addr;
	uint8_t query_buf[512];
	unsigned int query_len;
	bool done;
	bool closing;
} dns_udp_ctx_t;

// UDP DNS query context for sync operations
typedef struct {
	dns_udp_ctx_t ctx;
	bool done;
	int status;
	int close_status;
} dns_sync_ctx_t;

/* RFC 1035 - Standard DNS Record Types */
#define DNS_A       1     /* IPv4 address */
#define DNS_NS      2     /* Name server */
#define DNS_CNAME   5     /* Canonical name (alias) */
#define DNS_SOA     6     /* Start of authority */
#define DNS_PTR     12    /* Pointer record (reverse DNS) */
#define DNS_MX      15    /* Mail exchange */
#define DNS_TXT     16    /* Text record */
#define DNS_AAAA    28    /* IPv6 address */
#define DNS_SRV     33    /* Service location */
#define DNS_NAPTR   35    /* Naming Authority Pointer */
#define DNS_OPT     41    /* EDNS0 option */
#define DNS_DS      43    /* Delegation Signer */
#define DNS_RRSIG   46    /* DNSSEC signature */
#define DNS_NSEC    47    /* Next Secure record */
#define DNS_DNSKEY  48    /* DNSSEC public key */
#define DNS_TLSA    52    /* TLSA certificate association */
#define DNS_CDS     59    /* Child DS */
#define DNS_CDNSKEY 60    /* Child DNSKEY */
#define DNS_OPENPGPKEY 61 /* OpenPGP public key */
#define DNS_CSYNC   62    /* Child-to-Parent Synchronization */
#define DNS_SVCB    64    /* Service Binding */
#define DNS_HTTPS   65    /* HTTPS Binding */
#define DNS_CAA     257   /* Certification Authority Authorization */
#define DNS_ANY     255   /* Any available record */

static JSClassID tjs_dns_query_class_id;
static JSClassDef tjs_dns_query_class = { "DNSQuery" };

// ============ DNS Packet Building/Parsing ============

// Encode domain name to DNS format (www.example.com -> 3www7example3com0)
static int encode_dns_name(const char* name, uint8_t* buf, size_t buflen) {
	size_t pos = 0;
	const char* p = name;
	if (name[0] == '.' && name[1] == '\0') {
		if (buflen == 0) return -1;
		buf[0] = 0;
		return 1;
	}

	while (*p) {
		const char* dot = strchr(p, '.');
		size_t len = dot ? (size_t) (dot - p) : strlen(p);

		if (len == 0 || len > 63 || pos + len + 1 >= buflen || pos + len + 2 > 255) {
			return -1;
		}

		buf[pos++] = (uint8_t) len;
		memcpy(buf + pos, p, len);
		pos += len;

		p += len;
		if (*p == '.') p++;
	}

	if (pos >= buflen) return -1;
	buf[pos++] = 0;
	return pos;
}

// Decode DNS name from packet
static int decode_dns_name(const uint8_t* packet, size_t packet_len,
	size_t* offset, char* name, size_t name_len) {
	size_t pos = *offset;
	size_t name_pos = 0;
	int jumped = 0;
	size_t jump_offset = 0;
	int label_count = 0;
	int jumps = 0;

	if (name_len == 0) return -1;

	while (pos < packet_len && label_count < 127) {
		uint8_t len = packet[pos];

		// Compression pointer
		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= packet_len) return -1;
			if (!jumped) {
				jump_offset = pos + 2;
				jumped = 1;
			}
			// Bound the number of compression-pointer jumps to defeat
			// malicious packets whose pointers reference each other (a
			// loop that never consumes a label would otherwise spin
			// forever, since pointer follows do not advance label_count).
			if (++jumps > 128) return -1;
			pos = ((len & 0x3F) << 8) | packet[pos + 1];
			if (pos >= packet_len) return -1;
			continue;
		}

		// End of name
		if (len == 0) {
			if (!jumped) *offset = pos + 1;
			else *offset = jump_offset;
			// Always NUL-terminate; callers pass uninitialized buffers
			// (cname/ns/mx/target/...) straight to JS_NewString.
			name[name_pos] = '\0';
			return 0;
		}

		// Label
		if (len > 63 || pos + 1 + len > packet_len) return -1;
		if (name_pos + len + 1 >= name_len) return -1;

		if (name_pos > 0) name[name_pos++] = '.';
		memcpy(name + name_pos, packet + pos + 1, len);
		name_pos += len;
		pos += len + 1;
		label_count++;
	}

	return -1;
}

static bool dns_name_fits_rdata(const uint8_t* packet, size_t packet_len,
	size_t* offset, size_t rdata_end) {
	char name[256];
	if (decode_dns_name(packet, packet_len, offset, name, sizeof(name)) != 0) return false;
	return *offset <= rdata_end;
}

// Build DNS query packet
static int build_dns_query(const char* hostname, uint16_t query_id,
	uint16_t qtype, uint8_t* buf, size_t buflen) {
	if (buflen < 512) return -1;

	dns_header_t hdr = {
		.id = htons(query_id),
		.flags = htons(0x0100),
		.qdcount = htons(1),
		.ancount = 0,
		.nscount = 0,
		.arcount = 0,
	};
	memcpy(buf, &hdr, sizeof(hdr));

	size_t pos = sizeof(dns_header_t);
	int name_len = encode_dns_name(hostname, buf + pos, buflen - pos - 4);
	if (name_len < 0) return -1;

	pos += name_len;
	uint16_t query_type = htons(qtype);
	memcpy(buf + pos, &query_type, sizeof(query_type));
	pos += 2;
	uint16_t query_class = htons(1);
	memcpy(buf + pos, &query_class, sizeof(query_class));
	pos += 2;

	return pos;
}

static uint16_t dns_random_query_id(void) {
	uint16_t id;
	if (uv_random(NULL, NULL, &id, sizeof(id), 0, NULL) == 0) return id;
	return (uint16_t) (uv_hrtime() ^ (uintptr_t) &id);
}

enum dns_parse_status {
	DNS_PARSE_OK = 0,
	DNS_PARSE_BAD_RESPONSE = -1,
	DNS_PARSE_FORMERR = -2,
	DNS_PARSE_SERVFAIL = -3,
	DNS_PARSE_NOTFOUND = -4,
	DNS_PARSE_NOTIMP = -5,
	DNS_PARSE_REFUSED = -6,
	DNS_PARSE_NODATA = -7,
	DNS_PARSE_TRUNCATED = -8,
};

// Parse DNS response packet
static int parse_dns_response(const uint8_t* packet, size_t packet_len,
	uint16_t expected_id, dns_answer_t** answers, int* answer_count) {
	if (packet_len < sizeof(dns_header_t)) return -1;

	dns_header_t hdr;
	memcpy(&hdr, packet, sizeof(dns_header_t));
	hdr.id = ntohs(hdr.id);
	hdr.flags = ntohs(hdr.flags);
	hdr.qdcount = ntohs(hdr.qdcount);
	hdr.ancount = ntohs(hdr.ancount);

	if (hdr.id != expected_id || !(hdr.flags & 0x8000)) return DNS_PARSE_BAD_RESPONSE;
	if ((hdr.flags & 0x7800) != 0 || hdr.qdcount != 1) return DNS_PARSE_BAD_RESPONSE;
	if (hdr.flags & 0x0200) return DNS_PARSE_TRUNCATED;

	// Check response code and preserve the DNS-level error for callers.
	int rcode = hdr.flags & 0x000F;
	if (rcode == 1) return DNS_PARSE_FORMERR;
	if (rcode == 2) return DNS_PARSE_SERVFAIL;
	if (rcode == 3) return DNS_PARSE_NOTFOUND;
	if (rcode == 4) return DNS_PARSE_NOTIMP;
	if (rcode == 5) return DNS_PARSE_REFUSED;
	if (rcode != 0) return DNS_PARSE_BAD_RESPONSE;
	if (hdr.ancount > packet_len / 11) return DNS_PARSE_BAD_RESPONSE;

	size_t pos = sizeof(dns_header_t);

	// Skip questions
	for (int i = 0; i < hdr.qdcount; i++) {
		char name[256];
		if (decode_dns_name(packet, packet_len, &pos, name, sizeof(name)) != 0) {
			return -1;
		}
		if (pos + 4 > packet_len) return -1;
		pos += 4;  // Skip qtype and qclass
	}

	// Parse answers
	*answer_count = hdr.ancount;
	if (hdr.ancount == 0) {
		*answers = NULL;
		return DNS_PARSE_NODATA;
	}

	*answers = calloc(hdr.ancount, sizeof(dns_answer_t));
	if (!*answers) return -1;

	for (int i = 0; i < hdr.ancount; i++) {
		dns_answer_t* ans = &(*answers)[i];

		// Parse name
		char name[256] = {0};
		if (decode_dns_name(packet, packet_len, &pos, name, sizeof(name)) != 0) {
			goto parse_error;
		}
		ans->name = strdup(name);
		if (!ans->name) goto parse_error;

		// Parse type, class, TTL, rdlength (use memcpy for alignment safety)
		if (pos + 10 > packet_len) goto parse_error;
		uint16_t type_val, class_val, rdlength_val;
		uint32_t ttl_val;
		memcpy(&type_val, packet + pos, 2); pos += 2;
		ans->type = ntohs(type_val);
		memcpy(&class_val, packet + pos, 2); pos += 2;
		ans->class = ntohs(class_val);
		memcpy(&ttl_val, packet + pos, 4); pos += 4;
		ans->ttl = ntohl(ttl_val);
		memcpy(&rdlength_val, packet + pos, 2); pos += 2;
		ans->rdlength = ntohs(rdlength_val);

		// Parse rdata
		if (pos + ans->rdlength > packet_len) goto parse_error;

		// Store packet context for CNAME resolution
		ans->packet = packet;
		ans->packet_len = packet_len;
		ans->rdata_offset = pos;
		size_t rdata_end = pos + ans->rdlength;
		size_t name_offset;

		if (ans->class != 1) goto parse_error;
		switch (ans->type) {
		case DNS_A:
			if (ans->rdlength != 4) goto parse_error;
			break;
		case DNS_AAAA:
			if (ans->rdlength != 16) goto parse_error;
			break;
		case DNS_CNAME:
		case DNS_NS:
		case DNS_PTR:
			name_offset = pos;
			if (!dns_name_fits_rdata(packet, packet_len, &name_offset, rdata_end)) goto parse_error;
			break;
		case DNS_MX:
			name_offset = pos + 2;
			if (ans->rdlength <= 2 ||
				!dns_name_fits_rdata(packet, packet_len, &name_offset, rdata_end)) goto parse_error;
			break;
		case DNS_SOA:
			name_offset = pos;
			if (ans->rdlength < 22 ||
				!dns_name_fits_rdata(packet, packet_len, &name_offset, rdata_end) ||
				!dns_name_fits_rdata(packet, packet_len, &name_offset, rdata_end) ||
				rdata_end - name_offset < 20) goto parse_error;
			break;
		case DNS_SRV:
			name_offset = pos + 6;
			if (ans->rdlength <= 6 ||
				!dns_name_fits_rdata(packet, packet_len, &name_offset, rdata_end)) goto parse_error;
			break;
		case DNS_TXT: {
			if (ans->rdlength == 0) goto parse_error;
			size_t txt_offset = pos;
			while (txt_offset < rdata_end) {
				uint8_t length = packet[txt_offset++];
				if (length > rdata_end - txt_offset) goto parse_error;
				txt_offset += length;
			}
			break;
		}
		case DNS_NAPTR: {
			if (ans->rdlength < 8) goto parse_error;
			size_t naptr_offset = pos + 4;
			for (int field = 0; field < 3; field++) {
				if (naptr_offset >= rdata_end) goto parse_error;
				uint8_t length = packet[naptr_offset++];
				if (length > rdata_end - naptr_offset) goto parse_error;
				naptr_offset += length;
			}
			if (!dns_name_fits_rdata(packet, packet_len, &naptr_offset, rdata_end)) goto parse_error;
			break;
		}
		case DNS_CAA:
			if (ans->rdlength < 2 || packet[pos + 1] > ans->rdlength - 2) goto parse_error;
			break;
		default:
			break;
		}

		// For CNAME, don't copy raw data (it may contain pointers), decode later
		if (ans->type == 5) {
			ans->rdata = NULL;
		}
		else if (ans->rdlength > 0) {
			ans->rdata = malloc(ans->rdlength);
			if (!ans->rdata) goto parse_error;
			memcpy(ans->rdata, packet + pos, ans->rdlength);
		}
		pos += ans->rdlength;
	}

	return 0;

parse_error:
	for (int i = 0; i < hdr.ancount; i++) {
		if ((*answers)[i].name) free((*answers)[i].name);
		if ((*answers)[i].rdata) free((*answers)[i].rdata);
	}
	free(*answers);
	*answers = NULL;
	return -1;
}

// Free parsed answers
static void free_dns_answers(dns_answer_t* answers, int count) {
	if (!answers) return;
	for (int i = 0; i < count; i++) {
		if (answers[i].name) free(answers[i].name);
		if (answers[i].rdata) free(answers[i].rdata);
	}
	free(answers);
}

// Convert answer to JS object
static JSValue dns_answer_to_js(JSContext* ctx, dns_answer_t* ans) {
	JSValue obj = JS_NewObject(ctx);

	JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, ans->name));
	JS_SetPropertyStr(ctx, obj, "type", JS_NewInt32(ctx, ans->type));
	JS_SetPropertyStr(ctx, obj, "class", JS_NewInt32(ctx, ans->class));
	JS_SetPropertyStr(ctx, obj, "ttl", JS_NewUint32(ctx, ans->ttl));

	if (ans->type == DNS_A && ans->rdlength == 4) {  // A record
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, ans->rdata, ip, sizeof(ip));
		JS_SetPropertyStr(ctx, obj, "address", JS_NewString(ctx, ip));
	}
	else if (ans->type == DNS_AAAA && ans->rdlength == 16) {  // AAAA record
		char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ans->rdata, ip, sizeof(ip));
		JS_SetPropertyStr(ctx, obj, "address", JS_NewString(ctx, ip));
	}
	else if (ans->type == DNS_CNAME) {  // CNAME
		char cname[256];
		size_t offset = ans->rdata_offset;
		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, cname, sizeof(cname)) == 0) {
			JS_SetPropertyStr(ctx, obj, "cname", JS_NewString(ctx, cname));
		}
		else {
			JS_SetPropertyStr(ctx, obj, "cname", JS_NewString(ctx, "(invalid)"));
		}
	}
	else if (ans->type == DNS_NS) {  // NS
		char ns[256];
		size_t offset = ans->rdata_offset;
		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, ns, sizeof(ns)) == 0) {
			JS_SetPropertyStr(ctx, obj, "ns", JS_NewString(ctx, ns));
		}
		else {
			JS_SetPropertyStr(ctx, obj, "ns", JS_NewString(ctx, "(invalid)"));
		}
	}
	else if (ans->type == DNS_PTR) {  // PTR
		char ptr[256];
		size_t offset = ans->rdata_offset;
		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, ptr, sizeof(ptr)) == 0) {
			JS_SetPropertyStr(ctx, obj, "ptr", JS_NewString(ctx, ptr));
		}
		else {
			JS_SetPropertyStr(ctx, obj, "ptr", JS_NewString(ctx, "(invalid)"));
		}
	}
	else if (ans->type == DNS_MX && ans->rdlength > 2) {  // MX
		uint16_t priority;
		memcpy(&priority, ans->rdata, sizeof(priority));
		priority = ntohs(priority);
		char mx[256];
		size_t offset = ans->rdata_offset + 2;

		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, mx, sizeof(mx)) == 0) {
			JS_SetPropertyStr(ctx, obj, "priority", JS_NewInt32(ctx, priority));
			JS_SetPropertyStr(ctx, obj, "exchange", JS_NewString(ctx, mx));
		}
		else {
			JS_SetPropertyStr(ctx, obj, "exchange", JS_NewString(ctx, "(invalid)"));
		}
	}
	else if (ans->type == DNS_SOA && ans->rdlength >= 22) {  // SOA
		size_t offset = ans->rdata_offset;

		// main domain server
		char primary[256];
		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, primary, sizeof(primary)) == 0) {
			JS_SetPropertyStr(ctx, obj, "primary", JS_NewString(ctx, primary));
		}

		char admin_dns[256];
		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, admin_dns, sizeof(admin_dns)) == 0) {
			JS_SetPropertyStr(ctx, obj, "admin", JS_NewString(ctx, admin_dns));
		}

		// 5x32bit (serial, refresh, retry, expire, minimum)
		if (offset + 20 <= ans->rdata_offset + ans->rdlength) {
			size_t param_offset = (ans->rdata) ? (offset - ans->rdata_offset) : offset;
			const uint8_t* params = ans->rdata ? (ans->rdata + param_offset) : (ans->packet + offset);

			// Use memcpy for alignment safety
			uint32_t serial, refresh, retry, expire, minimum;
			memcpy(&serial, params, 4);
			memcpy(&refresh, params + 4, 4);
			memcpy(&retry, params + 8, 4);
			memcpy(&expire, params + 12, 4);
			memcpy(&minimum, params + 16, 4);
			serial = ntohl(serial);
			refresh = ntohl(refresh);
			retry = ntohl(retry);
			expire = ntohl(expire);
			minimum = ntohl(minimum);

			JS_SetPropertyStr(ctx, obj, "serial", JS_NewUint32(ctx, serial));
			JS_SetPropertyStr(ctx, obj, "refresh", JS_NewUint32(ctx, refresh));
			JS_SetPropertyStr(ctx, obj, "retry", JS_NewUint32(ctx, retry));
			JS_SetPropertyStr(ctx, obj, "expire", JS_NewUint32(ctx, expire));
			JS_SetPropertyStr(ctx, obj, "minimum", JS_NewUint32(ctx, minimum));
		}
	}
	else if (ans->type == DNS_SRV && ans->rdlength > 6) {
		// Use memcpy for alignment safety
		uint16_t priority, weight, port;
		memcpy(&priority, ans->rdata, 2);
		memcpy(&weight, ans->rdata + 2, 2);
		memcpy(&port, ans->rdata + 4, 2);
		priority = ntohs(priority);
		weight = ntohs(weight);
		port = ntohs(port);
		char target[256];
		size_t offset = ans->rdata_offset + 6;  // 6 byte offset

		if (ans->packet && decode_dns_name(ans->packet, ans->packet_len,
			&offset, target, sizeof(target)) == 0) {
			JS_SetPropertyStr(ctx, obj, "priority", JS_NewInt32(ctx, priority));
			JS_SetPropertyStr(ctx, obj, "weight", JS_NewInt32(ctx, weight));
			JS_SetPropertyStr(ctx, obj, "port", JS_NewInt32(ctx, port));
			JS_SetPropertyStr(ctx, obj, "target", JS_NewString(ctx, target));
		}
	}
	else if (ans->type == DNS_TXT && ans->rdata) {  // TXT
		JSValue entries = JS_NewArray(ctx);
		size_t offset = 0;
		uint32_t index = 0;
		while (offset < ans->rdlength) {
			uint8_t length = ans->rdata[offset++];
			if (length > ans->rdlength - offset) break;
			JS_SetPropertyUint32(ctx, entries, index++,
				JS_NewStringLen(ctx, (char*) ans->rdata + offset, length));
			offset += length;
		}
		JS_SetPropertyStr(ctx, obj, "entries", entries);
		JS_SetPropertyStr(ctx, obj, "txt",
			JS_NewStringLen(ctx, (char*) ans->rdata, ans->rdlength));
	}
	else if (ans->type == DNS_NAPTR && ans->rdlength > 7) {
		const uint8_t* ptr = ans->rdata;
		uint16_t order_value, preference_value;
		memcpy(&order_value, ptr, 2);
		memcpy(&preference_value, ptr + 2, 2);
		size_t pos = 4;
		uint8_t flags_len = ptr[pos++];
		if (pos + flags_len >= ans->rdlength) return obj;
		JSValue flags = JS_NewStringLen(ctx, (char*) ptr + pos, flags_len);
		pos += flags_len;
		uint8_t services_len = ptr[pos++];
		if (pos + services_len >= ans->rdlength) {
			JS_FreeValue(ctx, flags);
			return obj;
		}
		JSValue services = JS_NewStringLen(ctx, (char*) ptr + pos, services_len);
		pos += services_len;
		uint8_t regexp_len = ptr[pos++];
		if (pos + regexp_len >= ans->rdlength) {
			JS_FreeValue(ctx, flags);
			JS_FreeValue(ctx, services);
			return obj;
		}
		JSValue regexp = JS_NewStringLen(ctx, (char*) ptr + pos, regexp_len);
		pos += regexp_len;
		char replacement[256] = {0};
		size_t replacement_offset = ans->rdata_offset + pos;
		if (!ans->packet || decode_dns_name(ans->packet, ans->packet_len,
			&replacement_offset, replacement, sizeof(replacement)) != 0) {
			JS_FreeValue(ctx, flags);
			JS_FreeValue(ctx, services);
			JS_FreeValue(ctx, regexp);
			return obj;
		}
		JS_SetPropertyStr(ctx, obj, "order", JS_NewInt32(ctx, ntohs(order_value)));
		JS_SetPropertyStr(ctx, obj, "preference", JS_NewInt32(ctx, ntohs(preference_value)));
		JS_SetPropertyStr(ctx, obj, "flags", flags);
		JS_SetPropertyStr(ctx, obj, "services", services);
		JS_SetPropertyStr(ctx, obj, "regexp", regexp);
		JS_SetPropertyStr(ctx, obj, "replacement", JS_NewString(ctx, replacement));
	}
    else if (ans->type == DNS_CAA && ans->rdlength >= 2) {  // CAA (Certification Authority Authorization)
        const uint8_t *ptr = ans->rdata ? ans->rdata : (ans->packet + ans->rdata_offset);
        
        // flags (1bytes)
        uint8_t flags = ptr[0];
        JS_SetPropertyStr(ctx, obj, "flags", JS_NewInt32(ctx, flags));
        
        // tag (1bytes + string)
        uint8_t tag_len = ptr[1];
        char tag[256] = {0};
        if (2 + tag_len <= ans->rdlength) {
            memcpy(tag, ptr + 2, tag_len);
            tag[tag_len] = '\0';
            JS_SetPropertyStr(ctx, obj, "tag", JS_NewString(ctx, tag));
        }
        
		// value (remaining)
		size_t value_len = ans->rdlength - 2 - tag_len;
		const char *value = (const char *)(ptr + 2 + tag_len);
		JS_SetPropertyStr(ctx, obj, "value", JS_NewStringLen(ctx, value, value_len));
    }
	else {  // unknown record type
		if (ans->rdata) {
			JS_SetPropertyStr(ctx, obj, "rdlength", JS_NewInt32(ctx, ans->rdlength));
			uint8_t* data = js_malloc(ctx, ans->rdlength);
			if (data) {
				memcpy(data, ans->rdata, ans->rdlength);
				JS_SetPropertyStr(ctx, obj, "data",
					TJS_NewUint8Array(ctx, data, ans->rdlength));
			}
		}
	}

	return obj;
}

// ============ UDP DNS Query ===========

static void cleanup_callback(uv_handle_t* handle) {
	dns_udp_ctx_t* ctx = (dns_udp_ctx_t*) handle->data;
	if (ctx->hostname) free(ctx->hostname);
	free(ctx);
}

static void dns_udp_detach_controller(dns_udp_ctx_t* ctx) {
	if (!JS_IsUndefined(ctx->controller)) {
		JS_SetOpaque(ctx->controller, NULL);
		JS_FreeValue(ctx->ctx, ctx->controller);
		ctx->controller = JS_UNDEFINED;
	}
}

static void dns_udp_free_callbacks(dns_udp_ctx_t* ctx) {
	if (!JS_IsUndefined(ctx->resolve_func)) {
		JS_FreeValue(ctx->ctx, ctx->resolve_func);
		ctx->resolve_func = JS_UNDEFINED;
	}
	if (!JS_IsUndefined(ctx->reject_func)) {
		JS_FreeValue(ctx->ctx, ctx->reject_func);
		ctx->reject_func = JS_UNDEFINED;
	}
}

static void dns_udp_close(dns_udp_ctx_t* ctx) {
	if (ctx->closing) return;
	ctx->closing = true;
	uv_udp_recv_stop(&ctx->udp);
	if (!uv_is_closing((uv_handle_t*) &ctx->udp)) {
		uv_close((uv_handle_t*) &ctx->udp, cleanup_callback);
	}
}

static void dns_udp_finish(dns_udp_ctx_t* ctx) {
	dns_udp_detach_controller(ctx);
	dns_udp_free_callbacks(ctx);
	dns_udp_close(ctx);
}

static void dns_udp_reject_code(dns_udp_ctx_t* ctx, const char* code, const char* message) {
	if (ctx->done) return;
	ctx->done = true;
	JSValue error = JS_NewError(ctx->ctx);
	if (JS_IsException(error)) {
		error = JS_GetException(ctx->ctx);
	} else {
		JS_DefinePropertyValueStr(ctx->ctx, error, "message", JS_NewString(ctx->ctx, message),
			JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
		JS_DefinePropertyValueStr(ctx->ctx, error, "code", JS_NewString(ctx->ctx, code),
			JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
	}
	JSValue args[] = { error };
	JSValue ignored = JS_Call(ctx->ctx, ctx->reject_func, JS_UNDEFINED, 1, args);
	JS_FreeValue(ctx->ctx, ignored);
	JS_FreeValue(ctx->ctx, args[0]);
	dns_udp_finish(ctx);
}

static const char* dns_parse_error_code(int status) {
	switch (status) {
	case DNS_PARSE_FORMERR: return "EFORMERR";
	case DNS_PARSE_SERVFAIL: return "ESERVFAIL";
	case DNS_PARSE_NOTFOUND: return "ENOTFOUND";
	case DNS_PARSE_NOTIMP: return "ENOTIMP";
	case DNS_PARSE_REFUSED: return "EREFUSED";
	case DNS_PARSE_NODATA: return "ENODATA";
	case DNS_PARSE_TRUNCATED: return "EBADRESP";
	default: return "EBADRESP";
	}
}

static bool dns_server_matches(const dns_udp_ctx_t* ctx, const struct sockaddr* addr) {
	if (!addr || addr->sa_family != ctx->server_addr.ss_family) return false;
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in* expected = (const struct sockaddr_in*) &ctx->server_addr;
		const struct sockaddr_in* actual = (const struct sockaddr_in*) addr;
		return expected->sin_port == actual->sin_port &&
			memcmp(&expected->sin_addr, &actual->sin_addr, sizeof(expected->sin_addr)) == 0;
	}
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6* expected = (const struct sockaddr_in6*) &ctx->server_addr;
		const struct sockaddr_in6* actual = (const struct sockaddr_in6*) addr;
		return expected->sin6_port == actual->sin6_port &&
			memcmp(&expected->sin6_addr, &actual->sin6_addr, sizeof(expected->sin6_addr)) == 0;
	}
	return false;
}

static void udp_recv_callback(uv_udp_t* handle, ssize_t nread,
	const uv_buf_t* buf, const struct sockaddr* addr,
	unsigned flags) {
	dns_udp_ctx_t* ctx = (dns_udp_ctx_t*) handle->data;
	JSContext* js_ctx = ctx->ctx;
	TJSRuntime* qrt = TJS_GetRuntime(js_ctx);

	// If runtime is being freed, just cleanup without touching JSContext
	if (!qrt || qrt->freeing) {
		dns_udp_close(ctx);
		if (buf->base) free(buf->base);
		return;
	}

	if (ctx->done) {
		if (buf->base) free(buf->base);
		return;
	}
	if (nread >= 0 && !dns_server_matches(ctx, addr)) {
		if (buf->base) free(buf->base);
		return;
	}
	if (flags & UV_UDP_PARTIAL) {
		dns_udp_reject_code(ctx, "EBADRESP", "Truncated DNS datagram");
		if (buf->base) free(buf->base);
		return;
	}

	if (nread < 0) {
		dns_udp_reject_code(ctx, uv_err_name((int) nread), uv_strerror(nread));
		if (buf->base) free(buf->base);
		return;
	}

	if (nread > 0) {
		dns_answer_t* answers = NULL;
		int answer_count = 0;
		if (nread >= (ssize_t) sizeof(dns_header_t)) {
			uint16_t response_id;
			memcpy(&response_id, buf->base, sizeof(response_id));
			if (ntohs(response_id) != ctx->query_id) {
				free(buf->base);
				return;
			}
		}
		int parse_status = parse_dns_response((uint8_t*) buf->base, nread,
			ctx->query_id, &answers, &answer_count);
		if (parse_status == DNS_PARSE_OK) {
			JSValue result = JS_NewArray(js_ctx);
			for (int i = 0; i < answer_count; i++) {
				JSValue ans_obj = dns_answer_to_js(js_ctx, &answers[i]);
				JS_SetPropertyUint32(js_ctx, result, i, ans_obj);
			}
			free_dns_answers(answers, answer_count);
			JSValue args[] = { result };
			JSValue ignored = JS_Call(js_ctx, ctx->resolve_func, JS_UNDEFINED, 1, args);
			JS_FreeValue(js_ctx, ignored);
			JS_FreeValue(js_ctx, result);
			ctx->done = true;
		} else {
			dns_udp_reject_code(ctx, dns_parse_error_code(parse_status),
				parse_status == DNS_PARSE_NODATA ? "DNS response contains no answers" : "Failed to parse DNS response");
			free(buf->base);
			return;
		}
	}

	free(buf->base);
	if (ctx->done) dns_udp_finish(ctx);
}

static void udp_alloc_callback(uv_handle_t* handle, size_t suggested_size,
	uv_buf_t* buf) {
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

static void udp_send_callback(uv_udp_send_t* req, int status) {
	dns_udp_ctx_t* ctx = (dns_udp_ctx_t*) req->data;
	TJSRuntime* qrt = TJS_GetRuntime(ctx->ctx);

	// If runtime is being freed, just cleanup without touching JSContext
	if (!qrt || qrt->freeing) {
		dns_udp_close(ctx);
		return;
	}
	if (status == 0 || ctx->done) return;
	dns_udp_reject_code(ctx, uv_err_name(status), uv_strerror(status));
}

static JSValue tjs_dns_query_abort(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv, int magic, JSValue* func_data) {
	dns_udp_ctx_t* req_ctx = JS_GetOpaque(func_data[0], tjs_dns_query_class_id);
	if (!req_ctx || req_ctx->done) return JS_UNDEFINED;
	dns_udp_reject_code(req_ctx, "ECANCELLED", "DNS query cancelled");
	return JS_UNDEFINED;
}
// DNS.query(hostname, type, server, port)
// Performs raw UDP DNS query
static JSValue tjs_dns_query(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSRuntime* trt = TJS_GetRuntime(ctx);
	const char* hostname = JS_ToCString(ctx, argv[0]);
	if (!hostname) return JS_ThrowTypeError(ctx, "Invalid hostname");

	int32_t qtype = 1;  // Default A record
	if (argc >= 2 && -1 == JS_ToInt32(ctx, &qtype, argv[1])) {
		JS_FreeCString(ctx, hostname);
		return JS_ThrowTypeError(ctx, "Invalid query type");
	}

	const char* server = "8.8.8.8";  // Default Google DNS (IPv4 - DNS queries use IPv4 regardless of record type)
	bool server_is_js = false;
	if (argc >= 3 && !JS_IsUndefined(argv[2])) {
		server = JS_ToCString(ctx, argv[2]);
		if (!server) {
			JS_FreeCString(ctx, hostname);
			return JS_ThrowTypeError(ctx, "Invalid server");
		}
		server_is_js = true;
	}

	int32_t port = 53;
	if (argc >= 4 && !JS_IsUndefined(argv[3]) && -1 == JS_ToInt32(ctx, &port, argv[3])) {
		JS_FreeCString(ctx, hostname);
		if (server_is_js) JS_FreeCString(ctx, server);
		return JS_ThrowTypeError(ctx, "Invalid port");
	}
	if (port <= 0 || port > 65535) {
		JS_FreeCString(ctx, hostname);
		if (server_is_js) JS_FreeCString(ctx, server);
		return JS_ThrowRangeError(ctx, "Invalid port");
	}

	dns_udp_ctx_t* req_ctx = malloc(sizeof(dns_udp_ctx_t));
	if (!req_ctx) {
		JS_FreeCString(ctx, hostname);
		if (server_is_js) JS_FreeCString(ctx, server);
		return JS_ThrowOutOfMemory(ctx);
	}
	memset(req_ctx, 0, sizeof(dns_udp_ctx_t));

	req_ctx->ctx = ctx;
	req_ctx->hostname = strdup(hostname);
	if (!req_ctx->hostname) {
		JS_FreeCString(ctx, hostname);
		if (server_is_js) JS_FreeCString(ctx, server);
		free(req_ctx);
		return JS_ThrowOutOfMemory(ctx);
	}
	req_ctx->query_id = dns_random_query_id();
	req_ctx->udp.data = req_ctx;
	req_ctx->send_req.data = req_ctx;
	req_ctx->resolve_func = JS_UNDEFINED;
	req_ctx->reject_func = JS_UNDEFINED;
	req_ctx->controller = JS_UNDEFINED;

	// Create promise
	JSValue promise, callbacks[2];
	promise = JS_NewPromiseCapability(ctx, callbacks);
	if (JS_IsException(promise)) {
		if (server_is_js) JS_FreeCString(ctx, server);
		JS_FreeCString(ctx, hostname);
		free(req_ctx->hostname);
		free(req_ctx);
		return promise;
	}
	req_ctx->resolve_func = callbacks[0];
	req_ctx->reject_func = callbacks[1];
	JSValue controller = JS_NewObjectClass(ctx, tjs_dns_query_class_id);
	if (JS_IsException(controller)) {
		if (server_is_js) JS_FreeCString(ctx, server);
		JS_FreeValue(ctx, req_ctx->resolve_func);
		JS_FreeValue(ctx, req_ctx->reject_func);
		JS_FreeValue(ctx, promise);
		free(req_ctx->hostname);
		free(req_ctx);
		return controller;
	}
	JS_SetOpaque(controller, req_ctx);
	req_ctx->controller = JS_DupValue(ctx, controller);
	JSValue abort_func = JS_NewCFunctionData(ctx, tjs_dns_query_abort,
		0, 0, 1, (JSValueConst[]) { controller });
	JS_FreeValue(ctx, controller);
	if (JS_IsException(abort_func)) {
		if (server_is_js) JS_FreeCString(ctx, server);
		dns_udp_detach_controller(req_ctx);
		JS_FreeValue(ctx, req_ctx->resolve_func);
		JS_FreeValue(ctx, req_ctx->reject_func);
		JS_FreeValue(ctx, promise);
		free(req_ctx->hostname);
		free(req_ctx);
		return abort_func;
	}
	JS_DefinePropertyValueStr(ctx, promise, "abort", abort_func, JS_PROP_CONFIGURABLE);

	// Build DNS query packet
	int query_len = build_dns_query(hostname, req_ctx->query_id, qtype,
		req_ctx->query_buf, sizeof(req_ctx->query_buf));
	req_ctx->query_len = query_len > 0 ? (unsigned int) query_len : 0;

	JS_FreeCString(ctx, hostname);

	if (query_len < 0) {
		if (server_is_js) JS_FreeCString(ctx, server);
		dns_udp_detach_controller(req_ctx);
		dns_udp_free_callbacks(req_ctx);
		JS_FreeValue(ctx, promise);
		free(req_ctx->hostname);
		free(req_ctx);
		return JS_ThrowInternalError(ctx, "Failed to build DNS query");
	}

	// Setup IPv4 or IPv6 server address.
	struct sockaddr_in server_addr4;
	struct sockaddr_in6 server_addr6;
	int r = uv_ip4_addr(server, port, &server_addr4);
	if (r == 0) {
		memcpy(&req_ctx->server_addr, &server_addr4, sizeof(server_addr4));
	} else {
		r = uv_ip6_addr(server, port, &server_addr6);
		if (r == 0) memcpy(&req_ctx->server_addr, &server_addr6, sizeof(server_addr6));
	}
	if (server_is_js) {
		JS_FreeCString(ctx, server);
		server_is_js = false;
	}
	if (r < 0) {
		dns_udp_detach_controller(req_ctx);
		dns_udp_free_callbacks(req_ctx);
		JS_FreeValue(ctx, promise);
		free(req_ctx->hostname);
		free(req_ctx);
		return JS_ThrowTypeError(ctx, "Invalid server address");
	}

	// Initialize UDP socket
	// Note: TJS is not using libuv's default loop
	uv_loop_t* loop = TJS_GetLoop(trt);
	r = uv_udp_init(loop, &req_ctx->udp);
	if (r < 0) {
		dns_udp_detach_controller(req_ctx);
		dns_udp_free_callbacks(req_ctx);
		JS_FreeValue(ctx, promise);
		free(req_ctx->hostname);
		free(req_ctx);
		return tjs_throw_errno(ctx, r);
	}

	// Start receiving
	r = uv_udp_recv_start(&req_ctx->udp, udp_alloc_callback, udp_recv_callback);
	if (r < 0) {
		uv_close((uv_handle_t*) &req_ctx->udp, cleanup_callback);
		dns_udp_detach_controller(req_ctx);
		dns_udp_free_callbacks(req_ctx);
		JS_FreeValue(ctx, promise);
		return tjs_throw_errno(ctx, r);
	}

	// Send query
	uv_buf_t buf = uv_buf_init((char*) req_ctx->query_buf, req_ctx->query_len);
	r = uv_udp_send(&req_ctx->send_req, &req_ctx->udp, &buf, 1,
		(const struct sockaddr*) &req_ctx->server_addr,
		udp_send_callback);

	if (r < 0) {
		uv_udp_recv_stop(&req_ctx->udp);
		uv_close((uv_handle_t*) &req_ctx->udp, cleanup_callback);
		dns_udp_detach_controller(req_ctx);
		dns_udp_free_callbacks(req_ctx);
		JS_FreeValue(ctx, promise);
		return tjs_throw_errno(ctx, r);
	}

	return promise;
}

static const JSCFunctionListEntry tjs_dns_funcs[] = {
	JS_CFUNC_DEF("query", 4, tjs_dns_query),
	// DNS record type constants
	TJS_CONST2("A", DNS_A),
	TJS_CONST2("AAAA", DNS_AAAA),
	TJS_CONST2("CNAME", DNS_CNAME),
	TJS_CONST2("MX", DNS_MX),
	TJS_CONST2("NS", DNS_NS),
	TJS_CONST2("PTR", DNS_PTR),
	TJS_CONST2("SOA", DNS_SOA),
	TJS_CONST2("SRV", DNS_SRV),
	TJS_CONST2("TXT", DNS_TXT),
	TJS_CONST2("NAPTR", DNS_NAPTR),
	TJS_CONST2("CAA", DNS_CAA),
	TJS_CONST2("ANY", DNS_ANY),

	TJS_CFUNC_DEF("lookupService", 2, tjs_dns_lookup_service),
	TJS_CFUNC_DEF("resolve", 2, tjs_dns_getaddrinfo),
	TJS_CFUNC_DEF("resolveSync", 2, tjs_dns_getaddrinfo_sync)
};

void tjs__mod_dns_init(JSContext* ctx, JSValue ns) {
	JSRuntime* rt = JS_GetRuntime(ctx);
	JS_NewClassID(rt, &tjs_dns_query_class_id);
	JS_NewClass(rt, tjs_dns_query_class_id, &tjs_dns_query_class);
	JS_SetPropertyFunctionList(ctx, ns, tjs_dns_funcs, countof(tjs_dns_funcs));
}
