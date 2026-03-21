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

static JSValue tjs_addrinfo2obj(JSContext* ctx, struct addrinfo* ai) {
	JSValue obj = JS_NewArray(ctx);

	struct addrinfo* ptr;
	int i = 0;
	for (ptr = ai; ptr; ptr = ptr->ai_next) {
		CHECK_EQ(ptr->ai_socktype, SOCK_STREAM);
		JSValue item = JS_NewObjectProto(ctx, JS_NULL);
		tjs_addr2obj(ctx, item, ptr->ai_addr, true);
		JS_DefinePropertyValueUint32(ctx, obj, i, item, JS_PROP_C_W_E);
		i++;
	}

	return obj;
}

static void uv__getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
	TJSGetAddrInfoReq* gr = req->data;
	CHECK_NOT_NULL(gr);

	JSContext* ctx = gr->ctx;
	JSValue arg;
	bool is_reject = status != 0;

	if (status != 0) {
		arg = tjs_new_error(ctx, status);
	}
	else {
		arg = tjs_addrinfo2obj(ctx, res);
	}

	TJS_SettlePromise(ctx, &gr->result, is_reject, 1, &arg);

	uv_freeaddrinfo(res);
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

	JSValue js_nameserver = JS_GetPropertyStr(ctx, opts, "server");
	const char* nameserver = JS_IsString(js_nameserver) ? JS_ToCString(ctx, js_nameserver) : NULL;
	JS_FreeValue(ctx, js_nameserver);

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
	hints.ai_flags = AI_ADDRCONFIG | AI_ALL;

	int r = uv_getaddrinfo(tjs_get_loop(ctx), &gr->req, uv__getaddrinfo_cb, node, nameserver, &hints);

	if (nameserver) JS_FreeCString(ctx, nameserver);
	JS_FreeCString(ctx, node);

	if (r != 0) {
		js_free(ctx, gr);
		return tjs_throw_errno(ctx, r);
	}

	return TJS_InitPromise(ctx, &gr->result);
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

	JSValue js_nameserver = JS_GetPropertyStr(ctx, opts, "server");
	const char* nameserver = JS_IsString(js_nameserver) ? JS_ToCString(ctx, js_nameserver) : NULL;
	JS_FreeValue(ctx, js_nameserver);

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = family;
	hints.ai_flags = AI_ADDRCONFIG | AI_ALL;

	// Direct system call instead of using libuv
	struct addrinfo* res = NULL;
	int r = getaddrinfo(node, nameserver, &hints, &res);

	if (nameserver) JS_FreeCString(ctx, nameserver);
	JS_FreeCString(ctx, node);

	JSValue result;
	if (r != 0) {
		result = tjs_new_error(ctx, r);
	} else {
		result = tjs_addrinfo2obj(ctx, res);
	}

	if (res) {
		freeaddrinfo(res);
	}

	return result;
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
	uint16_t query_id;
	char* hostname;
	struct sockaddr_in server_addr;
	uv_timer_t timeout_timer;
	int __close_count;
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

// ============ DNS Packet Building/Parsing ============

// Encode domain name to DNS format (www.example.com -> 3www7example3com0)
static int encode_dns_name(const char* name, uint8_t* buf, size_t buflen) {
	size_t pos = 0;
	const char* p = name;

	while (*p) {
		const char* dot = strchr(p, '.');
		size_t len = dot ? (size_t) (dot - p) : strlen(p);

		if (len == 0 || len > 63 || pos + len + 1 >= buflen) {
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

	while (pos < packet_len && label_count < 127) {
		uint8_t len = packet[pos];

		// Compression pointer
		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= packet_len) return -1;
			if (!jumped) {
				jump_offset = pos + 2;
				jumped = 1;
			}
			pos = ((len & 0x3F) << 8) | packet[pos + 1];
			if (pos >= packet_len) return -1;
			continue;
		}

		// End of name
		if (len == 0) {
			if (!jumped) *offset = pos + 1;
			else *offset = jump_offset;
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

// Build DNS query packet
static int build_dns_query(const char* hostname, uint16_t query_id,
	uint16_t qtype, uint8_t* buf, size_t buflen) {
	if (buflen < 512) return -1;

	dns_header_t* hdr = (dns_header_t*) buf;
	hdr->id = htons(query_id);
	hdr->flags = htons(0x0100);  // Standard query, recursion desired
	hdr->qdcount = htons(1);
	hdr->ancount = 0;
	hdr->nscount = 0;
	hdr->arcount = 0;

	size_t pos = sizeof(dns_header_t);
	int name_len = encode_dns_name(hostname, buf + pos, buflen - pos - 4);
	if (name_len < 0) return -1;

	pos += name_len;
	*(uint16_t*) (buf + pos) = htons(qtype);
	pos += 2;
	*(uint16_t*) (buf + pos) = htons(1);  // IN class
	pos += 2;

	return pos;
}

// Parse DNS response packet
static int parse_dns_response(const uint8_t* packet, size_t packet_len,
	dns_answer_t** answers, int* answer_count) {
	if (packet_len < sizeof(dns_header_t)) return -1;

	dns_header_t hdr;
	memcpy(&hdr, packet, sizeof(dns_header_t));
	hdr.id = ntohs(hdr.id);
	hdr.flags = ntohs(hdr.flags);
	hdr.qdcount = ntohs(hdr.qdcount);
	hdr.ancount = ntohs(hdr.ancount);

	// Check response code
	int rcode = hdr.flags & 0x000F;
	if (rcode != 0) return -1;

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
		return 0;
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

		// Parse type, class, TTL, rdlength
		if (pos + 10 > packet_len) goto parse_error;
		ans->type = ntohs(*(uint16_t*) (packet + pos));
		pos += 2;
		ans->class = ntohs(*(uint16_t*) (packet + pos));
		pos += 2;
		ans->ttl = ntohl(*(uint32_t*) (packet + pos));
		pos += 4;
		ans->rdlength = ntohs(*(uint16_t*) (packet + pos));
		pos += 2;

		// Parse rdata
		if (pos + ans->rdlength > packet_len) goto parse_error;

		// Store packet context for CNAME resolution
		ans->packet = packet;
		ans->packet_len = packet_len;
		ans->rdata_offset = pos;

		// For CNAME, don't copy raw data (it may contain pointers), decode later
		if (ans->type == 5) {
			ans->rdata = NULL;
		}
		else {
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
	JS_SetPropertyStr(ctx, obj, "ttl", JS_NewInt32(ctx, ans->ttl));

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
		uint16_t priority = ntohs(*(uint16_t*) ans->rdata);
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
	else if (ans->type == DNS_SOA && ans->rdlength > 22) {  // SOA
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
			// email format (host.master@example.com)
			char admin[256];
			char* dot = strchr(admin_dns, '.');
			if (dot) {
				size_t at = dot - admin_dns;
				memcpy(admin, admin_dns, at);
				admin[at] = '@';
				strcpy(admin + at + 1, dot + 1);
				JS_SetPropertyStr(ctx, obj, "admin", JS_NewString(ctx, admin));
			}
		}

		// 5x32bit (serial, refresh, retry, expire, minimum)
		if (offset + 20 <= ans->rdata_offset + ans->rdlength) {
			size_t param_offset = (ans->rdata) ? (offset - ans->rdata_offset) : offset;
			const uint8_t* params = ans->rdata ? (ans->rdata + param_offset) : (ans->packet + offset);

			uint32_t serial = ntohl(*(uint32_t*) params);
			uint32_t refresh = ntohl(*(uint32_t*) (params + 4));
			uint32_t retry = ntohl(*(uint32_t*) (params + 8));
			uint32_t expire = ntohl(*(uint32_t*) (params + 12));
			uint32_t minimum = ntohl(*(uint32_t*) (params + 16));

			JS_SetPropertyStr(ctx, obj, "serial", JS_NewInt32(ctx, serial));
			JS_SetPropertyStr(ctx, obj, "refresh", JS_NewInt32(ctx, refresh));
			JS_SetPropertyStr(ctx, obj, "retry", JS_NewInt32(ctx, retry));
			JS_SetPropertyStr(ctx, obj, "expire", JS_NewInt32(ctx, expire));
			JS_SetPropertyStr(ctx, obj, "minimum", JS_NewInt32(ctx, minimum));
		}
	}
	else if (ans->type == DNS_SRV && ans->rdlength > 6) {
		uint16_t priority = ntohs(*(uint16_t*) ans->rdata);
		uint16_t weight = ntohs(*(uint16_t*) (ans->rdata + 2));
		uint16_t port = ntohs(*(uint16_t*) (ans->rdata + 4));
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
		JS_SetPropertyStr(ctx, obj, "txt",
			JS_NewStringLen(ctx, (char*) ans->rdata, ans->rdlength));
	}
    else if (ans->type == DNS_NAPTR && ans->rdlength > 6) {  // NAPTR (Naming Authority Pointer)
        size_t offset = ans->rdata_offset;
        const uint8_t *ptr = ans->rdata ? ans->rdata : (ans->packet + offset);
        
        // order (2bytes), preference (2bytes)
        uint16_t order = ntohs(*(uint16_t *)ptr);
        uint16_t preference = ntohs(*(uint16_t *)(ptr + 2));
        
        // flags
        uint8_t flags_len = ptr[4];
        char flags[256] = {0};
        if (flags_len > 0 && 5 + flags_len <= ans->rdlength) {
            memcpy(flags, ptr + 5, flags_len);
            flags[flags_len] = '\0';
        }
        
        // services
        size_t pos = 5 + flags_len;
        uint8_t services_len = ptr[pos];
        char services[256] = {0};
        if (services_len > 0 && pos + 1 + services_len <= ans->rdlength) {
            memcpy(services, ptr + pos + 1, services_len);
            services[services_len] = '\0';
        }
        
        // regexp
        pos += 1 + services_len;
        uint8_t regexp_len = ptr[pos];
        char regexp[512] = {0};
        if (regexp_len > 0 && pos + 1 + regexp_len <= ans->rdlength) {
            memcpy(regexp, ptr + pos + 1, regexp_len);
            regexp[regexp_len] = '\0';
        }
        
        // replacement
        pos += 1 + regexp_len;
        char replacement[256] = {0};
        if (ans->packet && decode_dns_name(ans->packet, ans->packet_len, 
                                            &offset, replacement, sizeof(replacement)) == 0) {
            // success
        }
        
        JS_SetPropertyStr(ctx, obj, "order", JS_NewInt32(ctx, order));
        JS_SetPropertyStr(ctx, obj, "preference", JS_NewInt32(ctx, preference));
        JS_SetPropertyStr(ctx, obj, "flags", JS_NewString(ctx, flags));
        JS_SetPropertyStr(ctx, obj, "services", JS_NewString(ctx, services));
        JS_SetPropertyStr(ctx, obj, "regexp", JS_NewString(ctx, regexp));
        JS_SetPropertyStr(ctx, obj, "replacement", JS_NewString(ctx, replacement));
    }
    else if (ans->type == DNS_CAA && ans->rdlength > 2) {  // CAA (Certification Authority Authorization)
        const uint8_t *ptr = ans->rdata ? ans->rdata : (ans->packet + ans->rdata_offset);
        
        // flags (1bytes)
        uint8_t flags = ptr[0];
        JS_SetPropertyStr(ctx, obj, "flags", JS_NewInt32(ctx, flags));
        
        // tag (1bytes + string)
        uint8_t tag_len = ptr[1];
        char tag[256] = {0};
        if (tag_len > 0 && tag_len < sizeof(tag) && 2 + tag_len <= ans->rdlength) {
            memcpy(tag, ptr + 2, tag_len);
            tag[tag_len] = '\0';
            JS_SetPropertyStr(ctx, obj, "tag", JS_NewString(ctx, tag));
        }
        
        // value (remaining)
        /* fix: guard against underflow if rdlength < 2 + tag_len */
        size_t value_len = (ans->rdlength >= 2 + tag_len) ? ans->rdlength - 2 - tag_len : 0;
        if (value_len > 0) {
            const char *value = (const char *)(ptr + 2 + tag_len);
            JS_SetPropertyStr(ctx, obj, "value", 
                JS_NewStringLen(ctx, value, value_len));
        }
    }
	else {  // unknown record type
		if (ans->rdata) {
			JS_SetPropertyStr(ctx, obj, "rdlength", JS_NewInt32(ctx, ans->rdlength));
			uint8_t* data = js_malloc(ctx, ans->rdlength);
			if (data) {
				memcpy(data, ans->rdata, ans->rdlength);
				/* fix: use TJS_NewUint8Array so the buffer is freed via js_free_rt
				 * when GC'd. The old JS_NewArrayBuffer(..., NULL, NULL, 1) (external,
				 * no freer) would silently leak the js_malloc'd block. */
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
	// after udp and timeout handles are closed, free the context
	if (ctx->__close_count ++ == 1) free(ctx);
}

static void udp_recv_callback(uv_udp_t* handle, ssize_t nread,
	const uv_buf_t* buf, const struct sockaddr* addr,
	unsigned flags) {
	dns_udp_ctx_t* ctx = (dns_udp_ctx_t*) handle->data;
	JSContext* js_ctx = ctx->ctx;

	if (nread < 0) {
		JSValue error = JS_NewError(js_ctx);
		JS_SetPropertyStr(js_ctx, error, "message",
			JS_NewString(js_ctx, uv_strerror(nread)));
		JSValue args[] = { error };
		JS_Call(js_ctx, ctx->reject_func, JS_UNDEFINED, 1, args);
		JS_FreeValue(js_ctx, error);
		goto cleanup;
	}

	if (nread > 0) {
		// Parse DNS response
		dns_answer_t* answers = NULL;
		int answer_count = 0;

		if (parse_dns_response((uint8_t*) buf->base, nread,
			&answers, &answer_count) == 0) {
			JSValue result = JS_NewArray(js_ctx);

			for (int i = 0; i < answer_count; i++) {
				JSValue ans_obj = dns_answer_to_js(js_ctx, &answers[i]);
				JS_SetPropertyUint32(js_ctx, result, i, ans_obj);
			}

			free_dns_answers(answers, answer_count);

			JSValue args[] = { result };
			JS_Call(js_ctx, ctx->resolve_func, JS_UNDEFINED, 1, args);
			JS_FreeValue(js_ctx, result);
		}
		else {
			JSValue error = JS_NewError(js_ctx);
			JS_SetPropertyStr(js_ctx, error, "message",
				JS_NewString(js_ctx, "Failed to parse DNS response"));
			JSValue args[] = { error };
			JS_Call(js_ctx, ctx->reject_func, JS_UNDEFINED, 1, args);
			JS_FreeValue(js_ctx, error);
		}

		goto cleanup;
	}

	if (buf->base) free(buf->base);
	return;

cleanup:
	uv_timer_stop(&ctx->timeout_timer);
	uv_close((uv_handle_t*) &ctx->timeout_timer, cleanup_callback);
	uv_close((uv_handle_t*) &ctx->udp, cleanup_callback);
	if (buf->base) free(buf->base);
	JS_FreeValue(js_ctx, ctx->resolve_func);
	JS_FreeValue(js_ctx, ctx->reject_func);
	if (ctx->hostname) free(ctx->hostname);
}

static void udp_alloc_callback(uv_handle_t* handle, size_t suggested_size,
	uv_buf_t* buf) {
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

static void udp_send_callback(uv_udp_send_t* req, int status) {
	dns_udp_ctx_t* ctx = (dns_udp_ctx_t*) req->data;

	if (status < 0) {
		JSValue error = JS_NewError(ctx->ctx);
		JS_SetPropertyStr(ctx->ctx, error, "message",
			JS_NewString(ctx->ctx, uv_strerror(status)));
		JSValue args[] = { error };
		JS_Call(ctx->ctx, ctx->reject_func, JS_UNDEFINED, 1, args);
		JS_FreeValue(ctx->ctx, error);

		/* fix: stop recv before closing; otherwise udp_recv_callback may fire
		 * after resolve/reject funcs are freed, causing UAF. */
		uv_udp_recv_stop(&ctx->udp);
		uv_timer_stop(&ctx->timeout_timer);
		uv_close((uv_handle_t*) &ctx->timeout_timer, cleanup_callback);
		uv_close((uv_handle_t*) &ctx->udp, cleanup_callback);
		JS_FreeValue(ctx->ctx, ctx->resolve_func);
		JS_FreeValue(ctx->ctx, ctx->reject_func);
		if (ctx->hostname) free(ctx->hostname);
	}
}

static void udp_timeout_callback(uv_timer_t* handle) {
	dns_udp_ctx_t* ctx = (dns_udp_ctx_t*) handle->data;

	JSValue error = JS_NewError(ctx->ctx);
	JS_SetPropertyStr(ctx->ctx, error, "message",
		JS_NewString(ctx->ctx, "DNS query timeout"));
	JSValue args[] = { error };
	JS_Call(ctx->ctx, ctx->reject_func, JS_UNDEFINED, 1, args);
	JS_FreeValue(ctx->ctx, error);

	uv_timer_stop(&ctx->timeout_timer);
	uv_close((uv_handle_t*) &ctx->timeout_timer, cleanup_callback);
	uv_close((uv_handle_t*) &ctx->udp, cleanup_callback);
	JS_FreeValue(ctx->ctx, ctx->resolve_func);
	JS_FreeValue(ctx->ctx, ctx->reject_func);
	if (ctx->hostname) free(ctx->hostname);
}

// Sync versions of the callbacks
static void udp_recv_sync_callback(uv_udp_t* handle, ssize_t nread,
	const uv_buf_t* buf, const struct sockaddr* addr,
	unsigned flags) {
	dns_sync_ctx_t* sync_ctx = (dns_sync_ctx_t*) handle->data;
	dns_udp_ctx_t* ctx = &sync_ctx->ctx;

	if (nread < 0) {
		sync_ctx->status = nread;
		sync_ctx->done = true;
		if (buf->base) free(buf->base);  /* fix: was leaked on error early return */
		return;
	}

	if (nread > 0) {
		// Parse DNS response
		dns_answer_t* answers = NULL;
		int answer_count = 0;

		if (parse_dns_response((uint8_t*) buf->base, nread,
			&answers, &answer_count) == 0) {
			// Store the answers in the context for later use
			ctx->resolve_func = JS_NewArray(ctx->ctx);
			for (int i = 0; i < answer_count; i++) {
				JSValue ans_obj = dns_answer_to_js(ctx->ctx, &answers[i]);
				JS_SetPropertyUint32(ctx->ctx, ctx->resolve_func, i, ans_obj);
			}
			free_dns_answers(answers, answer_count);
			sync_ctx->status = 0;
		} else {
			sync_ctx->status = -1; // Parse error
		}
		sync_ctx->done = true;
	}

	if (buf->base) free(buf->base);
}

static void udp_send_sync_callback(uv_udp_send_t* req, int status) {
	dns_sync_ctx_t* sync_ctx = (dns_sync_ctx_t*) req->data;

	if (status < 0) {
		sync_ctx->status = status;
		sync_ctx->done = true;
	}
}

static void uv__close_step_1(uv_handle_t* handle) {
	dns_sync_ctx_t* ctx = (void*) handle->data;
	ctx->close_status |= 0xf;
}

static void uv__close_step_2(uv_handle_t* handle) {
	dns_sync_ctx_t* ctx = (void*) handle->data;
	ctx->close_status |= 0xf0;
}

static void udp_timeout_sync_callback(uv_timer_t* handle) {
	dns_sync_ctx_t* sync_ctx = (dns_sync_ctx_t*) handle->data;
	sync_ctx->status = -2; // Timeout error
	sync_ctx->done = true;
}

// DNS.query(hostname, type, server, [timeout])
// Performs raw UDP DNS query
static JSValue tjs_dns_query(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSRuntime* trt = TJS_GetRuntime(ctx);
	const char* hostname = JS_ToCString(ctx, argv[0]);
	if (!hostname) return JS_ThrowTypeError(ctx, "Invalid hostname");

	int32_t qtype = 1;  // Default A record
	if (argc >= 2 && -1 == JS_ToInt32(ctx, &qtype, argv[1]))
		return JS_ThrowTypeError(ctx, "Invalid query type");

	const char* server = qtype == DNS_AAAA ? "2001:4860:4860::8888" : "8.8.8.8";  // Default Google DNS
	if (argc >= 3 && !JS_IsUndefined(argv[2])) {
		server = JS_ToCString(ctx, argv[2]);
		if (!server) {
			JS_FreeCString(ctx, hostname);
			return JS_ThrowTypeError(ctx, "Invalid server");
		}
	}

	int32_t timeout_ms = 5000;  // Default 5s timeout
	if (argc >= 4 && -1 == JS_ToInt32(ctx, &timeout_ms, argv[3]))
		return JS_ThrowTypeError(ctx, "Invalid timeout");

	dns_udp_ctx_t* req_ctx = malloc(sizeof(dns_udp_ctx_t));
	if (!req_ctx) {
		JS_FreeCString(ctx, hostname);
		if (argc >= 3) JS_FreeCString(ctx, server);
		return JS_ThrowOutOfMemory(ctx);
	}
	memset(req_ctx, 0, sizeof(dns_udp_ctx_t));

	req_ctx->ctx = ctx;
	req_ctx->hostname = strdup(hostname);
	req_ctx->query_id = (uint16_t) (rand() & 0xFFFF);
	req_ctx->udp.data = req_ctx;
	req_ctx->send_req.data = req_ctx;
	req_ctx->timeout_timer.data = req_ctx;

	// Create promise
	JSValue promise, callbacks[2];
	promise = JS_NewPromiseCapability(ctx, callbacks);
	req_ctx->resolve_func = callbacks[0];
	req_ctx->reject_func = callbacks[1];

	// Build DNS query packet
	uint8_t query_buf[512];
	int query_len = build_dns_query(hostname, req_ctx->query_id, qtype,
		query_buf, sizeof(query_buf));

	JS_FreeCString(ctx, hostname);

	if (query_len < 0) {
		if (argc >= 3) JS_FreeCString(ctx, server);
		JS_FreeValue(ctx, req_ctx->resolve_func);
		JS_FreeValue(ctx, req_ctx->reject_func);
		free(req_ctx->hostname);
		free(req_ctx);
		return JS_ThrowInternalError(ctx, "Failed to build DNS query");
	}

	// Setup server address
	uv_ip4_addr(server, 53, &req_ctx->server_addr);
	if (argc >= 3) JS_FreeCString(ctx, server);

	// Initialize UDP socket
	// Note: TJS is not using libuv's default loop
	uv_loop_t* loop = TJS_GetLoop(trt);
	uv_udp_init(loop, &req_ctx->udp);

	// Start receiving
	uv_udp_recv_start(&req_ctx->udp, udp_alloc_callback, udp_recv_callback);

	// Send query
	uv_buf_t buf = uv_buf_init((char*) query_buf, query_len);
	int ret = uv_udp_send(&req_ctx->send_req, &req_ctx->udp, &buf, 1,
		(const struct sockaddr*) &req_ctx->server_addr,
		udp_send_callback);

	if (ret < 0) {
		req_ctx->__close_count = 1;  // no timer handle to close
		uv_close((uv_handle_t*) &req_ctx->udp, cleanup_callback);
		JS_FreeValue(ctx, req_ctx->resolve_func);
		JS_FreeValue(ctx, req_ctx->reject_func);
		free(req_ctx->hostname);
		return JS_ThrowInternalError(ctx, "Failed to send DNS query");
	}

	// Setup timeout
	uv_timer_init(loop, &req_ctx->timeout_timer);
	uv_timer_start(&req_ctx->timeout_timer, udp_timeout_callback,
		timeout_ms, 0);

	return promise;
}

// DNS.querySync(hostname, type, server, [timeout])
// Performs raw UDP DNS query synchronously
static JSValue tjs_dns_query_sync(JSContext* ctx, JSValueConst this_val,
	int argc, JSValueConst* argv) {
	TJSRuntime* trt = TJS_GetRuntime(ctx);
	const char* hostname = JS_ToCString(ctx, argv[0]);
	if (!hostname) return JS_ThrowTypeError(ctx, "Invalid hostname");

	int32_t qtype = 1;  // Default A record
	if (argc >= 2 && -1 == JS_ToInt32(ctx, &qtype, argv[1]))
		return JS_ThrowTypeError(ctx, "Invalid query type");

	const char* server = qtype == DNS_AAAA ? "2001:4860:4860::8888" : "8.8.8.8";  // Default Google DNS
	if (argc >= 3 && !JS_IsUndefined(argv[2])) {
		server = JS_ToCString(ctx, argv[2]);
		if (!server) {
			JS_FreeCString(ctx, hostname);
			return JS_ThrowTypeError(ctx, "Invalid server");
		}
	}

	int32_t timeout_ms = 5000;  // Default 5s timeout
	if (argc >= 4 && -1 == JS_ToInt32(ctx, &timeout_ms, argv[3]))
		return JS_ThrowTypeError(ctx, "Invalid timeout");

	dns_sync_ctx_t* req_ctx = malloc(sizeof(dns_sync_ctx_t));
	if (!req_ctx) {
		JS_FreeCString(ctx, hostname);
		if (argc >= 3) JS_FreeCString(ctx, server);
		return JS_ThrowOutOfMemory(ctx);
	}
	memset(req_ctx, 0, sizeof(dns_sync_ctx_t));
	/* fix: resolve_func is abused to hold the result array in sync mode; init
	 * it to JS_UNDEFINED (not 0) so it's safe to JS_FreeValue on error paths */
	dns_udp_ctx_t* udp_ctx = &req_ctx->ctx;
	udp_ctx->resolve_func = JS_UNDEFINED;
	udp_ctx->ctx = ctx;
	udp_ctx->hostname = strdup(hostname);
	udp_ctx->query_id = (uint16_t) (rand() & 0xFFFF);
	udp_ctx->udp.data = req_ctx;
	udp_ctx->send_req.data = req_ctx;
	udp_ctx->timeout_timer.data = req_ctx;
	req_ctx->done = false;
	req_ctx->status = 0;
	req_ctx->close_status = 0;

	// Build DNS query packet
	uint8_t query_buf[512];
	int query_len = build_dns_query(hostname, udp_ctx->query_id, qtype,
		query_buf, sizeof(query_buf));

	JS_FreeCString(ctx, hostname);

	if (query_len < 0) {
		if (argc >= 3) JS_FreeCString(ctx, server);
		free(udp_ctx->hostname);
		free(req_ctx);
		return JS_ThrowInternalError(ctx, "Failed to build DNS query");
	}

	// Setup server address
	uv_ip4_addr(server, 53, &udp_ctx->server_addr);
	if (argc >= 3) JS_FreeCString(ctx, server);

	// Initialize UDP socket
	// Note: TJS is not using libuv's default loop
	uv_loop_t* loop = TJS_GetLoop(trt);
	uv_udp_init(loop, &udp_ctx->udp);

	// Start receiving
	uv_udp_recv_start(&udp_ctx->udp, udp_alloc_callback, udp_recv_sync_callback);

	// Send query
	uv_buf_t buf = uv_buf_init((char*) query_buf, query_len);
	int ret = uv_udp_send(&udp_ctx->send_req, &udp_ctx->udp, &buf, 1,
		(const struct sockaddr*) &udp_ctx->server_addr,
		udp_send_sync_callback);

	if (ret < 0) {
		uv_close((uv_handle_t*) &udp_ctx->udp, NULL);
		free(udp_ctx->hostname);
		free(req_ctx);
		return JS_ThrowInternalError(ctx, "Failed to send DNS query");
	}

	// Setup timeout
	uv_timer_init(loop, &udp_ctx->timeout_timer);
	uv_timer_start(&udp_ctx->timeout_timer, udp_timeout_sync_callback,
		timeout_ms, 0);

	// Run the event loop until the operation is done
	while (!req_ctx->done) {
		uv_run(loop, UV_RUN_ONCE);
	}

	// Clean up
	uv_timer_stop(&udp_ctx->timeout_timer);
	uv_udp_recv_stop(&udp_ctx->udp);
	
	// Close handles
	req_ctx->close_status = 0;
	uv_close((uv_handle_t*) &udp_ctx->timeout_timer, uv__close_step_1);
	uv_close((uv_handle_t*) &udp_ctx->udp, uv__close_step_2);
	
	// Wait for handles to be closed properly
	while (req_ctx->close_status != 0xff) {
		uv_run(loop, UV_RUN_ONCE);
	}

	JSValue result;
	if (req_ctx->status != 0) {
		const char* error_msg;
		switch (req_ctx->status) {
			case -1:
				error_msg = "Failed to parse DNS response";
				break;
			case -2:
				error_msg = "DNS query timeout";
				break;
			default:
				error_msg = uv_strerror(req_ctx->status);
				break;
		}
		result = JS_ThrowInternalError(ctx, error_msg);
	} else {
		result = udp_ctx->resolve_func;
	}

	free(udp_ctx->hostname);
	free(req_ctx);

	return result;
}

static const JSCFunctionListEntry tjs_dns_funcs[] = {
	JS_CFUNC_DEF("query", 4, tjs_dns_query),
	JS_CFUNC_DEF("querySync", 4, tjs_dns_query_sync),
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

	TJS_CFUNC_DEF("resolve", 2, tjs_dns_getaddrinfo),
	TJS_CFUNC_DEF("resolveSync", 2, tjs_dns_getaddrinfo_sync),
};

void tjs__mod_dns_init(JSContext* ctx, JSValue ns) {
	JS_SetPropertyFunctionList(ctx, ns, tjs_dns_funcs, countof(tjs_dns_funcs));
}