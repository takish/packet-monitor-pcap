/*
 * dns_parse.h - DNS packet parser for resolve mode
 */

#ifndef DNS_PARSE_H
#define DNS_PARSE_H

#include <stdint.h>
#include <stddef.h>

/* DNS header (12 bytes) */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/* Parsed DNS answer record */
typedef struct {
    char     name[256];
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    char     rdata_str[256];  /* human-readable rdata */
} dns_answer_t;

#define DNS_MAX_ANSWERS 8

/* Parsed DNS packet */
typedef struct {
    dns_header_t hdr;
    char         qname[256];
    uint16_t     qtype;
    uint16_t     qclass;
    int          is_response;
    int          rcode;
    int          answer_count;          /* actually parsed count */
    dns_answer_t answers[DNS_MAX_ANSWERS];
} dns_parsed_t;

/*
 * Parse a DNS packet starting from the DNS header.
 * data: pointer to start of DNS header
 * len:  bytes available
 * Returns 0 on success, -1 on parse error.
 */
int dns_parse(const uint8_t *data, size_t len, dns_parsed_t *out);

/* Lookup DNS record type name (A, AAAA, CNAME, etc.) */
const char *dns_type_name(uint16_t type);

/* Lookup DNS RCODE name (NOERROR, NXDOMAIN, etc.) */
const char *dns_rcode_name(int rcode);

#endif /* DNS_PARSE_H */
