/*
 * dns_parse.c - DNS packet parser
 */

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "dns_parse.h"

/* ---- name tables ------------------------------------------------------ */

const char *dns_type_name(uint16_t type)
{
    switch (type) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 41:  return "OPT";
    case 65:  return "HTTPS";
    case 255: return "ANY";
    default:  return NULL;
    }
}

const char *dns_rcode_name(int rcode)
{
    switch (rcode) {
    case 0: return "NOERROR";
    case 1: return "FORMERR";
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 4: return "NOTIMP";
    case 5: return "REFUSED";
    default: return "UNKNOWN";
    }
}

/* ---- DNS name decompression ------------------------------------------- */

/*
 * Decode a DNS name with compression pointer support.
 * pkt: start of DNS packet, pkt_len: total packet length.
 * offset: current read position (updated on return).
 * out: output buffer, out_len: output buffer size.
 * Returns 0 on success, -1 on error.
 */
static int dns_decode_name(const uint8_t *pkt, size_t pkt_len,
                           size_t *offset, char *out, size_t out_len)
{
    size_t pos = *offset;
    size_t out_pos = 0;
    int jumped = 0;
    size_t end_pos = 0;
    int loop_guard = 0;

    while (pos < pkt_len) {
        uint8_t label_len = pkt[pos];

        if (loop_guard++ > 128) return -1;  /* circular reference */

        if (label_len == 0) {
            pos++;
            if (!jumped) end_pos = pos;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* compression pointer */
            if (pos + 1 >= pkt_len) return -1;
            size_t ptr = ((size_t)(label_len & 0x3F) << 8) | pkt[pos + 1];
            if (ptr >= pkt_len) return -1;
            if (!jumped) end_pos = pos + 2;
            pos = ptr;
            jumped = 1;
            continue;
        }

        pos++;
        if (pos + label_len > pkt_len) return -1;

        if (out_pos > 0 && out_pos < out_len - 1)
            out[out_pos++] = '.';

        size_t copy_len = label_len;
        if (out_pos + copy_len >= out_len - 1)
            copy_len = out_len - 1 - out_pos;
        memcpy(out + out_pos, pkt + pos, copy_len);
        out_pos += copy_len;
        pos += label_len;
    }

    out[out_pos] = '\0';
    *offset = jumped ? end_pos : pos;
    return 0;
}

/* ---- main parser ------------------------------------------------------ */

int dns_parse(const uint8_t *data, size_t len, dns_parsed_t *out)
{
    size_t offset;
    int i;

    memset(out, 0, sizeof(*out));

    if (len < 12) return -1;

    /* Parse header */
    out->hdr.id      = ntohs(*(const uint16_t *)(data + 0));
    out->hdr.flags   = ntohs(*(const uint16_t *)(data + 2));
    out->hdr.qdcount = ntohs(*(const uint16_t *)(data + 4));
    out->hdr.ancount = ntohs(*(const uint16_t *)(data + 6));
    out->hdr.nscount = ntohs(*(const uint16_t *)(data + 8));
    out->hdr.arcount = ntohs(*(const uint16_t *)(data + 10));

    out->is_response = (out->hdr.flags >> 15) & 1;
    out->rcode       = out->hdr.flags & 0x0F;

    offset = 12;

    /* Parse question section (only first question) */
    if (out->hdr.qdcount > 0) {
        if (dns_decode_name(data, len, &offset, out->qname,
                            sizeof(out->qname)) < 0)
            return -1;
        if (offset + 4 > len) return -1;
        out->qtype  = ntohs(*(const uint16_t *)(data + offset));
        out->qclass = ntohs(*(const uint16_t *)(data + offset + 2));
        offset += 4;

        /* skip remaining questions */
        for (i = 1; i < (int)out->hdr.qdcount; i++) {
            char skip[256];
            if (dns_decode_name(data, len, &offset, skip, sizeof(skip)) < 0)
                return -1;
            if (offset + 4 > len) return -1;
            offset += 4;
        }
    }

    /* Parse answer section */
    out->answer_count = 0;
    for (i = 0; i < (int)out->hdr.ancount && offset < len; i++) {
        char name[256];
        uint16_t rtype, rclass, rdlen;
        uint32_t ttl;

        if (dns_decode_name(data, len, &offset, name, sizeof(name)) < 0)
            break;
        if (offset + 10 > len) break;

        rtype  = ntohs(*(const uint16_t *)(data + offset));
        rclass = ntohs(*(const uint16_t *)(data + offset + 2));
        memcpy(&ttl, data + offset + 4, 4);
        ttl = ntohl(ttl);
        rdlen  = ntohs(*(const uint16_t *)(data + offset + 8));
        offset += 10;

        if (offset + rdlen > len) break;

        if (out->answer_count < DNS_MAX_ANSWERS) {
            dns_answer_t *a = &out->answers[out->answer_count];
            snprintf(a->name, sizeof(a->name), "%s", name);
            a->type   = rtype;
            a->class_ = rclass;
            a->ttl    = ttl;
            a->rdata_str[0] = '\0';

            /* Format rdata based on type */
            if (rtype == 1 && rdlen == 4) {
                /* A record */
                struct in_addr addr;
                memcpy(&addr, data + offset, 4);
                inet_ntop(AF_INET, &addr, a->rdata_str,
                          sizeof(a->rdata_str));
            } else if (rtype == 28 && rdlen == 16) {
                /* AAAA record */
                struct in6_addr addr6;
                memcpy(&addr6, data + offset, 16);
                inet_ntop(AF_INET6, &addr6, a->rdata_str,
                          sizeof(a->rdata_str));
            } else if (rtype == 5 || rtype == 2 || rtype == 12) {
                /* CNAME, NS, PTR */
                size_t rd_off = offset;
                dns_decode_name(data, len, &rd_off,
                                a->rdata_str, sizeof(a->rdata_str));
            } else if (rtype == 15 && rdlen >= 3) {
                /* MX: 2-byte preference + name */
                uint16_t pref = ntohs(*(const uint16_t *)(data + offset));
                size_t rd_off = offset + 2;
                char mx_name[200];
                if (dns_decode_name(data, len, &rd_off,
                                    mx_name, sizeof(mx_name)) == 0)
                    snprintf(a->rdata_str, sizeof(a->rdata_str),
                             "%u %s", pref, mx_name);
            } else {
                snprintf(a->rdata_str, sizeof(a->rdata_str),
                         "(%u bytes)", rdlen);
            }

            out->answer_count++;
        }

        offset += rdlen;
    }

    return 0;
}
