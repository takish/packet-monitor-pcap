/*
 * layer_detail.h - Layer detail mode: ring buffer, counters, and display helpers
 */

#ifndef LAYER_DETAIL_H
#define LAYER_DETAIL_H

#include <stdint.h>
#include <sys/time.h>

#define DETAIL_RING_SIZE 64
#define DETAIL_LINE_LEN  256

/* ---- ring buffer ------------------------------------------------------ */

typedef struct {
    char           line[DETAIL_LINE_LEN];  /* formatted display line */
    struct timeval ts;                      /* timestamp */
} detail_entry_t;

typedef struct {
    detail_entry_t entries[DETAIL_RING_SIZE];
    int head;   /* next write position */
    int count;  /* entries stored (max DETAIL_RING_SIZE) */
} detail_ring_t;

void                   detail_ring_push(detail_ring_t *ring, const char *line);
const detail_entry_t  *detail_ring_get(const detail_ring_t *ring, int idx);
void                   detail_ring_clear(detail_ring_t *ring);

/* ---- layer counters --------------------------------------------------- */

typedef struct {
    uint32_t request;
    uint32_t reply;
    uint32_t other;
} layer2_counter_t;

typedef struct {
    uint32_t ipv4;
    uint32_t ipv6;
    uint32_t icmp;
} layer3_counter_t;

typedef struct {
    uint32_t tcp_total;
    uint32_t udp_total;
    uint32_t tcp_syn;
    uint32_t tcp_synack;
    uint32_t tcp_ack;
    uint32_t tcp_fin;
    uint32_t tcp_rst;
    uint32_t tcp_psh;
} layer4_counter_t;

/* ---- ARP resolver tracker --------------------------------------------- */

#define ARP_PENDING_MAX  128
#define ARP_TIMEOUT_MS   3000

typedef struct {
    uint32_t       target_ip;       /* network byte order */
    struct timeval request_time;
    int            answered;
} arp_pending_t;

typedef struct {
    uint32_t requests;
    uint32_t replies;
    uint32_t matched;       /* request→reply paired */
    uint32_t timeouts;
    uint32_t gratuitous;
} arp_resolve_counter_t;

typedef struct {
    arp_pending_t         pending[ARP_PENDING_MAX];
    int                   pending_count;
    arp_resolve_counter_t counter;
} arp_resolver_t;

/* ---- DNS resolver tracker --------------------------------------------- */

#define DNS_PENDING_MAX  256
#define DNS_TIMEOUT_MS   5000

typedef struct {
    uint16_t       txid;
    char           qname[128];
    struct timeval query_time;
    int            answered;
} dns_pending_t;

typedef struct {
    uint32_t queries;
    uint32_t responses;
    uint32_t matched;
    uint32_t timeouts;
    uint32_t nxdomain;
    uint32_t errors;        /* SERVFAIL, REFUSED, etc. */
} dns_resolve_counter_t;

typedef struct {
    dns_pending_t          pending[DNS_PENDING_MAX];
    int                    pending_count;
    dns_resolve_counter_t  counter;
} dns_resolver_t;

/* ---- unified detail context ------------------------------------------- */

typedef struct {
    detail_ring_t      ring;
    layer2_counter_t   l2;
    layer3_counter_t   l3;
    layer4_counter_t   l4;
    arp_resolver_t     arp_res;
    dns_resolver_t     dns_res;
} detail_ctx_t;

/*
 * Build the auto BPF filter string for a given layer mode.
 * If user_filter is non-NULL, combines as "(user_filter) and (layer_filter)".
 * The result is written into buf (buflen bytes).
 * Returns buf on success, NULL if layer_mode is invalid.
 */
const char *layer_build_filter(int layer_mode, const char *user_filter,
                               char *buf, size_t buflen);

/*
 * Build the BPF filter for resolve mode.
 * resolve_mode: 'a' (arp) or 'd' (dns).
 */
const char *resolve_build_filter(int resolve_mode, const char *user_filter,
                                 char *buf, size_t buflen);

/*
 * ARP resolver: record a request, match a reply.
 * Returns elapsed_ms >= 0 on matched reply, -1 if unmatched.
 */
void arp_resolver_request(arp_resolver_t *r, uint32_t target_ip,
                          const struct timeval *ts);
double arp_resolver_reply(arp_resolver_t *r, uint32_t target_ip,
                          const struct timeval *ts);
void arp_resolver_expire(arp_resolver_t *r, const struct timeval *now);

/*
 * DNS resolver: record a query, match a response.
 */
void dns_resolver_query(dns_resolver_t *r, uint16_t txid, const char *qname,
                        const struct timeval *ts);
double dns_resolver_response(dns_resolver_t *r, uint16_t txid,
                             const struct timeval *ts);
void dns_resolver_expire(dns_resolver_t *r, const struct timeval *now);

#endif /* LAYER_DETAIL_H */
