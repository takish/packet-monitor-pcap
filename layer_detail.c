/*
 * layer_detail.c - Layer detail mode: ring buffer, resolver trackers, filters
 */

#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include "layer_detail.h"

/* ---- ring buffer ------------------------------------------------------ */

void detail_ring_push(detail_ring_t *ring, const char *line)
{
    detail_entry_t *e = &ring->entries[ring->head];

    snprintf(e->line, DETAIL_LINE_LEN, "%s", line);
    gettimeofday(&e->ts, NULL);

    ring->head = (ring->head + 1) % DETAIL_RING_SIZE;
    if (ring->count < DETAIL_RING_SIZE)
        ring->count++;
}

const detail_entry_t *detail_ring_get(const detail_ring_t *ring, int idx)
{
    int pos;

    if (idx < 0 || idx >= ring->count)
        return NULL;

    if (ring->count < DETAIL_RING_SIZE)
        pos = idx;
    else
        pos = (ring->head + idx) % DETAIL_RING_SIZE;

    return &ring->entries[pos];
}

void detail_ring_clear(detail_ring_t *ring)
{
    ring->head  = 0;
    ring->count = 0;
}

/* ---- BPF filter builders ---------------------------------------------- */

const char *layer_build_filter(int layer_mode, const char *user_filter,
                               char *buf, size_t buflen)
{
    const char *layer_filter;

    switch (layer_mode) {
    case 2:
        layer_filter = "arp";
        break;
    case 3:
        layer_filter = "ip or ip6 or icmp";
        break;
    case 4:
        layer_filter = "tcp or udp";
        break;
    default:
        return NULL;
    }

    if (user_filter)
        snprintf(buf, buflen, "(%s) and (%s)", user_filter, layer_filter);
    else
        snprintf(buf, buflen, "%s", layer_filter);

    return buf;
}

const char *resolve_build_filter(int resolve_mode, const char *user_filter,
                                 char *buf, size_t buflen)
{
    const char *base;

    switch (resolve_mode) {
    case 'a':
        base = "arp";
        break;
    case 'd':
        base = "udp port 53";
        break;
    default:
        return NULL;
    }

    if (user_filter)
        snprintf(buf, buflen, "(%s) and (%s)", user_filter, base);
    else
        snprintf(buf, buflen, "%s", base);

    return buf;
}

/* ---- timeval helpers -------------------------------------------------- */

static double tv_diff_ms(const struct timeval *end, const struct timeval *start)
{
    double sec  = (double)(end->tv_sec  - start->tv_sec);
    double usec = (double)(end->tv_usec - start->tv_usec);
    return sec * 1000.0 + usec / 1000.0;
}

/* ---- ARP resolver ----------------------------------------------------- */

void arp_resolver_request(arp_resolver_t *r, uint32_t target_ip,
                          const struct timeval *ts)
{
    int i;

    r->counter.requests++;

    /* check for existing pending entry for this target */
    for (i = 0; i < r->pending_count; i++) {
        if (r->pending[i].target_ip == target_ip && !r->pending[i].answered) {
            r->pending[i].request_time = *ts;
            return;
        }
    }

    /* add new pending entry */
    if (r->pending_count < ARP_PENDING_MAX) {
        arp_pending_t *p = &r->pending[r->pending_count++];
        p->target_ip    = target_ip;
        p->request_time = *ts;
        p->answered     = 0;
    }
}

double arp_resolver_reply(arp_resolver_t *r, uint32_t target_ip,
                          const struct timeval *ts)
{
    int i;

    r->counter.replies++;

    for (i = 0; i < r->pending_count; i++) {
        if (r->pending[i].target_ip == target_ip && !r->pending[i].answered) {
            r->pending[i].answered = 1;
            r->counter.matched++;
            return tv_diff_ms(ts, &r->pending[i].request_time);
        }
    }

    return -1.0;
}

void arp_resolver_expire(arp_resolver_t *r, const struct timeval *now)
{
    int i, j;

    for (i = 0; i < r->pending_count; ) {
        arp_pending_t *p = &r->pending[i];
        if (p->answered || tv_diff_ms(now, &p->request_time) > ARP_TIMEOUT_MS) {
            if (!p->answered)
                r->counter.timeouts++;
            /* remove by shifting */
            for (j = i; j < r->pending_count - 1; j++)
                r->pending[j] = r->pending[j + 1];
            r->pending_count--;
        } else {
            i++;
        }
    }
}

/* ---- DNS resolver ----------------------------------------------------- */

void dns_resolver_query(dns_resolver_t *r, uint16_t txid, const char *qname,
                        const struct timeval *ts)
{
    int i;

    r->counter.queries++;

    /* check for existing pending entry with same txid */
    for (i = 0; i < r->pending_count; i++) {
        if (r->pending[i].txid == txid && !r->pending[i].answered) {
            r->pending[i].query_time = *ts;
            snprintf(r->pending[i].qname, sizeof(r->pending[i].qname),
                     "%s", qname);
            return;
        }
    }

    if (r->pending_count < DNS_PENDING_MAX) {
        dns_pending_t *p = &r->pending[r->pending_count++];
        p->txid      = txid;
        p->query_time = *ts;
        p->answered  = 0;
        snprintf(p->qname, sizeof(p->qname), "%s", qname);
    }
}

double dns_resolver_response(dns_resolver_t *r, uint16_t txid,
                             const struct timeval *ts)
{
    int i;

    r->counter.responses++;

    for (i = 0; i < r->pending_count; i++) {
        if (r->pending[i].txid == txid && !r->pending[i].answered) {
            r->pending[i].answered = 1;
            r->counter.matched++;
            return tv_diff_ms(ts, &r->pending[i].query_time);
        }
    }

    return -1.0;
}

void dns_resolver_expire(dns_resolver_t *r, const struct timeval *now)
{
    int i, j;

    for (i = 0; i < r->pending_count; ) {
        dns_pending_t *p = &r->pending[i];
        if (p->answered || tv_diff_ms(now, &p->query_time) > DNS_TIMEOUT_MS) {
            if (!p->answered)
                r->counter.timeouts++;
            for (j = i; j < r->pending_count - 1; j++)
                r->pending[j] = r->pending[j + 1];
            r->pending_count--;
        } else {
            i++;
        }
    }
}
