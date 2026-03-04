/*
 * layer_detail.c - Layer detail mode: ring buffer and display helpers
 */

#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include "layer_detail.h"

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
