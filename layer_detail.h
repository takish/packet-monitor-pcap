/*
 * layer_detail.h - Layer detail mode: ring buffer and display helpers
 */

#ifndef LAYER_DETAIL_H
#define LAYER_DETAIL_H

#include <sys/time.h>

#define DETAIL_RING_SIZE 64
#define DETAIL_LINE_LEN  256

typedef struct {
    char           line[DETAIL_LINE_LEN];  /* formatted display line */
    struct timeval ts;                      /* timestamp */
} detail_entry_t;

typedef struct {
    detail_entry_t entries[DETAIL_RING_SIZE];
    int head;   /* next write position */
    int count;  /* entries stored (max DETAIL_RING_SIZE) */
} detail_ring_t;

/*
 * Append a formatted line to the ring buffer.
 * Older entries are overwritten when the buffer is full.
 */
void detail_ring_push(detail_ring_t *ring, const char *line);

/*
 * Get entry at logical index (0 = oldest).
 * Returns NULL if idx >= count.
 */
const detail_entry_t *detail_ring_get(const detail_ring_t *ring, int idx);

/*
 * Clear all entries.
 */
void detail_ring_clear(detail_ring_t *ring);

/*
 * Build the auto BPF filter string for a given layer mode.
 * If user_filter is non-NULL, combines as "(user_filter) and (layer_filter)".
 * The result is written into buf (buflen bytes).
 * Returns buf on success, NULL if layer_mode is invalid.
 */
const char *layer_build_filter(int layer_mode, const char *user_filter,
                               char *buf, size_t buflen);

#endif /* LAYER_DETAIL_H */
