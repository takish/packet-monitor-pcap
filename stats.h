/*
 * stats.h - Host and port tracking for Top-N flow analysis
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>

#define HOST_TABLE_SIZE  4096   /* must be power of 2 */
#define HOST_TABLE_MAX   3072   /* 75% load factor */
#define PORT_COUNT       65536

typedef struct {
    uint32_t addr;          /* IPv4 (network byte order), 0 = empty */
    uint32_t pkts_src;
    uint32_t pkts_dst;
} host_entry_t;

typedef struct {
    host_entry_t slots[HOST_TABLE_SIZE];
    int count;
} host_table_t;

typedef struct {
    uint32_t *tcp_dst;      /* PORT_COUNT entries, malloc'd */
    uint32_t *udp_dst;      /* PORT_COUNT entries, malloc'd */
} port_table_t;

typedef struct {
    host_table_t hosts;
    port_table_t ports;
} flow_stats_t;

int  flow_stats_init(flow_stats_t *fs);
void flow_stats_cleanup(flow_stats_t *fs);
void flow_stats_record_host(flow_stats_t *fs, uint32_t src, uint32_t dst);
void flow_stats_record_port(flow_stats_t *fs, uint16_t port, int is_tcp);
void flow_stats_print(const flow_stats_t *fs, int top_n);

#endif /* STATS_H */
