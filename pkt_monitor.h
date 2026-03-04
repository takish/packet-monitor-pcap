/*
 * pkt_monitor.h - Shared types and constants
 */

#ifndef PKT_MONITOR_H
#define PKT_MONITOR_H

#include <pcap/pcap.h>

#define SNAP_LEN     1600
#define INTVAL       10
#define MAX_IFACES   8

typedef struct {
    int all;
    int ip;
    int ipv6;
    int arp;
    int icmp;
    int tcp;
    int udp;
    int bps;
} packet_counter_t;

typedef struct {
    char             name[16];
    pcap_t          *handle;
    packet_counter_t pkt_cnt;     /* per-second, reset every tick */
    packet_counter_t total_cnt;   /* cumulative */
    int              elapsed_sec;
} iface_ctx_t;

#endif /* PKT_MONITOR_H */
