/*
 * pkt_monitor.h - Shared types and constants
 */

#ifndef PKT_MONITOR_H
#define PKT_MONITOR_H

#define SNAP_LEN     1600
#define INTVAL       10

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

#endif /* PKT_MONITOR_H */
