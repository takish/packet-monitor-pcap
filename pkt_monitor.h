/*
 * pkt_monitor.h - Shared types and constants
 */

#ifndef PKT_MONITOR_H
#define PKT_MONITOR_H

#include <stdint.h>
#include <time.h>
#include <pcap/pcap.h>

#define SNAP_LEN     1600
#define INTVAL       10
#define MAX_IFACES   8

typedef struct {
    uint32_t all;
    uint32_t ip;
    uint32_t ipv6;
    uint32_t arp;
    uint32_t icmp;
    uint32_t tcp;
    uint32_t udp;
    uint64_t bytes;
} packet_counter_t;

typedef struct {
    char             name[16];
    pcap_t          *handle;
    packet_counter_t pkt_cnt;     /* per-second, reset every tick */
    packet_counter_t total_cnt;   /* cumulative */
    int              elapsed_sec;
} iface_ctx_t;

typedef struct {
    const char *filter_expr;    /* -f: BPF filter */
    const char *log_file;       /* -l: log file path */
    int         direction;      /* 0=both, 1=in, 2=out */
    int         use_tui;        /* -u */
    int         json_mode;      /* -j */
    int         csv_mode;       /* -c */
    int         duration;       /* -t: seconds, 0=unlimited */
    double      alert_kbps;     /* -a: threshold, 0=disabled */
    int         top_n;          /* -T: 0=disabled */
    int         no_promisc;     /* -p: disable promiscuous mode */
    int         interval_ms;    /* -n: output interval in ms (default 1000) */
    const char *write_file;     /* -w: pcap output file */
    const char *read_file;      /* -r: pcap input file */
    int         layer_mode;     /* -L: 0=all, 2/3/4=layer detail */
} monitor_config_t;

static inline void get_time_str(char *buf, size_t len)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, len, "%H:%M:%S", tm);
}

#endif /* PKT_MONITOR_H */
