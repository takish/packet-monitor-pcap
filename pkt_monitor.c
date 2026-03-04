/*
 * pkt_monitor - Cross-platform packet monitor using libpcap
 *
 * Counts packets by protocol (IPv4, IPv6, ARP, ICMP, TCP, UDP)
 * and displays traffic statistics with bandwidth in kbps.
 *
 * Works on Linux and macOS.
 *
 * Based on the original Linux-only pkt_monitor (2004) by takashi.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>

#include <pcap/pcap.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif

#include "pkt_monitor.h"
#include "output.h"
#include "stats.h"
#include "layer_detail.h"

#ifdef HAS_NCURSES
#include "tui.h"
#endif

/* ---- global state ----------------------------------------------------- */

static iface_ctx_t ifaces[MAX_IFACES];
static int iface_count;
static volatile sig_atomic_t running = 1;
static flow_stats_t *g_flow_stats;  /* non-NULL when -T is active */
static pcap_dumper_t *g_dumper;     /* non-NULL when -w is active */

/*
 * Accumulate per-second counters into totals for one interface.
 * Does NOT zero pkt_cnt — caller is responsible for that.
 */
static void accumulate_totals(iface_ctx_t *ctx)
{
    ctx->total_cnt.all   += ctx->pkt_cnt.all;
    ctx->total_cnt.ip    += ctx->pkt_cnt.ip;
    ctx->total_cnt.ipv6  += ctx->pkt_cnt.ipv6;
    ctx->total_cnt.arp   += ctx->pkt_cnt.arp;
    ctx->total_cnt.icmp  += ctx->pkt_cnt.icmp;
    ctx->total_cnt.tcp   += ctx->pkt_cnt.tcp;
    ctx->total_cnt.udp   += ctx->pkt_cnt.udp;
    ctx->total_cnt.bytes += ctx->pkt_cnt.bytes;
    ctx->elapsed_sec++;
}

/*
 * Aggregate counters across all interfaces.
 * If use_total is non-zero, aggregates total_cnt; otherwise pkt_cnt.
 */
static void aggregate_counters(packet_counter_t *agg, int use_total)
{
    int i;
    memset(agg, 0, sizeof(*agg));
    for (i = 0; i < iface_count; i++) {
        const packet_counter_t *src = use_total ?
            &ifaces[i].total_cnt : &ifaces[i].pkt_cnt;
        agg->all   += src->all;
        agg->ip    += src->ip;
        agg->ipv6  += src->ipv6;
        agg->arp   += src->arp;
        agg->icmp  += src->icmp;
        agg->tcp   += src->tcp;
        agg->udp   += src->udp;
        agg->bytes += src->bytes;
    }
}

/*
 * pcap callback: parse each captured packet and update counters.
 * The user pointer points to the iface_ctx_t's pkt_cnt.
 */
static void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    packet_counter_t *cnt = (packet_counter_t *)user;
    const struct ether_header *eth;
    const struct ip *iph;
    uint16_t ether_type;

    if (header->caplen < sizeof(struct ether_header))
        return;

    if (g_dumper)
        pcap_dump((u_char *)g_dumper, header, packet);

    cnt->all++;
    cnt->bytes += header->len;

    eth = (const struct ether_header *)packet;
    ether_type = ntohs(eth->ether_type);

    switch (ether_type) {
    case ETHERTYPE_IP:
        cnt->ip++;
        break;
    case ETHERTYPE_IPV6:
        cnt->ipv6++;
        /* Parse IPv6 transport layer (simple: no extension header chain) */
        if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
            const struct ip6_hdr *ip6 = (const struct ip6_hdr *)
                (packet + sizeof(struct ether_header));
            /* TODO: does not follow IPv6 extension header chain */
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
            switch (ip6->ip6_nxt) {
            case IPPROTO_ICMPV6:
                cnt->icmp++;
                break;
            case IPPROTO_TCP:
                cnt->tcp++;
                break;
            case IPPROTO_UDP:
                cnt->udp++;
                break;
            }
        }
        return;
    case ETHERTYPE_ARP:
        cnt->arp++;
        return;
    default:
        return;
    }

    /* Parse IPv4 transport layer */
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
        return;

    iph = (const struct ip *)(packet + sizeof(struct ether_header));

    /* Top-N host tracking */
    if (g_flow_stats)
        flow_stats_record_host(g_flow_stats,
                               iph->ip_src.s_addr, iph->ip_dst.s_addr);

    switch (iph->ip_p) {
    case IPPROTO_ICMP:
        cnt->icmp++;
        break;
    case IPPROTO_TCP:
        cnt->tcp++;
        if (g_flow_stats) {
            unsigned int ip_hlen = (unsigned int)iph->ip_hl * 4;
            if (header->caplen >= sizeof(struct ether_header) + ip_hlen + 4) {
                const struct tcphdr *th = (const struct tcphdr *)
                    (packet + sizeof(struct ether_header) + ip_hlen);
                flow_stats_record_port(g_flow_stats, ntohs(th->th_dport), 1);
            }
        }
        break;
    case IPPROTO_UDP:
        cnt->udp++;
        if (g_flow_stats) {
            unsigned int ip_hlen = (unsigned int)iph->ip_hl * 4;
            if (header->caplen >= sizeof(struct ether_header) + ip_hlen + 4) {
                const struct udphdr *uh = (const struct udphdr *)
                    (packet + sizeof(struct ether_header) + ip_hlen);
                flow_stats_record_port(g_flow_stats, ntohs(uh->uh_dport), 0);
            }
        }
        break;
    }
}

/*
 * SIGINT/SIGTERM handler: clean shutdown.
 */
static void cleanup_handler(int sig)
{
    int i;
    (void)sig;

    running = 0;
    for (i = 0; i < iface_count; i++)
        if (ifaces[i].handle)
            pcap_breakloop(ifaces[i].handle);
}

/*
 * Close all pcap handles.
 */
static void cleanup_all(void)
{
    int i;
    for (i = 0; i < iface_count; i++) {
        if (ifaces[i].handle) {
            pcap_close(ifaces[i].handle);
            ifaces[i].handle = NULL;
        }
    }
}

/*
 * Apply BPF filter to a pcap handle.
 * Returns 0 on success, -1 on error.
 */
static int apply_filter(pcap_t *h, const char *iface_name, const char *expr)
{
    struct bpf_program fp;

    if (pcap_compile(h, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter compile error on %s: %s\n",
                iface_name, pcap_geterr(h));
        return -1;
    }
    if (pcap_setfilter(h, &fp) == -1) {
        fprintf(stderr, "Filter set error on %s: %s\n",
                iface_name, pcap_geterr(h));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

/*
 * Get current time in milliseconds.
 */
static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/*
 * Print text-mode stats lines (per-interface when multi).
 */
static void print_text_lines(int *header_count)
{
    char timebuf[16];
    int i;

    get_time_str(timebuf, sizeof(timebuf));

    if ((*header_count % INTVAL) == 0) {
        if (iface_count > 1)
            printf("# time #\tiface\t  all\t  tcp\t  udp\t ipv4\t ipv6"
                   "\ticmp\tarp\n");
        else
            printf("# time #\t  all\t  tcp\t  udp\t ipv4\t ipv6\ticmp\tarp\n");
    }
    (*header_count)++;

    for (i = 0; i < iface_count; i++) {
        packet_counter_t *c = &ifaces[i].pkt_cnt;
        if (iface_count > 1)
            printf("%s\t%s\t%5" PRIu32 "\t%5" PRIu32 "\t%5" PRIu32
                   "\t%5" PRIu32 "\t%5" PRIu32 "\t%3" PRIu32
                   "\t%3" PRIu32 "%6.1fkbps\n",
                   timebuf, ifaces[i].name,
                   c->all, c->tcp, c->udp, c->ip, c->ipv6, c->icmp,
                   c->arp, (double)c->bytes * 8.0 / 1024.0);
        else
            printf("%s\t%5" PRIu32 "\t%5" PRIu32 "\t%5" PRIu32
                   "\t%5" PRIu32 "\t%5" PRIu32 "\t%3" PRIu32
                   "\t%3" PRIu32 "%6.1fkbps\n",
                   timebuf,
                   c->all, c->tcp, c->udp, c->ip, c->ipv6, c->icmp,
                   c->arp, (double)c->bytes * 8.0 / 1024.0);
    }
}

/*
 * Text mode main loop using pcap_dispatch (non-blocking polling).
 * Replaces the old SIGALRM-based approach for better signal safety
 * and to support JSON/CSV/log/alert/duration features.
 */
static int run_text(const monitor_config_t *cfg)
{
    int header_count = 0;
    long long last_tick;
    FILE *logfp = NULL;
    packet_counter_t agg;
    double kbps;
    int i;

    if (cfg->log_file) {
        logfp = fopen(cfg->log_file, "w");
        if (!logfp) {
            perror(cfg->log_file);
            return 1;
        }
    }

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    if (cfg->csv_mode)
        output_csv_header(stdout);

    last_tick = now_ms();

    while (running) {
        /* Round-robin dispatch across all interfaces */
        for (i = 0; i < iface_count; i++) {
            int ret = pcap_dispatch(ifaces[i].handle, -1, packet_handler,
                                    (u_char *)&ifaces[i].pkt_cnt);
            if (ret == PCAP_ERROR) {
                fprintf(stderr, "pcap error on %s: %s\n",
                        ifaces[i].name, pcap_geterr(ifaces[i].handle));
                running = 0;
                break;
            }
        }

        /* Check for interval tick */
        if (now_ms() - last_tick >= cfg->interval_ms) {
            last_tick += cfg->interval_ms;

            /* Output per-second data */
            if (cfg->json_mode || cfg->csv_mode) {
                aggregate_counters(&agg, 0);
                if (cfg->json_mode)
                    output_json_line(stdout, &agg);
                else
                    output_csv_line(stdout, &agg);
            } else {
                print_text_lines(&header_count);
            }

            /* Log and alert (need aggregated data) */
            if (logfp || cfg->alert_kbps > 0) {
                if (!(cfg->json_mode || cfg->csv_mode))
                    aggregate_counters(&agg, 0);
                if (logfp)
                    output_log_line(logfp, &agg);
                if (cfg->alert_kbps > 0) {
                    kbps = (double)agg.bytes * 8.0 / 1024.0;
                    if (kbps > cfg->alert_kbps)
                        fprintf(stderr,
                                "ALERT: %.1f kbps > %.1f kbps threshold\n",
                                kbps, cfg->alert_kbps);
                }
            }

            /* Accumulate totals and reset per-second counters */
            for (i = 0; i < iface_count; i++) {
                accumulate_totals(&ifaces[i]);
                memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));
            }

            if (cfg->duration > 0 && ifaces[0].elapsed_sec >= cfg->duration)
                break;
        }
    }

    if (!cfg->json_mode && !cfg->csv_mode)
        printf("\n# Capture stopped.\n");

    if (logfp)
        fclose(logfp);

    return 0;
}

/*
 * Print capture summary at exit.
 */
static void print_summary(void)
{
    packet_counter_t agg;
    int elapsed, dur, i;

    elapsed = ifaces[0].elapsed_sec;
    dur = elapsed > 0 ? elapsed : 1;

    aggregate_counters(&agg, 1);

    printf("\n# Capture Summary\n");
    printf("# Duration: %ds\n", elapsed);
    if (iface_count > 1) {
        printf("# Interfaces:");
        for (i = 0; i < iface_count; i++)
            printf(" %s", ifaces[i].name);
        printf("\n");
    }
    printf("# Total: %" PRIu32 " packets (IPv4: %" PRIu32
           ", IPv6: %" PRIu32 ", ARP: %" PRIu32 ")\n",
           agg.all, agg.ip, agg.ipv6, agg.arp);
    printf("# Protocols: ICMP: %" PRIu32 ", TCP: %" PRIu32
           ", UDP: %" PRIu32 "\n",
           agg.icmp, agg.tcp, agg.udp);
    printf("# Average: %.1f pkt/s, %.1f kbps\n",
           (double)agg.all / dur,
           (double)agg.bytes * 8.0 / 1024.0 / dur);
}

#ifdef HAS_NCURSES
/*
 * TUI mode main loop using round-robin pcap_dispatch (non-blocking).
 */
static int run_tui(const monitor_config_t *cfg)
{
    int paused = 0;
    long long last_tick;
    int action, i;
    FILE *logfp = NULL;

    if (cfg->log_file) {
        logfp = fopen(cfg->log_file, "w");
        if (!logfp) {
            perror(cfg->log_file);
            return 1;
        }
    }

    if (tui_init(cfg) < 0) {
        if (logfp) fclose(logfp);
        return 1;
    }

    /* Disable SIGALRM in TUI mode */
    signal(SIGALRM, SIG_IGN);

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    /* Initial draw */
    tui_update(ifaces, iface_count, paused, cfg);

    last_tick = now_ms();

    for (;;) {
        if (!running)
            break;

        /* Round-robin dispatch across all interfaces */
        for (i = 0; i < iface_count; i++) {
            int ret = pcap_dispatch(ifaces[i].handle, -1, packet_handler,
                                    (u_char *)&ifaces[i].pkt_cnt);
            if (ret == PCAP_ERROR_BREAK) {
                tui_cleanup();
                if (logfp) fclose(logfp);
                return 0;
            }
        }

        /* Check for interval tick */
        if (now_ms() - last_tick >= cfg->interval_ms) {
            last_tick += cfg->interval_ms;
            if (!paused) {
                /* Log before accumulate (uses pkt_cnt) */
                if (logfp) {
                    packet_counter_t agg;
                    aggregate_counters(&agg, 0);
                    output_log_line(logfp, &agg);
                }

                /* Accumulate totals (does NOT zero pkt_cnt) */
                for (i = 0; i < iface_count; i++)
                    accumulate_totals(&ifaces[i]);

                /* Draw TUI (reads both pkt_cnt and total_cnt) */
                tui_update(ifaces, iface_count, paused, cfg);

                /* Now zero per-second counters */
                for (i = 0; i < iface_count; i++)
                    memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));

                if (cfg->duration > 0 &&
                    ifaces[0].elapsed_sec >= cfg->duration)
                    break;
            }
        }

        /* Handle keyboard input */
        action = tui_handle_input();
        if (action == 'q')
            break;
        if (action == 'p')
            paused = !paused;
        if (action == 'r') {
            for (i = 0; i < iface_count; i++) {
                memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));
                memset(&ifaces[i].total_cnt, 0, sizeof(packet_counter_t));
                ifaces[i].elapsed_sec = 0;
            }
            tui_update(ifaces, iface_count, paused, cfg);
        }
    }

    tui_cleanup();
    if (logfp) fclose(logfp);
    return 0;
}
#endif /* HAS_NCURSES */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-d device [-d device2 ...]] [-i|-o] [-f filter] [-L 2|3|4]\n"
            "       %s [-r file] [-w file] [-u] [-j|-c] [-t secs] [-l logfile] [-a kbps] [-T N] [-h]\n"
            "\n"
            "  -d device   Network interface (repeatable, max %d)\n"
            "  -i          Capture incoming packets only\n"
            "  -o          Capture outgoing packets only\n"
            "  -f filter   BPF filter expression (tcpdump syntax)\n"
            "  -L 2|3|4    Layer detail mode (2=ARP, 3=IP/ICMP, 4=TCP/UDP)\n"
            "  -r file     Read packets from pcap file (offline mode)\n"
            "  -w file     Write captured packets to pcap file\n"
#ifdef HAS_NCURSES
            "  -u          TUI mode (ncurses)\n"
#else
            "  -u          TUI mode (not available, build with ncurses)\n"
#endif
            "  -p          Disable promiscuous mode\n"
            "  -n secs     Output interval in seconds (default 1.0, e.g. 0.5)\n"
            "  -j          JSON output (one line per interval)\n"
            "  -c          CSV output\n"
            "  -t secs     Stop after N seconds\n"
            "  -l logfile  Write stats to log file\n"
            "  -a kbps     Alert when bandwidth exceeds threshold\n"
            "  -T N        Show top N hosts/ports at exit\n"
            "  -h          Show this help\n",
            prog, prog, MAX_IFACES);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    monitor_config_t cfg;
    int opt, i;
    const char *dir_str;
    int timeout_ms;

    memset(&cfg, 0, sizeof(cfg));
    cfg.interval_ms = 1000;

    while ((opt = getopt(argc, argv, "d:iof:r:w:jt:l:L:ca:T:upn:h")) != -1) {
        switch (opt) {
        case 'd':
            if (iface_count >= MAX_IFACES) {
                fprintf(stderr, "Error: max %d interfaces\n", MAX_IFACES);
                return 1;
            }
            snprintf(ifaces[iface_count].name,
                     sizeof(ifaces[iface_count].name), "%s", optarg);
            iface_count++;
            break;
        case 'i':
            cfg.direction = 1;
            break;
        case 'o':
            cfg.direction = 2;
            break;
        case 'f':
            cfg.filter_expr = optarg;
            break;
        case 'j':
            cfg.json_mode = 1;
            break;
        case 't':
            cfg.duration = atoi(optarg);
            if (cfg.duration < 1) {
                fprintf(stderr, "Error: -t requires a positive integer\n");
                return 1;
            }
            break;
        case 'l':
            cfg.log_file = optarg;
            break;
        case 'c':
            cfg.csv_mode = 1;
            break;
        case 'a':
            cfg.alert_kbps = atof(optarg);
            if (cfg.alert_kbps <= 0) {
                fprintf(stderr, "Error: -a requires a positive number\n");
                return 1;
            }
            break;
        case 'T':
            cfg.top_n = atoi(optarg);
            if (cfg.top_n < 1) cfg.top_n = 1;
            break;
        case 'r':
            cfg.read_file = optarg;
            break;
        case 'w':
            cfg.write_file = optarg;
            break;
        case 'L':
            cfg.layer_mode = atoi(optarg);
            if (cfg.layer_mode != 2 && cfg.layer_mode != 3 &&
                cfg.layer_mode != 4) {
                fprintf(stderr, "Error: -L requires 2, 3, or 4\n");
                return 1;
            }
            break;
        case 'u':
            cfg.use_tui = 1;
            break;
        case 'p':
            cfg.no_promisc = 1;
            break;
        case 'n': {
            double secs = atof(optarg);
            if (secs <= 0) {
                fprintf(stderr, "Error: -n requires a positive number\n");
                return 1;
            }
            cfg.interval_ms = (int)(secs * 1000);
            if (cfg.interval_ms < 1) cfg.interval_ms = 1;
            break;
        }
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Validate mutually exclusive options */
    if (cfg.layer_mode && (cfg.json_mode || cfg.csv_mode)) {
        fprintf(stderr, "Error: -L cannot be combined with -j or -c\n");
        return 1;
    }
    if (cfg.use_tui && (cfg.json_mode || cfg.csv_mode)) {
        fprintf(stderr, "Error: -u cannot be combined with -j or -c\n");
        return 1;
    }
    if (cfg.json_mode && cfg.csv_mode) {
        fprintf(stderr, "Error: -j and -c are mutually exclusive\n");
        return 1;
    }
    if (cfg.read_file && iface_count > 0) {
        fprintf(stderr, "Error: -r and -d are mutually exclusive\n");
        return 1;
    }
    if (cfg.read_file && cfg.use_tui) {
        fprintf(stderr, "Error: -r cannot be combined with -u\n");
        return 1;
    }

    if (cfg.read_file) {
        /* -r mode: open pcap file for offline reading */
        ifaces[0].handle = pcap_open_offline(cfg.read_file, errbuf);
        if (!ifaces[0].handle) {
            fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
            return 1;
        }
        snprintf(ifaces[0].name, sizeof(ifaces[0].name), "file");
        iface_count = 1;
        {
            char layer_fbuf[512];
            const char *effective_filter = cfg.filter_expr;

            if (cfg.layer_mode) {
                const char *lf = layer_build_filter(
                    cfg.layer_mode, cfg.filter_expr,
                    layer_fbuf, sizeof(layer_fbuf));
                if (lf)
                    effective_filter = lf;
            }

            if (effective_filter) {
                if (apply_filter(ifaces[0].handle, "file",
                                 effective_filter) == -1) {
                    cleanup_all();
                    return 1;
                }
            }
        }
    } else {
        /* Legacy positional argument support: pkt_monitor <device> */
        if (iface_count == 0 && optind < argc) {
            snprintf(ifaces[0].name, sizeof(ifaces[0].name), "%s", argv[optind]);
            iface_count = 1;
        }

        /* Auto-detect device if not specified */
        if (iface_count == 0) {
            pcap_if_t *alldevs;

            if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
                fprintf(stderr, "No capture device found: %s\n", errbuf);
                return 1;
            }
            snprintf(ifaces[0].name, sizeof(ifaces[0].name), "%s", alldevs->name);
            iface_count = 1;
            pcap_freealldevs(alldevs);
            if (!cfg.use_tui)
                printf("# auto-detected device: %s\n", ifaces[0].name);
        }

        /* TUI requires ncurses */
#ifndef HAS_NCURSES
        if (cfg.use_tui) {
            fprintf(stderr, "TUI mode not available. Rebuild with ncurses support.\n");
            return 1;
        }
#endif

        /*
         * Open all capture devices.
         * Adjust timeout per interface for fair round-robin.
         */
        timeout_ms = 100 / iface_count;
        if (timeout_ms < 10) timeout_ms = 10;

        for (i = 0; i < iface_count; i++) {
            memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));
            memset(&ifaces[i].total_cnt, 0, sizeof(packet_counter_t));
            ifaces[i].elapsed_sec = 0;

            ifaces[i].handle = pcap_open_live(ifaces[i].name, SNAP_LEN,
                                              cfg.no_promisc ? 0 : 1,
                                              timeout_ms, errbuf);
            if (!ifaces[i].handle) {
                fprintf(stderr, "pcap_open_live(%s): %s\n",
                        ifaces[i].name, errbuf);
                cleanup_all();
                return 1;
            }

            /* Verify Ethernet link layer */
            if (pcap_datalink(ifaces[i].handle) != DLT_EN10MB) {
                fprintf(stderr, "Device %s does not provide Ethernet headers\n",
                        ifaces[i].name);
                cleanup_all();
                return 1;
            }

            /* Set capture direction if requested */
            if (cfg.direction == 1) {
                if (pcap_setdirection(ifaces[i].handle, PCAP_D_IN) == -1)
                    fprintf(stderr, "Warning: %s: cannot set direction to inbound: %s\n",
                            ifaces[i].name, pcap_geterr(ifaces[i].handle));
            } else if (cfg.direction == 2) {
                if (pcap_setdirection(ifaces[i].handle, PCAP_D_OUT) == -1)
                    fprintf(stderr, "Warning: %s: cannot set direction to outbound: %s\n",
                            ifaces[i].name, pcap_geterr(ifaces[i].handle));
            }

            /* Apply BPF filter (layer mode auto-filter + user filter) */
            {
                char layer_fbuf[512];
                const char *effective_filter = cfg.filter_expr;

                if (cfg.layer_mode) {
                    const char *lf = layer_build_filter(
                        cfg.layer_mode, cfg.filter_expr,
                        layer_fbuf, sizeof(layer_fbuf));
                    if (lf)
                        effective_filter = lf;
                }

                if (effective_filter) {
                    if (apply_filter(ifaces[i].handle, ifaces[i].name,
                                     effective_filter) == -1) {
                        cleanup_all();
                        return 1;
                    }
                }
            }
        }
    }

    /* Open pcap dumper for -w */
    if (cfg.write_file) {
        g_dumper = pcap_dump_open(ifaces[0].handle, cfg.write_file);
        if (!g_dumper) {
            fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(ifaces[0].handle));
            cleanup_all();
            return 1;
        }
    }

    dir_str = cfg.direction == 0 ? "both" : cfg.direction == 1 ? "in" : "out";

    /* Initialize Top-N tracking if requested */
    if (cfg.top_n > 0) {
        static flow_stats_t fs;
        if (flow_stats_init(&fs) < 0) {
            fprintf(stderr, "Warning: failed to allocate flow stats\n");
        } else {
            g_flow_stats = &fs;
        }
    }

    /* -r mode: process all packets from file and return */
    if (cfg.read_file) {
        pcap_loop(ifaces[0].handle, -1, packet_handler,
                  (u_char *)&ifaces[0].pkt_cnt);
        accumulate_totals(&ifaces[0]);
        cleanup_all();
        print_summary();
        if (g_flow_stats)
            flow_stats_print(g_flow_stats, cfg.top_n);
        if (g_flow_stats)
            flow_stats_cleanup(g_flow_stats);
        if (g_dumper) {
            pcap_dump_close(g_dumper);
            g_dumper = NULL;
        }
        return 0;
    }

#ifdef HAS_NCURSES
    if (cfg.use_tui) {
        int ret = run_tui(&cfg);
        if (g_dumper) {
            pcap_dump_close(g_dumper);
            g_dumper = NULL;
        }
        cleanup_all();
        if (ret == 0)
            print_summary();
        if (ret == 0 && g_flow_stats)
            flow_stats_print(g_flow_stats, cfg.top_n);
        if (g_flow_stats)
            flow_stats_cleanup(g_flow_stats);
        return ret;
    }
#endif

    /* Text mode */
    if (iface_count == 1) {
        printf("# Capturing on %s (direction: %s)", ifaces[0].name, dir_str);
    } else {
        printf("# Capturing on");
        for (i = 0; i < iface_count; i++)
            printf(" %s%s", ifaces[i].name,
                   i < iface_count - 1 ? "," : "");
        printf(" (direction: %s)", dir_str);
    }
    if (cfg.layer_mode)
        printf(" [L%d detail]", cfg.layer_mode);
    if (cfg.filter_expr)
        printf(" [filter: %s]", cfg.filter_expr);
    if (cfg.no_promisc)
        printf(" [no-promisc]");
    else
        printf(" [promisc]");
    printf("\n");

    {
        int ret = run_text(&cfg);
        if (g_dumper) {
            pcap_dump_close(g_dumper);
            g_dumper = NULL;
        }
        cleanup_all();
        if (ret == 0 && !cfg.json_mode && !cfg.csv_mode)
            print_summary();
        if (ret == 0 && g_flow_stats)
            flow_stats_print(g_flow_stats, cfg.top_n);
        if (g_flow_stats)
            flow_stats_cleanup(g_flow_stats);
        return ret;
    }
}
