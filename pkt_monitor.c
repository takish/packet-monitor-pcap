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
#include <time.h>
#include <unistd.h>
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

#ifdef HAS_NCURSES
#include "tui.h"
#endif

#define TIMEOUT_SEC  1
#define TIMEOUT_USEC 0

/* ---- global state ----------------------------------------------------- */

static iface_ctx_t ifaces[MAX_IFACES];
static int iface_count;
static char *filter_expr;
static volatile sig_atomic_t running = 1;

/*
 * Get current time as HH:MM:SS string.
 */
static void get_time(char *buf, size_t len)
{
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);
    strftime(buf, len, "%H:%M:%S", tm);
}

/*
 * Accumulate per-second counters into totals for one interface.
 */
static void accumulate_totals(iface_ctx_t *ctx)
{
    ctx->total_cnt.all  += ctx->pkt_cnt.all;
    ctx->total_cnt.ip   += ctx->pkt_cnt.ip;
    ctx->total_cnt.ipv6 += ctx->pkt_cnt.ipv6;
    ctx->total_cnt.arp  += ctx->pkt_cnt.arp;
    ctx->total_cnt.icmp += ctx->pkt_cnt.icmp;
    ctx->total_cnt.tcp  += ctx->pkt_cnt.tcp;
    ctx->total_cnt.udp  += ctx->pkt_cnt.udp;
    ctx->total_cnt.bps  += ctx->pkt_cnt.bps;
    ctx->elapsed_sec++;

    memset(&ctx->pkt_cnt, 0, sizeof(ctx->pkt_cnt));
}

/*
 * SIGALRM handler: print stats every second, header every INTVAL seconds.
 * Used only in text mode.
 */
static void alarm_handler(int sig)
{
    char timebuf[16];
    static int sec = 1;
    int i;

    (void)sig;

    get_time(timebuf, sizeof(timebuf));

    if ((sec % INTVAL) == 1) {
        if (iface_count > 1)
            printf("# time #\tiface\t  all\t ipv4\t ipv6\tarp\ticmp"
                   "\ttcp\tudp\n");
        else
            printf("# time #\t  all\t ipv4\t ipv6\tarp\ticmp\ttcp\tudp\n");
        sec = 1;
    }

    for (i = 0; i < iface_count; i++) {
        packet_counter_t *c = &ifaces[i].pkt_cnt;
        if (iface_count > 1)
            printf("%s\t%s\t%5d\t%5d\t%5d\t%3d\t%3d\t%5d\t%5d%6.1fkbps\n",
                   timebuf, ifaces[i].name,
                   c->all, c->ip, c->ipv6, c->arp, c->icmp,
                   c->tcp, c->udp, (double)c->bps * 8 / 1024);
        else
            printf("%s\t%5d\t%5d\t%5d\t%3d\t%3d\t%5d\t%5d%6.1fkbps\n",
                   timebuf,
                   c->all, c->ip, c->ipv6, c->arp, c->icmp,
                   c->tcp, c->udp, (double)c->bps * 8 / 1024);
    }

    sec++;

    for (i = 0; i < iface_count; i++)
        accumulate_totals(&ifaces[i]);
}

/*
 * Set up SIGALRM timer for periodic stats output (text mode only).
 */
static void setup_timer(void)
{
    struct itimerval timer;

    signal(SIGALRM, alarm_handler);

    timer.it_interval.tv_sec  = TIMEOUT_SEC;
    timer.it_interval.tv_usec = TIMEOUT_USEC;
    timer.it_value.tv_sec     = TIMEOUT_SEC;
    timer.it_value.tv_usec    = TIMEOUT_USEC;

    setitimer(ITIMER_REAL, &timer, NULL);
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

    cnt->all++;
    cnt->bps += header->len;

    eth = (const struct ether_header *)packet;
    ether_type = ntohs(eth->ether_type);

    switch (ether_type) {
    case ETHERTYPE_IP:
        cnt->ip++;
        break;
    case ETHERTYPE_IPV6:
        cnt->ipv6++;
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

    switch (iph->ip_p) {
    case IPPROTO_ICMP:
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
 * Get current time in milliseconds (monotonic).
 */
static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

#ifdef HAS_NCURSES
/*
 * TUI mode main loop using round-robin pcap_dispatch (non-blocking).
 */
static int run_tui(const char *dir_str)
{
    int paused = 0;
    long long last_tick;
    int action, i;

    if (tui_init(ifaces, iface_count, dir_str) < 0)
        return 1;

    /* Disable SIGALRM in TUI mode */
    signal(SIGALRM, SIG_IGN);

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    /* Initial draw */
    tui_update(ifaces, iface_count, paused);

    last_tick = now_ms();

    for (;;) {
        /* Round-robin dispatch across all interfaces */
        for (i = 0; i < iface_count; i++) {
            int ret = pcap_dispatch(ifaces[i].handle, -1, packet_handler,
                                    (u_char *)&ifaces[i].pkt_cnt);
            if (ret == PCAP_ERROR_BREAK) {
                tui_cleanup();
                return 0;
            }
        }

        /* Check for 1-second tick */
        if (now_ms() - last_tick >= 1000) {
            last_tick += 1000;
            if (!paused) {
                for (i = 0; i < iface_count; i++)
                    accumulate_totals(&ifaces[i]);
                tui_update(ifaces, iface_count, paused);
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
            tui_update(ifaces, iface_count, paused);
        }
    }

    tui_cleanup();
    return 0;
}
#endif /* HAS_NCURSES */

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int direction = 0; /* 0=both, 1=in, 2=out */
    int use_tui = 0;
    int opt, i;
    const char *dir_str;
    int timeout_ms;

    while ((opt = getopt(argc, argv, "d:f:iouh")) != -1) {
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
        case 'f':
            filter_expr = optarg;
            break;
        case 'i':
            direction = 1;
            break;
        case 'o':
            direction = 2;
            break;
        case 'u':
            use_tui = 1;
            break;
        case 'h':
        default:
            fprintf(stderr,
                    "Usage: %s [-d device [-d device2 ...]] [-f filter]"
                    " [-i|-o] [-u] [-h]\n"
                    "  -d device   Network interface (repeatable, max %d)\n"
                    "  -f filter   BPF filter expression (tcpdump syntax)\n"
                    "  -i          Capture incoming packets only\n"
                    "  -o          Capture outgoing packets only\n"
#ifdef HAS_NCURSES
                    "  -u          TUI mode (ncurses)\n"
#else
                    "  -u          TUI mode (not available, build with ncurses)\n"
#endif
                    "  -h          Show this help\n",
                    argv[0], MAX_IFACES);
            return (opt == 'h') ? 0 : 1;
        }
    }

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
        if (!use_tui)
            printf("# auto-detected device: %s\n", ifaces[0].name);
    }

    /* TUI requires ncurses */
#ifndef HAS_NCURSES
    if (use_tui) {
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

        ifaces[i].handle = pcap_open_live(ifaces[i].name, SNAP_LEN, 1,
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
        if (direction == 1) {
            if (pcap_setdirection(ifaces[i].handle, PCAP_D_IN) == -1)
                fprintf(stderr, "Warning: %s: cannot set direction to inbound: %s\n",
                        ifaces[i].name, pcap_geterr(ifaces[i].handle));
        } else if (direction == 2) {
            if (pcap_setdirection(ifaces[i].handle, PCAP_D_OUT) == -1)
                fprintf(stderr, "Warning: %s: cannot set direction to outbound: %s\n",
                        ifaces[i].name, pcap_geterr(ifaces[i].handle));
        }

        /* Apply BPF filter */
        if (filter_expr) {
            if (apply_filter(ifaces[i].handle, ifaces[i].name,
                             filter_expr) == -1) {
                cleanup_all();
                return 1;
            }
        }
    }

    dir_str = direction == 0 ? "both" : direction == 1 ? "in" : "out";

#ifdef HAS_NCURSES
    if (use_tui) {
        int ret = run_tui(dir_str);
        cleanup_all();
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
    if (filter_expr)
        printf(" [filter: %s]", filter_expr);
    printf("\n");

    setup_timer();

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    /* Round-robin dispatch */
    while (running) {
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
    }

    cleanup_all();
    printf("\n# Capture stopped.\n");

    return 0;
}
