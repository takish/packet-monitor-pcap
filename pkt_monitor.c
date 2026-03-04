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

static packet_counter_t pkt_cnt;
static packet_counter_t total_cnt;
static pcap_t *handle;

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
 * SIGALRM handler: print stats every second, header every INTVAL seconds.
 * Used only in text mode.
 */
static void alarm_handler(int sig)
{
    char timebuf[16];
    static int sec = 1;

    (void)sig;

    get_time(timebuf, sizeof(timebuf));

    if ((sec % INTVAL) == 1) {
        printf("# time #\t  all\t ipv4\t ipv6\tarp\ticmp\ttcp\tudp\n");
        sec = 1;
    }

    printf("%s\t%5d\t%5d\t%5d\t%3d\t%3d\t%5d\t%5d%6.1fkbps\n",
           timebuf, pkt_cnt.all, pkt_cnt.ip,
           pkt_cnt.ipv6, pkt_cnt.arp, pkt_cnt.icmp,
           pkt_cnt.tcp, pkt_cnt.udp, (double)pkt_cnt.bps * 8 / 1024);

    sec++;

    memset(&pkt_cnt, 0, sizeof(pkt_cnt));
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
 */
static void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    const struct ether_header *eth;
    const struct ip *iph;
    uint16_t ether_type;

    (void)user;

    if (header->caplen < sizeof(struct ether_header))
        return;

    pkt_cnt.all++;
    pkt_cnt.bps += header->len;

    eth = (const struct ether_header *)packet;
    ether_type = ntohs(eth->ether_type);

    switch (ether_type) {
    case ETHERTYPE_IP:
        pkt_cnt.ip++;
        break;
    case ETHERTYPE_IPV6:
        pkt_cnt.ipv6++;
        return;
    case ETHERTYPE_ARP:
        pkt_cnt.arp++;
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
        pkt_cnt.icmp++;
        break;
    case IPPROTO_TCP:
        pkt_cnt.tcp++;
        break;
    case IPPROTO_UDP:
        pkt_cnt.udp++;
        break;
    }
}

/*
 * Accumulate per-second counters into totals.
 */
static void accumulate_totals(void)
{
    total_cnt.all  += pkt_cnt.all;
    total_cnt.ip   += pkt_cnt.ip;
    total_cnt.ipv6 += pkt_cnt.ipv6;
    total_cnt.arp  += pkt_cnt.arp;
    total_cnt.icmp += pkt_cnt.icmp;
    total_cnt.tcp  += pkt_cnt.tcp;
    total_cnt.udp  += pkt_cnt.udp;
    total_cnt.bps  += pkt_cnt.bps;
}

/*
 * SIGINT/SIGTERM handler: clean shutdown.
 */
static void cleanup_handler(int sig)
{
    (void)sig;

    if (handle) {
        pcap_breakloop(handle);
    }
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
 * TUI mode main loop using pcap_dispatch (non-blocking).
 */
static int run_tui(const char *device, const char *dir_str)
{
    int elapsed = 0;
    int paused = 0;
    long long last_tick;
    int action;

    if (tui_init(device, dir_str) < 0)
        return 1;

    /* Disable SIGALRM in TUI mode */
    signal(SIGALRM, SIG_IGN);

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    memset(&pkt_cnt, 0, sizeof(pkt_cnt));
    memset(&total_cnt, 0, sizeof(total_cnt));

    /* Initial draw */
    tui_update(&pkt_cnt, &total_cnt, elapsed, paused);

    last_tick = now_ms();

    for (;;) {
        /* Process packets (non-blocking, pcap timeout handles ~100ms) */
        if (pcap_dispatch(handle, -1, packet_handler, NULL) == PCAP_ERROR_BREAK)
            break;

        /* Check for 1-second tick */
        if (now_ms() - last_tick >= 1000) {
            last_tick += 1000;
            if (!paused) {
                elapsed++;
                accumulate_totals();
                tui_update(&pkt_cnt, &total_cnt, elapsed, paused);
                memset(&pkt_cnt, 0, sizeof(pkt_cnt));
            }
        }

        /* Handle keyboard input */
        action = tui_handle_input();
        if (action == 'q')
            break;
        if (action == 'p')
            paused = !paused;
        if (action == 'r') {
            memset(&pkt_cnt, 0, sizeof(pkt_cnt));
            memset(&total_cnt, 0, sizeof(total_cnt));
            elapsed = 0;
            tui_update(&pkt_cnt, &total_cnt, elapsed, paused);
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
    int opt;
    const char *device = NULL;
    const char *dir_str;

    while ((opt = getopt(argc, argv, "d:iouh")) != -1) {
        switch (opt) {
        case 'd':
            device = optarg;
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
                    "Usage: %s [-d device] [-i|-o] [-u] [-h]\n"
                    "  -d device   Network interface (default: auto-detect)\n"
                    "  -i          Capture incoming packets only\n"
                    "  -o          Capture outgoing packets only\n"
#ifdef HAS_NCURSES
                    "  -u          TUI mode (ncurses)\n"
#else
                    "  -u          TUI mode (not available, build with ncurses)\n"
#endif
                    "  -h          Show this help\n",
                    argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Legacy positional argument support: pkt_monitor <device> */
    if (!device && optind < argc) {
        device = argv[optind];
    }

    /* Auto-detect device if not specified */
    if (!device) {
        pcap_if_t *alldevs;

        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "No capture device found: %s\n", errbuf);
            return 1;
        }
        device = alldevs->name;
        if (!use_tui)
            printf("# auto-detected device: %s\n", device);
    }

    /* TUI requires ncurses */
#ifndef HAS_NCURSES
    if (use_tui) {
        fprintf(stderr, "TUI mode not available. Rebuild with ncurses support.\n");
        return 1;
    }
#endif

    /*
     * Open capture device.
     * promiscuous mode = 1, timeout = 100ms
     */
    handle = pcap_open_live(device, SNAP_LEN, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", device, errbuf);
        return 1;
    }

    /* Verify Ethernet link layer */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers\n", device);
        pcap_close(handle);
        return 1;
    }

    /* Set capture direction if requested */
    if (direction == 1) {
        if (pcap_setdirection(handle, PCAP_D_IN) == -1) {
            fprintf(stderr, "Warning: cannot set direction to inbound: %s\n",
                    pcap_geterr(handle));
        }
    } else if (direction == 2) {
        if (pcap_setdirection(handle, PCAP_D_OUT) == -1) {
            fprintf(stderr, "Warning: cannot set direction to outbound: %s\n",
                    pcap_geterr(handle));
        }
    }

    dir_str = direction == 0 ? "both" : direction == 1 ? "in" : "out";

#ifdef HAS_NCURSES
    if (use_tui) {
        int ret = run_tui(device, dir_str);
        pcap_close(handle);
        return ret;
    }
#endif

    /* Text mode */
    printf("# Capturing on %s (direction: %s)\n", device, dir_str);

    setup_timer();

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    memset(&pkt_cnt, 0, sizeof(pkt_cnt));
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    printf("\n# Capture stopped.\n");

    return 0;
}
