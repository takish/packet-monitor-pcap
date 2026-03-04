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

#define TIMEOUT_SEC  1
#define INTVAL       10
#define SNAP_LEN     1600

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

static packet_counter_t pkt_cnt;
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
 * Set up SIGALRM timer for periodic stats output.
 */
static void setup_timer(void)
{
    struct itimerval timer;

    signal(SIGALRM, alarm_handler);

    timer.it_interval.tv_sec  = TIMEOUT_SEC;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec     = TIMEOUT_SEC;
    timer.it_value.tv_usec    = 0;

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
 * SIGINT/SIGTERM handler: clean shutdown.
 */
static void cleanup_handler(int sig)
{
    (void)sig;

    if (handle) {
        pcap_breakloop(handle);
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int direction = 0; /* 0=both, 1=in, 2=out */
    int opt;
    const char *device = NULL;

    while ((opt = getopt(argc, argv, "d:ioh")) != -1) {
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
        case 'h':
        default:
            fprintf(stderr,
                    "Usage: %s [-d device] [-i|-o] [-h]\n"
                    "  -d device   Network interface (default: auto-detect)\n"
                    "  -i          Capture incoming packets only\n"
                    "  -o          Capture outgoing packets only\n"
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
        printf("# auto-detected device: %s\n", device);
        /* Note: alldevs memory is intentionally kept alive for device pointer */
    }

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

    printf("# Capturing on %s (direction: %s)\n", device,
           direction == 0 ? "both" : direction == 1 ? "in" : "out");

    /* Set up periodic timer and signal handlers */
    setup_timer();

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    /* Main capture loop */
    memset(&pkt_cnt, 0, sizeof(pkt_cnt));
    pcap_loop(handle, -1, packet_handler, NULL);

    /* Cleanup */
    pcap_close(handle);
    printf("\n# Capture stopped.\n");

    return 0;
}
