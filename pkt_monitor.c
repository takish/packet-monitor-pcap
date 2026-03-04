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
#include <getopt.h>

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

#include <net/if_arp.h>
#include <arpa/inet.h>

#include "pkt_monitor.h"
#include "output.h"
#include "stats.h"
#include "layer_detail.h"
#include "dns_parse.h"
#include "prometheus.h"

#ifdef HAS_NCURSES
#include "tui.h"
#endif

/* ---- global state ----------------------------------------------------- */

static iface_ctx_t ifaces[MAX_IFACES];
static int iface_count;
static volatile sig_atomic_t running = 1;
static flow_stats_t *g_flow_stats;  /* non-NULL when -T is active */
static pcap_dumper_t *g_dumper;     /* non-NULL when -w is active */
static detail_ctx_t g_detail;       /* layer detail / resolve mode context */
static const monitor_config_t *g_cfg; /* pointer for packet_handler access */

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

/* Forward declaration for detail mode handler */
static void detail_packet_handler(const struct pcap_pkthdr *header,
                                  const u_char *packet);

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

    /* Dispatch to detail handler if layer/resolve mode is active */
    if (g_cfg && (g_cfg->layer_mode || g_cfg->resolve_mode))
        detail_packet_handler(header, packet);

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

/* ---- layer detail / resolve mode packet processing -------------------- */

static const char *icmp_type_name(uint8_t type)
{
    switch (type) {
    case 0:  return "Echo Reply";
    case 3:  return "Dest Unreachable";
    case 4:  return "Source Quench";
    case 5:  return "Redirect";
    case 8:  return "Echo Request";
    case 9:  return "Router Advert";
    case 10: return "Router Solicit";
    case 11: return "Time Exceeded";
    case 13: return "Timestamp";
    case 14: return "Timestamp Reply";
    default: return "Unknown";
    }
}

static void tcp_flags_str(uint8_t flags, char *buf, size_t len)
{
    size_t pos = 0;

    buf[0] = '\0';
    if (pos < len - 1) buf[pos++] = '[';

#define APPEND_FLAG(mask, name) do { \
    if ((flags & (mask)) && pos < len - 4) { \
        if (pos > 1) buf[pos++] = ','; \
        const char *s = (name); \
        while (*s && pos < len - 2) buf[pos++] = *s++; \
    } \
} while (0)

    APPEND_FLAG(0x02, "SYN");
    APPEND_FLAG(0x10, "ACK");
    APPEND_FLAG(0x01, "FIN");
    APPEND_FLAG(0x04, "RST");
    APPEND_FLAG(0x08, "PSH");
    APPEND_FLAG(0x20, "URG");
#undef APPEND_FLAG

    if (pos < len - 1) buf[pos++] = ']';
    buf[pos] = '\0';
}

static const char *ip_proto_name(uint8_t proto)
{
    switch (proto) {
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    case 2:            return "IGMP";
    case 47:           return "GRE";
    case 50:           return "ESP";
    case 51:           return "AH";
    case 89:           return "OSPF";
    default:           return "Other";
    }
}

static const char *ipv6_nxt_name(uint8_t nxt)
{
    switch (nxt) {
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    case 0:            return "HopByHop";
    case 43:           return "Routing";
    case 44:           return "Fragment";
    case 58:           return "ICMPv6";
    case 59:           return "NoNext";
    case 60:           return "DestOpts";
    default:           return "Other";
    }
}

/*
 * Layer-detail aware packet handler.
 * Called from packet_handler when layer_mode or resolve_mode is active.
 */
static void detail_packet_handler(const struct pcap_pkthdr *header,
                                  const u_char *packet)
{
    const struct ether_header *eth;
    uint16_t ether_type;
    char line[DETAIL_LINE_LEN];
    char timebuf[16];

    if (header->caplen < sizeof(struct ether_header))
        return;

    eth = (const struct ether_header *)packet;
    ether_type = ntohs(eth->ether_type);

    get_time_str(timebuf, sizeof(timebuf));

    /* -R arp mode */
    if (g_cfg->resolve_mode == 'a') {
        if (ether_type != ETHERTYPE_ARP) return;
        if (header->caplen < 42) return;  /* Ethernet 14 + ARP 28 */

        const uint8_t *arp_raw = packet + sizeof(struct ether_header);
        uint16_t op = ntohs(*(const uint16_t *)(arp_raw + 6));
        /* sender: arp_raw+8 (6B MAC) + arp_raw+14 (4B IP) */
        /* target: arp_raw+18 (6B MAC) + arp_raw+24 (4B IP) */
        uint32_t sender_ip, target_ip;
        memcpy(&sender_ip, arp_raw + 14, 4);
        memcpy(&target_ip, arp_raw + 24, 4);

        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_ip, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &target_ip, dst_str, sizeof(dst_str));

        int is_gratuitous = (sender_ip == target_ip);

        if (op == 1) { /* ARP Request */
            arp_resolver_request(&g_detail.arp_res, target_ip, &header->ts);
            if (is_gratuitous) {
                g_detail.arp_res.counter.gratuitous++;
                snprintf(line, sizeof(line),
                         "%s  GRAT  %s (gratuitous ARP)", timebuf, src_str);
            } else {
                snprintf(line, sizeof(line),
                         "%s  REQ   who-has %s? tell %s",
                         timebuf, dst_str, src_str);
            }
        } else if (op == 2) { /* ARP Reply */
            double ms = arp_resolver_reply(&g_detail.arp_res, sender_ip,
                                           &header->ts);
            if (ms >= 0) {
                snprintf(line, sizeof(line),
                         "%s  REPLY %s is-at %02x:%02x:%02x:%02x:%02x:%02x (%.1fms)",
                         timebuf, src_str,
                         packet[22], packet[23], packet[24],
                         packet[25], packet[26], packet[27], ms);
            } else {
                snprintf(line, sizeof(line),
                         "%s  REPLY %s is-at %02x:%02x:%02x:%02x:%02x:%02x",
                         timebuf, src_str,
                         packet[22], packet[23], packet[24],
                         packet[25], packet[26], packet[27]);
            }
        } else {
            snprintf(line, sizeof(line),
                     "%s  ARP op=%u %s -> %s", timebuf, op, src_str, dst_str);
        }

        detail_ring_push(&g_detail.ring, line);
        return;
    }

    /* -R dns mode */
    if (g_cfg->resolve_mode == 'd') {
        /* Must be IP + UDP + port 53 */
        if (ether_type != ETHERTYPE_IP) return;
        if (header->caplen < sizeof(struct ether_header) + 20) return;

        const struct ip *iph = (const struct ip *)
            (packet + sizeof(struct ether_header));
        if (iph->ip_p != IPPROTO_UDP) return;

        unsigned int ip_hlen = (unsigned int)iph->ip_hl * 4;
        size_t udp_off = sizeof(struct ether_header) + ip_hlen;
        if (header->caplen < udp_off + 8) return;

        const struct udphdr *uh = (const struct udphdr *)(packet + udp_off);
        uint16_t sport = ntohs(uh->uh_sport);
        uint16_t dport = ntohs(uh->uh_dport);
        if (sport != 53 && dport != 53) return;

        size_t dns_off = udp_off + 8;
        size_t dns_len = header->caplen - dns_off;
        if (dns_len < 12) return;

        dns_parsed_t dns;
        if (dns_parse(packet + dns_off, dns_len, &dns) < 0) return;

        if (!dns.is_response) {
            /* Query */
            const char *tname = dns_type_name(dns.qtype);
            dns_resolver_query(&g_detail.dns_res, dns.hdr.id,
                               dns.qname, &header->ts);
            if (tname)
                snprintf(line, sizeof(line), "%s  Q  %s %s",
                         timebuf, tname, dns.qname);
            else
                snprintf(line, sizeof(line), "%s  Q  type%u %s",
                         timebuf, dns.qtype, dns.qname);
        } else {
            /* Response */
            double ms = dns_resolver_response(&g_detail.dns_res, dns.hdr.id,
                                              &header->ts);
            const char *rc = dns_rcode_name(dns.rcode);

            if (dns.rcode == 3)
                g_detail.dns_res.counter.nxdomain++;
            else if (dns.rcode != 0)
                g_detail.dns_res.counter.errors++;

            if (dns.answer_count > 0) {
                const char *tname = dns_type_name(dns.answers[0].type);
                if (ms >= 0)
                    snprintf(line, sizeof(line),
                             "%s  R  %s %s -> %s %s (%.1fms)",
                             timebuf, rc, dns.qname,
                             tname ? tname : "?",
                             dns.answers[0].rdata_str, ms);
                else
                    snprintf(line, sizeof(line),
                             "%s  R  %s %s -> %s %s",
                             timebuf, rc, dns.qname,
                             tname ? tname : "?",
                             dns.answers[0].rdata_str);
            } else {
                if (ms >= 0)
                    snprintf(line, sizeof(line),
                             "%s  R  %s %s (no answers, %.1fms)",
                             timebuf, rc, dns.qname, ms);
                else
                    snprintf(line, sizeof(line),
                             "%s  R  %s %s (no answers)",
                             timebuf, rc, dns.qname);
            }
        }

        detail_ring_push(&g_detail.ring, line);
        return;
    }

    /* -L 2 ARP detail */
    if (g_cfg->layer_mode == 2) {
        if (ether_type != ETHERTYPE_ARP) return;
        if (header->caplen < 42) return;

        const uint8_t *arp_raw = packet + sizeof(struct ether_header);
        uint16_t op = ntohs(*(const uint16_t *)(arp_raw + 6));
        uint32_t sender_ip, target_ip;
        memcpy(&sender_ip, arp_raw + 14, 4);
        memcpy(&target_ip, arp_raw + 24, 4);

        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_ip, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &target_ip, dst_str, sizeof(dst_str));

        if (op == 1) {
            g_detail.l2.request++;
            snprintf(line, sizeof(line),
                     "%s  REQ   who-has %s? tell %s",
                     timebuf, dst_str, src_str);
        } else if (op == 2) {
            g_detail.l2.reply++;
            snprintf(line, sizeof(line),
                     "%s  REPLY %s is-at %02x:%02x:%02x:%02x:%02x:%02x",
                     timebuf, src_str,
                     packet[22], packet[23], packet[24],
                     packet[25], packet[26], packet[27]);
        } else {
            g_detail.l2.other++;
            snprintf(line, sizeof(line),
                     "%s  ARP op=%u %s -> %s", timebuf, op, src_str, dst_str);
        }

        detail_ring_push(&g_detail.ring, line);
        return;
    }

    /* -L 3 IP/IPv6/ICMP detail */
    if (g_cfg->layer_mode == 3) {
        if (ether_type == ETHERTYPE_IP) {
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
                return;
            const struct ip *iph = (const struct ip *)
                (packet + sizeof(struct ether_header));

            char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iph->ip_src, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &iph->ip_dst, dst_str, sizeof(dst_str));

            g_detail.l3.ipv4++;

            if (iph->ip_p == IPPROTO_ICMP) {
                g_detail.l3.icmp++;
                unsigned int ip_hlen = (unsigned int)iph->ip_hl * 4;
                if (header->caplen >= sizeof(struct ether_header) + ip_hlen + 4) {
                    const uint8_t *icmp = packet + sizeof(struct ether_header) + ip_hlen;
                    uint8_t icmp_type = icmp[0];
                    uint8_t icmp_code = icmp[1];
                    snprintf(line, sizeof(line),
                             "%s  ICMP  %s -> %s  %s (type=%u code=%u)",
                             timebuf, src_str, dst_str,
                             icmp_type_name(icmp_type), icmp_type, icmp_code);
                } else {
                    snprintf(line, sizeof(line),
                             "%s  ICMP  %s -> %s  (truncated)",
                             timebuf, src_str, dst_str);
                }
            } else {
                snprintf(line, sizeof(line),
                         "%s  IPv4  %s -> %s  proto=%s TTL=%u %uB",
                         timebuf, src_str, dst_str,
                         ip_proto_name(iph->ip_p),
                         iph->ip_ttl, ntohs(iph->ip_len));
            }
        } else if (ether_type == ETHERTYPE_IPV6) {
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr))
                return;
            const struct ip6_hdr *ip6 = (const struct ip6_hdr *)
                (packet + sizeof(struct ether_header));

            char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, src_str, sizeof(src_str));
            inet_ntop(AF_INET6, &ip6->ip6_dst, dst_str, sizeof(dst_str));

            g_detail.l3.ipv6++;

            snprintf(line, sizeof(line),
                     "%s  IPv6  %s -> %s  nxt=%s hop=%u %uB",
                     timebuf, src_str, dst_str,
                     ipv6_nxt_name(ip6->ip6_nxt),
                     ip6->ip6_hlim,
                     ntohs(ip6->ip6_plen));
        } else {
            return;
        }

        detail_ring_push(&g_detail.ring, line);
        return;
    }

    /* -L 4 TCP/UDP detail */
    if (g_cfg->layer_mode == 4) {
        const struct ip *iph;
        unsigned int ip_hlen;
        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        uint16_t sport, dport;

        if (ether_type == ETHERTYPE_IP) {
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
                return;
            iph = (const struct ip *)(packet + sizeof(struct ether_header));
            ip_hlen = (unsigned int)iph->ip_hl * 4;

            inet_ntop(AF_INET, &iph->ip_src, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &iph->ip_dst, dst_str, sizeof(dst_str));

            if (iph->ip_p == IPPROTO_TCP) {
                if (header->caplen < sizeof(struct ether_header) + ip_hlen + 20)
                    return;
                const struct tcphdr *th = (const struct tcphdr *)
                    (packet + sizeof(struct ether_header) + ip_hlen);

                sport = ntohs(th->th_sport);
                dport = ntohs(th->th_dport);
                uint8_t flags = th->th_flags;

                g_detail.l4.tcp_total++;
                if ((flags & 0x12) == 0x02) g_detail.l4.tcp_syn++;
                if ((flags & 0x12) == 0x12) g_detail.l4.tcp_synack++;
                if ((flags & 0x10) && !(flags & 0x02)) g_detail.l4.tcp_ack++;
                if (flags & 0x01) g_detail.l4.tcp_fin++;
                if (flags & 0x04) g_detail.l4.tcp_rst++;
                if (flags & 0x08) g_detail.l4.tcp_psh++;

                char flagbuf[64];
                tcp_flags_str(flags, flagbuf, sizeof(flagbuf));

                const char *s_svc = port_service_name(sport);
                const char *d_svc = port_service_name(dport);
                char src_port_str[32], dst_port_str[32];

                if (s_svc)
                    snprintf(src_port_str, sizeof(src_port_str),
                             "%s(%u)", s_svc, sport);
                else
                    snprintf(src_port_str, sizeof(src_port_str), "%u", sport);

                if (d_svc)
                    snprintf(dst_port_str, sizeof(dst_port_str),
                             "%s(%u)", d_svc, dport);
                else
                    snprintf(dst_port_str, sizeof(dst_port_str), "%u", dport);

                snprintf(line, sizeof(line),
                         "%s  TCP  %s:%s -> %s:%s %s %uB",
                         timebuf, src_str, src_port_str,
                         dst_str, dst_port_str,
                         flagbuf, ntohs(iph->ip_len));
            } else if (iph->ip_p == IPPROTO_UDP) {
                if (header->caplen < sizeof(struct ether_header) + ip_hlen + 8)
                    return;
                const struct udphdr *uh = (const struct udphdr *)
                    (packet + sizeof(struct ether_header) + ip_hlen);

                sport = ntohs(uh->uh_sport);
                dport = ntohs(uh->uh_dport);

                g_detail.l4.udp_total++;

                const char *s_svc = port_service_name(sport);
                const char *d_svc = port_service_name(dport);
                char src_port_str[32], dst_port_str[32];

                if (s_svc)
                    snprintf(src_port_str, sizeof(src_port_str),
                             "%s(%u)", s_svc, sport);
                else
                    snprintf(src_port_str, sizeof(src_port_str), "%u", sport);

                if (d_svc)
                    snprintf(dst_port_str, sizeof(dst_port_str),
                             "%s(%u)", d_svc, dport);
                else
                    snprintf(dst_port_str, sizeof(dst_port_str), "%u", dport);

                snprintf(line, sizeof(line),
                         "%s  UDP  %s:%s -> %s:%s %uB",
                         timebuf, src_str, src_port_str,
                         dst_str, dst_port_str,
                         ntohs(iph->ip_len));
            } else {
                return;
            }
        } else if (ether_type == ETHERTYPE_IPV6) {
            /* IPv6 TCP/UDP */
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr))
                return;
            const struct ip6_hdr *ip6 = (const struct ip6_hdr *)
                (packet + sizeof(struct ether_header));
            size_t l4_off = sizeof(struct ether_header) + sizeof(struct ip6_hdr);

            char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, src6, sizeof(src6));
            inet_ntop(AF_INET6, &ip6->ip6_dst, dst6, sizeof(dst6));

            if (ip6->ip6_nxt == IPPROTO_TCP) {
                if (header->caplen < l4_off + 20) return;
                const struct tcphdr *th = (const struct tcphdr *)(packet + l4_off);
                sport = ntohs(th->th_sport);
                dport = ntohs(th->th_dport);
                uint8_t flags = th->th_flags;

                g_detail.l4.tcp_total++;
                if ((flags & 0x12) == 0x02) g_detail.l4.tcp_syn++;
                if ((flags & 0x12) == 0x12) g_detail.l4.tcp_synack++;
                if ((flags & 0x10) && !(flags & 0x02)) g_detail.l4.tcp_ack++;
                if (flags & 0x01) g_detail.l4.tcp_fin++;
                if (flags & 0x04) g_detail.l4.tcp_rst++;
                if (flags & 0x08) g_detail.l4.tcp_psh++;

                char flagbuf[64];
                tcp_flags_str(flags, flagbuf, sizeof(flagbuf));

                snprintf(line, sizeof(line),
                         "%s  TCP6 %s:%u -> %s:%u %s %uB",
                         timebuf, src6, sport, dst6, dport,
                         flagbuf, ntohs(ip6->ip6_plen));
            } else if (ip6->ip6_nxt == IPPROTO_UDP) {
                if (header->caplen < l4_off + 8) return;
                const struct udphdr *uh = (const struct udphdr *)(packet + l4_off);
                sport = ntohs(uh->uh_sport);
                dport = ntohs(uh->uh_dport);

                g_detail.l4.udp_total++;

                snprintf(line, sizeof(line),
                         "%s  UDP6 %s:%u -> %s:%u %uB",
                         timebuf, src6, sport, dst6, dport,
                         ntohs(ip6->ip6_plen));
            } else {
                return;
            }
        } else {
            return;
        }

        detail_ring_push(&g_detail.ring, line);
        return;
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
    prometheus_stop();
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
 * Print layer detail / resolve mode text output.
 * Flushes the ring buffer and prints counter summary.
 */
static void print_detail_lines(const monitor_config_t *cfg, int *last_count)
{
    int i;
    int count = g_detail.ring.count;

    /* Print new entries since last flush */
    for (i = *last_count; i < count; i++) {
        const detail_entry_t *e = detail_ring_get(&g_detail.ring, i);
        if (e)
            printf("  %s\n", e->line);
    }
    *last_count = count;

    /* When ring wraps, reset tracking */
    if (count == DETAIL_RING_SIZE && *last_count == DETAIL_RING_SIZE)
        *last_count = 0;

    (void)cfg;
}

static void print_detail_summary(const monitor_config_t *cfg)
{
    if (cfg->layer_mode == 2) {
        printf("\n# L2 ARP Summary: Request=%" PRIu32 " Reply=%" PRIu32
               " Other=%" PRIu32 "\n",
               g_detail.l2.request, g_detail.l2.reply, g_detail.l2.other);
    } else if (cfg->layer_mode == 3) {
        printf("\n# L3 Summary: IPv4=%" PRIu32 " IPv6=%" PRIu32
               " ICMP=%" PRIu32 "\n",
               g_detail.l3.ipv4, g_detail.l3.ipv6, g_detail.l3.icmp);
    } else if (cfg->layer_mode == 4) {
        printf("\n# L4 Summary: TCP=%" PRIu32 " UDP=%" PRIu32 "\n",
               g_detail.l4.tcp_total, g_detail.l4.udp_total);
        printf("#   TCP flags: SYN=%" PRIu32 " SYN/ACK=%" PRIu32
               " ACK=%" PRIu32 " FIN=%" PRIu32
               " RST=%" PRIu32 " PSH=%" PRIu32 "\n",
               g_detail.l4.tcp_syn, g_detail.l4.tcp_synack,
               g_detail.l4.tcp_ack, g_detail.l4.tcp_fin,
               g_detail.l4.tcp_rst, g_detail.l4.tcp_psh);
    } else if (cfg->resolve_mode == 'a') {
        printf("\n# ARP Resolve Summary: Req=%" PRIu32 " Reply=%" PRIu32
               " Matched=%" PRIu32 " Timeout=%" PRIu32
               " Gratuitous=%" PRIu32 "\n",
               g_detail.arp_res.counter.requests,
               g_detail.arp_res.counter.replies,
               g_detail.arp_res.counter.matched,
               g_detail.arp_res.counter.timeouts,
               g_detail.arp_res.counter.gratuitous);
    } else if (cfg->resolve_mode == 'd') {
        printf("\n# DNS Resolve Summary: Query=%" PRIu32 " Response=%" PRIu32
               " Matched=%" PRIu32 " Timeout=%" PRIu32
               " NXDOMAIN=%" PRIu32 " Error=%" PRIu32 "\n",
               g_detail.dns_res.counter.queries,
               g_detail.dns_res.counter.responses,
               g_detail.dns_res.counter.matched,
               g_detail.dns_res.counter.timeouts,
               g_detail.dns_res.counter.nxdomain,
               g_detail.dns_res.counter.errors);
    }
}

/*
 * Layer detail / resolve mode text main loop.
 */
static int run_layer_detail(const monitor_config_t *cfg)
{
    long long last_tick;
    long long last_expire;
    int last_count = 0;
    int i;

    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    memset(&g_detail, 0, sizeof(g_detail));

    if (cfg->layer_mode)
        printf("# Layer %d detail mode\n", cfg->layer_mode);
    else if (cfg->resolve_mode == 'a')
        printf("# ARP resolve mode (-R arp)\n");
    else if (cfg->resolve_mode == 'd')
        printf("# DNS resolve mode (-R dns)\n");

    last_tick = now_ms();
    last_expire = last_tick;

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

        /* Flush display at interval */
        if (now_ms() - last_tick >= (long long)cfg->interval_ms) {
            last_tick += cfg->interval_ms;
            print_detail_lines(cfg, &last_count);

            for (i = 0; i < iface_count; i++) {
                accumulate_totals(&ifaces[i]);
                memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));
            }

            if (cfg->duration > 0 && ifaces[0].elapsed_sec >= cfg->duration)
                break;
        }

        /* Expire pending resolve entries every second */
        if (now_ms() - last_expire >= 1000) {
            last_expire = now_ms();
            struct timeval now_tv;
            gettimeofday(&now_tv, NULL);
            if (cfg->resolve_mode == 'a')
                arp_resolver_expire(&g_detail.arp_res, &now_tv);
            else if (cfg->resolve_mode == 'd')
                dns_resolver_expire(&g_detail.dns_res, &now_tv);
        }
    }

    printf("\n# Capture stopped.\n");
    print_detail_summary(cfg);

    return 0;
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
 * TUI mode for layer detail / resolve mode.
 */
static int run_tui_detail(const monitor_config_t *cfg)
{
    int paused = 0;
    long long last_tick, last_expire;
    int action, i;

    if (tui_init(cfg) < 0)
        return 1;

    signal(SIGALRM, SIG_IGN);
    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    memset(&g_detail, 0, sizeof(g_detail));

    tui_update_detail(&g_detail, 0, paused, cfg);

    last_tick = now_ms();
    last_expire = last_tick;

    for (;;) {
        if (!running)
            break;

        for (i = 0; i < iface_count; i++) {
            int ret = pcap_dispatch(ifaces[i].handle, -1, packet_handler,
                                    (u_char *)&ifaces[i].pkt_cnt);
            if (ret == PCAP_ERROR_BREAK) {
                tui_cleanup();
                return 0;
            }
        }

        if (now_ms() - last_tick >= (long long)cfg->interval_ms) {
            last_tick += cfg->interval_ms;
            if (!paused) {
                for (i = 0; i < iface_count; i++)
                    accumulate_totals(&ifaces[i]);

                tui_update_detail(&g_detail, ifaces[0].elapsed_sec,
                                  paused, cfg);

                for (i = 0; i < iface_count; i++)
                    memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));

                if (cfg->duration > 0 &&
                    ifaces[0].elapsed_sec >= cfg->duration)
                    break;
            }
        }

        /* Expire pending resolve entries */
        if (now_ms() - last_expire >= 1000) {
            last_expire = now_ms();
            struct timeval now_tv;
            gettimeofday(&now_tv, NULL);
            if (cfg->resolve_mode == 'a')
                arp_resolver_expire(&g_detail.arp_res, &now_tv);
            else if (cfg->resolve_mode == 'd')
                dns_resolver_expire(&g_detail.dns_res, &now_tv);
        }

        action = tui_handle_input();
        if (action == 'q')
            break;
        if (action == 'p')
            paused = !paused;
        if (action == 'r') {
            memset(&g_detail, 0, sizeof(g_detail));
            for (i = 0; i < iface_count; i++) {
                memset(&ifaces[i].pkt_cnt, 0, sizeof(packet_counter_t));
                memset(&ifaces[i].total_cnt, 0, sizeof(packet_counter_t));
                ifaces[i].elapsed_sec = 0;
            }
            tui_update_detail(&g_detail, 0, paused, cfg);
        }
    }

    tui_cleanup();
    return 0;
}

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
            "Usage: %s [-d device [-d device2 ...]] [-i|-o] [-f filter] [-L 2|3|4] [-R arp|dns]\n"
            "       %s [-r file] [-w file] [-u] [-j|-c] [-t secs] [-l logfile] [-a kbps] [-T N] [-h]\n"
            "\n"
            "  -d device   Network interface (repeatable, max %d)\n"
            "  -i          Capture incoming packets only\n"
            "  -o          Capture outgoing packets only\n"
            "  -f filter   BPF filter expression (tcpdump syntax)\n"
            "  -L 2|3|4    Layer detail mode (2=ARP, 3=IP/ICMP, 4=TCP/UDP)\n"
            "  -R arp|dns  Name resolution visualization mode\n"
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
            "  --prometheus :PORT  Expose Prometheus metrics on HTTP port\n"
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

    static struct option long_opts[] = {
        { "prometheus", required_argument, NULL, 0 },
        { NULL, 0, NULL, 0 }
    };
    int long_idx = 0;

    while ((opt = getopt_long(argc, argv, "d:iof:r:w:jt:l:L:R:ca:T:upn:h",
                              long_opts, &long_idx)) != -1) {
        switch (opt) {
        case 0:
            /* Long options */
            if (strcmp(long_opts[long_idx].name, "prometheus") == 0) {
                const char *arg = optarg;
                /* Accept ":PORT" or "PORT" */
                if (arg[0] == ':') arg++;
                cfg.prometheus_port = atoi(arg);
                if (cfg.prometheus_port < 1 || cfg.prometheus_port > 65535) {
                    fprintf(stderr,
                            "Error: --prometheus requires port 1-65535\n");
                    return 1;
                }
            }
            break;
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
        case 'R':
            if (strcmp(optarg, "arp") == 0)
                cfg.resolve_mode = 'a';
            else if (strcmp(optarg, "dns") == 0)
                cfg.resolve_mode = 'd';
            else {
                fprintf(stderr, "Error: -R requires 'arp' or 'dns'\n");
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
    if (cfg.layer_mode && cfg.resolve_mode) {
        fprintf(stderr, "Error: -L and -R are mutually exclusive\n");
        return 1;
    }
    if ((cfg.layer_mode || cfg.resolve_mode) && (cfg.json_mode || cfg.csv_mode)) {
        fprintf(stderr, "Error: -L/-R cannot be combined with -j or -c\n");
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

    /* Set g_cfg for detail_packet_handler access */
    g_cfg = &cfg;

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
            } else if (cfg.resolve_mode) {
                const char *rf = resolve_build_filter(
                    cfg.resolve_mode, cfg.filter_expr,
                    layer_fbuf, sizeof(layer_fbuf));
                if (rf)
                    effective_filter = rf;
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

            /* Apply BPF filter (layer/resolve mode auto-filter + user filter) */
            {
                char layer_fbuf[512];
                const char *effective_filter = cfg.filter_expr;

                if (cfg.layer_mode) {
                    const char *lf = layer_build_filter(
                        cfg.layer_mode, cfg.filter_expr,
                        layer_fbuf, sizeof(layer_fbuf));
                    if (lf)
                        effective_filter = lf;
                } else if (cfg.resolve_mode) {
                    const char *rf = resolve_build_filter(
                        cfg.resolve_mode, cfg.filter_expr,
                        layer_fbuf, sizeof(layer_fbuf));
                    if (rf)
                        effective_filter = rf;
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

    /* Start Prometheus exporter if requested */
    if (cfg.prometheus_port > 0) {
        if (prometheus_start(cfg.prometheus_port, ifaces, iface_count) < 0) {
            fprintf(stderr, "Warning: failed to start Prometheus exporter\n");
        } else {
            fprintf(stderr, "# Prometheus metrics: http://localhost:%d/metrics\n",
                    cfg.prometheus_port);
        }
    }

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
        int ret;
        if (cfg.layer_mode || cfg.resolve_mode)
            ret = run_tui_detail(&cfg);
        else
            ret = run_tui(&cfg);
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
    if (cfg.resolve_mode == 'a')
        printf(" [resolve: ARP]");
    else if (cfg.resolve_mode == 'd')
        printf(" [resolve: DNS]");
    if (cfg.filter_expr)
        printf(" [filter: %s]", cfg.filter_expr);
    if (cfg.no_promisc)
        printf(" [no-promisc]");
    else
        printf(" [promisc]");
    printf("\n");

    {
        int ret;
        if (cfg.layer_mode || cfg.resolve_mode)
            ret = run_layer_detail(&cfg);
        else
            ret = run_text(&cfg);
        if (g_dumper) {
            pcap_dump_close(g_dumper);
            g_dumper = NULL;
        }
        cleanup_all();
        if (ret == 0 && !cfg.json_mode && !cfg.csv_mode &&
            !cfg.layer_mode && !cfg.resolve_mode)
            print_summary();
        if (ret == 0 && g_flow_stats)
            flow_stats_print(g_flow_stats, cfg.top_n);
        if (g_flow_stats)
            flow_stats_cleanup(g_flow_stats);
        return ret;
    }
}
