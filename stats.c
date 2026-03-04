/*
 * stats.c - Host and port tracking for Top-N flow analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "stats.h"

/* ---- well-known port names -------------------------------------------- */

typedef struct { uint16_t port; const char *name; } port_name_t;

static const port_name_t well_known[] = {
    {   20, "FTP-DATA"   }, {   21, "FTP"        }, {   22, "SSH"        },
    {   23, "TELNET"     }, {   25, "SMTP"       }, {   53, "DNS"        },
    {   67, "DHCP-S"     }, {   68, "DHCP-C"     }, {   80, "HTTP"       },
    {  110, "POP3"       }, {  123, "NTP"        }, {  143, "IMAP"       },
    {  161, "SNMP"       }, {  443, "HTTPS"      }, {  445, "SMB"        },
    {  465, "SMTPS"      }, {  587, "SUBMISSION"  },
    {  993, "IMAPS"      }, {  995, "POP3S"      },
    { 1433, "MSSQL"      }, { 3306, "MySQL"      }, { 3389, "RDP"        },
    { 5432, "PostgreSQL" }, { 5900, "VNC"        },
    { 6379, "Redis"      }, { 8080, "HTTP-ALT"   }, { 8443, "HTTPS-ALT"  },
    { 8888, "HTTP-ALT2"  }, { 9090, "Prometheus" }, {27017, "MongoDB"    },
    { 0, NULL }
};

static const char *port_service_name(uint16_t port)
{
    const port_name_t *p;
    for (p = well_known; p->name; p++)
        if (p->port == port) return p->name;
    return NULL;
}

/* ---- lifecycle -------------------------------------------------------- */

int flow_stats_init(flow_stats_t *fs)
{
    memset(&fs->hosts, 0, sizeof(fs->hosts));

    fs->ports.tcp_dst = calloc(PORT_COUNT, sizeof(uint32_t));
    fs->ports.udp_dst = calloc(PORT_COUNT, sizeof(uint32_t));

    if (!fs->ports.tcp_dst || !fs->ports.udp_dst) {
        free(fs->ports.tcp_dst);
        free(fs->ports.udp_dst);
        fs->ports.tcp_dst = NULL;
        fs->ports.udp_dst = NULL;
        return -1;
    }

    return 0;
}

void flow_stats_cleanup(flow_stats_t *fs)
{
    free(fs->ports.tcp_dst);
    free(fs->ports.udp_dst);
    fs->ports.tcp_dst = NULL;
    fs->ports.udp_dst = NULL;
}

/* ---- host tracking (open-addressing hash table) ----------------------- */

static uint32_t host_hash(uint32_t addr)
{
    uint32_t h = addr;
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return h & (HOST_TABLE_SIZE - 1);
}

static host_entry_t *host_find_or_insert(host_table_t *ht, uint32_t addr)
{
    uint32_t idx, slot;
    int i;

    if (addr == 0) return NULL;

    idx = host_hash(addr);

    for (i = 0; i < HOST_TABLE_SIZE; i++) {
        slot = (idx + (uint32_t)i) & (HOST_TABLE_SIZE - 1);

        if (ht->slots[slot].addr == addr)
            return &ht->slots[slot];

        if (ht->slots[slot].addr == 0) {
            if (ht->count >= HOST_TABLE_MAX)
                return NULL;        /* table full */
            ht->slots[slot].addr = addr;
            ht->count++;
            return &ht->slots[slot];
        }
    }
    return NULL;
}

void flow_stats_record_host(flow_stats_t *fs, uint32_t src, uint32_t dst)
{
    host_entry_t *e;

    e = host_find_or_insert(&fs->hosts, src);
    if (e) e->pkts_src++;

    e = host_find_or_insert(&fs->hosts, dst);
    if (e) e->pkts_dst++;
}

/* ---- port tracking ---------------------------------------------------- */

void flow_stats_record_port(flow_stats_t *fs, uint16_t port, int is_tcp)
{
    if (!fs->ports.tcp_dst || !fs->ports.udp_dst)
        return;

    if (is_tcp)
        fs->ports.tcp_dst[port]++;
    else
        fs->ports.udp_dst[port]++;
}

/* ---- summary output --------------------------------------------------- */

typedef struct {
    uint32_t addr;
    uint32_t total;
    uint32_t pkts_src;
    uint32_t pkts_dst;
} host_sort_t;

static int cmp_host_desc(const void *a, const void *b)
{
    const host_sort_t *ha = a, *hb = b;
    if (hb->total > ha->total) return  1;
    if (hb->total < ha->total) return -1;
    return 0;
}

typedef struct {
    uint16_t port;
    uint32_t count;
    int      is_tcp;
} port_sort_t;

static int cmp_port_desc(const void *a, const void *b)
{
    const port_sort_t *pa = a, *pb = b;
    if (pb->count > pa->count) return  1;
    if (pb->count < pa->count) return -1;
    return 0;
}

void flow_stats_print(const flow_stats_t *fs, int top_n)
{
    int i;

    /* Top-N hosts */
    if (fs->hosts.count > 0) {
        host_sort_t *harr;
        int hcount = 0;
        int show;

        harr = malloc(sizeof(host_sort_t) * (size_t)fs->hosts.count);
        if (!harr) return;

        for (i = 0; i < HOST_TABLE_SIZE; i++) {
            if (fs->hosts.slots[i].addr != 0) {
                harr[hcount].addr     = fs->hosts.slots[i].addr;
                harr[hcount].pkts_src = fs->hosts.slots[i].pkts_src;
                harr[hcount].pkts_dst = fs->hosts.slots[i].pkts_dst;
                harr[hcount].total    = fs->hosts.slots[i].pkts_src +
                                        fs->hosts.slots[i].pkts_dst;
                hcount++;
            }
        }

        qsort(harr, (size_t)hcount, sizeof(host_sort_t), cmp_host_desc);

        show = hcount < top_n ? hcount : top_n;
        printf("\n# Top %d hosts:\n", show);
        for (i = 0; i < show; i++) {
            struct in_addr a;
            a.s_addr = harr[i].addr;
            printf("#   %d. %-15s  %" PRIu32 " pkts (src: %" PRIu32
                   ", dst: %" PRIu32 ")\n",
                   i + 1, inet_ntoa(a), harr[i].total,
                   harr[i].pkts_src, harr[i].pkts_dst);
        }
        free(harr);
    }

    /* Top-N ports */
    if (fs->ports.tcp_dst && fs->ports.udp_dst) {
        int pcount = 0;
        port_sort_t *parr;
        int pi = 0;
        int show;

        for (i = 0; i < PORT_COUNT; i++) {
            if (fs->ports.tcp_dst[i] > 0) pcount++;
            if (fs->ports.udp_dst[i] > 0) pcount++;
        }

        if (pcount > 0) {
            parr = malloc(sizeof(port_sort_t) * (size_t)pcount);
            if (!parr) return;

            for (i = 0; i < PORT_COUNT; i++) {
                if (fs->ports.tcp_dst[i] > 0) {
                    parr[pi].port   = (uint16_t)i;
                    parr[pi].count  = fs->ports.tcp_dst[i];
                    parr[pi].is_tcp = 1;
                    pi++;
                }
                if (fs->ports.udp_dst[i] > 0) {
                    parr[pi].port   = (uint16_t)i;
                    parr[pi].count  = fs->ports.udp_dst[i];
                    parr[pi].is_tcp = 0;
                    pi++;
                }
            }

            qsort(parr, (size_t)pi, sizeof(port_sort_t), cmp_port_desc);

            show = pi < top_n ? pi : top_n;
            printf("\n# Top %d ports:\n", show);
            for (i = 0; i < show; i++) {
                const char *svc = port_service_name(parr[i].port);
                printf("#   %5d/%s", parr[i].port,
                       parr[i].is_tcp ? "tcp" : "udp");
                if (svc)
                    printf(" (%-12s)", svc);
                else
                    printf("               ");
                printf("  %" PRIu32 " pkts\n", parr[i].count);
            }
            free(parr);
        }
    }
}
