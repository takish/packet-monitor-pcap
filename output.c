/*
 * output.c - Structured output formats (JSON, CSV, log)
 */

#include <inttypes.h>
#include "output.h"

void output_json_line(FILE *fp, const packet_counter_t *cur)
{
    char timebuf[16];

    get_time_str(timebuf, sizeof(timebuf));
    fprintf(fp,
        "{\"time\":\"%s\",\"all\":%" PRIu32 ",\"ipv4\":%" PRIu32
        ",\"ipv6\":%" PRIu32 ",\"arp\":%" PRIu32 ",\"icmp\":%" PRIu32
        ",\"tcp\":%" PRIu32 ",\"udp\":%" PRIu32 ",\"kbps\":%.1f}\n",
        timebuf, cur->all, cur->ip, cur->ipv6, cur->arp,
        cur->icmp, cur->tcp, cur->udp,
        (double)cur->bytes * 8.0 / 1024.0);
    fflush(fp);
}

void output_csv_header(FILE *fp)
{
    fprintf(fp, "time,all,ipv4,ipv6,arp,icmp,tcp,udp,kbps\n");
    fflush(fp);
}

void output_csv_line(FILE *fp, const packet_counter_t *cur)
{
    char timebuf[16];

    get_time_str(timebuf, sizeof(timebuf));
    fprintf(fp, "%s,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
            ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%.1f\n",
            timebuf, cur->all, cur->ip, cur->ipv6, cur->arp,
            cur->icmp, cur->tcp, cur->udp,
            (double)cur->bytes * 8.0 / 1024.0);
    fflush(fp);
}

void output_log_line(FILE *fp, const packet_counter_t *cur)
{
    char timebuf[16];

    get_time_str(timebuf, sizeof(timebuf));
    fprintf(fp, "%s\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32
            "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%.1fkbps\n",
            timebuf, cur->all, cur->ip, cur->ipv6, cur->arp,
            cur->icmp, cur->tcp, cur->udp,
            (double)cur->bytes * 8.0 / 1024.0);
    fflush(fp);
}
