/*
 * prometheus.c - Prometheus metrics exporter
 *
 * Minimal HTTP server on a background thread.
 * Serves /metrics in Prometheus text exposition format.
 * No external library dependencies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "prometheus.h"

static int server_fd = -1;
static pthread_t server_thread;
static volatile int server_running;

/* Shared state (read-only from server thread) */
static iface_ctx_t *prom_ifaces;
static int prom_iface_count;

/*
 * Build the metrics body.
 * Uses cumulative total_cnt (never reset) per Prometheus counter convention.
 */
static int build_metrics(char *buf, size_t buflen)
{
    int i;
    size_t off = 0;
    uint64_t total_bytes = 0;
    uint32_t total_all = 0, total_ip = 0, total_ipv6 = 0;
    uint32_t total_arp = 0, total_icmp = 0, total_tcp = 0, total_udp = 0;

    /* Aggregate across interfaces */
    for (i = 0; i < prom_iface_count; i++) {
        const packet_counter_t *t = &prom_ifaces[i].total_cnt;
        total_all   += t->all;
        total_ip    += t->ip;
        total_ipv6  += t->ipv6;
        total_arp   += t->arp;
        total_icmp  += t->icmp;
        total_tcp   += t->tcp;
        total_udp   += t->udp;
        total_bytes += t->bytes;
    }

    off += (size_t)snprintf(buf + off, buflen - off,
        "# HELP pkt_monitor_packets_total Total packets captured\n"
        "# TYPE pkt_monitor_packets_total counter\n"
        "pkt_monitor_packets_total{protocol=\"all\"} %" PRIu32 "\n"
        "pkt_monitor_packets_total{protocol=\"ipv4\"} %" PRIu32 "\n"
        "pkt_monitor_packets_total{protocol=\"ipv6\"} %" PRIu32 "\n"
        "pkt_monitor_packets_total{protocol=\"arp\"} %" PRIu32 "\n"
        "pkt_monitor_packets_total{protocol=\"icmp\"} %" PRIu32 "\n"
        "pkt_monitor_packets_total{protocol=\"tcp\"} %" PRIu32 "\n"
        "pkt_monitor_packets_total{protocol=\"udp\"} %" PRIu32 "\n",
        total_all, total_ip, total_ipv6, total_arp,
        total_icmp, total_tcp, total_udp);

    off += (size_t)snprintf(buf + off, buflen - off,
        "# HELP pkt_monitor_bytes_total Total bytes captured\n"
        "# TYPE pkt_monitor_bytes_total counter\n"
        "pkt_monitor_bytes_total %" PRIu64 "\n",
        total_bytes);

    /* Per-interface metrics */
    if (prom_iface_count > 1) {
        off += (size_t)snprintf(buf + off, buflen - off,
            "# HELP pkt_monitor_iface_packets_total "
            "Total packets per interface\n"
            "# TYPE pkt_monitor_iface_packets_total counter\n");

        for (i = 0; i < prom_iface_count; i++) {
            const packet_counter_t *t = &prom_ifaces[i].total_cnt;
            off += (size_t)snprintf(buf + off, buflen - off,
                "pkt_monitor_iface_packets_total"
                "{iface=\"%s\",protocol=\"all\"} %" PRIu32 "\n"
                "pkt_monitor_iface_packets_total"
                "{iface=\"%s\",protocol=\"tcp\"} %" PRIu32 "\n"
                "pkt_monitor_iface_packets_total"
                "{iface=\"%s\",protocol=\"udp\"} %" PRIu32 "\n",
                prom_ifaces[i].name, t->all,
                prom_ifaces[i].name, t->tcp,
                prom_ifaces[i].name, t->udp);
        }

        off += (size_t)snprintf(buf + off, buflen - off,
            "# HELP pkt_monitor_iface_bytes_total "
            "Total bytes per interface\n"
            "# TYPE pkt_monitor_iface_bytes_total counter\n");

        for (i = 0; i < prom_iface_count; i++) {
            off += (size_t)snprintf(buf + off, buflen - off,
                "pkt_monitor_iface_bytes_total"
                "{iface=\"%s\"} %" PRIu64 "\n",
                prom_ifaces[i].name,
                prom_ifaces[i].total_cnt.bytes);
        }
    }

    /* Uptime */
    off += (size_t)snprintf(buf + off, buflen - off,
        "# HELP pkt_monitor_uptime_seconds Capture duration\n"
        "# TYPE pkt_monitor_uptime_seconds gauge\n"
        "pkt_monitor_uptime_seconds %d\n",
        prom_ifaces[0].elapsed_sec);

    return (int)off;
}

/*
 * Handle a single HTTP connection.
 */
static void handle_client(int client_fd)
{
    char req[1024];
    char body[8192];
    char response[8192 + 256];
    ssize_t n;
    int body_len;

    n = read(client_fd, req, sizeof(req) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    req[n] = '\0';

    /* Only serve GET /metrics */
    if (strncmp(req, "GET /metrics", 12) == 0) {
        body_len = build_metrics(body, sizeof(body));
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                 "Content-Length: %d\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 body_len, body);
    } else if (strncmp(req, "GET / ", 6) == 0 ||
               strncmp(req, "GET /\r", 6) == 0) {
        const char *html =
            "<html><body><h1>pkt_monitor</h1>"
            "<p><a href=\"/metrics\">/metrics</a></p>"
            "</body></html>";
        int html_len = (int)strlen(html);
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/html\r\n"
                 "Content-Length: %d\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 html_len, html);
    } else {
        const char *not_found = "404 Not Found\n";
        int nf_len = (int)strlen(not_found);
        snprintf(response, sizeof(response),
                 "HTTP/1.1 404 Not Found\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %d\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 nf_len, not_found);
    }

    /* Write full response (ignore partial write for simplicity) */
    (void)write(client_fd, response, strlen(response));
    close(client_fd);
}

/*
 * Server thread main loop.
 */
static void *server_loop(void *arg)
{
    (void)arg;

    while (server_running) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd;

        client_fd = accept(server_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) {
            if (!server_running) break;
            continue;
        }

        /* Set a short read timeout so we don't block forever */
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        handle_client(client_fd);
    }

    return NULL;
}

int prometheus_start(int port, iface_ctx_t *ifaces, int iface_count)
{
    struct sockaddr_in addr;
    int opt = 1;

    prom_ifaces = ifaces;
    prom_iface_count = iface_count;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("prometheus: socket");
        return -1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("prometheus: bind");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("prometheus: listen");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    server_running = 1;

    if (pthread_create(&server_thread, NULL, server_loop, NULL) != 0) {
        perror("prometheus: pthread_create");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    /* Detach so cleanup is simpler */
    pthread_detach(server_thread);

    return 0;
}

void prometheus_stop(void)
{
    if (server_fd < 0) return;

    server_running = 0;
    /* Close server socket to unblock accept() */
    close(server_fd);
    server_fd = -1;
}
