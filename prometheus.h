/*
 * prometheus.h - Prometheus metrics exporter (simple HTTP server)
 */

#ifndef PROMETHEUS_H
#define PROMETHEUS_H

#include "pkt_monitor.h"

/*
 * Start the Prometheus metrics HTTP server on the given port.
 * Spawns a background thread to handle requests.
 * ifaces/iface_count are read by the metrics handler (read-only).
 * Returns 0 on success, -1 on error.
 */
int prometheus_start(int port, iface_ctx_t *ifaces, int iface_count);

/*
 * Stop the Prometheus server and clean up.
 */
void prometheus_stop(void);

#endif /* PROMETHEUS_H */
