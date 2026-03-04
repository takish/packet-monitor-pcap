/*
 * output.h - Structured output formats (JSON, CSV, log)
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdio.h>
#include "pkt_monitor.h"

void output_json_line(FILE *fp, const packet_counter_t *cur);
void output_csv_header(FILE *fp);
void output_csv_line(FILE *fp, const packet_counter_t *cur);
void output_log_line(FILE *fp, const packet_counter_t *cur);

#endif /* OUTPUT_H */
