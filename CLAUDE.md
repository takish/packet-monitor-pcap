# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

C packet monitor using libpcap. Single-file project (`pkt_monitor.c`) that compiles to a standalone binary.

## Build

```bash
make          # build pkt_monitor binary
make clean    # remove binary and .o files
make install  # install to /usr/local/bin (requires sudo)
```

Compiler: `cc` with `-O2 -g -Wall -Wextra -Werror`. All warnings are treated as errors.

## Dependencies

- libpcap: macOS ships it pre-installed. Linux: `apt install libpcap-dev` or `yum install libpcap-devel`

## Running

Requires root or `CAP_NET_RAW` capability:

```bash
sudo ./pkt_monitor [-d device] [-i|-o] [-h]
```

## Code Structure

`pkt_monitor.c` is the only source file. Key sections:

- `packet_counter_t`: struct holding per-second counters (all, ip, ipv6, arp, icmp, tcp, udp, bps)
- `alarm_handler()`: SIGALRM handler, fires every second via `setitimer`, prints stats and resets counters
- `packet_handler()`: pcap callback, parses Ethernet frames and updates counters
- `main()`: argument parsing, pcap setup, timer setup, capture loop

## Important Notes

- Only Ethernet (`DLT_EN10MB`) link layers are supported. The binary exits with an error on other link types (e.g., loopback, Wi-Fi monitor mode).
- ICMP and TCP/UDP counters are only incremented for IPv4. IPv6 transport protocols are not broken down further.
- `INTVAL` (10) controls how often the header line is reprinted.
- `SNAP_LEN` (1600) is the capture snapshot length in bytes.
- The `alldevs` memory from `pcap_findalldevs` is intentionally not freed because the `device` pointer references it.
