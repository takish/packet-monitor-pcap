# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

C packet monitor using libpcap with optional ncurses TUI. Multi-file project that compiles to a standalone binary.

## Build

```bash
make          # build pkt_monitor binary (auto-detects ncurses)
make clean    # remove binary and .o files
make install  # install to /usr/local/bin (requires sudo)
```

Compiler: `cc` with `-O2 -g -Wall -Wextra -Werror`. All warnings are treated as errors.

ncurses is auto-detected at build time. If available, TUI mode is enabled (`-u` flag). Build output indicates whether ncurses support is included.

## Dependencies

- libpcap: macOS ships it pre-installed. Linux: `apt install libpcap-dev` or `yum install libpcap-devel`
- ncurses (optional): macOS ships it pre-installed. Linux: `apt install libncurses-dev`

## Running

Requires root or `CAP_NET_RAW` capability:

```bash
sudo ./pkt_monitor [-d device] [-i|-o] [-u] [-h]
```

## Code Structure

### Files

- `pkt_monitor.h`: shared types (`packet_counter_t`, `monitor_config_t`, `port_service_name()`) and constants
- `pkt_monitor.c`: main(), capture logic, text mode output, TUI mode loop, layer detail packet parsing
- `layer_detail.h` / `layer_detail.c`: ring buffer, layer counters, ARP/DNS resolver trackers, BPF filter builders
- `dns_parse.h` / `dns_parse.c`: DNS packet parser (header, question, answer sections with compression pointer support)
- `prometheus.h` / `prometheus.c`: Prometheus metrics exporter (background thread HTTP server, no external deps)
- `tui.h` / `tui.c`: ncurses TUI rendering (compiled only when ncurses is available)

### Key sections in pkt_monitor.c

- `packet_handler()`: pcap callback, parses Ethernet frames and updates per-second counters
- `detail_packet_handler()`: layer detail / resolve mode packet parsing (ARP, IP/ICMP, TCP/UDP, DNS)
- `run_layer_detail()`: text mode loop for -L and -R modes (ring buffer flush + counter display)
- `run_tui_detail()`: TUI mode loop for -L and -R modes
- `run_tui()`: TUI mode main loop for standard capture mode
- `accumulate_totals()`: adds per-second counters to cumulative totals
- `main()`: argument parsing, pcap setup, mode dispatch (text vs TUI vs detail)

### Key sections in tui.c

- `tui_init()`: ncurses setup, color pairs, terminal size check
- `tui_update()`: draws header, protocol table with bar graphs, footer
- `tui_update_detail()`: draws layer detail counters + ring buffer for -L/-R modes
- `tui_handle_input()`: non-blocking key input (q=quit, p=pause, r=reset)
- `tui_cleanup()`: ncurses teardown

### Design decisions

- Text mode uses `pcap_dispatch()` (non-blocking polling) + `now_ms()` timer
- TUI mode uses `pcap_dispatch()` (non-blocking, ~100ms timeout) + `gettimeofday()` timer
- SIGALRM is disabled in TUI mode to avoid ncurses corruption
- `#ifdef HAS_NCURSES` guards all ncurses code for conditional compilation
- `-L` layer mode auto-applies BPF filters (L2=arp, L3=ip/ip6/icmp, L4=tcp/udp) and combines with user `-f` filter via AND
- `-R` resolve mode auto-applies BPF filters (arp for ARP, udp port 53 for DNS)
- `--prometheus :PORT` starts a background thread HTTP server serving `/metrics` in Prometheus text format
- ARP resolver tracks Request→Reply pairs with 3s timeout; DNS resolver tracks Query→Response by txid with 5s timeout
- `detail_packet_handler()` is called from `packet_handler()` when layer_mode or resolve_mode is active
- Layer counters (layer2/3/4_counter_t) and resolver trackers are stored in global `detail_ctx_t`

## Important Notes

- Only Ethernet (`DLT_EN10MB`) link layers are supported
- ICMP and TCP/UDP counters are only incremented for IPv4; IPv6 transport protocols are not broken down further
- `INTVAL` (10) controls how often the header line is reprinted (text mode)
- `SNAP_LEN` (1600) is the capture snapshot length in bytes
- The `alldevs` memory from `pcap_findalldevs` is freed after copying the device name
- TUI requires minimum terminal size of 60x15
- `-L` and `-R` are mutually exclusive; neither can combine with `-j` or `-c`
