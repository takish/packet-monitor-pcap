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

- `pkt_monitor.h`: shared types (`packet_counter_t`, `monitor_config_t`) and constants
- `pkt_monitor.c`: main(), capture logic, text mode output, TUI mode loop
- `layer_detail.h` / `layer_detail.c`: layer detail mode ring buffer and BPF filter builder
- `tui.h` / `tui.c`: ncurses TUI rendering (compiled only when ncurses is available)

### Key sections in pkt_monitor.c

- `packet_handler()`: pcap callback, parses Ethernet frames and updates per-second counters
- `alarm_handler()`: SIGALRM handler for text mode, fires every second via `setitimer`
- `run_tui()`: TUI mode main loop using `pcap_dispatch()` (non-blocking) + ncurses
- `accumulate_totals()`: adds per-second counters to cumulative totals
- `main()`: argument parsing, pcap setup, mode dispatch (text vs TUI)

### Key sections in tui.c

- `tui_init()`: ncurses setup, color pairs, terminal size check
- `tui_update()`: draws header, protocol table with bar graphs, footer
- `tui_handle_input()`: non-blocking key input (q=quit, p=pause, r=reset)
- `tui_cleanup()`: ncurses teardown

### Design decisions

- Text mode uses `pcap_loop()` (blocking) + SIGALRM timer
- TUI mode uses `pcap_dispatch()` (non-blocking, ~100ms timeout) + `gettimeofday()` timer
- SIGALRM is disabled in TUI mode to avoid ncurses corruption
- `#ifdef HAS_NCURSES` guards all ncurses code for conditional compilation
- `-L` layer mode auto-applies BPF filters (L2=arp, L3=ip/ip6/icmp, L4=tcp/udp) and combines with user `-f` filter via AND

## Important Notes

- Only Ethernet (`DLT_EN10MB`) link layers are supported
- ICMP and TCP/UDP counters are only incremented for IPv4; IPv6 transport protocols are not broken down further
- `INTVAL` (10) controls how often the header line is reprinted (text mode)
- `SNAP_LEN` (1600) is the capture snapshot length in bytes
- The `alldevs` memory from `pcap_findalldevs` is intentionally not freed because the `device` pointer references it
- TUI requires minimum terminal size of 60x15
