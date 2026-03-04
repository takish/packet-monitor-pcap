# pkt_monitor (libpcap version)

Cross-platform packet monitor that counts packets by protocol and displays traffic statistics.

Based on the [original Linux-only version](https://github.com/takish/packet-monitor) (2004).

## Supported Platforms

- Linux
- macOS

## Requirements

- libpcap (macOS: pre-installed, Linux: `apt install libpcap-dev` or `yum install libpcap-devel`)
- ncurses (optional, for TUI mode; macOS: pre-installed, Linux: `apt install libncurses-dev`)

## Build

```bash
make
```

## Usage

```bash
# Auto-detect interface
sudo ./pkt_monitor

# Specify interface
sudo ./pkt_monitor -d en0      # macOS
sudo ./pkt_monitor -d eth0     # Linux

# Legacy syntax (compatible with original version)
sudo ./pkt_monitor en0

# Incoming packets only
sudo ./pkt_monitor -d en0 -i

# Outgoing packets only
sudo ./pkt_monitor -d en0 -o

# TUI mode (ncurses)
sudo ./pkt_monitor -d en0 -u

# Show help
./pkt_monitor -h
```

## Install

```bash
sudo make install   # installs to /usr/local/bin/pkt_monitor
```

## Output

```
# Capturing on en0 (direction: both)
# time #	  all	 ipv4	 ipv6	arp	icmp	tcp	udp
12:34:56	   42	   30	    8	  4	   2	   20	    8  23.4kbps
12:34:57	   38	   28	    7	  3	   1	   19	    8  20.1kbps
```

## TUI Mode

Use `-u` to launch the ncurses-based TUI. Requires ncurses (auto-detected at build time).

```
┌ pkt_monitor ── en0 ── both ── 00:01:23 ────────────────┐
│                                                         │
│  Proto    pkt/s      Total   Bandwidth          kbps    │
│  ──────── ──────── ──────── ──────────────── ────────   │
│  IPv4        30      1,234  ████████████░░░  23.4 kbps  │
│  IPv6         8        200  ███░░░░░░░░░░░░   6.2 kbps  │
│  ARP          4         54  █░░░░░░░░░░░░░░   0.3 kbps  │
│  ICMP         2         45  ░░░░░░░░░░░░░░░   0.2 kbps  │
│  TCP         20        800  ██████████░░░░░  15.6 kbps  │
│  UDP          8        400  ████░░░░░░░░░░░   6.2 kbps  │
│  ──────── ──────── ──────── ──────────────── ────────   │
│  ALL         42      1,488                   29.4 kbps  │
│                                                         │
│  [q] Quit  [p] Pause  [r] Reset counters                │
└─────────────────────────────────────────────────────────┘
```

## Differences from original

| Feature | Original (2004) | libpcap version |
|---------|----------------|-----------------|
| Platform | Linux only | Linux + macOS |
| Packet capture | PF_PACKET raw socket | libpcap |
| BPF filter | Hand-written bytecode | libpcap API |
| Privileges | setuid root | sudo (or CAP_NET_RAW on Linux) |
| Interface | Positional arg only | `-d` flag + auto-detect |
| Direction filter | Compile-time `#ifdef` | Runtime `-i`/`-o` flags |
