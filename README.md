# sondare

[![PyPI](https://img.shields.io/pypi/v/sondare)](https://pypi.org/project/sondare/)
[![Python](https://img.shields.io/pypi/pyversions/sondare)](https://pypi.org/project/sondare/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> *From italian: sonda di rete - network probe*

## About

**sondare** is a Python CLI tool for auditing local networks, built on top of [Scapy](https://scapy.net/). It provides scanning and fingerprinting methods, each running with multithreaded packet dispatch for speed.

- **ARP** — discovers all active IPv4 hosts on the local subnet (cannot be blocked by firewalls)
- **NDP** — discovers IPv6 hosts on the local link via ICMPv6 multicast ping + neighbor cache
- **ICMP** — pings all hosts to check reachability (iOS devices block ICMP by design; use ARP for full discovery)
- **TCP** — performs a SYN scan on a target host to find open ports; optionally grabs service banners
- **UDP** — probes UDP ports; reports open (got a UDP reply) or open|filtered (no response) ports
- **OS fingerprinting** — guesses the OS of a host by analysing TTL and TCP window size in a SYN-ACK response
- **TLS/SSL probing** — extracts certificate details (CN, issuer, validity, SANs) from HTTPS ports; flags expired and self-signed certs
- **Hostname resolution** — resolves hostnames via mDNS service browse, SSDP/UPnP, NetBIOS, and PTR records
- **Network graph** — renders an interactive HTML topology of the local network via dual-stack ARP + NDP discovery, with optional OS fingerprinting and vendor labels per node

## Requirements

- Python 3.10+
- Root / administrator privileges (required for raw packet access)
- npcap (Windows only)

## Installation

### pipx (recommended)

```bash
sudo pipx install sondare --global
```

### From source

```bash
git clone https://github.com/w1ldy0uth/sondare.git
cd sondare
./init.sh
source sondare_venv/bin/activate
```

`init.sh` creates a virtual environment, installs all dependencies, and registers the `sondare` command inside it. On Windows use `init.bat` and `call sondare_venv\Scripts\activate` instead.

## Usage

```bash
sudo sondare <command> [options]
```

### Commands

| Command | Description |
| --------- | ------------- |
| `arp` | ARP scan of the local subnet (IPv4) |
| `ndp` | NDP scan of the local link (IPv6) |
| `ping` | ICMP scan of the local subnet |
| `tcp` | TCP SYN port scan of a target host |
| `udp` | UDP port scan of a target host |
| `os` | OS fingerprint of a target host |
| `monitor arp` | Watch for ARP traffic; report new hosts and MAC changes |
| `monitor ndp` | Watch for ICMPv6 Neighbor Advertisements; report new IPv6 hosts and MAC changes |
| `monitor hosts` | Live host reachability table with auto-discovery (IPv4 and IPv6) |
| `monitor ports` | Periodically SYN-scan a target and report port state changes (IPv4 and IPv6) |
| `monitor traffic` | Live packet capture with per-packet protocol breakdown |
| `graph` | Generate an interactive HTML network graph via ARP + NDP dual-stack discovery |
| `mdns` | Discover mDNS/Bonjour services on the local network |
| `trace` | Trace the network path to a target host |
| `tls` | Probe TLS/SSL certificate details on a target host |

### Examples

```bash
# Discover all hosts via ARP
sudo sondare arp

# Discover hosts and resolve their hostnames (requires PTR records on the network)
sudo sondare arp --resolve_hostname

# Discover IPv6 hosts on the local link via NDP
sudo sondare ndp

# NDP scan with a longer timeout (useful on slower networks)
sudo sondare ndp -t 5

# NDP with hostname resolution
sudo sondare ndp --resolve_hostname

# Discover live hosts via ICMP with 10s timeout
sudo sondare ping -t 10

# Ping scan with hostname resolution
sudo sondare ping --resolve_hostname

# Probe a single IPv4 host
sudo sondare ping --target 192.168.1.1

# Probe a single IPv6 host
sudo sondare ping --target fe80::dead:beef

# Scan all IPv6 hosts on the local link via ICMPv6 multicast
sudo sondare ping --ipv6

# Note: iOS devices block ICMP by design and won't appear in ping results.
# Use `sondare arp` for complete host discovery including iOS devices.

# Scan ports 1–1024 on a target
sudo sondare tcp --target 192.168.1.1:1-1024

# Scan a single port
sudo sondare tcp --target 192.168.1.1:80

# Grab service banners from open ports
sudo sondare tcp --target 192.168.1.1:1-1024 --banners

# Scan an IPv6 host (quote brackets to prevent shell glob expansion)
sudo sondare tcp --target '[fe80::dead:beef]:1-1024'

# UDP scan of common ports
sudo sondare udp --target 192.168.1.1:1-1024

# UDP scan of an IPv6 host
sudo sondare udp --target '[fe80::dead:beef]:1-1024'

# Fingerprint a host OS (auto-probes common ports)
sudo sondare os --target 192.168.1.1

# Fingerprint using a known-open port
sudo sondare os --target 192.168.1.1 --port 80

# Fingerprint an IPv6 host
sudo sondare os --target fe80::dead:beef

# Watch for new hosts and ARP spoofing attempts
sudo sondare monitor arp

# Watch for new IPv6 hosts and NDP spoofing (neighbor cache poisoning) attempts
sudo sondare monitor ndp

# Monitor all hosts on the subnet (auto-discovers new/departed hosts)
sudo sondare monitor hosts

# Monitor specific hosts every 10s (IPv6 addresses are detected automatically)
sudo sondare monitor hosts --hosts 192.168.1.1 fe80::dead:beef -i 10

# Watch for port state changes on a target
sudo sondare monitor ports --target 192.168.1.1:1-1024

# Watch ports on an IPv6 target
sudo sondare monitor ports --target '[fe80::dead:beef]:1-1024'

# Live packet capture (all traffic)
sudo sondare monitor traffic

# Live capture filtered to DNS
sudo sondare monitor traffic --filter "udp port 53"

# Generate a network graph (saved as sondare_graph.html)
sudo sondare graph

# Graph with OS fingerprinting for each discovered host
sudo sondare graph --fingerprint

# Save to a custom path
sudo sondare graph -o /tmp/my_network.html

# Save as structured JSON topology instead of HTML
sudo sondare graph -o topology.json

# Trace the network path to a host
sudo sondare trace --target 8.8.8.8

# Trace with a longer per-hop timeout and a cap of 20 hops
sudo sondare trace --target 8.8.8.8 -t 5 --max-hops 20

# Trace to an IPv6 host
sudo sondare trace --target fe80::dead:beef

# Discover mDNS/Bonjour services (AirPlay, SSH, SMB, Chromecast, HomeKit, …)
sudo sondare mdns

# Browse for longer to catch slower devices
sudo sondare mdns -t 10

# Probe TLS certificate on common HTTPS ports (443 and 8443)
sudo sondare tls --target 192.168.1.1

# Probe a specific port
sudo sondare tls --target 192.168.1.1:8443

# Output results as JSON (supported by all scan commands)
sudo sondare arp --json
sudo sondare ndp --json
sudo sondare ping --json
sudo sondare tcp --target 192.168.1.1:1-1024 --banners --json
sudo sondare mdns --json
sudo sondare tls --target 192.168.1.1 --json
```

### Options

```bash
arp:
  -t, --timeout          Packet timeout in seconds (default: 5)
  --resolve_hostname     Resolve hostnames via mDNS, SSDP, NetBIOS, and PTR
  -v, --verbose          Verbose scapy output
  --json                 JSON output

ping:
  --target           Single host to probe (IPv4 or IPv6); omit to scan the local IPv4 subnet
  --ipv6             ICMPv6 multicast sweep of ff02::1 (all IPv6 hosts on the local link)
  -t, --timeout      Packet timeout in seconds (default: 5)
  --resolve_hostname Resolve hostnames via mDNS, SSDP, NetBIOS, and PTR
  -v, --verbose      Verbose scapy output
  --json             JSON output

ndp:
  -t, --timeout          Scan timeout in seconds (default: 3)
  --resolve_hostname     Resolve hostnames via PTR lookup
  -v, --verbose          Verbose scapy output
  --json                 JSON output

tcp:
  --target          Target as ip, ip:port, or ip:start-end; IPv6 with ports: '[fe80::1]:80'
                    (quote brackets in shell); default: local machine, ports 1-1000
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -b, --banners     Grab service banners from open ports
  -v, --verbose     Verbose scapy output
  --json            JSON output

udp:
  --target          Target as ip, ip:port, or ip:start-end; IPv6 with ports: '[fe80::1]:80'
                    (quote brackets in shell); default: local machine, ports 1-1000
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -v, --verbose     Verbose scapy output

os:
  --target          Target IPv4 or IPv6 address (required)
  --port            Port to probe; omit to auto-try common ports in parallel
  -t, --timeout     Timeout per probe in seconds (default: 3)
  -v, --verbose     Verbose scapy output

monitor arp:
  -t, --timeout     Timeout for initial ARP seed scan (default: 5)
  -v, --verbose     Verbose scapy output

monitor ndp:
  -t, --timeout     Timeout for initial ICMPv6 multicast seed sweep (default: 5)
  -v, --verbose     Verbose scapy output

monitor hosts:
  --hosts           Hosts to monitor; IPv4 and IPv6 addresses accepted; omit to
                    auto-discover via ARP each round
  -i, --interval    Seconds between ping rounds (default: 30)
  -t, --timeout     Ping timeout in seconds (default: 2)
  -th, --threads    Concurrent pings per round (default: 50)
  -v, --verbose     Verbose scapy output

monitor ports:
  --target          Target as ip, ip:port, or ip:start-end; IPv6 with ports: '[fe80::1]:80'
                    (quote brackets in shell); default: local machine, ports 1-1000
  -i, --interval    Seconds between scans (default: 60)
  -t, --timeout     Timeout per probe in seconds (default: 3)
  -th, --threads    Concurrent probes per scan (default: 20)
  -v, --verbose     Verbose scapy output

monitor traffic:
  --filter          BPF filter expression (e.g. 'tcp', 'udp port 53', 'host 192.168.1.1')
  -v, --verbose     Verbose scapy output

graph:
  --fingerprint     OS-fingerprint each discovered host (TCP SYN, falls back to ICMP TTL)
  -o, --output      Output path: .html for interactive graph, .json for topology data (default: sondare_graph.html)
  -t, --timeout     ARP + NDP scan timeout in seconds (default: 3)
  -th, --threads    Concurrent fingerprint probes (default: 10)
  -v, --verbose     Verbose scapy output

mdns:
  -t, --timeout     Browse duration in seconds (default: 5)
  -v, --verbose     Verbose scapy output
  --json            JSON output

trace:
  --target          Target IPv4 or IPv6 address (required)
  -t, --timeout     Timeout per hop in seconds (default: 3)
  --max-hops        Maximum number of hops (default: 30)
  -v, --verbose     Verbose scapy output
  --json            JSON output

tls:
  --target          Target as ip or ip:port; IPv6 with port: '[fe80::1]:443'
                    (quote brackets in shell); default ports: 443, 8443
  -t, --timeout     Connection timeout in seconds (default: 5)
  -v, --verbose     Verbose mode
  --json            JSON output
```

## Notes

- **`trace`** uses ICMP/ICMPv6 echo probes. Hosts that block ICMP will show `*` for all hops.
- **`ndp` / `monitor ndp`** send ICMPv6 echo requests to the all-nodes multicast `ff02::1` and merge results with the OS NDP neighbor cache. Hosts that block ICMPv6 pings may still appear via the cache if they were recently reachable.
- **`graph`** runs ARP and NDP discovery in parallel. Devices with both IPv4 and IPv6 addresses are merged by MAC and appear as a single node in the graph.
- **IPv6 with ports** — use bracket notation and quote it to prevent shell glob expansion: `'[fe80::1]:443'`. Applies to `tcp`, `udp`, `monitor ports`, and `tls`.
