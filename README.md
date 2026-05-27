# sondare

[![PyPI](https://img.shields.io/pypi/v/sondare)](https://pypi.org/project/sondare/)
[![Python](https://img.shields.io/pypi/pyversions/sondare)](https://pypi.org/project/sondare/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> *From italian: <u>sonda</u> di <u>re</u>te - network probe*

## About

**sondare** is a Python CLI tool for auditing local networks, built on top of [Scapy](https://scapy.net/). It provides scanning and fingerprinting methods, each running with multithreaded packet dispatch for speed.

- **ARP** — discovers all active hosts on the local subnet (cannot be blocked by firewalls)
- **ICMP** — pings all hosts to check reachability (iOS devices block ICMP by design; use ARP for full discovery)
- **TCP** — performs a SYN scan on a target host to find open ports; optionally grabs service banners
- **UDP** — probes UDP ports; reports open (got a UDP reply) or open|filtered (no response) ports
- **OS fingerprinting** — guesses the OS of a host by analysing TTL and TCP window size in a SYN-ACK response
- **Hostname resolution** — resolves hostnames via mDNS service browse, SSDP/UPnP, NetBIOS, and PTR records

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
| `arp` | ARP scan of the local subnet |
| `ping` | ICMP scan of the local subnet |
| `tcp` | TCP SYN port scan of a target host |
| `udp` | UDP port scan of a target host |
| `os` | OS fingerprint of a target host |
| `monitor arp` | Watch for ARP traffic; report new hosts and MAC changes |
| `monitor hosts` | Live host reachability table with auto-discovery |
| `monitor ports` | Periodically SYN-scan a target and report port state changes |
| `monitor traffic` | Live packet capture with per-packet protocol breakdown |
| `graph` | Generate an interactive HTML network graph of the local subnet |

### Examples

```bash
# Discover all hosts via ARP
sudo sondare arp

# Discover hosts and resolve their hostnames (requires PTR records on the network)
sudo sondare arp --resolve_hostname

# Discover live hosts via ICMP with 10s timeout
sudo sondare ping -t 10

# Ping scan with hostname resolution
sudo sondare ping --resolve_hostname

# Note: iOS devices block ICMP by design and won't appear in ping results.
# Use `sondare arp` for complete host discovery including iOS devices.

# Scan ports 1–1024 on a target
sudo sondare tcp --target 192.168.1.1:1-1024

# Scan a single port
sudo sondare tcp --target 192.168.1.1:80

# Grab service banners from open ports
sudo sondare tcp --target 192.168.1.1:1-1024 --banners

# UDP scan of common ports
sudo sondare udp --target 192.168.1.1:1-1024

# Fingerprint a host OS (auto-probes common ports)
sudo sondare os --target 192.168.1.1

# Fingerprint using a known-open port
sudo sondare os --target 192.168.1.1 --port 80

# Watch for new hosts and ARP spoofing attempts
sudo sondare monitor arp

# Monitor all hosts on the subnet (auto-discovers new/departed hosts)
sudo sondare monitor hosts

# Monitor specific hosts every 10s
sudo sondare monitor hosts --hosts 192.168.1.1 192.168.1.50 -i 10

# Watch for port state changes on a target
sudo sondare monitor ports --target 192.168.1.1:1-1024

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

# Output results as JSON (supported by all scan commands)
sudo sondare arp --json
sudo sondare ping --json
sudo sondare tcp --target 192.168.1.1:1-1024 --banners --json
```

### Options

```bash
arp:
  -t, --timeout          Packet timeout in seconds (default: 5)
  --resolve_hostname     Resolve hostnames via mDNS, SSDP, NetBIOS, and PTR
  -v, --verbose          Verbose scapy output
  --json                 JSON output

ping:
  -t, --timeout          Packet timeout in seconds (default: 5)
  --resolve_hostname     Resolve hostnames via mDNS, SSDP, NetBIOS, and PTR
  -v, --verbose          Verbose scapy output
  --json                 JSON output

tcp:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -b, --banners     Grab service banners from open ports
  -v, --verbose     Verbose scapy output
  --json            JSON output

udp:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -v, --verbose     Verbose scapy output

os:
  --target          Target IP address (required)
  --port            Port to probe; omit to auto-try common ports in parallel
  -t, --timeout     Timeout per probe in seconds (default: 3)
  -v, --verbose     Verbose scapy output

monitor arp:
  -t, --timeout     Timeout for initial ARP seed scan (default: 5)
  -v, --verbose     Verbose scapy output

monitor hosts:
  --hosts           Hosts to monitor; omit to auto-discover via ARP each round
  -i, --interval    Seconds between ping rounds (default: 30)
  -t, --timeout     Ping timeout in seconds (default: 2)
  -th, --threads    Concurrent pings per round (default: 50)
  -v, --verbose     Verbose scapy output

monitor ports:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -i, --interval    Seconds between scans (default: 60)
  -t, --timeout     Timeout per probe in seconds (default: 3)
  -th, --threads    Concurrent probes per scan (default: 20)
  -v, --verbose     Verbose scapy output

monitor traffic:
  --filter          BPF filter expression (e.g. 'tcp', 'udp port 53', 'host 192.168.1.1')
  -v, --verbose     Verbose scapy output

graph:
  --fingerprint     OS-fingerprint each discovered host (TCP SYN, falls back to ICMP TTL)
  -o, --output      Output file path (default: sondare_graph.html)
  -t, --timeout     ARP scan timeout in seconds (default: 3)
  -th, --threads    Concurrent fingerprint probes (default: 10)
  -v, --verbose     Verbose scapy output
```
