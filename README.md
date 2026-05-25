# netScan

## About

**netScan** is a Python CLI tool for auditing local networks, built on top of [Scapy](https://scapy.net/). It provides scanning and fingerprinting methods, each running with multithreaded packet dispatch for speed.

- **ARP** — discovers all active hosts on the local subnet (cannot be blocked by firewalls)
- **ICMP** — pings all hosts to check reachability
- **TCP** — performs a SYN scan on a target host to find open ports
- **UDP** — probes UDP ports; reports open (got a UDP reply) or open|filtered (no response) ports
- **OS fingerprinting** — guesses the OS of a host by analysing TTL and TCP window size in a SYN-ACK response

## Requirements

- Python 3.10+
- Root / administrator privileges (required for raw packet access)
- npcap (Windows only)

## Setup

### Linux & macOS

```bash
./init.sh
source netscan_venv/bin/activate
```

### Windows

```bat
init.bat
call netscan_venv\Scripts\activate
```

`init.sh` / `init.bat` creates a virtual environment and runs `pip install -e .`, which installs all dependencies and registers the `netscan` command.

## Usage

```bash
sudo netscan <command> [options]
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
sudo netscan arp

# Discover live hosts via ICMP with 10s timeout
sudo netscan ping -t 10

# Scan ports 1–1024 on a target
sudo netscan tcp --target 192.168.1.1:1-1024

# Scan a single port
sudo netscan tcp --target 192.168.1.1:80

# UDP scan of common ports
sudo netscan udp --target 192.168.1.1:1-1024

# Fingerprint a host OS (auto-probes common ports)
sudo netscan os --target 192.168.1.1

# Fingerprint using a known-open port
sudo netscan os --target 192.168.1.1 --port 80

# Watch for new hosts and ARP spoofing attempts
sudo netscan monitor arp

# Monitor all hosts on the subnet (auto-discovers new/departed hosts)
sudo netscan monitor hosts

# Monitor specific hosts every 10s
sudo netscan monitor hosts --hosts 192.168.1.1 192.168.1.50 -i 10

# Watch for port state changes on a target
sudo netscan monitor ports --target 192.168.1.1:1-1024

# Live packet capture (all traffic)
sudo netscan monitor traffic

# Live capture filtered to DNS
sudo netscan monitor traffic --filter "udp port 53"

# Generate a network graph (saved as netscan_graph.html)
sudo netscan graph

# Graph with OS fingerprinting for each discovered host
sudo netscan graph --fingerprint

# Save to a custom path
sudo netscan graph -o /tmp/my_network.html
```

### Options

```bash
arp:
  -t, --timeout     Packet timeout in seconds (default: 5)
  -v, --verbose     Verbose scapy output

ping:
  -t, --timeout     Packet timeout in seconds (default: 5)
  -th, --threads    Number of threads (default: 100)
  -v, --verbose     Verbose scapy output

tcp:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -v, --verbose     Verbose scapy output

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
  -o, --output      Output file path (default: netscan_graph.html)
  -t, --timeout     ARP scan timeout in seconds (default: 3)
  -th, --threads    Concurrent fingerprint probes (default: 10)
  -v, --verbose     Verbose scapy output
```

## Roadmap

- [x] UDP scan
- [x] Adaptive scan algorithm (AIMD concurrency + RTT-based timeout for TCP, ICMP, UDP and OS fingerprinting)
- [x] OS fingerprinting
- [x] Real-time packet capture / host monitoring (ARP watcher, host reachability table, port watcher, traffic sniffer)
- [x] Interactive HTML network graph (vis-network, dark theme, OS fingerprinting overlay)
