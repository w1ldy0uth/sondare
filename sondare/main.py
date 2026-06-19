#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import json
import re
import sys
from importlib.metadata import version as _pkg_version, PackageNotFoundError
from typing import NamedTuple

import sondare.utils.network as network
import sondare.utils.root as root
from sondare.services.arp import Arp
from sondare.services.ndp import Ndp
from sondare.services.icmp import Ping
from sondare.services.tcp import Tcp
from sondare.services.udp import Udp
from sondare.services.fingerprint import OsFingerprinter
from sondare.services.graph import NetworkGraph
from sondare.services.mdns import Mdns
from sondare.services.trace import Traceroute
from sondare.services.tls import TlsProber, DEFAULT_PORTS as _TLS_DEFAULT_PORTS
from sondare.monitors.arp_watcher import ArpWatcher
from sondare.monitors.hosts_watcher import HostsWatcher
from sondare.monitors.ndp_watcher import NdpWatcher
from sondare.monitors.port_watcher import PortWatcher
from sondare.monitors.traffic_sniffer import TrafficSniffer


class Target(NamedTuple):
    ip: str
    port_begin: int
    port_end: int


_DEFAULT_PORT_BEGIN = 1
_DEFAULT_PORT_END = 1000

# Bracket IPv6 with optional port range: [fe80::1] or [fe80::1]:80 or [fe80::1]:80-443
_IPV6_BRACKET_RE = re.compile(r"\[([^\]]+)\](?::(\d+)(?:-(\d+))?)?")
# IPv4 / hostname with optional port range
_IPV4_RE = re.compile(r"([^:]+)(?::(\d+)(?:-(\d+))?)?")


def _parse_port_range(port_str: str | None, end_str: str | None, value: str) -> tuple[int, int]:
    if port_str is None:
        return _DEFAULT_PORT_BEGIN, _DEFAULT_PORT_END
    start = int(port_str)
    end   = int(end_str) if end_str else start
    if start < 1 or end > 65535:
        raise argparse.ArgumentTypeError(f"Port out of range (1-65535) in '{value}'.")
    if start > end:
        raise argparse.ArgumentTypeError(f"Start port {start} must be <= end port {end} in '{value}'.")
    return start, end


def parse_target(value: str) -> Target:
    """Parses 'ip', 'ip:port', 'ip:start-end', '[ipv6]', '[ipv6]:port', or '[ipv6]:start-end'."""
    import ipaddress as _ia
    if value.startswith("["):
        m = _IPV6_BRACKET_RE.fullmatch(value)
        if not m:
            raise argparse.ArgumentTypeError(f"Invalid target format: '{value}'.")
        ip = m.group(1)
        start, end = _parse_port_range(m.group(2), m.group(3), value)
    else:
        # Bare IPv6 without brackets (no port can be specified this way)
        try:
            addr = _ia.ip_address(value)
            if isinstance(addr, _ia.IPv6Address):
                return Target(value, _DEFAULT_PORT_BEGIN, _DEFAULT_PORT_END)
        except ValueError:
            pass
        # Detect bare IPv6 + port suffix and suggest bracket notation.
        # Strip a trailing :port or :start-end and test if the remainder is valid IPv6.
        m_suffix = re.match(r"^(.+):(\d+(?:-\d+)?)$", value)
        if m_suffix:
            try:
                candidate = _ia.ip_address(m_suffix.group(1))
                if isinstance(candidate, _ia.IPv6Address):
                    raise argparse.ArgumentTypeError(
                        f"IPv6 addresses with ports require bracket notation: "
                        f"[{m_suffix.group(1)}]:{m_suffix.group(2)}"
                    )
            except ValueError:
                pass
        m = _IPV4_RE.fullmatch(value)
        if not m:
            raise argparse.ArgumentTypeError(f"Invalid target format: '{value}'.")
        ip = m.group(1)
        start, end = _parse_port_range(m.group(2), m.group(3), value)
    return Target(ip, start, end)


def _parse_tls_target(value: str) -> tuple[str, tuple[int, ...]]:
    """Parses 'ip', '[ipv6]', 'ip:port', or '[ipv6]:port' into (ip, ports)."""
    import ipaddress as _ia
    if value.startswith("["):
        m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", value)
        if not m:
            raise argparse.ArgumentTypeError(f"Invalid target: '{value}'")
        ip, port_str = m.group(1), m.group(2)
    else:
        # Bare IPv6 without port
        try:
            addr = _ia.ip_address(value)
            if isinstance(addr, _ia.IPv6Address):
                return value, _TLS_DEFAULT_PORTS
        except ValueError:
            pass
        m = re.fullmatch(r"([^:]+)(?::(\d+))?", value)
        if not m:
            raise argparse.ArgumentTypeError(f"Invalid target: '{value}'")
        ip, port_str = m.group(1), m.group(2)
    if port_str is not None:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise argparse.ArgumentTypeError(f"Port {port} out of range (1-65535).")
        return ip, (port,)
    return ip, _TLS_DEFAULT_PORTS


def _fmt_port_range(begin: int, end: int) -> str:
    return str(begin) if begin == end else f"{begin}-{end}"


def _get_version() -> str:
    try:
        return _pkg_version("sondare")
    except PackageNotFoundError:
        return "unknown"


def parse_args() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--json", action="store_true", help="Output results as JSON")
    shared.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    parser = argparse.ArgumentParser(
        prog="sondare",
        description=f"sondare {_get_version()} — Probe and monitor local network hosts.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
arp / ping / ndp:
  -t, --timeout          Packet timeout in seconds (default: 5 for arp/ping, 3 for ndp)
  --resolve_hostname     Resolve hostnames via mDNS, SSDP, NetBIOS, and PTR
  -v, --verbose          Verbose output
  --json                 JSON output

tcp:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -b, --banners     Grab service banners from open ports
  -v, --verbose     Verbose output
  --json            JSON output

udp:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -t, --timeout     Packet timeout in seconds (default: 3)
  -th, --threads    Number of threads (default: 20)
  -r, --retries     Retries per port on no response (default: 2)
  -v, --verbose     Verbose output
  --json            JSON output

os:
  --target          Target IP address (required)
  --port            Port to probe; omit to auto-try common ports
  -t, --timeout     Timeout per probe in seconds (default: 3)
  -v, --verbose     Verbose output
  --json            JSON output

monitor arp:
  -t, --timeout     Timeout for initial ARP seed scan (default: 5)
  -v, --verbose     Verbose output

monitor ndp:
  -t, --timeout     Timeout for initial multicast seed sweep (default: 5)
  -v, --verbose     Verbose output

monitor hosts:
  --hosts           Hosts to monitor; omit to auto-discover via ARP
  -i, --interval    Seconds between ping rounds (default: 30)
  -t, --timeout     Ping timeout in seconds (default: 2)
  -th, --threads    Concurrent pings per round (default: 50)
  -v, --verbose     Verbose output

monitor ports:
  --target          Target as ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)
  -i, --interval    Seconds between scans (default: 60)
  -t, --timeout     Timeout per probe in seconds (default: 3)
  -th, --threads    Concurrent probes per scan (default: 20)
  -v, --verbose     Verbose output

monitor traffic:
  --filter          BPF filter expression (e.g. 'tcp', 'udp port 53', 'host 192.168.1.1')
  -v, --verbose     Verbose output

graph:
  --fingerprint     OS-fingerprint each discovered host
  -o, --output      Output path: .html for interactive graph, .json for topology data (default: sondare_graph.html)
  -t, --timeout     ARP scan timeout in seconds (default: 3)
  -th, --threads    Concurrent fingerprint probes (default: 10)
  -v, --verbose     Verbose output

mdns:
  -t, --timeout     Browse duration in seconds (default: 5)
  -v, --verbose     Verbose output
  --json            JSON output

trace:
  --target          Target IP address (required)
  -t, --timeout     Timeout per hop in seconds (default: 3)
  --max-hops        Maximum number of hops (default: 30)
  -v, --verbose     Verbose output
  --json            JSON output

Note: trace uses ICMP echo probes. Hosts that block ICMP will show * for all hops.

tls:
  --target          Target as ip or ip:port (default ports: 443, 8443)
  -t, --timeout     Connection timeout in seconds (default: 5)
  -v, --verbose     Verbose mode
  --json            JSON output
        """
    )

    parser.add_argument("-V", "--version", action="version", version=f"sondare {_get_version()}")

    subparsers = parser.add_subparsers(title="SCAN METHODS", dest="scan_method")

    # ARP scan
    arp_parser = subparsers.add_parser("arp", parents=[shared], help="Scan local network with ARP packets.")
    arp_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for scan response")
    arp_parser.add_argument("--resolve_hostname", action="store_true", help="Resolve hostnames via PTR lookup")

    # NDP scan
    ndp_parser = subparsers.add_parser("ndp", parents=[shared], help="Discover IPv6 hosts via Neighbor Discovery Protocol.")
    ndp_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds (default: 3)")
    ndp_parser.add_argument("--resolve_hostname", action="store_true", help="Resolve hostnames via PTR lookup")

    # Ping scan
    ping_parser = subparsers.add_parser("ping", parents=[shared], help="Ping all hosts in local network with ICMP packets.")
    ping_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for scan response")
    ping_parser.add_argument("--resolve_hostname", action="store_true", help="Resolve hostnames via PTR lookup")
    ping_parser.add_argument("--target", type=str, default=None, help="Single host to probe (IPv4 or IPv6); omit to scan the local subnet")
    ping_parser.add_argument("--ipv6", action="store_true", help="ICMPv6 multicast sweep of ff02::1 (all IPv6 hosts on the local link)")

    # TCP scan
    tcp_parser = subparsers.add_parser("tcp", parents=[shared], help="Scan ports of target host with TCP packets.")
    tcp_parser.add_argument("--target", type=parse_target, default=None, help="Target as ip, ip:port, or ip:start-end. IPv6 with ports: '[fe80::1]:80' (quote brackets in shell)")
    tcp_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for port scan (default: 3)")
    tcp_parser.add_argument("-th", "--threads", type=int, default=20, help="Amount of threads to use")
    tcp_parser.add_argument("-r", "--retries", type=int, default=2, help="Retries per port on no response (default: 2)")
    tcp_parser.add_argument("-b", "--banners", action="store_true", help="Grab service banners from open ports")

    # OS fingerprint
    os_parser = subparsers.add_parser("os", parents=[shared], help="Guess the OS of a target host via TCP SYN-ACK analysis.")
    os_parser.add_argument("--target", required=True, help="Target IP address")
    os_parser.add_argument("--port", type=int, default=None, help="Port to probe (default: auto-tries common ports)")
    os_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout per probe in seconds (default: 3)")

    # UDP scan
    udp_parser = subparsers.add_parser("udp", parents=[shared], help="Scan ports of target host with UDP packets.")
    udp_parser.add_argument("--target", type=parse_target, default=None, help="Target as ip, ip:port, or ip:start-end. IPv6 with ports: '[fe80::1]:80' (quote brackets in shell)")
    udp_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for port scan (default: 3)")
    udp_parser.add_argument("-th", "--threads", type=int, default=20, help="Amount of threads to use")
    udp_parser.add_argument("-r", "--retries", type=int, default=2, help="Retries per port on no response (default: 2)")

    # Monitor commands
    monitor_parser = subparsers.add_parser("monitor", help="Real-time network monitors.")
    monitor_sub = monitor_parser.add_subparsers(title="MONITOR TYPES", dest="monitor_type")

    arp_watch_parser = monitor_sub.add_parser("arp", parents=[shared], help="Watch for ARP traffic and report new hosts or MAC changes.")
    ndp_watch_parser = monitor_sub.add_parser("ndp", parents=[shared], help="Watch for ICMPv6 Neighbor Advertisements and report new IPv6 hosts or MAC changes.")
    arp_watch_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for initial ARP seed scan (default: 5)")
    ndp_watch_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for initial multicast seed sweep (default: 5)")

    updown_parser = monitor_sub.add_parser("hosts", parents=[shared], help="Periodically ping hosts and report up/down state changes.")
    updown_parser.add_argument("--hosts", nargs="+", metavar="IP", default=None, help="Hosts to monitor (default: discover via ARP scan)")
    updown_parser.add_argument("-i", "--interval", type=int, default=30, help="Seconds between ping rounds (default: 30)")
    updown_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Ping timeout in seconds (default: 2)")
    updown_parser.add_argument("-th", "--threads", type=int, default=50, help="Concurrent pings per round (default: 50)")

    ports_parser = monitor_sub.add_parser("ports", parents=[shared], help="Periodically SYN-scan a target and report port state changes.")
    ports_parser.add_argument("--target", type=parse_target, default=None, help="Target as ip, ip:port, or ip:start-end. IPv6 with ports: '[fe80::1]:80' (quote brackets in shell)")
    ports_parser.add_argument("-i", "--interval", type=int, default=60, help="Seconds between scans (default: 60)")
    ports_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Timeout per probe in seconds (default: 3)")
    ports_parser.add_argument("-th", "--threads", type=int, default=20, help="Concurrent probes per scan (default: 20)")

    traffic_parser = monitor_sub.add_parser("traffic", parents=[shared], help="Live packet capture with per-packet protocol breakdown.")
    traffic_parser.add_argument("--filter", metavar="BPF", default=None, help="BPF filter expression (e.g. 'tcp', 'udp port 53', 'host 192.168.1.1')")

    # Graph
    graph_parser = subparsers.add_parser("graph", parents=[shared], help="Generate an interactive HTML network graph.")
    graph_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="ARP scan timeout in seconds (default: 3)")
    graph_parser.add_argument("-th", "--threads", type=int, default=10, help="Concurrent fingerprint probes (default: 10)")
    graph_parser.add_argument("--fingerprint", action="store_true", help="OS-fingerprint each discovered host")
    graph_parser.add_argument("-o", "--output", default="sondare_graph.html", help="Output path: .html for interactive graph, .json for topology data (default: sondare_graph.html)")

    # TLS probe
    tls_parser = subparsers.add_parser("tls", parents=[shared], help="Probe TLS/SSL certificate details on a target host.")
    tls_parser.add_argument("--target", required=True, help="Target as ip or ip:port. IPv6 with port: '[fe80::1]:443' (quote brackets in shell)")
    tls_parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Connection timeout in seconds (default: 5)")

    # mDNS scan
    mdns_parser = subparsers.add_parser("mdns", parents=[shared], help="Discover mDNS/Bonjour services on the local network.")
    mdns_parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Browse duration in seconds (default: 5)")

    # Traceroute
    trace_parser = subparsers.add_parser("trace", parents=[shared], help="Trace the network path to a target host.")
    trace_parser.add_argument("--target", required=True, help="Target IP address")
    trace_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Timeout per hop in seconds (default: 3)")
    trace_parser.add_argument("--max-hops", type=int, default=30, help="Maximum number of hops (default: 30)")

    return parser


def main() -> None:
    """Entry point: parses CLI arguments and dispatches to the appropriate scanner."""
    parser = parse_args()
    args = parser.parse_args()

    if not root.is_running_as_root():
        print("Access denied. Run this program as root.")
        sys.exit(1)

    if args.scan_method is None:
        parser.print_help()
        return

    try:
        if args.scan_method == "arp":
            print(f"Running ARP scan with {args.timeout} seconds timeout")
            scanner = Arp(verbose=args.verbose, timeout=args.timeout, resolve_hostname=args.resolve_hostname)
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                print(json.dumps({"hosts": [
                    {
                        "ip": h.ip,
                        "mac": h.mac,
                        **({"hostname": h.hostname} if args.resolve_hostname else {}),
                        **({"vendor": h.vendor} if h.vendor else {}),
                    }
                    for h in results
                ]}))
            else:
                if args.resolve_hostname:
                    host_col = max((len(h.hostname or '') for h in results), default=8) + 2
                    mac_col  = max((len(h.mac) for h in results), default=17) + 2
                    print("IP".ljust(15) + "HOSTNAME".ljust(host_col) + "MAC".ljust(mac_col) + "VENDOR")
                    for h in results:
                        print(f"{h.ip.ljust(15)}{(h.hostname or '').ljust(host_col)}{h.mac.ljust(mac_col)}{h.vendor or ''}")
                else:
                    print("IP".ljust(15) + "MAC".ljust(20) + "VENDOR")
                    for h in results:
                        print(f"{h.ip.ljust(15)}{h.mac.ljust(20)}{h.vendor or ''}")

        elif args.scan_method == "ndp":
            print(f"Running NDP scan with {args.timeout}s timeout")
            scanner = Ndp(verbose=args.verbose, timeout=args.timeout, resolve_hostname=args.resolve_hostname)
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                print(json.dumps({"hosts": [
                    {
                        "ip": h.ip,
                        "mac": h.mac,
                        **({"hostname": h.hostname} if args.resolve_hostname else {}),
                        **({"vendor": h.vendor} if h.vendor else {}),
                    }
                    for h in results
                ]}))
            else:
                ip_col = max((len(h.ip) for h in results), default=4) + 2
                if args.resolve_hostname:
                    host_col = max((len(h.hostname or '') for h in results), default=8) + 2
                    mac_col  = max((len(h.mac) for h in results), default=17) + 2
                    print("IPv6".ljust(ip_col) + "HOSTNAME".ljust(host_col) + "MAC".ljust(mac_col) + "VENDOR")
                    for h in results:
                        print(f"{h.ip.ljust(ip_col)}{(h.hostname or '').ljust(host_col)}{h.mac.ljust(mac_col)}{h.vendor or ''}")
                else:
                    mac_col = max((len(h.mac) for h in results), default=17) + 2
                    print("IPv6".ljust(ip_col) + "MAC".ljust(mac_col) + "VENDOR")
                    for h in results:
                        print(f"{h.ip.ljust(ip_col)}{h.mac.ljust(mac_col)}{h.vendor or ''}")

        elif args.scan_method == "ping":
            if args.target:
                import ipaddress as _ipaddress
                try:
                    _ipaddress.ip_address(args.target)
                except ValueError:
                    print(f"Error: '{args.target}' is not a valid IP address.", file=sys.stderr)
                    sys.exit(1)
                print(f"Pinging {args.target} with {args.timeout}s timeout")
            elif args.ipv6:
                print(f"Running ICMPv6 scan on local link with {args.timeout}s timeout")
            else:
                print(f"Running ICMP scan on {network.get_network_interface()} with {args.timeout}s timeout")
            scanner = Ping(verbose=args.verbose, timeout=args.timeout, resolve_hostname=args.resolve_hostname, target=args.target, ipv6=args.ipv6)
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                hostnames = scanner.get_hostnames() if args.resolve_hostname else {}
                print(json.dumps({"hosts": [
                    {"ip": ip, **({"hostname": hostnames[ip]} if hostnames.get(ip) else {})}
                    for ip in results
                ]}))
            else:
                hostnames = scanner.get_hostnames() if args.resolve_hostname else {}
                for ip in results:
                    suffix = f" ({hostnames[ip]})" if hostnames.get(ip) else ""
                    print(f"{ip}{suffix} is alive")

        elif args.scan_method == "tcp":
            target: Target = args.target or parse_target(network.get_ip_address())
            port_range = _fmt_port_range(target.port_begin, target.port_end)
            print(f"Running TCP scan for {target.ip}:{port_range} with {args.timeout}s timeout, {args.threads} {'thread' if args.threads == 1 else 'threads'}, {args.retries} retr{'y' if args.retries == 1 else 'ies'}")
            scanner = Tcp(
                verbose=args.verbose,
                timeout=args.timeout,
                threads=args.threads,
                retries=args.retries,
                banners=args.banners,
                ip=target.ip,
                port_begin=target.port_begin,
                port_end=target.port_end
            )
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                ports_data = [
                    {
                        "port": p.port,
                        **({"service": p.service} if p.service else {}),
                        **({"banner": p.banner} if p.banner else {}),
                    }
                    for p in results
                ]
                print(json.dumps({"host": target.ip, "ports": ports_data}))
            else:
                print(f"Open ports: {len(results)}\n_______________________")
                for port in results:
                    label = f"{port.ip}:{port.port}/{port.service}" if port.service else f"{port.ip}:{port.port}"
                    suffix = f"  {port.banner}" if port.banner else ""
                    print(f"{label} is open{suffix}")

        elif args.scan_method == "os":
            port_hint = f":{args.port}" if args.port else " (auto)"
            print(f"Fingerprinting {args.target}{port_hint} with {args.timeout}s timeout")
            scanner = OsFingerprinter(
                verbose=args.verbose,
                ip=args.target,
                port=args.port,
                timeout=args.timeout,
            )
            scanner.scan()
            result = scanner.get_results()

            if result is None:
                print("No response — could not fingerprint host.")
            elif args.json:
                print(json.dumps({
                    "ip": result.ip,
                    "os": result.os,
                    "ttl": result.ttl,
                    "window": result.window,
                    "source": result.source,
                }))
            else:
                src_label = "ICMP" if result.source == "icmp" else "TCP SYN-ACK"
                print(f"IP:     {result.ip}")
                print(f"OS:     {result.os}  [{src_label}]")
                print(f"TTL:    {result.ttl}")
                if result.source == "tcp":
                    print(f"Window: {result.window}")

        elif args.scan_method == "udp":
            target: Target = args.target or parse_target(network.get_ip_address())
            port_range = _fmt_port_range(target.port_begin, target.port_end)
            print(f"Running UDP scan for {target.ip}:{port_range} with {args.timeout}s timeout, {args.threads} {'thread' if args.threads == 1 else 'threads'}, {args.retries} retr{'y' if args.retries == 1 else 'ies'}")
            scanner = Udp(
                verbose=args.verbose,
                timeout=args.timeout,
                threads=args.threads,
                retries=args.retries,
                ip=target.ip,
                port_begin=target.port_begin,
                port_end=target.port_end
            )
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                ports_data = [
                    {"port": p.port, **({"service": p.service} if p.service else {})}
                    for p in results
                ]
                print(json.dumps({"host": target.ip, "ports": ports_data}))
            else:
                print(f"Open|filtered ports: {len(results)}\n_______________________")
                for port in results:
                    label = f"{port.ip}:{port.port}/{port.service}" if port.service else f"{port.ip}:{port.port}"
                    print(f"{label} is open|filtered")

        elif args.scan_method == "monitor":
            if args.monitor_type is None:
                print("Usage: sondare monitor {arp,ndp,hosts,ports,traffic}\nRun 'sondare monitor <type> --help' for details.")
                return
            if args.monitor_type == "arp":
                watcher = ArpWatcher(verbose=args.verbose, timeout=args.timeout)
                watcher.watch()
            elif args.monitor_type == "ndp":
                watcher = NdpWatcher(verbose=args.verbose, timeout=args.timeout)
                watcher.watch()
            elif args.monitor_type == "hosts":
                monitor = HostsWatcher(
                    verbose=args.verbose,
                    hosts=args.hosts or [],
                    timeout=args.timeout,
                    threads=args.threads,
                    interval=args.interval,
                    auto_discover=args.hosts is None,
                )
                monitor.watch()
            elif args.monitor_type == "ports":
                target: Target = args.target or parse_target(network.get_ip_address())
                watcher = PortWatcher(
                    verbose=args.verbose,
                    ip=target.ip,
                    port_begin=target.port_begin,
                    port_end=target.port_end,
                    timeout=args.timeout,
                    threads=args.threads,
                    interval=args.interval,
                )
                watcher.watch()
            elif args.monitor_type == "traffic":
                sniffer = TrafficSniffer(verbose=args.verbose, bpf_filter=args.filter)
                sniffer.sniff()

        elif args.scan_method == "graph":
            grapher = NetworkGraph(
                verbose=args.verbose,
                timeout=args.timeout,
                threads=args.threads,
                fingerprint=args.fingerprint,
                output=args.output,
            )
            grapher.run()

        elif args.scan_method == "trace":
            print(f"Tracing route to {args.target}, max {args.max_hops} hops\n")

            _ip_col = 45 if network.is_ipv6_address(args.target) else 18

            def _fmt_hop(hop: "Hop") -> str:
                if hop.ip is None:
                    return f"{hop.ttl:>3}  *"
                return f"{hop.ttl:>3}  {hop.ip:<{_ip_col}} {hop.rtt_ms:.2f} ms"

            on_hop = None if args.json else lambda h: print(_fmt_hop(h))
            scanner = Traceroute(
                verbose=args.verbose,
                ip=args.target,
                timeout=args.timeout,
                max_hops=args.max_hops,
                on_hop=on_hop,
            )
            scanner.scan()

            if args.json:
                print(json.dumps({"target": args.target, "hops": [
                    {"ttl": h.ttl, "ip": h.ip, "rtt_ms": h.rtt_ms}
                    for h in scanner.get_results()
                ]}))

        elif args.scan_method == "tls":
            ip, ports = _parse_tls_target(args.target)
            port_label = ",".join(str(p) for p in ports)
            print(f"Probing TLS on {ip}:{port_label} ...")
            prober = TlsProber(ip=ip, ports=ports, timeout=args.timeout)
            prober.scan()
            results = prober.get_results()

            if not results:
                print("No TLS certificates found.")
            elif args.json:
                print(json.dumps({"certs": [
                    {
                        "ip": c.ip,
                        "port": c.port,
                        **({"cn": c.cn} if c.cn else {}),
                        **({"issuer": c.issuer} if c.issuer else {}),
                        "not_before": c.not_before,
                        "not_after": c.not_after,
                        "san": list(c.san),
                        "expired": c.expired,
                        "self_signed": c.self_signed,
                    }
                    for c in results
                ]}))
            else:
                for cert in results:
                    print(f"\nPort:        {cert.port}")
                    if cert.cn:
                        print(f"CN:          {cert.cn}")
                    if cert.issuer:
                        print(f"Issuer:      {cert.issuer}")
                    print(f"Valid from:  {cert.not_before}")
                    print(f"Valid to:    {cert.not_after}")
                    print(f"Expired:     {'Yes' if cert.expired else 'No'}")
                    print(f"Self-signed: {'Yes' if cert.self_signed else 'No'}")
                    if cert.san:
                        print(f"SANs:        {', '.join(cert.san)}")

        elif args.scan_method == "mdns":
            print(f"Browsing mDNS services for {args.timeout}s ...", end=" ", flush=True)
            scanner = Mdns(verbose=args.verbose, timeout=args.timeout)
            scanner.scan()
            print("done")
            results = scanner.get_results()

            if args.json:
                print(json.dumps({"services": [
                    {"hostname": r.hostname, "ip": r.ip, "service": r.service, "port": r.port}
                    for r in results
                ]}))
            else:
                if not results:
                    print("No mDNS services found.")
                else:
                    host_col    = max((len(r.hostname) for r in results), default=8) + 2
                    ip_col      = max((len(r.ip) for r in results), default=2) + 2
                    service_col = max((len(r.service) for r in results), default=7) + 2
                    print("HOSTNAME".ljust(host_col) + "IP".ljust(ip_col) + "SERVICE".ljust(service_col) + "PORT")
                    for r in results:
                        print(f"{r.hostname.ljust(host_col)}{r.ip.ljust(ip_col)}{r.service.ljust(service_col)}{r.port}")

    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
