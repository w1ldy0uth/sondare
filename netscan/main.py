#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import json
import logging
import re
import sys
from typing import NamedTuple

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import netscan.utils.system_utils as system_utils
from netscan.services.arp import Arp
from netscan.services.icmp import Ping
from netscan.services.tcp import Tcp
from netscan.services.udp import Udp
from netscan.services.fingerprint import OsFingerprinter


class Target(NamedTuple):
    ip: str
    port_begin: int
    port_end: int


_TARGET_RE = re.compile(r"([^:]+)(?::(\d+)(?:-(\d+))?)?")


def parse_target(value: str) -> Target:
    """Parses 'ip', 'ip:port', or 'ip:start-end' into a Target."""
    match = _TARGET_RE.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError(f"Invalid target format: '{value}'. Expected ip, ip:port, or ip:start-end.")
    ip = match.group(1)
    if match.group(2) is None:
        return Target(ip, 1, 1000)
    start = int(match.group(2))
    end = int(match.group(3)) if match.group(3) else start
    if start > end:
        raise argparse.ArgumentTypeError(f"Start port {start} must be <= end port {end}.")
    if end > 65535:
        raise argparse.ArgumentTypeError(f"Port {end} out of range (0-65535).")
    return Target(ip, start, end)


def parse_args() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--json", action="store_true", help="Output results as JSON")

    parser = argparse.ArgumentParser(
        prog="netScan",
        description="Manage local network hosts' information.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
    sudo netscan arp [-t TIMEOUT] [-v] [--json]
    sudo netscan ping [-t TIMEOUT] [-th THREADS] [-v] [--json]
    sudo netscan tcp [--target IP[:START-END]] [-t TIMEOUT] [-th THREADS] [-r RETRIES] [-v] [--json]
    sudo netscan udp [--target IP[:START-END]] [-t TIMEOUT] [-th THREADS] [-r RETRIES] [-v] [--json]
    sudo netscan os --target IP [--port PORT] [-t TIMEOUT] [-v] [--json]
        """
    )

    subparsers = parser.add_subparsers(title="SCAN METHODS", dest="scan_method")

    # ARP scan
    arp_parser = subparsers.add_parser("arp", parents=[shared], help="Scan local network with ARP packets.")
    arp_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    arp_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for scan response")

    # Ping scan
    ping_parser = subparsers.add_parser("ping", parents=[shared], help="Ping all hosts in local network with ICMP packets.")
    ping_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    ping_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for scan response")
    ping_parser.add_argument("-th", "--threads", type=int, default=100, help="Amount of threads to use")

    # TCP scan
    tcp_parser = subparsers.add_parser("tcp", parents=[shared], help="Scan ports of target host with TCP packets.")
    tcp_parser.add_argument("--target", type=parse_target, default=None, help="Target in the form ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)")
    tcp_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for port scan (default: 3)")
    tcp_parser.add_argument("-th", "--threads", type=int, default=20, help="Amount of threads to use")
    tcp_parser.add_argument("-r", "--retries", type=int, default=2, help="Retries per port on no response (default: 2)")
    tcp_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    # OS fingerprint
    os_parser = subparsers.add_parser("os", parents=[shared], help="Guess the OS of a target host via TCP SYN-ACK analysis.")
    os_parser.add_argument("--target", required=True, help="Target IP address")
    os_parser.add_argument("--port", type=int, default=None, help="Port to probe (default: auto-tries common ports)")
    os_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout per probe in seconds (default: 3)")
    os_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    # UDP scan
    udp_parser = subparsers.add_parser("udp", parents=[shared], help="Scan ports of target host with UDP packets.")
    udp_parser.add_argument("--target", type=parse_target, default=None, help="Target in the form ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)")
    udp_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for port scan (default: 3)")
    udp_parser.add_argument("-th", "--threads", type=int, default=20, help="Amount of threads to use")
    udp_parser.add_argument("-r", "--retries", type=int, default=2, help="Retries per port on no response (default: 2)")
    udp_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    return parser


def main() -> None:
    """Entry point: parses CLI arguments and dispatches to the appropriate scanner."""
    if not system_utils.is_running_as_root():
        print("Access denied. Run this program as root.")
        sys.exit(1)

    parser = parse_args()
    args = parser.parse_args()

    if args.scan_method is None:
        parser.print_help()
        return

    try:
        if args.scan_method == "arp":
            print(f"Running ARP scan with {args.timeout} seconds timeout")
            scanner = Arp(verbose=args.verbose, timeout=args.timeout)
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                print(json.dumps({"hosts": [{"ip": h.ip, "mac": h.mac} for h in results]}))
            else:
                print("IP".ljust(15) + "MAC")
                for host in results:
                    print(f"{host.ip.ljust(15)}{host.mac}")

        elif args.scan_method == "ping":
            print(f"Running ICMP scan with {args.timeout} seconds timeout and {args.threads} {'thread' if args.threads == 1 else 'threads'}")
            scanner = Ping(verbose=args.verbose, timeout=args.timeout, threads=args.threads)
            scanner.scan()
            results = scanner.get_results()

            if args.json:
                print(json.dumps({"hosts": results}))
            else:
                for host in results:
                    print(f"{host} is alive")

        elif args.scan_method == "tcp":
            target: Target = args.target or parse_target(system_utils.get_ip_address())
            port_range = str(target.port_begin) if target.port_begin == target.port_end else f"{target.port_begin}-{target.port_end}"
            print(f"Running TCP scan for {target.ip}:{port_range} with {args.timeout}s timeout, {args.threads} {'thread' if args.threads == 1 else 'threads'}, {args.retries} retr{'y' if args.retries == 1 else 'ies'}")
            scanner = Tcp(
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
                print(json.dumps({"host": target.ip, "ports": [p.port for p in results]}))
            else:
                print(f"Open ports: {len(results)}\n_______________________")
                for port in results:
                    print(f"{port.ip}:{port.port} is open")

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
                print("No SYN-ACK received — could not fingerprint host.")
            elif args.json:
                print(json.dumps({"ip": result.ip, "os": result.os, "ttl": result.ttl, "window": result.window}))
            else:
                print(f"IP:     {result.ip}")
                print(f"OS:     {result.os}")
                print(f"TTL:    {result.ttl}")
                print(f"Window: {result.window}")

        elif args.scan_method == "udp":
            target: Target = args.target or parse_target(system_utils.get_ip_address())
            port_range = str(target.port_begin) if target.port_begin == target.port_end else f"{target.port_begin}-{target.port_end}"
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
                print(json.dumps({"host": target.ip, "ports": [p.port for p in results]}))
            else:
                print(f"Open|filtered ports: {len(results)}\n_______________________")
                for port in results:
                    print(f"{port.ip}:{port.port} is open|filtered")

    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
