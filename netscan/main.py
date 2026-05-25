#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import logging
import re
import sys
from typing import NamedTuple

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import netscan.utils.system_utils as system_utils
from netscan.services.arp import Arp
from netscan.services.icmp import Ping
from netscan.services.tcp import Port


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
    parser = argparse.ArgumentParser(
        prog="netScan",
        description="Manage local network hosts' information.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
    sudo netscan arp [-t TIMEOUT] [-v]
    sudo netscan ping [-t TIMEOUT] [-th THREADS] [-v]
    sudo netscan tcp [--target IP[:START-END]] [-t TIMEOUT] [-th THREADS] [-r RETRIES] [-v]
        """
    )

    subparsers = parser.add_subparsers(title="SCAN METHODS", dest="scan_method")

    # ARP scan
    arp_parser = subparsers.add_parser("arp", help="Scan local network with ARP packets.")
    arp_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    arp_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for scan response")

    # Ping scan
    ping_parser = subparsers.add_parser("ping", help="Ping all hosts in local network with ICMP packets.")
    ping_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    ping_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for scan response")
    ping_parser.add_argument("-th", "--threads", type=int, default=100, help="Amount of threads to use")

    # TCP scan
    tcp_parser = subparsers.add_parser("tcp", help="Scan ports of target host with TCP packets.")
    tcp_parser.add_argument("--target", type=parse_target, default=None, help="Target in the form ip, ip:port, or ip:start-end (default: local machine, ports 1-1000)")
    tcp_parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for port scan (default: 3)")
    tcp_parser.add_argument("-th", "--threads", type=int, default=20, help="Amount of threads to use")
    tcp_parser.add_argument("-r", "--retries", type=int, default=2, help="Retries per port on no response (default: 2)")
    tcp_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

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

            print("IP".ljust(15) + "MAC")
            for host in results:
                print(f"{host.ip.ljust(15)}{host.mac}")

        elif args.scan_method == "ping":
            print(f"Running ICMP scan with {args.timeout} seconds timeout and {args.threads} {'thread' if args.threads == 1 else 'threads'}")
            scanner = Ping(verbose=args.verbose, timeout=args.timeout, threads=args.threads)
            scanner.scan()
            results = scanner.get_results()
            for host in results:
                print(f"{host} is alive")

        elif args.scan_method == "tcp":
            target: Target = args.target or parse_target(system_utils.get_ip_address())
            print(f"Running TCP scan for {target.ip}:{target.port_begin}-{target.port_end} with {args.timeout}s timeout, {args.threads} {'thread' if args.threads == 1 else 'threads'}, {args.retries} retr{'y' if args.retries == 1 else 'ies'}")
            scanner = Port(
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

            print(f"Open ports: {len(results)}\n_______________________")
            for port in results:
                print(f"{port} is open")

    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
