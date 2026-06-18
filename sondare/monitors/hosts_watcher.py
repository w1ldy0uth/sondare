#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import threading
import time
from datetime import datetime
from scapy.all import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, sr1
from sondare import _sondare
from sondare.utils.network import get_subnet, get_network_interface, is_ipv6_address


def _arp_scan(timeout: int, verbose: bool) -> list[str]:
    """ARP-scans the local subnet and returns a sorted list of live IPs."""
    cidr = get_subnet()
    iface = get_network_interface()
    grace_ms = max(200, timeout * 500)
    pairs = _sondare.arp_sweep_v4(iface, cidr, 500, grace_ms)
    return sorted(ip for ip, _mac in pairs)


class HostsWatcher:
    """
    Periodically pings a set of hosts and displays a live status table.

    The table redraws in place after every round — no streaming log lines.
    Each row shows the host IP, current status, and the time the status
    last changed.

    When auto_discover=True the host list is refreshed via ARP before every
    round; new hosts appear in the table, departed hosts are removed.
    When auto_discover=False the host list is fixed for the session.
    """

    def __init__(
        self,
        verbose: bool,
        hosts: list[str],
        timeout: float,
        threads: int,
        interval: int,
        auto_discover: bool = False,
        arp_timeout: int = 5,
    ) -> None:
        self._verbose = verbose
        self._hosts = list(hosts)
        self._timeout = timeout
        self._threads = threads
        self._interval = interval
        self._auto_discover = auto_discover
        self._arp_timeout = arp_timeout
        self._state: dict[str, tuple[bool, str]] = {}  # ip -> (is_up, since)
        self._last_line_count = 0

    def _ping_ipv6(self, host: str) -> bool:
        ans = sr1(
            IPv6(dst=host) / ICMPv6EchoRequest(),
            timeout=self._timeout,
            verbose=self._verbose,
            promisc=False,
        )
        return bool(ans and ans.haslayer(ICMPv6EchoReply))

    def _round(self) -> dict[str, bool]:
        ipv4_hosts = [h for h in self._hosts if not is_ipv6_address(h)]
        ipv6_hosts = [h for h in self._hosts if is_ipv6_address(h)]

        results: dict[str, bool] = {}

        if ipv4_hosts:
            iface = get_network_interface()
            grace_ms = max(200, int(self._timeout * 1000 // 2))
            alive = set(_sondare.icmp_sweep_v4(iface, ipv4_hosts, 500, grace_ms))
            for h in ipv4_hosts:
                results[h] = h in alive

        if ipv6_hosts:
            lock = threading.Lock()
            sem = threading.Semaphore(self._threads)

            def probe(host: str) -> None:
                try:
                    up = self._ping_ipv6(host)
                finally:
                    sem.release()
                with lock:
                    results[host] = up

            threads = []
            for host in ipv6_hosts:
                sem.acquire()
                t = threading.Thread(target=probe, args=(host,), daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join()

        return results

    def _refresh_hosts(self) -> None:
        """Re-ARPs and updates _hosts; removes departed hosts from state."""
        fresh = set(_arp_scan(self._arp_timeout, self._verbose))
        for ip in set(self._hosts) - fresh:
            self._state.pop(ip, None)
        self._hosts = sorted(fresh)

    def _clear_last(self) -> None:
        if self._last_line_count:
            print(f"\033[{self._last_line_count}A\033[J", end="", flush=True)

    def _draw(self, ts: str) -> None:
        ip_w = max((len(ip) for ip in self._state), default=14) + 2
        ip_w = max(ip_w, 4)  # at least wide enough for "IP" header
        lines = [
            f"Host monitor — updated {ts}, interval {self._interval}s (Ctrl+C to stop)",
            "",
            f"  {'IP':<{ip_w}}{'Status':<6}  Since",
            f"  {'─' * ip_w}{'─' * 6}  {'─' * 8}",
        ]
        if self._state:
            for ip in sorted(self._state):
                is_up, since = self._state[ip]
                status = "UP  " if is_up else "DOWN"
                lines.append(f"  {ip:<{ip_w}}{status}  {since}")
        else:
            lines.append("  (no hosts found)")
        print("\n".join(lines), flush=True)
        self._last_line_count = len(lines)

    def watch(self) -> None:
        while True:
            if self._auto_discover:
                self._refresh_hosts()

            new_results = self._round()
            ts = datetime.now().strftime("%H:%M:%S")

            for ip, is_up in new_results.items():
                prev = self._state.get(ip)
                if prev is None or prev[0] != is_up:
                    self._state[ip] = (is_up, ts)

            self._clear_last()
            self._draw(ts)
            time.sleep(self._interval)
