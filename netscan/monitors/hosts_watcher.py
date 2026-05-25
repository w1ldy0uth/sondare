#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import threading
import time
from datetime import datetime
from scapy.all import IP, ICMP, ARP, Ether, sr1, srp
from netscan.utils.system_utils import get_subnet, get_network_interface


def _arp_scan(timeout: int, verbose: bool) -> list[str]:
    """ARP-scans the local subnet and returns a sorted list of live IPs."""
    cidr = get_subnet()
    iface = get_network_interface()
    ans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
        iface=iface,
        timeout=timeout,
        verbose=verbose,
        promisc=False,
    )[0]
    return sorted(rcv.psrc for _, rcv in ans)


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

    def _ping(self, host: str) -> bool:
        ans = sr1(
            IP(dst=host) / ICMP(),
            timeout=self._timeout,
            verbose=self._verbose,
            promisc=False,
        )
        return bool(ans and ans.haslayer(ICMP) and ans.getlayer(ICMP).type == 0)

    def _round(self) -> dict[str, bool]:
        results: dict[str, bool] = {}
        lock = threading.Lock()
        sem = threading.Semaphore(self._threads)

        def probe(host: str) -> None:
            try:
                up = self._ping(host)
            finally:
                sem.release()
            with lock:
                results[host] = up

        threads = []
        for host in self._hosts:
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
        lines = [
            f"Host monitor — updated {ts}, interval {self._interval}s (Ctrl+C to stop)",
            "",
            f"  {'IP':<16}{'Status':<6}  Since",
            f"  {'─' * 16}{'─' * 6}  {'─' * 8}",
        ]
        if self._state:
            for ip in sorted(self._state):
                is_up, since = self._state[ip]
                status = "UP  " if is_up else "DOWN"
                lines.append(f"  {ip:<16}{status}  {since}")
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
