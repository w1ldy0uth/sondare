#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import random
import threading
import time
from datetime import datetime
from queue import Queue
from scapy.all import IPv6, TCP, sr1, sr
from sondare import _sondare
from sondare.utils.network import get_network_interface, warm_arp_cache, is_ipv6_address


def _syn_scan_ipv6(ip: str, port_begin: int, port_end: int, timeout: float, threads: int, verbose: bool) -> set[int]:
    """SYN scan for IPv6 targets via Scapy."""
    open_ports: set[int] = set()
    lock = threading.Lock()
    q: Queue[int] = Queue()

    def check(port: int) -> None:
        sport = random.randint(1025, 65534)
        rsp = sr1(
            IPv6(dst=ip) / TCP(sport=sport, dport=port, flags="S"),
            timeout=timeout,
            verbose=verbose,
            promisc=False,
        )
        if rsp and rsp.haslayer(TCP) and rsp.getlayer(TCP).flags == 0x12:
            sr(IPv6(dst=ip) / TCP(sport=sport, dport=port, flags="R"), timeout=1, verbose=False, promisc=False)
            with lock:
                open_ports.add(port)

    def worker() -> None:
        while True:
            port = q.get()
            check(port)
            q.task_done()

    total = port_end - port_begin + 1
    for _ in range(min(threads, total)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    for p in range(port_begin, port_end + 1):
        q.put(p)
    q.join()

    return open_ports


class PortWatcher:
    """
    Repeatedly SYN-scans a target's port range and reports state changes:
      OPENED — port was closed/filtered, now open
      CLOSED — port was open, now closed/filtered
    """

    def __init__(
        self,
        verbose: bool,
        ip: str,
        port_begin: int,
        port_end: int,
        timeout: float,
        threads: int,
        interval: int,
    ) -> None:
        self._verbose = verbose
        self._ip = ip
        self._port_begin = port_begin
        self._port_end = port_end
        self._timeout = timeout
        self._threads = threads
        self._interval = interval
        self._open: set[int] = set()

    def _scan(self) -> set[int]:
        if is_ipv6_address(self._ip):
            return _syn_scan_ipv6(
                ip=self._ip,
                port_begin=self._port_begin,
                port_end=self._port_end,
                timeout=self._timeout,
                threads=self._threads,
                verbose=self._verbose,
            )
        iface = get_network_interface()
        ports = list(range(self._port_begin, self._port_end + 1))
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        return set(_sondare.tcp_syn_scan_v4(iface, self._ip, ports, 500, grace_ms))

    def watch(self) -> None:
        port_range = (
            str(self._port_begin)
            if self._port_begin == self._port_end
            else f"{self._port_begin}-{self._port_end}"
        )
        print(
            f"Monitoring ports {port_range} on {self._ip}"
            f" every {self._interval}s — Ctrl+C to stop\n"
        )
        if not is_ipv6_address(self._ip):
            warm_arp_cache(self._ip)
        first = True
        while True:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] Scanning ...", end=" ", flush=True)
            new_open = self._scan()
            print("done")

            if first:
                ports_str = ", ".join(str(p) for p in sorted(new_open)) or "none"
                print(f"[{ts}] Initial state: {len(new_open)} open port(s): {ports_str}\n")
                first = False
            else:
                opened = sorted(new_open - self._open)
                closed = sorted(self._open - new_open)
                for p in opened:
                    print(f"[{ts}] OPENED  {self._ip}:{p}")
                for p in closed:
                    print(f"[{ts}] CLOSED  {self._ip}:{p}")

            self._open = new_open
            time.sleep(self._interval)
