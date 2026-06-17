#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import random
import threading
import time
from queue import Queue
from scapy.all import IP, IPv6, TCP, sr1, sr
from sondare import _sondare
from sondare.models import Port
from sondare.utils.banners import grab_banner
from sondare.utils.network import (
    warm_arp_cache, get_port_service, is_ipv6_address, get_network_interface,
)
from sondare.utils.adaptive_pool import AdaptivePool


class Tcp:
    """Scans TCP ports on a target host using SYN packets."""

    def __init__(self, verbose: bool, ip: str, port_begin: int, port_end: int, timeout: float, threads: int, retries: int, banners: bool = False) -> None:
        self.verbose = verbose
        self.ip = ip
        self.threads = threads
        self.port_begin = port_begin
        self.port_end = port_end
        self.retries = retries
        self.banners = banners
        self._timeout = timeout

        self._ipv6 = is_ipv6_address(ip)
        self._pool = AdaptivePool(max_threads=threads, timeout=timeout, adapt_concurrency=True)
        self._lock = threading.Lock()
        self.q: Queue[int] = Queue()

        self._open_ports: list[Port] = []
        self._results: list[Port] = []
        self._done = 0
        self._total = port_end - port_begin + 1

    def check_port(self, target_port: int) -> None:
        """Probes a port up to retries+1 times; records it if any attempt gets a SYN-ACK."""
        ip_layer = IPv6(dst=self.ip) if self._ipv6 else IP(dst=self.ip)
        for _ in range(self.retries + 1):
            source_port = random.randint(1025, 65534)
            self._pool.acquire()
            try:
                start = time.monotonic()
                rsp = sr1(
                    ip_layer / TCP(sport=source_port, dport=target_port, flags="S"),
                    timeout=self._pool.timeout,
                    verbose=self.verbose,
                    promisc=False,
                )
            finally:
                self._pool.release()

            elapsed = time.monotonic() - start
            self._pool.record(is_timeout=(rsp is None), rtt=elapsed if rsp is not None else None)

            if rsp is None:
                continue

            if rsp.haslayer(TCP):
                if rsp.getlayer(TCP).flags == 0x12:  # SYN-ACK: open
                    sr(ip_layer / TCP(sport=source_port, dport=target_port, flags="R"), timeout=1, verbose=False, promisc=False)
                    with self._lock:
                        self._open_ports.append(Port(ip=self.ip, port=target_port))
                return  # RST or anything else: definitive answer, stop retrying

    def _threader(self) -> None:
        """Worker: pulls ports from the queue and checks them."""
        while True:
            current = self.q.get()
            self.check_port(current)
            with self._lock:
                self._done += 1
                done, total = self._done, self._total
            print(f"\rProgress: {done}/{total} ports", end="", flush=True)
            self.q.task_done()

    def scan(self) -> None:
        """Runs the SYN scan."""
        if self._ipv6:
            self._scan_ipv6()
        else:
            self._scan_ipv4()

    def _scan_ipv4(self) -> None:
        warm_arp_cache(self.ip)
        iface = get_network_interface()
        ports = list(range(self.port_begin, self.port_end + 1))
        pps = 500
        grace_ms = 500  # LAN-only (MAC resolved via ARP); 500ms >> worst-case LAN RTT
        open_port_nums = _sondare.tcp_syn_scan_v4(iface, self.ip, ports, pps, grace_ms)
        self._open_ports = [Port(ip=self.ip, port=p) for p in open_port_nums]
        self._finalise()

    def _scan_ipv6(self) -> None:
        thread_count = min(self.threads, self._total)
        for _ in range(thread_count):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        for curr in range(self.port_begin, self.port_end + 1):
            self.q.put(curr)
        self.q.join()
        print()
        self._finalise()

    def _finalise(self) -> None:
        if self.banners:
            self._open_ports = [
                Port(ip=p.ip, port=p.port, banner=grab_banner(p.ip, p.port, self._timeout))
                for p in self._open_ports
            ]
        self._results = [
            Port(ip=p.ip, port=p.port, banner=p.banner, service=get_port_service(p.port))
            for p in sorted(self._open_ports, key=lambda p: p.port)
        ]

    def get_results(self) -> list[Port]:
        return self._results
