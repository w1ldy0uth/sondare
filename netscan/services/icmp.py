#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import ipaddress
import threading
import time
from queue import Queue
from scapy.all import IP, ICMP, sr1
from netscan.utils.system_utils import get_subnet
from netscan.utils.adaptive import AdaptivePool


class Ping:
    """Discovers live hosts on the local network via ICMP echo."""

    def __init__(self, verbose: bool, timeout: float, threads: int) -> None:
        self.verbose = verbose
        self.threads = threads

        self._pool = AdaptivePool(max_threads=threads, timeout=timeout)
        self._lock = threading.Lock()
        self.q: Queue[str] = Queue()

        self.hosts = [str(ip) for ip in ipaddress.IPv4Network(get_subnet()).hosts()]
        self.results: list[str] = []
        self._done = 0
        self._total = len(self.hosts)

    def check_host(self, host: str) -> None:
        """Pings host and appends its IP to results if an echo reply is received."""
        self._pool.acquire()
        try:
            start = time.monotonic()
            ans = sr1(
                IP(dst=host) / ICMP(),
                timeout=self._pool.timeout,
                verbose=self.verbose,
                promisc=False,
            )
        finally:
            self._pool.release()

        elapsed = time.monotonic() - start
        self._pool.record(is_timeout=(ans is None), rtt=elapsed if ans is not None else None)

        with self._lock:
            if ans and ans.haslayer(ICMP) and ans.getlayer(ICMP).type == 0:
                self.results.append(host)
            self._done += 1
            done, total = self._done, self._total
        print(f"\rProgress: {done}/{total} hosts", end="", flush=True)

    def _threader(self) -> None:
        """Worker: pulls hosts from the queue and checks them."""
        while True:
            current = self.q.get()
            self.check_host(current)
            self.q.task_done()

    def scan(self) -> None:
        """Runs the threaded ICMP scan."""
        thread_count = min(self.threads, self._total)
        for _ in range(thread_count):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()

        for curr in self.hosts:
            self.q.put(curr)

        self.q.join()
        print()

    def get_results(self) -> list[str]:
        """Returns IPs of live hosts discovered by scan()."""
        return self.results
