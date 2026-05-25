#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import threading
from queue import Queue
from scapy.all import IP, UDP, ICMP, sr1
from netscan.models import Port
from netscan.utils.system_utils import warm_arp_cache


class Udp:
    """Scans UDP ports on a target host."""

    def __init__(self, verbose: bool, ip: str, port_begin: int, port_end: int, timeout: int, threads: int, retries: int) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.ip = ip
        self.threads = threads
        self.port_begin = port_begin
        self.port_end = port_end
        self.retries = retries

        self._lock = threading.Lock()
        self.q: Queue[int] = Queue()

        self.open_ports: list[Port] = []
        self._done = 0
        self._total = port_end - port_begin + 1

    def check_port(self, target_port: int) -> None:
        """Probes a UDP port; records it unless ICMP port-unreachable is received."""
        for attempt in range(self.retries + 1):
            rsp = sr1(
                IP(dst=self.ip) / UDP(dport=target_port),
                timeout=self.timeout,
                verbose=self.verbose,
                promisc=False
            )

            if rsp is None:
                if attempt == self.retries:
                    with self._lock:
                        self.open_ports.append(Port(ip=self.ip, port=target_port))
                continue

            if rsp.haslayer(ICMP):
                icmp = rsp.getlayer(ICMP)
                if icmp.type == 3 and icmp.code == 3:
                    return  # port unreachable — closed

            with self._lock:
                self.open_ports.append(Port(ip=self.ip, port=target_port))
            return

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
        """Runs the threaded UDP scan."""
        warm_arp_cache(self.ip)
        thread_count = min(self.threads, self._total)
        for _ in range(thread_count):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()

        for curr in range(self.port_begin, self.port_end + 1):
            self.q.put(curr)

        self.q.join()
        print()

    def get_results(self) -> list[Port]:
        """Returns open|filtered ports discovered by scan()."""
        return self.open_ports
