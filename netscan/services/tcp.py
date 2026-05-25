#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import threading
import random
from queue import Queue
from scapy.all import IP, TCP, sr1, sr


class Port:
    """Scans TCP ports on a target host using SYN packets."""

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

        self.open_ports: list[str] = []
        self._done = 0
        self._total = port_end - port_begin + 1

    def check_port(self, target_port: int) -> None:
        """Probes a port up to retries+1 times; records it if any attempt gets a SYN-ACK."""
        for _ in range(self.retries + 1):
            source_port = random.randint(1025, 65534)
            rsp = sr1(
                IP(dst=self.ip) / TCP(sport=source_port, dport=target_port, flags="S"),
                timeout=self.timeout,
                verbose=self.verbose,
                promisc=False
            )

            if rsp is None:
                continue  # no response — retry

            if rsp.haslayer(TCP):
                if rsp.getlayer(TCP).flags == 0x12:  # SYN-ACK: open
                    sr(IP(dst=self.ip) / TCP(sport=source_port, dport=target_port, flags="R"), timeout=1, verbose=False, promisc=False)
                    with self._lock:
                        self.open_ports.append(self.ip + ":" + str(target_port))
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
        """Runs the threaded SYN scan."""
        thread_count = min(self.threads, self._total)
        for _ in range(thread_count):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()

        for curr in range(self.port_begin, self.port_end + 1):
            self.q.put(curr)

        self.q.join()
        print()

    def get_results(self) -> list[str]:
        """Returns open ports as 'ip:port' strings discovered by scan()."""
        return self.open_ports
