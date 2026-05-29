#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import signal
import time
from collections.abc import Callable
from scapy.all import IP, ICMP, sr1
from sondare.models import Hop


class Traceroute:
    """Traces the network path to a target host using ICMP echo probes."""

    def __init__(
        self,
        verbose: bool,
        ip: str,
        timeout: float = 3.0,
        max_hops: int = 30,
        on_hop: Callable[[Hop], None] | None = None,
    ) -> None:
        self.verbose = verbose
        self.ip = ip
        self._timeout = timeout
        self._max_hops = max_hops
        self._on_hop = on_hop
        self._results: list[Hop] = []
        self._interrupted = False

    def _probe(self, ttl: int) -> Hop:
        pkt = IP(dst=self.ip, ttl=ttl) / ICMP()
        t0 = time.perf_counter()
        reply = sr1(pkt, timeout=self._timeout, verbose=self.verbose, promisc=False)
        rtt = round((time.perf_counter() - t0) * 1000, 2)
        if reply is None:
            return Hop(ttl=ttl, ip=None, rtt_ms=None)
        return Hop(ttl=ttl, ip=reply.src, rtt_ms=rtt)

    def scan(self) -> None:
        self._interrupted = False

        def _handler(_signum: int, _frame: object) -> None:
            self._interrupted = True
            raise KeyboardInterrupt

        old = signal.signal(signal.SIGINT, _handler)
        try:
            for ttl in range(1, self._max_hops + 1):
                if self._interrupted:
                    break
                hop = self._probe(ttl)
                self._results.append(hop)
                if self._on_hop:
                    self._on_hop(hop)
                if hop.ip == self.ip:
                    break
        finally:
            signal.signal(signal.SIGINT, old)

        if self._interrupted:
            raise KeyboardInterrupt

    def get_results(self) -> list[Hop]:
        return self._results
