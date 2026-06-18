#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from collections.abc import Callable
from sondare import _sondare
from sondare.models import Hop
from sondare.utils.network import is_ipv6_address, get_network_interface


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
        self._ipv6 = is_ipv6_address(ip)
        self._results: list[Hop] = []

    def scan(self) -> None:
        if self._ipv6:
            self._scan_ipv6()
        else:
            self._scan_ipv4()

    def _scan_ipv4(self) -> None:
        iface = get_network_interface()
        timeout_ms = int(self._timeout * 1000)
        raw_hops = _sondare.traceroute_v4(iface, self.ip, self._max_hops, timeout_ms)
        self._replay_hops(raw_hops)

    def _scan_ipv6(self) -> None:
        iface = get_network_interface()
        timeout_ms = int(self._timeout * 1000)
        raw_hops = _sondare.traceroute_v6(iface, self.ip, self._max_hops, timeout_ms)
        self._replay_hops(raw_hops)

    def _replay_hops(self, raw_hops: list) -> None:
        for ttl, ip, rtt_ms in raw_hops:
            hop = Hop(ttl=ttl, ip=ip, rtt_ms=rtt_ms)
            self._results.append(hop)
            if self._on_hop:
                self._on_hop(hop)

    def get_results(self) -> list[Hop]:
        return self._results
