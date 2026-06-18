#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import Port
from sondare.utils.network import (
    warm_arp_cache, get_port_service, is_ipv6_address, get_network_interface,
)


class Udp:
    """Scans UDP ports on a target host."""

    def __init__(self, verbose: bool, ip: str, port_begin: int, port_end: int, timeout: float, threads: int, retries: int) -> None:
        self.verbose = verbose
        self.ip = ip
        self.threads = threads
        self.port_begin = port_begin
        self.port_end = port_end
        self.retries = retries
        self._timeout = timeout

        self._ipv6 = is_ipv6_address(ip)
        self._results: list[Port] = []

    def scan(self) -> None:
        if self._ipv6:
            self._scan_ipv6()
        else:
            self._scan_ipv4()

    def _scan_ipv4(self) -> None:
        warm_arp_cache(self.ip)
        iface = get_network_interface()
        ports = list(range(self.port_begin, self.port_end + 1))
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        open_port_nums = _sondare.udp_scan_v4(iface, self.ip, ports, 500, grace_ms)
        self._results = [
            Port(ip=self.ip, port=p, service=get_port_service(p, "udp"))
            for p in sorted(open_port_nums)
        ]

    def _scan_ipv6(self) -> None:
        iface = get_network_interface()
        ports = list(range(self.port_begin, self.port_end + 1))
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        open_port_nums = _sondare.udp_scan_v6(iface, self.ip, ports, 500, grace_ms)
        self._results = [
            Port(ip=self.ip, port=p, service=get_port_service(p, "udp"))
            for p in sorted(open_port_nums)
        ]

    def get_results(self) -> list[Port]:
        return self._results
