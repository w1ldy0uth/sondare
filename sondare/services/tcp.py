#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import Port
from sondare.utils.banners import grab_banner
from sondare.utils.network import (
    get_port_service, is_ipv6_address, get_network_interface,
)


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

        self._open_ports: list[Port] = []
        self._results: list[Port] = []

    def scan(self) -> None:
        if self._ipv6:
            self._scan_ipv6()
        else:
            self._scan_ipv4()

    def _scan_ipv4(self) -> None:
        self._scan_rust(_sondare.tcp_syn_scan_v4)

    def _scan_ipv6(self) -> None:
        self._scan_rust(_sondare.tcp_syn_scan_v6)

    def _scan_rust(self, scan_fn) -> None:
        iface = get_network_interface()
        ports = list(range(self.port_begin, self.port_end + 1))
        pps = self.threads * 25
        grace_ms = max(200, int(self._timeout * 1000))
        total = len(ports)
        print(f"\rScanning {total} port(s) on {self.ip} ...", end="", flush=True)
        open_port_nums = scan_fn(iface, self.ip, ports, pps, grace_ms, self.retries)
        print(f"\rScanning {total} port(s) on {self.ip} ... done")
        self._open_ports = [Port(ip=self.ip, port=p) for p in open_port_nums]
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
