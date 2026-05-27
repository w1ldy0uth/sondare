#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import ipaddress
from scapy.all import IP, ICMP, sr
from sondare.utils.network import get_subnet, resolve_hostnames


class Ping:
    """Discovers live hosts on the local network via ICMP echo."""

    def __init__(self, verbose: bool, timeout: float, resolve_hostname: bool = False) -> None:
        self.verbose = verbose
        self._timeout = timeout
        self._resolve_hostname = resolve_hostname

        self.hosts = [str(ip) for ip in ipaddress.IPv4Network(get_subnet()).hosts()]
        self.results: list[str] = []
        self._hostnames: dict[str, str | None] = {}

    def scan(self) -> None:
        """Sends all ICMP echo requests in one batch and collects replies."""
        print(f"Scanning {len(self.hosts)} hosts ...", end=" ", flush=True)
        packets = [IP(dst=h) / ICMP() for h in self.hosts]
        answered, _ = sr(packets, timeout=self._timeout, verbose=self.verbose, promisc=False, inter=0)
        print("done")
        for sent, received in answered:
            if received.haslayer(ICMP) and received.getlayer(ICMP).type == 0:
                self.results.append(sent[IP].dst)
        if self._resolve_hostname:
            self._hostnames = resolve_hostnames(self.results)

    def get_results(self) -> list[str]:
        """Returns IPs of live hosts discovered by scan()."""
        return self.results

    def get_hostnames(self) -> dict[str, str | None]:
        """Returns {ip: hostname} for resolved hosts. Empty if resolve_hostname was False."""
        return self._hostnames
