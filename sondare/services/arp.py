#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from scapy.all import ARP, srp, Ether
from sondare.models import Host
from sondare.utils.network import get_subnet, get_network_interface, resolve_hostnames


class Arp:
    """Discovers hosts on the local network via ARP broadcast."""

    def __init__(self, verbose: bool, timeout: int, resolve_hostname: bool = False) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.resolve_hostname = resolve_hostname
        self._answer = None

    def scan(self) -> None:
        """Sends ARP broadcast and records responses."""
        cidr = get_subnet()
        iface = get_network_interface()
        print(f"Scanning {cidr} ...", end=" ", flush=True)
        arp = ARP(pdst=cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        self._answer = srp(ether/arp, iface=iface, timeout=self.timeout, verbose=self.verbose, promisc=False)[0]
        print("done")

    def get_results(self) -> list[Host]:
        """Returns a Host(ip, mac[, hostname]) for each responding host."""
        if self._answer is None:
            return []
        hosts = [Host(ip=rcv.psrc, mac=rcv.hwsrc) for _, rcv in self._answer]
        if self.resolve_hostname:
            names = resolve_hostnames([h.ip for h in hosts])
            hosts = [Host(ip=h.ip, mac=h.mac, hostname=names[h.ip]) for h in hosts]
        return hosts
