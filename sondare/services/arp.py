#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import Host
from sondare.utils.network import get_subnet, get_network_interface, get_mac_vendor, read_arp_cache, resolve_hostnames


class Arp:
    """Discovers hosts on the local network via ARP broadcast."""

    def __init__(self, verbose: bool, timeout: float, resolve_hostname: bool = False) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.resolve_hostname = resolve_hostname
        self._results: list[Host] = []

    def scan(self) -> None:
        """Sends ARP broadcast, merges the OS ARP cache, resolves hostnames and vendor names."""
        cidr = get_subnet()
        iface = get_network_interface()
        print(f"Scanning {cidr} on {iface} ...", end=" ", flush=True)
        grace_ms = max(200, int(self.timeout * 1000 // 2))
        active = _sondare.arp_sweep_v4(iface, cidr, 500, grace_ms)
        print("done")

        hosts = [Host(ip=ip, mac=mac) for ip, mac in active]
        seen = {h.ip for h in hosts}
        for ip, mac in read_arp_cache(cidr).items():
            if ip not in seen:
                hosts.append(Host(ip=ip, mac=mac))

        if self.resolve_hostname:
            names = resolve_hostnames([h.ip for h in hosts])
            self._results = [Host(ip=h.ip, mac=h.mac, hostname=names[h.ip], vendor=get_mac_vendor(h.mac)) for h in hosts]
        else:
            self._results = [Host(ip=h.ip, mac=h.mac, vendor=get_mac_vendor(h.mac)) for h in hosts]

    def get_results(self) -> list[Host]:
        return self._results
