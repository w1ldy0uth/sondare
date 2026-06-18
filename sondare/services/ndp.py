#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import Host
from sondare.utils.network import (
    get_network_interface, get_mac_vendor,
    read_ndp_cache, resolve_hostnames, IPV6_ALL_NODES_ADDR,
)


class Ndp:
    """Discovers IPv6 hosts on the local link via ICMPv6 multicast ping + NDP neighbor cache."""

    def __init__(self, verbose: bool, timeout: float, resolve_hostname: bool = False) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.resolve_hostname = resolve_hostname
        self._results: list[Host] = []

    def scan(self) -> None:
        """Sends an ICMPv6 echo request to ff02::1, merges with the NDP neighbor cache,
        and stores the final host list. Active replies take precedence over cache entries.
        The scanner's own link-local address and multicast prefixes are excluded.
        """
        iface = get_network_interface()
        grace_ms = max(200, int(self.timeout * 1000 // 2))

        print(f"Scanning {IPV6_ALL_NODES_ADDR} on {iface} ...", end=" ", flush=True)
        pairs = _sondare.ndp_sweep(iface, 500, grace_ms)
        print("done")

        hosts: dict[str, str] = {}
        for ip, mac in pairs:
            hosts[ip.lower()] = mac.lower()

        for ip, mac in read_ndp_cache(iface).items():
            if ip not in hosts and not ip.startswith("ff"):
                hosts[ip] = mac

        if self.resolve_hostname:
            names = resolve_hostnames(list(hosts))
            self._results = [
                Host(ip=ip, mac=mac, hostname=names.get(ip), vendor=get_mac_vendor(mac))
                for ip, mac in sorted(hosts.items())
            ]
        else:
            self._results = [
                Host(ip=ip, mac=mac, vendor=get_mac_vendor(mac))
                for ip, mac in sorted(hosts.items())
            ]

    def get_results(self) -> list[Host]:
        return self._results
