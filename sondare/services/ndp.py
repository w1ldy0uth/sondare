#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from scapy.all import Ether, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, srp
from sondare.models import Host
from sondare.utils.network import (
    get_network_interface, get_mac_vendor, get_ipv6_link_local,
    read_ndp_cache, resolve_hostnames,
)

# Ethernet and IPv6 all-nodes multicast addresses (RFC 4291 §2.7.1).
_ALL_NODES_MAC  = "33:33:00:00:00:01"
_ALL_NODES_ADDR = "ff02::1"


class Ndp:
    """Discovers IPv6 hosts on the local link via ICMPv6 multicast ping + NDP neighbor cache."""

    def __init__(self, verbose: bool, timeout: int, resolve_hostname: bool = False) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.resolve_hostname = resolve_hostname
        self._results: list[Host] = []

    def scan(self) -> None:
        """Sends an ICMPv6 echo request to ff02::1, merges with the NDP neighbor cache,
        and stores the final host list. Active replies take precedence over cache entries.
        The scanner's own link-local address and multicast prefixes are excluded.
        """
        iface    = get_network_interface()
        local_ip = (get_ipv6_link_local(iface) or "").lower()

        pkt = (
            Ether(dst=_ALL_NODES_MAC) /
            IPv6(dst=_ALL_NODES_ADDR) /
            ICMPv6EchoRequest(id=0x5afe, seq=1)
        )
        print(f"Scanning {_ALL_NODES_ADDR} on {iface} ...", end=" ", flush=True)
        answer = srp(
            pkt,
            iface=iface,
            timeout=self.timeout,
            verbose=self.verbose,
            promisc=False,
            multi=True,
        )[0]
        print("done")

        hosts: dict[str, str] = {}  # normalized_ipv6 -> mac

        for _, rcv in answer:
            if not rcv.haslayer(ICMPv6EchoReply):
                continue
            ip  = rcv[IPv6].src.split("%")[0].lower()
            mac = rcv[Ether].src.lower()
            if ip != local_ip and not ip.startswith("ff"):
                hosts[ip] = mac

        for ip, mac in read_ndp_cache(iface).items():
            if ip not in hosts and ip != local_ip and not ip.startswith("ff"):
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
