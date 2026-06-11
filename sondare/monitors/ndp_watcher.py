#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import threading
from datetime import datetime
from scapy.all import Ether, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NA, srp, sniff
from scapy.packet import Packet
from sondare.utils.network import (
    get_network_interface, get_ipv6_link_local, read_ndp_cache,
    IPV6_ALL_NODES_MAC, IPV6_ALL_NODES_ADDR,
)


class NdpWatcher:
    """
    Seeds known IPv6 hosts with an initial multicast echo sweep + NDP cache,
    then passively sniffs ICMPv6 Neighbor Advertisement traffic and prints
    events as they arrive:
      NEW     — first time this IPv6 address is seen
      CHANGED — same address, different MAC (potential NDP spoofing)
    """

    def __init__(self, verbose: bool, timeout: float) -> None:
        self.verbose = verbose
        self._timeout = timeout
        self._hosts: dict[str, str] = {}  # ipv6 -> mac
        self._lock = threading.Lock()
        self._iface = get_network_interface()
        self._own_ip = (get_ipv6_link_local(self._iface) or "").lower()

    def _seed(self) -> None:
        print(f"Seeding from ICMPv6 multicast sweep on {self._iface} ...", end=" ", flush=True)
        pkt = (
            Ether(dst=IPV6_ALL_NODES_MAC)
            / IPv6(dst=IPV6_ALL_NODES_ADDR)
            / ICMPv6EchoRequest(id=0x5afe, seq=1)
        )
        ans = srp(
            pkt,
            iface=self._iface,
            timeout=self._timeout,
            verbose=self.verbose,
            promisc=False,
            multi=True,
        )[0]
        for _, rcv in ans:
            if not rcv.haslayer(ICMPv6EchoReply):
                continue
            ip  = rcv[IPv6].src.split("%")[0].lower()
            mac = rcv[Ether].src.lower()
            if ip != self._own_ip and not ip.startswith("ff"):
                self._hosts[ip] = mac

        for ip, mac in read_ndp_cache(self._iface).items():
            if ip not in self._hosts and ip != self._own_ip and not ip.startswith("ff"):
                self._hosts[ip] = mac

        print(f"found {len(self._hosts)} host(s)")
        if self._hosts:
            ip_w = max(len(ip) for ip in self._hosts) + 2
            print("  " + "IPv6".ljust(ip_w) + "MAC")
            for ip, mac in sorted(self._hosts.items()):
                print(f"  {ip.ljust(ip_w)}{mac}")

    def _handle(self, pkt: Packet) -> None:
        if not (pkt.haslayer(IPv6) and pkt.haslayer(ICMPv6ND_NA) and pkt.haslayer(Ether)):
            return
        ip  = pkt[IPv6].src.split("%")[0].lower()
        mac = pkt[Ether].src.lower()
        if not ip or ip == self._own_ip or ip.startswith("ff"):
            return
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = mac
                print(f"[{ts}] NEW     {ip}  {mac}")
            elif self._hosts[ip] != mac:
                old_mac = self._hosts[ip]
                self._hosts[ip] = mac
                print(f"[{ts}] CHANGED {ip}  {old_mac} -> {mac}  (possible NDP spoofing!)")

    def watch(self) -> None:
        self._seed()
        print(f"\nWatching for ICMPv6 Neighbor Advertisements on {self._iface} (Ctrl+C to stop) ...\n")
        sniff(
            iface=self._iface,
            filter="icmp6 and ip6[40] == 136",
            prn=self._handle,
            store=False,
            promisc=False,
        )
