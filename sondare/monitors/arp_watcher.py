#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import threading
from datetime import datetime
from scapy.all import ARP, sniff
from scapy.packet import Packet
from sondare import _sondare
from sondare.utils.network import get_subnet, get_network_interface


class ArpWatcher:
    """
    Seeds known hosts with an initial ARP scan, then passively sniffs ARP
    traffic and prints events as they arrive:
      NEW     — first time this IP is seen
      CHANGED — same IP, different MAC (potential ARP spoofing)
    """

    def __init__(self, verbose: bool, timeout: float) -> None:
        self.verbose = verbose
        self._timeout = timeout
        self._hosts: dict[str, str] = {}  # ip -> mac
        self._lock = threading.Lock()

    def _seed(self) -> None:
        cidr = get_subnet()
        iface = get_network_interface()
        print(f"Seeding from ARP scan of {cidr} ...", end=" ", flush=True)
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        pairs = _sondare.arp_sweep_v4(iface, cidr, 500, grace_ms)
        for ip, mac in pairs:
            self._hosts[ip] = mac.lower()
        print(f"found {len(self._hosts)} host(s)")
        if self._hosts:
            ip_w = max(len(ip) for ip in self._hosts) + 2
            print("  " + "IP".ljust(ip_w) + "MAC")
            for ip, mac in sorted(self._hosts.items()):
                print(f"  {ip.ljust(ip_w)}{mac}")

    def _handle(self, pkt: Packet) -> None:
        arp = pkt.getlayer(ARP)
        if arp is None:
            return
        ip, mac = arp.psrc, arp.hwsrc
        if ip == "0.0.0.0":
            return
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = mac
                print(f"[{ts}] NEW     {ip.ljust(16)}{mac}")
            elif self._hosts[ip] != mac:
                old_mac = self._hosts[ip]
                self._hosts[ip] = mac
                print(f"[{ts}] CHANGED {ip.ljust(16)}{old_mac} -> {mac}  (possible ARP spoofing!)")

    def watch(self) -> None:
        self._seed()
        iface = get_network_interface()
        print(f"\nWatching for ARP traffic on {iface} (Ctrl+C to stop) ...\n")
        sniff(iface=iface, filter="arp", prn=self._handle, store=False, promisc=False)
