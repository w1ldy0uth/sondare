#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import socket
import struct
import threading
from datetime import datetime
from sondare import _sondare
from sondare.utils.network import (
    get_network_interface, get_ipv6_link_local, read_ndp_cache,
)

_ETH_LEN = 14
_IPV6_LEN = 40
_NA_TYPE = 136


def _parse_ndp_na(raw: bytes) -> tuple[str, str] | None:
    """Extracts (ipv6_src, src_mac) from a raw Ethernet+IPv6+ICMPv6 NA frame."""
    if len(raw) < _ETH_LEN + _IPV6_LEN + 8:
        return None
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype != 0x86DD:
        return None
    next_hdr = raw[_ETH_LEN + 6]
    if next_hdr != 58:  # ICMPv6
        return None
    icmpv6_offset = _ETH_LEN + _IPV6_LEN
    icmpv6_type = raw[icmpv6_offset]
    if icmpv6_type != _NA_TYPE:
        return None
    src_ip_bytes = raw[_ETH_LEN + 8 : _ETH_LEN + 24]
    src_ip = socket.inet_ntop(socket.AF_INET6, src_ip_bytes).lower()
    src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
    return src_ip, src_mac


class NdpWatcher:
    """
    Seeds known IPv6 hosts with an initial multicast echo sweep + NDP cache,
    then passively sniffs ICMPv6 Neighbor Advertisement traffic and prints
    events as they arrive:
      NEW     - first time this IPv6 address is seen
      CHANGED - same address, different MAC (potential NDP spoofing)
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
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        pairs = _sondare.ndp_sweep(self._iface, 500, grace_ms)
        for ip, mac in pairs:
            ip_l = ip.lower()
            mac_l = mac.lower()
            if ip_l != self._own_ip and not ip_l.startswith("ff"):
                self._hosts[ip_l] = mac_l

        for ip, mac in read_ndp_cache(self._iface).items():
            if ip not in self._hosts and ip != self._own_ip and not ip.startswith("ff"):
                self._hosts[ip] = mac

        print(f"found {len(self._hosts)} host(s)")
        if self._hosts:
            ip_w = max(len(ip) for ip in self._hosts) + 2
            print("  " + "IPv6".ljust(ip_w) + "MAC")
            for ip, mac in sorted(self._hosts.items()):
                print(f"  {ip.ljust(ip_w)}{mac}")

    def _handle(self, raw: bytes) -> None:
        parsed = _parse_ndp_na(raw)
        if parsed is None:
            return
        ip, mac = parsed
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
        _sondare.sniff(self._iface, "icmp6 and ip6[40] == 136", self._handle)
