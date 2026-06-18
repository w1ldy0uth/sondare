#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import Fingerprint
from sondare.utils.network import (
    warm_arp_cache, is_ipv6_address, get_network_interface,
)

_COMMON_PORTS = [80, 443, 22, 8080, 21, 25, 3389, 445, 23, 53]

_LINUX_WINDOWS: frozenset[int] = frozenset({29200, 14600, 5840})


def _initial_ttl(received: int) -> int:
    for initial in (32, 64, 128, 255):
        if received <= initial:
            return initial
    return 255


def _guess_os(ttl: int, window: int, tcp_opts: dict | None = None) -> str:
    initial = _initial_ttl(ttl)
    opts   = tcp_opts or {}
    has_ts = opts.get("timestamps", False)
    wscale = opts.get("wscale")

    if initial > 128:
        return "Cisco / Network Device"

    if initial > 64:
        if has_ts:
            return "Linux / Unix"
        if window == 64240:
            return "Windows 10 / 11"
        return "Windows"

    if window in _LINUX_WINDOWS:
        return "Linux"
    if window == 32768:
        return "Linux / Unix"
    if window == 65535:
        if has_ts and wscale == 6:
            return "macOS / iOS"
        if has_ts:
            return "macOS / FreeBSD"
        return "macOS / iOS / FreeBSD"
    return "Linux / Unix"


class OsFingerprinter:
    """Guesses the OS of a host by analysing a TCP SYN-ACK response, with optional ICMP TTL fallback."""

    def __init__(self, verbose: bool, ip: str, port: int | None, timeout: float, icmp_fallback: bool = True) -> None:
        self.verbose = verbose
        self.ip = ip
        self.port = port
        self._icmp_fallback = icmp_fallback
        self._timeout = timeout
        self._ipv6 = is_ipv6_address(ip)
        self._result: Fingerprint | None = None

    def _fingerprint_from_rust(self, result: tuple) -> None:
        ttl, window, mss, wscale, has_timestamps, has_sack = result
        tcp_opts = {
            "mss": mss,
            "wscale": wscale,
            "timestamps": has_timestamps,
            "sack": has_sack,
        }
        self._result = Fingerprint(
            ip=self.ip,
            os=_guess_os(ttl, window, tcp_opts),
            ttl=ttl,
            window=window,
            source="tcp",
        )

    def _icmp_probe(self) -> None:
        iface = get_network_interface()
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        if self._ipv6:
            alive = _sondare.icmp_sweep_v6(iface, [self.ip], 500, grace_ms)
        else:
            alive = _sondare.icmp_sweep_v4(iface, [self.ip], 500, grace_ms)
        if alive:
            ttl = 64 if self._ipv6 else 64
            self._result = Fingerprint(ip=self.ip, os=_guess_os(ttl, 0), ttl=ttl, window=0, source="icmp")

    def scan(self) -> None:
        if self._ipv6:
            self._scan_ipv6()
        else:
            self._scan_ipv4()

    def _scan_ipv4(self) -> None:
        warm_arp_cache(self.ip)
        iface = get_network_interface()
        ports = [self.port] if self.port is not None else _COMMON_PORTS
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        try:
            result = _sondare.fingerprint_v4(iface, self.ip, ports, 500, grace_ms)
        except RuntimeError:
            result = None
        if result is not None:
            self._fingerprint_from_rust(result)
        elif self._icmp_fallback:
            self._icmp_probe()

    def _scan_ipv6(self) -> None:
        iface = get_network_interface()
        ports = [self.port] if self.port is not None else _COMMON_PORTS
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        try:
            result = _sondare.fingerprint_v6(iface, self.ip, ports, 500, grace_ms)
        except RuntimeError:
            result = None
        if result is not None:
            self._fingerprint_from_rust(result)
        elif self._icmp_fallback:
            self._icmp_probe()

    def get_results(self) -> Fingerprint | None:
        return self._result
