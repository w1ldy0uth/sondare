#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import random
import threading
import time
from scapy.all import IP, IPv6, TCP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, sr1, sr
from sondare import _sondare
from sondare.models import Fingerprint
from sondare.utils.network import (
    warm_arp_cache, is_ipv6_address, get_network_interface,
)
from sondare.utils.adaptive_pool import AdaptivePool

# Ports tried in parallel when no specific port is given.
_COMMON_PORTS = [80, 443, 22, 8080, 21, 25, 3389, 445, 23, 53]

# Window sizes that unambiguously identify Linux variants (within the TTL ≤ 64 bucket).
_LINUX_WINDOWS: frozenset[int] = frozenset({29200, 14600, 5840})


def _initial_ttl(received: int) -> int:
    """Rounds received TTL up to the nearest common initial value."""
    for initial in (32, 64, 128, 255):
        if received <= initial:
            return initial
    return 255


def _parse_tcp_options(options) -> dict:
    """Extracts MSS, window-scale, timestamps, and SACK from a scapy TCP options list."""
    result: dict = {"mss": None, "wscale": None, "timestamps": False, "sack": False}
    for opt in (options or []):
        name = opt[0] if isinstance(opt, (list, tuple)) else opt
        val  = opt[1] if isinstance(opt, (list, tuple)) and len(opt) > 1 else None
        if name == "MSS":
            result["mss"] = val
        elif name == "WScale":
            result["wscale"] = val
        elif name == "Timestamp":
            result["timestamps"] = True
        elif name in ("SAckOK", "SACK"):
            result["sack"] = True
    return result


def _guess_os(ttl: int, window: int, tcp_opts: dict | None = None) -> str:
    """Infers OS from TTL bucket, TCP window size, and optional TCP option signals."""
    initial = _initial_ttl(ttl)
    opts   = tcp_opts or {}
    has_ts = opts.get("timestamps", False)
    wscale = opts.get("wscale")

    if initial > 128:
        return "Cisco / Network Device"

    if initial > 64:
        # Default Windows territory; timestamps disambiguate misclassified Linux hosts.
        if has_ts:
            return "Linux / Unix"
        if window == 64240:
            return "Windows 10 / 11"
        return "Windows"

    # TTL ≤ 64: Linux / macOS / FreeBSD / iOS territory.
    if window in _LINUX_WINDOWS:
        return "Linux"
    if window == 32768:
        return "Linux / Unix"
    if window == 65535:
        if has_ts and wscale == 6:
            return "macOS / iOS"
        if has_ts:
            return "macOS / FreeBSD"
        return "macOS / iOS / FreeBSD"  # no options signal — keep broad
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
        self._pool = AdaptivePool(max_threads=len(_COMMON_PORTS), timeout=timeout)
        self._result: Fingerprint | None = None
        self._lock = threading.Lock()
        self._found = threading.Event()

    def _syn_probe(self, sport: int, port: int) -> object:
        """Sends one SYN packet, updates the pool, and returns the response or None."""
        ip_layer = IPv6(dst=self.ip) if self._ipv6 else IP(dst=self.ip)
        self._pool.acquire()
        try:
            start = time.monotonic()
            rsp = sr1(
                ip_layer / TCP(sport=sport, dport=port, flags="S"),
                timeout=self._pool.timeout,
                verbose=self.verbose,
                promisc=False,
            )
        finally:
            self._pool.release()
        elapsed = time.monotonic() - start
        self._pool.record(is_timeout=(rsp is None), rtt=elapsed if rsp is not None else None)
        return rsp

    def _probe(self, port: int) -> None:
        """Sends a SYN probe with one retry on timeout; records fingerprint on SYN-ACK.

        RST is a definitive closed-port signal and is never retried. The retry
        only fires on timeout, which can be caused by transient packet loss when
        multiple hosts are fingerprinted concurrently (e.g. graph mode).
        """
        if self._found.is_set():
            return
        sport = random.randint(1025, 65534)

        rsp = self._syn_probe(sport, port)
        if rsp is None and not self._found.is_set():
            rsp = self._syn_probe(sport, port)

        if rsp is None or not rsp.haslayer(TCP):
            return
        if rsp.getlayer(TCP).flags != 0x12:
            return
        with self._lock:
            if self._result is not None:
                return  # another thread already recorded a result
            ip_layer = IPv6(dst=self.ip) if self._ipv6 else IP(dst=self.ip)
            sr(
                ip_layer / TCP(sport=sport, dport=port, flags="R"),
                timeout=1, verbose=False, promisc=False,
            )
            tcp      = rsp.getlayer(TCP)
            opts     = _parse_tcp_options(tcp.options)
            ip_resp  = rsp.getlayer(IPv6) if self._ipv6 else rsp.getlayer(IP)
            ttl      = ip_resp.hlim if self._ipv6 else ip_resp.ttl
            self._result = Fingerprint(
                ip=self.ip,
                os=_guess_os(ttl, tcp.window, opts),
                ttl=ttl,
                window=tcp.window,
                source="tcp",
            )
            self._found.set()

    def _icmp_probe(self) -> None:
        """Sends one ICMP/ICMPv6 echo and records OS from TTL/hlim alone (window=0 = ICMP-derived)."""
        if self._ipv6:
            pkt = sr1(
                IPv6(dst=self.ip) / ICMPv6EchoRequest(),
                timeout=self._timeout, verbose=self.verbose, promisc=False,
            )
            if pkt is not None and pkt.haslayer(ICMPv6EchoReply):
                hlim = pkt.getlayer(IPv6).hlim
                self._result = Fingerprint(ip=self.ip, os=_guess_os(hlim, 0), ttl=hlim, window=0, source="icmp")
        else:
            pkt = sr1(
                IP(dst=self.ip) / ICMP(),
                timeout=self._timeout, verbose=self.verbose, promisc=False,
            )
            if pkt is not None and pkt.haslayer(IP):
                ttl = pkt.getlayer(IP).ttl
                self._result = Fingerprint(ip=self.ip, os=_guess_os(ttl, 0), ttl=ttl, window=0, source="icmp")

    def scan(self) -> None:
        """Probes all ports in parallel; fingerprints on the first SYN-ACK.
        Falls back to ICMP TTL when no TCP port responds (unless icmp_fallback=False)."""
        if self._ipv6:
            self._scan_ipv6()
        else:
            self._scan_ipv4()

    def _scan_ipv4(self) -> None:
        warm_arp_cache(self.ip)
        iface = get_network_interface()
        ports = [self.port] if self.port is not None else _COMMON_PORTS
        pps = 500
        grace_ms = 500
        try:
            result = _sondare.fingerprint_v4(iface, self.ip, ports, pps, grace_ms)
        except RuntimeError:
            result = None
        if result is not None:
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
        elif self._icmp_fallback:
            self._icmp_probe()

    def _scan_ipv6(self) -> None:
        ports = [self.port] if self.port is not None else _COMMON_PORTS
        threads = [
            threading.Thread(target=self._probe, args=(port,), daemon=True)
            for port in ports
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if self._result is None and self._icmp_fallback:
            self._icmp_probe()

    def get_results(self) -> Fingerprint | None:
        """Returns the fingerprint, or None if no SYN-ACK was received."""
        return self._result
