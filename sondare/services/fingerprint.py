#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import random
import threading
import time
from scapy.all import IP, TCP, sr1, sr
from sondare.models import Fingerprint
from sondare.utils.system_utils import warm_arp_cache
from sondare.utils.adaptive import AdaptivePool

# Ports tried in parallel when no specific port is given.
_COMMON_PORTS = [80, 443, 22, 8080, 21, 25, 3389, 445, 23, 53]

# Window sizes that map to a specific OS within the Linux/Unix TTL bucket.
_WINDOW_OS: dict[int, str] = {
    65535: "macOS / iOS / FreeBSD",
    29200: "Linux",
    14600: "Linux",
     5840: "Linux",
    32768: "Linux / Unix",
}


def _initial_ttl(received: int) -> int:
    """Rounds received TTL up to the nearest common initial value."""
    for initial in (32, 64, 128, 255):
        if received <= initial:
            return initial
    return 255


def _guess_os(ttl: int, window: int) -> str:
    initial = _initial_ttl(ttl)
    if initial <= 64:
        return _WINDOW_OS.get(window, "Linux / Unix")
    if initial <= 128:
        return "Windows"
    return "Cisco / Network Device"


class OsFingerprinter:
    """Guesses the OS of a host by analysing a TCP SYN-ACK response."""

    def __init__(self, verbose: bool, ip: str, port: int | None, timeout: float) -> None:
        self.verbose = verbose
        self.ip = ip
        self.port = port
        self._pool = AdaptivePool(max_threads=len(_COMMON_PORTS), timeout=timeout)
        self._result: Fingerprint | None = None
        self._lock = threading.Lock()
        self._found = threading.Event()

    def _probe(self, port: int) -> None:
        """Sends a single SYN probe; records the fingerprint on SYN-ACK."""
        if self._found.is_set():
            return
        sport = random.randint(1025, 65534)
        self._pool.acquire()
        try:
            start = time.monotonic()
            rsp = sr1(
                IP(dst=self.ip) / TCP(sport=sport, dport=port, flags="S"),
                timeout=self._pool.timeout,
                verbose=self.verbose,
                promisc=False,
            )
        finally:
            self._pool.release()

        elapsed = time.monotonic() - start
        self._pool.record(is_timeout=(rsp is None), rtt=elapsed if rsp is not None else None)

        if rsp is None or not rsp.haslayer(TCP):
            return
        if rsp.getlayer(TCP).flags != 0x12:
            return
        with self._lock:
            if self._result is not None:
                return  # another thread already recorded a result
            sr(
                IP(dst=self.ip) / TCP(sport=sport, dport=port, flags="R"),
                timeout=1, verbose=False, promisc=False,
            )
            tcp = rsp.getlayer(TCP)
            self._result = Fingerprint(
                ip=self.ip,
                os=_guess_os(rsp.getlayer(IP).ttl, tcp.window),
                ttl=rsp.getlayer(IP).ttl,
                window=tcp.window,
            )
            self._found.set()

    def scan(self) -> None:
        """Probes all ports in parallel; fingerprints on the first SYN-ACK."""
        warm_arp_cache(self.ip)
        ports = [self.port] if self.port is not None else _COMMON_PORTS
        threads = [
            threading.Thread(target=self._probe, args=(port,), daemon=True)
            for port in ports
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def get_results(self) -> Fingerprint | None:
        """Returns the fingerprint, or None if no SYN-ACK was received."""
        return self._result
