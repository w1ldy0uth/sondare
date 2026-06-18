#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import time
from datetime import datetime
from sondare import _sondare
from sondare.utils.network import get_network_interface, is_ipv6_address


class PortWatcher:
    """
    Repeatedly SYN-scans a target's port range and reports state changes:
      OPENED - port was closed/filtered, now open
      CLOSED - port was open, now closed/filtered
    """

    def __init__(
        self,
        verbose: bool,
        ip: str,
        port_begin: int,
        port_end: int,
        timeout: float,
        threads: int,
        interval: int,
    ) -> None:
        self._verbose = verbose
        self._ip = ip
        self._port_begin = port_begin
        self._port_end = port_end
        self._timeout = timeout
        self._threads = threads
        self._interval = interval
        self._open: set[int] = set()

    def _scan(self) -> set[int]:
        iface = get_network_interface()
        ports = list(range(self._port_begin, self._port_end + 1))
        pps = self._threads * 25
        grace_ms = max(200, int(self._timeout * 1000))
        if is_ipv6_address(self._ip):
            return set(_sondare.tcp_syn_scan_v6(iface, self._ip, ports, pps, grace_ms))
        return set(_sondare.tcp_syn_scan_v4(iface, self._ip, ports, pps, grace_ms))

    def watch(self) -> None:
        port_range = (
            str(self._port_begin)
            if self._port_begin == self._port_end
            else f"{self._port_begin}-{self._port_end}"
        )
        print(
            f"Monitoring ports {port_range} on {self._ip}"
            f" every {self._interval}s - Ctrl+C to stop\n"
        )
        first = True
        while True:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] Scanning ...", end=" ", flush=True)
            new_open = self._scan()
            print("done")

            if first:
                ports_str = ", ".join(str(p) for p in sorted(new_open)) or "none"
                print(f"[{ts}] Initial state: {len(new_open)} open port(s): {ports_str}\n")
                first = False
            else:
                opened = sorted(new_open - self._open)
                closed = sorted(self._open - new_open)
                for p in opened:
                    print(f"[{ts}] OPENED  {self._ip}:{p}")
                for p in closed:
                    print(f"[{ts}] CLOSED  {self._ip}:{p}")

            self._open = new_open
            time.sleep(self._interval)
