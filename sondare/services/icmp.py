#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import ipaddress
from sondare import _sondare
from sondare.utils.network import (
    get_subnet, get_network_interface, get_ipv6_link_local, is_ipv6_address,
    resolve_hostnames,
)


class Ping:
    """Discovers live hosts via ICMP echo.

    No flags:              ICMPv4 sweep of the local IPv4 subnet.
    --target <ipv4>:       probe a single IPv4 host.
    --target <ipv6>:       probe a single IPv6 host via ICMPv6.
    --ipv6:                ICMPv6 multicast sweep of ff02::1 (all IPv6 hosts on the link).
    """

    def __init__(
        self,
        verbose: bool,
        timeout: float,
        resolve_hostname: bool = False,
        target: str | None = None,
        ipv6: bool = False,
    ) -> None:
        self.verbose = verbose
        self._timeout = timeout
        self._resolve_hostname = resolve_hostname
        self._target = target
        self._ipv6_mode = ipv6 or (target is not None and is_ipv6_address(target))
        self._multicast = ipv6 and target is None

        if not self._ipv6_mode:
            # IPv4: enumerate the full subnet or just the single target
            self.hosts = (
                [target] if target is not None
                else [str(ip) for ip in ipaddress.IPv4Network(get_subnet()).hosts()]
            )
        else:
            self.hosts = [] if self._multicast else [target]  # type: ignore[list-item]

        self.results: list[str] = []
        self._hostnames: dict[str, str | None] = {}

    def scan(self) -> None:
        """Sends ICMP echo request(s) and records responding hosts."""
        if self._ipv6_mode:
            self._scan_icmpv6()
        else:
            self._scan_icmpv4()
        if self._resolve_hostname:
            self._hostnames = resolve_hostnames(self.results)

    def _scan_icmpv4(self) -> None:
        subnet_scan = self._target is None
        if subnet_scan:
            print(f"Scanning {len(self.hosts)} hosts ...", end=" ", flush=True)
        iface = get_network_interface()
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        self.results = _sondare.icmp_sweep_v4(iface, self.hosts, 500, grace_ms)
        if subnet_scan:
            print("done")

    def _scan_icmpv6(self) -> None:
        if self._multicast:
            self._scan_icmpv6_multicast()
        else:
            self._scan_icmpv6_unicast()

    def _scan_icmpv6_unicast(self) -> None:
        target = self._target
        print(f"Pinging {target} ...", end=" ", flush=True)
        iface = get_network_interface()
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        self.results = _sondare.icmp_sweep_v6(iface, [target], 500, grace_ms)
        print("done")

    def _scan_icmpv6_multicast(self) -> None:
        iface = get_network_interface()
        print(f"Scanning ff02::1 on {iface} ...", end=" ", flush=True)
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        self.results = _sondare.icmp_multicast_v6(iface, 500, grace_ms)
        print("done")

    def get_results(self) -> list[str]:
        """Returns IPs of live hosts discovered by scan()."""
        return self.results

    def get_hostnames(self) -> dict[str, str | None]:
        """Returns {ip: hostname} for resolved hosts. Empty if resolve_hostname was False."""
        return self._hostnames
