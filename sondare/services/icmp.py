#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import ipaddress
from scapy.all import IP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, sr, sr1
from sondare.utils.network import get_subnet, resolve_hostnames


def _is_ipv6(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address)
    except ValueError:
        return False


class Ping:
    """Discovers live hosts via ICMP echo.

    Without a target: sends ICMPv4 to every host on the local IPv4 subnet.
    With an IPv4 target: probes that single host with ICMPv4.
    With an IPv6 target: probes that single host with ICMPv6 echo request.
    """

    def __init__(
        self,
        verbose: bool,
        timeout: float,
        resolve_hostname: bool = False,
        target: str | None = None,
    ) -> None:
        self.verbose = verbose
        self._timeout = timeout
        self._resolve_hostname = resolve_hostname
        self._target = target
        self._ipv6_mode = target is not None and _is_ipv6(target)

        if target is None:
            self.hosts = [str(ip) for ip in ipaddress.IPv4Network(get_subnet()).hosts()]
        else:
            self.hosts = [target]

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
        print(f"Scanning {len(self.hosts)} host{'s' if len(self.hosts) != 1 else ''} ...", end=" ", flush=True)
        packets = [IP(dst=h) / ICMP() for h in self.hosts]
        answered, _ = sr(packets, timeout=self._timeout, verbose=self.verbose, promisc=False, inter=0)
        print("done")
        for sent, received in answered:
            if received.haslayer(ICMP) and received.getlayer(ICMP).type == 0:
                self.results.append(sent[IP].dst)

    def _scan_icmpv6(self) -> None:
        target = self._target  # guaranteed non-None in this branch
        print(f"Pinging {target} ...", end=" ", flush=True)
        rsp = sr1(
            IPv6(dst=target) / ICMPv6EchoRequest(id=0x5afe, seq=1),
            timeout=self._timeout,
            verbose=self.verbose,
            promisc=False,
        )
        print("done")
        if rsp is not None and rsp.haslayer(ICMPv6EchoReply):
            self.results.append(target)

    def get_results(self) -> list[str]:
        """Returns IPs of live hosts discovered by scan()."""
        return self.results

    def get_hostnames(self) -> dict[str, str | None]:
        """Returns {ip: hostname} for resolved hosts. Empty if resolve_hostname was False."""
        return self._hostnames
