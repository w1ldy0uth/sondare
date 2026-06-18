#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import MdnsRecord
from sondare.utils.network import _MDNS_SCAN_SERVICES


class Mdns:
    """Discovers mDNS/Bonjour service advertisements on the local network."""

    def __init__(self, verbose: bool, timeout: float) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self._results: list[MdnsRecord] = []

    def scan(self) -> None:
        timeout_ms = int(self.timeout * 1000)
        raw = _sondare.mdns_scan(_MDNS_SCAN_SERVICES, timeout_ms)
        self._results = [
            MdnsRecord(hostname=h, ip=ip, service=svc, port=p)
            for h, ip, svc, p in raw
        ]

    def get_results(self) -> list[MdnsRecord]:
        return self._results
