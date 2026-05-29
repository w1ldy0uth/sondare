#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare.models import MdnsRecord
from sondare.utils.network import browse_mdns


class Mdns:
    """Discovers mDNS/Bonjour service advertisements on the local network."""

    def __init__(self, verbose: bool, timeout: float) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self._results: list[MdnsRecord] = []

    def scan(self) -> None:
        self._results = browse_mdns(timeout=self.timeout)

    def get_results(self) -> list[MdnsRecord]:
        return self._results
