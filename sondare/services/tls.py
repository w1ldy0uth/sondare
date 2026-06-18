#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from sondare import _sondare
from sondare.models import TlsCert

DEFAULT_PORTS = (443, 8443)


class TlsProber:
    """Probes TLS/SSL certificates on one or more ports of a target host."""

    def __init__(self, ip: str, ports: tuple[int, ...], timeout: float = 5.0) -> None:
        self.ip = ip
        self.ports = ports
        self._timeout = timeout
        self._results: list[TlsCert] = []

    def scan(self) -> None:
        timeout_ms = int(self._timeout * 1000)
        raw = _sondare.tls_probe(self.ip, list(self.ports), timeout_ms)
        for ip, port, cn, issuer, not_before, not_after, san, expired, self_signed in raw:
            self._results.append(TlsCert(
                ip=ip,
                port=port,
                cn=cn,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
                san=tuple(san),
                expired=expired,
                self_signed=self_signed,
            ))

    def get_results(self) -> list[TlsCert]:
        return list(self._results)
