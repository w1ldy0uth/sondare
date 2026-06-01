#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sondare.models import TlsCert

DEFAULT_PORTS = (443, 8443)


class TlsProber:
    """Probes TLS/SSL certificates on one or more ports of a target host."""

    def __init__(self, ip: str, ports: tuple[int, ...], timeout: float = 5.0) -> None:
        self.ip = ip
        self.ports = ports
        self._timeout = timeout
        self._results: list[TlsCert] = []

    def _probe(self, port: int) -> TlsCert | None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.ip, port), timeout=self._timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.ip) as tls:
                    der = tls.getpeercert(binary_form=True)
        except OSError:
            return None

        if not der:
            return None

        cert = x509.load_der_x509_certificate(der, default_backend())

        cn = _first_attr(cert.subject, x509.NameOID.COMMON_NAME)
        issuer = (
            _first_attr(cert.issuer, x509.NameOID.ORGANIZATION_NAME)
            or _first_attr(cert.issuer, x509.NameOID.COMMON_NAME)
        )

        nb, na = _cert_validity(cert)
        now = datetime.now(timezone.utc)

        san: tuple[str, ...] = ()
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = tuple(ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass

        return TlsCert(
            ip=self.ip,
            port=port,
            cn=cn,
            issuer=issuer,
            not_before=nb.isoformat(),
            not_after=na.isoformat(),
            san=san,
            expired=na < now,
            self_signed=(cert.issuer == cert.subject),
        )

    def scan(self) -> None:
        for port in self.ports:
            result = self._probe(port)
            if result is not None:
                self._results.append(result)

    def get_results(self) -> list[TlsCert]:
        return list(self._results)


def _first_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _cert_validity(cert: x509.Certificate) -> tuple[datetime, datetime]:
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        return (
            cert.not_valid_before.replace(tzinfo=timezone.utc),
            cert.not_valid_after.replace(tzinfo=timezone.utc),
        )
