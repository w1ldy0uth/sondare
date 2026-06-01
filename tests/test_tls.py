import datetime
import ssl
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import NameOID

from sondare.models import TlsCert
from sondare.services.tls import TlsProber, _cert_validity, _first_attr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cert(
    cn: str = "example.com",
    org: str | None = "Example Org",
    expired: bool = False,
    san_names: list[str] | None = None,
    self_signed: bool = True,
) -> bytes:
    """Builds a minimal DER-encoded certificate for testing."""
    key = generate_private_key(SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    if expired:
        not_before = now - datetime.timedelta(days=60)
        not_after = now - datetime.timedelta(days=1)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    subject = x509.Name(subject_attrs)

    issuer_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if self_signed and org:
        issuer_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _mock_tls_socket(der: bytes):
    """Returns a context-manager-compatible mock TLS socket returning the given DER cert."""
    tls_sock = MagicMock()
    tls_sock.getpeercert.return_value = der
    tls_sock.__enter__ = MagicMock(return_value=tls_sock)
    tls_sock.__exit__ = MagicMock(return_value=False)
    return tls_sock


def _mock_raw_socket():
    raw = MagicMock()
    raw.__enter__ = MagicMock(return_value=raw)
    raw.__exit__ = MagicMock(return_value=False)
    return raw


# ---------------------------------------------------------------------------
# _first_attr
# ---------------------------------------------------------------------------

class TestFirstAttr:
    def test_returns_value_when_present(self):
        der = _make_cert(cn="host.local")
        cert = x509.load_der_x509_certificate(der)
        assert _first_attr(cert.subject, NameOID.COMMON_NAME) == "host.local"

    def test_returns_none_when_absent(self):
        der = _make_cert(cn="host.local", org=None)
        cert = x509.load_der_x509_certificate(der)
        assert _first_attr(cert.subject, NameOID.ORGANIZATION_NAME) is None


# ---------------------------------------------------------------------------
# _cert_validity
# ---------------------------------------------------------------------------

class TestCertValidity:
    def test_returns_aware_datetimes(self):
        der = _make_cert()
        cert = x509.load_der_x509_certificate(der)
        nb, na = _cert_validity(cert)
        assert nb.tzinfo is not None
        assert na.tzinfo is not None

    def test_naive_fallback(self):
        der = _make_cert()
        cert = x509.load_der_x509_certificate(der)
        # Simulate old cryptography API returning naive datetimes.
        naive = datetime.datetime(2025, 1, 1)
        mock_cert = MagicMock(spec=[])  # no not_valid_before_utc attribute
        mock_cert.not_valid_before = naive
        mock_cert.not_valid_after = naive
        nb, na = _cert_validity(mock_cert)
        assert nb.tzinfo is datetime.timezone.utc
        assert na.tzinfo is datetime.timezone.utc


# ---------------------------------------------------------------------------
# TlsProber._probe
# ---------------------------------------------------------------------------

class TestTlsProberProbe:
    def _run_probe(self, der: bytes, port: int = 443) -> TlsCert | None:
        prober = TlsProber(ip="10.0.0.1", ports=(port,), timeout=3.0)
        raw_sock = _mock_raw_socket()
        tls_sock = _mock_tls_socket(der)

        ctx_mock = MagicMock()
        ctx_mock.wrap_socket.return_value = tls_sock

        with patch("sondare.services.tls.socket.create_connection", return_value=raw_sock), \
             patch("sondare.services.tls.ssl.SSLContext", return_value=ctx_mock):
            return prober._probe(port)

    def test_returns_cert_on_success(self):
        der = _make_cert(cn="example.com", san_names=["example.com", "www.example.com"])
        result = self._run_probe(der)

        assert result is not None
        assert result.ip == "10.0.0.1"
        assert result.port == 443
        assert result.cn == "example.com"
        assert "example.com" in result.san
        assert "www.example.com" in result.san

    def test_expired_flag_set_for_past_cert(self):
        der = _make_cert(expired=True)
        result = self._run_probe(der)
        assert result is not None
        assert result.expired is True

    def test_not_expired_for_future_cert(self):
        der = _make_cert(expired=False)
        result = self._run_probe(der)
        assert result is not None
        assert result.expired is False

    def test_self_signed_detection(self):
        der = _make_cert(self_signed=True)
        result = self._run_probe(der)
        assert result is not None
        assert result.self_signed is True

    def test_not_self_signed_when_different_issuer(self):
        der = _make_cert(self_signed=False)
        result = self._run_probe(der)
        assert result is not None
        assert result.self_signed is False

    def test_issuer_org_preferred_over_cn(self):
        der = _make_cert(cn="host.example.com", org="Example Corp")
        result = self._run_probe(der)
        assert result is not None
        assert result.issuer == "Example Corp"

    def test_issuer_falls_back_to_cn(self):
        der = _make_cert(cn="host.example.com", org=None)
        result = self._run_probe(der)
        assert result is not None
        assert result.issuer == "host.example.com"

    def test_empty_san_when_no_extension(self):
        der = _make_cert(san_names=None)
        result = self._run_probe(der)
        assert result is not None
        assert result.san == ()

    def test_returns_none_on_connection_refused(self):
        prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=1.0)
        with patch("sondare.services.tls.socket.create_connection", side_effect=ConnectionRefusedError):
            result = prober._probe(443)
        assert result is None

    def test_returns_none_on_timeout(self):
        prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=1.0)
        with patch("sondare.services.tls.socket.create_connection", side_effect=TimeoutError):
            result = prober._probe(443)
        assert result is None

    def test_returns_none_when_no_cert(self):
        prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=1.0)
        raw_sock = _mock_raw_socket()
        tls_sock = _mock_tls_socket(b"")  # empty DER
        ctx_mock = MagicMock()
        ctx_mock.wrap_socket.return_value = tls_sock
        with patch("sondare.services.tls.socket.create_connection", return_value=raw_sock), \
             patch("sondare.services.tls.ssl.SSLContext", return_value=ctx_mock):
            result = prober._probe(443)
        assert result is None


# ---------------------------------------------------------------------------
# TlsProber.scan / get_results
# ---------------------------------------------------------------------------

class TestTlsProberScan:
    def test_scan_probes_all_ports(self):
        der = _make_cert()
        prober = TlsProber(ip="10.0.0.1", ports=(443, 8443), timeout=3.0)

        raw_sock = _mock_raw_socket()
        tls_sock = _mock_tls_socket(der)
        ctx_mock = MagicMock()
        ctx_mock.wrap_socket.return_value = tls_sock

        with patch("sondare.services.tls.socket.create_connection", return_value=raw_sock), \
             patch("sondare.services.tls.ssl.SSLContext", return_value=ctx_mock):
            prober.scan()

        results = prober.get_results()
        assert len(results) == 2
        assert {r.port for r in results} == {443, 8443}

    def test_scan_skips_unreachable_ports(self):
        der = _make_cert()
        prober = TlsProber(ip="10.0.0.1", ports=(443, 8443), timeout=1.0)

        raw_sock = _mock_raw_socket()
        tls_sock = _mock_tls_socket(der)
        ctx_mock = MagicMock()
        ctx_mock.wrap_socket.return_value = tls_sock

        call_count = 0

        def _conn(addr, timeout):
            nonlocal call_count
            call_count += 1
            if addr[1] == 8443:
                raise ConnectionRefusedError
            return raw_sock

        with patch("sondare.services.tls.socket.create_connection", side_effect=_conn), \
             patch("sondare.services.tls.ssl.SSLContext", return_value=ctx_mock):
            prober.scan()

        results = prober.get_results()
        assert len(results) == 1
        assert results[0].port == 443

    def test_get_results_empty_before_scan(self):
        prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=1.0)
        assert prober.get_results() == []
