from unittest.mock import patch
from sondare.models import TlsCert
from sondare.services.tls import TlsProber


_SENTINEL = object()

def _rust_result(
    ip="10.0.0.1", port=443, cn="example.com", issuer="Example Org",
    not_before="2025-01-01T00:00:00+00:00", not_after="2026-01-01T00:00:00+00:00",
    san=_SENTINEL, expired=False, self_signed=True,
):
    if san is _SENTINEL:
        san = ["example.com"]
    return (ip, port, cn, issuer, not_before, not_after, san, expired, self_signed)


class TestTlsProberScan:
    def test_scan_returns_results_from_rust(self):
        raw = [_rust_result(port=443), _rust_result(port=8443)]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443, 8443), timeout=3.0)
            prober.scan()

        results = prober.get_results()
        assert len(results) == 2
        assert {r.port for r in results} == {443, 8443}

    def test_scan_skips_unreachable_ports(self):
        raw = [_rust_result(port=443)]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443, 8443), timeout=1.0)
            prober.scan()

        results = prober.get_results()
        assert len(results) == 1
        assert results[0].port == 443

    def test_get_results_empty_before_scan(self):
        prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=1.0)
        assert prober.get_results() == []

    def test_cn_and_issuer_populated(self):
        raw = [_rust_result(cn="host.local", issuer="My CA")]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        cert = prober.get_results()[0]
        assert cert.cn == "host.local"
        assert cert.issuer == "My CA"

    def test_expired_flag(self):
        raw = [_rust_result(expired=True)]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        assert prober.get_results()[0].expired is True

    def test_not_expired_flag(self):
        raw = [_rust_result(expired=False)]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        assert prober.get_results()[0].expired is False

    def test_self_signed_flag(self):
        raw = [_rust_result(self_signed=True)]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        assert prober.get_results()[0].self_signed is True

    def test_not_self_signed_flag(self):
        raw = [_rust_result(self_signed=False)]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        assert prober.get_results()[0].self_signed is False

    def test_san_populated(self):
        raw = [_rust_result(san=["example.com", "www.example.com"])]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        cert = prober.get_results()[0]
        assert "example.com" in cert.san
        assert "www.example.com" in cert.san

    def test_empty_san(self):
        raw = [_rust_result(san=[])]
        with patch("sondare.services.tls._sondare.tls_probe", return_value=raw):
            prober = TlsProber(ip="10.0.0.1", ports=(443,))
            prober.scan()

        assert prober.get_results()[0].san == ()

    def test_no_results_when_rust_returns_empty(self):
        with patch("sondare.services.tls._sondare.tls_probe", return_value=[]):
            prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=1.0)
            prober.scan()

        assert prober.get_results() == []

    def test_timeout_passed_to_rust(self):
        with patch("sondare.services.tls._sondare.tls_probe", return_value=[]) as mock_rust:
            prober = TlsProber(ip="10.0.0.1", ports=(443,), timeout=2.5)
            prober.scan()

        args = mock_rust.call_args[0]
        assert args[0] == "10.0.0.1"
        assert args[1] == [443]
        assert args[2] == 2500
