from unittest.mock import patch, MagicMock, call
from sondare.services.fingerprint import OsFingerprinter, _initial_ttl, _guess_os, _parse_tcp_options
from sondare.models import Fingerprint


def _syn_ack(ttl: int, window: int, options=None):
    tcp = MagicMock()
    tcp.flags = 0x12
    tcp.window = window
    tcp.options = options or []
    ip = MagicMock()
    ip.ttl = ttl
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.getlayer.side_effect = lambda cls: tcp if cls.__name__ == "TCP" else ip
    return pkt


def _rst():
    tcp = MagicMock()
    tcp.flags = 0x04
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.getlayer.return_value = tcp
    return pkt


class TestInitialTtl:
    def test_rounds_up_to_64(self):
        assert _initial_ttl(54) == 64
        assert _initial_ttl(64) == 64

    def test_rounds_up_to_128(self):
        assert _initial_ttl(100) == 128
        assert _initial_ttl(128) == 128

    def test_rounds_up_to_255(self):
        assert _initial_ttl(200) == 255
        assert _initial_ttl(255) == 255

    def test_rounds_up_to_32(self):
        assert _initial_ttl(30) == 32


class TestParseTcpOptions:
    def test_empty(self):
        r = _parse_tcp_options([])
        assert r == {"mss": None, "wscale": None, "timestamps": False, "sack": False}

    def test_none_input(self):
        r = _parse_tcp_options(None)
        assert r["timestamps"] is False

    def test_parses_mss(self):
        assert _parse_tcp_options([("MSS", 1460)])["mss"] == 1460

    def test_parses_wscale(self):
        assert _parse_tcp_options([("WScale", 6)])["wscale"] == 6

    def test_parses_timestamps(self):
        assert _parse_tcp_options([("Timestamp", (12345, 0))])["timestamps"] is True

    def test_parses_sack(self):
        assert _parse_tcp_options([("SAckOK", b"")])["sack"] is True

    def test_full_linux_options(self):
        opts = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]
        r = _parse_tcp_options(opts)
        assert r["mss"] == 1460 and r["wscale"] == 7 and r["timestamps"] is True and r["sack"] is True

    def test_unknown_option_ignored(self):
        r = _parse_tcp_options([("NOP", None), ("EOL", None)])
        assert r == {"mss": None, "wscale": None, "timestamps": False, "sack": False}


class TestGuessOs:
    def test_linux_by_window(self):
        assert _guess_os(64, 29200) == "Linux"
        assert _guess_os(60, 14600) == "Linux"
        assert _guess_os(64,  5840) == "Linux"

    def test_macos_ios_by_window(self):
        assert _guess_os(64, 65535) == "macOS / iOS / FreeBSD"

    def test_unknown_unix_window(self):
        assert _guess_os(64, 12345) == "Linux / Unix"

    def test_windows_by_ttl(self):
        assert _guess_os(128, 8192)  == "Windows"
        assert _guess_os(110, 65535) == "Windows"

    def test_cisco_by_ttl(self):
        assert _guess_os(255, 4096) == "Cisco / Network Device"
        assert _guess_os(200, 4096) == "Cisco / Network Device"

    def test_windows10_by_window(self):
        assert _guess_os(128, 64240) == "Windows 10 / 11"

    def test_timestamps_disambiguate_linux_from_windows(self):
        # A Linux host seen through many hops can land in the 65–128 TTL bucket.
        # Timestamps signal it is not Windows.
        assert _guess_os(128, 65535, {"timestamps": True}) == "Linux / Unix"
        assert _guess_os(100, 8192,  {"timestamps": True}) == "Linux / Unix"

    def test_macos_ios_with_timestamps_wscale6(self):
        assert _guess_os(64, 65535, {"timestamps": True, "wscale": 6}) == "macOS / iOS"

    def test_macos_freebsd_with_timestamps_other_wscale(self):
        assert _guess_os(64, 65535, {"timestamps": True, "wscale": 8}) == "macOS / FreeBSD"

    def test_macos_freebsd_with_timestamps_no_wscale(self):
        assert _guess_os(64, 65535, {"timestamps": True, "wscale": None}) == "macOS / FreeBSD"


def _ipv4_patches(rust_result):
    return [
        patch("sondare.services.fingerprint._sondare.fingerprint_v4", return_value=rust_result),
        patch("sondare.services.fingerprint.warm_arp_cache"),
        patch("sondare.services.fingerprint.get_network_interface", return_value="eth0"),
    ]


class TestOsFingerprinter:
    def test_syn_ack_produces_fingerprint(self):
        # (ttl, window, mss, wscale, has_timestamps, has_sack)
        patches = _ipv4_patches((64, 29200, None, None, False, False))
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="192.168.1.1", port=80, timeout=1)
            scanner.scan()

        assert scanner.get_results() == Fingerprint(ip="192.168.1.1", os="Linux", ttl=64, window=29200)

    def test_no_response_returns_none(self):
        patches = _ipv4_patches(None)
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="192.168.1.1", port=80, timeout=1,
                                      icmp_fallback=False)
            scanner.scan()

        assert scanner.get_results() is None

    def test_auto_probe_returns_fingerprint(self):
        patches = _ipv4_patches((64, 65535, None, None, False, False))
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=None, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.os == "macOS / iOS / FreeBSD"

    def test_returns_none_before_scan(self):
        scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
        assert scanner.get_results() is None

    def test_icmp_fallback_when_no_tcp_response(self):
        icmp_pkt = MagicMock()
        icmp_pkt.haslayer.return_value = True
        ip_layer = MagicMock()
        ip_layer.ttl = 63
        icmp_pkt.getlayer.return_value = ip_layer

        patches = _ipv4_patches(None)
        with patches[0], patches[1], patches[2], \
             patch("sondare.services.fingerprint.sr1", return_value=icmp_pkt):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.os == "Linux / Unix"
        assert result.ttl == 63
        assert result.window == 0
        assert result.source == "icmp"

    def test_icmp_fallback_disabled_returns_none(self):
        patches = _ipv4_patches(None)
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1,
                                      icmp_fallback=False)
            scanner.scan()

        assert scanner.get_results() is None

    def test_icmp_fallback_skipped_when_tcp_succeeds(self):
        patches = _ipv4_patches((64, 65535, None, None, False, False))
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.window == 65535

    def test_tcp_result_has_tcp_source(self):
        patches = _ipv4_patches((64, 29200, None, None, False, False))
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        assert scanner.get_results().source == "tcp"

    def test_tcp_options_refine_macos_ios(self):
        patches = _ipv4_patches((64, 65535, 1460, 6, True, True))
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.os == "macOS / iOS"
        assert result.source == "tcp"

    def test_tcp_options_windows10_window(self):
        patches = _ipv4_patches((128, 64240, None, None, False, False))
        with patches[0], patches[1], patches[2]:
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        assert scanner.get_results().os == "Windows 10 / 11"
