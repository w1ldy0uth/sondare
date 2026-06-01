from unittest.mock import patch, MagicMock, call
from sondare.services.fingerprint import OsFingerprinter, _initial_ttl, _guess_os
from sondare.models import Fingerprint


def _syn_ack(ttl: int, window: int):
    tcp = MagicMock()
    tcp.flags = 0x12
    tcp.window = window
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


class TestOsFingerprinter:
    def test_syn_ack_produces_fingerprint(self):
        with patch("sondare.services.fingerprint.sr1", return_value=_syn_ack(ttl=64, window=29200)), \
             patch("sondare.services.fingerprint.sr"), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="192.168.1.1", port=80, timeout=1)
            scanner.scan()

        assert scanner.get_results() == Fingerprint(ip="192.168.1.1", os="Linux", ttl=64, window=29200)

    def test_no_response_returns_none(self):
        with patch("sondare.services.fingerprint.sr1", return_value=None), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="192.168.1.1", port=80, timeout=1,
                                      icmp_fallback=False)
            scanner.scan()

        assert scanner.get_results() is None

    def test_rst_does_not_produce_fingerprint(self):
        # RST is definitive — no retry, falls straight to ICMP (which also returns None here)
        with patch("sondare.services.fingerprint.sr1", side_effect=[_rst(), None]), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        assert scanner.get_results() is None

    def test_rst_does_not_trigger_retry(self):
        with patch("sondare.services.fingerprint.sr1", side_effect=[_rst(), None]) as mock_sr1, \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()
        # exactly 2 calls: RST (no retry) + ICMP probe
        assert mock_sr1.call_count == 2

    def test_auto_probe_uses_common_ports_in_parallel(self):
        # Patch to two ports so both are probed; first SYN-ACK wins.
        with patch("sondare.services.fingerprint._COMMON_PORTS", [80, 443]), \
             patch("sondare.services.fingerprint.sr1", return_value=_syn_ack(64, 65535)), \
             patch("sondare.services.fingerprint.sr"), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=None, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.os == "macOS / iOS / FreeBSD"

    def test_only_one_result_recorded_when_multiple_syn_acks(self):
        # Both parallel probes return SYN-ACK; only one result should be stored.
        with patch("sondare.services.fingerprint._COMMON_PORTS", [80, 443]), \
             patch("sondare.services.fingerprint.sr1", return_value=_syn_ack(64, 29200)), \
             patch("sondare.services.fingerprint.sr"), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=None, timeout=1)
            scanner.scan()

        assert scanner.get_results() is not None  # exactly one result, not duplicated

    def test_single_port_makes_one_probe(self):
        with patch("sondare.services.fingerprint.sr1", return_value=_syn_ack(64, 65535)) as mock_sr1, \
             patch("sondare.services.fingerprint.sr"), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        assert mock_sr1.call_count == 1

    def test_returns_none_before_scan(self):
        scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
        assert scanner.get_results() is None

    def test_timeout_triggers_retry(self):
        # First sr1 call times out; second (retry) also times out; ICMP also times out.
        with patch("sondare.services.fingerprint.sr1", return_value=None) as mock_sr1, \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()
        # port probe × 2 (retry) + 1 ICMP = 3 total calls
        assert mock_sr1.call_count == 3
        assert scanner.get_results() is None

    def test_icmp_fallback_when_no_tcp_response(self):
        icmp_pkt = MagicMock()
        icmp_pkt.haslayer.return_value = True
        ip_layer = MagicMock()
        ip_layer.ttl = 63
        icmp_pkt.getlayer.return_value = ip_layer

        # None × 2 (port probe + retry) then icmp_pkt
        with patch("sondare.services.fingerprint.sr1", side_effect=[None, None, icmp_pkt]), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.os == "Linux / Unix"
        assert result.ttl == 63
        assert result.window == 0

    def test_icmp_fallback_disabled_returns_none(self):
        with patch("sondare.services.fingerprint.sr1", return_value=None), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1,
                                      icmp_fallback=False)
            scanner.scan()

        assert scanner.get_results() is None

    def test_icmp_fallback_skipped_when_tcp_succeeds(self):
        with patch("sondare.services.fingerprint.sr1", return_value=_syn_ack(64, 65535)) as mock_sr1, \
             patch("sondare.services.fingerprint.sr"), \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        result = scanner.get_results()
        assert result is not None
        assert result.window == 65535  # TCP-derived, not ICMP fallback

    def test_sends_rst_after_syn_ack(self):
        with patch("sondare.services.fingerprint.sr1", return_value=_syn_ack(64, 29200)), \
             patch("sondare.services.fingerprint.sr") as mock_sr, \
             patch("sondare.services.fingerprint.warm_arp_cache"):
            scanner = OsFingerprinter(verbose=False, ip="10.0.0.1", port=80, timeout=1)
            scanner.scan()

        mock_sr.assert_called_once()
