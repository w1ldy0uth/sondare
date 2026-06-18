from unittest.mock import patch, MagicMock
from sondare.services.udp import Udp
from sondare.models import Port


def _make_scanner(**kwargs):
    defaults = dict(verbose=False, ip="10.0.0.1", port_begin=53, port_end=53, timeout=1, threads=1, retries=2)
    defaults.update(kwargs)
    return Udp(**defaults)


def _ipv4_patches(open_ports):
    return [
        patch("sondare.services.udp._sondare.udp_scan_v4", return_value=open_ports),
        patch("sondare.services.udp.warm_arp_cache"),
        patch("sondare.services.udp.get_network_interface", return_value="eth0"),
    ]


class TestScanIpv4:
    def test_scan_calls_rust_backend(self):
        scanner = _make_scanner()
        patches = _ipv4_patches([53])
        with patches[0] as mock_rust, patches[1], patches[2]:
            scanner.scan()
        mock_rust.assert_called_once()

    def test_open_port_recorded(self):
        scanner = _make_scanner()
        patches = _ipv4_patches([53])
        with patches[0], patches[1], patches[2]:
            scanner.scan()
        assert 53 in [p.port for p in scanner.get_results()]

    def test_no_open_ports(self):
        scanner = _make_scanner()
        patches = _ipv4_patches([])
        with patches[0], patches[1], patches[2]:
            scanner.scan()
        assert scanner.get_results() == []


class TestGetResults:
    def test_returns_empty_before_scan(self):
        scanner = _make_scanner()
        assert scanner.get_results() == []

    def test_get_results_after_scan_includes_service_name(self):
        scanner = _make_scanner(port_begin=53, port_end=53)
        patches = _ipv4_patches([53])
        with patches[0], patches[1], patches[2]:
            scanner.scan()
        assert scanner.get_results() == [Port("10.0.0.1", 53, service="domain")]

    def test_results_sorted_by_port(self):
        scanner = _make_scanner(port_begin=53, port_end=69)
        patches = _ipv4_patches(list(range(69, 52, -1)))
        with patches[0], patches[1], patches[2]:
            scanner.scan()
        ports = [p.port for p in scanner.get_results()]
        assert ports == sorted(ports)


class TestIpv6Udp:
    def test_ipv6_scan_calls_rust_v6_backend(self):
        scanner = Udp(verbose=False, ip="fe80::1", port_begin=53, port_end=53,
                      timeout=1, threads=1, retries=0)
        with patch("sondare.services.udp._sondare.udp_scan_v6", return_value=[53]) as mock_v6, \
             patch("sondare.services.udp.get_network_interface", return_value="eth0"):
            scanner.scan()
        mock_v6.assert_called_once()
        assert 53 in [p.port for p in scanner.get_results()]

    def test_ipv6_scan_does_not_call_arp_cache(self):
        scanner = Udp(verbose=False, ip="fe80::1", port_begin=53, port_end=53,
                      timeout=1, threads=1, retries=0)
        with patch("sondare.services.udp._sondare.udp_scan_v6", return_value=[]), \
             patch("sondare.services.udp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.udp.warm_arp_cache") as mock_arp:
            scanner.scan()
        mock_arp.assert_not_called()

    def test_ipv4_scan_calls_arp_cache(self):
        scanner = Udp(verbose=False, ip="192.168.1.1", port_begin=53, port_end=53,
                      timeout=1, threads=1, retries=0)
        patches = _ipv4_patches([])
        with patches[0], patches[1] as mock_arp, patches[2]:
            scanner.scan()
        mock_arp.assert_called_once_with("192.168.1.1")
