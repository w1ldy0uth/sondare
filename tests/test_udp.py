from unittest.mock import patch, MagicMock
from sondare.services.udp import Udp
from sondare.models import Port


def _make_scanner(**kwargs):
    defaults = dict(verbose=False, ip="10.0.0.1", port_begin=53, port_end=53, timeout=1, threads=1, retries=2)
    defaults.update(kwargs)
    return Udp(**defaults)


def _icmp_response(icmp_type: int, icmp_code: int):
    icmp_layer = MagicMock()
    icmp_layer.type = icmp_type
    icmp_layer.code = icmp_code
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.getlayer.return_value = icmp_layer
    return pkt


def _udp_response():
    pkt = MagicMock()
    pkt.haslayer.return_value = False  # no ICMP layer
    return pkt


PORT_UNREACHABLE_TYPE = 3
PORT_UNREACHABLE_CODE = 3


class TestCheckPort:
    def test_icmp_port_unreachable_marks_closed(self):
        scanner = _make_scanner()
        with patch("sondare.services.udp.sr1", return_value=_icmp_response(PORT_UNREACHABLE_TYPE, PORT_UNREACHABLE_CODE)):
            scanner.check_port(53)

        assert scanner._open_ports == []

    def test_icmp_other_type_marks_open(self):
        scanner = _make_scanner()
        with patch("sondare.services.udp.sr1", return_value=_icmp_response(3, 1)):  # net unreachable, not port
            scanner.check_port(53)

        assert Port(ip="10.0.0.1", port=53) in scanner._open_ports

    def test_udp_response_marks_open(self):
        scanner = _make_scanner()
        with patch("sondare.services.udp.sr1", return_value=_udp_response()):
            scanner.check_port(53)

        assert Port(ip="10.0.0.1", port=53) in scanner._open_ports

    def test_no_response_exhausts_retries_then_marks_open_filtered(self):
        scanner = _make_scanner(retries=2)
        with patch("sondare.services.udp.sr1", return_value=None) as mock_sr1:
            scanner.check_port(53)

        assert mock_sr1.call_count == 3  # initial + 2 retries
        assert Port(ip="10.0.0.1", port=53) in scanner._open_ports

    def test_no_response_does_not_add_port_until_retries_exhausted(self):
        scanner = _make_scanner(retries=2)
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return None
            return _icmp_response(PORT_UNREACHABLE_TYPE, PORT_UNREACHABLE_CODE)

        with patch("sondare.services.udp.sr1", side_effect=side_effect):
            scanner.check_port(53)

        assert scanner._open_ports == []  # closed on last attempt

    def test_icmp_unreachable_stops_retrying(self):
        scanner = _make_scanner(retries=3)
        with patch("sondare.services.udp.sr1", return_value=_icmp_response(PORT_UNREACHABLE_TYPE, PORT_UNREACHABLE_CODE)) as mock_sr1:
            scanner.check_port(53)

        assert mock_sr1.call_count == 1
        assert scanner._open_ports == []

    def test_udp_response_stops_retrying(self):
        scanner = _make_scanner(retries=3)
        with patch("sondare.services.udp.sr1", return_value=_udp_response()) as mock_sr1:
            scanner.check_port(53)

        assert mock_sr1.call_count == 1
        assert Port(ip="10.0.0.1", port=53) in scanner._open_ports


class TestGetResults:
    def test_returns_empty_before_scan(self):
        scanner = _make_scanner()
        assert scanner.get_results() == []

    def test_get_results_after_scan_includes_service_name(self):
        scanner = _make_scanner(port_begin=53, port_end=53)
        with patch("sondare.services.udp.sr1", return_value=None), \
             patch("sondare.services.udp.warm_arp_cache"):
            scanner.scan()

        assert scanner.get_results() == [Port("10.0.0.1", 53, service="domain")]

    def test_results_sorted_by_port(self):
        scanner = _make_scanner(port_begin=53, port_end=69)
        with patch("sondare.services.udp.sr1", return_value=None), \
             patch("sondare.services.udp.warm_arp_cache"):
            scanner.scan()

        ports = [p.port for p in scanner.get_results()]
        assert ports == sorted(ports)


class TestIpv6Udp:
    def test_ipv6_target_uses_ipv6_layer(self):
        from scapy.all import IPv6
        scanner = Udp(verbose=False, ip="fe80::1", port_begin=53, port_end=53,
                      timeout=1, threads=1, retries=0)
        with patch("sondare.services.udp.sr1", return_value=None) as mock_sr1, \
             patch("sondare.services.udp.warm_arp_cache"):
            scanner.check_port(53)

        pkt = mock_sr1.call_args[0][0]
        assert pkt.haslayer(IPv6)

    def test_ipv6_port_unreachable_closes_port(self):
        from unittest.mock import patch, MagicMock
        icmpv6 = MagicMock()
        icmpv6.code = 4
        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda cls: cls.__name__ == "ICMPv6DestUnreach"
        pkt.getlayer.return_value = icmpv6

        scanner = Udp(verbose=False, ip="fe80::1", port_begin=53, port_end=53,
                      timeout=1, threads=1, retries=0)
        with patch("sondare.services.udp.sr1", return_value=pkt), \
             patch("sondare.services.udp.warm_arp_cache"):
            scanner.check_port(53)

        assert scanner._open_ports == []

    def test_ipv6_scan_skips_arp_cache(self):
        scanner = Udp(verbose=False, ip="fe80::1", port_begin=53, port_end=53,
                      timeout=1, threads=1, retries=0)
        with patch("sondare.services.udp.sr1", return_value=None), \
             patch("sondare.services.udp.warm_arp_cache") as mock_arp:
            scanner.scan()

        mock_arp.assert_not_called()
