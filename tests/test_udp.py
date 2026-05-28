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

        assert scanner.open_ports == []

    def test_icmp_other_type_marks_open(self):
        scanner = _make_scanner()
        with patch("sondare.services.udp.sr1", return_value=_icmp_response(3, 1)):  # net unreachable, not port
            scanner.check_port(53)

        assert Port(ip="10.0.0.1", port=53) in scanner.open_ports

    def test_udp_response_marks_open(self):
        scanner = _make_scanner()
        with patch("sondare.services.udp.sr1", return_value=_udp_response()):
            scanner.check_port(53)

        assert Port(ip="10.0.0.1", port=53) in scanner.open_ports

    def test_no_response_exhausts_retries_then_marks_open_filtered(self):
        scanner = _make_scanner(retries=2)
        with patch("sondare.services.udp.sr1", return_value=None) as mock_sr1:
            scanner.check_port(53)

        assert mock_sr1.call_count == 3  # initial + 2 retries
        assert Port(ip="10.0.0.1", port=53) in scanner.open_ports

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

        assert scanner.open_ports == []  # closed on last attempt

    def test_icmp_unreachable_stops_retrying(self):
        scanner = _make_scanner(retries=3)
        with patch("sondare.services.udp.sr1", return_value=_icmp_response(PORT_UNREACHABLE_TYPE, PORT_UNREACHABLE_CODE)) as mock_sr1:
            scanner.check_port(53)

        assert mock_sr1.call_count == 1
        assert scanner.open_ports == []

    def test_udp_response_stops_retrying(self):
        scanner = _make_scanner(retries=3)
        with patch("sondare.services.udp.sr1", return_value=_udp_response()) as mock_sr1:
            scanner.check_port(53)

        assert mock_sr1.call_count == 1
        assert Port(ip="10.0.0.1", port=53) in scanner.open_ports


class TestGetResults:
    def test_returns_empty_before_scan(self):
        scanner = _make_scanner()
        assert scanner.get_results() == []

    def test_returns_open_filtered_ports_after_check(self):
        scanner = _make_scanner(port_begin=53, port_end=69)
        responses = {
            53: None,                                                            # open|filtered
            54: _icmp_response(PORT_UNREACHABLE_TYPE, PORT_UNREACHABLE_CODE),   # closed
            69: _udp_response(),                                                 # open
        }

        for port, rsp in responses.items():
            with patch("sondare.services.udp.sr1", return_value=rsp):
                scanner.check_port(port)

        assert set(scanner.get_results()) == {Port("10.0.0.1", 53, service="domain"), Port("10.0.0.1", 69, service="tftp")}
