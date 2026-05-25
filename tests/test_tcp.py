from unittest.mock import patch, MagicMock, call
from netscan.services.tcp import Port


def _make_scanner(**kwargs):
    defaults = dict(verbose=False, ip="10.0.0.1", port_begin=80, port_end=80, timeout=1, threads=1, retries=2)
    defaults.update(kwargs)
    return Port(**defaults)


def _tcp_response(flags: int):
    layer = MagicMock()
    layer.flags = flags
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.getlayer.return_value = layer
    return pkt


SYN_ACK = 0x12
RST = 0x04


class TestCheckPort:
    def test_syn_ack_adds_open_port(self):
        scanner = _make_scanner()
        with patch("netscan.services.tcp.sr1", return_value=_tcp_response(SYN_ACK)), \
             patch("netscan.services.tcp.sr"), \
             patch("random.randint", return_value=54321):
            scanner.check_port(80)

        assert "10.0.0.1:80" in scanner.open_ports

    def test_syn_ack_sends_rst(self):
        scanner = _make_scanner()
        with patch("netscan.services.tcp.sr1", return_value=_tcp_response(SYN_ACK)), \
             patch("netscan.services.tcp.sr") as mock_sr, \
             patch("random.randint", return_value=54321):
            scanner.check_port(80)

        mock_sr.assert_called_once()
        rst_pkt = mock_sr.call_args.args[0]
        assert rst_pkt.getlayer is not None  # basic sanity

    def test_rst_does_not_add_port(self):
        scanner = _make_scanner()
        with patch("netscan.services.tcp.sr1", return_value=_tcp_response(RST)), \
             patch("netscan.services.tcp.sr"):
            scanner.check_port(80)

        assert scanner.open_ports == []

    def test_rst_stops_retrying(self):
        scanner = _make_scanner(retries=3)
        with patch("netscan.services.tcp.sr1", return_value=_tcp_response(RST)) as mock_sr1, \
             patch("netscan.services.tcp.sr"):
            scanner.check_port(80)

        assert mock_sr1.call_count == 1  # returned after first RST, no retries

    def test_none_response_retries_up_to_limit(self):
        scanner = _make_scanner(retries=2)
        with patch("netscan.services.tcp.sr1", return_value=None) as mock_sr1, \
             patch("netscan.services.tcp.sr"):
            scanner.check_port(80)

        assert mock_sr1.call_count == 3  # initial + 2 retries
        assert scanner.open_ports == []

    def test_none_then_syn_ack_adds_port(self):
        scanner = _make_scanner(retries=2)
        responses = [None, None, _tcp_response(SYN_ACK)]
        with patch("netscan.services.tcp.sr1", side_effect=responses), \
             patch("netscan.services.tcp.sr"), \
             patch("random.randint", return_value=54321):
            scanner.check_port(80)

        assert "10.0.0.1:80" in scanner.open_ports


class TestGetResults:
    def test_returns_empty_before_scan(self):
        scanner = _make_scanner()
        assert scanner.get_results() == []

    def test_returns_open_ports_after_check(self):
        scanner = _make_scanner(port_begin=79, port_end=81)
        with patch("netscan.services.tcp.sr1", side_effect=[
            _tcp_response(SYN_ACK),  # port 79 open
            _tcp_response(RST),      # port 80 closed
            _tcp_response(SYN_ACK),  # port 81 open
        ]), patch("netscan.services.tcp.sr"), \
           patch("random.randint", return_value=54321):
            scanner.check_port(79)
            scanner.check_port(80)
            scanner.check_port(81)

        assert set(scanner.get_results()) == {"10.0.0.1:79", "10.0.0.1:81"}
