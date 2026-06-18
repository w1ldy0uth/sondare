import struct
from unittest.mock import patch
from sondare.monitors.traffic_sniffer import TrafficSniffer, _parse_packet


def _make_ipv4_frame(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    """Build Ethernet+IPv4+payload frame."""
    src_ip = bytes(int(b) for b in src.split("."))
    dst_ip = bytes(int(b) for b in dst.split("."))
    ihl = 5
    ip_len = ihl * 4 + len(payload)
    frame = bytearray(14 + ihl * 4 + len(payload))
    struct.pack_into("!H", frame, 12, 0x0800)
    frame[14] = (4 << 4) | ihl
    struct.pack_into("!H", frame, 14 + 2, ip_len)
    frame[14 + 9] = proto
    frame[14 + 12 : 14 + 16] = src_ip
    frame[14 + 16 : 14 + 20] = dst_ip
    frame[14 + ihl * 4 :] = payload
    return bytes(frame)


def _tcp_payload(sport: int, dport: int, flags: int) -> bytes:
    p = bytearray(20)
    struct.pack_into("!HH", p, 0, sport, dport)
    p[12] = 5 << 4  # data offset
    p[13] = flags
    return bytes(p)


def _udp_payload(sport: int, dport: int) -> bytes:
    p = bytearray(8)
    struct.pack_into("!HH", p, 0, sport, dport)
    struct.pack_into("!H", p, 4, 8)
    return bytes(p)


def _icmp_payload(icmp_type: int) -> bytes:
    return bytes([icmp_type, 0, 0, 0, 0, 0, 0, 0])


def _arp_frame(op: int, spa: str, tpa: str, sha: str = "aa:bb:cc:dd:ee:ff") -> bytes:
    mac_bytes = bytes(int(b, 16) for b in sha.split(":"))
    spa_bytes = bytes(int(b) for b in spa.split("."))
    tpa_bytes = bytes(int(b) for b in tpa.split("."))
    frame = bytearray(42)
    struct.pack_into("!H", frame, 12, 0x0806)
    struct.pack_into("!HHBBH", frame, 14, 1, 0x0800, 6, 4, op)
    frame[22:28] = mac_bytes
    frame[28:32] = spa_bytes
    frame[38:42] = tpa_bytes
    return bytes(frame)


def _sniffer(bpf_filter=None) -> TrafficSniffer:
    return TrafficSniffer(verbose=False, bpf_filter=bpf_filter)


class TestParsePacket:
    def test_tcp_syn(self):
        raw = _make_ipv4_frame(6, "10.0.0.1", "10.0.0.2", _tcp_payload(54321, 80, 0x02))
        result = _parse_packet(raw)
        assert result is not None
        proto, src, dst, info = result
        assert proto == "TCP"
        assert src == "10.0.0.1:54321"
        assert dst == "10.0.0.2:80"
        assert info == "SYN"

    def test_tcp_syn_ack(self):
        raw = _make_ipv4_frame(6, "1.2.3.4", "5.6.7.8", _tcp_payload(80, 54321, 0x12))
        result = _parse_packet(raw)
        assert result[3] == "SYN-ACK"

    def test_tcp_unknown_flags(self):
        raw = _make_ipv4_frame(6, "1.1.1.1", "2.2.2.2", _tcp_payload(1, 2, 0xFF))
        result = _parse_packet(raw)
        assert "0xff" in result[3]

    def test_udp(self):
        raw = _make_ipv4_frame(17, "10.0.0.1", "8.8.8.8", _udp_payload(12345, 53))
        result = _parse_packet(raw)
        assert result is not None
        proto, src, dst, info = result
        assert proto == "UDP"
        assert src == "10.0.0.1:12345"
        assert dst == "8.8.8.8:53"

    def test_icmp_echo_request(self):
        raw = _make_ipv4_frame(1, "10.0.0.1", "10.0.0.2", _icmp_payload(8))
        result = _parse_packet(raw)
        assert result is not None
        assert result[0] == "ICMP"
        assert result[3] == "Echo request"

    def test_icmp_echo_reply(self):
        raw = _make_ipv4_frame(1, "10.0.0.2", "10.0.0.1", _icmp_payload(0))
        result = _parse_packet(raw)
        assert result[3] == "Echo reply"

    def test_arp_who_has(self):
        raw = _arp_frame(1, "10.0.0.1", "10.0.0.254")
        result = _parse_packet(raw)
        assert result is not None
        assert result[0] == "ARP"
        assert "who has" in result[3]
        assert "10.0.0.254" in result[3]

    def test_arp_is_at(self):
        raw = _arp_frame(2, "10.0.0.254", "10.0.0.1", sha="aa:bb:cc:dd:ee:ff")
        result = _parse_packet(raw)
        assert "is at" in result[3]
        assert "aa:bb:cc:dd:ee:ff" in result[3]

    def test_unknown_protocol_returns_none(self):
        raw = bytes(60)
        assert _parse_packet(raw) is None

    def test_too_short_returns_none(self):
        assert _parse_packet(b"\x00" * 5) is None


class TestTrafficSniffer:
    def test_handle_tcp_prints_line(self, capsys):
        s = _sniffer()
        raw = _make_ipv4_frame(6, "10.0.0.1", "10.0.0.2", _tcp_payload(54321, 80, 0x02))
        s._handle(raw)
        out = capsys.readouterr().out
        assert "TCP" in out
        assert "10.0.0.1" in out

    def test_handle_arp_prints_line(self, capsys):
        s = _sniffer()
        s._handle(_arp_frame(1, "10.0.0.1", "10.0.0.254"))
        out = capsys.readouterr().out
        assert "ARP" in out

    def test_handle_unknown_prints_nothing(self, capsys):
        s = _sniffer()
        s._handle(bytes(60))
        assert capsys.readouterr().out == ""

    def test_bpf_filter_stored(self):
        s = TrafficSniffer(verbose=False, bpf_filter="tcp port 80")
        assert s._filter == "tcp port 80"

    def test_no_filter_defaults_to_empty_string(self):
        s = TrafficSniffer(verbose=False, bpf_filter=None)
        assert s._filter == ""

    def test_sniff_calls_rust_backend(self):
        s = _sniffer(bpf_filter="udp")
        with patch("sondare.monitors.traffic_sniffer.get_network_interface", return_value="en0"), \
             patch("sondare.monitors.traffic_sniffer._sondare.sniff") as mock_sniff:
            s.sniff()
        mock_sniff.assert_called_once()
        args = mock_sniff.call_args[0]
        assert args[0] == "en0"
        assert args[1] == "udp"
