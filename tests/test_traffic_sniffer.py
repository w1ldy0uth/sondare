from unittest.mock import MagicMock, patch
from netscan.monitors.traffic_sniffer import TrafficSniffer, _tcp_info, _udp_info, _icmp_info, _arp_info


def _make_ip(src="192.168.1.1", dst="192.168.1.2"):
    ip = MagicMock()
    ip.src, ip.dst = src, dst
    return ip


def _sniffer(bpf_filter=None) -> TrafficSniffer:
    return TrafficSniffer(verbose=False, bpf_filter=bpf_filter)


class TestPacketFormatters:
    def test_tcp_info_extracts_src_dst_and_flags(self):
        pkt = MagicMock()
        pkt.getlayer.side_effect = lambda cls: _make_ip() if cls.__name__ == "IP" else MagicMock(sport=12345, dport=80, flags=MagicMock(__int__=lambda s: 0x02))
        # Build real-ish mocks
        ip = MagicMock(); ip.src = "10.0.0.1"; ip.dst = "10.0.0.2"
        tcp = MagicMock(); tcp.sport = 54321; tcp.dport = 80; tcp.flags = 0x02

        class FakePkt:
            def getlayer(self, cls):
                from scapy.all import IP, TCP
                return ip if cls is IP else tcp

        src, dst, info = _tcp_info(FakePkt())
        assert src == "10.0.0.1:54321"
        assert dst == "10.0.0.2:80"
        assert info == "SYN"

    def test_tcp_syn_ack_flag(self):
        ip = MagicMock(); ip.src = "1.2.3.4"; ip.dst = "5.6.7.8"
        tcp = MagicMock(); tcp.sport = 80; tcp.dport = 54321; tcp.flags = 0x12

        class FakePkt:
            def getlayer(self, cls):
                from scapy.all import IP
                return ip if cls is IP else tcp

        _, _, info = _tcp_info(FakePkt())
        assert info == "SYN-ACK"

    def test_tcp_unknown_flags_hex(self):
        ip = MagicMock(); ip.src = "1.1.1.1"; ip.dst = "2.2.2.2"
        tcp = MagicMock(); tcp.sport = 1; tcp.dport = 2; tcp.flags = 0xFF

        class FakePkt:
            def getlayer(self, cls):
                from scapy.all import IP
                return ip if cls is IP else tcp

        _, _, info = _tcp_info(FakePkt())
        assert "0xff" in info

    def test_udp_info_extracts_ports(self):
        ip = MagicMock(); ip.src = "10.0.0.1"; ip.dst = "8.8.8.8"
        udp = MagicMock(); udp.sport = 12345; udp.dport = 53

        class FakePkt:
            def getlayer(self, cls):
                from scapy.all import IP
                return ip if cls is IP else udp

        src, dst, info = _udp_info(FakePkt())
        assert src == "10.0.0.1:12345"
        assert dst == "8.8.8.8:53"
        assert info == ""

    def test_icmp_echo_request(self):
        ip = MagicMock(); ip.src = "10.0.0.1"; ip.dst = "10.0.0.2"
        icmp = MagicMock(); icmp.type = 8

        class FakePkt:
            def getlayer(self, cls):
                from scapy.all import IP
                return ip if cls is IP else icmp

        src, dst, info = _icmp_info(FakePkt())
        assert src == "10.0.0.1"
        assert info == "Echo request"

    def test_icmp_echo_reply(self):
        ip = MagicMock(); ip.src = "10.0.0.2"; ip.dst = "10.0.0.1"
        icmp = MagicMock(); icmp.type = 0

        class FakePkt:
            def getlayer(self, cls):
                from scapy.all import IP
                return ip if cls is IP else icmp

        _, _, info = _icmp_info(FakePkt())
        assert info == "Echo reply"

    def test_arp_who_has(self):
        arp = MagicMock(); arp.op = 1; arp.psrc = "10.0.0.1"; arp.pdst = "10.0.0.254"

        class FakePkt:
            def getlayer(self, _cls):
                return arp

        src, dst, info = _arp_info(FakePkt())
        assert "who has" in info
        assert "10.0.0.254" in info

    def test_arp_is_at(self):
        arp = MagicMock(); arp.op = 2; arp.psrc = "10.0.0.254"; arp.pdst = "10.0.0.1"
        arp.hwsrc = "aa:bb:cc:dd:ee:ff"

        class FakePkt:
            def getlayer(self, _cls):
                return arp

        _, _, info = _arp_info(FakePkt())
        assert "is at" in info
        assert "aa:bb:cc:dd:ee:ff" in info


class TestTrafficSniffer:
    def _make_tcp_pkt(self, src="10.0.0.1", sport=54321, dst="10.0.0.2", dport=80, flags=0x02):
        from scapy.all import IP, TCP, ARP, UDP, ICMP
        pkt = MagicMock()
        ip = MagicMock(); ip.src = src; ip.dst = dst
        tcp = MagicMock(); tcp.sport = sport; tcp.dport = dport; tcp.flags = flags

        def haslayer(cls):
            return cls in (IP, TCP)

        def getlayer(cls):
            return ip if cls is IP else tcp

        pkt.haslayer = haslayer
        pkt.getlayer = getlayer
        return pkt

    def _make_arp_pkt(self, op=1, psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="aa:bb:cc:dd:ee:ff"):
        from scapy.all import IP, TCP, ARP, UDP, ICMP
        pkt = MagicMock()
        arp = MagicMock(); arp.op = op; arp.psrc = psrc; arp.pdst = pdst; arp.hwsrc = hwsrc

        def haslayer(cls):
            return cls is ARP

        pkt.haslayer = haslayer
        pkt.getlayer = lambda _: arp
        return pkt

    def test_handle_tcp_prints_line(self, capsys):
        s = _sniffer()
        s._handle(self._make_tcp_pkt())
        out = capsys.readouterr().out
        assert "TCP" in out
        assert "10.0.0.1" in out

    def test_handle_arp_prints_line(self, capsys):
        s = _sniffer()
        s._handle(self._make_arp_pkt())
        out = capsys.readouterr().out
        assert "ARP" in out

    def test_handle_unknown_proto_prints_nothing(self, capsys):
        from scapy.all import IP, TCP, ARP, UDP, ICMP
        pkt = MagicMock()
        pkt.haslayer = lambda cls: False
        s = _sniffer()
        s._handle(pkt)
        assert capsys.readouterr().out == ""

    def test_bpf_filter_stored(self):
        s = TrafficSniffer(verbose=False, bpf_filter="tcp port 80")
        assert s._filter == "tcp port 80"

    def test_no_filter_defaults_to_empty_string(self):
        s = TrafficSniffer(verbose=False, bpf_filter=None)
        assert s._filter == ""

    def test_sniff_passes_filter_to_scapy(self):
        s = _sniffer(bpf_filter="udp")
        with patch("netscan.monitors.traffic_sniffer.get_network_interface", return_value="en0"), \
             patch("netscan.monitors.traffic_sniffer.sniff") as mock_sniff:
            s.sniff()
        mock_sniff.assert_called_once()
        assert mock_sniff.call_args.kwargs["filter"] == "udp"

    def test_sniff_uses_correct_iface(self):
        s = _sniffer()
        with patch("netscan.monitors.traffic_sniffer.get_network_interface", return_value="eth0"), \
             patch("netscan.monitors.traffic_sniffer.sniff") as mock_sniff:
            s.sniff()
        assert mock_sniff.call_args.kwargs["iface"] == "eth0"

    def test_sniff_no_promisc(self):
        s = _sniffer()
        with patch("netscan.monitors.traffic_sniffer.get_network_interface", return_value="en0"), \
             patch("netscan.monitors.traffic_sniffer.sniff") as mock_sniff:
            s.sniff()
        assert mock_sniff.call_args.kwargs["promisc"] is False
