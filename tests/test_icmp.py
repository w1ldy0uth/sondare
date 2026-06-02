from unittest.mock import patch, MagicMock
from scapy.all import IP, ICMP
from sondare.services.icmp import Ping, _is_ipv6


def _make_ping_scanner(net_mocks, ip="192.168.1.1"):
    addrs, stats = net_mocks(ip=ip)
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats):
        return Ping(verbose=False, timeout=1)


def _icmp_reply(icmp_type: int):
    layer = MagicMock()
    layer.type = icmp_type
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.getlayer.return_value = layer
    return pkt


class TestScan:
    def test_echo_reply_adds_host(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        sent = IP(dst="192.168.1.2") / ICMP()
        with patch("sondare.services.icmp.sr", return_value=([(sent, _icmp_reply(0))], [])), \
             patch("builtins.print"):
            scanner.scan()
        assert "192.168.1.2" in scanner.results

    def test_unreachable_does_not_add_host(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        sent = IP(dst="192.168.1.2") / ICMP()
        with patch("sondare.services.icmp.sr", return_value=([(sent, _icmp_reply(3))], [])), \
             patch("builtins.print"):
            scanner.scan()
        assert scanner.results == []

    def test_no_response_does_not_add_host(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        with patch("sondare.services.icmp.sr", return_value=([], [])), \
             patch("builtins.print"):
            scanner.scan()
        assert scanner.results == []

    def test_multiple_hosts_found(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        answered = [
            (IP(dst="192.168.1.2") / ICMP(), _icmp_reply(0)),
            (IP(dst="192.168.1.3") / ICMP(), _icmp_reply(0)),
        ]
        with patch("sondare.services.icmp.sr", return_value=(answered, [])), \
             patch("builtins.print"):
            scanner.scan()
        assert scanner.results == ["192.168.1.2", "192.168.1.3"]


class TestGetResults:
    def test_returns_empty_before_scan(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        assert scanner.get_results() == []


class TestIsIpv6:
    def test_ipv6_link_local(self):
        assert _is_ipv6("fe80::1") is True

    def test_ipv6_full(self):
        assert _is_ipv6("2001:db8::1") is True

    def test_ipv4(self):
        assert _is_ipv6("192.168.1.1") is False

    def test_invalid(self):
        assert _is_ipv6("not-an-ip") is False


class TestIpv6Ping:
    def _make_v6_reply(self, has_reply: bool = True):
        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda cls: has_reply and cls.__name__ == "ICMPv6EchoReply"
        return pkt

    def test_ipv6_target_sends_icmpv6(self):
        with patch("sondare.services.icmp.sr1", return_value=None) as mock_sr1, \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        from scapy.all import IPv6, ICMPv6EchoRequest
        mock_sr1.assert_called_once()
        pkt = mock_sr1.call_args[0][0]
        assert pkt.haslayer(IPv6)
        assert pkt.haslayer(ICMPv6EchoRequest)

    def test_ipv6_echo_reply_adds_host(self):
        target = "fe80::dead:beef"
        with patch("sondare.services.icmp.sr1", return_value=self._make_v6_reply(True)), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target=target)
            scanner.scan()

        assert scanner.get_results() == [target]

    def test_ipv6_no_reply_empty_results(self):
        with patch("sondare.services.icmp.sr1", return_value=None), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        assert scanner.get_results() == []

    def test_ipv6_non_echo_reply_ignored(self):
        with patch("sondare.services.icmp.sr1", return_value=self._make_v6_reply(False)), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        assert scanner.get_results() == []

    def test_ipv6_does_not_call_sr(self):
        with patch("sondare.services.icmp.sr1", return_value=None), \
             patch("sondare.services.icmp.sr") as mock_sr, \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        mock_sr.assert_not_called()

    def test_ipv4_target_uses_icmpv4_not_sr1(self, net_mocks):
        addrs, stats = net_mocks(ip="192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, target="192.168.1.2")

        with patch("sondare.services.icmp.sr", return_value=([], [])) as mock_sr, \
             patch("sondare.services.icmp.sr1") as mock_sr1, \
             patch("builtins.print"):
            scanner.scan()

        mock_sr.assert_called_once()
        mock_sr1.assert_not_called()


class TestResolveHostname:
    def test_get_hostnames_empty_without_flag(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        assert scanner.get_hostnames() == {}

    def test_scan_resolves_hostnames_when_flag_set(self, net_mocks):
        addrs, stats = net_mocks(ip="192.168.1.1")
        resolved = {"192.168.1.2": "desktop.local"}
        sent = IP(dst="192.168.1.2") / ICMP()

        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, resolve_hostname=True)

        with patch("sondare.services.icmp.sr", return_value=([(sent, _icmp_reply(0))], [])), \
             patch("sondare.services.icmp.resolve_hostnames", return_value=resolved) as mock_resolve, \
             patch("builtins.print"):
            scanner.scan()

        mock_resolve.assert_called_once_with(scanner.results)
        assert scanner.get_hostnames() == resolved
