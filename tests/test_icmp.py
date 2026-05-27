from unittest.mock import patch, MagicMock
from scapy.all import IP, ICMP
from sondare.services.icmp import Ping


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
