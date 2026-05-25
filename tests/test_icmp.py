import socket
from unittest.mock import patch, MagicMock
from netscan.services.icmp import Ping


def _make_net_mocks(ip="192.168.1.1"):
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = ip
    addr.netmask = "255.255.255.0"
    stat = MagicMock()
    stat.isup = True
    return {"eth0": [addr]}, {"eth0": stat}


def _make_ping_scanner(ip="192.168.1.0"):
    addrs, stats = _make_net_mocks(ip=ip + ".1" if "/" not in ip else ip)
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats):
        return Ping(verbose=False, timeout=1, threads=1)


def _icmp_reply(icmp_type: int):
    layer = MagicMock()
    layer.type = icmp_type
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.getlayer.return_value = layer
    return pkt


class TestCheckHost:
    def test_echo_reply_adds_host(self):
        addrs, stats = _make_net_mocks("192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, threads=1)

        with patch("netscan.services.icmp.sr1", return_value=_icmp_reply(0)), \
             patch("builtins.print"):
            scanner.check_host("192.168.1.2")

        assert "192.168.1.2" in scanner.results

    def test_unreachable_does_not_add_host(self):
        addrs, stats = _make_net_mocks("192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, threads=1)

        with patch("netscan.services.icmp.sr1", return_value=_icmp_reply(3)), \
             patch("builtins.print"):
            scanner.check_host("192.168.1.2")

        assert scanner.results == []

    def test_no_response_does_not_add_host(self):
        addrs, stats = _make_net_mocks("192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, threads=1)

        with patch("netscan.services.icmp.sr1", return_value=None), \
             patch("builtins.print"):
            scanner.check_host("192.168.1.2")

        assert scanner.results == []

    def test_increments_done_counter(self):
        addrs, stats = _make_net_mocks("192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, threads=1)

        with patch("netscan.services.icmp.sr1", return_value=None), \
             patch("builtins.print"):
            scanner.check_host("192.168.1.2")
            scanner.check_host("192.168.1.3")

        assert scanner._done == 2


class TestGetResults:
    def test_returns_empty_before_scan(self):
        addrs, stats = _make_net_mocks("192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, threads=1)
        assert scanner.get_results() == []
