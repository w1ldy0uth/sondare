from unittest.mock import patch, MagicMock
from sondare.services.icmp import Ping
from sondare.utils.network import is_ipv6_address as _is_ipv6


def _make_ping_scanner(net_mocks, ip="192.168.1.1"):
    addrs, stats = net_mocks(ip=ip)
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats):
        return Ping(verbose=False, timeout=1)


class TestScan:
    def test_echo_reply_adds_host(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        with patch("sondare.services.icmp._sondare.icmp_sweep_v4", return_value=["192.168.1.2"]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner.scan()
        assert "192.168.1.2" in scanner.results

    def test_unreachable_does_not_add_host(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        with patch("sondare.services.icmp._sondare.icmp_sweep_v4", return_value=[]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner.scan()
        assert scanner.results == []

    def test_no_response_does_not_add_host(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        with patch("sondare.services.icmp._sondare.icmp_sweep_v4", return_value=[]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner.scan()
        assert scanner.results == []

    def test_multiple_hosts_found(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        with patch("sondare.services.icmp._sondare.icmp_sweep_v4", return_value=["192.168.1.2", "192.168.1.3"]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
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
    def test_ipv6_target_calls_rust_sweep_v6(self):
        with patch("sondare.services.icmp._sondare.icmp_sweep_v6", return_value=["fe80::1"]) as mock_v6, \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        mock_v6.assert_called_once()
        assert scanner.get_results() == ["fe80::1"]

    def test_ipv6_no_reply_empty_results(self):
        with patch("sondare.services.icmp._sondare.icmp_sweep_v6", return_value=[]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        assert scanner.get_results() == []

    def test_ipv6_does_not_call_icmp_sweep_v4(self):
        with patch("sondare.services.icmp._sondare.icmp_sweep_v6", return_value=[]), \
             patch("sondare.services.icmp._sondare.icmp_sweep_v4") as mock_v4, \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, target="fe80::1")
            scanner.scan()

        mock_v4.assert_not_called()

    def test_ipv4_target_uses_icmp_sweep_v4(self, net_mocks):
        addrs, stats = net_mocks(ip="192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, target="192.168.1.2")

        with patch("sondare.services.icmp._sondare.icmp_sweep_v4", return_value=[]) as mock_sweep, \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner.scan()

        mock_sweep.assert_called_once()

    def test_ipv4_target_only_scans_that_host(self, net_mocks):
        addrs, stats = net_mocks(ip="192.168.1.1")
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, target="192.168.1.2")

        assert scanner.hosts == ["192.168.1.2"]


class TestIpv6MulticastScan:
    def test_ipv6_flag_calls_multicast_v6(self):
        with patch("sondare.services.icmp._sondare.icmp_multicast_v6", return_value=["fe80::aaaa", "fe80::bbbb"]) as mock_mc, \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=3, ipv6=True)
            scanner.scan()

        mock_mc.assert_called_once()
        assert set(scanner.get_results()) == {"fe80::aaaa", "fe80::bbbb"}

    def test_multicast_empty_results(self):
        with patch("sondare.services.icmp._sondare.icmp_multicast_v6", return_value=[]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            scanner = Ping(verbose=False, timeout=1, ipv6=True)
            scanner.scan()

        assert scanner.get_results() == []

    def test_ipv6_flag_does_not_call_icmp_sweep_v4(self):
        with patch("sondare.services.icmp._sondare.icmp_multicast_v6", return_value=[]), \
             patch("sondare.services.icmp._sondare.icmp_sweep_v4") as mock_v4, \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("builtins.print"):
            Ping(verbose=False, timeout=1, ipv6=True).scan()

        mock_v4.assert_not_called()

    def test_ipv6_flag_hosts_list_is_empty(self):
        scanner = Ping(verbose=False, timeout=1, ipv6=True)
        assert scanner.hosts == []


class TestResolveHostname:
    def test_get_hostnames_empty_without_flag(self, net_mocks):
        scanner = _make_ping_scanner(net_mocks)
        assert scanner.get_hostnames() == {}

    def test_scan_resolves_hostnames_when_flag_set(self, net_mocks):
        addrs, stats = net_mocks(ip="192.168.1.1")
        resolved = {"192.168.1.2": "desktop.local"}

        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            scanner = Ping(verbose=False, timeout=1, resolve_hostname=True)

        with patch("sondare.services.icmp._sondare.icmp_sweep_v4", return_value=["192.168.1.2"]), \
             patch("sondare.services.icmp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.icmp.resolve_hostnames", return_value=resolved) as mock_resolve, \
             patch("builtins.print"):
            scanner.scan()

        mock_resolve.assert_called_once_with(scanner.results)
        assert scanner.get_hostnames() == resolved
