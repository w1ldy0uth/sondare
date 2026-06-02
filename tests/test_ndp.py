from unittest.mock import patch, MagicMock, call
from sondare.services.ndp import Ndp
from sondare.models import Host


def _echo_reply(src_ip: str, src_mac: str, is_reply: bool = True):
    """Builds a mock packet that looks like an ICMPv6 Echo Reply."""
    ipv6_layer = MagicMock()
    ipv6_layer.src = src_ip
    ether_layer = MagicMock()
    ether_layer.src = src_mac

    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda cls: is_reply and cls.__name__ == "ICMPv6EchoReply"
    pkt.__getitem__ = MagicMock(
        side_effect=lambda cls: ipv6_layer if cls.__name__ == "IPv6" else ether_layer
    )
    return pkt


def _scan(scanner, srp_pairs=None, ndp_cache=None, local_ip="fe80::1"):
    """Helper: runs scanner.scan() with all network calls mocked."""
    with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
         patch("sondare.services.ndp.get_ipv6_link_local", return_value=local_ip), \
         patch("sondare.services.ndp.srp", return_value=(srp_pairs or [], None)), \
         patch("sondare.services.ndp.read_ndp_cache", return_value=ndp_cache or {}), \
         patch("sondare.services.ndp.get_mac_vendor", return_value=None), \
         patch("builtins.print"):
        scanner.scan()


class TestNdpScan:
    def test_get_results_before_scan_returns_empty(self):
        scanner = Ndp(verbose=False, timeout=1)
        assert scanner.get_results() == []

    def test_scan_calls_srp_with_multicast_and_multi_flag(self):
        with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.ndp.get_ipv6_link_local", return_value="fe80::1"), \
             patch("sondare.services.ndp.srp", return_value=([], None)) as mock_srp, \
             patch("sondare.services.ndp.read_ndp_cache", return_value={}), \
             patch("builtins.print"):
            Ndp(verbose=False, timeout=3).scan()

        kwargs = mock_srp.call_args.kwargs
        assert kwargs["iface"] == "eth0"
        assert kwargs["timeout"] == 3
        assert kwargs["multi"] is True
        assert kwargs["verbose"] is False
        assert kwargs["promisc"] is False

    def test_returns_host_for_each_echo_reply(self):
        pairs = [
            (None, _echo_reply("fe80::aaaa", "aa:bb:cc:dd:ee:01")),
            (None, _echo_reply("fe80::bbbb", "aa:bb:cc:dd:ee:02")),
        ]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, srp_pairs=pairs)

        results = scanner.get_results()
        assert len(results) == 2
        ips = {h.ip for h in results}
        assert "fe80::aaaa" in ips
        assert "fe80::bbbb" in ips

    def test_non_echo_reply_packets_are_ignored(self):
        pairs = [
            (None, _echo_reply("fe80::aaaa", "aa:bb:cc:dd:ee:01", is_reply=False)),
        ]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, srp_pairs=pairs)
        assert scanner.get_results() == []

    def test_excludes_own_link_local_address(self):
        own = "fe80::dead:beef"
        pairs = [(None, _echo_reply(own, "aa:bb:cc:dd:ee:ff"))]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, srp_pairs=pairs, local_ip=own)
        assert scanner.get_results() == []

    def test_excludes_multicast_addresses_from_cache(self):
        cache = {
            "ff02::1": "33:33:00:00:00:01",
            "fe80::1111": "aa:bb:cc:dd:ee:ff",
        }
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, ndp_cache=cache)

        results = scanner.get_results()
        assert len(results) == 1
        assert results[0].ip == "fe80::1111"

    def test_merges_neighbor_cache_when_active_scan_empty(self):
        cache = {"fe80::cafe": "de:ad:be:ef:00:01"}
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, ndp_cache=cache)

        results = scanner.get_results()
        assert results == [Host(ip="fe80::cafe", mac="de:ad:be:ef:00:01")]

    def test_active_scan_entry_not_duplicated_by_cache(self):
        pairs = [(None, _echo_reply("fe80::cafe", "aa:bb:cc:dd:ee:01"))]
        cache = {"fe80::cafe": "11:22:33:44:55:66"}  # same IP, different MAC
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, srp_pairs=pairs, ndp_cache=cache)

        results = scanner.get_results()
        assert len(results) == 1
        assert results[0].mac == "aa:bb:cc:dd:ee:01"  # active scan MAC wins

    def test_results_are_sorted_by_ip(self):
        pairs = [
            (None, _echo_reply("fe80::cccc", "cc:cc:cc:cc:cc:cc")),
            (None, _echo_reply("fe80::aaaa", "aa:aa:aa:aa:aa:aa")),
            (None, _echo_reply("fe80::bbbb", "bb:bb:bb:bb:bb:bb")),
        ]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, srp_pairs=pairs)

        ips = [h.ip for h in scanner.get_results()]
        assert ips == sorted(ips)

    def test_resolve_hostname_populates_field(self):
        pairs = [(None, _echo_reply("fe80::1234", "aa:bb:cc:dd:ee:01"))]
        scanner = Ndp(verbose=False, timeout=1, resolve_hostname=True)

        with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.ndp.get_ipv6_link_local", return_value="fe80::1"), \
             patch("sondare.services.ndp.srp", return_value=(pairs, None)), \
             patch("sondare.services.ndp.read_ndp_cache", return_value={}), \
             patch("sondare.services.ndp.get_mac_vendor", return_value=None), \
             patch("sondare.services.ndp.resolve_hostnames",
                   return_value={"fe80::1234": "myhost.local"}) as mock_resolve, \
             patch("builtins.print"):
            scanner.scan()
            results = scanner.get_results()

        assert results[0].hostname == "myhost.local"
        mock_resolve.assert_called_once_with(["fe80::1234"])

    def test_vendor_looked_up_for_each_host(self):
        pairs = [(None, _echo_reply("fe80::1234", "aa:bb:cc:dd:ee:01"))]
        scanner = Ndp(verbose=False, timeout=1)

        with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.ndp.get_ipv6_link_local", return_value="fe80::1"), \
             patch("sondare.services.ndp.srp", return_value=(pairs, None)), \
             patch("sondare.services.ndp.read_ndp_cache", return_value={}), \
             patch("sondare.services.ndp.get_mac_vendor", return_value="Apple, Inc.") as mock_vendor, \
             patch("builtins.print"):
            scanner.scan()
            results = scanner.get_results()

        assert results[0].vendor == "Apple, Inc."
        mock_vendor.assert_called_once_with("aa:bb:cc:dd:ee:01")

    def test_scope_suffix_stripped_from_ip(self):
        # Some stacks return addresses with %iface scope suffix.
        pairs = [(None, _echo_reply("fe80::abcd%eth0", "aa:bb:cc:dd:ee:01"))]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, srp_pairs=pairs)

        results = scanner.get_results()
        assert results[0].ip == "fe80::abcd"
