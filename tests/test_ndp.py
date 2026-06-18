from unittest.mock import patch, MagicMock, call
from sondare.services.ndp import Ndp
from sondare.models import Host


def _scan(scanner, rust_pairs=None, ndp_cache=None):
    """Helper: runs scanner.scan() with all network calls mocked."""
    with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
         patch("sondare.services.ndp._sondare.ndp_sweep", return_value=rust_pairs or []), \
         patch("sondare.services.ndp.read_ndp_cache", return_value=ndp_cache or {}), \
         patch("sondare.services.ndp.get_mac_vendor", return_value=None), \
         patch("builtins.print"):
        scanner.scan()


class TestNdpScan:
    def test_get_results_before_scan_returns_empty(self):
        scanner = Ndp(verbose=False, timeout=1)
        assert scanner.get_results() == []

    def test_returns_host_for_each_echo_reply(self):
        pairs = [
            ("fe80::aaaa", "aa:bb:cc:dd:ee:01"),
            ("fe80::bbbb", "aa:bb:cc:dd:ee:02"),
        ]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, rust_pairs=pairs)

        results = scanner.get_results()
        assert len(results) == 2
        ips = {h.ip for h in results}
        assert "fe80::aaaa" in ips
        assert "fe80::bbbb" in ips

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
        pairs = [("fe80::cafe", "aa:bb:cc:dd:ee:01")]
        cache = {"fe80::cafe": "11:22:33:44:55:66"}
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, rust_pairs=pairs, ndp_cache=cache)

        results = scanner.get_results()
        assert len(results) == 1
        assert results[0].mac == "aa:bb:cc:dd:ee:01"

    def test_results_are_sorted_by_ip(self):
        pairs = [
            ("fe80::cccc", "cc:cc:cc:cc:cc:cc"),
            ("fe80::aaaa", "aa:aa:aa:aa:aa:aa"),
            ("fe80::bbbb", "bb:bb:bb:bb:bb:bb"),
        ]
        scanner = Ndp(verbose=False, timeout=1)
        _scan(scanner, rust_pairs=pairs)

        ips = [h.ip for h in scanner.get_results()]
        assert ips == sorted(ips)

    def test_resolve_hostname_populates_field(self):
        scanner = Ndp(verbose=False, timeout=1, resolve_hostname=True)

        with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.ndp._sondare.ndp_sweep", return_value=[("fe80::1234", "aa:bb:cc:dd:ee:01")]), \
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
        scanner = Ndp(verbose=False, timeout=1)

        with patch("sondare.services.ndp.get_network_interface", return_value="eth0"), \
             patch("sondare.services.ndp._sondare.ndp_sweep", return_value=[("fe80::1234", "aa:bb:cc:dd:ee:01")]), \
             patch("sondare.services.ndp.read_ndp_cache", return_value={}), \
             patch("sondare.services.ndp.get_mac_vendor", return_value="Apple, Inc.") as mock_vendor, \
             patch("builtins.print"):
            scanner.scan()
            results = scanner.get_results()

        assert results[0].vendor == "Apple, Inc."
        mock_vendor.assert_called_once_with("aa:bb:cc:dd:ee:01")
