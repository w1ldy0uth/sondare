from unittest.mock import patch, MagicMock, call
from sondare.monitors.ndp_watcher import NdpWatcher


def _na_pkt(src_ip: str, src_mac: str, has_na: bool = True):
    """Mock ICMPv6 Neighbor Advertisement packet."""
    ipv6_layer = MagicMock()
    ipv6_layer.src = src_ip
    ether_layer = MagicMock()
    ether_layer.src = src_mac

    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda cls: {
        "IPv6": True,
        "ICMPv6ND_NA": has_na,
        "Ether": True,
    }.get(cls.__name__, False)
    pkt.__getitem__ = MagicMock(
        side_effect=lambda cls: ipv6_layer if cls.__name__ == "IPv6" else ether_layer
    )
    return pkt


def _echo_reply(src_ip: str, src_mac: str):
    ipv6_layer = MagicMock()
    ipv6_layer.src = src_ip
    ether_layer = MagicMock()
    ether_layer.src = src_mac
    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda cls: cls.__name__ == "ICMPv6EchoReply"
    pkt.__getitem__ = MagicMock(
        side_effect=lambda cls: ipv6_layer if cls.__name__ == "IPv6" else ether_layer
    )
    return pkt


def _make_watcher(local_ip="fe80::1"):
    with patch("sondare.monitors.ndp_watcher.get_network_interface", return_value="eth0"), \
         patch("sondare.monitors.ndp_watcher.get_ipv6_link_local", return_value=local_ip):
        return NdpWatcher(verbose=False, timeout=3)


def _seed(watcher, srp_pairs=None, ndp_cache=None):
    with patch("sondare.monitors.ndp_watcher.srp", return_value=(srp_pairs or [], None)), \
         patch("sondare.monitors.ndp_watcher.read_ndp_cache", return_value=ndp_cache or {}), \
         patch("builtins.print"):
        watcher._seed()


class TestSeed:
    def test_seed_calls_srp_multicast_with_multi(self):
        watcher = _make_watcher()
        with patch("sondare.monitors.ndp_watcher.srp", return_value=([], None)) as mock_srp, \
             patch("sondare.monitors.ndp_watcher.read_ndp_cache", return_value={}), \
             patch("builtins.print"):
            watcher._seed()

        kwargs = mock_srp.call_args.kwargs
        assert kwargs["multi"] is True
        assert kwargs["iface"] == "eth0"

    def test_seed_collects_echo_replies(self):
        watcher = _make_watcher()
        pairs = [
            (None, _echo_reply("fe80::aaaa", "aa:bb:cc:dd:ee:01")),
            (None, _echo_reply("fe80::bbbb", "aa:bb:cc:dd:ee:02")),
        ]
        _seed(watcher, srp_pairs=pairs)
        assert set(watcher._hosts.keys()) == {"fe80::aaaa", "fe80::bbbb"}

    def test_seed_merges_ndp_cache(self):
        watcher = _make_watcher()
        _seed(watcher, ndp_cache={"fe80::cafe": "de:ad:be:ef:00:01"})
        assert "fe80::cafe" in watcher._hosts

    def test_seed_excludes_own_link_local(self):
        watcher = _make_watcher(local_ip="fe80::dead:beef")
        pairs = [(None, _echo_reply("fe80::dead:beef", "aa:bb:cc:dd:ee:ff"))]
        _seed(watcher, srp_pairs=pairs)
        assert watcher._hosts == {}

    def test_seed_excludes_multicast_from_cache(self):
        watcher = _make_watcher()
        _seed(watcher, ndp_cache={"ff02::1": "33:33:00:00:00:01"})
        assert watcher._hosts == {}

    def test_seed_active_scan_takes_precedence_over_cache(self):
        watcher = _make_watcher()
        pairs = [(None, _echo_reply("fe80::cafe", "aa:11:22:33:44:55"))]
        _seed(watcher, srp_pairs=pairs, ndp_cache={"fe80::cafe": "ff:ee:dd:cc:bb:aa"})
        assert watcher._hosts["fe80::cafe"] == "aa:11:22:33:44:55"

    def test_seed_strips_scope_suffix(self):
        watcher = _make_watcher()
        pairs = [(None, _echo_reply("fe80::abcd%eth0", "aa:bb:cc:dd:ee:01"))]
        _seed(watcher, srp_pairs=pairs)
        assert "fe80::abcd" in watcher._hosts
        assert "fe80::abcd%eth0" not in watcher._hosts


class TestHandle:
    def test_new_host_is_printed(self, capsys):
        watcher = _make_watcher()
        watcher._handle(_na_pkt("fe80::1111", "aa:bb:cc:dd:ee:01"))
        out = capsys.readouterr().out
        assert "NEW" in out
        assert "fe80::1111" in out

    def test_changed_mac_is_printed(self, capsys):
        watcher = _make_watcher()
        watcher._hosts["fe80::1111"] = "aa:bb:cc:dd:ee:01"
        watcher._handle(_na_pkt("fe80::1111", "ff:ee:dd:cc:bb:aa"))
        out = capsys.readouterr().out
        assert "CHANGED" in out
        assert "NDP spoofing" in out

    def test_unchanged_host_is_silent(self, capsys):
        watcher = _make_watcher()
        watcher._hosts["fe80::1111"] = "aa:bb:cc:dd:ee:01"
        watcher._handle(_na_pkt("fe80::1111", "aa:bb:cc:dd:ee:01"))
        out = capsys.readouterr().out
        assert out == ""

    def test_own_link_local_ignored(self, capsys):
        watcher = _make_watcher(local_ip="fe80::1")
        watcher._handle(_na_pkt("fe80::1", "aa:bb:cc:dd:ee:ff"))
        assert capsys.readouterr().out == ""

    def test_multicast_address_ignored(self, capsys):
        watcher = _make_watcher()
        watcher._handle(_na_pkt("ff02::1", "33:33:00:00:00:01"))
        assert capsys.readouterr().out == ""

    def test_non_na_packet_ignored(self, capsys):
        watcher = _make_watcher()
        watcher._handle(_na_pkt("fe80::1234", "aa:bb:cc:dd:ee:01", has_na=False))
        assert capsys.readouterr().out == ""

    def test_scope_suffix_stripped(self, capsys):
        watcher = _make_watcher()
        watcher._handle(_na_pkt("fe80::abcd%eth0", "aa:bb:cc:dd:ee:01"))
        out = capsys.readouterr().out
        assert "fe80::abcd" in out
        assert "%" not in out
