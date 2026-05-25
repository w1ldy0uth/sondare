from unittest.mock import MagicMock, patch
from netscan.monitors.arp_watcher import ArpWatcher


def _make_pkt(ip: str, mac: str) -> MagicMock:
    """Build a minimal mock that looks like an ARP packet to ArpWatcher._handle."""
    arp = MagicMock()
    arp.psrc = ip
    arp.hwsrc = mac
    pkt = MagicMock()
    pkt.getlayer.return_value = arp
    return pkt


class TestArpWatcher:
    def _watcher(self) -> ArpWatcher:
        return ArpWatcher(verbose=False, timeout=5)

    def test_new_host_added_to_hosts(self):
        w = self._watcher()
        w._handle(_make_pkt("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
        assert w._hosts == {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}

    def test_known_host_same_mac_no_change(self):
        w = self._watcher()
        w._hosts["192.168.1.10"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_pkt("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
        assert w._hosts["192.168.1.10"] == "aa:bb:cc:dd:ee:ff"

    def test_mac_change_updates_hosts(self):
        w = self._watcher()
        w._hosts["192.168.1.10"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_pkt("192.168.1.10", "11:22:33:44:55:66"))
        assert w._hosts["192.168.1.10"] == "11:22:33:44:55:66"

    def test_zero_ip_ignored(self):
        w = self._watcher()
        w._handle(_make_pkt("0.0.0.0", "aa:bb:cc:dd:ee:ff"))
        assert w._hosts == {}

    def test_none_arp_layer_ignored(self):
        w = self._watcher()
        pkt = MagicMock()
        pkt.getlayer.return_value = None
        w._handle(pkt)
        assert w._hosts == {}

    def test_multiple_new_hosts(self):
        w = self._watcher()
        w._handle(_make_pkt("10.0.0.1", "aa:aa:aa:aa:aa:aa"))
        w._handle(_make_pkt("10.0.0.2", "bb:bb:bb:bb:bb:bb"))
        assert len(w._hosts) == 2

    def test_new_host_prints_new_event(self, capsys):
        w = self._watcher()
        w._handle(_make_pkt("192.168.1.50", "de:ad:be:ef:00:01"))
        out = capsys.readouterr().out
        assert "NEW" in out
        assert "192.168.1.50" in out

    def test_mac_change_prints_changed_event(self, capsys):
        w = self._watcher()
        w._hosts["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_pkt("192.168.1.1", "11:22:33:44:55:66"))
        out = capsys.readouterr().out
        assert "CHANGED" in out
        assert "192.168.1.1" in out

    def test_mac_change_mentions_spoofing(self, capsys):
        w = self._watcher()
        w._hosts["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_pkt("192.168.1.1", "11:22:33:44:55:66"))
        out = capsys.readouterr().out
        assert "spoofing" in out.lower()

    def test_same_mac_no_output(self, capsys):
        w = self._watcher()
        w._hosts["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_pkt("192.168.1.1", "aa:bb:cc:dd:ee:ff"))
        out = capsys.readouterr().out
        assert out == ""
