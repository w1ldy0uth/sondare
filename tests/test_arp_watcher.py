import struct
from sondare.monitors.arp_watcher import ArpWatcher


def _make_arp_frame(ip: str, mac: str) -> bytes:
    """Build a minimal raw Ethernet+ARP frame."""
    mac_bytes = bytes(int(b, 16) for b in mac.split(":"))
    ip_bytes = bytes(int(b) for b in ip.split("."))
    frame = bytearray(42)
    # Ethernet: dst(6) + src(6) + ethertype(2)
    frame[6:12] = mac_bytes
    struct.pack_into("!H", frame, 12, 0x0806)
    # ARP: htype(2) + ptype(2) + hlen(1) + plen(1) + op(2)
    struct.pack_into("!HHBBH", frame, 14, 1, 0x0800, 6, 4, 2)
    # Sender MAC + IP
    frame[22:28] = mac_bytes
    frame[28:32] = ip_bytes
    return bytes(frame)


class TestArpWatcher:
    def _watcher(self) -> ArpWatcher:
        return ArpWatcher(verbose=False, timeout=5)

    def test_new_host_added_to_hosts(self):
        w = self._watcher()
        w._handle(_make_arp_frame("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
        assert w._hosts == {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}

    def test_known_host_same_mac_no_change(self):
        w = self._watcher()
        w._hosts["192.168.1.10"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_arp_frame("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
        assert w._hosts["192.168.1.10"] == "aa:bb:cc:dd:ee:ff"

    def test_mac_change_updates_hosts(self):
        w = self._watcher()
        w._hosts["192.168.1.10"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_arp_frame("192.168.1.10", "11:22:33:44:55:66"))
        assert w._hosts["192.168.1.10"] == "11:22:33:44:55:66"

    def test_zero_ip_ignored(self):
        w = self._watcher()
        w._handle(_make_arp_frame("0.0.0.0", "aa:bb:cc:dd:ee:ff"))
        assert w._hosts == {}

    def test_too_short_frame_ignored(self):
        w = self._watcher()
        w._handle(b"\x00" * 10)
        assert w._hosts == {}

    def test_non_arp_ethertype_ignored(self):
        w = self._watcher()
        frame = bytearray(_make_arp_frame("192.168.1.1", "aa:bb:cc:dd:ee:ff"))
        struct.pack_into("!H", frame, 12, 0x0800)  # IPv4, not ARP
        w._handle(bytes(frame))
        assert w._hosts == {}

    def test_multiple_new_hosts(self):
        w = self._watcher()
        w._handle(_make_arp_frame("10.0.0.1", "aa:aa:aa:aa:aa:aa"))
        w._handle(_make_arp_frame("10.0.0.2", "bb:bb:bb:bb:bb:bb"))
        assert len(w._hosts) == 2

    def test_new_host_prints_new_event(self, capsys):
        w = self._watcher()
        w._handle(_make_arp_frame("192.168.1.50", "de:ad:be:ef:00:01"))
        out = capsys.readouterr().out
        assert "NEW" in out
        assert "192.168.1.50" in out

    def test_mac_change_prints_changed_event(self, capsys):
        w = self._watcher()
        w._hosts["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_arp_frame("192.168.1.1", "11:22:33:44:55:66"))
        out = capsys.readouterr().out
        assert "CHANGED" in out
        assert "192.168.1.1" in out

    def test_mac_change_mentions_spoofing(self, capsys):
        w = self._watcher()
        w._hosts["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_arp_frame("192.168.1.1", "11:22:33:44:55:66"))
        out = capsys.readouterr().out
        assert "spoofing" in out.lower()

    def test_same_mac_no_output(self, capsys):
        w = self._watcher()
        w._hosts["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        w._handle(_make_arp_frame("192.168.1.1", "aa:bb:cc:dd:ee:ff"))
        out = capsys.readouterr().out
        assert out == ""
