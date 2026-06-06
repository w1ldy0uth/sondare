from unittest.mock import MagicMock, patch
from sondare.monitors.hosts_watcher import HostsWatcher


def _monitor(hosts=None, interval=30, auto_discover=False) -> HostsWatcher:
    return HostsWatcher(
        verbose=False,
        hosts=hosts or ["192.168.1.1", "192.168.1.2"],
        timeout=2.0,
        threads=10,
        interval=interval,
        auto_discover=auto_discover,
    )


def _two_sleeps_then_interrupt():
    count = 0

    def fake_sleep(_):
        nonlocal count
        count += 1
        if count >= 2:
            raise KeyboardInterrupt

    return fake_sleep


class TestUpDownMonitor:
    def test_ping_returns_true_on_icmp_reply(self):
        m = _monitor()
        icmp_reply = MagicMock()
        icmp_reply.haslayer.return_value = True
        icmp_reply.getlayer.return_value = MagicMock(type=0)
        with patch("sondare.monitors.hosts_watcher.sr1", return_value=icmp_reply):
            assert m._ping("192.168.1.1") is True

    def test_ping_returns_false_on_no_response(self):
        m = _monitor()
        with patch("sondare.monitors.hosts_watcher.sr1", return_value=None):
            assert m._ping("192.168.1.1") is False

    def test_ping_returns_false_on_non_echo_reply(self):
        m = _monitor()
        pkt = MagicMock()
        pkt.haslayer.return_value = True
        pkt.getlayer.return_value = MagicMock(type=3)
        with patch("sondare.monitors.hosts_watcher.sr1", return_value=pkt):
            assert m._ping("192.168.1.1") is False

    def test_round_returns_result_for_every_host(self):
        m = _monitor(hosts=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        with patch.object(m, "_ping", return_value=True):
            result = m._round()
        assert set(result.keys()) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    def test_round_maps_up_and_down_correctly(self):
        m = _monitor(hosts=["10.0.0.1", "10.0.0.2"])

        def fake_ping(host):
            return host == "10.0.0.1"

        with patch.object(m, "_ping", side_effect=fake_ping):
            result = m._round()
        assert result["10.0.0.1"] is True
        assert result["10.0.0.2"] is False

    # --- state tracking ---

    def test_state_populated_after_first_round(self):
        m = _monitor(hosts=["10.0.0.1"])
        with patch.object(m, "_round", return_value={"10.0.0.1": True}), \
             patch("sondare.monitors.hosts_watcher.time.sleep", side_effect=KeyboardInterrupt):
            try:
                m.watch()
            except KeyboardInterrupt:
                pass
        assert "10.0.0.1" in m._state
        assert m._state["10.0.0.1"][0] is True

    def test_since_unchanged_when_status_stable(self):
        m = _monitor(hosts=["10.0.0.1"])
        m._state["10.0.0.1"] = (True, "12:00:00")
        call_count = 0

        def fake_round():
            nonlocal call_count
            call_count += 1
            return {"10.0.0.1": True}

        with patch.object(m, "_round", side_effect=fake_round), \
             patch("sondare.monitors.hosts_watcher.time.sleep", side_effect=_two_sleeps_then_interrupt()):
            try:
                m.watch()
            except KeyboardInterrupt:
                pass
        assert m._state["10.0.0.1"][1] == "12:00:00"

    def test_since_updated_on_status_change(self):
        m = _monitor(hosts=["10.0.0.1"])
        m._state["10.0.0.1"] = (True, "12:00:00")
        call_count = 0

        def fake_round():
            nonlocal call_count
            call_count += 1
            return {"10.0.0.1": True} if call_count == 1 else {"10.0.0.1": False}

        with patch.object(m, "_round", side_effect=fake_round), \
             patch("sondare.monitors.hosts_watcher.time.sleep", side_effect=_two_sleeps_then_interrupt()):
            try:
                m.watch()
            except KeyboardInterrupt:
                pass
        assert m._state["10.0.0.1"][0] is False
        assert m._state["10.0.0.1"][1] != "12:00:00"

    # --- table output ---

    def test_draw_shows_up_host(self, capsys):
        m = _monitor(hosts=["10.0.0.1"])
        m._state["10.0.0.1"] = (True, "12:00:00")
        m._draw("12:00:00")
        out = capsys.readouterr().out
        assert "10.0.0.1" in out
        assert "UP" in out

    def test_draw_shows_down_host(self, capsys):
        m = _monitor(hosts=["10.0.0.1"])
        m._state["10.0.0.1"] = (False, "12:00:00")
        m._draw("12:00:00")
        out = capsys.readouterr().out
        assert "DOWN" in out

    def test_draw_shows_no_hosts_message(self, capsys):
        m = _monitor(hosts=[])
        m._draw("12:00:00")
        out = capsys.readouterr().out
        assert "no hosts" in out.lower()

    def test_draw_updates_line_count(self):
        m = _monitor(hosts=["10.0.0.1", "10.0.0.2"])
        m._state = {"10.0.0.1": (True, "t"), "10.0.0.2": (False, "t")}
        with patch("builtins.print"):
            m._draw("12:00:00")
        assert m._last_line_count > 0

    # --- auto_discover ---

    def test_auto_discover_new_host_appears_in_state(self):
        m = _monitor(hosts=[], interval=1, auto_discover=True)
        call_count = 0

        def fake_arp(*_a, **_kw):
            nonlocal call_count
            call_count += 1
            return ["10.0.0.1"] if call_count == 1 else ["10.0.0.1", "10.0.0.2"]

        rounds = iter([{"10.0.0.1": True}, {"10.0.0.1": True, "10.0.0.2": True}])

        with patch("sondare.monitors.hosts_watcher._arp_scan", side_effect=fake_arp), \
             patch.object(m, "_round", side_effect=lambda: next(rounds)), \
             patch("sondare.monitors.hosts_watcher.time.sleep", side_effect=_two_sleeps_then_interrupt()):
            try:
                m.watch()
            except KeyboardInterrupt:
                pass

        assert "10.0.0.2" in m._state

    def test_auto_discover_gone_host_removed_from_state(self):
        m = _monitor(hosts=[], interval=1, auto_discover=True)
        call_count = 0

        def fake_arp(*_a, **_kw):
            nonlocal call_count
            call_count += 1
            return ["10.0.0.1", "10.0.0.2"] if call_count == 1 else ["10.0.0.1"]

        rounds = iter([
            {"10.0.0.1": True, "10.0.0.2": True},
            {"10.0.0.1": True},
        ])

        with patch("sondare.monitors.hosts_watcher._arp_scan", side_effect=fake_arp), \
             patch.object(m, "_round", side_effect=lambda: next(rounds)), \
             patch("sondare.monitors.hosts_watcher.time.sleep", side_effect=_two_sleeps_then_interrupt()):
            try:
                m.watch()
            except KeyboardInterrupt:
                pass

        assert "10.0.0.2" not in m._state

    def test_fixed_hosts_not_refreshed(self):
        m = _monitor(hosts=["10.0.0.1"], auto_discover=False)
        with patch("sondare.monitors.hosts_watcher._arp_scan") as mock_arp, \
             patch.object(m, "_round", return_value={"10.0.0.1": True}), \
             patch("sondare.monitors.hosts_watcher.time.sleep", side_effect=KeyboardInterrupt):
            try:
                m.watch()
            except KeyboardInterrupt:
                pass
        mock_arp.assert_not_called()


class TestIpv6HostsWatcher:
    def _make_v6_reply(self, has_reply: bool = True):
        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda cls: has_reply and cls.__name__ == "ICMPv6EchoReply"
        return pkt

    def test_ping_ipv6_sends_icmpv6_echo_request(self):
        m = _monitor()
        sent_pkts = []

        def fake_sr1(pkt, **_kw):
            sent_pkts.append(pkt)
            return None

        with patch("sondare.monitors.hosts_watcher.sr1", side_effect=fake_sr1):
            m._ping("fe80::1")

        from scapy.all import IPv6, ICMPv6EchoRequest
        assert any(pkt.haslayer(IPv6) and pkt.haslayer(ICMPv6EchoRequest) for pkt in sent_pkts)

    def test_ping_ipv6_returns_true_on_echo_reply(self):
        m = _monitor()
        with patch("sondare.monitors.hosts_watcher.sr1", return_value=self._make_v6_reply(True)):
            assert m._ping("fe80::1") is True

    def test_ping_ipv6_returns_false_on_no_response(self):
        m = _monitor()
        with patch("sondare.monitors.hosts_watcher.sr1", return_value=None):
            assert m._ping("fe80::1") is False

    def test_ping_ipv6_returns_false_on_wrong_reply(self):
        m = _monitor()
        with patch("sondare.monitors.hosts_watcher.sr1", return_value=self._make_v6_reply(False)):
            assert m._ping("fe80::1") is False

    def test_ping_ipv4_does_not_use_icmpv6(self):
        m = _monitor()
        sent_pkts = []

        def fake_sr1(pkt, **_kw):
            sent_pkts.append(pkt)
            return None

        with patch("sondare.monitors.hosts_watcher.sr1", side_effect=fake_sr1):
            m._ping("192.168.1.1")

        from scapy.all import ICMPv6EchoRequest
        assert not any(pkt.haslayer(ICMPv6EchoRequest) for pkt in sent_pkts)

    def test_draw_widens_column_for_ipv6_address(self, capsys):
        m = _monitor(hosts=[])
        m._state = {"fe80::dead:beef:1234:5678": (True, "12:00:00")}
        m._draw("12:00:00")
        out = capsys.readouterr().out
        # The IPv6 address must appear without truncation
        assert "fe80::dead:beef:1234:5678" in out
