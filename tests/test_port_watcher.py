from unittest.mock import patch, MagicMock
from sondare.monitors.port_watcher import PortWatcher, _syn_scan


def _watcher(ip="192.168.1.1", port_begin=1, port_end=100, interval=60) -> PortWatcher:
    return PortWatcher(
        verbose=False,
        ip=ip,
        port_begin=port_begin,
        port_end=port_end,
        timeout=3.0,
        threads=10,
        interval=interval,
    )


class TestPortWatcher:
    def test_initial_open_set_is_empty(self):
        w = _watcher()
        assert w._open == set()

    def test_watch_prints_initial_state(self, capsys):
        w = _watcher()

        rounds = iter([{80, 443}])

        def fake_scan():
            try:
                return next(rounds)
            except StopIteration:
                raise KeyboardInterrupt

        with patch.object(w, "_scan", side_effect=fake_scan), \
             patch("sondare.monitors.port_watcher.warm_arp_cache"), \
             patch("sondare.monitors.port_watcher.time.sleep", side_effect=KeyboardInterrupt):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        out = capsys.readouterr().out
        assert "Initial state" in out
        assert "80" in out
        assert "443" in out

    def test_watch_reports_opened_port(self, capsys):
        w = _watcher()
        w._open = {80}

        call_count = 0

        def fake_scan():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {80}           # first round — initial
            return {80, 443}          # second round — 443 opened

        sleep_count = 0

        def fake_sleep(_):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                raise KeyboardInterrupt

        with patch.object(w, "_scan", side_effect=fake_scan), \
             patch("sondare.monitors.port_watcher.warm_arp_cache"), \
             patch("sondare.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        out = capsys.readouterr().out
        assert "OPENED" in out
        assert "443" in out

    def test_watch_reports_closed_port(self, capsys):
        w = _watcher()

        call_count = 0

        def fake_scan():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {80, 22}       # first round — initial
            return {80}              # second round — 22 closed

        sleep_count = 0

        def fake_sleep(_):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                raise KeyboardInterrupt

        with patch.object(w, "_scan", side_effect=fake_scan), \
             patch("sondare.monitors.port_watcher.warm_arp_cache"), \
             patch("sondare.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        out = capsys.readouterr().out
        assert "CLOSED" in out
        assert "22" in out

    def test_no_change_output_when_ports_stable(self, capsys):
        w = _watcher()

        call_count = 0

        def fake_scan():
            nonlocal call_count
            call_count += 1
            return {80, 443}

        sleep_count = 0

        def fake_sleep(_):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                raise KeyboardInterrupt

        with patch.object(w, "_scan", side_effect=fake_scan), \
             patch("sondare.monitors.port_watcher.warm_arp_cache"), \
             patch("sondare.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        out = capsys.readouterr().out
        assert "OPENED" not in out
        assert "CLOSED" not in out

    def test_open_set_updated_after_each_round(self):
        w = _watcher()

        call_count = 0

        def fake_scan():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {80}
            return {443}

        sleep_count = 0

        def fake_sleep(_):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                raise KeyboardInterrupt

        with patch.object(w, "_scan", side_effect=fake_scan), \
             patch("sondare.monitors.port_watcher.warm_arp_cache"), \
             patch("sondare.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        assert w._open == {443}

    def test_initial_state_shows_none_when_all_closed(self, capsys):
        w = _watcher()

        rounds = iter([set()])

        def fake_scan():
            try:
                return next(rounds)
            except StopIteration:
                raise KeyboardInterrupt

        with patch.object(w, "_scan", side_effect=fake_scan), \
             patch("sondare.monitors.port_watcher.warm_arp_cache"), \
             patch("sondare.monitors.port_watcher.time.sleep", side_effect=KeyboardInterrupt):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        out = capsys.readouterr().out
        assert "none" in out


class TestIpv6PortWatcher:
    def test_ipv6_target_uses_ipv6_layer(self):
        sent_pkts = []

        def fake_sr1(pkt, **_kw):
            sent_pkts.append(pkt)
            return None

        with patch("sondare.monitors.port_watcher.sr1", side_effect=fake_sr1):
            _syn_scan("fe80::1", 80, 80, timeout=1, threads=1, verbose=False)

        from scapy.all import IPv6
        assert any(pkt.haslayer(IPv6) for pkt in sent_pkts)

    def test_ipv4_target_uses_ip_layer(self):
        sent_pkts = []

        def fake_sr1(pkt, **_kw):
            sent_pkts.append(pkt)
            return None

        with patch("sondare.monitors.port_watcher.sr1", side_effect=fake_sr1):
            _syn_scan("192.168.1.1", 80, 80, timeout=1, threads=1, verbose=False)

        from scapy.all import IP, IPv6
        assert all(pkt.haslayer(IP) and not pkt.haslayer(IPv6) for pkt in sent_pkts)

    def test_ipv6_watch_skips_warm_arp_cache(self, capsys):
        w = _watcher(ip="fe80::1")
        with patch.object(w, "_scan", side_effect=KeyboardInterrupt), \
             patch("sondare.monitors.port_watcher.warm_arp_cache") as mock_arp, \
             patch("sondare.monitors.port_watcher.is_ipv6_address", return_value=True):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass
        mock_arp.assert_not_called()

    def test_ipv4_watch_calls_warm_arp_cache(self, capsys):
        w = _watcher(ip="192.168.1.1")
        with patch.object(w, "_scan", side_effect=KeyboardInterrupt), \
             patch("sondare.monitors.port_watcher.warm_arp_cache") as mock_arp:
            try:
                w.watch()
            except KeyboardInterrupt:
                pass
        mock_arp.assert_called_once_with("192.168.1.1")
