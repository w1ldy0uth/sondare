from unittest.mock import patch
from netscan.monitors.port_watcher import PortWatcher


def _watcher(port_begin=1, port_end=100, interval=60) -> PortWatcher:
    return PortWatcher(
        verbose=False,
        ip="192.168.1.1",
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
             patch("netscan.monitors.port_watcher.warm_arp_cache"), \
             patch("netscan.monitors.port_watcher.time.sleep", side_effect=KeyboardInterrupt):
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
             patch("netscan.monitors.port_watcher.warm_arp_cache"), \
             patch("netscan.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
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
             patch("netscan.monitors.port_watcher.warm_arp_cache"), \
             patch("netscan.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
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
             patch("netscan.monitors.port_watcher.warm_arp_cache"), \
             patch("netscan.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
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
             patch("netscan.monitors.port_watcher.warm_arp_cache"), \
             patch("netscan.monitors.port_watcher.time.sleep", side_effect=fake_sleep):
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
             patch("netscan.monitors.port_watcher.warm_arp_cache"), \
             patch("netscan.monitors.port_watcher.time.sleep", side_effect=KeyboardInterrupt):
            try:
                w.watch()
            except KeyboardInterrupt:
                pass

        out = capsys.readouterr().out
        assert "none" in out
