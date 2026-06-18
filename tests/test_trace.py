import json
from unittest.mock import patch, MagicMock
from sondare.services.trace import Traceroute
from sondare.models import Hop


def _make_reply(src: str) -> MagicMock:
    reply = MagicMock()
    reply.src = src
    return reply


def _rust_patches(hops):
    """Mock Rust traceroute_v4 returning list of (ttl, ip_or_none, rtt_or_none)."""
    return [
        patch("sondare.services.trace._sondare.traceroute_v4", return_value=hops),
        patch("sondare.services.trace.get_network_interface", return_value="eth0"),
    ]


def test_get_results_before_scan_returns_empty():
    scanner = Traceroute(verbose=False, ip="10.0.0.1")
    assert scanner.get_results() == []


def test_scan_reaches_destination():
    hops = [(1, "192.168.1.1", 0.5), (2, "10.0.0.1", 1.2)]
    patches = _rust_patches(hops)
    with patches[0], patches[1]:
        scanner = Traceroute(verbose=False, ip="10.0.0.1", timeout=1)
        scanner.scan()

    results = scanner.get_results()
    assert results[-1].ip == "10.0.0.1"
    assert len(results) == 2


def test_scan_non_responding_hop():
    hops = [(1, None, None), (2, "10.0.0.1", 1.2)]
    patches = _rust_patches(hops)
    with patches[0], patches[1]:
        scanner = Traceroute(verbose=False, ip="10.0.0.1", timeout=1)
        scanner.scan()

    results = scanner.get_results()
    assert results[0] == Hop(ttl=1, ip=None, rtt_ms=None)
    assert results[1].ip == "10.0.0.1"


def test_scan_stops_at_max_hops():
    hops = [(i, None, None) for i in range(1, 6)]
    patches = _rust_patches(hops)
    with patches[0], patches[1]:
        scanner = Traceroute(verbose=False, ip="10.0.0.1", timeout=1, max_hops=5)
        scanner.scan()

    assert len(scanner.get_results()) == 5


def test_on_hop_callback_called_for_each_hop():
    hops = [(1, "192.168.1.1", 0.5), (2, "10.0.0.1", 1.2)]
    seen = []
    patches = _rust_patches(hops)
    with patches[0], patches[1]:
        scanner = Traceroute(verbose=False, ip="10.0.0.1", timeout=1, on_hop=seen.append)
        scanner.scan()

    assert len(seen) == 2
    assert seen[0].ttl == 1
    assert seen[1].ttl == 2


def test_main_trace_json_output(capsys):
    with patch("sondare.main.Traceroute") as MockTrace, \
         patch("sondare.main.root.is_running_as_root", return_value=True):
        instance = MockTrace.return_value
        instance.get_results.return_value = [
            Hop(ttl=1, ip="192.168.1.1", rtt_ms=1.23),
            Hop(ttl=2, ip=None, rtt_ms=None),
            Hop(ttl=3, ip="8.8.8.8", rtt_ms=12.34),
        ]

        import sys
        sys.argv = ["sondare", "trace", "--target", "8.8.8.8", "--json"]
        from sondare.main import main
        try:
            main()
        except SystemExit:
            pass

    captured = capsys.readouterr()
    for line in captured.out.splitlines():
        try:
            data = json.loads(line)
            assert data["target"] == "8.8.8.8"
            assert len(data["hops"]) == 3
            assert data["hops"][1]["ip"] is None
            assert data["hops"][2]["rtt_ms"] == 12.34
            return
        except json.JSONDecodeError:
            continue
    assert False, "No JSON line found in output"


def test_ipv6_target_calls_rust_traceroute_v6():
    hops = [(1, "fe80::1", 0.5)]
    with patch("sondare.services.trace._sondare.traceroute_v6", return_value=hops) as mock_v6, \
         patch("sondare.services.trace.get_network_interface", return_value="eth0"):
        scanner = Traceroute(verbose=False, ip="fe80::1", timeout=1, max_hops=1)
        scanner.scan()

    mock_v6.assert_called_once()
    assert scanner.get_results()[0].ip == "fe80::1"


def test_ipv4_scan_calls_rust_backend():
    hops = [(1, None, None)]
    patches = _rust_patches(hops)
    with patches[0] as mock_rust, patches[1]:
        scanner = Traceroute(verbose=False, ip="8.8.8.8", timeout=1, max_hops=1)
        scanner.scan()

    mock_rust.assert_called_once()
