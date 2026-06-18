import json
from unittest.mock import patch, MagicMock
from sondare.services.mdns import Mdns
from sondare.models import MdnsRecord


_RAW_TUPLES = [
    ("macbook.local", "192.168.1.10", "_airplay._tcp", 7000),
    ("macbook.local", "192.168.1.10", "_ssh._tcp", 22),
    ("chromecast.local", "192.168.1.20", "_googlecast._tcp", 8009),
]

_RECORDS = [
    MdnsRecord(hostname="macbook.local", ip="192.168.1.10", service="_airplay._tcp", port=7000),
    MdnsRecord(hostname="macbook.local", ip="192.168.1.10", service="_ssh._tcp", port=22),
    MdnsRecord(hostname="chromecast.local", ip="192.168.1.20", service="_googlecast._tcp", port=8009),
]


def test_get_results_before_scan_returns_empty():
    scanner = Mdns(verbose=False, timeout=1)
    assert scanner.get_results() == []


def test_scan_returns_records():
    with patch("sondare.services.mdns._sondare.mdns_scan", return_value=_RAW_TUPLES):
        scanner = Mdns(verbose=False, timeout=1)
        scanner.scan()

    assert scanner.get_results() == _RECORDS


def test_scan_empty_network():
    with patch("sondare.services.mdns._sondare.mdns_scan", return_value=[]):
        scanner = Mdns(verbose=False, timeout=1)
        scanner.scan()

    assert scanner.get_results() == []


def test_main_mdns_table_output(capsys):
    with patch("sondare.main.Mdns") as MockMdns, \
         patch("sondare.main.root.is_running_as_root", return_value=True), \
         patch("builtins.print"):
        instance = MockMdns.return_value
        instance.get_results.return_value = _RECORDS

        from sondare.main import main
        import sys
        sys.argv = ["sondare", "mdns", "-t", "1"]
        try:
            main()
        except SystemExit:
            pass

        MockMdns.assert_called_once_with(verbose=False, timeout=1.0)
        instance.scan.assert_called_once()


def test_main_mdns_json_output(capsys):
    with patch("sondare.main.Mdns") as MockMdns, \
         patch("sondare.main.root.is_running_as_root", return_value=True):
        instance = MockMdns.return_value
        instance.get_results.return_value = _RECORDS

        from sondare.main import main
        import sys
        sys.argv = ["sondare", "mdns", "--json", "-t", "1"]
        try:
            main()
        except SystemExit:
            pass

    captured = capsys.readouterr()
    # Find the JSON line in output
    for line in captured.out.splitlines():
        try:
            data = json.loads(line)
            assert "services" in data
            assert len(data["services"]) == 3
            assert data["services"][0]["hostname"] == "macbook.local"
            assert data["services"][0]["service"] == "_airplay._tcp"
            assert data["services"][0]["port"] == 7000
            return
        except json.JSONDecodeError:
            continue
    assert False, "No JSON line found in output"
