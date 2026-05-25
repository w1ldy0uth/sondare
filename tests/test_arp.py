import socket
from unittest.mock import patch, MagicMock
from netscan.services.arp import Arp
from netscan.models import Host


def _make_net_mocks():
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = "192.168.1.5"
    stat = MagicMock()
    stat.isup = True
    return {"eth0": [addr]}, {"eth0": stat}


def test_get_results_before_scan_returns_empty():
    scanner = Arp(verbose=False, timeout=1)
    assert scanner.get_results() == []


def test_scan_calls_srp_with_correct_args():
    addrs, stats = _make_net_mocks()
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats), \
         patch("netscan.services.arp.srp", return_value=([], None)) as mock_srp, \
         patch("builtins.print"):
        scanner = Arp(verbose=False, timeout=3)
        scanner.scan()

    call_kwargs = mock_srp.call_args.kwargs
    assert call_kwargs["iface"] == "eth0"
    assert call_kwargs["timeout"] == 3
    assert call_kwargs["verbose"] is False
    assert call_kwargs["promisc"] is False


def test_get_results_returns_host_list():
    sent = MagicMock()
    rcv1 = MagicMock()
    rcv1.psrc = "192.168.1.2"
    rcv1.hwsrc = "aa:bb:cc:dd:ee:01"
    rcv2 = MagicMock()
    rcv2.psrc = "192.168.1.3"
    rcv2.hwsrc = "aa:bb:cc:dd:ee:02"

    addrs, stats = _make_net_mocks()
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats), \
         patch("netscan.services.arp.srp", return_value=([(sent, rcv1), (sent, rcv2)], None)), \
         patch("builtins.print"):
        scanner = Arp(verbose=False, timeout=1)
        scanner.scan()

    results = scanner.get_results()
    assert results == [
        Host(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:01"),
        Host(ip="192.168.1.3", mac="aa:bb:cc:dd:ee:02"),
    ]


def test_scan_with_no_responses_returns_empty():
    addrs, stats = _make_net_mocks()
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats), \
         patch("netscan.services.arp.srp", return_value=([], None)), \
         patch("builtins.print"):
        scanner = Arp(verbose=False, timeout=1)
        scanner.scan()

    assert scanner.get_results() == []
