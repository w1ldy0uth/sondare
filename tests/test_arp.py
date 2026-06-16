from unittest.mock import patch
from sondare.services.arp import Arp
from sondare.models import Host


def _scan(scanner, active=None, cache=None):
    with patch("sondare.services.arp._sondare.arp_sweep_v4", return_value=active or []), \
         patch("sondare.services.arp.get_network_interface", return_value="eth0"), \
         patch("sondare.services.arp.get_subnet", return_value="192.168.1.0/24"), \
         patch("sondare.services.arp.read_arp_cache", return_value=cache or {}), \
         patch("builtins.print"):
        scanner.scan()


def test_get_results_before_scan_returns_empty():
    scanner = Arp(verbose=False, timeout=1)
    assert scanner.get_results() == []


def test_scan_calls_arp_sweep_v4_with_iface_and_cidr(net_mocks):
    addrs, stats = net_mocks()
    with patch("psutil.net_if_addrs", return_value=addrs), \
         patch("psutil.net_if_stats", return_value=stats), \
         patch("sondare.services.arp._sondare.arp_sweep_v4", return_value=[]) as mock_sweep, \
         patch("sondare.services.arp.read_arp_cache", return_value={}), \
         patch("builtins.print"):
        Arp(verbose=False, timeout=3).scan()

    args = mock_sweep.call_args
    assert args[0][0] == "eth0"           # iface
    assert args[0][1] == "192.168.1.0/24" # cidr (from net_mocks ip=192.168.1.5/24)


def test_get_results_returns_host_list():
    scanner = Arp(verbose=False, timeout=1)
    _scan(scanner, active=[
        ("192.168.1.2", "aa:bb:cc:dd:ee:01"),
        ("192.168.1.3", "aa:bb:cc:dd:ee:02"),
    ])
    results = scanner.get_results()
    assert results == [
        Host(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:01"),
        Host(ip="192.168.1.3", mac="aa:bb:cc:dd:ee:02"),
    ]


def test_scan_with_no_responses_returns_empty():
    scanner = Arp(verbose=False, timeout=1)
    _scan(scanner)
    assert scanner.get_results() == []


def test_arp_cache_merges_unseen_hosts():
    scanner = Arp(verbose=False, timeout=1)
    _scan(
        scanner,
        active=[("192.168.1.2", "aa:bb:cc:dd:ee:01")],
        cache={"192.168.1.3": "aa:bb:cc:dd:ee:02"},
    )
    ips = [h.ip for h in scanner.get_results()]
    assert "192.168.1.2" in ips
    assert "192.168.1.3" in ips


def test_arp_cache_does_not_duplicate_active_hosts():
    scanner = Arp(verbose=False, timeout=1)
    _scan(
        scanner,
        active=[("192.168.1.2", "aa:bb:cc:dd:ee:01")],
        cache={"192.168.1.2": "aa:bb:cc:dd:ee:01"},
    )
    assert len(scanner.get_results()) == 1


def test_resolve_hostname_populates_hostname_field():
    scanner = Arp(verbose=False, timeout=1, resolve_hostname=True)
    with patch("sondare.services.arp._sondare.arp_sweep_v4", return_value=[
            ("192.168.1.2", "aa:bb:cc:dd:ee:01"),
            ("192.168.1.3", "aa:bb:cc:dd:ee:02"),
         ]), \
         patch("sondare.services.arp.get_network_interface", return_value="eth0"), \
         patch("sondare.services.arp.get_subnet", return_value="192.168.1.0/24"), \
         patch("sondare.services.arp.read_arp_cache", return_value={}), \
         patch("sondare.services.arp.resolve_hostnames", return_value={
             "192.168.1.2": "router.local",
             "192.168.1.3": None,
         }), \
         patch("builtins.print"):
        scanner.scan()

    results = scanner.get_results()
    assert results[0] == Host(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:01", hostname="router.local")
    assert results[1] == Host(ip="192.168.1.3", mac="aa:bb:cc:dd:ee:02", hostname=None)
