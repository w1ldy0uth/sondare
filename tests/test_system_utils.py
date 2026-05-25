import socket
import pytest
from unittest.mock import patch, MagicMock
from sondare.utils import system_utils


def _make_addr(family, address, netmask="255.255.255.0"):
    a = MagicMock()
    a.family = family
    a.address = address
    a.netmask = netmask
    return a


def _make_stats(isup=True):
    s = MagicMock()
    s.isup = isup
    return s


class TestIsRunningAsRoot:
    def test_root_on_unix(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.geteuid", return_value=0):
            assert system_utils.is_running_as_root() is True

    def test_non_root_on_unix(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.geteuid", return_value=1000):
            assert system_utils.is_running_as_root() is False

    def test_windows_always_true(self):
        with patch("platform.system", return_value="Windows"):
            assert system_utils.is_running_as_root() is True


class TestGetNetworkInterface:
    def test_returns_first_valid_interface(self):
        addrs = {
            "lo": [_make_addr(socket.AF_INET, "127.0.0.1")],
            "eth0": [_make_addr(socket.AF_INET, "192.168.1.5")],
        }
        stats = {
            "lo": _make_stats(isup=True),
            "eth0": _make_stats(isup=True),
        }
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert system_utils.get_network_interface() == "eth0"

    def test_skips_down_interface(self):
        addrs = {
            "eth0": [_make_addr(socket.AF_INET, "10.0.0.1")],
            "eth1": [_make_addr(socket.AF_INET, "10.0.0.2")],
        }
        stats = {
            "eth0": _make_stats(isup=False),
            "eth1": _make_stats(isup=True),
        }
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert system_utils.get_network_interface() == "eth1"

    def test_raises_when_no_valid_interface(self):
        addrs = {"lo": [_make_addr(socket.AF_INET, "127.0.0.1")]}
        stats = {"lo": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            with pytest.raises(RuntimeError, match="No active network interface"):
                system_utils.get_network_interface()

    def test_skips_interface_without_ipv4(self):
        addrs = {
            "eth0": [_make_addr(socket.AF_UNIX, "")],  # no IPv4 addr
            "eth1": [_make_addr(socket.AF_INET, "10.0.0.1")],
        }
        stats = {
            "eth0": _make_stats(isup=True),
            "eth1": _make_stats(isup=True),
        }
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert system_utils.get_network_interface() == "eth1"


class TestGetIpAddress:
    def test_returns_ipv4_of_active_interface(self):
        addrs = {"eth0": [_make_addr(socket.AF_INET, "192.168.1.10")]}
        stats = {"eth0": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert system_utils.get_ip_address() == "192.168.1.10"


class TestGetSubnet:
    def test_produces_slash24(self):
        addrs = {"eth0": [_make_addr(socket.AF_INET, "10.0.1.55", "255.255.255.0")]}
        stats = {"eth0": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert system_utils.get_subnet() == "10.0.1.0/24"

    def test_respects_non_slash24_netmask(self):
        addrs = {"eth0": [_make_addr(socket.AF_INET, "10.0.1.55", "255.255.0.0")]}
        stats = {"eth0": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert system_utils.get_subnet() == "10.0.0.0/16"
