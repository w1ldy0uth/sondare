import socket
import pytest
from unittest.mock import patch, MagicMock
import sondare.utils.network as network
import sondare.utils.root as root


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
            assert root.is_running_as_root() is True

    def test_non_root_on_unix(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.geteuid", return_value=1000):
            assert root.is_running_as_root() is False

    def test_windows_always_true(self):
        with patch("platform.system", return_value="Windows"):
            assert root.is_running_as_root() is True


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
            assert network.get_network_interface() == "eth0"

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
            assert network.get_network_interface() == "eth1"

    def test_raises_when_no_valid_interface(self):
        addrs = {"lo": [_make_addr(socket.AF_INET, "127.0.0.1")]}
        stats = {"lo": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            with pytest.raises(RuntimeError, match="No active network interface"):
                network.get_network_interface()

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
            assert network.get_network_interface() == "eth1"


class TestGetIpAddress:
    def test_returns_ipv4_of_active_interface(self):
        addrs = {"eth0": [_make_addr(socket.AF_INET, "192.168.1.10")]}
        stats = {"eth0": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert network.get_ip_address() == "192.168.1.10"


class TestGetSubnet:
    def test_produces_slash24(self):
        addrs = {"eth0": [_make_addr(socket.AF_INET, "10.0.1.55", "255.255.255.0")]}
        stats = {"eth0": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert network.get_subnet() == "10.0.1.0/24"

    def test_respects_non_slash24_netmask(self):
        addrs = {"eth0": [_make_addr(socket.AF_INET, "10.0.1.55", "255.255.0.0")]}
        stats = {"eth0": _make_stats(isup=True)}
        with patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            assert network.get_subnet() == "10.0.0.0/16"


class TestResolveHostname:
    def test_returns_hostname_on_success(self):
        with patch("sondare.utils.network.socket.gethostbyaddr", return_value=("router.local", [], ["192.168.1.1"])):
            assert network.resolve_hostname("192.168.1.1") == "router.local"

    def test_returns_none_on_herror(self):
        with patch("sondare.utils.network.socket.gethostbyaddr", side_effect=socket.herror):
            assert network.resolve_hostname("192.168.1.99") is None

    def test_returns_none_on_gaierror(self):
        with patch("sondare.utils.network.socket.gethostbyaddr", side_effect=socket.gaierror):
            assert network.resolve_hostname("10.0.0.1") is None


class TestResolveHostnames:
    def test_returns_dict_of_ip_to_hostname(self):
        def _fake_gethostbyaddr(ip):
            return (f"host-{ip.split('.')[-1]}.local", [], [ip])

        with patch("sondare.utils.network.socket.gethostbyaddr", side_effect=_fake_gethostbyaddr), \
             patch("sondare.utils.network._browse_mdns", return_value={}), \
             patch("sondare.utils.network._browse_ssdp", return_value={}):
            result = network.resolve_hostnames(["192.168.1.1", "192.168.1.2"])

        assert result == {"192.168.1.1": "host-1.local", "192.168.1.2": "host-2.local"}

    def test_handles_partial_failures(self):
        def _fake(ip):
            if ip == "192.168.1.1":
                return ("router.local", [], [ip])
            raise socket.herror

        with patch("sondare.utils.network.socket.gethostbyaddr", side_effect=_fake), \
             patch("sondare.utils.network._browse_mdns", return_value={}), \
             patch("sondare.utils.network._browse_ssdp", return_value={}), \
             patch("sondare.utils.network._netbios_name", return_value=None):
            result = network.resolve_hostnames(["192.168.1.1", "192.168.1.2"])

        assert result == {"192.168.1.1": "router.local", "192.168.1.2": None}

    def test_returns_empty_dict_for_empty_input(self):
        result = network.resolve_hostnames([])
        assert result == {}


class TestResolveHostnamesFallback:
    """Verifies the PTR → mDNS → SSDP → NetBIOS fallback priority."""

    _NO_PTR = socket.herror

    def _run(self, ip, ptr_result, mdns_map, ssdp_map, netbios_result):
        ptr_side = (lambda _: (ptr_result, [], [ip])) if ptr_result else self._NO_PTR
        with patch("sondare.utils.network.socket.gethostbyaddr", side_effect=ptr_side), \
             patch("sondare.utils.network._browse_mdns", return_value=mdns_map), \
             patch("sondare.utils.network._browse_ssdp", return_value=ssdp_map), \
             patch("sondare.utils.network._netbios_name", return_value=netbios_result):
            return network.resolve_hostnames([ip])[ip]

    def test_ptr_takes_priority_over_all(self):
        result = self._run(
            "192.168.1.1",
            ptr_result="ptr.local",
            mdns_map={"192.168.1.1": "mdns.local"},
            ssdp_map={"192.168.1.1": "SSDP Device"},
            netbios_result="NBNAME",
        )
        assert result == "ptr.local"

    def test_mdns_used_when_ptr_fails(self):
        result = self._run(
            "192.168.1.1",
            ptr_result=None,
            mdns_map={"192.168.1.1": "macbook.local"},
            ssdp_map={"192.168.1.1": "SSDP Device"},
            netbios_result="NBNAME",
        )
        assert result == "macbook.local"

    def test_ssdp_used_when_ptr_and_mdns_fail(self):
        result = self._run(
            "192.168.1.1",
            ptr_result=None,
            mdns_map={},
            ssdp_map={"192.168.1.1": "Cudy router"},
            netbios_result="NBNAME",
        )
        assert result == "Cudy router"

    def test_netbios_used_when_ptr_mdns_ssdp_fail(self):
        result = self._run(
            "192.168.1.1",
            ptr_result=None,
            mdns_map={},
            ssdp_map={},
            netbios_result="W1PC",
        )
        assert result == "W1PC"

    def test_none_when_all_methods_fail(self):
        result = self._run(
            "192.168.1.1",
            ptr_result=None,
            mdns_map={},
            ssdp_map={},
            netbios_result=None,
        )
        assert result is None

    def test_each_ip_resolved_independently(self):
        with patch("sondare.utils.network.socket.gethostbyaddr", side_effect=socket.herror), \
             patch("sondare.utils.network._browse_mdns", return_value={"192.168.1.2": "macbook.local"}), \
             patch("sondare.utils.network._browse_ssdp", return_value={"192.168.1.1": "Cudy router"}), \
             patch("sondare.utils.network._netbios_name", return_value=None):
            result = network.resolve_hostnames(["192.168.1.1", "192.168.1.2"])

        assert result == {"192.168.1.1": "Cudy router", "192.168.1.2": "macbook.local"}


class TestGetPortService:
    def test_returns_name_for_known_port(self):
        assert network.get_port_service(22) == "ssh"
        assert network.get_port_service(80) == "http"
        assert network.get_port_service(443) == "https"

    def test_returns_none_for_unknown_port(self):
        assert network.get_port_service(0) is None

    def test_respects_proto_argument(self):
        assert network.get_port_service(53, "udp") == "domain"
