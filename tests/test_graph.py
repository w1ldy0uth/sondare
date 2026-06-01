import json
from unittest.mock import patch, MagicMock
from sondare.services.graph import NetworkGraph, _get_gateway
from sondare.models import Host


def _grapher(**kwargs) -> NetworkGraph:
    defaults = dict(verbose=False, timeout=3.0, threads=5, fingerprint=False,
                    output="/tmp/test_graph.html")
    return NetworkGraph(**{**defaults, **kwargs})


def _hosts():
    return [
        Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01"),
        Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:02"),
        Host(ip="192.168.1.20", mac="aa:bb:cc:dd:ee:03"),
    ]


def _patch_ipconfig(output: str | None):
    """Patches subprocess so _get_gateway() reads a fake ipconfig getoption response."""
    import subprocess as sp
    if output is None:
        return patch("sondare.services.graph.subprocess.check_output",
                     side_effect=sp.CalledProcessError(1, "ipconfig"))
    return patch("sondare.services.graph.subprocess.check_output", return_value=output)


class TestGetGateway:
    def test_returns_gateway_ip_via_ipconfig(self):
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig("192.168.1.1\n"):
            assert _get_gateway() == "192.168.1.1"

    def test_returns_none_for_zero_gateway(self):
        mock_conf = MagicMock()
        mock_conf.route.route.return_value = ("en0", "0.0.0.0", "0.0.0.0")
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig("0.0.0.0\n"), \
             patch("sondare.services.graph.conf", mock_conf):
            assert _get_gateway() is None

    def test_falls_back_to_scapy_on_subprocess_failure(self):
        mock_conf = MagicMock()
        mock_conf.route.route.return_value = ("en0", "192.168.1.10", "192.168.1.1")
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig(None), \
             patch("sondare.services.graph.conf", mock_conf):
            assert _get_gateway() == "192.168.1.1"

    def test_returns_none_on_all_methods_failing(self):
        mock_conf = MagicMock()
        mock_conf.route.route.side_effect = Exception("no route")
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig(None), \
             patch("sondare.services.graph.conf", mock_conf):
            assert _get_gateway() is None


class TestBuildGraph:
    def test_gateway_node_has_gateway_group(self):
        g = _grapher()
        g._hosts = _hosts()
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        gw = next(n for n in nodes if n["id"] == "192.168.1.1")
        assert gw["group"] == "gateway"

    def test_local_node_has_local_group(self):
        g = _grapher()
        g._hosts = _hosts()
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        local = next(n for n in nodes if n["id"] == "192.168.1.10")
        assert local["group"] == "local"

    def test_regular_host_has_host_group(self):
        g = _grapher()
        g._hosts = _hosts()
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        host = next(n for n in nodes if n["id"] == "192.168.1.20")
        assert host["group"] == "host"

    def test_edges_connect_hosts_to_gateway(self):
        g = _grapher()
        g._hosts = _hosts()
        _, edges = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        edge_targets = {e["to"] for e in edges}
        assert "192.168.1.20" in edge_targets

    def test_all_edges_originate_from_gateway(self):
        g = _grapher()
        g._hosts = _hosts()
        _, edges = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        assert all(e["from"] == "192.168.1.1" for e in edges)

    def test_no_gateway_edges_originate_from_local(self):
        g = _grapher()
        g._hosts = _hosts()
        _, edges = g._build_graph(gateway=None, local_ip="192.168.1.10")
        assert all(e["from"] == "192.168.1.10" for e in edges)

    def test_os_in_node_title_when_fingerprinted(self):
        g = _grapher()
        g._hosts = _hosts()
        g._os_map["192.168.1.20"] = "Linux / Unix"
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        host = next(n for n in nodes if n["id"] == "192.168.1.20")
        assert "Linux / Unix" in host["title"]

    def test_os_in_node_label_when_fingerprinted(self):
        g = _grapher()
        g._hosts = _hosts()
        g._os_map["192.168.1.20"] = "Linux / Unix"
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        host = next(n for n in nodes if n["id"] == "192.168.1.20")
        assert "Linux / Unix" in host["label"]

    def test_local_ip_not_duplicated_when_in_arp_results(self):
        g = _grapher()
        g._hosts = _hosts()
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        ids = [n["id"] for n in nodes]
        assert ids.count("192.168.1.10") == 1

    def test_gateway_not_duplicated_as_regular_host(self):
        g = _grapher()
        g._hosts = _hosts()
        nodes, _ = g._build_graph(gateway="192.168.1.1", local_ip="192.168.1.10")
        gateway_nodes = [n for n in nodes if n["id"] == "192.168.1.1"]
        assert len(gateway_nodes) == 1


class TestRun:
    def test_writes_html_file(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            g.run()
        assert open(out).read().startswith("<!DOCTYPE html>")

    def test_html_contains_node_data(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            g.run()
        content = open(out).read()
        assert "192.168.1.20" in content

    def test_returns_output_path(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            result = g.run()
        assert result == out

    def test_fingerprint_called_when_enabled(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out, fingerprint=True)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch.object(g, "_fingerprint_hosts") as mock_fp, \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            g.run()
        mock_fp.assert_called_once()

    def test_fingerprint_not_called_when_disabled(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out, fingerprint=False)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch.object(g, "_fingerprint_hosts") as mock_fp, \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            g.run()
        mock_fp.assert_not_called()


class TestBuildTopology:
    def test_structure_keys(self):
        g = _grapher()
        g._hosts = _hosts()
        topo = g._build_topology(gateway="192.168.1.1", local_ip="192.168.1.10",
                                  subnet="192.168.1.0/24", scan_time="2026-06-01 12:00:00")
        assert set(topo.keys()) == {"subnet", "gateway", "local_ip", "scan_time", "hosts"}

    def test_gateway_role(self):
        g = _grapher()
        g._hosts = _hosts()
        topo = g._build_topology("192.168.1.1", "192.168.1.10", "192.168.1.0/24", "t")
        gw = next(h for h in topo["hosts"] if h["ip"] == "192.168.1.1")
        assert gw["role"] == "gateway"

    def test_local_role(self):
        g = _grapher()
        g._hosts = _hosts()
        topo = g._build_topology("192.168.1.1", "192.168.1.10", "192.168.1.0/24", "t")
        local = next(h for h in topo["hosts"] if h["ip"] == "192.168.1.10")
        assert local["role"] == "local"

    def test_regular_host_role(self):
        g = _grapher()
        g._hosts = _hosts()
        topo = g._build_topology("192.168.1.1", "192.168.1.10", "192.168.1.0/24", "t")
        host = next(h for h in topo["hosts"] if h["ip"] == "192.168.1.20")
        assert host["role"] == "host"

    def test_os_included_when_fingerprinted(self):
        g = _grapher()
        g._hosts = _hosts()
        g._os_map["192.168.1.20"] = "Linux / Unix"
        topo = g._build_topology("192.168.1.1", "192.168.1.10", "192.168.1.0/24", "t")
        host = next(h for h in topo["hosts"] if h["ip"] == "192.168.1.20")
        assert host["os"] == "Linux / Unix"

    def test_os_omitted_when_not_fingerprinted(self):
        g = _grapher()
        g._hosts = _hosts()
        topo = g._build_topology("192.168.1.1", "192.168.1.10", "192.168.1.0/24", "t")
        host = next(h for h in topo["hosts"] if h["ip"] == "192.168.1.20")
        assert "os" not in host

    def test_no_gateway_sets_none(self):
        g = _grapher()
        g._hosts = _hosts()
        topo = g._build_topology(None, "192.168.1.10", "192.168.1.0/24", "t")
        assert topo["gateway"] is None

    def test_local_ip_always_present(self):
        g = _grapher()
        g._hosts = []  # empty ARP results
        topo = g._build_topology(None, "192.168.1.10", "192.168.1.0/24", "t")
        assert any(h["ip"] == "192.168.1.10" for h in topo["hosts"])


class TestRunJson:
    def _run_json(self, tmp_path, fingerprint=False):
        out = str(tmp_path / "graph.json")
        g = _grapher(output=out, fingerprint=fingerprint)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            g.run()
        return json.loads(open(out).read())

    def test_writes_valid_json(self, tmp_path):
        data = self._run_json(tmp_path)
        assert isinstance(data, dict)

    def test_json_contains_subnet(self, tmp_path):
        data = self._run_json(tmp_path)
        assert data["subnet"] == "192.168.1.0/24"

    def test_json_contains_all_hosts(self, tmp_path):
        data = self._run_json(tmp_path)
        ips = {h["ip"] for h in data["hosts"]}
        assert "192.168.1.1" in ips
        assert "192.168.1.20" in ips

    def test_html_not_written_for_json_output(self, tmp_path):
        out = str(tmp_path / "graph.json")
        g = _grapher(output=out)
        with patch.object(g, "_arp_scan", return_value=_hosts()), \
             patch("sondare.services.graph._get_gateway", return_value="192.168.1.1"), \
             patch("sondare.services.graph.get_ip_address", return_value="192.168.1.10"), \
             patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"):
            g.run()
        assert not open(out).read().startswith("<!DOCTYPE html>")
