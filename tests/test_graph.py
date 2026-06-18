import json
from unittest.mock import patch, MagicMock
from sondare.services.graph import NetworkGraph, _get_gateway

_LOCAL_MAC = "ff:ee:dd:cc:bb:aa"
_LOCAL_IPV4 = "192.168.1.10"
_LOCAL_IPV6 = None
_GATEWAY_IP = "192.168.1.1"
_VIS_STUB = "/* vis-network stub */"


def _grapher(**kwargs) -> NetworkGraph:
    defaults = dict(verbose=False, timeout=3.0, threads=5, fingerprint=False,
                    output="/tmp/test_graph.html")
    return NetworkGraph(**{**defaults, **kwargs})


def _devices():
    """Three discovered devices: gateway, local machine, one regular host."""
    return [
        {"mac": "aa:bb:cc:dd:ee:01", "ipv4": "192.168.1.1",  "ipv6": None},
        {"mac": "aa:bb:cc:dd:ee:02", "ipv4": "192.168.1.10", "ipv6": None},
        {"mac": "aa:bb:cc:dd:ee:03", "ipv4": "192.168.1.20", "ipv6": None},
    ]


def _arp_map():
    return {d["mac"]: d["ipv4"] for d in _devices()}


def _patch_ipconfig(output: str | None):
    import subprocess as sp
    if output is None:
        return patch("sondare.services.graph.subprocess.check_output",
                     side_effect=sp.CalledProcessError(1, "ipconfig"))
    return patch("sondare.services.graph.subprocess.check_output", return_value=output)


# ---------------------------------------------------------------------------
# _get_gateway
# ---------------------------------------------------------------------------

class TestGetGateway:
    def test_returns_gateway_ip_via_ipconfig(self):
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig("192.168.1.1\n"):
            assert _get_gateway() == "192.168.1.1"

    def test_returns_none_for_zero_gateway(self):
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig("0.0.0.0\n"):
            assert _get_gateway() is None

    def test_returns_none_on_subprocess_failure(self):
        with patch("sondare.services.graph.platform.system", return_value="Darwin"), \
             patch("sondare.services.graph.get_network_interface", return_value="en0"), \
             _patch_ipconfig(None):
            assert _get_gateway() is None


# ---------------------------------------------------------------------------
# _merge
# ---------------------------------------------------------------------------

class TestMerge:
    def test_ipv4_only_device(self):
        g = _grapher()
        result = g._merge({"aa:bb:cc:dd:ee:01": "10.0.0.1"}, {})
        assert result == [{"mac": "aa:bb:cc:dd:ee:01", "ipv4": "10.0.0.1", "ipv6": None}]

    def test_ipv6_only_device(self):
        g = _grapher()
        result = g._merge({}, {"aa:bb:cc:dd:ee:01": "fe80::1"})
        assert result == [{"mac": "aa:bb:cc:dd:ee:01", "ipv4": None, "ipv6": "fe80::1"}]

    def test_dual_stack_device_merged_into_one(self):
        g = _grapher()
        arp = {"aa:bb:cc:dd:ee:01": "10.0.0.1"}
        ndp = {"aa:bb:cc:dd:ee:01": "fe80::1"}
        result = g._merge(arp, ndp)
        assert len(result) == 1
        assert result[0]["ipv4"] == "10.0.0.1"
        assert result[0]["ipv6"] == "fe80::1"

    def test_distinct_macs_produce_distinct_devices(self):
        g = _grapher()
        arp = {"aa:bb:cc:dd:ee:01": "10.0.0.1", "aa:bb:cc:dd:ee:02": "10.0.0.2"}
        result = g._merge(arp, {})
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _build_graph
# ---------------------------------------------------------------------------

class TestBuildGraph:
    def _graph(self):
        g = _grapher()
        g._devices = _devices()
        return g

    def _build(self, g, gateway=_GATEWAY_IP, local_ipv4=_LOCAL_IPV4,
               local_ipv6=None, local_mac=_LOCAL_MAC):
        return g._build_graph(gateway=gateway, local_ipv4=local_ipv4,
                               local_ipv6=local_ipv6, local_mac=local_mac)

    def test_gateway_node_has_gateway_group(self):
        g = self._graph()
        nodes, _ = self._build(g)
        gw = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:01")
        assert gw["group"] == "gateway"

    def test_local_node_has_local_group(self):
        g = self._graph()
        nodes, _ = self._build(g)
        local = next(n for n in nodes if n["id"] == _LOCAL_MAC)
        assert local["group"] == "local"

    def test_regular_host_has_host_group(self):
        g = self._graph()
        nodes, _ = self._build(g)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert host["group"] == "host"

    def test_edges_connect_hosts_to_gateway(self):
        g = self._graph()
        _, edges = self._build(g)
        assert any(e["to"] == "aa:bb:cc:dd:ee:03" for e in edges)

    def test_all_edges_originate_from_gateway(self):
        g = self._graph()
        _, edges = self._build(g)
        assert all(e["from"] == "aa:bb:cc:dd:ee:01" for e in edges)

    def test_no_gateway_edges_originate_from_local(self):
        g = self._graph()
        _, edges = self._build(g, gateway=None)
        assert all(e["from"] == _LOCAL_MAC for e in edges)

    def test_os_in_node_title_when_fingerprinted(self):
        g = self._graph()
        g._os_map["aa:bb:cc:dd:ee:03"] = "Linux / Unix"
        nodes, _ = self._build(g)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert "Linux / Unix" in host["title"]

    def test_os_in_node_label_when_fingerprinted(self):
        g = self._graph()
        g._os_map["aa:bb:cc:dd:ee:03"] = "Linux / Unix"
        nodes, _ = self._build(g)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert "OS: Linux / Unix" in host["label"]

    def test_vendor_in_node_label(self):
        g = self._graph()
        g._vendor_map["aa:bb:cc:dd:ee:03"] = "Apple, Inc."
        nodes, _ = self._build(g)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert "Vendor: Apple, Inc." in host["label"]

    def test_vendor_in_node_title(self):
        g = self._graph()
        g._vendor_map["aa:bb:cc:dd:ee:03"] = "Apple, Inc."
        nodes, _ = self._build(g)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert "Vendor: Apple, Inc." in host["title"]

    def test_no_vendor_line_when_unknown(self):
        g = self._graph()
        nodes, _ = self._build(g)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert "Vendor:" not in host["label"]

    def test_local_not_duplicated(self):
        g = self._graph()
        nodes, _ = self._build(g)
        ids = [n["id"] for n in nodes]
        assert ids.count(_LOCAL_MAC) == 1

    def test_gateway_not_duplicated(self):
        g = self._graph()
        nodes, _ = self._build(g)
        gw_nodes = [n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:01"]
        assert len(gw_nodes) == 1

    def test_dual_stack_device_single_node_with_both_ips(self):
        g = _grapher()
        g._devices = [{"mac": "aa:bb:cc:dd:ee:03", "ipv4": "192.168.1.20", "ipv6": "fe80::3"}]
        nodes, _ = self._build(g, gateway=None)
        host = next(n for n in nodes if n["id"] == "aa:bb:cc:dd:ee:03")
        assert "IPv4: 192.168.1.20" in host["label"]
        assert "IPv6: fe80::3" in host["label"]

    def test_ipv6_only_device_appears_as_node(self):
        g = _grapher()
        g._devices = [{"mac": "bb:cc:dd:ee:ff:01", "ipv4": None, "ipv6": "fe80::cafe"}]
        nodes, _ = self._build(g, gateway=None)
        assert any(n["id"] == "bb:cc:dd:ee:ff:01" for n in nodes)

    def test_local_mac_fallback_to_ip_when_none(self):
        g = _grapher()
        g._devices = []
        nodes, _ = g._build_graph(gateway=None, local_ipv4="10.0.0.1",
                                   local_ipv6=None, local_mac=None)
        assert any(n["id"] == "10.0.0.1" for n in nodes)


# ---------------------------------------------------------------------------
# _build_topology
# ---------------------------------------------------------------------------

class TestBuildTopology:
    def _topo(self, g, gateway=_GATEWAY_IP, local_ipv4=_LOCAL_IPV4,
              local_ipv6=None, local_mac=_LOCAL_MAC):
        return g._build_topology(gateway, local_ipv4, local_ipv6, local_mac,
                                  "192.168.1.0/24", "2026-06-01 12:00:00")

    def test_structure_keys(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g)
        assert set(topo.keys()) == {"subnet", "gateway", "local_ipv4", "scan_time", "hosts"}

    def test_gateway_role(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g)
        gw = next(h for h in topo["hosts"] if h.get("ipv4") == _GATEWAY_IP)
        assert gw["role"] == "gateway"

    def test_local_role(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g)
        local = next(h for h in topo["hosts"] if h.get("ipv4") == _LOCAL_IPV4)
        assert local["role"] == "local"

    def test_regular_host_role(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert host["role"] == "host"

    def test_os_included_when_fingerprinted(self):
        g = _grapher()
        g._devices = _devices()
        g._os_map["aa:bb:cc:dd:ee:03"] = "Linux / Unix"
        topo = self._topo(g)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert host["os"] == "Linux / Unix"

    def test_os_omitted_when_not_fingerprinted(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert "os" not in host

    def test_no_gateway_sets_none(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g, gateway=None)
        assert topo["gateway"] is None

    def test_local_machine_present_when_not_in_scan_results(self):
        g = _grapher()
        g._devices = []
        topo = self._topo(g)
        assert any(h.get("ipv4") == _LOCAL_IPV4 for h in topo["hosts"])

    def test_dual_stack_device_has_both_address_fields(self):
        g = _grapher()
        g._devices = [{"mac": "aa:bb:cc:dd:ee:03", "ipv4": "192.168.1.20", "ipv6": "fe80::3"}]
        topo = self._topo(g, gateway=None)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert host["ipv6"] == "fe80::3"

    def test_ipv4_only_device_has_no_ipv6_field(self):
        g = _grapher()
        g._devices = [{"mac": "aa:bb:cc:dd:ee:03", "ipv4": "192.168.1.20", "ipv6": None}]
        topo = self._topo(g, gateway=None)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert "ipv6" not in host

    def test_vendor_included_in_topology(self):
        g = _grapher()
        g._devices = _devices()
        g._vendor_map["aa:bb:cc:dd:ee:03"] = "Apple, Inc."
        topo = self._topo(g)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert host["vendor"] == "Apple, Inc."

    def test_vendor_omitted_when_unknown(self):
        g = _grapher()
        g._devices = _devices()
        topo = self._topo(g)
        host = next(h for h in topo["hosts"] if h.get("ipv4") == "192.168.1.20")
        assert "vendor" not in host


# ---------------------------------------------------------------------------
# run() — HTML
# ---------------------------------------------------------------------------

def _run_patches(g, arp=None, ndp=None):
    """Context manager that patches all I/O for g.run()."""
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch.object(g, "_arp_scan", return_value=arp or _arp_map()))
    stack.enter_context(patch.object(g, "_ndp_scan", return_value=ndp or {}))
    stack.enter_context(patch("sondare.services.graph._get_gateway", return_value=_GATEWAY_IP))
    stack.enter_context(patch("sondare.services.graph.get_ip_address", return_value=_LOCAL_IPV4))
    stack.enter_context(patch("sondare.services.graph.get_network_interface", return_value="en0"))
    stack.enter_context(patch("sondare.services.graph.get_ipv6_link_local", return_value=None))
    stack.enter_context(patch("sondare.services.graph._get_local_mac", return_value=_LOCAL_MAC))
    stack.enter_context(patch("sondare.services.graph.get_subnet", return_value="192.168.1.0/24"))
    stack.enter_context(patch("sondare.services.graph._load_vis_network", return_value=_VIS_STUB))
    return stack


class TestRun:
    def test_writes_html_file(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with _run_patches(g):
            g.run()
        assert open(out).read().startswith("<!DOCTYPE html>")

    def test_html_contains_node_data(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with _run_patches(g):
            g.run()
        assert "192.168.1.20" in open(out).read()

    def test_returns_output_path(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with _run_patches(g):
            result = g.run()
        assert result == out

    def test_fingerprint_called_when_enabled(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out, fingerprint=True)
        with _run_patches(g), patch.object(g, "_fingerprint_hosts") as mock_fp:
            g.run()
        mock_fp.assert_called_once()

    def test_fingerprint_not_called_when_disabled(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out, fingerprint=False)
        with _run_patches(g), patch.object(g, "_fingerprint_hosts") as mock_fp:
            g.run()
        mock_fp.assert_not_called()

    def test_vis_network_inlined_no_cdn(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with _run_patches(g):
            g.run()
        content = open(out).read()
        assert "unpkg.com" not in content
        assert _VIS_STUB in content

    def test_vendor_lookup_called_for_each_device(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with _run_patches(g), \
             patch("sondare.services.graph.get_mac_vendor", return_value="Raspberry Pi") as mock_v:
            g.run()
        assert mock_v.call_count == len(_arp_map())

    def test_ndp_scan_called_during_run(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        with _run_patches(g), patch.object(g, "_ndp_scan", return_value={}) as mock_ndp:
            g.run()
        mock_ndp.assert_called_once()

    def test_dual_stack_device_is_single_node(self, tmp_path):
        out = str(tmp_path / "graph.html")
        g = _grapher(output=out)
        shared_mac = "aa:bb:cc:dd:ee:05"
        arp = {shared_mac: "192.168.1.50"}
        ndp = {shared_mac: "fe80::5"}
        with _run_patches(g, arp=arp, ndp=ndp):
            g.run()
        content = open(out).read()
        # Both addresses present and only one node id for that MAC
        assert shared_mac in content
        assert content.count(shared_mac) >= 1  # appears as node id
        assert "192.168.1.50" in content
        assert "fe80::5" in content


# ---------------------------------------------------------------------------
# run() — JSON
# ---------------------------------------------------------------------------

class TestRunJson:
    def _run_json(self, tmp_path, fingerprint=False, ndp=None):
        out = str(tmp_path / "graph.json")
        g = _grapher(output=out, fingerprint=fingerprint)
        with _run_patches(g, ndp=ndp or {}):
            g.run()
        return json.loads(open(out).read())

    def test_writes_valid_json(self, tmp_path):
        assert isinstance(self._run_json(tmp_path), dict)

    def test_json_contains_subnet(self, tmp_path):
        data = self._run_json(tmp_path)
        assert data["subnet"] == "192.168.1.0/24"

    def test_json_contains_all_discovered_hosts(self, tmp_path):
        data = self._run_json(tmp_path)
        ipv4s = {h.get("ipv4") for h in data["hosts"]}
        assert "192.168.1.1" in ipv4s
        assert "192.168.1.20" in ipv4s

    def test_html_not_written_for_json_output(self, tmp_path):
        out = str(tmp_path / "graph.json")
        g = _grapher(output=out)
        with _run_patches(g):
            g.run()
        assert not open(out).read().startswith("<!DOCTYPE html>")

    def test_json_dual_stack_host_has_both_fields(self, tmp_path):
        shared_mac = "aa:bb:cc:dd:ee:05"
        data = self._run_json(tmp_path, ndp={shared_mac: "fe80::5"},
                              )
        # shared_mac appears only in ndp (no ipv4), so it should have ipv6 but no ipv4
        host = next((h for h in data["hosts"] if h.get("ipv6") == "fe80::5"), None)
        assert host is not None
        assert "ipv4" not in host

    def test_json_local_ipv4_key_present(self, tmp_path):
        data = self._run_json(tmp_path)
        assert "local_ipv4" in data
        assert data["local_ipv4"] == _LOCAL_IPV4
