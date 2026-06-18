#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import json
import os
import platform
import psutil
import socket
import subprocess
import threading
from datetime import datetime
from importlib.resources import files as _res_files

from sondare import _sondare
from sondare.services.fingerprint import OsFingerprinter
from sondare.utils.network import (
    get_subnet, get_network_interface, get_ip_address,
    get_ipv6_link_local, read_ndp_cache, get_mac_vendor,
)

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>sondare — Network Graph</title>
<script>VIS_NETWORK_JS</script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; }
#graph { width: 100vw; height: 100vh; }
#info {
  position: fixed; top: 20px; left: 20px;
  background: rgba(22,27,34,0.92); border: 1px solid #30363d;
  border-radius: 6px; padding: 12px 16px; font-size: 12px; line-height: 1.6;
}
#info h3 { font-size: 14px; color: #58a6ff; margin-bottom: 6px; }
#info span { color: #8b949e; }
#legend {
  position: fixed; bottom: 20px; left: 20px;
  background: rgba(22,27,34,0.92); border: 1px solid #30363d;
  border-radius: 6px; padding: 12px 16px; font-size: 12px;
}
#legend h4 { margin-bottom: 8px; color: #8b949e; letter-spacing: 0.05em; }
.leg { display: flex; align-items: center; gap: 8px; margin: 5px 0; }
.dot { width: 11px; height: 11px; border-radius: 50%; flex-shrink: 0; }
</style>
</head>
<body>
<div id="graph"></div>
<div id="info">
  <h3>sondare</h3>
  <div><span>Subnet:  </span>SUBNET</div>
  <div><span>Hosts:   </span>HOST_COUNT</div>
  <div><span>Scanned: </span>SCAN_TIME</div>
</div>
<div id="legend">
  <h4>LEGEND</h4>
  <div class="leg"><div class="dot" style="background:#f0a500"></div>Gateway</div>
  <div class="leg"><div class="dot" style="background:#4c9be8"></div>This machine</div>
  <div class="leg"><div class="dot" style="background:#3fb950"></div>Host</div>
</div>
<script>
const nodes = new vis.DataSet(NODES_JSON);
const edges = new vis.DataSet(EDGES_JSON);
const options = {
  nodes: {
    font: { color: '#c9d1d9', face: 'Courier New', size: 12, multi: true },
    borderWidth: 2,
    shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 8 },
  },
  edges: {
    color: { color: '#30363d', highlight: '#58a6ff', hover: '#58a6ff' },
    width: 2,
    smooth: { type: 'continuous' },
    hoverWidth: 3,
  },
  groups: {
    gateway: {
      shape: 'star', size: 34,
      color: { background: '#f0a500', border: '#b07800', highlight: { background: '#ffc107', border: '#b07800' } },
    },
    local: {
      shape: 'diamond', size: 24,
      color: { background: '#4c9be8', border: '#2055a0', highlight: { background: '#74b9f5', border: '#2055a0' } },
    },
    host: {
      shape: 'dot', size: 20,
      color: { background: '#3fb950', border: '#238636', highlight: { background: '#56d364', border: '#238636' } },
    },
  },
  physics: {
    solver: 'forceAtlas2Based',
    forceAtlas2Based: { gravitationalConstant: -80, springLength: 160, springConstant: 0.05 },
    stabilization: { iterations: 200 },
  },
  interaction: { hover: true, tooltipDelay: 80, navigationButtons: true, keyboard: true },
};
const network = new vis.Network(document.getElementById('graph'), { nodes, edges }, options);
</script>
</body>
</html>
"""


def _load_vis_network() -> str:
    return _res_files("sondare").joinpath("static/vis-network.min.js").read_text(encoding="utf-8")


def _get_gateway() -> str | None:
    """Returns the default gateway IP scoped to the physical network interface."""
    _SKIP = {"0.0.0.0", "127.0.0.1"}
    try:
        iface = get_network_interface()
        system = platform.system()
        if system == "Darwin":
            out = subprocess.check_output(
                ["/usr/sbin/ipconfig", "getoption", iface, "router"],
                text=True, stderr=subprocess.DEVNULL,
            ).strip()
            if out and out not in _SKIP:
                return out
        elif system == "Linux":
            out = subprocess.check_output(
                ["ip", "route", "show", "dev", iface],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if "default" in parts and "via" in parts:
                    gw = parts[parts.index("via") + 1]
                    if gw not in _SKIP:
                        return gw
    except Exception:
        pass
    return None


def _get_local_mac(iface: str) -> str | None:
    """Returns the MAC address of the local network interface."""
    try:
        link_family = getattr(psutil, "AF_LINK", getattr(socket, "AF_PACKET", None))
        if link_family is None:
            return None
        for addr in psutil.net_if_addrs().get(iface, []):
            if addr.family == link_family:
                return addr.address.lower().replace("-", ":")
    except Exception:
        pass
    return None


class NetworkGraph:
    """
    Discovers hosts via ARP + ICMPv6 multicast (NDP), merges results by MAC
    so each physical device appears as one node regardless of address family,
    optionally fingerprints their OS, then renders an interactive HTML network
    graph using vis-network (bundled, no CDN needed).
    """

    def __init__(
        self,
        verbose: bool,
        timeout: float,
        threads: int,
        fingerprint: bool,
        output: str,
    ) -> None:
        self._verbose = verbose
        self._timeout = timeout
        self._threads = threads
        self._fingerprint = fingerprint
        self._output = output
        self._devices: list[dict] = []  # [{mac, ipv4, ipv6}] — one entry per physical device
        self._os_map: dict[str, str] = {}      # mac -> os string
        self._vendor_map: dict[str, str] = {}  # mac -> vendor string

    def _arp_scan(self) -> dict[str, str]:
        """Returns {mac: ipv4} from ARP broadcast."""
        cidr = get_subnet()
        iface = get_network_interface()
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        pairs = _sondare.arp_sweep_v4(iface, cidr, 500, grace_ms)
        return {mac.lower(): ip for ip, mac in pairs}

    def _ndp_scan(self) -> dict[str, str]:
        """Returns {mac: ipv6} from ICMPv6 multicast echo + NDP neighbor cache."""
        iface = get_network_interface()
        grace_ms = max(200, int(self._timeout * 1000 // 2))
        pairs = _sondare.ndp_sweep(iface, 500, grace_ms)
        result: dict[str, str] = {}
        for ip, mac in pairs:
            result[mac.lower()] = ip.lower()
        for ip, mac in read_ndp_cache(iface).items():
            if mac not in result and not ip.startswith("ff"):
                result[mac] = ip
        return result

    def _merge(self, arp: dict[str, str], ndp: dict[str, str]) -> list[dict]:
        """Merges ARP and NDP results by MAC — one dict per physical device."""
        all_macs = set(arp) | set(ndp)
        return [{"mac": m, "ipv4": arp.get(m), "ipv6": ndp.get(m)} for m in all_macs]

    def _preferred_ip(self, device: dict) -> str:
        """IPv4 preferred for OS fingerprinting; fall back to IPv6."""
        return device["ipv4"] or device["ipv6"]

    def _fingerprint_hosts(self, devices: list[dict]) -> None:
        lock = threading.Lock()
        sem = threading.Semaphore(self._threads)

        def probe(device: dict) -> None:
            ip = self._preferred_ip(device)
            try:
                scanner = OsFingerprinter(
                    verbose=self._verbose, ip=ip, port=None, timeout=self._timeout
                )
                scanner.scan()
                result = scanner.get_results()
                if result:
                    with lock:
                        self._os_map[device["mac"]] = result.os
            except Exception:
                pass
            finally:
                sem.release()

        threads = []
        for device in devices:
            sem.acquire()
            t = threading.Thread(target=probe, args=(device,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def _build_topology(
        self,
        gateway: str | None,
        local_ipv4: str,
        local_ipv6: str | None,
        local_mac: str | None,
        subnet: str,
        scan_time: str,
    ) -> dict:
        ipv4_to_mac = {d["ipv4"]: d["mac"] for d in self._devices if d["ipv4"]}
        gw_mac = ipv4_to_mac.get(gateway) if gateway else None

        def _role(d: dict) -> str:
            if d["mac"] == gw_mac or d["ipv4"] == gateway:
                return "gateway"
            if d["mac"] == local_mac or d["ipv4"] == local_ipv4:
                return "local"
            return "host"

        hosts = []
        for d in sorted(self._devices, key=lambda x: (x["ipv4"] or x["ipv6"] or "")):
            entry: dict = {"mac": d["mac"], "role": _role(d)}
            if d["ipv4"]:
                entry["ipv4"] = d["ipv4"]
            if d["ipv6"]:
                entry["ipv6"] = d["ipv6"]
            if d["mac"] in self._vendor_map:
                entry["vendor"] = self._vendor_map[d["mac"]]
            if d["mac"] in self._os_map:
                entry["os"] = self._os_map[d["mac"]]
            hosts.append(entry)

        # Ensure local machine appears even when it didn't respond to ARP/NDP
        local_present = any(
            h.get("ipv4") == local_ipv4 or h.get("mac") == local_mac
            for h in hosts
        )
        if not local_present:
            local_entry: dict = {"mac": local_mac or "local", "role": "local", "ipv4": local_ipv4}
            if local_ipv6:
                local_entry["ipv6"] = local_ipv6
            hosts.append(local_entry)

        return {
            "subnet": subnet,
            "gateway": gateway,
            "local_ipv4": local_ipv4,
            "scan_time": scan_time,
            "hosts": hosts,
        }

    def _build_graph(
        self,
        gateway: str | None,
        local_ipv4: str,
        local_ipv6: str | None,
        local_mac: str | None,
    ) -> tuple[list[dict], list[dict]]:
        nodes: list[dict] = []
        edges: list[dict] = []

        ipv4_to_mac = {d["ipv4"]: d["mac"] for d in self._devices if d["ipv4"]}
        gw_mac = ipv4_to_mac.get(gateway) if gateway else None
        local_id = local_mac or local_ipv4  # fallback to IP when MAC unavailable

        def _node(node_id: str, ipv4: str | None, ipv6: str | None, group: str, extra: str = "") -> dict:
            os_str     = self._os_map.get(node_id, "")
            vendor_str = self._vendor_map.get(node_id, "")
            label_parts: list[str] = []
            if ipv4:
                label_parts.append(f"IPv4: {ipv4}")
            if ipv6:
                label_parts.append(f"IPv6: {ipv6}")
            label_parts.append(f"MAC:  {node_id}")
            if vendor_str:
                label_parts.append(f"Vendor: {vendor_str}")
            if extra:
                label_parts.append(extra)
            if os_str:
                label_parts.append(f"OS: {os_str}")
            title = f"<b>{ipv4 or ipv6 or node_id}</b>"
            if ipv4 and ipv6:
                title += f"<br>IPv6: {ipv6}"
            title += f"<br>MAC: {node_id}"
            if vendor_str:
                title += f"<br>Vendor: {vendor_str}"
            if os_str:
                title += f"<br>OS: {os_str}"
            return {"id": node_id, "label": "\n".join(label_parts), "title": title, "group": group}

        hub_id = gw_mac or local_id

        if gateway and gw_mac:
            gw_dev = next((d for d in self._devices if d["mac"] == gw_mac), None)
            nodes.append(_node(gw_mac, gw_dev["ipv4"] if gw_dev else gateway,
                               gw_dev["ipv6"] if gw_dev else None, "gateway", "gateway"))

        nodes.append(_node(local_id, local_ipv4, local_ipv6, "local", "this machine"))
        if gw_mac and local_id != gw_mac:
            edges.append({"from": gw_mac, "to": local_id})

        for d in sorted(self._devices, key=lambda x: (x["ipv4"] or x["ipv6"] or "")):
            mac = d["mac"]
            if mac in (gw_mac, local_id):
                continue
            nodes.append(_node(mac, d["ipv4"], d["ipv6"], "host"))
            edges.append({"from": hub_id, "to": mac})

        return nodes, edges

    def run(self) -> str:
        iface      = get_network_interface()
        local_ipv4 = get_ip_address()
        local_ipv6 = get_ipv6_link_local(iface)
        local_mac  = _get_local_mac(iface)
        gateway    = _get_gateway()
        subnet     = get_subnet()

        print("Constructing network graph...")
        arp = self._arp_scan()
        ndp = self._ndp_scan()
        self._devices = self._merge(arp, ndp)
        self._vendor_map = {
            d["mac"]: v
            for d in self._devices
            if (v := get_mac_vendor(d["mac"]))
        }

        if self._fingerprint and self._devices:
            self._fingerprint_hosts(self._devices)

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if self._output.endswith(".json"):
            topology = self._build_topology(gateway, local_ipv4, local_ipv6, local_mac, subnet, scan_time)
            with open(self._output, "w", encoding="utf-8") as f:
                json.dump(topology, f, indent=2)
            print(f"Network topology saved in {os.path.abspath(self._output)}")
        else:
            nodes, edges = self._build_graph(gateway, local_ipv4, local_ipv6, local_mac)
            host_count = len(nodes)
            html = (
                _HTML_TEMPLATE
                .replace("VIS_NETWORK_JS", _load_vis_network())
                .replace("NODES_JSON", json.dumps(nodes))
                .replace("EDGES_JSON", json.dumps(edges))
                .replace("SUBNET", subnet)
                .replace("HOST_COUNT", str(host_count))
                .replace("SCAN_TIME", scan_time)
            )
            with open(self._output, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"Network graph saved in {os.path.abspath(self._output)}")

        return self._output
