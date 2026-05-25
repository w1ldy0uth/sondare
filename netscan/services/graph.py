#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import json
import os
import platform
import subprocess
import threading
from datetime import datetime

from scapy.all import ARP, Ether, IP, ICMP, srp, sr1, conf
from netscan.models import Host
from netscan.services.fingerprint import OsFingerprinter
from netscan.utils.system_utils import get_subnet, get_network_interface, get_ip_address

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>netScan — Network Graph</title>
<script src="https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js"></script>
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
  <h3>netScan</h3>
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
    try:
        gw = conf.route.route("0.0.0.0")[2]
        return gw if gw not in _SKIP else None
    except Exception:
        return None


class NetworkGraph:
    """
    Discovers hosts via ARP, optionally fingerprints their OS, then renders
    an interactive HTML network graph using vis-network (loaded from CDN).
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
        self._hosts: list[Host] = []
        self._os_map: dict[str, str] = {}  # ip -> os string

    def _arp_scan(self) -> list[Host]:
        cidr = get_subnet()
        iface = get_network_interface()
        ans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            iface=iface,
            timeout=self._timeout,
            verbose=self._verbose,
            promisc=False,
        )[0]
        return [Host(ip=rcv.psrc, mac=rcv.hwsrc) for _, rcv in ans]

    @staticmethod
    def _ttl_to_os(ttl: int) -> str:
        for threshold, label in ((64, "Linux / Unix"), (128, "Windows"), (255, "Cisco / Network Device")):
            if ttl <= threshold:
                return label
        return "Cisco / Network Device"

    def _fingerprint_hosts(self, ips: list[str]) -> None:
        lock = threading.Lock()
        sem = threading.Semaphore(self._threads)

        def probe(ip: str) -> None:
            try:
                scanner = OsFingerprinter(
                    verbose=self._verbose, ip=ip, port=None, timeout=self._timeout
                )
                scanner.scan()
                result = scanner.get_results()
                if result:
                    with lock:
                        self._os_map[ip] = result.os
                    return
                # TCP failed (no open port) — fall back to ICMP TTL
                pkt = sr1(
                    IP(dst=ip) / ICMP(),
                    timeout=self._timeout,
                    verbose=self._verbose,
                    promisc=False,
                )
                if pkt and pkt.haslayer(IP):
                    with lock:
                        self._os_map[ip] = self._ttl_to_os(pkt.getlayer(IP).ttl)
            except Exception:
                pass
            finally:
                sem.release()

        threads = []
        for ip in ips:
            sem.acquire()
            t = threading.Thread(target=probe, args=(ip,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def _build_graph(
        self, gateway: str | None, local_ip: str
    ) -> tuple[list[dict], list[dict]]:
        nodes: list[dict] = []
        edges: list[dict] = []
        mac_lookup = {h.ip: h.mac for h in self._hosts}

        def _node(ip: str, group: str, extra_label: str = "") -> dict:
            mac = mac_lookup.get(ip, "unknown")
            os_str = self._os_map.get(ip, "")
            label_parts = [ip, mac]
            if extra_label:
                label_parts.append(extra_label)
            if os_str:
                label_parts.append(os_str)
            title = f"<b>{ip}</b><br>MAC: {mac}"
            if os_str:
                title += f"<br>OS: {os_str}"
            return {"id": ip, "label": "\n".join(label_parts), "title": title, "group": group}

        hub = gateway or local_ip

        if gateway:
            nodes.append(_node(gateway, "gateway", "gateway"))

        nodes.append(_node(local_ip, "local", "this machine"))
        if gateway and local_ip != gateway:
            edges.append({"from": gateway, "to": local_ip})

        for host in sorted(self._hosts, key=lambda h: h.ip):
            if host.ip in (gateway, local_ip):
                continue
            nodes.append(_node(host.ip, "host"))
            edges.append({"from": hub, "to": host.ip})

        return nodes, edges

    def run(self) -> str:
        local_ip = get_ip_address()
        gateway = _get_gateway()
        subnet = get_subnet()

        print("Constructing network graph...")
        self._hosts = self._arp_scan()

        if self._fingerprint and self._hosts:
            self._fingerprint_hosts([h.ip for h in self._hosts])

        nodes, edges = self._build_graph(gateway, local_ip)
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        host_count = len(nodes)

        html = (
            _HTML_TEMPLATE
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
