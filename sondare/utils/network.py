import ipaddress
import platform
import re
import socket
import subprocess
import threading
import psutil
from concurrent.futures import ThreadPoolExecutor


IPV6_ALL_NODES_MAC  = "33:33:00:00:00:01"
IPV6_ALL_NODES_ADDR = "ff02::1"

_MDNS_SCAN_SERVICES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_ftp._tcp.local.",
    "_smb._tcp.local.",
    "_afp._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_homekit._tcp.local.",
]


def browse_mdns(service_types: list[str] | None = None, timeout: float = 5.0) -> list:
    """Returns a list of MdnsRecord for each service advertisement found on the network."""
    from sondare.models import MdnsRecord
    from sondare import _sondare
    try:
        types = service_types if service_types is not None else _MDNS_SCAN_SERVICES
        timeout_ms = int(timeout * 1000)
        raw = _sondare.mdns_scan(types, timeout_ms)
        return [MdnsRecord(hostname=h, ip=ip, service=s, port=p) for h, ip, s, p in raw]
    except Exception:
        return []


def _browse_mdns(timeout: float = 3.0) -> dict[str, str]:
    """Returns {ip: hostname} discovered via mDNS service browsing."""
    records = browse_mdns(service_types=_MDNS_SCAN_SERVICES, timeout=timeout)
    return {r.ip: r.hostname for r in records}


def _browse_ssdp(timeout: float = 3.0) -> dict[str, str]:
    """Returns {ip: friendly_name} discovered via SSDP/UPnP M-SEARCH."""
    import time
    import urllib.request
    import xml.etree.ElementTree as ET

    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.3)
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        locations: dict[str, str] = {}  # ip -> LOCATION url
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip not in locations:
                    text = data.decode("utf-8", errors="replace")
                    for line in text.splitlines():
                        if line.upper().startswith("LOCATION:"):
                            locations[ip] = line.split(":", 1)[1].strip()
                            break
            except socket.timeout:
                pass
    finally:
        sock.close()

    result: dict[str, str] = {}
    ns = {"u": "urn:schemas-upnp-org:device-1-0"}
    for ip, url in locations.items():
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                tree = ET.fromstring(resp.read())
            device = tree.find("u:device", ns)
            if device is None:
                continue
            friendly = device.findtext("u:friendlyName", namespaces=ns)
            if friendly:
                result[ip] = friendly.strip()
        except Exception:
            pass
    return result


def _netbios_name(ip: str, timeout: float = 1.0) -> str | None:
    """Returns the NetBIOS machine name for a Windows host, or None."""
    # NBSTAT query: wildcard name lookup
    query = (
        b"\xab\xcd\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) < 57:
            return None
        num_names = data[56]
        if num_names == 0:
            return None
        name = data[57:72].decode("ascii", errors="replace").rstrip()
        return name if name else None
    except Exception:
        return None
    finally:
        sock.close()


def is_ipv6_address(addr: str) -> bool:
    """Returns True if addr is a valid IPv6 address, False otherwise."""
    try:
        return isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address)
    except ValueError:
        return False


def get_port_service(port: int, proto: str = "tcp") -> str | None:
    """Returns the well-known service name for a port/protocol, or None."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def get_mac_vendor(mac: str) -> str | None:
    """Returns the full OUI vendor name for a MAC address, or None if unknown."""
    try:
        from scapy.all import conf
        short, long = conf.manufdb._get_manuf_couple(mac)
        return long if long != mac else None
    except Exception:
        return None


def resolve_hostname(ip: str) -> str | None:
    """Returns a PTR hostname for an IP, or None if not found."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None


def resolve_hostnames(ips: list[str]) -> dict[str, str | None]:
    """Returns {ip: hostname} via PTR, mDNS service browse, and NetBIOS fallbacks."""
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=min(len(ips) + 2, 22)) as pool:
        ptr_futures = {ip: pool.submit(resolve_hostname, ip) for ip in ips}
        mdns_future = pool.submit(_browse_mdns, 3.0)
        ssdp_future = pool.submit(_browse_ssdp, 3.0)
        mdns_map = mdns_future.result()
        ssdp_map = ssdp_future.result()
        result: dict[str, str | None] = {}
        for ip in ips:
            name = ptr_futures[ip].result()
            if not name:
                name = mdns_map.get(ip)
            if not name:
                name = ssdp_map.get(ip)
            if not name:
                name = _netbios_name(ip)
            result[ip] = name
    return result


def get_network_interface() -> str:
    """Returns the first active non-loopback interface that has an IPv4 address."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for interface, addr_list in addrs.items():
        if not stats.get(interface, None) or not stats[interface].isup:
            continue
        if interface.startswith("lo"):
            continue
        if any(a.family == socket.AF_INET and a.address for a in addr_list):
            return interface
    raise RuntimeError("No active network interface with an IPv4 address found.")


def get_ip_address() -> str:
    """Returns the IPv4 address of the active network interface."""
    iface = get_network_interface()
    for addr in psutil.net_if_addrs().get(iface, []):
        if addr.family == socket.AF_INET:
            return addr.address
    return socket.gethostbyname(socket.gethostname())


def read_arp_cache(subnet: str) -> dict[str, str]:
    """Returns {ip: mac} for all entries in the OS ARP cache that fall within subnet."""
    network = ipaddress.IPv4Network(subnet, strict=False)
    result: dict[str, str] = {}
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=5,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-f-]{11,17})", line, re.I)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("-", ":")
                    if ipaddress.IPv4Address(ip) in network:
                        result[ip] = mac.lower()
        else:
            out = subprocess.check_output(["arp", "-an"], text=True, timeout=5,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([\da-f:]{11,17})", line, re.I)
                if m:
                    ip, mac = m.group(1), m.group(2)
                    if ipaddress.IPv4Address(ip) in network:
                        result[ip] = mac.lower()
    except Exception:
        pass
    return result


def get_ipv6_link_local(iface: str) -> str | None:
    """Returns the link-local IPv6 address of the given interface (without scope suffix), or None."""
    for addr in psutil.net_if_addrs().get(iface, []):
        if addr.family == socket.AF_INET6:
            raw = addr.address.split("%")[0]
            if raw.lower().startswith("fe80"):
                return raw.lower()
    return None


def read_ndp_cache(iface: str) -> dict[str, str]:
    """Returns {ipv6: mac} from the OS NDP neighbor cache for the given interface."""
    result: dict[str, str] = {}
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(["ndp", "-an"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 3 or parts[2] != iface:
                    continue
                ip_raw = parts[0].split("%")[0].lower()
                mac = parts[1]
                if re.match(r"(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}", mac, re.I):
                    result[ip_raw] = mac.lower()
        else:
            out = subprocess.check_output(
                ["ip", "-6", "neigh", "show", "dev", iface],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if "lladdr" not in parts:
                    continue
                ip_raw = parts[0].split("%")[0].lower()
                mac = parts[parts.index("lladdr") + 1]
                result[ip_raw] = mac.lower()
    except Exception:
        pass
    return result


def warm_arp_cache(ip: str) -> None:
    """ARP-resolves ip and stores the result in Scapy's cache to avoid promiscuous mode errors."""
    from scapy.all import ARP, Ether, srp, conf
    iface = get_network_interface()
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=iface, timeout=2, verbose=False, promisc=False
    )
    for _, rcv in ans:
        conf.netcache.arp_cache[rcv.psrc] = rcv.hwsrc


def get_subnet() -> str:
    """Returns the CIDR block of the active interface (e.g. 192.168.1.0/24)."""
    iface = get_network_interface()
    for addr in psutil.net_if_addrs().get(iface, []):
        if addr.family == socket.AF_INET and addr.netmask:
            network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
            return str(network)
    raise RuntimeError("Could not determine network CIDR for active interface.")
