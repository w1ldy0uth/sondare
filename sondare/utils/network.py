import ipaddress
import platform
import re
import socket
import subprocess
import psutil
from concurrent.futures import ThreadPoolExecutor


def resolve_hostname(ip: str) -> str | None:
    """Returns the PTR hostname for an IP, or None if not found."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_hostnames(ips: list[str]) -> dict[str, str | None]:
    """Resolves PTR records for a list of IPs concurrently. Returns {ip: hostname}."""
    with ThreadPoolExecutor(max_workers=min(len(ips), 20)) as pool:
        return dict(zip(ips, pool.map(resolve_hostname, ips)))


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
