import ipaddress
import os
import psutil
import socket
import platform


def is_running_as_root() -> bool:
    """Returns True if the process has root/admin privileges."""
    if platform.system() != "Windows" and os.geteuid() != 0:
        return False
    return True


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


def get_subnet() -> str:
    """Returns the CIDR block of the active interface (e.g. 192.168.1.0/24)."""
    iface = get_network_interface()
    for addr in psutil.net_if_addrs().get(iface, []):
        if addr.family == socket.AF_INET and addr.netmask:
            network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
            return str(network)
    raise RuntimeError("Could not determine network CIDR for active interface.")
