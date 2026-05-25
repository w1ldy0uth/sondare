#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, sniff
from scapy.packet import Packet
from netscan.utils.system_utils import get_network_interface

_TCP_FLAGS: dict[int, str] = {
    0x02: "SYN",
    0x12: "SYN-ACK",
    0x10: "ACK",
    0x18: "PSH-ACK",
    0x01: "FIN",
    0x11: "FIN-ACK",
    0x04: "RST",
    0x14: "RST-ACK",
}

_ICMP_TYPES: dict[int, str] = {
    0:  "Echo reply",
    3:  "Unreachable",
    8:  "Echo request",
    11: "TTL exceeded",
}


def _tcp_info(pkt: Packet) -> tuple[str, str, str]:
    ip, tcp = pkt.getlayer(IP), pkt.getlayer(TCP)
    src = f"{ip.src}:{tcp.sport}"
    dst = f"{ip.dst}:{tcp.dport}"
    info = _TCP_FLAGS.get(int(tcp.flags), f"flags=0x{int(tcp.flags):02x}")
    return src, dst, info


def _udp_info(pkt: Packet) -> tuple[str, str, str]:
    ip, udp = pkt.getlayer(IP), pkt.getlayer(UDP)
    return f"{ip.src}:{udp.sport}", f"{ip.dst}:{udp.dport}", ""


def _icmp_info(pkt: Packet) -> tuple[str, str, str]:
    ip, icmp = pkt.getlayer(IP), pkt.getlayer(ICMP)
    info = _ICMP_TYPES.get(icmp.type, f"type={icmp.type}")
    return ip.src, ip.dst, info


def _arp_info(pkt: Packet) -> tuple[str, str, str]:
    arp = pkt.getlayer(ARP)
    if arp.op == 1:
        info = f"who has {arp.pdst}?"
    else:
        info = f"{arp.psrc} is at {arp.hwsrc}"
    return arp.psrc, arp.pdst, info


class TrafficSniffer:
    """
    Passively captures packets and prints one formatted line per packet.

    Recognised protocols: TCP, UDP, ICMP, ARP.
    An optional BPF filter string is passed directly to scapy so any
    libpcap filter expression works (e.g. "tcp", "udp port 53",
    "host 192.168.1.1").
    """

    def __init__(self, verbose: bool, bpf_filter: str | None) -> None:
        self._verbose = verbose
        self._filter = bpf_filter or ""

    def _handle(self, pkt: Packet) -> None:
        ts = datetime.now().strftime("%H:%M:%S")

        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            proto, src, dst, info = "TCP", *_tcp_info(pkt)
        elif pkt.haslayer(UDP) and pkt.haslayer(IP):
            proto, src, dst, info = "UDP", *_udp_info(pkt)
        elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
            proto, src, dst, info = "ICMP", *_icmp_info(pkt)
        elif pkt.haslayer(ARP):
            proto, src, dst, info = "ARP", *_arp_info(pkt)
        else:
            return

        print(f"  {ts}  {proto:<5}  {src:<22}  {dst:<22}  {info}")

    def sniff(self) -> None:
        iface = get_network_interface()
        filter_hint = f" [{self._filter}]" if self._filter else ""
        print(f"Sniffing on {iface}{filter_hint} (Ctrl+C to stop)\n")
        print(f"  {'TIME':<8}  {'PROTO':<5}  {'SRC':<22}  {'DST':<22}  INFO")
        print(f"  {'─'*8}  {'─'*5}  {'─'*22}  {'─'*22}  {'─'*20}")
        sniff(
            iface=iface,
            filter=self._filter,
            prn=self._handle,
            store=False,
            promisc=False,
        )
