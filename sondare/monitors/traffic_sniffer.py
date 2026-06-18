#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import socket
import struct
from datetime import datetime
from sondare import _sondare
from sondare.utils.network import get_network_interface

_ETH_LEN = 14

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


def _ipv4_addrs(raw: bytes, off: int) -> tuple[str, str, int, int]:
    """Returns (src_ip, dst_ip, protocol, header_end) from an IPv4 header."""
    ihl = (raw[off] & 0x0F) * 4
    proto = raw[off + 9]
    src = socket.inet_ntoa(raw[off + 12 : off + 16])
    dst = socket.inet_ntoa(raw[off + 16 : off + 20])
    return src, dst, proto, off + ihl


def _parse_tcp(raw: bytes) -> tuple[str, str, str, str] | None:
    off = _ETH_LEN
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype != 0x0800:
        return None
    if len(raw) < off + 20:
        return None
    src_ip, dst_ip, proto, hdr_end = _ipv4_addrs(raw, off)
    if proto != 6 or len(raw) < hdr_end + 14:
        return None
    sport, dport = struct.unpack_from("!HH", raw, hdr_end)
    flags = raw[hdr_end + 13]
    info = _TCP_FLAGS.get(flags, f"flags=0x{flags:02x}")
    return "TCP", f"{src_ip}:{sport}", f"{dst_ip}:{dport}", info


def _parse_udp(raw: bytes) -> tuple[str, str, str, str] | None:
    off = _ETH_LEN
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype != 0x0800:
        return None
    if len(raw) < off + 20:
        return None
    src_ip, dst_ip, proto, hdr_end = _ipv4_addrs(raw, off)
    if proto != 17 or len(raw) < hdr_end + 8:
        return None
    sport, dport = struct.unpack_from("!HH", raw, hdr_end)
    return "UDP", f"{src_ip}:{sport}", f"{dst_ip}:{dport}", ""


def _parse_icmp(raw: bytes) -> tuple[str, str, str, str] | None:
    off = _ETH_LEN
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype != 0x0800:
        return None
    if len(raw) < off + 20:
        return None
    src_ip, dst_ip, proto, hdr_end = _ipv4_addrs(raw, off)
    if proto != 1 or len(raw) < hdr_end + 2:
        return None
    icmp_type = raw[hdr_end]
    info = _ICMP_TYPES.get(icmp_type, f"type={icmp_type}")
    return "ICMP", src_ip, dst_ip, info


def _parse_arp(raw: bytes) -> tuple[str, str, str, str] | None:
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype != 0x0806 or len(raw) < _ETH_LEN + 28:
        return None
    op = struct.unpack_from("!H", raw, _ETH_LEN + 6)[0]
    sha = ":".join(f"{b:02x}" for b in raw[22:28])
    spa = ".".join(str(b) for b in raw[28:32])
    tpa = ".".join(str(b) for b in raw[38:42])
    if op == 1:
        info = f"who has {tpa}?"
    else:
        info = f"{spa} is at {sha}"
    return "ARP", spa, tpa, info


def _parse_packet(raw: bytes) -> tuple[str, str, str, str] | None:
    if len(raw) < _ETH_LEN + 2:
        return None
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype == 0x0800 and len(raw) >= _ETH_LEN + 20:
        proto = raw[_ETH_LEN + 9]
        if proto == 6:
            return _parse_tcp(raw)
        if proto == 17:
            return _parse_udp(raw)
        if proto == 1:
            return _parse_icmp(raw)
    if ethertype == 0x0806:
        return _parse_arp(raw)
    return None


class TrafficSniffer:
    """
    Passively captures packets and prints one formatted line per packet.

    Recognised protocols: TCP, UDP, ICMP, ARP.
    An optional BPF filter string is passed directly to libpcap so any
    filter expression works (e.g. "tcp", "udp port 53",
    "host 192.168.1.1").
    """

    def __init__(self, verbose: bool, bpf_filter: str | None) -> None:
        self._verbose = verbose
        self._filter = bpf_filter or ""

    def _handle(self, raw: bytes) -> None:
        parsed = _parse_packet(raw)
        if parsed is None:
            return
        proto, src, dst, info = parsed
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  {ts}  {proto:<5}  {src:<22}  {dst:<22}  {info}")

    def sniff(self) -> None:
        iface = get_network_interface()
        filter_hint = f" [{self._filter}]" if self._filter else ""
        print(f"Sniffing on {iface}{filter_hint} (Ctrl+C to stop)\n")
        print(f"  {'TIME':<8}  {'PROTO':<5}  {'SRC':<22}  {'DST':<22}  INFO")
        print(f"  {'─'*8}  {'─'*5}  {'─'*22}  {'─'*22}  {'─'*20}")
        _sondare.sniff(iface, self._filter, self._handle)
