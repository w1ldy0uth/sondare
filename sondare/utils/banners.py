#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import re
import socket
import ssl

_HTTP_PORTS = {80, 8080, 8008, 8888}
_HTTPS_PORTS = {443, 8443}
_SMB_PORTS = {139, 445}

# SMBv2 Negotiate Request: NetBIOS header + SMB2 header (64 bytes) + body with 4 dialects
_SMBv2_NEGOTIATE = (
    b"\x00\x00\x00\x6c"                    # NetBIOS: Session Message, length=108
    b"\xfe\x53\x4d\x42"                    # SMB2 ProtocolId
    b"\x40\x00"                            # StructureSize=64
    b"\x00\x00"                            # CreditCharge=0
    b"\x00\x00\x00\x00"                    # Status=0
    b"\x00\x00"                            # Command=Negotiate
    b"\x1f\x00"                            # Credits=31
    b"\x00\x00\x00\x00"                    # Flags=0
    b"\x00\x00\x00\x00"                    # NextCommand=0
    b"\x00\x00\x00\x00\x00\x00\x00\x00"   # MessageId=0
    b"\x00\x00\x00\x00"                    # Reserved
    b"\x00\x00\x00\x00"                    # TreeId=0
    b"\x00\x00\x00\x00\x00\x00\x00\x00"   # SessionId=0
    b"\x00\x00\x00\x00\x00\x00\x00\x00"   # Signature (16 bytes)
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x24\x00"                            # Body StructureSize=36
    b"\x04\x00"                            # DialectCount=4
    b"\x00\x00"                            # SecurityMode=0
    b"\x00\x00"                            # Reserved=0
    b"\x7f\x00\x00\x00"                    # Capabilities=0x7f
    b"\x00\x00\x00\x00\x00\x00\x00\x00"   # ClientGuid (16 bytes)
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"   # ClientStartTime=0
    b"\x02\x02"                            # Dialect: SMB 2.0.2
    b"\x10\x02"                            # Dialect: SMB 2.1.0
    b"\x00\x03"                            # Dialect: SMB 3.0.0
    b"\x02\x03"                            # Dialect: SMB 3.0.2
)

# DialectRevision → human-readable OS hint
# offset in response: 4 (NetBIOS) + 64 (SMB2 header) + 2 (StructureSize) + 2 (SecurityMode) = 72
_SMB_DIALECT_OFFSET = 72
_SMB_DIALECTS: dict[int, str] = {
    0x0202: "SMB 2.0.2 (Windows Vista / Server 2008)",
    0x0210: "SMB 2.1 (Windows 7 / Server 2008 R2)",
    0x0300: "SMB 3.0 (Windows 8 / Server 2012)",
    0x0302: "SMB 3.0.2 (Windows 8.1 / Server 2012 R2+)",
}

_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_TLS_CONTEXT.check_hostname = False
_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_REALM_RE = re.compile(r'realm="([^"]+)"', re.IGNORECASE)
_META_REFRESH_RE = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=[^>]*URL=([^"\'>\s]+)', re.IGNORECASE)


def _fetch_http(ip: str, port: int, path: str, timeout: float, tls: bool = False) -> str:
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        sock = _TLS_CONTEXT.wrap_socket(raw, server_hostname=ip) if tls else raw
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        return b"".join(chunks).decode(errors="replace")


def _parse_http(data: str) -> str | None:
    for line in data.splitlines():
        lower = line.lower()
        if lower.startswith("server:"):
            return line.split(":", 1)[1].strip()
        if lower.startswith("x-powered-by:"):
            return line.split(":", 1)[1].strip()
        if lower.startswith("www-authenticate:"):
            m = _REALM_RE.search(line)
            return m.group(1) if m else line.split(":", 1)[1].strip()
    m = _TITLE_RE.search(data)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        if title:
            return title
    return None


def _meta_refresh_path(data: str) -> str | None:
    m = _META_REFRESH_RE.search(data)
    if not m:
        return None
    url = m.group(1)
    return None if url.startswith("http") else "/" + url.lstrip("/")


def _smb_banner(ip: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_SMBv2_NEGOTIATE)
            data = sock.recv(256)
        if len(data) < _SMB_DIALECT_OFFSET + 2:
            return None
        if data[4:8] != b"\xfe\x53\x4d\x42":
            return None
        dialect = int.from_bytes(data[_SMB_DIALECT_OFFSET:_SMB_DIALECT_OFFSET + 2], "little")
        return _SMB_DIALECTS.get(dialect)
    except Exception:
        return None


def grab_banner(ip: str, port: int, timeout: float) -> str | None:
    """Opens a real TCP connection and reads the service banner, if any."""
    if port in _SMB_PORTS:
        return _smb_banner(ip, port, timeout)

    tls = port in _HTTPS_PORTS
    if not tls and port not in _HTTP_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = sock.recv(1024)
            return data.decode(errors="replace").strip() or None
        except Exception:
            return None

    try:
        first = _fetch_http(ip, port, "/", timeout, tls=tls)
        banner = _parse_http(first)
        if banner:
            return banner
        redirect = _meta_refresh_path(first)
        if redirect:
            second = _fetch_http(ip, port, redirect, timeout, tls=tls)
            banner = _parse_http(second)
            if banner:
                return banner
        lines = first.splitlines()
        return lines[0].strip() if lines else None
    except Exception:
        return None
