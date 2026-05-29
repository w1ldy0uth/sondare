from typing import NamedTuple


class Host(NamedTuple):
    """A host discovered on the local network."""
    ip: str
    mac: str
    hostname: str | None = None
    vendor: str | None = None


class Port(NamedTuple):
    """An open TCP port on a scanned host."""
    ip: str
    port: int
    banner: str | None = None
    service: str | None = None


class Fingerprint(NamedTuple):
    """OS fingerprint inferred from a TCP SYN-ACK response."""
    ip: str
    os: str
    ttl: int
    window: int


class MdnsRecord(NamedTuple):
    """An mDNS/Bonjour service advertisement discovered on the local network."""
    hostname: str
    ip: str
    service: str
    port: int
