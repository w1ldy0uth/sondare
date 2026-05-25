from typing import NamedTuple


class Host(NamedTuple):
    """A host discovered on the local network."""
    ip: str
    mac: str


class Port(NamedTuple):
    """An open TCP port on a scanned host."""
    ip: str
    port: int


class Fingerprint(NamedTuple):
    """OS fingerprint inferred from a TCP SYN-ACK response."""
    ip: str
    os: str
    ttl: int
    window: int
