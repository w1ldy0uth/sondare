from typing import NamedTuple


class Host(NamedTuple):
    """A host discovered on the local network."""
    ip: str
    mac: str
