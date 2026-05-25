import socket
from unittest.mock import MagicMock
import pytest


@pytest.fixture
def net_mocks():
    """Factory fixture returning (addrs, stats) psutil mock dicts for a single eth0 interface."""
    def make(ip: str = "192.168.1.5") -> tuple[dict, dict]:
        addr = MagicMock()
        addr.family = socket.AF_INET
        addr.address = ip
        addr.netmask = "255.255.255.0"
        stat = MagicMock()
        stat.isup = True
        return {"eth0": [addr]}, {"eth0": stat}
    return make
