import os
import platform


def is_running_as_root() -> bool:
    """Returns True if the process has root/admin privileges."""
    if platform.system() != "Windows" and os.geteuid() != 0:
        return False
    return True
