#!/usr/bin/python3
"""Install parent-death handling after exec, avoiding fork callbacks with threads."""
import ctypes
import os
import signal
import sys

if __name__ == "__main__":
    parent = int(sys.argv[1])
    if ctypes.CDLL(None).prctl(1, signal.SIGTERM) != 0:
        raise OSError("Could not enable DHCP parent-death cleanup")
    if os.getppid() != parent:
        sys.exit(1)
    executable = sys.argv[2]
    if executable not in ("/usr/sbin/dnsmasq", "/usr/bin/dnsmasq", "/sbin/dnsmasq", "/bin/dnsmasq"):
        raise ValueError("Unexpected DHCP executable")
    os.execv(executable, sys.argv[2:])
