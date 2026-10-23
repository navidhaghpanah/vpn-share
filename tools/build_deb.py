"""Build an architecture-independent Debian package without host installation."""
import io
import os
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "work" / "linux-vpnshare"
if not SRC.exists(): SRC=ROOT / "Linux"
OUT = ROOT / "outputs" / "VPNShare-Linux"
OUT.mkdir(exist_ok=True, parents=True)


def tar_gz(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        parents = sorted({str(parent) for name, _, _ in files for parent in Path(name).parents if str(parent) != "."}, key=lambda x: (x.count("/"), x))
        for directory in parents:
            info = tarfile.TarInfo(directory.replace("\\", "/")); info.type = tarfile.DIRTYPE; info.mode = 0o755
            archive.addfile(info)
        for name, contents, mode in files:
            info = tarfile.TarInfo(name.replace("\\", "/")); info.mode = mode; info.size = len(contents)
            archive.addfile(info, io.BytesIO(contents))
    return stream.getvalue()


control = b"""Package: vpnshare
Version: 0.5.0~preview8
Section: net
Priority: optional
Architecture: all
Maintainer: VPN Share Project <noreply@localhost>
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, network-manager, nftables, iproute2, dnsmasq-base, pkexec | policykit-1
Description: Desktop widget for sharing a routed VPN over Wi-Fi or Ethernet
 Native GTK widget with a privileged, fixed-path network helper,
 dedicated NetworkManager profiles, DHCP/DNS and isolated nftables rules.
 Engineering build; physical end-to-end validation is pending.
"""
launcher = b'#!/usr/bin/python3\nimport os\nos.execv("/usr/bin/python3",["/usr/bin/python3","/usr/lib/vpnshare/widget.py"])\n'
helper = b'#!/usr/bin/python3\nimport runpy\nrunpy.run_path("/usr/lib/vpnshare/helper.py",run_name="__main__")\n'
# The fixed helper directory is root-owned and is the only import search addition.
helper = b'#!/usr/bin/python3\nimport sys,runpy\nsys.path.insert(0,"/usr/lib/vpnshare")\nrunpy.run_path("/usr/lib/vpnshare/helper.py",run_name="__main__")\n'
desktop = b"""[Desktop Entry]
Type=Application
Name=VPN Share
Comment=Share your connected VPN over Wi-Fi or Ethernet
Exec=vpnshare
Icon=vpnshare
Terminal=false
Categories=Network;Utility;
StartupWMClass=vpnshare
"""
policy = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="org.navid.vpnshare.configure">
    <description>Configure VPN Share networking</description>
    <message>Authentication is required to share a VPN connection.</message>
    <defaults><allow_any>no</allow_any><allow_inactive>auth_admin</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/lib/vpnshare/vpnshare-helper</annotate>
  </action>
</policyconfig>
"""
files = [(f"usr/lib/vpnshare/{name}", (SRC / name).read_bytes(), 0o644) for name in ("core.py", "helper.py", "widget.py", "dhcp_child.py", "about.json")]
files += [("usr/bin/vpnshare", launcher, 0o755), ("usr/lib/vpnshare/vpnshare-helper", helper, 0o755),
          ("usr/share/applications/vpnshare.desktop", desktop, 0o644),
          ("usr/share/polkit-1/actions/org.navid.vpnshare.policy", policy, 0o644),
          ("usr/share/doc/vpnshare/copyright", ((ROOT / "work/vpnshare/LICENSE") if (ROOT / "work/vpnshare/LICENSE").exists() else ROOT / "Windows/LICENSE").read_bytes(), 0o644)]
icon = ROOT / "work" / "vpnshare-icon.png"
if not icon.exists(): icon=ROOT / "Windows" / "app.png"
if icon.exists(): files.append(("usr/share/icons/hicolor/64x64/apps/vpnshare.png", icon.read_bytes(), 0o644))
members = [("debian-binary", b"2.0\n"), ("control.tar.gz", tar_gz([("control", control, 0o644)])), ("data.tar.gz", tar_gz(files))]
package = OUT / "vpnshare_0.5.0~preview8_all.deb"
with package.open("wb") as stream:
    stream.write(b"!<arch>\n")
    for name, content in members:
        header = f"{name+'/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(content):<10}`\n".encode()
        if len(header) != 60: raise ValueError("Invalid ar header")
        stream.write(header); stream.write(content)
        if len(content) % 2: stream.write(b"\n")
print(package)
print(f"{package.stat().st_size} bytes; package only, no installation performed")
