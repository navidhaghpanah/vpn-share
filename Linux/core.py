"""VPN Share Linux backend. Commands use argv arrays; never an interactive shell."""
from __future__ import annotations
import ipaddress
import json
import os
import re
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
RUN = Path("/run/vpnshare")


def command(*args, input=None, check=True):
    binary = shutil.which(args[0], path=PATH)
    if not binary:
        raise RuntimeError(f"Required system component is missing: {args[0]}")
    result = subprocess.run([binary, *map(str, args[1:])], input=input, text=True,
                            capture_output=True, timeout=35,
                            env={**os.environ, "LC_ALL": "C", "PATH": PATH})
    if check and result.returncode:
        # Never include argv: a future NetworkManager secret must not enter logs.
        raise RuntimeError(f"{args[0]}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def json_command(*args):
    return json.loads(command(*args) or "[]")


def interface(value):
    if not isinstance(value, str) or value in (".", "..") or value.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value):
        raise ValueError("Invalid network interface name")
    return value


def nm_fields(line):
    fields, value, escaped = [], "", False
    for character in line:
        if escaped:
            value += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append(value)
            value = ""
        else:
            value += character
    fields.append(value)
    return fields


def inventory():
    links = json_command("ip", "-j", "-d", "address", "show")
    active = [nm_fields(row) for row in command("nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active").splitlines()]
    devices = [nm_fields(row) for row in command("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status").splitlines()]
    result = {"vpns": [], "outputs": [], "input": "USB / Ethernet / Wi-Fi"}
    types = {row[0]: row[1] for row in devices if len(row) >= 3}
    for link in links:
        name = link["ifname"]
        addresses = [item["local"] for item in link.get("addr_info", []) if item["family"] == "inet"]
        kind = link.get("linkinfo", {}).get("info_kind", "")
        tunnel = kind in ("wireguard", "tun", "xfrm", "vti", "gre") or re.match(r"^(tun|tap|wg|ipsec|tailscale)[0-9A-Za-z_-]*$", name)
        # A physical device carrying policy-only IPsec is NOT treated as a tunnel.
        # Otherwise an oifname guard could permit its unencrypted physical traffic.
        if tunnel and addresses and "UP" in link.get("flags", []):
            title = next((row[0] for row in active if len(row) >= 4 and row[3] == name), name)
            result["vpns"].append({"name": name, "title": title, "ip": addresses[0]})
        if types.get(name) in ("wifi", "ethernet"):
            gateway = command("nmcli", "-g", "IP4.GATEWAY", "device", "show", name, check=False)
            usb = "/usb" in os.path.realpath(f"/sys/class/net/{name}/device")
            if gateway and usb:
                result["input"] = "USB mobile tethering"
            if not gateway:
                ap = types[name] != "wifi" or command("nmcli", "-g", "WIFI-PROPERTIES.AP", "device", "show", name, check=False) == "yes"
                if ap:
                    result["outputs"].append({"name": name, "kind": types[name]})
    return result


def choose_subnet(routes):
    networks = []
    for row in routes:
        try:
            network = ipaddress.ip_network(row.get("dst", ""), strict=False)
            if network.version == 4 and network.prefixlen > 1:
                networks.append(network)
        except ValueError:
            pass
    candidates = [f"10.{i}.91.0/24" for i in range(203, 250)]
    candidates += [f"172.29.{i}.0/24" for i in range(200, 250)]
    candidates += [f"192.168.{i}.0/24" for i in range(233, 255)]
    for text in candidates:
        candidate = ipaddress.ip_network(text)
        if not any(candidate.overlaps(existing) for existing in networks):
            return str(candidate)
    raise RuntimeError("No unused private subnet is available")


def validate_request(request):
    if not isinstance(request, dict):
        raise ValueError("Invalid control request")
    if request.get("action") != "start":
        raise ValueError("Unsupported request")
    vpn, downstream = interface(request.get("vpn")), interface(request.get("output"))
    if vpn == downstream:
        raise ValueError("VPN and output must be different")
    mode = request.get("mode")
    if mode not in ("wifi", "ethernet"):
        raise ValueError("Choose Wi-Fi or Ethernet")
    ssid, password = request.get("ssid", ""), request.get("password", "")
    if mode == "wifi":
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32 or any(c in ssid for c in "\n\r\0"):
            raise ValueError("Wi-Fi name must contain 1 to 32 UTF-8 bytes")
        if not isinstance(password, str) or not 8 <= len(password) <= 63 or any(ord(c) < 32 or ord(c) > 126 for c in password):
            raise ValueError("Wi-Fi password must contain 8 to 63 printable ASCII characters")
    resolver = request.get("dns", "")
    if not isinstance(resolver, str):
        raise ValueError("DNS must be an IPv4 address")
    resolver = resolver.strip() or "1.1.1.1"
    parsed = ipaddress.ip_address(resolver)
    if parsed.version != 4 or parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError("DNS must be a reachable IPv4 resolver")
    return {"vpn": vpn, "output": downstream, "mode": mode, "ssid": ssid, "password": password, "dns": str(parsed)}


def keyfile(data, profile, gateway):
    # GLib keyfiles accept SSIDs as byte lists; this avoids delimiter injection.
    def escaped(text):
        return text.replace("\\", "\\\\").replace(" ", "\\s")
    base = (f"[connection]\nid=VPN Share {profile}\nuuid={profile}\ntype={data['mode']}\n"
            f"interface-name={data['output']}\nautoconnect=false\n")
    if data["mode"] == "wifi":
        octets = ";".join(str(byte) for byte in data["ssid"].encode("utf-8")) + ";"
        base += f"\n[wifi]\nmode=ap\nssid={octets}\n\n[wifi-security]\nkey-mgmt=wpa-psk\npsk={escaped(data['password'])}\n"
    else:
        base += "\n[ethernet]\n"
    return base + f"\n[ipv4]\nmethod=manual\naddress1={gateway}/24\nnever-default=true\n\n[ipv6]\nmethod=disabled\n"


def nft_rules(state, vpn_ip=None, updating=False):
    down, vpn = interface(state["output"]), interface(state["vpn"])
    network = str(ipaddress.ip_network(state["subnet"]))
    table = state["nft"]
    if not re.fullmatch(r"vpnshare_[0-9a-f]{12}", table):
        raise ValueError("Invalid firewall table")
    gateway = str(ipaddress.ip_address(state["gateway"]))
    if vpn_ip:
        vpn_ip = str(ipaddress.IPv4Address(vpn_ip))
    if updating:
        lines = [f"flush chain inet {table} forward", f"flush chain inet {table} output", f"flush chain inet {table} input"]
    else:
        lines = [f"add table inet {table}", f"add counter inet {table} upload", f"add counter inet {table} download",
                 f"add chain inet {table} forward {{ type filter hook forward priority -150; policy accept; }}",
                 f"add chain inet {table} output {{ type filter hook output priority -150; policy accept; }}",
                 f"add chain inet {table} input {{ type filter hook input priority -150; policy accept; }}",
                 f"add chain inet {table} nat {{ type nat hook postrouting priority 100; policy accept; }}",
                 f'add rule inet {table} nat oifname "{vpn}" ip saddr {network} masquerade']
    lines += [f'add rule inet {table} forward iifname "{down}" oifname "{vpn}" meta nfproto ipv4 tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240',
              f'add rule inet {table} forward iifname "{vpn}" oifname "{down}" meta nfproto ipv4 tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240',
              f'add rule inet {table} forward iifname "{down}" oifname "{vpn}" ip saddr {network} ct state {{ new, established, related }} counter name upload accept',
              f'add rule inet {table} forward iifname "{vpn}" oifname "{down}" ip daddr {network} ct state {{ established, related }} counter name download accept',
              f'add rule inet {table} forward iifname "{down}" drop',
              f'add rule inet {table} forward oifname "{down}" drop',
              f'add rule inet {table} input iifname "{down}" udp dport 67 accept',
              f'add rule inet {table} input iifname "{down}" ip saddr {network} ip daddr {gateway} udp dport 53 accept',
              f'add rule inet {table} input iifname "{down}" ip saddr {network} ip daddr {gateway} tcp dport 53 accept',
              f'add rule inet {table} input iifname "{down}" drop']
    if vpn_ip:
        lines += [f'add rule inet {table} output ip saddr {vpn_ip} oifname != "{vpn}" drop']
    return "\n".join(lines) + "\n"


def secure_run():
    RUN.mkdir(mode=0o700, exist_ok=True)
    info = RUN.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError("The recovery directory must be owned by root with mode 0700")


def save(state):
    secure_run()
    temporary = RUN / "session.tmp"
    with open(temporary, "w", encoding="utf-8", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, RUN / "session.json")


def sysctl_path(device, name):
    return Path("/proc/sys/net/ipv4/conf") / interface(device) / name


def restore(state):
    # Stop packet services first. Exact app-owned objects only; no global flush.
    for device, values in state.get("sysctl", {}).items():
        for name, old in values.items():
            if name not in ("forwarding", "rp_filter", "send_redirects"):
                raise ValueError("Invalid recovery setting")
            path = sysctl_path(device, name)
            if path.exists():
                path.write_text(str(int(old)))
    for priority in (state["priority"], state["priority"] - 1):
        command("ip", "-4", "rule", "del", "priority", priority, "table", state["table"], check=False)
    command("ip", "-4", "route", "flush", "table", state["table"], check=False)
    profiles = command("nmcli", "-t", "-f", "UUID", "connection", "show").splitlines()
    if state["profile"] in profiles:
        command("nmcli", "connection", "delete", "uuid", state["profile"])
    old = state.get("previous_profile", "")
    if old:
        command("nmcli", "connection", "up", "uuid", old)
    if state.get("wifi_was_disabled"):
        command("nmcli", "radio", "wifi", "off")
    # Remove the guard only after the downstream network has been removed/restored.
    command("nft", "delete", "table", "inet", state["nft"], check=False)
    for name in ("session.nmconnection", "session.json", "dhcp.leases", "dhcp.log", "dhcp.pid"):
        (RUN / name).unlink(missing_ok=True)


def recover():
    secure_run()
    journal = RUN / "session.json"
    if journal.exists():
        state = json.loads(journal.read_text())
        # A trusted root-owned journal still gets strict schema checks.
        interface(state["output"]); interface(state["vpn"])
        uuid.UUID(state["profile"])
        if not 20000 <= int(state["table"]) <= 50000 or not 20000 <= int(state["priority"]) <= 50000:
            raise ValueError("Invalid recovery routing identifiers")
        nft_rules(state)
        restore(state)


class DnsBudget:
    """Bound global work and prevent one source from monopolizing it."""
    def __init__(self, total=48, per_client=8):
        self.total, self.per_client = total, per_client
        self.lock = threading.Lock()
        self.active = 0
        self.clients = {}

    def acquire(self, address):
        with self.lock:
            count = self.clients.get(address, 0)
            if self.active >= self.total or count >= self.per_client:
                return False
            self.active += 1
            self.clients[address] = count + 1
            return True

    def release(self, address):
        with self.lock:
            count = self.clients.get(address, 0)
            if count == 0:
                raise RuntimeError("Unbalanced DNS budget release")
            self.active -= 1
            if count == 1:
                del self.clients[address]
            else:
                self.clients[address] = count - 1


def dns_timeout(stream, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS request deadline exceeded")
    stream.settimeout(min(6, remaining))


class DnsService:
    def __init__(self, gateway, target, available):
        self.target, self.available = target, available
        self.subnet = ipaddress.ip_network(gateway + "/24", strict=False)
        self.slots = DnsBudget()
        service = self

        class Limited(socketserver.ThreadingMixIn):
            daemon_threads = True
            def verify_request(self, request, client):
                return ipaddress.ip_address(client[0]) in service.subnet and service.available()
            def process_request(self, request, client):
                if not service.slots.acquire(client[0]):
                    self.shutdown_request(request); return
                try:
                    super().process_request(request, client)
                except BaseException:
                    service.slots.release(client[0]); raise
            def process_request_thread(self, request, client):
                try:
                    super().process_request_thread(request, client)
                finally:
                    service.slots.release(client[0])

        class UDP(Limited, socketserver.UDPServer):
            allow_reuse_address = False
            max_packet_size = 65535
        class TCP(Limited, socketserver.TCPServer):
            allow_reuse_address = False

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    deadline = time.monotonic() + 12
                    tcp = isinstance(self.request, socket.socket)
                    if tcp:
                        header = read_exact(self.request, 2, deadline)
                        query = read_exact(self.request, int.from_bytes(header, "big"), deadline)
                    else:
                        query = self.request[0]
                    if len(query) < 12 or query[2] & 0x80:
                        return
                    target = service.target
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as outbound:
                        dns_timeout(outbound, deadline)
                        outbound.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, target[0].encode() + b"\0")
                        outbound.bind((target[1], 0))
                        outbound.connect((target[2], 53))
                        dns_timeout(outbound, deadline)
                        outbound.sendall((len(query).to_bytes(2, "big") if tcp else b"") + query)
                        dns_timeout(outbound, deadline)
                        answer = read_exact(outbound, int.from_bytes(read_exact(outbound, 2, deadline), "big"), deadline) if tcp else outbound.recv(65535)
                    if service.available() and target == service.target and len(answer) >= 12 and answer[:2] == query[:2] and answer[2] & 0x80:
                        if tcp:
                            dns_timeout(self.request, deadline)
                            self.request.sendall(len(answer).to_bytes(2, "big") + answer)
                        else:
                            self.request[1].sendto(answer, getattr(socket, "MSG_DONTWAIT", 0), self.client_address)
                except (OSError, ValueError):
                    pass
        self.servers = []
        try:
            for cls in (UDP, TCP):
                self.servers.append(cls((gateway, 53), Handler))
        except BaseException:
            for server in self.servers: server.server_close()
            raise

    def start(self):
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self):
        for server in self.servers:
            server.shutdown(); server.server_close()


def read_exact(stream, size, deadline=None):
    if size > 65535:
        raise ValueError("DNS frame is too large")
    deadline = time.monotonic() + 6 if deadline is None else deadline
    data = b""
    while len(data) < size:
        dns_timeout(stream, deadline)
        part = stream.recv(size - len(data))
        if not part:
            raise OSError("DNS connection closed")
        data += part
    return data


class Session:
    def __init__(self):
        self.state = None
        self.dhcp = None
        self.dns = None
        self.connected = False
        self.last_ip = None
        self.last_index = None

    def start(self, request):
        data = validate_request(request)
        for required in ("ip", "nmcli", "nft", "dnsmasq"):
            if not shutil.which(required, path=PATH):
                raise RuntimeError(f"Required system component is missing: {required}")
        recover()
        devices = inventory()
        if data["vpn"] not in {item["name"] for item in devices["vpns"]}:
            raise ValueError("The selected routed VPN interface is not connected")
        if not any(item["name"] == data["output"] and item["kind"] == data["mode"] for item in devices["outputs"]):
            raise ValueError("Choose an unused output adapter; the incoming internet adapter is protected")
        profile = str(uuid.uuid4())
        used = {int(item["priority"]) for item in json_command("ip", "-j", "rule", "show")}
        priority = next(number for number in range(31000, 49000, 2) if number not in used and number - 1 not in used)
        table = next(number for number in range(24000, 49000) if not command("ip", "-4", "route", "show", "table", number, check=False))
        subnet = choose_subnet(json_command("ip", "-4", "-j", "route", "show", "table", "all"))
        gateway = str(ipaddress.ip_network(subnet).network_address + 1)
        previous = command("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", data["output"], check=False)
        if previous in ("", "--"): previous = ""
        if previous: uuid.UUID(previous)
        self.state = {"vpn": data["vpn"], "output": data["output"], "subnet": subnet, "gateway": gateway,
                      "profile": profile, "priority": priority, "table": table, "previous_profile": previous,
                      "nft": "vpnshare_" + uuid.uuid4().hex[:12], "sysctl": {},
                      "wifi_was_disabled": data["mode"] == "wifi" and command("nmcli", "radio", "wifi") == "disabled"}
        state = self.state
        try:
            save(state)
            # Guard is installed before any interface or forwarding changes.
            command("nft", "-f", "-", input=nft_rules(state))
            if state["wifi_was_disabled"]: command("nmcli", "radio", "wifi", "on")
            profile_path = RUN / "session.nmconnection"
            with open(profile_path, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                stream.write(keyfile(data, profile, gateway))
            command("nmcli", "connection", "load", str(profile_path))
            command("nmcli", "connection", "up", "uuid", profile)
            command("ip", "-4", "route", "add", "unreachable", "default", "table", table, "metric", 32767)
            command("ip", "-4", "rule", "add", "priority", priority, "from", subnet, "table", table)
            for device in (state["output"], state["vpn"]):
                state["sysctl"][device] = {name: int(sysctl_path(device, name).read_text()) for name in ("forwarding", "rp_filter", "send_redirects")}
                save(state)
                for name, value in (("forwarding", 1), ("rp_filter", 2), ("send_redirects", 0)):
                    sysctl_path(device, name).write_text(str(value))
            self.resolver = data["dns"]
            self.refresh()
            self.dns = DnsService(gateway, (state["vpn"], self.last_ip, self.resolver), lambda: self.connected)
            self.dns.start()
            network = ipaddress.ip_network(subnet)
            log = open(RUN / "dhcp.log", "ab")
            try:
                self.dhcp = subprocess.Popen([sys.executable, str(Path(__file__).with_name("dhcp_child.py")), str(os.getpid()), shutil.which("dnsmasq", path=PATH), "--keep-in-foreground", "--conf-file=/dev/null", "--port=0", "--no-hosts", "--no-resolv", "--user=root", "--group=root",
                    f"--interface={state['output']}", "--bind-dynamic", "--dhcp-authoritative",
                    f"--dhcp-range={network.network_address + 20},{network.network_address + 219},255.255.255.0,1h",
                    f"--dhcp-option=option:router,{gateway}", f"--dhcp-option=option:dns-server,{gateway}", "--dhcp-option=option:mtu,1280",
                    f"--dhcp-leasefile={RUN / 'dhcp.leases'}", f"--pid-file={RUN / 'dhcp.pid'}"], stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
            finally: log.close()
            time.sleep(.15)
            if self.dhcp.poll() is not None: raise RuntimeError("DHCP could not start: " + (RUN / "dhcp.log").read_text()[-600:])
        except BaseException:
            self.stop(); raise

    def refresh(self):
        state = self.state
        links = json_command("ip", "-j", "address", "show", "dev", state["vpn"])
        link = next(iter(links), {})
        addresses = [item["local"] for item in link.get("addr_info", []) if item["family"] == "inet"]
        self.connected = bool(addresses and "UP" in link.get("flags", []))
        if self.connected and (addresses[0] != self.last_ip or link.get("ifindex") != self.last_index):
            new_ip = str(ipaddress.IPv4Address(addresses[0]))
            self.connected = False
            command("nft", "-f", "-", input=nft_rules(state, new_ip, updating=True))
            routes = json_command("ip", "-4", "-j", "route", "show", "dev", state["vpn"])
            gateway = next((item["gateway"] for item in routes if "gateway" in item and item.get("dst") in ("default", "0.0.0.0/1", "128.0.0.0/1")), None)
            route = ["ip", "-4", "route", "replace", "table", state["table"], "default"]
            if gateway: route += ["via", str(ipaddress.IPv4Address(gateway))]
            route += ["dev", state["vpn"]]
            if gateway: route += ["onlink"]
            command(*route, "metric", 10)
            command("ip", "-4", "rule", "del", "priority", state["priority"] - 1, "table", state["table"], check=False)
            command("ip", "-4", "rule", "add", "priority", state["priority"] - 1, "from", new_ip + "/32", "table", state["table"])
            # A re-created VPN interface has fresh per-interface forwarding state.
            for name, value in (("forwarding", 1), ("rp_filter", 2), ("send_redirects", 0)):
                sysctl_path(state["vpn"], name).write_text(str(value))
            self.last_ip = new_ip
            self.last_index = link.get("ifindex")
            if self.dns: self.dns.target = (state["vpn"], new_ip, self.resolver)
            self.connected = True
        return self.status()

    def status(self):
        counters = {"upload": 0, "download": 0}
        try:
            for entry in json_command("nft", "-j", "list", "table", "inet", self.state["nft"]).get("nftables", []):
                value = entry.get("counter", {})
                if value.get("name") in counters: counters[value["name"]] = value.get("bytes", 0)
        except (RuntimeError, ValueError, AttributeError): pass
        leases = []
        try:
            for line in (RUN / "dhcp.leases").read_text().splitlines():
                fields = line.split()
                if len(fields) >= 4 and int(fields[0]) > time.time(): leases.append({"mac": fields[1], "ip": fields[2], "name": fields[3]})
        except (FileNotFoundError, ValueError): pass
        return {"event": "status", "connected": self.connected, "clients": leases, **counters}

    def stop(self):
        self.connected = False
        if self.dhcp:
            self.dhcp.terminate()
            try: self.dhcp.wait(timeout=3)
            except subprocess.TimeoutExpired: self.dhcp.kill(); self.dhcp.wait(timeout=2)
            self.dhcp = None
        if self.dns: self.dns.close(); self.dns = None
        if self.state:
            restore(self.state)
            self.state = None
