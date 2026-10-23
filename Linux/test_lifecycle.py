"""Mocked lifecycle: no root privileges, sockets, or network mutation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import core


class FakeDns:
    def __init__(self, gateway, target, available): self.target, self.available = target, available
    def start(self): pass
    def close(self): pass


class FakeProcess:
    def __init__(self, *args, **kwargs): self.code = None
    def poll(self): return self.code
    def terminate(self): self.code = 0
    def wait(self, **kwargs): self.code = 0
    def kill(self): self.code = 0


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).parent / "test-work"
        base.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=base)
        self.path = Path(self.directory.name)
        self.calls, self.journals = [], []
        self.address, self.index, self.link_up = "10.8.0.2", 10, True
        self.fail_up, self.fail_restore = False, False
        self.previous = ""
        for device in ("tun0", "wlan0"):
            folder = self.path / device; folder.mkdir()
            for name, value in (("forwarding", "0"), ("rp_filter", "1"), ("send_redirects", "1")):
                (folder / name).write_text(value)
        self.patches = [patch.object(core, "RUN", self.path), patch.object(core, "command", side_effect=self.command),
                        patch.object(core, "inventory", return_value={"vpns": [{"name": "tun0"}], "outputs": [{"name": "wlan0", "kind": "wifi"}]}),
                        patch.object(core, "recover"), patch.object(core, "save", side_effect=lambda s: self.journals.append(json.loads(json.dumps(s)))),
                        patch.object(core, "sysctl_path", side_effect=lambda d, n: self.path / d / n),
                        patch.object(core, "DnsService", FakeDns), patch.object(core.subprocess, "Popen", FakeProcess), patch.object(core.time, "sleep"),
                        patch.object(core.shutil, "which", side_effect=lambda tool, **_: "/usr/bin/" + tool)]
        for mock in self.patches: mock.start()

    def tearDown(self):
        for mock in reversed(self.patches): mock.stop()
        self.directory.cleanup()

    def command(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:4] == ("ip", "-j", "rule", "show"): return "[]"
        if args[:6] == ("ip", "-4", "-j", "route", "show", "table"): return "[]"
        if args[:6] == ("ip", "-j", "address", "show", "dev", "tun0"):
            return json.dumps([{"ifindex": self.index, "flags": ["UP"] if self.link_up else [], "addr_info": [{"family": "inet", "local": self.address}]}])
        if args[:6] == ("ip", "-4", "-j", "route", "show", "dev"):
            return '[{"dst":"default","gateway":"10.8.0.1"}]'
        if args[:3] == ("nft", "-j", "list"): return '{"nftables":[]}'
        if args == ("nmcli", "-t", "-f", "UUID", "connection", "show"):
            profile = self.path / "session.nmconnection"
            if profile.exists():
                return next(line[5:] for line in profile.read_text().splitlines() if line.startswith("uuid="))
            return ""
        if args[:4] == ("nmcli", "-g", "GENERAL.CON-UUID", "device"): return self.previous
        if args == ("nmcli", "radio", "wifi"): return "enabled"
        if args[:3] == ("nmcli", "connection", "up"):
            if self.fail_up and args[-1] != self.previous: raise RuntimeError("Simulated hotspot activation failure")
            if self.fail_restore and args[-1] == self.previous: raise RuntimeError("Simulated restoration failure")
        return ""

    def start(self):
        session = core.Session()
        session.start({"action": "start", "vpn": "tun0", "output": "wlan0", "mode": "wifi", "ssid": "Test", "password": "test-secret", "dns": "1.1.1.1"})
        return session

    def test_guard_is_installed_before_hotspot_activation(self):
        session = self.start()
        guard = next(i for i, (a, k) in enumerate(self.calls) if a == ("nft", "-f", "-") and "add table" in k["input"])
        activate = next(i for i, (a, _) in enumerate(self.calls) if a[:3] == ("nmcli", "connection", "up"))
        self.assertLess(guard, activate)
        self.assertTrue(self.journals)
        session.stop()

    def test_stop_restores_per_interface_sysctls(self):
        session = self.start()
        self.assertEqual((self.path / "wlan0/forwarding").read_text(), "1")
        session.stop()
        for device in ("wlan0", "tun0"):
            self.assertEqual((self.path / device / "forwarding").read_text(), "0")
            self.assertEqual((self.path / device / "rp_filter").read_text(), "1")
        self.assertFalse(any("flush ruleset" in str(call) for call in self.calls))

    def test_ip_change_rebinds_dns_without_changing_the_client_gateway(self):
        session = self.start(); gateway = session.state["gateway"]
        self.address = "10.8.0.9"
        session.refresh()
        self.assertEqual(session.dns.target, ("tun0", "10.8.0.9", "1.1.1.1"))
        self.assertEqual(session.state["gateway"], gateway)
        self.assertTrue(session.connected)
        session.stop()

    def test_same_ip_recreated_interface_restores_forwarding(self):
        session = self.start()
        (self.path / "tun0/forwarding").write_text("0")
        self.index = 23
        session.refresh()
        self.assertEqual((self.path / "tun0/forwarding").read_text(), "1")
        session.stop()

    def test_vpn_loss_pauses_dns_and_keeps_the_guard(self):
        session = self.start()
        self.calls.clear(); self.link_up = False
        session.refresh()
        self.assertFalse(session.connected)
        self.assertFalse(session.dns.available())
        self.assertFalse(any(a[:3] == ("nft", "delete", "table") for a, _ in self.calls))
        session.stop()

    def test_hotspot_failure_rolls_back_owned_profile_and_guard(self):
        self.fail_up = True
        with self.assertRaisesRegex(RuntimeError, "activation failure"): self.start()
        self.assertTrue(any(a[:3] == ("nmcli", "connection", "delete") for a, _ in self.calls))
        self.assertTrue(any(a[:3] == ("nft", "delete", "table") for a, _ in self.calls))

    def test_restore_failure_retains_the_guard(self):
        self.previous = "78c0a241-deaf-4939-8669-42bc5faf1506"
        session = self.start(); self.calls.clear(); self.fail_restore = True
        with self.assertRaisesRegex(RuntimeError, "restoration failure"): session.stop()
        self.assertFalse(any(a[:3] == ("nft", "delete", "table") for a, _ in self.calls))
        self.assertIsNotNone(session.state)

    def test_password_never_appears_in_process_argv(self):
        session = self.start()
        self.assertFalse(any("test-secret" in str(args) for args, _ in self.calls))
        self.assertIn("test-secret", (self.path / "session.nmconnection").read_text())
        session.stop()


if __name__ == "__main__": unittest.main(verbosity=2)
