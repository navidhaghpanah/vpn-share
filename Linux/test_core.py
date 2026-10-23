import json
import unittest
from unittest.mock import patch
import core


class CoreTests(unittest.TestCase):
    def request(self, **changes):
        return {"action": "start", "vpn": "tun0", "output": "wlan0", "mode": "wifi", "ssid": "Navid VPN", "password": "test-passphrase", "dns": "", **changes}

    def state(self):
        return {"vpn": "tun0", "output": "wlan0", "subnet": "10.203.91.0/24", "gateway": "10.203.91.1", "nft": "vpnshare_a123456789ab"}

    def test_valid_request(self):
        self.assertEqual(core.validate_request(self.request())["dns"], "1.1.1.1")

    def test_reject_same_interface(self):
        with self.assertRaises(ValueError): core.validate_request(self.request(output="tun0"))

    def test_reject_command_injection(self):
        for value in ("wlan0;reboot", 'wlan0" drop', "../../eth0", "eth0\nfoo", "A" * 16, ".", "..", "--help"):
            with self.subTest(value=value), self.assertRaises(ValueError): core.validate_request(self.request(output=value))

    def test_utf8_ssid_limit(self):
        self.assertEqual(core.validate_request(self.request(ssid="ا" * 16))["ssid"], "ا" * 16)
        with self.assertRaises(ValueError): core.validate_request(self.request(ssid="ا" * 17))

    def test_no_ssid_keyfile_injection(self):
        for value in ("", "test\n[connection]", "name\0"):
            with self.subTest(value=value), self.assertRaises(ValueError): core.validate_request(self.request(ssid=value))

    def test_password_validation(self):
        for value in ("short", "a" * 64, "abcdefgh\n", "abcdefghé"):
            with self.subTest(value=value), self.assertRaises(ValueError): core.validate_request(self.request(password=value))

    def test_dns_validation(self):
        for value in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "8.8.8.8; reboot", {}):
            with self.subTest(value=value), self.assertRaises(ValueError): core.validate_request(self.request(dns=value))

    def test_ethernet_does_not_require_wifi_credentials(self):
        self.assertEqual(core.validate_request(self.request(mode="ethernet", ssid="", password=""))["mode"], "ethernet")

    def test_control_request_whitelist(self):
        for value in ([], {}, {"action": "execute", "command": "anything"}):
            with self.subTest(value=value), self.assertRaises(ValueError): core.validate_request(value)

    def test_nmcli_escaping(self):
        self.assertEqual(core.nm_fields(r"Office\: VPN:abc:vpn:tun0"), ["Office: VPN", "abc", "vpn", "tun0"])

    def test_subnet_ignores_full_tunnel_routes(self):
        self.assertEqual(core.choose_subnet([{"dst": "0.0.0.0/1"}, {"dst": "128.0.0.0/1"}]), "10.203.91.0/24")

    def test_subnet_avoids_connected_network(self):
        self.assertEqual(core.choose_subnet([{"dst": "10.203.91.0/24"}]), "10.204.91.0/24")

    def test_subnet_falls_back_to_another_private_range(self):
        self.assertEqual(core.choose_subnet([{"dst": "10.0.0.0/8"}]), "172.29.200.0/24")

    def test_no_available_subnet_is_explicit(self):
        with self.assertRaises(RuntimeError): core.choose_subnet([{"dst": "10.0.0.0/8"}, {"dst": "172.16.0.0/12"}, {"dst": "192.168.0.0/16"}])

    def test_nft_guard_restricts_both_directions(self):
        script = core.nft_rules(self.state(), "10.8.0.2")
        self.assertIn('iifname "wlan0" oifname "tun0" ip saddr 10.203.91.0/24', script)
        self.assertIn('iifname "tun0" oifname "wlan0" ip daddr 10.203.91.0/24 ct state { established, related }', script)
        self.assertIn('iifname "wlan0" drop', script)
        self.assertIn('oifname "wlan0" drop', script)

    def test_ipv6_has_no_forward_allow_rule(self):
        lines = core.nft_rules(self.state()).splitlines()
        accepts = [line for line in lines if " forward " in line and line.endswith(" accept")]
        self.assertTrue(all("ip saddr" in line or "ip daddr" in line for line in accepts))

    def test_dns_egress_is_tunnel_bound(self):
        self.assertIn('ip saddr 10.8.0.2 oifname != "tun0" drop', core.nft_rules(self.state(), "10.8.0.2"))

    def test_atomic_update_preserves_guard_table(self):
        script = core.nft_rules(self.state(), "10.8.0.9", updating=True)
        self.assertNotIn("delete table", script)
        self.assertNotIn("add table", script)
        self.assertIn("flush chain", script)
        self.assertIn('iifname "wlan0" drop', script)
        self.assertIn('ip saddr 10.8.0.9', script)

    def test_no_global_firewall_flush(self):
        self.assertNotIn("flush ruleset", core.nft_rules(self.state()))

    def test_firewall_table_injection_is_rejected(self):
        with self.assertRaises(ValueError): core.nft_rules({**self.state(), "nft": "x; flush ruleset"})

    def test_keyfile_uses_no_shared_mode(self):
        profile = core.keyfile(core.validate_request(self.request()), "1c95e66d-80c7-4e62-a0e7-c10e31c74822", "10.203.91.1")
        self.assertIn("method=manual", profile)
        self.assertNotIn("method=shared", profile)
        self.assertIn("mode=ap", profile)
        self.assertIn("method=disabled", profile)
        self.assertIn("ssid=78;97;118;105;100;32;86;80;78;", profile)

    def test_ethernet_keyfile_has_no_password(self):
        profile = core.keyfile(core.validate_request(self.request(mode="ethernet")), "id", "10.203.91.1")
        self.assertNotIn("psk=", profile)
        self.assertIn("[ethernet]", profile)

    def test_inventory_does_not_mislabel_physical_ipsec_as_a_tunnel(self):
        links = [{"ifname": "eth0", "flags": ["UP"], "addr_info": [{"family": "inet", "local": "192.168.1.2"}]},
                 {"ifname": "private0", "flags": ["UP"], "linkinfo": {"info_kind": "wireguard"}, "addr_info": [{"family": "inet", "local": "10.8.0.2"}]}]
        def fake(*args, **kwargs):
            if args[0] == "ip": return json.dumps(links)
            if "NAME,UUID,TYPE,DEVICE" in args: return "IPsec:uuid:vpn:eth0\nWireGuard:uuid:wireguard:private0"
            if "DEVICE,TYPE,STATE" in args: return "eth0:ethernet:connected"
            if "IP4.GATEWAY" in args: return "192.168.1.1"
            return ""
        with patch.object(core, "command", side_effect=fake):
            result = core.inventory()
        self.assertEqual([item["name"] for item in result["vpns"]], ["private0"])
        self.assertEqual(result["outputs"], [])

    def test_dns_total_deadline_stops_slow_successful_receives(self):
        clock = [0.0]
        class Slow:
            def settimeout(self, timeout): self.timeout = timeout
            def recv(self, size):
                if self.timeout < 5:
                    raise TimeoutError("total deadline")
                clock[0] += 5
                return b"x"
        with patch.object(core.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(TimeoutError): core.read_exact(Slow(), 64)
        self.assertLessEqual(clock[0], 6)

    def test_dns_frame_header_and_body_share_deadline(self):
        clock = [0.0]
        class Frames:
            def settimeout(self, timeout): self.timeout = timeout
            def recv(self, size):
                if self.timeout < 4: raise TimeoutError("shared deadline")
                clock[0] += 4
                return b"x" * size
        stream = Frames()
        with patch.object(core.time, "monotonic", side_effect=lambda: clock[0]):
            self.assertEqual(core.read_exact(stream, 2, 6), b"xx")
            with self.assertRaises(TimeoutError): core.read_exact(stream, 12, 6)

    def test_dns_client_cannot_take_all_global_slots(self):
        budget = core.DnsBudget()
        for _ in range(8): self.assertTrue(budget.acquire("10.203.91.20"))
        self.assertFalse(budget.acquire("10.203.91.20"))
        self.assertTrue(budget.acquire("10.203.91.21"))
        for _ in range(8): budget.release("10.203.91.20")
        self.assertNotIn("10.203.91.20", budget.clients)
        self.assertEqual(budget.active, 1)

    def test_dns_budget_enforces_global_capacity(self):
        budget = core.DnsBudget(total=2, per_client=2)
        self.assertTrue(budget.acquire("one")); self.assertTrue(budget.acquire("two"))
        self.assertFalse(budget.acquire("three"))
        budget.release("one")
        self.assertTrue(budget.acquire("three"))

    def test_dns_read_rejects_truncated_frame(self):
        class Closed:
            def settimeout(self, _): pass
            def recv(self, _): return b""
        with self.assertRaises(OSError): core.read_exact(Closed(), 20)


if __name__ == "__main__": unittest.main(verbosity=2)
