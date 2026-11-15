# VPN sharing from LAN fails when connected via any VPN except IKEv2

**Status:** Improved (stronger fallback committed 2026-11-15)
**Created:** 2026-11-05
**Updated:** 2026-11-15

## Problem

When sharing the VPN connection from the LAN, it only works with IKEv2. Connecting with any other VPN protocol (e.g., WireGuard, OpenVPN, Reality, gRPC) breaks LAN sharing — clients on the local network cannot reach the shared VPN.

## Expected

LAN sharing should work regardless of which VPN protocol is active.

## Actual

Only IKEv2 allows LAN sharing; all other protocols fail.

## Progress

### 2026-11-15 (second update)
- More aggressive pure-IP tunnel detection (WinTun, WireGuard, VLESS, Reality, Sing-box, Hiddify, Xray, OpenVPN, Clash, NekoBox, any VPN with no gateway, etc.).
- If the adapter is not found by GUID, try matching via WAN links.
- ARP is now optional: if it fails, the engine falls back to zero-MAC IP-tunnel mode instead of failing.
- Clearer log messages indicate which backend (IP-tunnel / Ethernet / WAN) is being used.

This should make LAN sharing work with most modern pure-IP tunnels. Hardware verification is still recommended.

## Notes

- Affects LAN sharing feature
- Possible remaining issues: specific driver quirks, IPv6, or split-tunnel configurations
