# VPN sharing from LAN fails when connected via any VPN except IKEv2

**Status:** Improved (partial fix committed 2026-11-15)
**Created:** 2026-11-05
**Updated:** 2026-11-15

## Problem

When sharing the VPN connection from the LAN, it only works with IKEv2. Connecting with any other VPN protocol (e.g., WireGuard, OpenVPN, Reality, gRPC) breaks LAN sharing — clients on the local network cannot reach the shared VPN.

## Expected

LAN sharing should work regardless of which VPN protocol is active.

## Actual

Only IKEv2 allows LAN sharing; all other protocols fail.

## Progress (2026-11-15)

- Added detection for common pure-IP tunnels (WinTun, WireGuard, VLESS, Reality, Sing-box, Hiddify, Xray).
- When ARP resolution fails, the engine now falls back to IP-tunnel mode (zero MAC addresses) for these adapters instead of immediately failing.
- Clearer error message when the adapter is still unsupported, suggesting IKEv2 or reporting the adapter name.
- This does **not** guarantee full compatibility with every non-IKEv2 VPN yet; hardware testing is still required.

## Notes

- Affects LAN sharing feature
- Protocol-specific: IKEv2 works, others don't
- Possible remaining causes: adapter binding differences, DHCP gateway handling, or protocol-specific routing rules
