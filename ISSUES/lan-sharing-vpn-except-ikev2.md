# VPN sharing from LAN fails when connected via any VPN except IKEv2

**Status:** Open
**Created:** 2026-11-05

## Problem

When sharing the VPN connection from the LAN, it only works with IKEv2. Connecting with any other VPN protocol (e.g., WireGuard, OpenVPN, Reality, gRPC) breaks LAN sharing — clients on the local network cannot reach the shared VPN.

## Expected

LAN sharing should work regardless of which VPN protocol is active.

## Actual

Only IKEv2 allows LAN sharing; all other protocols fail.

## Notes

- Affects LAN sharing feature
- Protocol-specific: IKEv2 works, others don't
- Possible causes: adapter binding, DHCP gateway handling, or protocol-specific routing rules
