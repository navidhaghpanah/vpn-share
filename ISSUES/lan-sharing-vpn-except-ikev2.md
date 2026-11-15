# VPN sharing from LAN fails when connected via any VPN except IKEv2

**Status:** Reworked (Windows socket relay, 2026-11-15)
**Created:** 2026-11-05
**Updated:** 2026-11-15

## Problem

When sharing the VPN connection from the LAN, it only works with IKEv2. Connecting with any other VPN protocol (e.g., WireGuard, OpenVPN, Reality, gRPC) breaks LAN sharing — clients on the local network cannot reach the shared VPN.

## Expected

LAN sharing should work regardless of which VPN protocol is active.

## Actual

Only IKEv2 allows LAN sharing; all other protocols fail.

## Progress

### 2026-11-15 (socket relay)

Injecting packets into the VPN adapter only works for a few drivers (IKEv2 WAN headers, some WinTun devices). Windscribe and other clients accept ordinary PC traffic but drop injected frames, so the hotspot came up and the phone associated while no site opened.

Shared TCP and UDP are now normal Windows sockets bound to the selected VPN address, with the egress interface forced onto that VPN. The packet driver is used only to capture the hotspot side. Any connected VPN that gives this PC an IPv4 address can be shared, including when it is not the system default route. WFP still blocks that VPN address from leaving through another NIC.

Hardware check still required: phone joins, a site opens, and the log shows non-zero `up` and `down`.
