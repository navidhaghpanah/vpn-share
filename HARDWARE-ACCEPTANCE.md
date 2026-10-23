# Hardware acceptance record — partial Windows acceptance

Recorded on 2026-10-23 (Asia/Tehran). This remains an engineering build, not a fully accepted cross-platform release.

## Passed on the current Windows system

- VPN Share 0.4.6 started a dedicated Hosted AP using the sole compatible spare Wi-Fi card; the incoming Wi-Fi interfaces were retained.
- The driver-visible sing-tun IP tunnel was used with synthetic Ethernet framing, without ARP.
- A separate mobile connected. Runtime records contain two DHCP leases in the application subnet and substantial bidirectional traffic.
- The user disabled mobile data and confirmed a filtered website/YouTube opens through the shared Wi-Fi.
- Native UI inspection confirmed the active sharing state, two client leases, traffic counters and readable controls; sirgsm.ir and NH are visible in the footer.
- Read-only Windows queries show the gateway Preferred, IPv4 MTU 1280, and Windows IPv4/IPv6 forwarding Disabled on the AP adapter.
- The missing AP initializer was reproduced (error 1610) and corrected on the system. Version 0.4.7 includes that call for first use.

## Still pending

- VPN disconnect blocks new client internet requests; reconnect resumes sharing.
- Client public IP comparison, external DNS and IPv6 leak checks.
- Normal stop and forced-process recovery restore the prior adapter/AP state.
- A full start/client/stop cycle on the delivered 0.4.7 binary.
- Separate Windows 10, Ethernet output, native IKEv2 regression and Ubuntu/Debian hardware cases.

## Existing automated evidence

69 Windows checks passed before the initializer change; the initializer itself was exercised against the actual Windows WLAN API. 36 Linux tests passed previously; Linux lifecycle tests include mocked components and no actual Linux AP runtime has been validated. A successful build or protocol test is not evidence of complete client leak protection.

No client MAC, hostname, public IP, password or raw packet payload is included in this record.
