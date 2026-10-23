# VPN Share 0.4.6 — Windows engineering build

This build fixes the Ethernet-only assumption for IP-medium VPNs and adds a dedicated AP path for compatible spare Wi-Fi adapters. It includes the sirgsm.ir link and NH footer.

## What changed

- The driver adapter ABI now decodes the NDIS medium. For NdisMediumIP (19), the engine uses the driver's synthetic Ethernet framing without ARP. Other Ethernet and native WAN paths are preserved.
- An official WLAN API capability query identifies cards supporting Hosted AP. Automatic mode prefers a single compatible spare card with no incoming gateway. Options > Wi-Fi output adapter allows selecting that card explicitly.
- AP creation uses a process-owned WLAN session, a temporary WPA2 password and a protected recovery journal. Previous AP settings/key are backed up; the key is encrypted using machine DPAPI inside administrator/SYSTEM-only storage. No ICS or WinNAT engine is enabled.
- Multiple AP-capable cards are rejected for this dedicated mode because the public Hosted Network API cannot directly select between them. Automatic Wi-Fi Direct remains an alternative with Windows selecting its radio.
- Native imports are restricted to the Windows system directory.

## Verified on this computer

- 69 Windows protocol, ABI, NAT, DNS and helper regression checks passed.
- The active sing-tun interface is driver-visible with NDIS medium 19. Header-only listen copies confirmed synthetic Ethernet framing; the original mode was restored.
- A DNS baseline to the tunnel's configured resolver succeeded. A separately crafted UDP DNS packet injected through the driver into that same IP tunnel received a matching response. No addressing, routing or firewall changes were made for that smoke test.
- The WLAN API reports Wi-Fi 3 as the only Hosted AP-capable card. Its existing Hosted Network virtual interface is visible to the packet driver.

These checks do not establish second-device Wi-Fi association, DHCP, internet access, DNS/IPv6 leak protection, VPN reconnect or AP restoration on hardware. Those acceptance checks remain pending. Linux was not live-tested.

## Run

Close the previous VPN Share instance. Open this VPNShare.exe and approve UAC. Keep the VPN connected. Leave Wi-Fi output set to Automatic, or select Wi-Fi 3 in Options and save. Start sharing, then connect a separate client to the configured SSID/password. If startup fails, inspect Options activity before retrying.

## References

- NDIS media types: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddndis/ne-ntddndis-_ndis_medium
- Process-owned AP lifecycle: https://learn.microsoft.com/en-us/windows/win32/nativewifi/using-hosted-network-and-internet-connection-sharing
- Temporary secondary key and removal: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanhostednetworksetsecondarykey
