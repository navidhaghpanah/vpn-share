# First Custom NAT preview

Windows: download **VPNShare-0.5.0-preview.3.exe** and run it as Administrator. This is one self-contained portable EXE; .NET does not need to be installed. If the separate packet driver is missing, the app downloads its official personal-use installer and verifies its pinned hash and signature. The driver is not bundled. Network drivers require system installation even though the app is portable.

Ubuntu/Debian: install **vpnshare_0.5.0.preview3_all.deb** using `sudo apt install ./vpnshare_0.5.0.preview3_all.deb`. This installs GTK, NetworkManager and packet-filter dependencies through the distribution package manager. Launch VPN Share from the applications menu. Linux is packaged and tested at the logic level; actual Linux hotspot operation is not yet validated.

Both versions include About, NH branding, sirgsm.ir and the developer's explicitly provided public contact details. Windows uses custom NDIS NAT; Linux uses nftables and policy routing. Clients need no proxy or VPN app.

Windows hardware validation: a separate mobile joined, obtained DHCP and opened a filtered site with mobile data disabled through the sing-tun VPN. The spare AP-capable Wi-Fi card was used. A missing first-use AP initialization call was reproduced and fixed. Automated local checks: 86 Windows and 36 Linux tests passed.

**Preview limitations:** VPN disconnect/reconnect, client DNS/IPv6 leak checks, crash recovery, Windows 10 and Linux hardware acceptance remain pending. This release is not a claim of universal VPN/adapter compatibility or completed security acceptance. The user requested publication before those remaining live checks. Use the supplied SHA256SUMS.txt to verify downloads.


Preview 2 adds ownership-checked recovery for a Hosted AP retained by Windows after the application exits. Six regression checks cover adapter identity, SSID and ownership. Live recovery verification remains pending.

## Preview 3: reconnect and AP lifecycle fixes

- Re-enumerate packet bindings during cleanup; never issue resets against a removed handle or reset a different binding reusing the same name. Failed resets retain their journal entries for retry.
- Retry pending binding recovery before opening a replacement engine. Dispose partially started engines; only publish a replacement after Connected is true and Faulted is false.
- Atomically replace VPN egress guards in a WFP transaction, so an old interface rule cannot block DNS on a re-created VPN interface. Downstream forwarding guards remain installed.
- Stop packet workers on driver failure. Reconnect messages describe packet-interface readiness, not proof of client internet access.
- Do not use an unavailable Hosted Network status GUID before enabling/starting the AP; capture and journal the actual active AP identity.
- 86 Windows regression/integration checks passed locally, including 11 new startup, binding recovery and AP ownership checks. Live disconnect/reconnect, DNS/IPv6 leak and hardware recovery acceptance remain pending.
