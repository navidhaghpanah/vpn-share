# First Custom NAT preview

Windows: download **VPNShare-0.5.0-preview.2.exe** and run it as Administrator. This is one self-contained portable EXE; .NET does not need to be installed. If the separate packet driver is missing, the app downloads its official personal-use installer and verifies its pinned hash and signature. The driver is not bundled. Network drivers require system installation even though the app is portable.

Ubuntu/Debian: install **vpnshare_0.5.0.preview2_all.deb** using `sudo apt install ./vpnshare_0.5.0.preview2_all.deb`. This installs GTK, NetworkManager and packet-filter dependencies through the distribution package manager. Launch VPN Share from the applications menu. Linux is packaged and tested at the logic level; actual Linux hotspot operation is not yet validated.

Both versions include About, NH branding, sirgsm.ir and the developer's explicitly provided public contact details. Windows uses custom NDIS NAT; Linux uses nftables and policy routing. Clients need no proxy or VPN app.

Windows hardware validation: a separate mobile joined, obtained DHCP and opened a filtered site with mobile data disabled through the sing-tun VPN. The spare AP-capable Wi-Fi card was used. A missing first-use AP initialization call was reproduced and fixed. Automated local checks: 75 Windows and 36 Linux tests passed.

**Preview limitations:** VPN disconnect/reconnect, client DNS/IPv6 leak checks, crash recovery, Windows 10 and Linux hardware acceptance remain pending. This release is not a claim of universal VPN/adapter compatibility or completed security acceptance. The user requested publication before those remaining live checks. Use the supplied SHA256SUMS.txt to verify downloads.


Preview 2 adds ownership-checked recovery for a Hosted AP retained by Windows after the application exits. Six regression checks cover adapter identity, SSID and ownership. Live recovery verification remains pending.
