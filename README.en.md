# VPN Share

Stable version 0.5.2 for Windows 10/11 and Ubuntu/Debian, plus an Android 0.1.0 alpha prototype.

## Downloads

The first preview release provides one self-contained portable Windows EXE, a Debian package for Linux, source, and SHA-256 checksums. Windows does not require a separate .NET installation. The packet driver requires system installation; if missing, the app handles the official verified personal-use installer after elevation. No MSI/driver binary is redistributed in the release.

## Features

- Detect an existing full-tunnel VPN and share it through Wi-Fi or an unused Ethernet adapter. Incoming internet may use Wi-Fi, Ethernet or USB tethering.
- Configure Wi-Fi name/password inside the widget. Clients require no proxy or VPN app.
- Custom Windows NDIS NAT supports driver-visible Ethernet, native IPv4 WAN links, and IP-medium tunnels such as the tested sing-tun interface. Universal VPN compatibility is not established.
- Prefer a compatible spare Hosted AP card, or select it in Options. This mode requires exactly one Hosted AP-capable card because Windows cannot explicitly select between multiple such cards. Wi-Fi Direct fallback leaves radio selection to Windows.
- Ubuntu/Debian uses a GTK widget, NetworkManager AP profiles, nftables, policy routing, DHCP/DNS and a privileged polkit helper.
- Android detects an active VPN and offers a guarded hotspot workflow. Protected forwarding through another app's VPN requires root or OEM/system privileges; the root alpha installs dedicated NAT, IPv6-block and fail-closed forwarding rules with recovery state.
- Both versions include About, NH branding, the sirgsm.ir website and the developer's public contact details.

## Validation and limits

120 Windows checks, 36 Linux tests and 7 Android root-plan tests passed locally. A separate mobile joined the Windows hotspot, received DHCP and opened a filtered site with mobile data disabled through sing-tun. Android APK build and logic tests pass, but Android hotspot-to-VPN forwarding still requires a rooted physical-device test.

VPN disconnect/reconnect, client DNS/IPv6 leak checks, crash recovery and Windows 10/Linux hardware acceptance remain pending. Linux tests cover protocol logic and mocked lifecycle; the Debian package was built but has not been installed or exercised on a real Linux hotspot. The user requested this preview before the remaining live checks. See HARDWARE-ACCEPTANCE.md and RELEASE-NOTES.md.

## Build

```powershell
dotnet run --project Windows/Tests/Tests.csproj -c Release
dotnet publish Windows/VpnShare.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

```text
python -m unittest discover -s Linux
python tools/build_deb.py
```

```powershell
cd Android
.\gradlew.bat test assembleDebug
```

The GitHub workflow builds/test-checks both targets before publishing the preview. Generated artifacts contain no private diagnostics, saved Wi-Fi passwords, client identities or bundled third-party drivers.

## Driver licensing

Windows Packet Filter is a separately licensed vendor driver. Personal use is permitted by its vendor terms; commercial redistribution requires the appropriate vendor license. See https://www.ntkernel.com/windows-packet-filter/licensing/ . Do not disable antivirus, Secure Boot or driver protections.
