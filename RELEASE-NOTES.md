# First Custom NAT preview

Windows: download **VPNShare-0.5.0-preview.4.exe** and run it as Administrator. This is one self-contained portable EXE; .NET does not need to be installed. If the separate packet driver is missing, the app downloads its official personal-use installer and verifies its pinned hash and signature. The driver is not bundled. Network drivers require system installation even though the app is portable.

Ubuntu/Debian: install **vpnshare_0.5.0.preview4_all.deb** using `sudo apt install ./vpnshare_0.5.0.preview4_all.deb`. This installs GTK, NetworkManager and packet-filter dependencies through the distribution package manager. Launch VPN Share from the applications menu. Linux is packaged and tested at the logic level; actual Linux hotspot operation is not yet validated.

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

## Preview 4: ExpressVPN visibility and tethering subnet selection

- Distinguish a vendor-confirmed ExpressVPN connection with no usable tunnel adapter from a disconnected VPN. The check runs the installed vendor CLI in read-only status mode with a timeout; it never changes VPN settings or treats the physical USB/LAN input as a VPN.
- Disable Start when no usable VPN is selected; retain Stop/Restore controls. Show the full build version in the widget footer.
- Exempt only exact RFC1918 aggregate routes with a real forwarding next hop from private subnet occupancy. Keep on-link networks, specific routed networks, other aggregate prefixes and unknown next hops protected. Existing routes are not edited.
- A new hotspot /24 can shadow destinations inside a forwarded private summary. Deployments using private remote networks should review the chosen range; this preview has no manual pool configuration.
- 98 Windows checks passed locally, including a read-only gateway selection against the actual tethered route table. A vendor protocol switch was tried with user approval: Lightway TCP did not complete within the observation window, Automatic was restored and connected using Lightway UDP with a visible tunnel.
- This does not establish client internet, leak or reconnect acceptance for ExpressVPN. Adapterless WireGuard/PKF operation is still unsupported by this NAT backend.

## Preview 5: finish recovery after packet engine shutdown errors

- Always attempt journal restoration with a fresh driver device after engine disposal fails. Previously that error aborted Stop before NetworkSetup.Restore could run, leaving recovery pending.
- A successful fresh recovery completes shutdown; failures preserve both errors and the protection journal. No driver service restart or system reboot is attempted.
- Four regression checks exercise ordering, stale-device disposal failure, combined failure and failed recovery propagation. Repeated live sharing/quit/reopen acceptance still needs hardware verification.

## Preview 6: Wi-Fi Direct aborted publisher recovery

Only call publisher Stop while Started. Windows rejects Stop on an Aborted publisher, which previously prevented repeated Restore network attempts from completing. Release references and peers in finally; preserve genuine stop failures for an active publisher. Includes four status regressions. Hotspot creation failures still require hardware validation.

## Preview 7: consistent widget corners

Use the custom rounded window region as the single outline. Disable the additional Windows 11 DWM corner rounding and system acrylic backdrop, which could expose an inconsistent grey edge around the painted glass gradient. The widget retains its painted glass design. Applies to Options, About and other GlassForm dialogs too.

## Preview 8: bounded Hosted AP availability recovery

Before changing AP properties, detect Unavailable and restart only the selected disconnected physical Wi-Fi output once. Recheck GUID, disconnected status and absence of forwarding routes immediately before reset. Reopen WLAN and wait up to 15 seconds for AP availability; report failure instead of blindly starting an unavailable AP. Incoming/VPN adapters and WLAN service are not restarted. Include the native start failure reason in diagnostics. Live recovery acceptance is pending.

## Preview 9: SirGSM app icon

Use the official sirgsm.ir favicon for the EXE, window and notification tray. Include the official 192px SirGSM icon in the Linux desktop package. No networking behavior changed.

## Preview 10: use the visible SirGSM brand mark

The site's favicon differs from its visible SirGSM mark. Build a multi-resolution Windows icon from the official 192px SirGSM image so EXE and tray match the requested brand.

## Preview 11: responsive lifecycle operations

Start/recovery/stop work now runs behind a shared single-flight background worker. Snapshot controls on the UI thread before dispatching network setup; marshal progress through the existing UI log handler. Options uses capability results collected by background inventory rather than synchronously probing WLAN on open. Closing during an operation requests cancellation and closes after cleanup finishes. Six regressions cover nonblocking dispatch, duplicate rejection, completion, failure retry, UI synchronization-context isolation and an actual WinForms message-pump heartbeat during blocking worker activity. 116 Windows checks passed locally. Live hardware operation latency remains dependent on Windows/driver calls.
