# VPN Share 0.5.2

Hosted AP selection hotfix for Windows systems that retain an inactive DHCP gateway on a disconnected spare Wi-Fi card. A disconnected card is no longer misclassified as incoming merely because Windows keeps its previous gateway lease. The app revalidates that the physical card is still Disconnected immediately before any bounded adapter reset or AP setup; a connected input remains protected and is never selected.

Wi-Fi reliability hotfix: a `WiFiDirectAdvertisementPublisher` result of `Aborted (Success)` is treated as a transient driver contradiction and retried up to three times. If it remains rejected, VPN Share safely re-enumerates Hosted AP support and falls back only when exactly one disconnected, route-free Wi-Fi output is available. Incoming Wi-Fi, USB, LAN and VPN adapters are never selected for this recovery. Automated checks cover the retry boundary, non-success rejection and safe fallback selection; live acceptance still depends on the target Wi-Fi driver.

First stable personal-use release for Windows 10/11 and Ubuntu/Debian. It includes the custom VPN NAT engine, fail-closed client guards, automatic recovery, the bounded Wi-Fi power-state retry introduced in Preview 12, the SirGSM application icon, and separate taskbar minimize and system-tray Hide actions.

The Windows package is a self-contained portable EXE; the separately installed signed Windows Packet Filter driver is still required. Hardware and VPN-client compatibility depends on the Windows Wi-Fi/NDIS drivers. The Ubuntu/Debian package has automated logic coverage but has not received the same physical hardware acceptance as Windows. Verify downloads with `SHA256SUMS.txt`.

Notes for Preview 2 through Preview 12 are historical and live in [docs/PREVIEW-HISTORY.md](docs/PREVIEW-HISTORY.md). They are not part of this stable release.
