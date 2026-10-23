# VPN Share 0.4.7 — AP initialization fix

The 0.4.6 live start failed with Windows error 1610 (ERROR_BAD_CONFIGURATION) when reading the Hosted AP settings. The required WlanHostedNetworkInitSettings call was missing.

This build calls the initializer before reading/backing up AP configuration. Windows leaves already valid settings unchanged and creates defaults when the profile has not been configured before. The original existing-session checks and protected restoration journal remain in place.

## Actual integration result

On this computer, before initialization the connection-settings query returned error 1610. After the official initializer ran, connection settings returned 40 bytes and the enabled flag returned 4 bytes, matching the native ABI. That probe did not start a hotspot or change adapter addressing, routing, firewall rules or packet-driver modes. The newly initialized default AP profile persists as specified by Windows.

The previous 69 protocol/ABI/NAT/DNS regression checks passed on 0.4.6. The 0.4.7 change was compiled and the new initializer was exercised directly against Windows. Real second-client Wi-Fi/DHCP/internet and recovery acceptance remain pending.

Close an older app before opening this executable. Approve UAC, keep the VPN connected, use Automatic Wi-Fi output (prefers the unique compatible spare AP card), and start sharing. The sirgsm.ir link and NH footer are included.

Microsoft API documentation: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanhostednetworkinitsettings
