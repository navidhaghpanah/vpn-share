# VPN Share for Android

Android alpha target: Android 8.0+ (`minSdk 26`), compiled against Android 16/API 36.

## What works

- Detects an active Android VPN transport and its TUN interface.
- Android 16/API 36: requests Wi-Fi tethering through the public `TetheringManager` API.
- Android 8–15: opens the system tethering panel because third-party apps do not have a stable public start/stop API.
- Optional root engine: installs a dedicated IPv4 NAT chain, fail-closed forwarding rule, and IPv6 forwarding block between the hotspot subnet and the detected VPN interface.
- Writes a recovery marker before changing root network rules and removes app-owned rules after interruption.

## Honest platform limit

An ordinary Android app cannot take packets out of another app's `VpnService`. Only one VPN service can be active for a user. `LocalOnlyHotspot` explicitly provides no Internet. Therefore protected hotspot-to-existing-VPN forwarding requires root or OEM/system privileges and must be hardware-tested per ROM.

## Build

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
$env:ANDROID_HOME = 'C:\Users\NH\AppData\Local\Android\Sdk'
.\gradlew.bat test assembleDebug
```

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.
