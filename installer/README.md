# Building the Windows Installer

This folder contains an **Inno Setup** script that produces a traditional Setup.exe in addition to the existing portable EXE.

## Requirements

- [Inno Setup 6](https://jrsoftware.org/isdl.php) (free)
- The published portable `VPNShare.exe` (from `dotnet publish`)

## Steps

1. Publish the Windows app:
   ```powershell
   cd Windows
   dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
   ```
2. Copy or ensure `VPNShare.exe` is at the path expected by `vpnshare.iss` (or edit the Source line).
3. Open `vpnshare.iss` in Inno Setup Compiler and click **Compile**.
4. The installer will appear in `installer/Output/`.

## Notes

- The portable EXE remains available as a separate download.
- The installer requests Administrator rights (needed for the packet driver and network changes).
- Persian language support is included if the Persian.isl file is present in your Inno Setup installation.
- Driver installation is still handled at runtime by the application itself (it downloads and verifies the official signed package).
