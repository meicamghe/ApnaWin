# Android APK manifest inspection

## Metadata-only inventory

Run the repository's inventory first to record the exact APK size and SHA-256:

```powershell
py -3 tools/inspect_apk.py .\\path\\to\\application.apk
```

It never extracts or executes archive members. See [apk-inventory.md](apk-inventory.md)
for ZIP safety limits and the fields that inventory does and does not establish.

## Optional Android SDK manifest decoder

Install Android SDK Command-line Tools / APK Analyzer and make `apkanalyzer`
available on `PATH`. Then run:

```powershell
py -3 tools/inspect_apk_manifest.py .\\path\\to\\application.apk
```

The command invokes the installed tool as an argument array
(`apkanalyzer manifest print APK`), without a shell, with a 30-second timeout.
If the tool is missing, the command fails clearly; it does not guess or download
an executable. The tool's output is limited to 4 MiB and only selected fields
are emitted: package name, numeric version code, whether a version name exists,
min/target SDK, permission names, component type/name/exported/permission, and
services declaring `android.permission.BIND_VPN_SERVICE`.

The report deliberately omits version-name text, labels, intent-filter data,
resource values, arbitrary strings, URLs, and raw XML. It does not verify APK
signatures, establish runtime behavior, or discover APNA server endpoints.
A service declaring the VPN binding permission is a manifest declaration, not
proof that the VPN service works. Keep the APK SHA-256, SDK tool version, and
exact command alongside any external evidence record.

The decoder uses Python's XML parser only on textual XML emitted by the
Android SDK tool. DTD/entity declarations are rejected. The APK itself is
passed as an input to the local SDK tool and is not unpacked by ApnaWin.
Treat APKs and SDK tools as untrusted software; use an isolated analysis
environment for unknown samples.
