# Base APK static analysis from ChatGPT Library — 2026-11-28

## Provenance and integrity

- Source: the user's existing ChatGPT Library file `/base.apk` (no re-upload requested).
- Materialized locally as `/mnt/data/apnawin-library/base.apk`.
- Size: 20,419,648 bytes.
- SHA-256: `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`.
- ZIP inventory: 1,479 entries; 24,155,576 uncompressed bytes.
- Package: `com.apnatunnel.lite`; versionName `APNA`; versionCode 51.
- Manifest declares `requiredSplitTypes="base__abi,base__density"`. This is not a complete install set: ABI and density splits are required.
- Application class: `com.liapp.x`; `debuggable=false`; `allowBackup=false`; `extractNativeLibs=true`.

## DEX inventory

- `classes.dex`: 13,774,224 bytes; 53,056 string IDs and 10,683 class definitions.
- `assets/.bxdtcxfzx.dex`: 99,335 bytes; one class definition under an obfuscated `com.liapp` descriptor.
- `assets/audience_network/classes.dex`: 57,076 bytes; 38 classes.
- `assets/audience_network/classes2.dex`: 5,237,600 bytes; 3,292 classes, primarily Facebook Audience Network SDK code.
- No `.so` member is present anywhere in this base APK. This does not contradict the repository's separate ABI split/native-library inventory; it means native payload provenance cannot be attributed to base.apk alone.

## Confirmed VPN/tunnel Java-side structure in base DEX

The primary DEX defines the following application classes and methods:

- `prince.open.vpn.service.vpn.TunnelManagerHelper`: `startXRay`, `stopXRay`, `startSsh`, `startSocksHttp`, and corresponding stop/restart methods.
- `Tunnel`: `startVpn`, `startTun2Socks`, `routeThroughTunnel`, `stopVpn`, `stopTun2Socks`, `startTunneling`, and `stopTunneling`.
- `TunnelVpnManager`: `startTunnel`, `runTunnel`, `newVpnServiceBuilder`, `onVpnEstablished`, `onTunnelConnected`, `onStartCommand`, and lifecycle/stop methods.
- `Tun2Socks`: `sendFd`, `run`, `interrupt`, and listener registration.
- `Pdnsd`: `makePdnsdConf`, `run`, `readFromRaw`, and file/config helpers.
- `org.uproxy.tun2socks.Tun2SocksJni`: declares native `runTun2Socks` and `terminateTun2Socks`.

The `TunnelManagerHelper.startXRay` DEX code was inspected at code-item offset `0xc157e4`. It constructs an Android `Intent` whose class literal is `prince.open.vpn.service.XRayDNSService`, calls `TunnelUtils.restartRotate()`, calls an obfuscated static helper `Kw.r(Context, Intent)`, and then invokes `Context.startService(Intent)`. This proves a Java-side service-start path for the XRay-named service; it does not prove the service's internal implementation or successful runtime startup.

The `sendFd` method on the Java `Tun2Socks` wrapper is a concrete descriptor-handoff lead. The DEX also references `libtun2socks.so` and `libpdnsd.so`, and contains the JNI class/method declarations above. Actual native invocation arguments, FD ownership, and lifecycle still require the ABI split's code and runtime corroboration.

## Manifest components

The binary Android manifest was decoded directly. It declares, among others:

- `prince.open.vpn.service.SalamanderService` (exported foreground service)
- `prince.open.vpn.service.XRayDNSService` (exported foreground service)
- `prince.open.vpn.service.SocksDNSService` (exported foreground service)
- `prince.open.vpn.service.PInjectorService`
- `prince.open.vpn.service.vpn.TunnelVpnService`, protected by `android.permission.BIND_VPN_SERVICE`
- `prince.open.vpn.tethering.ProxyService`

The application also requests Internet, network-state, foreground-service, notification, wake-lock, and boot-receiver permissions. Manifest declaration alone is not proof that a component is started or that its tunnel is functional.

The service descriptors for `XRayDNSService`, `SalamanderService`, and `TunnelVpnService` are referenced by the manifest/type table but their class definitions were not found in the base DEX class-def list. The required ABI/density splits must be inspected before concluding where those implementations live.

## Opaque asset

- `assets/janur.json`: 366,636 bytes.
- It is not plaintext JSON despite its extension.
- Its contents are valid Base64 text; decoding yields 274,976 bytes with measured byte entropy about 7.9993 bits/byte.
- This is consistent with opaque/high-entropy binary data, but does not identify a cipher, compression format, schema, or purpose. No decryption algorithm is claimed.

## Limitations and next parallel lanes

1. Obtain the user's existing `split_config.arm64_v8a.apk` from Library if present, then hash and inspect its DEX/native members; do not ask the user to re-upload until Library inventory is exhausted.
2. Inspect `XRayDNSService`, `SalamanderService`, and `TunnelVpnService` implementation definitions and connect service startup to native process/config loading.
3. Trace `Tunnel.sendFd` and the native `Tun2SocksJni` calls, including FD transfer direction, close semantics, and SOCKS/DNS endpoint configuration.
4. Analyze `assets/janur.json` only after identifying its consuming code and key/nonce derivation.
5. Match `libxray.so`, `libudpqtwo.so`, and `libsalamander.so` by SHA-256 to exact APK member paths before assigning provenance.

## Verification status

- Direct offline ZIP, DEX-table, class-definition, string-table, and binary-manifest inspection completed on the Library-backed `base.apk`.
- No APK code was executed; no device/runtime behavior is claimed.
- No CI, Windows build, SSH change, PR merge, or main-branch modification was performed.
- Existing DEX scanner/parser tests remain unexecuted; the observations above came from a separate bounded local parser and direct byte inspection.
