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


## Deeper VPN/TUN execution path recovered from DEX — 2026-11-28

A second pass decoded method references and DEX instruction operands for the tunnel classes:

- Tunnel.startVpn calls Android VpnService.Builder.addRoute (and app allow/disallow filters), setSession, setConfigureIntent, and establish(), which returns a ParcelFileDescriptor. It contains configure-intent references for XRayDNSService, SalamanderService, and SocksDNSService. This is direct static evidence that the app's Java VPN engine establishes Android's VPN interface and supports multiple service/configuration modes.
- Tunnel.routeThroughTunnel creates and starts both Pdnsd and Tun2Socks worker threads. The Tun2Socks constructor receives a ParcelFileDescriptor, MTU and several network/SOCKS parameters.
- Tun2Socks.run resolves the libtun2socks.so executable path, creates a sock_path under the app data directory, builds a command line containing the TUN FD (ParcelFileDescriptor.getFd()), socket path, MTU/network arguments and --udpgw-transparent-dns, then invokes Runtime.exec(String). It subsequently calls sendFd(ParcelFileDescriptor, File).
- Tun2Socks.sendFd connects an Android LocalSocket to the generated socket path, obtains the descriptor with ParcelFileDescriptor.getFileDescriptor(), calls LocalSocket.setFileDescriptorsForSend(FileDescriptor[]), writes a byte, shuts down the socket output and closes the socket. This is concrete static evidence of SCM_RIGHTS-style FD passing to the native tun2socks process; it closes the previously open question of whether the Java wrapper contains an FD handoff path. Exact native receive-side behavior still needs the ABI binary.
- Pdnsd.run resolves libpdnsd.so, generates pdnsd.conf and pdnsd.cache, and invokes the DNS helper using Runtime.exec(String).
- TunnelVpnManager.runTunnel calls Tunnel.startTunneling, waits on a CountDownLatch, then stops tunneling/foreground service on termination. onStartCommand extracts VPN settings, SOCKS server address and DNS resolvers from the incoming Intent and calls Tunnel.startRouting.

These findings establish a concrete Android VPNService → Builder.establish → ParcelFileDescriptor → Java tun2socks launcher → LocalSocket FD transfer → native process design in static code. They do not establish successful execution on a device, the exact contents/behavior of missing native split binaries, or the Xray core process/config launch path. In particular, TunnelManagerHelper.startXRay starts XRayDNSService; this is not yet a proven direct invocation of the Go Xray executable.

## Library inventory limitation

The Library root inventory currently exposes base.apk but no exact-title split_config.arm64_v8a.apk, libudpqtwo.so, or libsalamander.so entries. The required ABI/density splits are therefore still missing from the accessible Library inventory; the base APK is sufficient for the Java-side TUN path above but not for native payload analysis.


## GitHub object identity cross-check

The Library-backed base.apk was independently matched to the repository's main-branch Git object. GitHub reports blob SHA-1 329a7f7482c54d008e31cc9b7a4858d68d4a719c for APNA-APKs/base.apk; computing the Git blob SHA-1 locally over the materialized Library bytes produces the exact same value. Therefore the Library file analyzed above is byte-for-byte identical to the committed repository base.apk, not merely a same-named APK.


## DEX-wide native-loader and process-launch callsite audit — 2026-11-28

A separate pass walked method definitions and direct invoke references across the primary classes.dex, rather than relying only on the bounded candidate-class scanner. The pass is static and class-name independent for direct method-reference matches; it does not resolve reflection, dynamically computed strings, or invoke-custom call graphs.

### Application bootstrap / LIAPP boundary

- The manifest Application class is `com.liapp.x`. Its DEX constructor invokes `android.app.Application.<init>`.
- `com.liapp.x.attachBaseContext(Context)` invokes an obfuscated static initializer on `com.liapp.x` before delegating to `Application.attachBaseContext`. This places LIAPP-related initialization on the application bootstrap path.
- Direct references to `System.loadLibrary` in the primary DEX resolve to five callsites. Two load the explicit AndroidX DataStore library `datastore_shared_counter` (in unrelated framework/helper classes). Three are inside obfuscated `com.liapp.x` methods; their library-name strings are passed through an obfuscated `com.liapp.k` string decoder and are not plaintext in the DEX.
- Direct references to `System.load` occur in two obfuscated `com.liapp.x` methods. Their paths are likewise derived through the obfuscated string helper.
- LIAPP classes `com.liapp.x`, `com.liapp.n`, `com.liapp.i`, `com.liapp.a`, and `com.liapp.v` contain reflective access to ClassLoader internals, fields/methods, lists and ZIP files. This supports a custom class/native loading or runtime-patching layer. It does not establish which native payloads are loaded, nor prove anti-tamper behavior without decoding the string/branch logic and correlating with the split/native files.

### Direct process-launch callsites

The primary DEX contains direct `Runtime.exec` callsites in:

- `Pdnsd.run`: builds and executes a command for `libpdnsd.so` after writing the pdnsd config/cache.
- `Tun2Socks.run`: builds and executes a command for `libtun2socks.so`, starts stdout/stderr reader threads, calls `sendFd`, then waits for the process. The code references `libtun2socks.so` and a data-directory `sock_path`; exact full command strings include obfuscated string-helper results and are not fully recoverable from plaintext constants alone.
- `VpnUtils.findProcessId` and `VpnUtils.killProcess`: use shell/process commands for process discovery/termination; these are lifecycle helpers, not evidence of Xray launch.
- Additional obfuscated/support callsites exist in unrelated classes and require per-callsite review before attribution.

There are two direct `ProcessBuilder.start()` callsites in the primary DEX, in obfuscated classes `LU10;` and `Lz70;`. Neither is yet linked to Xray, Salamander, or a particular native library. No attribution is made from method names alone.

### Service class resolution status

The primary DEX class-def table contains the Java tunnel manager and helper classes documented above. It does not define the manifest-referenced `XRayDNSService`, `SalamanderService`, or `TunnelVpnService` class descriptors found in the manifest/type references. The required ABI/density split(s), any additional DEX containers, and dynamic class-loader paths must be inspected to locate their implementations. This is consistent with (but does not prove) split or dynamically loaded service implementations.

### Reproducibility and caveats

- Direct invoke-reference inventory was generated from the actual primary DEX bytes in the Library-backed base APK.
- The lightweight local decoder used for this pass is not yet committed as a general-purpose tool and has not been validated against the full DEX opcode corpus. Treat the callsite counts as a targeted static triage, not a complete verifier.
- The existing production DEX scanner's tests remain unexecuted. No APK code was run and no Android runtime behavior is claimed.


## Library encrypted-data side track — 2026-11-28

The recursive Library inventory was rechecked. Within /ApnaWin it exposes base.apk, Apna server list.txt, an opaque 405,128-byte item named 6aa1acd5d8b2b25e6884eae4483e57, the Windows package archives, and the previously saved project notes. It does not expose split_config.arm64_v8a.apk, libudpqtwo.so, or libsalamander.so by those names.

The text content of Apna server list.txt was inspected without copying its contents into the repository:
- 32,750 characters, all in the Base64 alphabet.
- Decodes to 24,561 bytes.
- Shannon entropy of decoded bytes: 7.9928 bits/byte.
- Printable-byte ratio: 0.3824.
- Initial bytes: 14 a2 ce c1 60 e8 80 5b 1a 78 1d 6e de 7f 07 ed.
- No common ZIP/GZIP/JSON header is apparent at offset zero. This is high-entropy opaque data; it may be encrypted, compressed, or a custom binary envelope. No cipher, key, or format is identified.

The opaque 405,128-byte Library item could not be materialized through the available Files interface and was not analyzed. Do not assume it is an APK or native library based on its size or hash-like title.
