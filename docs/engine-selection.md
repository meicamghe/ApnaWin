# Windows transport engine assessment

## Current implementation

Xray is no longer merely a candidate. The current branch contains a Windows Xray/Wintun TUN engine and registers it in the live desktop connection controller for `Transport.XRAY`.

The implementation includes:

- Explicit VLESS, VMess, Trojan and Shadowsocks share-link parsing and validation in `src/apnawin/engines/xray_share_link.py`.
- Encrypted profile configuration storage through the existing Windows current-user DPAPI store.
- A real `XrayTunnelEngine` backed by the elevated helper and `XrayTunnelSupervisor`.
- A Wintun-backed Xray TUN with IPv4/IPv6 system routes, DNS configuration, WFP leak blocking and readiness checks.
- Runtime verification against the installed Xray/Wintun manifest before the engine accepts a profile.
- Lifecycle monitoring and cleanup/error handling for helper exit and disconnect.

The desktop controller currently registers only `Transport.XRAY` and `Transport.APNA_SSH`. `Transport.OPENVPN` and `Transport.SOCKS` remain enum/profile metadata only; no live engine is registered for either, and the Connect control remains disabled for them.

## Pinned Windows runtime

`scripts/Install-VpnRuntime.ps1` pins and verifies:

| Component | Version | Verification |
|---|---:|---|
| Xray-core | 26.11.9 | Pinned release archive SHA-256, xray.exe PE x64 check and version check |
| Wintun | 0.14.1 | Pinned archive SHA-256, DLL PE x64 check and valid WireGuard Authenticode signer |

The script also copies the upstream license files and writes `runtime-manifest.json` with executable/DLL hashes. The test workflow independently downloads the pinned Xray archive, verifies its SHA-256 and asks the actual executable to validate representative generated VLESS, VMess, Trojan and Shadowsocks configurations.

This is source/runtime validation. Product packaging and artifact publication are currently disabled in CI; no new Windows installer or product artifact is being produced by the current workflow.

## What this does not prove

- Acceptance of any private APNA catalog category by the Xray engine.
- A real connection to an APNA provider endpoint.
- Successful authentication using an APNA account.
- A real provider UDPGW round-trip or end-to-end Windows application traffic.
- Clean-host Windows 10/11 acceptance for every route, DNS, leak and crash-cleanup case.

The Android split's `libxray.so` contains multiple protocol implementations, but that fact alone does not establish the protected APNA category-to-config mapping. APNA categories such as `ocsv2ray`, `ocsxray`, `ocstrojan` and `ocsshadow` must remain unmapped until the v51 selection/configuration contract is independently verified.

## Other engine families

- **APNA SSH:** implemented as a separate Paramiko-based adapter with payload socket modes, host-key verification, SOCKS5 forwarding and an optional SSH-carried UDPGW path. Its exact compatibility with the protected Salamander service and live provider behavior remains unproven.
- **OpenVPN:** no production adapter or process supervisor is registered. A generic imported `.ovpn` engine would be a separate feature and must not be confused with proof that an APNA catalog category selects OpenVPN.
- **SOCKS:** a proxy endpoint is not, by itself, an encrypted VPN transport. It requires a defined upstream role and lifecycle before it can become a selectable engine.
- **QUIC/DTLS / `libudpqtwo.so`:** static native signatures are insufficient to identify the protocol or service owner. Keep it classified as an unidentified protected proxy runtime until the service binding, config schema and handshake are recovered.
- **BadVPN:** the separate native Windows research build targets TAP-Windows and is not integrated with the product's Wintun backend.

## Acceptance gates

1. Independently verify the authorized provider's SSH host key and complete authentication.
2. Verify local SOCKS TCP forwarding and a real UDPGW datagram round-trip.
3. Verify routed TCP, UDP and DNS traffic through Wintun, including IPv4 and IPv6.
4. Verify DNS leak protection, startup rollback, disconnect and abnormal-process cleanup.
5. Repeat on clean Windows 10 and Windows 11 hosts with redacted diagnostics and recorded runtime hashes.

CI success, Xray config acceptance and process startup are not substitutes for real provider authentication and routed traffic. Keep PR #6 Draft and unmerged until the real-provider acceptance gates pass.
