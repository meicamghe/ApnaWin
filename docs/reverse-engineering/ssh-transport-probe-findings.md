# SSH / TLS / HTTP transport probe findings

**Status:** diagnostic evidence collected from the user's Windows test session; no protocol compatibility fix is established. This document records observations and standards checks only. It does not authorize weakening TLS verification, enabling legacy ciphers, or substituting profile values.

## Repository baseline checked

At the time of this investigation, the default `main` branch was at:

`3f699c03af3778671a5fba9680b7211de230fa6b`

The checked `pyproject.toml` and `requirements.txt` declare PySide6 only; no Paramiko or SSH transport dependency was present. The visible engine package contains the transport-neutral contract, mock adapter, packet queue, Windows job/process support, and Xray runner. The APK inspection code documents bounded static DEX/ELF metadata analysis; it does not yet provide proof of APNA SSH implementation recovery.

Therefore the reported SSH probe classes and runtime behavior cannot yet be mapped to source files in this repository snapshot. Verify the exact source commit/build provenance of the tested Windows artifact before changing the SSH implementation.

## User-reported probe evidence

### HTTP proxy / CloudFront

All reports used target endpoint `d2vkityu2663xy.cloudfront.net:1194` and failed before SSH key exchange.

| Profile label | HTTP request Host | Target origin | Observed response |
|---|---|---|---|
| CloudFront A | `testbed.swpc.noaa.gov` | `testbed.swpc.noaa.gov:80` | HTTP 301 from Apache; Location points to HTTPS `www.testbed.swpc.noaa.gov` |
| CloudFront G – Iran filter breaker | `[proxy]` | `redmas.com.co:80` | HTTP 403; CloudFront; `x-cache: Error from cloudfront` |
| CloudFront G – IR_MCl Wi-Fi | `[proxy]` | `careers.zebra.com:80` | HTTP 403; CloudFront; `x-cache: Error from cloudfront` |
| CloudFront G – Iran #8 | `[proxy]` | `estacio.br:80` | HTTP 403; CloudFront; `x-cache: Error from cloudfront` |
| NΞT SHIELD 04 | `[proxy]` | `posdigital.pucpr.br:80` | HTTP 403; CloudFront; `x-cache: Error from cloudfront` |

The repeated 403 across several target origins suggests a common request/profile/edge-policy issue, but does not identify which field is wrong. Do not copy Host, SNI, path, port, or payload values from one profile to another. The 301 is a distinct result: the probe intentionally rejects redirects rather than changing the requested route.

### TLS Direct

| Profile | TLS endpoint reported by probe | SNI | Result |
|---|---|---|---|
| MASTER G-Iran 1 | `sm2.tumsongcloud.xyz:443` | `www.whatismyip.com` | Certificate verification failed: self-signed certificate |
| MASTER G-Iran 5 | `sm16.tumsongcloud.xyz:443` | `10minutemail.com` | Certificate verification failed: self-signed certificate |

The profile port was 1194 while the TLS probe reported port 443. Confirm whether this is an intentional transport-specific mapping or a probe/configuration discrepancy. Never disable certificate verification or trust an unverified certificate. A provider CA must be obtained and authenticated through a trusted provider channel.

### SSH cipher negotiation

Two separate probes for the Tumsongcloud hosts reported:

- `sm2.tumsongcloud.xyz:1194`: server cipher list `[strawberry]` in both client-to-server and server-to-client directions.
- `sm16.tumsongcloud.xyz:1194`: same reported cipher list.
- Client policy in the error: AES CTR/CBC, AES-GCM, and 3DES-CBC; no overlap.
- The probe reports the peer name as unrecognized by its Paramiko build.

This is evidence from the probe's parser/error report, not yet an independently captured raw SSH_MSG_KEXINIT packet. Obtain a redacted packet-level capture or equivalent structured KEXINIT dump before concluding that the remote peer really advertises exactly this list.

## Standards check: the literal name `strawberry`

SSH algorithm names are case-sensitive. RFC 4251 specifies that names without `@` are assigned through the IANA registry, while locally defined extension names use the `name@domain` form. The IANA SSH Encryption Algorithm Names registry does not list `strawberry` in the registry snapshot checked for this investigation.

Sources:
- RFC 4251, Section 6: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
- IANA SSH Protocol Parameters, Encryption Algorithm Names: https://www.iana.org/assignments/ssh-parameters
- RFC 4253, SSH transport and cipher negotiation: https://www.rfc-editor.org/rfc/rfc4253.html

Consequences:
1. `strawberry` is not a registered SSH encryption algorithm name in the IANA list checked.
2. As written (without `@`), it does not follow RFC 4251's locally defined extension naming convention.
3. This does not prove it is a real proprietary cipher. It may be a server-specific non-standard implementation, a malformed/misparsed KEXINIT, a middlebox response, or a deliberately synthetic test value.
4. Do not alias it to AES, infer its primitive from its name, or add it to the client allowlist without the provider's protocol specification and a verifiable implementation.

The SSH negotiation is directional: client-to-server and server-to-client encryption names are selected independently. A future parser should preserve each raw name-list separately and report the exact category (cipher, KEX, host-key, MAC, compression) rather than collapsing all negotiation failures into a generic key-exchange error.

## Relevant source-research result

The previously supplied Net::SSH2 issue is relevant only as a reminder to verify the actual loaded SSH library and version: an application can load an older bundled shared library even when a newer one is installed. It does not explain `strawberry`.

The Projective Strawberry Cloud Access security document and the `strawberry-code/tuilegram` repository do not establish a relationship to the reported SSH cipher. In particular, the word “Strawberry” in those project names is not evidence about this peer's SSH algorithm.

## Next evidence required

- [ ] Identify the exact tested Windows artifact commit, build workflow run, and source branch.
- [ ] Obtain a redacted raw SSH identification + SSH_MSG_KEXINIT capture for an authorized test endpoint; preserve the server's exact name-lists and packet boundaries.
- [ ] Confirm whether the probe's `strawberry` value came directly from the server's encryption name-list, and separately inspect KEX, host-key, MAC, and compression lists.
- [ ] Recover the APK's relevant DEX call path and native-library linkage; do not infer linkage from filenames alone.
- [ ] Continue the existing `libudpqtwo.so` Go symbol-recovery work only with the exact APK/native binary and reproducible bounds-checked evidence.
- [ ] Keep TLS verification and the secure SSH cipher policy fail-closed until a provider-authenticated specification and implementation are available.

## Explicit non-goals

- No new Windows build before APK reverse engineering is complete.
- No profile value substitution across catalog entries.
- No redirect-following change for SSH payloads without provider-specific evidence.
- No TLS certificate bypass or trust-on-first-use shortcut.
- No guessed cipher alias, downgrade, or global legacy-cipher enablement.
- No claim of a working SSH/VPN connection based only on TCP reachability or an HTTP response.
