# Native reverse-engineering notes: `libudpqtwo.so`

**Status:** preliminary static analysis  
**Analysis date:** 2026-11-26  
**Sample:** `/tmp/apnawin-udpqtwo/libudpqtwo.so` extracted from the currently inspected ApnaWin APK set  
**Target ABI:** Android ARM64 / AArch64

This document records observations from ELF metadata, strings, Go metadata attempts, and AArch64 disassembly. It deliberately separates confirmed binary facts from hypotheses. No native code was executed, and no application source or build files were changed as part of this analysis.

## 1. Binary identity

- ELF64, little-endian, shared object, AArch64.
- Android API level 21; NDK r19c metadata.
- Dynamic dependencies observed: `liblog.so`, `libdl.so`, and `libc.so`.
- The library is stripped; ordinary Go symbol recovery did not succeed.
- The binary contains cgo startup symbols including `x_cgo_init`, `x_cgo_thread_start`, `x_cgo_callers`, and related runtime hooks.
- The Go build-info area contains `unknown`; `go version -m` did not recover a useful module/build version.

The above is strong evidence that the library contains Go code linked through cgo. It does not identify the Go toolchain version used to build the Android library.

## 2. Go symbol recovery status

The following attempt was made:

```bash
go install github.com/mandiant/GoReSym@latest
"$(go env GOPATH)/bin/GoReSym" -t -d -p \
  /tmp/apnawin-udpqtwo/libudpqtwo.so
```

GoReSym could not locate a usable pclntab. A scan for common pclntab magic values produced candidates, but none passed header validation. Therefore:

- Do not claim that pclntab is definitely absent.
- Do not select a Go version based only on unvalidated magic candidates.
- Function-name strings found by `strings -a -t x` are file offsets into string data, not code virtual addresses.
- The presence of readable Go function-name strings does not mean a complete Go symbol table was recovered.

## 3. Application-level names

The binary contains application package/type names including:

- `main.Relay`
- `main.serverConfig`
- `main.clientConfig`
- `type:.eq.main.Relay`

Closure/type metadata also references values such as `*main.serverConfig`, `*main.clientConfig`, `*prometheus.Registry`, a client type rendered as `*CiKk3EagH.Client`, and `chan error`.

These are high-value anchors for further analysis. In particular, `main.Relay` and the two config types are more useful next targets than continuing to enumerate third-party dependency symbols. The equality helper name `type:.eq.main.Relay` is type metadata evidence; it is not a recovered Relay method or its address.

The semantics of Relay and the configuration structures remain unknown. Their presence alone does not establish which protocol paths are active.

## 4. Networking implementations present in the binary

The strings and embedded Go package/function names show that the library includes substantial third-party networking code:

### QUIC and HTTP/3

Observed package families include:

- `github.com/quic-go/quic-go`
- `github.com/quic-go/qpack`
- `github.com/quic-go/quic-go/http3`
- `github.com/quic-go/qtls-go1-20`

The embedded names cover QUIC packet/frame handling, transport parameters, ACK/loss recovery, congestion control, flow control, packet protection, TLS handshake/key updates, stream and datagram APIs, retry/version negotiation, UDP socket handling, HTTP/3 client/server components, and QPACK.

**Interpretation:** a substantial QUIC and HTTP/3 implementation is compiled into this library. This does not prove that ApnaWin invokes every client/server API or that QUIC is an exposed user-selectable profile protocol.

### DTLS

Observed package family:

- `github.com/pion/dtls/v2`

The embedded names include DTLS handshake messages and record-layer operations, including ClientHello, ServerHello, ClientKeyExchange, Finished, HelloVerifyRequest, certificate and key-exchange messages, record marshal/unmarshal, and cipher-suite implementations. The cipher-suite names include AES-GCM, AES-CBC, AES-CCM, ECDHE-ECDSA, ECDHE-RSA, and PSK variants.

**Interpretation:** a substantial Pion DTLS v2 implementation is compiled in. The exact application call path and purpose have not yet been established.

### SOCKS5, HTTP proxy, and transparent proxy

Observed package families:

- `github.com/txthinking/socks5`
- `github.com/elazarl/goproxy`
- `github.com/LiamHaworth/go-tproxy`
- `github.com/txthinking/x`

Names include SOCKS5 negotiation/request/reply and datagram handling; HTTP proxy request/response and CONNECT handlers; WebSocket tunneling; TLS MITM support; TCP and UDP transparent-proxy helpers; and TCP/UDP dialing utilities.

**Interpretation:** the library contains components suitable for local proxying and transparent TCP/UDP traffic redirection. This is consistent with a proxy/relay networking role, but package inclusion is not proof that every component is active in the app's runtime path.

### Other dependency families

The binary also contains names associated with crypto helpers such as HKDF, Prometheus metrics, MaxMind GeoIP, ACME/certificate handling, and configuration formats/parsers such as YAML, TOML, and JSON. These are dependency observations, not a verified feature inventory.

## 5. ELF layout and address notes

Relevant section metadata observed:

| Section | Virtual address | File offset | Size |
|---|---:|---:|---:|
| `.text` | `0x1be520` | `0x1be520` | `0x731104` |
| `.rodata` | `0x8ef640` | `0x8ef640` | `0x138ef8` |
| `.data.rel.ro` | `0xa38de0` | `0xa28de0` | `0x689fd0` |
| `.data` | `0x10c31a0` | `0x10b31a0` | `0x19078` |
| `.go.buildinfo` | `0x10dc220` | `0x10cc220` | `0x30` |
| `.noptrdata` | `0x10dc260` | `0x10cc260` | `0x4b5d8` |
| `.bss` | `0x1127840` | N/A | `0x39ef0` |
| `.noptrbss` | `0x1161740` | N/A | `0xf310` |

For the examined second PT_LOAD mapping, the observed relationship is file offset = virtual address - `0x10000`. Do not apply this as a universal ELF rule outside that segment.

Selected dynamic symbols include cgo runtime hooks near `0x8efxxx`; `_start` is at `0x1be520`. No `JNI_OnLoad` export was found in the earlier limited dynamic-symbol inspection. This is not proof that the library has no JNI interaction; registration or loading may occur through other mechanisms or hidden/stripped symbols.

## 6. Current disassembly lead: `main.main`

A function labelled `main.main` was observed at virtual address `0x8c3b30`. The supplied disassembly shows it:

1. Performs a Go stack-guard check.
2. Loads a global value using the address `0x10c34a0`.
3. Calls `0x6e9f10`.
4. Adjusts the returned values and calls `0x6e6b40`.
5. Returns.

This is a short wrapper-like entry function, but its exact role is not yet established. The objdump labels for `0x6e9f10` and `0x6e6b40` are relative to the nearest visible symbol and must not be treated as reliable function names for those exact targets.

The next disassembly pass should inspect:

- `0x8c3b90` and nearby functions;
- `0x6e9f10`;
- `0x6e6b40`;
- the global object at VA `0x10c34a0` (file offset `0x10b34a0` under the observed PT_LOAD mapping);
- all application-specific `main.*` strings, especially methods associated with Relay and configuration types.

## 7. Important negative finding: no evidence for `strawberry`

No explicit `strawberry` string was found in the scanned `libudpqtwo.so` string data.

The presence of Pion DTLS AES-CBC/GCM/CCM suites does **not** identify the reported `strawberry` cipher and must not be used to infer an alias or mapping. No relationship between that cipher label and this DTLS implementation has been established.

A separate earlier inspection of `libputils.so` found JNI-style OpenSSL/AES-CBC encryption/decryption names, but no evidence currently links those methods to `strawberry` or to this `libudpqtwo.so` path.

## 8. Working architectural hypothesis

The combined dependency evidence is consistent with `libudpqtwo.so` being a Go-based networking/proxy/relay component that bundles several possible transport and proxy stacks: QUIC/HTTP3, DTLS, SOCKS5, HTTP proxying, and transparent TCP/UDP redirection.

This remains a **working hypothesis**, not a verified runtime architecture. Static package presence can result from linked dependencies that are unused by the specific application build or code path. Runtime call paths and configuration-to-constructor relationships still need to be recovered.

## 9. Next investigation steps

Prioritize application-owned code over more dependency string dumps:

1. Disassemble the addresses listed in section 6 and identify the global object used by `main.main`.
2. Recover function boundaries and references around the `main.*` name strings, taking care to distinguish file offsets, virtual addresses, and actual function entry points.
3. Trace references to `main.Relay`, `main.serverConfig`, and `main.clientConfig` to determine fields, constructors, methods, and which transports are selected.
4. Map app-owned call sites into the embedded QUIC, DTLS, SOCKS5, goproxy, and tproxy implementations.
5. Only after the app-level call graph is clearer, inspect `libxray.so`, `libsalamander.so`, and the remaining native libraries for their distinct responsibilities.

Suggested next command batch (run in the existing Ubuntu analysis environment):

```bash
LIB=/tmp/apnawin-udpqtwo/libudpqtwo.so

echo "===== APP-LEVEL GO NAMES ====="
strings -a -t x "$LIB" | grep -E 'main\\.|main[.]'

echo
echo "===== MAIN / RELAY / CONFIG RELATED STRINGS ====="
strings -a -t x "$LIB" | grep -Ei 'Relay|serverConfig|clientConfig|listen|dial|proxy|tproxy|socks|quic|dtls|http3|cipher|protocol|config'

echo
echo "===== MAIN.MAIN AND NEIGHBOR ====="
aarch64-linux-gnu-objdump -d \
  --start-address=0x8c3b30 --stop-address=0x8c3e00 "$LIB"

echo
echo "===== CALL TARGET 0x6e9f10 ====="
aarch64-linux-gnu-objdump -d \
  --start-address=0x6e9d00 --stop-address=0x6ea200 "$LIB"

echo
echo "===== CALL TARGET 0x6e6b40 ====="
aarch64-linux-gnu-objdump -d \
  --start-address=0x6e6900 --stop-address=0x6e6e00 "$LIB"

echo
echo "===== GLOBAL AT VA 0x10c34a0 (PT_LOAD2 FILE OFFSET 0x10b34a0) ====="
xxd -g8 -s 0x10b34a0 -l 128 "$LIB"
```

## 10. Scope and reproducibility caveats

- These notes summarize the binary observations and command outputs shared during this analysis session; they are not a fresh independent re-run against the user's local files.
- File offsets reported by `strings -a -t x` are not virtual addresses.
- Dependency symbols establish code presence, not use.
- Static analysis does not establish successful initialization, runtime loading, protocol negotiation, or server compatibility.
- No source changes, Windows builds, or CI runs were performed for this investigation.
