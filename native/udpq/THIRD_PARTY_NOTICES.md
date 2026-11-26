# Third-party notices

## StarUDP / Hysteria-v1 client source

- Project: https://github.com/starrising321/starudp
- Pinned commit: \`23fa29bb4fad600330b30e2b703b8029ef091446\`
- License: MIT
- Copyright notice from upstream \`LICENSE.md\`: Copyright (c) 2021 Toby

The upstream license text must accompany any redistribution of copied or built portions. This research build does not use the upstream \`gpl\` build tag. The source repository notes that builds made with \`-tags gpl\` are subject to GPLv3; this project must not enable that tag without a separate license review.


## Local security patch

The pinned source is patched at build time by native/udpq/patches/redact-client-config-logs.patch. The patch clears the client authentication bytes/string, XPlus obfuscation password and local HTTP/SOCKS credentials from the client config's INFO-level String() representation before it is logged. Patch SHA-256: 82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52. The patch is included in the test package and its digest is recorded in engine/runtime-manifest.json.
