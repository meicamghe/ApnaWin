# Privileged helper request envelope

The platform-neutral `apnawin.services.privileged_protocol` module validates the outer request envelope before any future named-pipe service dispatches it.

- Payload must be non-empty UTF-8 and no larger than 64 KiB.
- JSON duplicate keys and non-standard numeric constants are rejected.
- The envelope must contain exactly `version`, `request_id`, `transaction_id`, `operation` and `arguments`.
- Version 1 uses lowercase canonical UUID strings and a fixed operation allowlist.
- JSON nesting, total values, object members, array items, key length and string length are bounded.
- Unknown operations and unknown envelope fields fail closed.

This is only envelope parsing. It does not create an IPC endpoint, authenticate a peer, authorize a session, deduplicate requests, validate operation-specific argument schemas, acquire the service mutex or perform Windows operations. The service must validate each operation's exact argument schema before any OS call; a structurally valid envelope is not authorization.


## Numeric and Unicode scalar bounds

In addition to the byte, depth, node and collection limits, the decoder rejects
integer values larger than 256 bits and rejects lone UTF-16 surrogate code points
in both string values and object keys. This prevents oversized integer objects
and malformed Unicode keys from passing the structural envelope validation.
These are transport-level bounds only; operation-specific numeric ranges and
argument schemas must still be validated independently before any Windows API call.


## Complete-frame codec

`apnawin.services.privileged_frame` defines one transport-neutral framing
format for a future byte-stream IPC channel: a four-byte unsigned little-endian
payload length followed by exactly that many UTF-8 JSON bytes. The codec rejects
zero/oversized lengths, truncated frames, trailing bytes and invalid envelopes.

A future named-pipe server must read the four-byte header first, reject lengths
above 64 KiB before allocating or reading the body, then read exactly the
declared number of bytes with a finite deadline. This complete-frame codec is
not a stream reader, does not create a pipe, and does not authenticate peers or
authorize operation arguments.
