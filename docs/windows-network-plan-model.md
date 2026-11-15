# Windows network plan model

`apnawin.services.windows_network_plan` is a pure immutable validation layer for intent that a future privileged Windows helper may apply. It performs no operating-system mutation.

## Invariants

- Interface identity is a positive 64-bit Windows interface LUID, not a localized adapter name or shell fragment.
- Routes use canonical CIDRs, same-family next-hop IP literals, and unsigned 32-bit metrics.
- The VPN server endpoint is pinned with an exact /32 or /128 host route through the pre-existing physical interface.
- Tunnel redirection is expressed only as IPv4 and/or IPv6 default routes on the tunnel interface, at most one per family.
- DNS servers are explicit, unique IP literals, bounded to 16 entries and assigned to the tunnel interface.
- The endpoint pin is ordered before tunnel default routes to prevent recursive routing.

The model does not discover gateways, snapshot the live route table, mutate routes/DNS, create Wintun, or prove route selection. A future executor must compare the plan with a fresh snapshot, preserve pre-existing endpoint and DNS state, verify the endpoint pin before applying default routes, and use ownership-aware compensation. If a mutation cannot be proven reversible, it must not be attempted.

A valid plan is not evidence of a working VPN and does not authorize enabling Connect.
