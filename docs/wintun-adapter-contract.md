# Wintun ownership decision

ApnaWin delegates the Windows TUN adapter and packet I/O to Xray-core's native `tun` inbound. Xray already:
- opens or creates the Wintun adapter;
- starts and owns the Wintun ring session;
- receives and sends packets;
- configures interface addresses, MTU, routes and DNS;
- binds Xray's own outbound sockets to the physical interface;
- optionally installs Windows Filtering Platform leak filters;
- flushes route, address and DNS state and closes WFP/session/adapter resources on graceful shutdown.

A separate Python Wintun FFI or packet pump would duplicate the same adapter and conflict with Xray's ownership. Do not add one unless the Xray TUN implementation is deliberately replaced.

The Windows runtime requires a matching `wintun.dll` beside `xray.exe`. The DLL and Xray binary must be pinned, licensed and installed in a protected application directory before packaging.

See [Windows full-tunnel path using Xray TUN](xray-windows-tun.md) and the upstream implementation:
- https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows.go
- https://github.com/XTLS/Xray-core/blob/main/proxy/tun/handler.go
- https://github.com/WireGuard/wintun
