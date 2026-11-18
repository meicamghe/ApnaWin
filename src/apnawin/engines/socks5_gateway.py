"""Loopback SOCKS5 gateway that bridges TCP and UDPGW through SSH.

TCP CONNECT is delegated to the SSH client's local SOCKS5 dynamic-forwarding
endpoint. UDP ASSOCIATE is converted to BadVPN UDPGW packets over a TCP stream
opened through that same SSH endpoint. The listener is restricted to loopback.
"""
from __future__ import annotations

import ipaddress
import math
import select
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass

from apnawin.engines.udpgw_flows import UdpGwFlowTable
from apnawin.engines.udpgw_stream import (
    Socks5ConnectConfig,
    Socks5ProtocolError,
    UdpGwStreamClient,
    UdpGwTransportError,
    open_socks5_connect,
)


class Socks5GatewayError(RuntimeError):
    """The local SOCKS5 gateway could not be started or served a request."""


@dataclass(frozen=True, slots=True)
class Socks5GatewayConfig:
    ssh_proxy_host: str
    ssh_proxy_port: int
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    udpgw_host: str | None = None
    udpgw_port: int | None = None
    transparent_dns: bool = False
    dns_resolver: str | None = None
    max_udp_flows: int = 256
    keepalive_interval: float = 25.0
    udp_idle_timeout: float = 120.0
    connect_timeout: float = 10.0

    def __post_init__(self) -> None:
        for name in ("ssh_proxy_host", "udpgw_host"):
            value = getattr(self, name)
            if value is None and name == "udpgw_host":
                continue
            if not isinstance(value, str) or not value or len(value) > 253:
                raise ValueError(f"{name} must be a non-empty host")
            if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
                raise ValueError(f"{name} contains whitespace or control characters")
        try:
            listen_ip = ipaddress.ip_address(self.listen_host)
        except ValueError as exc:
            raise ValueError("listen_host must be a loopback IP address") from exc
        if not listen_ip.is_loopback or listen_ip.version != 4:
            raise ValueError("SOCKS5 gateway may only bind to an IPv4 loopback address")
        for name in ("ssh_proxy_port",):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise ValueError(f"{name} must be between 1 and 65535")
        if isinstance(self.listen_port, bool) or not isinstance(self.listen_port, int):
            raise ValueError("listen_port must be an integer")
        if not 0 <= self.listen_port <= 65535:
            raise ValueError("listen_port must be between 0 and 65535")
        if self.udpgw_host is None:
            if self.udpgw_port is not None:
                raise ValueError("udpgw_port requires udpgw_host")
        elif (
            isinstance(self.udpgw_port, bool)
            or not isinstance(self.udpgw_port, int)
            or not 1 <= self.udpgw_port <= 65535
        ):
            raise ValueError("udpgw_port must be between 1 and 65535")
        if not isinstance(self.transparent_dns, bool):
            raise ValueError("transparent_dns must be a boolean")
        if self.dns_resolver is not None:
            try:
                ipaddress.ip_address(self.dns_resolver)
            except ValueError as exc:
                raise ValueError("dns_resolver must be an IP address") from exc
        if (
            isinstance(self.max_udp_flows, bool)
            or not isinstance(self.max_udp_flows, int)
            or not 1 <= self.max_udp_flows <= 0xFFFF
        ):
            raise ValueError("max_udp_flows must be between 1 and 65535")
        for name in ("keepalive_interval", "udp_idle_timeout", "connect_timeout"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive and finite")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise Socks5GatewayError("SOCKS5 client disconnected during negotiation")
        result.extend(chunk)
    return bytes(result)


def _read_socks5_address(sock: socket.socket, address_type: int) -> str:
    if address_type == 1:
        return str(ipaddress.IPv4Address(_recv_exact(sock, 4)))
    if address_type == 4:
        return str(ipaddress.IPv6Address(_recv_exact(sock, 16)))
    if address_type == 3:
        length = _recv_exact(sock, 1)[0]
        if not length:
            raise Socks5GatewayError("SOCKS5 request contains an empty hostname")
        try:
            return _recv_exact(sock, length).decode("idna")
        except UnicodeError as exc:
            raise Socks5GatewayError("SOCKS5 request contains an invalid hostname") from exc
    raise Socks5GatewayError("SOCKS5 request uses an unsupported address type")


def parse_socks5_udp_datagram(data: bytes) -> tuple[str, int, bytes]:
    """Parse one SOCKS5 UDP request; fragmented datagrams are rejected."""
    if len(data) < 4 or data[:2] != b"\x00\x00":
        raise Socks5GatewayError("Malformed SOCKS5 UDP header")
    if data[2] != 0:
        raise Socks5GatewayError("SOCKS5 UDP fragmentation is not supported")
    address_type = data[3]
    offset = 4
    if address_type == 1:
        if len(data) < offset + 4 + 2:
            raise Socks5GatewayError("Truncated SOCKS5 IPv4 UDP datagram")
        host = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        offset += 4
    elif address_type == 4:
        if len(data) < offset + 16 + 2:
            raise Socks5GatewayError("Truncated SOCKS5 IPv6 UDP datagram")
        host = str(ipaddress.IPv6Address(data[offset : offset + 16]))
        offset += 16
    elif address_type == 3:
        if len(data) < offset + 1:
            raise Socks5GatewayError("Truncated SOCKS5 domain UDP datagram")
        length = data[offset]
        offset += 1
        if not length or len(data) < offset + length + 2:
            raise Socks5GatewayError("Invalid SOCKS5 domain UDP datagram")
        try:
            host = data[offset : offset + length].decode("idna")
        except UnicodeError as exc:
            raise Socks5GatewayError("Invalid SOCKS5 domain encoding") from exc
        offset += length
    else:
        raise Socks5GatewayError("SOCKS5 UDP datagram uses an unsupported address type")
    port = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    if port == 0:
        raise Socks5GatewayError("SOCKS5 UDP datagram uses destination port zero")
    return host, port, data[offset:]


def encode_socks5_udp_datagram(address: str, port: int, payload: bytes) -> bytes:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise Socks5GatewayError("SOCKS5 UDP response address must be an IP") from exc
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise Socks5GatewayError("SOCKS5 UDP response port is invalid")
    atyp = b"\x01" if isinstance(ip, ipaddress.IPv4Address) else b"\x04"
    return b"\x00\x00\x00" + atyp + ip.packed + struct.pack("!H", port) + bytes(payload)


def _socks5_reply(reply: int, host: str = "127.0.0.1", port: int = 0) -> bytes:
    address = ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv4Address):
        atyp = b"\x01"
    else:
        atyp = b"\x04"
    return b"\x05" + bytes((reply,)) + b"\x00" + atyp + address.packed + struct.pack("!H", port)


class _GatewayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, gateway) -> None:
        self.gateway = gateway
        super().__init__(address, handler)


class _GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        gateway: Socks5Gateway = self.server.gateway
        try:
            version, method_count = _recv_exact(self.request, 2)
            methods = _recv_exact(self.request, method_count)
            if version != 5 or 0 not in methods:
                self.request.sendall(b"\x05\xff")
                return
            self.request.sendall(b"\x05\x00")

            version, command, reserved, address_type = _recv_exact(self.request, 4)
            if version != 5 or reserved != 0:
                self.request.sendall(_socks5_reply(1))
                return
            target_host = _read_socks5_address(self.request, address_type)
            target_port = struct.unpack("!H", _recv_exact(self.request, 2))[0]
            # SOCKS5 UDP ASSOCIATE commonly uses port 0 to mean any
            # client-side UDP source port. Reject port zero only for CONNECT.
            if command == 1 and target_port == 0:
                self.request.sendall(_socks5_reply(1))
                return

            if command == 1:
                gateway._handle_connect(self.request, target_host, target_port)
            elif command == 3:
                gateway._handle_udp_associate(
                    self.request,
                    self.client_address[0],
                )
            else:
                self.request.sendall(_socks5_reply(7))
        except (OSError, Socks5GatewayError, UdpGwTransportError):
            return


class Socks5Gateway:
    """Local SOCKS5 server for TCP-over-SSH and UDP-over-UDPGW-over-SSH."""

    def __init__(self, config: Socks5GatewayConfig) -> None:
        self.config = config
        self._server: _GatewayServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise Socks5GatewayError("SOCKS5 gateway has not been started")
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def is_running(self) -> bool:
        """Whether the local SOCKS5 listener thread is still serving requests."""
        return (
            self._server is not None
            and self._thread is not None
            and self._thread.is_alive()
        )

    def start(self) -> Socks5Gateway:
        if self._server is not None:
            return self
        self._server = _GatewayServer(
            (self.config.listen_host, self.config.listen_port),
            _GatewayHandler,
            self,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="apnawin-socks5-gateway",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._thread = None

    def _handle_connect(
        self,
        client: socket.socket,
        target_host: str,
        target_port: int,
    ) -> None:
        try:
            upstream_socket = open_socks5_connect(
                Socks5ConnectConfig(
                    proxy_host=self.config.ssh_proxy_host,
                    proxy_port=self.config.ssh_proxy_port,
                    target_host=target_host,
                    target_port=target_port,
                    timeout=self.config.connect_timeout,
                )
            )
        except (OSError, ValueError, Socks5ProtocolError, UdpGwTransportError):
            try:
                client.sendall(_socks5_reply(5))
            except OSError:
                pass
            return

        try:
            client.sendall(_socks5_reply(0))
            self._relay_tcp(client, upstream_socket)
        finally:
            upstream_socket.close()

    @staticmethod
    def _relay_tcp(client: socket.socket, upstream: socket.socket) -> None:
        # Preserve both TCP directions independently. EOF from one peer is a
        # half-close, not a reason to discard a response still flowing back.
        readers = {client, upstream}
        while readers:
            readable, _, _ = select.select(tuple(readers), [], [], 30)
            if not readable:
                continue
            for source in readable:
                if source not in readers:
                    continue
                destination = upstream if source is client else client
                data = source.recv(64 * 1024)
                if not data:
                    readers.remove(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                destination.sendall(data)

    def _handle_udp_associate(self, control: socket.socket, peer_ip: str) -> None:
        if self.config.udpgw_host is None or self.config.udpgw_port is None:
            control.sendall(_socks5_reply(7))
            return

        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stream = None
        replied = False
        try:
            relay.bind((self.config.listen_host, 0))
            stream = UdpGwStreamClient(
                Socks5ConnectConfig(
                    proxy_host=self.config.ssh_proxy_host,
                    proxy_port=self.config.ssh_proxy_port,
                    target_host=self.config.udpgw_host,
                    target_port=self.config.udpgw_port,
                    timeout=self.config.connect_timeout,
                )
            ).connect()
            relay_host, relay_port = relay.getsockname()
            control.sendall(_socks5_reply(0, str(relay_host), int(relay_port)))
            replied = True
            self._run_udp_relay(control, relay, stream, peer_ip)
        except (OSError, UdpGwTransportError, Socks5GatewayError):
            if not replied:
                try:
                    control.sendall(_socks5_reply(1))
                except OSError:
                    pass
        finally:
            relay.close()
            if stream is not None:
                stream.close()

    def _run_udp_relay(
        self,
        control: socket.socket,
        relay: socket.socket,
        stream: UdpGwStreamClient,
        peer_ip: str,
    ) -> None:
        flows = UdpGwFlowTable(max_connections=self.config.max_udp_flows)
        allowed_endpoint: tuple[str, int] | None = None
        last_activity = time.monotonic()
        last_keepalive = last_activity

        while True:
            readable, _, _ = select.select(
                (control, relay, stream.socket),
                [],
                [],
                0.2,
            )
            now = time.monotonic()

            if control in readable:
                try:
                    if not control.recv(1, socket.MSG_PEEK):
                        return
                    return
                except OSError:
                    return

            if relay in readable:
                raw, source = relay.recvfrom(65535)
                if source[0] != peer_ip or (allowed_endpoint is not None and source != allowed_endpoint):
                    continue
                try:
                    target_host, target_port, payload = parse_socks5_udp_datagram(raw)
                    target_ip = self._resolve_udp_target(target_host, target_port)
                    lease = flows.get_or_create(
                        local_address=source[0],
                        local_port=source[1],
                        remote_address=target_ip,
                        remote_port=target_port,
                    )
                    stream.send_datagram(
                        connection_id=lease.connection_id,
                        address=target_ip,
                        port=target_port,
                        data=payload,
                        is_dns=self.config.transparent_dns and target_port == 53,
                        rebind=lease.rebind,
                    )
                    allowed_endpoint = source
                    last_activity = now
                except (ValueError, Socks5GatewayError, UdpGwTransportError):
                    continue

            if stream.socket in readable:
                try:
                    packet = stream.receive_packet(timeout=0.05)
                    if self._send_udp_response(packet, flows, relay):
                        last_activity = now
                    while stream.pending_packets:
                        packet = stream.receive_packet(timeout=0.05)
                        if self._send_udp_response(packet, flows, relay):
                            last_activity = now
                except socket.timeout:
                    pass
                except UdpGwTransportError:
                    return

            if now - last_keepalive >= self.config.keepalive_interval:
                stream.send_keepalive()
                last_keepalive = now
            if now - last_activity >= self.config.udp_idle_timeout:
                return

    def _resolve_udp_target(self, host: str, port: int) -> str:
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            if port == 53 and self.config.dns_resolver is not None:
                return str(ipaddress.ip_address(self.config.dns_resolver))
            raise Socks5GatewayError(
                "Domain-name UDP targets are disabled to prevent DNS leakage"
            )

    @staticmethod
    def _send_udp_response(
        packet,
        flows: UdpGwFlowTable,
        relay: socket.socket,
    ) -> bool:
        if packet.is_keepalive or packet.address is None or packet.port is None:
            return False
        flow = flows.lookup(packet.connection_id)
        if flow is None:
            return False
        destination = (str(flow[0]), flow[1])
        relay.sendto(
            encode_socks5_udp_datagram(str(packet.address), packet.port, packet.data),
            destination,
        )
        return True

    def __enter__(self) -> Socks5Gateway:
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
