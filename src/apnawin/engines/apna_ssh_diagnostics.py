"""Safe diagnostics for SSH algorithm negotiation failures.

The transport records only public peer KEXINIT cipher proposals. It does not
enable additional algorithms or weaken Paramiko's negotiated security policy.
"""
from __future__ import annotations

import re

import paramiko
from paramiko.message import Message


def _read_server_cipher_proposals(message: Message) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the peer KEXINIT client->server and server->client cipher lists."""
    parsed = Message(message.asbytes())
    parsed.get_bytes(16)  # KEXINIT cookie
    parsed.get_list()  # key-exchange algorithms
    parsed.get_list()  # server host-key algorithms
    client_to_server = tuple(parsed.get_list())
    server_to_client = tuple(parsed.get_list())
    return client_to_server, server_to_client


def _format_algorithms(values: tuple[str, ...]) -> str:
    if not values or values == ("",):
        return "[none]"
    visible = values[:12]
    result = ", ".join(visible)
    if len(values) > len(visible):
        result += f", … (+{len(values) - len(visible)} more)"
    return f"[{result}]"


class ApnaDiagnosticTransport(paramiko.Transport):
    """Paramiko transport that adds peer cipher proposals to mismatch errors."""

    def _parse_kex_init(self, message) -> None:
        proposals = None
        try:
            proposals = _read_server_cipher_proposals(message)
        except Exception:
            # Preserve Paramiko's own parser and error if a future wire-format
            # change makes the diagnostic parser unable to read the proposal.
            proposals = None

        try:
            return super()._parse_kex_init(message)
        except paramiko.SSHException as exc:
            if proposals is None or "no acceptable ciphers" not in str(exc).lower():
                raise
            client_to_server, server_to_client = proposals
            try:
                enabled = tuple(self.get_security_options().ciphers)
            except Exception:
                enabled = ()
            suffix = (
                "; server cipher offers: "
                f"client->server={_format_algorithms(client_to_server)}; "
                f"server->client={_format_algorithms(server_to_client)}; "
                f"client enabled={_format_algorithms(enabled)}"
            )
            raise paramiko.SSHException(f"{exc}{suffix}") from exc


def cipher_diagnostic_suffix(error: BaseException) -> str:
    """Return bounded, public algorithm details appended by ApnaDiagnosticTransport."""
    text = " ".join(str(error).split())
    marker = "; server cipher offers:"
    index = text.lower().find(marker)
    if index < 0:
        return ""
    details = text[index + 2 : index + 900]
    # Report peer names this Paramiko build does not implement, without
    # adding aliases or weakening the negotiated cipher policy.
    try:
        supported = set(paramiko.Transport._preferred_ciphers)
        proposals = _read_server_cipher_proposals_from_error(details)
    except Exception:
        proposals = ()
        supported = set()
    unknown = tuple(dict.fromkeys(name for name in proposals if name not in supported))
    if unknown:
        details += (
            "; peer advertised cipher name(s) not recognized by this Paramiko build: "
            + _format_algorithms(unknown)
            + ". Do not guess an alias or weaken cipher policy"
        )
    return " " + details


def _read_server_cipher_proposals_from_error(details: str) -> tuple[str, ...]:
    """Extract cipher names from the two bounded diagnostic proposal lists."""
    match = re.search(
        r"client->server=\[([^]]*)\];\s*server->client=\[([^]]*)\]",
        details,
    )
    if match is None:
        return ()
    names = []
    for group in match.groups():
        names.extend(
            item.strip()
            for item in group.split(",")
            if item.strip() and not item.strip().startswith("…")
        )
    return tuple(names)
