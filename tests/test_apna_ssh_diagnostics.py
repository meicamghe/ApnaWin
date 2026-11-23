from __future__ import annotations

from types import SimpleNamespace

import paramiko
import pytest
from paramiko.message import Message

from apnawin.engines.apna_ssh_diagnostics import (
    ApnaDiagnosticTransport,
    _read_server_cipher_proposals,
)


def _kex_init_message() -> Message:
    message = Message()
    message.add_bytes(b"\x00" * 16)
    message.add_list(["curve25519-sha256"])
    message.add_list(["ssh-ed25519"])
    message.add_list(["aes128-cbc"])
    message.add_list(["3des-cbc"])
    message.add_list(["hmac-sha2-256"])
    message.add_list(["hmac-sha1"])
    message.add_list(["none"])
    message.add_list(["none"])
    message.add_string(b"")
    message.add_string(b"")
    message.add_boolean(False)
    message.add_int(0)
    return message


def test_reads_both_directional_server_cipher_proposals():
    assert _read_server_cipher_proposals(_kex_init_message()) == (
        ("aes128-cbc",),
        ("3des-cbc",),
    )


def test_diagnostic_transport_reports_peer_ciphers_without_changing_policy(monkeypatch):
    def reject_negotiation(_self, _message):
        raise paramiko.SSHException("Incompatible ssh server (no acceptable ciphers)")

    monkeypatch.setattr(paramiko.Transport, "_parse_kex_init", reject_negotiation)

    class TestTransport(ApnaDiagnosticTransport):
        def get_security_options(self):
            return SimpleNamespace(ciphers=("aes128-ctr", "aes256-ctr"))

    transport = object.__new__(TestTransport)
    with pytest.raises(paramiko.SSHException, match="no acceptable ciphers") as error:
        TestTransport._parse_kex_init(transport, _kex_init_message())

    detail = str(error.value)
    assert "client->server=[aes128-cbc]" in detail
    assert "server->client=[3des-cbc]" in detail
    assert "client enabled=[aes128-ctr, aes256-ctr]" in detail
