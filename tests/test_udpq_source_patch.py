from __future__ import annotations

import hashlib
from pathlib import Path


def test_udpq_upstream_patch_is_pinned_and_redacts_all_client_secrets():
    patch_path = Path(__file__).parents[1] / "native/udpq/patches/redact-client-config-logs.patch"
    raw = patch_path.read_bytes()

    assert hashlib.sha256(raw).hexdigest() == (
        "82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52"
    )
    patch = raw.decode("utf-8")
    for field in (
        "redacted.Auth = nil",
        'redacted.AuthString = ""',
        'redacted.Obfs = ""',
        'redacted.SOCKS5.User = ""',
        'redacted.SOCKS5.Password = ""',
        'redacted.HTTP.User = ""',
        'redacted.HTTP.Password = ""',
    ):
        assert field in patch
