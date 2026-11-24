from __future__ import annotations

import hashlib
from pathlib import Path


def test_udpq_upstream_patch_is_pinned_and_redacts_all_client_secrets():
    patch_path = Path(__file__).parents[1] / "native/udpq/patches/redact-client-config-logs.patch"
    raw = patch_path.read_bytes()

    assert hashlib.sha256(raw).hexdigest() == (
        "6f18ca9871e62ad91db033411d0aaa801bde3b17533d4ce71e20ed33fe01bbe2"
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
