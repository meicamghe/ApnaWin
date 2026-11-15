"""Pure builders for explicit service-owned Windows object DACLs.

SIDs must come from the installed service configuration and an authenticated
client token. Never pass client-supplied SID strings to these functions.
"""
from __future__ import annotations

import re


_SERVICE_SID = re.compile(
    r"S-1-5-80-(?:0|[1-9][0-9]{0,9})-(?:0|[1-9][0-9]{0,9})-"
    r"(?:0|[1-9][0-9]{0,9})-(?:0|[1-9][0-9]{0,9})-"
    r"(?:0|[1-9][0-9]{0,9})"
)
# A user/account SID has the domain identifier plus a terminal RID. Requiring
# at least four subauthorities after the identifier authority rejects a bare
# domain SID and truncated values.
_ACCOUNT_SID = re.compile(
    r"S-1-5-(?:0|[1-9][0-9]{0,9})"
    r"(?:-(?:0|[1-9][0-9]{0,9})){3,14}"
)
_SYSTEM_SID = "S-1-5-18"


def _validate_sid(value: str, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{field} must be a canonical Windows SID")
    if any(int(part) > 0xFFFFFFFF for part in value.split("-")[2:]):
        raise ValueError(f"{field} contains an out-of-range SID subauthority")
    return value


def build_service_mutex_sddl(service_sid: str) -> str:
    """Grant full mutex control only to SYSTEM and the installed service SID."""
    service_sid = _validate_sid(service_sid, _SERVICE_SID, "service_sid")
    return f"D:P(A;;GA;;;{_SYSTEM_SID})(A;;GA;;;{service_sid})"


def build_local_pipe_sddl(service_sid: str, client_sid: str) -> str:
    """Grant service/SYSTEM full access and one authenticated client read/write."""
    if isinstance(client_sid, str) and client_sid in {_SYSTEM_SID, service_sid}:
        raise ValueError("client_sid must identify a distinct interactive account")
    service_sid = _validate_sid(service_sid, _SERVICE_SID, "service_sid")
    client_sid = _validate_sid(client_sid, _ACCOUNT_SID, "client_sid")
    return (
        f"D:P(A;;GA;;;{_SYSTEM_SID})"
        f"(A;;GA;;;{service_sid})"
        f"(A;;GRGW;;;{client_sid})"
    )
