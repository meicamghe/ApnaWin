"""JSON persistence for connection profiles.

Only non-secret connection metadata is stored. Credentials and private keys must
be handled by a dedicated secure store and must never be added to this format.
"""

import json
from pathlib import Path
from typing import Iterable

from apnawin.domain.profile import ConnectionProfile, Transport


_FORMAT_VERSION = 1
_REQUIRED_KEYS = {"name", "transport", "endpoint_host", "endpoint_port"}


def save_profiles(path: str | Path, profiles: Iterable[ConnectionProfile]) -> None:
    """Atomically save profiles as UTF-8 JSON."""
    destination = Path(path)
    items = []
    for profile in profiles:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profiles must contain only ConnectionProfile objects")
        items.append(
            {
                "name": profile.name,
                "transport": profile.transport.value,
                "endpoint_host": profile.endpoint_host,
                "endpoint_port": profile.endpoint_port,
            }
        )

    payload = {"format_version": _FORMAT_VERSION, "profiles": items}
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_profiles(path: str | Path) -> list[ConnectionProfile]:
    """Load profiles, rejecting unknown versions and malformed records."""
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid profile JSON: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Profile document must be a JSON object")
    if payload.get("format_version") != _FORMAT_VERSION:
        raise ValueError("Unsupported profile format version")

    records = payload.get("profiles")
    if not isinstance(records, list):
        raise ValueError("'profiles' must be a JSON array")

    profiles: list[ConnectionProfile] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _REQUIRED_KEYS:
            raise ValueError(f"Profile at index {index} has an invalid schema")
        try:
            transport = Transport(record["transport"])
            port = record["endpoint_port"]
            if isinstance(port, bool) or not isinstance(port, int):
                raise ValueError("endpoint_port must be an integer")
            profile = ConnectionProfile(
                name=record["name"],
                transport=transport,
                endpoint_host=record["endpoint_host"],
                endpoint_port=port,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid profile at index {index}: {exc}") from exc
        profiles.append(profile)

    return profiles
