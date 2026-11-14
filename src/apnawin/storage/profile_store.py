"""JSON persistence for connection profiles.

Only non-secret connection metadata is stored. Credentials and private keys must
be handled by a dedicated secure store and must never be added to this format.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable

from apnawin.domain.profile import ConnectionProfile, Transport


_FORMAT_VERSION = 1
_REQUIRED_KEYS = {"name", "transport", "endpoint_host", "endpoint_port"}


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def save_profiles(path: str | Path, profiles: Iterable[ConnectionProfile]) -> None:
    """Atomically save profiles as UTF-8 JSON using a unique same-directory temp file."""
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

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def load_profiles(path: str | Path) -> list[ConnectionProfile]:
    """Load profiles, rejecting unknown versions, duplicate keys and malformed records."""
    source = Path(path)
    try:
        payload = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid profile JSON: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Profile document must be a JSON object")
    version = payload.get("format_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != _FORMAT_VERSION:
        raise ValueError("Unsupported profile format version")
    if set(payload) != {"format_version", "profiles"}:
        raise ValueError("Profile document has an invalid schema")

    records = payload.get("profiles")
    if not isinstance(records, list):
        raise ValueError("'profiles' must be a JSON array")

    profiles: list[ConnectionProfile] = []
    seen_names: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _REQUIRED_KEYS:
            raise ValueError(f"Profile at index {index} has an invalid schema")
        try:
            if not isinstance(record["name"], str):
                raise ValueError("name must be a string")
            if not isinstance(record["endpoint_host"], str):
                raise ValueError("endpoint_host must be a string")
            if not isinstance(record["transport"], str):
                raise ValueError("transport must be a string")
            port = record["endpoint_port"]
            if isinstance(port, bool) or not isinstance(port, int):
                raise ValueError("endpoint_port must be an integer")
            profile = ConnectionProfile(
                name=record["name"],
                transport=Transport(record["transport"]),
                endpoint_host=record["endpoint_host"],
                endpoint_port=port,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid profile at index {index}: {exc}") from exc

        normalized_name = profile.name.casefold()
        if normalized_name in seen_names:
            raise ValueError(f"Duplicate profile name at index {index}")
        seen_names.add(normalized_name)
        profiles.append(profile)

    return profiles
