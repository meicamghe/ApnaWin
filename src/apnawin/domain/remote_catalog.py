"""Strict, provider-neutral model for a normalized remote server catalog.

This is an internal interchange format. It is not an assertion about APNA's
upstream API, and it deliberately contains no connection credentials or
engine-specific connection parameters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

MAX_REMOTE_CATALOG_BYTES = 1 * 1024 * 1024
MAX_REMOTE_SERVERS = 500
MAX_JSON_NESTING_DEPTH = 32
MAX_IDENTIFIER_LENGTH = 128
MAX_DISPLAY_TEXT_LENGTH = 256


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _check_json_nesting_depth(text: str) -> None:
    """Reject excessive container nesting before invoking the recursive JSON decoder."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise ValueError(
                    f"Remote catalog exceeds JSON nesting depth {MAX_JSON_NESTING_DEPTH}"
                )
        elif char in "]}":
            depth -= 1


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ValueError(f"{field} must be a bounded ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _bounded_text(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise ValueError(f"{field} must contain 1 to {limit} characters")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in normalized):
        raise ValueError(f"{field} must not contain control characters")
    return normalized


@dataclass(frozen=True, slots=True)
class RemoteServer:
    """Non-secret catalog metadata; not sufficient to establish a connection."""

    server_id: str
    name: str
    region: str
    available: bool


@dataclass(frozen=True, slots=True)
class RemoteCatalog:
    """Validated normalized catalog with an explicit freshness window."""

    revision: str
    generated_at: datetime
    expires_at: datetime
    servers: tuple[RemoteServer, ...]

    def is_fresh(self, now: datetime | None = None) -> bool:
        """Return whether this catalog is within its declared validity window."""
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        current = current.astimezone(timezone.utc)
        return self.generated_at <= current < self.expires_at


def parse_remote_catalog(document: str | bytes) -> RemoteCatalog:
    """Parse the local normalized catalog format with strict size/schema checks."""
    if isinstance(document, bytes):
        if len(document) > MAX_REMOTE_CATALOG_BYTES:
            raise ValueError("Remote catalog exceeds the document-size limit")
        try:
            text = document.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Remote catalog must be valid UTF-8") from exc
    elif isinstance(document, str):
        try:
            encoded = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("Remote catalog must be valid UTF-8") from exc
        if len(encoded) > MAX_REMOTE_CATALOG_BYTES:
            raise ValueError("Remote catalog exceeds the document-size limit")
        text = document
    else:
        raise TypeError("document must be str or bytes")

    _check_json_nesting_depth(text)
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid remote catalog JSON: {exc.msg}") from exc
    except RecursionError as exc:
        # Defensive fallback if decoder behavior changes or a future parser bypasses
        # the lexical nesting check.
        raise ValueError("Remote catalog JSON nesting is too deep") from exc

    if not isinstance(payload, dict):
        raise ValueError("Remote catalog root must be an object")
    if set(payload) != {"format_version", "revision", "generated_at", "expires_at", "servers"}:
        raise ValueError("Remote catalog has an invalid schema")
    version = payload["format_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise ValueError("Unsupported remote catalog format version")

    revision = _bounded_text(payload["revision"], "revision", MAX_IDENTIFIER_LENGTH)
    generated_at = _parse_timestamp(payload["generated_at"], "generated_at")
    expires_at = _parse_timestamp(payload["expires_at"], "expires_at")
    if expires_at <= generated_at:
        raise ValueError("expires_at must be later than generated_at")

    records = payload["servers"]
    if not isinstance(records, list):
        raise ValueError("servers must be an array")
    if len(records) > MAX_REMOTE_SERVERS:
        raise ValueError(f"Remote catalog exceeds {MAX_REMOTE_SERVERS} servers")

    servers: list[RemoteServer] = []
    seen_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != {"id", "name", "region", "available"}:
            raise ValueError(f"Server at index {index} has an invalid schema")
        server_id = _bounded_text(record["id"], f"servers[{index}].id", MAX_IDENTIFIER_LENGTH)
        name = _bounded_text(record["name"], f"servers[{index}].name", MAX_DISPLAY_TEXT_LENGTH)
        region = _bounded_text(record["region"], f"servers[{index}].region", MAX_DISPLAY_TEXT_LENGTH)
        available = record["available"]
        if not isinstance(available, bool):
            raise ValueError(f"servers[{index}].available must be a boolean")
        normalized_id = server_id.casefold()
        if normalized_id in seen_ids:
            raise ValueError(f"Duplicate server id at index {index}")
        seen_ids.add(normalized_id)
        servers.append(RemoteServer(server_id, name, region, available))

    return RemoteCatalog(revision, generated_at, expires_at, tuple(servers))
