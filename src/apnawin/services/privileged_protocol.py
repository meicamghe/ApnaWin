"""Strict, platform-neutral request-envelope validation for the future local helper.

This module parses data only. It opens no IPC endpoint and performs no privileged
operation; operation-specific argument schemas remain the helper's responsibility.
"""
from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass
from typing import Any


MAX_REQUEST_BYTES = 64 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4096
MAX_OBJECT_MEMBERS = 128
MAX_ARRAY_ITEMS = 1024
MAX_STRING_LENGTH = 8192
MAX_INTEGER_BITS = 256
PROTOCOL_VERSION = 1

ALLOWED_OPERATIONS = frozenset(
    {
        "snapshot_network",
        "create_owned_adapter",
        "configure_owned_adapter",
        "add_owned_route",
        "set_interface_dns",
        "restore_interface_dns",
        "remove_owned_route",
        "remove_owned_adapter",
        "query_transaction",
    }
)

_ENVELOPE_FIELDS = frozenset(
    {"version", "request_id", "transaction_id", "operation", "arguments"}
)


class PrivilegedRequestError(ValueError):
    """A request envelope is malformed, unsupported, or exceeds safe bounds."""


@dataclass(frozen=True, slots=True)
class PrivilegedRequest:
    """Validated request envelope; arguments are not yet operation-validated."""

    version: int
    request_id: uuid.UUID
    transaction_id: uuid.UUID
    operation: str
    arguments: dict[str, Any]


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrivilegedRequestError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise PrivilegedRequestError(f"non-JSON numeric constant is not allowed: {value}")


def _validate_tree(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise PrivilegedRequestError("request contains too many JSON values")
        if depth > MAX_JSON_DEPTH:
            raise PrivilegedRequestError("request JSON nesting is too deep")
        if isinstance(item, str):
            if len(item) > MAX_STRING_LENGTH:
                raise PrivilegedRequestError("request string exceeds its size limit")
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise PrivilegedRequestError("request string contains invalid Unicode")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise PrivilegedRequestError("request contains a non-finite number")
        elif isinstance(item, int) and not isinstance(item, bool):
            if item.bit_length() > MAX_INTEGER_BITS:
                raise PrivilegedRequestError("request integer exceeds its numeric size limit")
        elif isinstance(item, dict):
            if len(item) > MAX_OBJECT_MEMBERS:
                raise PrivilegedRequestError("request object has too many members")
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or len(key) > 128
                    or any(0xD800 <= ord(char) <= 0xDFFF for char in key)
                ):
                    raise PrivilegedRequestError("request object key is invalid or too long")
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > MAX_ARRAY_ITEMS:
                raise PrivilegedRequestError("request array has too many items")
            for child in item:
                visit(child, depth + 1)
        elif item is None or isinstance(item, (bool, int)):
            return
        else:
            raise PrivilegedRequestError("request contains an unsupported JSON value")

    visit(value, 0)


def _parse_uuid(value: Any, field: str) -> uuid.UUID:
    if not isinstance(value, str):
        raise PrivilegedRequestError(f"{field} must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise PrivilegedRequestError(f"{field} must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise PrivilegedRequestError(f"{field} must use lowercase canonical UUID form")
    return parsed


def decode_privileged_request(payload: bytes) -> PrivilegedRequest:
    """Decode a bounded UTF-8 JSON envelope without accepting ambiguous input.

    The returned arguments object is structurally bounded but deliberately not
    operation-validated. A service must validate each operation's exact schema
    before making any OS call.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise PrivilegedRequestError("request size is empty or exceeds 64 KiB")
    try:
        text = payload.decode("utf-8", errors="strict")
        raw = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except PrivilegedRequestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PrivilegedRequestError("request is not valid bounded UTF-8 JSON") from exc

    _validate_tree(raw)
    if not isinstance(raw, dict):
        raise PrivilegedRequestError("request envelope must be a JSON object")
    if set(raw) != _ENVELOPE_FIELDS:
        raise PrivilegedRequestError("request envelope fields do not match protocol version 1")
    version = raw["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise PrivilegedRequestError("unsupported request protocol version")
    operation = raw["operation"]
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise PrivilegedRequestError("unknown or unsupported helper operation")
    arguments = raw["arguments"]
    if not isinstance(arguments, dict):
        raise PrivilegedRequestError("operation arguments must be a JSON object")

    return PrivilegedRequest(
        version=version,
        request_id=_parse_uuid(raw["request_id"], "request_id"),
        transaction_id=_parse_uuid(raw["transaction_id"], "transaction_id"),
        operation=operation,
        arguments=arguments,
    )
