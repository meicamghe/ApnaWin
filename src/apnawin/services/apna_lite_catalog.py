"""Decoder and validator for the APNA TUNNEL LITE embedded catalog format.

The upstream catalog is obfuscated with Base64 + a modified XXTEA envelope.
XXTEA does not authenticate the document: decoded fields remain untrusted.
The returned mapping can contain account credentials; never log or persist it
without an explicitly reviewed secret-storage design.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import struct
from typing import Any

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RECORDS_PER_SECTION = 10_000
MAX_JSON_NODES = 200_000
MAX_JSON_DEPTH = 64
MAX_STRING_CHARS = 1_000_000
DELTA = 0x9E5729B1
MASK = 0xFFFFFFFF

# Fixed catalog-format constant recovered from the published decoder and
# independently verified against the supplied APNA TUNNEL LITE v51 APK asset.
_CATALOG_KEY = b"...|..."

_SERVER_FIELDS = frozenset(
    {
        "server_name",
        "server_host",
        "server_port",
        "server_udp_port",
        "ssl_port",
        "category",
        "username",
        "password",
        "custom_cert",
    }
)
_PAYLOAD_FIELDS = frozenset(
    {
        "friendly_name",
        "category",
        "host",
        "port",
        "method",
        "payload",
        "query",
        "sslws",
        "sausage",
        "dothost",
        "message",
    }
)
_SERVER_SECTIONS = (
    "Free_servers",
    "Premium_servers",
    "Vip_servers",
    "Private_servers",
)


class ApnaLiteCatalogError(ValueError):
    """Invalid, oversized, or unsupported APNA TUNNEL LITE catalog."""


def _words(raw: bytes) -> list[int]:
    if not raw:
        return []
    padded = raw.ljust((len(raw) + 3) // 4 * 4, b"\0")
    return list(struct.unpack("<" + "I" * (len(padded) // 4), padded))


def _mx(total: int, y: int, z: int, index: int, e: int, key: list[int]) -> int:
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (key[(index & 3) ^ e] ^ z))
    ) & MASK


def _decrypt_xxtea(ciphertext: bytes) -> bytes:
    if len(ciphertext) < 8 or len(ciphertext) % 4:
        raise ApnaLiteCatalogError("Invalid encrypted catalog length")

    values = _words(ciphertext)
    key = _words(_CATALOG_KEY.ljust(16, b"\0"))
    if len(values) < 2 or len(key) != 4:
        raise ApnaLiteCatalogError("Invalid encrypted catalog")

    end = len(values) - 1
    total = ((6 + 52 // len(values)) * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for index in range(end, 0, -1):
            z = values[index - 1]
            values[index] = (
                values[index] - _mx(total, y, z, index, e, key)
            ) & MASK
            y = values[index]
        z = values[end]
        values[0] = (values[0] - _mx(total, y, z, 0, e, key)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK

    output_size = (len(values) - 1) * 4
    plaintext_size = values[-1]
    if not output_size - 3 <= plaintext_size <= output_size:
        raise ApnaLiteCatalogError("Invalid decrypted catalog length")
    return struct.pack("<" + "I" * len(values), *values)[:plaintext_size]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApnaLiteCatalogError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ApnaLiteCatalogError(f"Invalid JSON constant: {value}")


def _check_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ApnaLiteCatalogError("Catalog JSON nesting is too deep")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ApnaLiteCatalogError("Malformed catalog JSON")


def _validate_tree(document: dict[str, Any]) -> None:
    pending: list[tuple[Any, int]] = [(document, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ApnaLiteCatalogError("Catalog structure exceeds limits")
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str) or len(key) > MAX_STRING_CHARS:
                    raise ApnaLiteCatalogError("Invalid catalog field name")
                pending.append((item, depth + 1))
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            if len(value) > MAX_STRING_CHARS:
                raise ApnaLiteCatalogError("Catalog string exceeds limit")
        elif isinstance(value, float):
            # parse_constant rejects NaN/Infinity; finite floats are allowed
            # only as generic JSON values, not in the known provider records.
            pass
        elif value is not None and not isinstance(value, (bool, int)):
            raise ApnaLiteCatalogError("Unsupported catalog value")


def _validate_records(
    document: dict[str, Any], section: str, required_fields: frozenset[str] | None
) -> None:
    records = document.get(section)
    if not isinstance(records, list):
        raise ApnaLiteCatalogError(f"{section} must be an array")
    if len(records) > MAX_RECORDS_PER_SECTION:
        raise ApnaLiteCatalogError(f"{section} exceeds the record limit")
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ApnaLiteCatalogError(f"{section}[{index}] must be an object")
        if required_fields is not None:
            missing = required_fields.difference(record)
            if missing:
                raise ApnaLiteCatalogError(f"{section}[{index}] is missing required fields")
            if any(not isinstance(record[field], str) for field in required_fields):
                raise ApnaLiteCatalogError(f"{section}[{index}] has invalid field types")


def decode_apna_lite_catalog(encrypted: bytes) -> dict[str, Any]:
    """Decode and validate a complete encrypted catalog.

    The returned document may include top-level Username/Password and
    per-server credentials. Callers must treat the result as secret-bearing
    data and must not log it, serialize it to diagnostics, or put it in tests.
    """
    if not isinstance(encrypted, bytes):
        raise TypeError("encrypted catalog must be bytes")
    if not encrypted or len(encrypted) > MAX_INPUT_BYTES:
        raise ApnaLiteCatalogError("Encrypted catalog size is invalid")

    normalized = re.sub(rb"\s+", b"", encrypted)
    if not normalized or len(normalized) > MAX_INPUT_BYTES:
        raise ApnaLiteCatalogError("Base64 catalog size is invalid")
    try:
        ciphertext = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApnaLiteCatalogError("Invalid Base64 catalog") from exc

    plaintext = _decrypt_xxtea(ciphertext)
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApnaLiteCatalogError("Decrypted catalog is not UTF-8") from exc

    _check_depth(text)
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ApnaLiteCatalogError("Decrypted catalog is not valid JSON") from exc

    if not isinstance(document, dict):
        raise ApnaLiteCatalogError("Catalog root must be an object")
    _validate_tree(document)

    version = document.get("Version")
    if not isinstance(version, str) or not version or len(version) > 64:
        raise ApnaLiteCatalogError("Catalog Version is invalid")

    _validate_records(document, "Free_servers", _SERVER_FIELDS)
    _validate_records(document, "Payloads", _PAYLOAD_FIELDS)
    for section in _SERVER_SECTIONS[1:]:
        if section in document:
            _validate_records(document, section, _SERVER_FIELDS)

    for field in ("Username", "Password"):
        if field in document and not isinstance(document[field], str):
            raise ApnaLiteCatalogError(f"{field} must be a string")

    return document


def summarize_apna_lite_catalog(document: dict[str, Any]) -> dict[str, int | str]:
    """Return safe metadata only; never include catalog credentials or payloads."""
    if not isinstance(document, dict):
        raise TypeError("document must be a dictionary")
    return {
        "version": str(document.get("Version", "")),
        "free_servers": len(document.get("Free_servers", [])),
        "premium_servers": len(document.get("Premium_servers", [])),
        "vip_servers": len(document.get("Vip_servers", [])),
        "private_servers": len(document.get("Private_servers", [])),
        "payloads": len(document.get("Payloads", [])),
    }
