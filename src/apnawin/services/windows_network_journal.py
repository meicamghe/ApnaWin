"""Bounded, crash-conscious journal storage for future Windows network transactions.

This module does not apply routes, change DNS, or provide privilege isolation.
The containing directory must be protected by an explicit Windows ACL before use
by a privileged helper.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

_MAX_FILE_BYTES = 1024 * 1024
_MAX_MUTATIONS = 256
_MAX_STATE_BYTES = 32 * 1024


class JournalError(ValueError):
    """Journal data is invalid, corrupt, or cannot be safely persisted."""


class JournalPhase(str, Enum):
    PREPARED = "prepared"
    APPLYING = "applying"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLBACK_FAILED = "rollback_failed"
    ROLLED_BACK = "rolled_back"


class ResourceKind(str, Enum):
    ROUTE = "route"
    DNS = "dns"


def _reject_constant(value: str) -> None:
    raise JournalError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JournalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _state_json(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise JournalError(f"{field} must be a bounded JSON object")
    try:
        if len(value.encode("utf-8")) > _MAX_STATE_BYTES:
            raise JournalError(f"{field} must be a bounded JSON object")
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise JournalError(f"{field} must be valid bounded JSON") from exc
    if not isinstance(parsed, dict):
        raise JournalError(f"{field} must encode a JSON object")
    try:
        return json.dumps(
            parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise JournalError(f"{field} contains unsupported JSON values") from exc


@dataclass(frozen=True, slots=True)
class JournalMutation:
    """One exact resource change, with snapshots and explicit apply progress."""

    kind: ResourceKind
    resource_key: str
    before_json: str
    after_json: str
    applied: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ResourceKind):
            raise JournalError("mutation kind is invalid")
        if (
            not isinstance(self.resource_key, str)
            or not self.resource_key
            or len(self.resource_key) > 512
            or any(ord(char) < 32 for char in self.resource_key)
        ):
            raise JournalError("resource_key must be a bounded printable identifier")
        object.__setattr__(self, "before_json", _state_json(self.before_json, "before_json"))
        object.__setattr__(self, "after_json", _state_json(self.after_json, "after_json"))
        if not isinstance(self.applied, bool):
            raise JournalError("applied must be a boolean")

    @classmethod
    def from_states(
        cls,
        kind: ResourceKind,
        resource_key: str,
        before: dict[str, Any],
        after: dict[str, Any],
        *,
        applied: bool = False,
    ) -> "JournalMutation":
        try:
            before_json = json.dumps(before, ensure_ascii=False, allow_nan=False)
            after_json = json.dumps(after, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise JournalError("mutation snapshots must contain JSON values") from exc
        return cls(kind, resource_key, before_json, after_json, applied)


@dataclass(frozen=True, slots=True)
class WindowsNetworkJournal:
    """Immutable transaction record; every revision is a complete snapshot."""

    transaction_id: str
    revision: int
    phase: JournalPhase
    mutations: tuple[JournalMutation, ...]

    def __post_init__(self) -> None:
        try:
            parsed_id = UUID(self.transaction_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise JournalError("transaction_id must be a UUID") from exc
        if str(parsed_id) != self.transaction_id.lower():
            raise JournalError("transaction_id must use canonical UUID notation")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 1
        ):
            raise JournalError("revision must be a positive integer")
        if not isinstance(self.phase, JournalPhase):
            raise JournalError("phase is invalid")
        if (
            not isinstance(self.mutations, tuple)
            or not 1 <= len(self.mutations) <= _MAX_MUTATIONS
        ):
            raise JournalError(f"mutations must contain 1 to {_MAX_MUTATIONS} entries")
        if any(not isinstance(item, JournalMutation) for item in self.mutations):
            raise JournalError("mutations must contain JournalMutation values")
        keys = [(item.kind, item.resource_key) for item in self.mutations]
        if len(set(keys)) != len(keys):
            raise JournalError("mutation resource identities must be unique")


def _document(journal: WindowsNetworkJournal) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "transaction_id": journal.transaction_id,
        "revision": journal.revision,
        "phase": journal.phase.value,
        "mutations": [
            {
                "kind": item.kind.value,
                "resource_key": item.resource_key,
                "before": json.loads(item.before_json),
                "after": json.loads(item.after_json),
                "applied": item.applied,
            }
            for item in journal.mutations
        ],
    }


def _parse_document(data: bytes) -> WindowsNetworkJournal:
    if not data or len(data) > _MAX_FILE_BYTES:
        raise JournalError("journal file is empty or exceeds the size limit")
    try:
        raw = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise JournalError("journal file is not valid bounded UTF-8 JSON") from exc
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version", "transaction_id", "revision", "phase", "mutations"
    }:
        raise JournalError("journal document has an unexpected schema")
    if raw["schema_version"] != 1 or isinstance(raw["schema_version"], bool):
        raise JournalError("unsupported journal schema version")
    if not isinstance(raw["mutations"], list) or len(raw["mutations"]) > _MAX_MUTATIONS:
        raise JournalError("journal mutation list is invalid")
    mutations: list[JournalMutation] = []
    for item in raw["mutations"]:
        if not isinstance(item, dict) or set(item) != {
            "kind", "resource_key", "before", "after", "applied"
        }:
            raise JournalError("journal mutation has an unexpected schema")
        if not isinstance(item["before"], dict) or not isinstance(item["after"], dict):
            raise JournalError("journal snapshots must be objects")
        try:
            kind = ResourceKind(item["kind"])
        except (ValueError, TypeError) as exc:
            raise JournalError("journal mutation kind is invalid") from exc
        mutations.append(
            JournalMutation.from_states(
                kind,
                item["resource_key"],
                item["before"],
                item["after"],
                applied=item["applied"],
            )
        )
    try:
        return WindowsNetworkJournal(
            transaction_id=raw["transaction_id"],
            revision=raw["revision"],
            phase=JournalPhase(raw["phase"]),
            mutations=tuple(mutations),
        )
    except (ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, JournalError):
            raise
        raise JournalError("journal fields are invalid") from exc


class WindowsNetworkJournalStore:
    """Atomic single-file journal store; caller serializes concurrent writers."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def save(self, journal: WindowsNetworkJournal) -> None:
        if not isinstance(journal, WindowsNetworkJournal):
            raise TypeError("journal must be a WindowsNetworkJournal")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise JournalError("journal directory could not be prepared") from exc
        payload = json.dumps(
            _document(journal), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(payload) > _MAX_FILE_BYTES:
            raise JournalError("serialized journal exceeds the size limit")

        descriptor = -1
        temporary_path: str | None = None
        try:
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
            )
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
            if os.name != "nt":
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except OSError as exc:
            raise JournalError("atomic journal persistence failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    def load(self) -> WindowsNetworkJournal:
        try:
            with self.path.open("rb") as stream:
                data = stream.read(_MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise JournalError("journal could not be read") from exc
        return _parse_document(data)

    def delete(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise JournalError("journal could not be deleted") from exc
