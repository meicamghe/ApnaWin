"""Atomic local cache for validated, non-secret remote catalog documents.

The cache preserves the last known-good document. Loading it never implies that
its freshness window is still valid; callers must check RemoteCatalog.is_fresh.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from apnawin.domain.remote_catalog import (
    MAX_REMOTE_CATALOG_BYTES,
    RemoteCatalog,
    parse_remote_catalog,
)


class RemoteCatalogStore:
    """Persist and reload a strictly validated normalized catalog document."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def save(self, document: str | bytes) -> RemoteCatalog:
        """Validate before touching disk, then atomically replace the cache."""
        catalog = parse_remote_catalog(document)
        serialized = document.encode("utf-8") if isinstance(document, str) else document
        if len(serialized) > MAX_REMOTE_CATALOG_BYTES:
            # Keep this guard local as well as relying on the parser contract.
            raise ValueError("Remote catalog exceeds the document-size limit")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return catalog

    def load(self) -> RemoteCatalog | None:
        """Load and revalidate the cache; return None only when it is absent."""
        try:
            with self.path.open("rb") as stream:
                document = stream.read(MAX_REMOTE_CATALOG_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(document) > MAX_REMOTE_CATALOG_BYTES:
            raise ValueError("Cached remote catalog exceeds the document-size limit")
        return parse_remote_catalog(document)
