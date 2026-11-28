"""Transactional import of Xray share links into profiles and encrypted configs."""
from __future__ import annotations

from collections.abc import Callable, Sequence

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.proxy_share_link import parse_proxy_links
from apnawin.services.xray_tun_config import serialize_tun_config


class ProxyProfileImportError(RuntimeError):
    """A batch import failed; cleanup_errors lists encrypted-record rollback failures."""

    def __init__(self, message: str, *, cleanup_errors: tuple[Exception, ...] = ()) -> None:
        super().__init__(message)
        self.cleanup_errors = cleanup_errors


def import_proxy_profiles(
    document: str | bytes,
    existing_profiles: Sequence[ConnectionProfile],
    config_store,
    save_profiles: Callable[[list[ConnectionProfile]], object],
) -> list[ConnectionProfile]:
    """Parse a complete batch, encrypt all configs, then atomically save metadata.

    The caller supplies the existing profile writer (normally save_profiles()).
    On a failure, every encrypted record created by this batch is removed. A
    cleanup failure is surfaced and never hidden behind the original exception.
    """
    parsed = parse_proxy_links(document)
    current = list(existing_profiles)
    existing_names = {profile.name.casefold() for profile in current}
    imported_names: set[str] = set()
    new_profiles: list[ConnectionProfile] = []
    records: list[tuple[ConnectionProfile, bytes]] = []

    for item in parsed:
        folded = item.name.casefold()
        if folded in existing_names or folded in imported_names:
            raise ValueError(f"Profile name collision in share-link import: {item.name}")
        profile = ConnectionProfile(
            name=item.name,
            transport=Transport.XRAY,
            endpoint_host=item.server,
            endpoint_port=item.port,
        )
        if config_store.has_config(profile.name):
            raise ValueError(
                f"An encrypted Xray config already exists for profile: {profile.name}"
            )
        new_profiles.append(profile)
        records.append((profile, serialize_tun_config(item)))
        imported_names.add(folded)

    attempted: list[str] = []
    try:
        for profile, config in records:
            # Include the current record before calling save: a storage backend
            # may raise after an atomic replace has already committed its file.
            attempted.append(profile.name)
            config_store.save(profile.name, config)
        save_profiles([*current, *new_profiles])
    except Exception as exc:
        cleanup_errors: list[Exception] = []
        for name in reversed(attempted):
            try:
                config_store.remove(name)
            except Exception as cleanup_exc:
                cleanup_errors.append(cleanup_exc)
        if cleanup_errors:
            raise ProxyProfileImportError(
                "Share-link import failed and encrypted-config cleanup was incomplete",
                cleanup_errors=tuple(cleanup_errors),
            ) from exc
        raise ProxyProfileImportError(
            "Share-link import failed; no new profile batch was committed"
        ) from exc

    return new_profiles
