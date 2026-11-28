import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.proxy_profile_import import (
    ProxyProfileImportError,
    import_proxy_profiles,
)


class FakeConfigStore:
    def __init__(self):
        self.records = {}
        self.fail_on_save = None
        self.fail_on_remove = False

    def has_config(self, name):
        return name in self.records

    def save(self, name, payload):
        if self.fail_on_save == name:
            raise OSError("save failed")
        self.records[name] = payload

    def remove(self, name):
        if self.fail_on_remove:
            raise OSError("remove failed")
        self.records.pop(name, None)


def vless(name, host="vpn.example"):
    return f"vless://user@{host}:443?security=tls#{name}"


def test_import_batch_persists_profiles_and_encrypted_tun_configs():
    store = FakeConfigStore()
    saved = []
    existing = [ConnectionProfile("Existing", Transport.SOCKS, "127.0.0.1", 1080)]

    imported = import_proxy_profiles(
        vless("Office") + "\n" + vless("Backup", "backup.example"),
        existing,
        store,
        lambda profiles: saved.extend(profiles),
    )

    assert [profile.name for profile in imported] == ["Office", "Backup"]
    assert [profile.transport for profile in imported] == [Transport.XRAY, Transport.XRAY]
    assert [profile.endpoint_host for profile in imported] == ["vpn.example", "backup.example"]
    assert set(store.records) == {"Office", "Backup"}
    assert all(b'"protocol":"tun"' in value for value in store.records.values())
    assert [profile.name for profile in saved] == ["Existing", "Office", "Backup"]


def test_import_rejects_collisions_before_writing_any_config():
    store = FakeConfigStore()
    existing = [ConnectionProfile("Office", Transport.XRAY, "vpn.example", 443)]
    with pytest.raises(ValueError, match="collision"):
        import_proxy_profiles(vless("office"), existing, store, lambda _profiles: None)
    assert store.records == {}


def test_import_rolls_back_prior_encrypted_configs_when_later_save_fails():
    store = FakeConfigStore()
    store.fail_on_save = "Backup"
    with pytest.raises(ProxyProfileImportError, match="no new profile batch"):
        import_proxy_profiles(
            vless("Office") + "\n" + vless("Backup"),
            [],
            store,
            lambda _profiles: pytest.fail("metadata must not be committed"),
        )
    assert store.records == {}


def test_import_rolls_back_encrypted_configs_when_profile_commit_fails():
    store = FakeConfigStore()
    with pytest.raises(ProxyProfileImportError, match="no new profile batch"):
        import_proxy_profiles(
            vless("Office"),
            [],
            store,
            lambda _profiles: (_ for _ in ()).throw(OSError("disk full")),
        )
    assert store.records == {}


def test_import_surfaces_failed_secret_record_cleanup():
    store = FakeConfigStore()
    store.fail_on_save = "Backup"
    store.fail_on_remove = True
    with pytest.raises(ProxyProfileImportError, match="cleanup was incomplete") as error:
        import_proxy_profiles(
            vless("Office") + "\n" + vless("Backup"),
            [],
            store,
            lambda _profiles: None,
        )
    assert len(error.value.cleanup_errors) == 1
    assert "Office" in store.records


def test_import_rejects_existing_orphaned_encrypted_config():
    store = FakeConfigStore()
    store.records["Office"] = b"existing"
    with pytest.raises(ValueError, match="already exists"):
        import_proxy_profiles(vless("Office"), [], store, lambda _profiles: None)
    assert store.records == {"Office": b"existing"}
