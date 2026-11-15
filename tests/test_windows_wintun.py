import hashlib
import ctypes
from types import SimpleNamespace

import pytest

from apnawin.engines import windows_wintun


def pe_x64_bytes():
    data = bytearray(128)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:70] = b"PE\0\0" + (0x8664).to_bytes(2, "little")
    return bytes(data)


def test_validate_dll_requires_pinned_hash_and_x64_image(tmp_path):
    path = tmp_path / "wintun.dll"
    content = pe_x64_bytes()
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    assert windows_wintun._validate_dll(path, digest) == path.resolve()
    with pytest.raises(windows_wintun.WintunNativeError, match="SHA-256"):
        windows_wintun._validate_dll(path, "0" * 64)


def test_validate_dll_rejects_non_pe_and_wrong_architecture(tmp_path):
    path = tmp_path / "wintun.dll"
    path.write_bytes(b"not a PE")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(windows_wintun.WintunNativeError, match="PE"):
        windows_wintun._validate_dll(path, digest)
    data = bytearray(pe_x64_bytes())
    data[68:70] = (0x14C).to_bytes(2, "little")
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    with pytest.raises(windows_wintun.WintunNativeError, match="x64"):
        windows_wintun._validate_dll(path, digest)


def test_validate_dll_rejects_symlink(tmp_path):
    target = tmp_path / "real.dll"
    target.write_bytes(pe_x64_bytes())
    link = tmp_path / "wintun.dll"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    with pytest.raises(windows_wintun.WintunNativeError, match="symbolic link"):
        windows_wintun._validate_dll(link, digest)


class FakeFunction:
    def __init__(self, callback=None):
        self.callback = callback
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        if self.callback:
            return self.callback(*args)
        return 1


def test_constructor_binds_all_required_exports_without_loading_path_search(monkeypatch, tmp_path):
    path = tmp_path / "wintun.dll"
    content = pe_x64_bytes()
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    exports = {name: FakeFunction() for name in (
        "WintunCreateAdapter", "WintunCloseAdapter", "WintunGetAdapterLUID",
        "WintunStartSession", "WintunEndSession", "WintunGetReadWaitEvent",
        "WintunReceivePacket", "WintunReleaseReceivePacket",
        "WintunAllocateSendPacket", "WintunSendPacket",
    )}
    fake_dll = SimpleNamespace(**exports)
    calls = []

    def fake_loader(filename, **kwargs):
        calls.append((filename, kwargs))
        return fake_dll

    monkeypatch.setattr(windows_wintun.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", fake_loader, raising=False)
    backend = windows_wintun.WindowsWintunBackend(path, expected_sha256=digest)
    assert backend.dll_path == path.resolve()
    assert calls[0][1]["winmode"] == (
        windows_wintun._LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
        | windows_wintun._LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
    )
    assert all(getattr(fake_dll, name).argtypes is not None for name in exports)


def test_constructor_rejects_missing_required_export(monkeypatch, tmp_path):
    path = tmp_path / "wintun.dll"
    content = pe_x64_bytes()
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    monkeypatch.setattr(windows_wintun.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: SimpleNamespace(), raising=False)
    with pytest.raises(windows_wintun.WintunNativeError, match="missing required export"):
        windows_wintun.WindowsWintunBackend(path, expected_sha256=digest)


def test_guid_parser_accepts_braced_and_unbraced_uuid():
    value = "{00000000-0000-0000-0000-000000000001}"
    assert isinstance(windows_wintun._guid(value), windows_wintun._GUID)
    assert isinstance(windows_wintun._guid(value.strip("{}")), windows_wintun._GUID)


@pytest.mark.parametrize("value", ["", "not-a-guid", None])
def test_guid_parser_rejects_invalid_uuid(value):
    with pytest.raises(ValueError, match="requested_guid"):
        windows_wintun._guid(value)
