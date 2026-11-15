import os

import pytest

from apnawin.storage.xray_config_store import dpapi_protect, dpapi_unprotect


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI integration test")
def test_current_user_dpapi_round_trip():
    plaintext = b"ApnaWin DPAPI round-trip test; never a real credential"
    ciphertext = dpapi_protect(plaintext)
    assert ciphertext
    assert ciphertext != plaintext
    assert dpapi_unprotect(ciphertext) == plaintext


@pytest.mark.skipif(os.name == "nt", reason="DPAPI is Windows-only")
def test_dpapi_rejects_non_windows_runtime():
    with pytest.raises(OSError, match="Windows DPAPI"):
        dpapi_protect(b"test")
