import os

import pytest

from apnawin.services.windows_tunnel_diagnostics import WindowsTunnelDiagnostics


pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows PowerShell test")


def test_powershell_tunnel_diagnostics_executes_on_native_windows():
    snapshot = WindowsTunnelDiagnostics(timeout=10).snapshot()
    assert isinstance(snapshot.adapter_present, bool)
    assert isinstance(snapshot.adapter_status, str)
    assert isinstance(snapshot.ipv4_default_route, bool)
    assert isinstance(snapshot.ipv6_default_route, bool)
    assert isinstance(snapshot.dns_servers, tuple)
    if snapshot.adapter_present:
        assert snapshot.interface_index is not None
