import ssl

import pytest

from apnawin.services.windows_tunnel_egress import (
    TARGETS,
    TunnelEgressError,
    probe_tun_egress,
)


def test_egress_probe_accepts_first_verified_tls_endpoint():
    observed = []
    target = probe_tun_egress(probe=lambda candidate: observed.append(candidate) or True)
    assert target == TARGETS[0]
    assert observed == [TARGETS[0]]


def test_egress_probe_falls_back_to_second_endpoint():
    observed = []

    def check(candidate):
        observed.append(candidate)
        return candidate == TARGETS[1]

    assert probe_tun_egress(probe=check) == TARGETS[1]
    assert observed == list(TARGETS)


def test_egress_probe_fails_closed_when_all_endpoints_fail():
    def fail(_candidate):
        raise OSError("unreachable")

    with pytest.raises(TunnelEgressError, match="through the VPN TUN"):
        probe_tun_egress(probe=fail)


def test_egress_probe_fails_closed_when_endpoints_do_not_complete_tls():
    with pytest.raises(TunnelEgressError):
        probe_tun_egress(probe=lambda _candidate: False)


def test_egress_probe_targets_are_fixed_ip_tls_identities():
    assert all(target.port == 443 for target in TARGETS)
    assert all(target.address and target.server_name for target in TARGETS)
