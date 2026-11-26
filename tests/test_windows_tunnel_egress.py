import ssl

import pytest

from apnawin.services.windows_tunnel_egress import (
    IPV4_TARGETS,
    IPV6_TARGETS,
    TARGETS,
    TunnelEgressError,
    probe_tun_egress,
)


def test_egress_probe_requires_verified_tls_for_both_ip_families():
    observed = []
    targets = probe_tun_egress(probe=lambda candidate: observed.append(candidate) or True)
    assert targets == (IPV4_TARGETS[0], IPV6_TARGETS[0])
    assert observed == [IPV4_TARGETS[0], IPV6_TARGETS[0]]


def test_egress_probe_falls_back_independently_for_each_family():
    observed = []

    def check(candidate):
        observed.append(candidate)
        return candidate in {IPV4_TARGETS[1], IPV6_TARGETS[1]}

    assert probe_tun_egress(probe=check) == (IPV4_TARGETS[1], IPV6_TARGETS[1])
    assert observed == [*IPV4_TARGETS, *IPV6_TARGETS]


def test_egress_probe_fails_closed_when_ipv4_is_unavailable():
    def check(candidate):
        return candidate.ip_version == 6

    with pytest.raises(TunnelEgressError, match="IPv4"):
        probe_tun_egress(probe=check)


def test_egress_probe_fails_closed_when_ipv6_is_unavailable():
    def check(candidate):
        return candidate.ip_version == 4

    with pytest.raises(TunnelEgressError, match="IPv6"):
        probe_tun_egress(probe=check)


def test_egress_probe_fails_closed_when_endpoints_do_not_complete_tls():
    with pytest.raises(TunnelEgressError, match="IPv4"):
        probe_tun_egress(probe=lambda _candidate: False)


def test_egress_probe_targets_are_fixed_ip_tls_identities():
    assert all(target.port == 443 for target in TARGETS)
    assert all(target.address and target.server_name for target in TARGETS)
    assert {target.ip_version for target in IPV4_TARGETS} == {4}
    assert {target.ip_version for target in IPV6_TARGETS} == {6}
