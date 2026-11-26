from __future__ import annotations

import ipaddress

import pytest

from apnawin.engines.udpgw_flows import UdpGwFlowTable


def test_new_flow_gets_id_and_requires_rebind() -> None:
    table = UdpGwFlowTable(max_connections=4)
    lease = table.get_or_create(
        local_address="10.0.0.2",
        local_port=40000,
        remote_address="8.8.8.8",
        remote_port=53,
    )
    assert lease.connection_id == 1
    assert lease.rebind is True
    assert table.count == 1


def test_existing_flow_reuses_id_without_rebind_and_moves_to_mru() -> None:
    table = UdpGwFlowTable(max_connections=2)
    first = table.get_or_create(
        local_address="10.0.0.2",
        local_port=40000,
        remote_address="8.8.8.8",
        remote_port=53,
    )
    second = table.get_or_create(
        local_address="10.0.0.2",
        local_port=40001,
        remote_address="1.1.1.1",
        remote_port=53,
    )
    again = table.get_or_create(
        local_address="10.0.0.2",
        local_port=40000,
        remote_address="8.8.8.8",
        remote_port=53,
    )
    assert again.connection_id == first.connection_id
    assert again.rebind is False
    assert table.lookup(second.connection_id) == (
        ipaddress.ip_address("10.0.0.2"),
        40001,
        ipaddress.ip_address("1.1.1.1"),
        53,
    )


def test_lru_flow_id_is_reused_with_rebind_when_capacity_is_full() -> None:
    table = UdpGwFlowTable(max_connections=2)
    first = table.get_or_create(
        local_address="10.0.0.2",
        local_port=40000,
        remote_address="8.8.8.8",
        remote_port=53,
    )
    table.get_or_create(
        local_address="10.0.0.2",
        local_port=40001,
        remote_address="1.1.1.1",
        remote_port=53,
    )
    table.get_or_create(
        local_address="10.0.0.2",
        local_port=40000,
        remote_address="8.8.8.8",
        remote_port=53,
    )
    third = table.get_or_create(
        local_address="10.0.0.2",
        local_port=40002,
        remote_address="9.9.9.9",
        remote_port=53,
    )
    assert third.connection_id == 2
    assert third.rebind is True
    assert table.lookup(first.connection_id) is not None


def test_remove_and_clear_release_connection_ids() -> None:
    table = UdpGwFlowTable(max_connections=1)
    lease = table.get_or_create(
        local_address="2001:db8::1",
        local_port=1234,
        remote_address="2001:4860:4860::8888",
        remote_port=53,
    )
    assert table.remove(
        local_address="2001:db8::1",
        local_port=1234,
        remote_address="2001:4860:4860::8888",
        remote_port=53,
    )
    assert table.lookup(lease.connection_id) is None
    assert not table.remove(
        local_address="2001:db8::1",
        local_port=1234,
        remote_address="2001:4860:4860::8888",
        remote_port=53,
    )
    table.clear()
    assert table.count == 0


@pytest.mark.parametrize("max_connections", [0, -1, 65536, True])
def test_flow_table_rejects_invalid_capacity(max_connections: int) -> None:
    with pytest.raises(ValueError):
        UdpGwFlowTable(max_connections=max_connections)


def test_flow_table_rejects_invalid_address_or_port() -> None:
    table = UdpGwFlowTable()
    with pytest.raises(ValueError):
        table.get_or_create(
            local_address="not-an-ip",
            local_port=1,
            remote_address="8.8.8.8",
            remote_port=53,
        )
    with pytest.raises(ValueError):
        table.get_or_create(
            local_address="10.0.0.1",
            local_port=0,
            remote_address="8.8.8.8",
            remote_port=53,
        )
