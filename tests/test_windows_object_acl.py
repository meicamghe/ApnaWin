import pytest

from apnawin.services.windows_object_acl import (
    build_local_pipe_sddl,
    build_service_mutex_sddl,
)


SERVICE_SID = "S-1-5-80-111-222-333-444-555"
USER_SID = "S-1-5-21-111-222-333-1001"


def test_service_mutex_acl_grants_only_system_and_service():
    assert build_service_mutex_sddl(SERVICE_SID) == (
        "D:P(A;;GA;;;S-1-5-18)(A;;GA;;;S-1-5-80-111-222-333-444-555)"
    )


def test_local_pipe_acl_grants_client_only_read_write():
    assert build_local_pipe_sddl(SERVICE_SID, USER_SID) == (
        "D:P(A;;GA;;;S-1-5-18)"
        "(A;;GA;;;S-1-5-80-111-222-333-444-555)"
        "(A;;GRGW;;;S-1-5-21-111-222-333-1001)"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "S-1-5-80-1-2-3-4",
        "S-1-5-80-1-2-3-4-5;D:(A;;GA;;;WD)",
        "S-1-5-80-01-2-3-4-5",
        "S-1-5-80-4294967296-2-3-4-5",
        None,
    ],
)
def test_service_sid_must_be_canonical_service_sid(value):
    with pytest.raises(ValueError, match="service_sid"):
        build_service_mutex_sddl(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "S-1-5-21-1-2",
        "S-1-5-21-1-2-3-4;D:(A;;GA;;;WD)",
        "S-1-5-21-01-2-3-1001",
        "S-1-5-21-4294967296-2-3-1001",
        None,
    ],
)
def test_client_sid_must_be_canonical_account_sid(value):
    with pytest.raises(ValueError, match="client_sid"):
        build_local_pipe_sddl(SERVICE_SID, value)


@pytest.mark.parametrize("sid", ["S-1-5-18", SERVICE_SID])
def test_pipe_client_must_be_distinct_from_service_and_system(sid):
    with pytest.raises(ValueError, match="distinct"):
        build_local_pipe_sddl(SERVICE_SID, sid)
