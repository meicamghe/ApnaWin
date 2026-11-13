import pytest

from apnawin.domain.profile import ConnectionProfile, Transport


def test_valid_profile_is_constructed():
    profile = ConnectionProfile("Office", Transport.SOCKS, "127.0.0.1", 1080)
    assert profile.endpoint_port == 1080


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_invalid_port_is_rejected(port):
    with pytest.raises(ValueError):
        ConnectionProfile("Office", Transport.SOCKS, "localhost", port)


def test_empty_host_is_rejected():
    with pytest.raises(ValueError):
        ConnectionProfile("Office", Transport.SOCKS, " ", 1080)
