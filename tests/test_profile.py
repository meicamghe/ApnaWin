import pytest

from apnawin.domain.profile import ConnectionProfile, Transport


def test_valid_profile_is_constructed():
    profile = ConnectionProfile("Office", Transport.SOCKS, "127.0.0.1", 1080)
    assert profile.endpoint_port == 1080


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_invalid_port_is_rejected(port):
    with pytest.raises(ValueError):
        ConnectionProfile("Office", Transport.SOCKS, "localhost", port)


@pytest.mark.parametrize("port", [True, False, 1080.0, "1080"])
def test_non_integer_port_is_rejected(port):
    with pytest.raises(TypeError, match="integer"):
        ConnectionProfile("Office", Transport.SOCKS, "localhost", port)


def test_empty_host_is_rejected():
    with pytest.raises(ValueError):
        ConnectionProfile("Office", Transport.SOCKS, " ", 1080)


@pytest.mark.parametrize("host", [None, 123, ["localhost"]])
def test_non_string_host_is_rejected(host):
    with pytest.raises(TypeError, match="host must be a string"):
        ConnectionProfile("Office", Transport.SOCKS, host, 1080)


@pytest.mark.parametrize("host", ["host name", "host\nname", "host\tname"])
def test_host_whitespace_is_rejected(host):
    with pytest.raises(ValueError, match="whitespace"):
        ConnectionProfile("Office", Transport.SOCKS, host, 1080)


@pytest.mark.parametrize("host", ["host\x85name", "host\x9fname"])\ndef test_unicode_control_characters_in_host_are_rejected(host):\n    with pytest.raises(ValueError, match="control characters"):\n        ConnectionProfile("Office", Transport.SOCKS, host, 1080)\n\n\n@pytest.mark.parametrize("name", [None, 123, []])
def test_non_string_name_is_rejected(name):
    with pytest.raises(TypeError, match="name must be a string"):
        ConnectionProfile(name, Transport.SOCKS, "localhost", 1080)


@pytest.mark.parametrize("name", ["Office\x85Name", "Office\x9fName"])
def test_unicode_control_characters_in_name_are_rejected(name):
    with pytest.raises(ValueError, match="control characters"):
        ConnectionProfile(name, Transport.SOCKS, "localhost", 1080)


def test_name_with_only_whitespace_is_rejected():
    with pytest.raises(ValueError, match="cannot be empty"):
        ConnectionProfile("   ", Transport.SOCKS, "localhost", 1080)


def test_non_enum_transport_is_rejected():
    with pytest.raises(TypeError, match="Transport"):
        ConnectionProfile("Office", "socks", "localhost", 1080)


def test_oversized_profile_fields_are_rejected():
    with pytest.raises(ValueError, match="128"):
        ConnectionProfile("x" * 129, Transport.SOCKS, "localhost", 1080)
    with pytest.raises(ValueError, match="253"):
        ConnectionProfile("Office", Transport.SOCKS, "a" * 254, 1080)
