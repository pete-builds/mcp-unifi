"""Configuration validation tests."""

from __future__ import annotations

import pytest

from mcp_unifi.config import Settings


def test_stub_mode_defaults_are_safe() -> None:
    s = Settings()
    assert s.stub_mode is True
    assert s.unifi_host == ""
    assert s.unifi_api_key == ""
    assert s.mcp_port == 3714


def test_real_mode_requires_host_and_key() -> None:
    with pytest.raises(ValueError) as exc:
        Settings(stub_mode=False)
    assert "UNIFI_HOST" in str(exc.value)
    assert "UNIFI_API_KEY" in str(exc.value)


def test_real_mode_with_credentials_validates() -> None:
    s = Settings(stub_mode=False, unifi_host="10.0.0.1", unifi_api_key="abc")
    assert s.stub_mode is False
    assert s.unifi_host == "10.0.0.1"


def test_iot_subnet_template_must_have_placeholder() -> None:
    with pytest.raises(ValueError):
        Settings(iot_subnet_template="10.0.5.0/24")


def test_dhcp_offsets_must_be_ordered() -> None:
    with pytest.raises(ValueError):
        Settings(iot_dhcp_start_offset=200, iot_dhcp_stop_offset=100)


def test_safe_repr_redacts_api_key() -> None:
    s = Settings(stub_mode=False, unifi_host="10.0.0.1", unifi_api_key="secret-key")
    repr_dict = s.safe_repr()
    assert repr_dict["unifi_api_key_set"] is True
    assert "secret-key" not in repr_dict.values()
    # Just to make absolutely sure no key field leaks the value
    for value in repr_dict.values():
        assert value != "secret-key"


def test_log_level_validation() -> None:
    Settings(log_level="DEBUG")
    Settings(log_level="ERROR")
    with pytest.raises(ValueError):
        Settings(log_level="VERBOSE")  # type: ignore[arg-type]


def test_port_range_validation() -> None:
    with pytest.raises(ValueError):
        Settings(mcp_port=0)
    with pytest.raises(ValueError):
        Settings(mcp_port=99999)
