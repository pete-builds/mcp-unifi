"""Configuration validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from mcp_unifi.config import ControllerConfig, Settings

# ---------------------------------------------------------------------------
# Stub-mode defaults & basic validation
# ---------------------------------------------------------------------------


def test_stub_mode_defaults_are_safe() -> None:
    s = Settings()
    assert s.stub_mode is True
    assert s.unifi_host == ""
    assert s.unifi_api_key == ""
    assert s.mcp_port == 3714
    # Stub mode synthesizes a single 'default' controller so the dispatcher
    # has something to bind tools against.
    assert len(s.controllers) == 1
    assert s.controllers[0].name == "default"
    assert s.controllers[0].host == "stub"


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


def test_transport_defaults_to_streamable_http() -> None:
    s = Settings()
    assert s.mcp_transport == "streamable-http"


def test_transport_accepts_stdio() -> None:
    s = Settings(mcp_transport="stdio")
    assert s.mcp_transport == "stdio"


def test_transport_rejects_unknown_values() -> None:
    with pytest.raises(ValueError):
        Settings(mcp_transport="websocket")  # type: ignore[arg-type]


def test_safe_repr_includes_transport() -> None:
    s = Settings(mcp_transport="stdio")
    assert s.safe_repr()["mcp_transport"] == "stdio"


# ---------------------------------------------------------------------------
# Multi-controller config (Step 2)
# ---------------------------------------------------------------------------


def test_single_controller_env_auto_promotes() -> None:
    """Legacy UNIFI_HOST/UNIFI_API_KEY must produce one 'default' controller
    with all fields preserved.
    """
    s = Settings(
        stub_mode=False,
        unifi_host="192.168.1.1",
        unifi_api_key="legacy-key",
        unifi_port=8443,
        unifi_site="alpha",
        unifi_verify_ssl=True,
    )
    assert len(s.controllers) == 1
    c = s.controllers[0]
    assert c.name == "default"
    assert c.host == "192.168.1.1"
    assert c.api_key.get_secret_value() == "legacy-key"
    assert c.port == 8443
    assert c.site == "alpha"
    assert c.verify_ssl is True


def test_multi_controller_yaml_loads(tmp_path: Path) -> None:
    yaml_path = tmp_path / "controllers.yml"
    yaml_path.write_text(
        """
- name: home
  host: 192.168.1.1
  api_key: home-key
  port: 443
  site: default
  verify_ssl: false
- name: office
  host: 10.0.0.1
  api_key: office-key
  port: 8443
  site: hq
  verify_ssl: true
- name: parents
  host: 172.16.0.1
  api_key: parents-key
""",
        encoding="utf-8",
    )
    s = Settings(stub_mode=False, controllers_file=yaml_path)
    assert len(s.controllers) == 3
    names = [c.name for c in s.controllers]
    assert names == ["home", "office", "parents"]
    home = s.controllers[0]
    assert home.host == "192.168.1.1"
    assert home.api_key.get_secret_value() == "home-key"
    office = s.controllers[1]
    assert office.port == 8443
    assert office.site == "hq"
    assert office.verify_ssl is True
    parents = s.controllers[2]
    # Defaults applied.
    assert parents.port == 443
    assert parents.site == "default"
    assert parents.verify_ssl is False


def test_yaml_with_top_level_controllers_key(tmp_path: Path) -> None:
    """The YAML may also be a dict with a top-level 'controllers:' key."""
    yaml_path = tmp_path / "controllers.yml"
    yaml_path.write_text(
        """
controllers:
  - name: home
    host: 192.168.1.1
    api_key: home-key
""",
        encoding="utf-8",
    )
    s = Settings(stub_mode=False, controllers_file=yaml_path)
    assert len(s.controllers) == 1
    assert s.controllers[0].name == "home"


def test_duplicate_controller_names_rejected(tmp_path: Path) -> None:
    yaml_path = tmp_path / "controllers.yml"
    yaml_path.write_text(
        """
- name: home
  host: 192.168.1.1
  api_key: a
- name: home
  host: 10.0.0.1
  api_key: b
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        Settings(stub_mode=False, controllers_file=yaml_path)
    assert "Duplicate controller names" in str(exc.value)
    assert "home" in str(exc.value)


def test_real_mode_with_no_config_raises() -> None:
    """Real mode + no controllers_file + no legacy env vars → hard error."""
    with pytest.raises(ValueError) as exc:
        Settings(stub_mode=False)
    msg = str(exc.value)
    assert "Real mode" in msg
    assert "MCP_UNIFI_CONTROLLERS_FILE" in msg or "UNIFI_HOST" in msg


def test_stub_mode_with_no_config_synthesizes_default() -> None:
    s = Settings(stub_mode=True)
    assert len(s.controllers) == 1
    c = s.controllers[0]
    assert c.name == "default"
    assert c.host == "stub"
    assert c.api_key.get_secret_value() == "stub"


def test_yaml_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yml"
    with pytest.raises(ValueError) as exc:
        Settings(stub_mode=False, controllers_file=missing)
    assert "does not exist" in str(exc.value)


def test_yaml_invalid_shape_raises(tmp_path: Path) -> None:
    yaml_path = tmp_path / "controllers.yml"
    yaml_path.write_text("just_a_string\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        Settings(stub_mode=False, controllers_file=yaml_path)
    assert "must contain a list" in str(exc.value)


def test_yaml_invalid_yaml_raises(tmp_path: Path) -> None:
    yaml_path = tmp_path / "controllers.yml"
    yaml_path.write_text("name: home\n  host: bad\n   indent: nope\n: oops", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        Settings(stub_mode=False, controllers_file=yaml_path)
    assert "not valid YAML" in str(exc.value)


def test_explicit_controllers_list_passes_through() -> None:
    """Callers (tests, programmatic users) can pass `controllers=[...]` directly."""
    s = Settings(
        stub_mode=False,
        controllers=[
            ControllerConfig(name="a", host="10.0.0.1", api_key=SecretStr("k1")),
            ControllerConfig(name="b", host="10.0.0.2", api_key=SecretStr("k2")),
        ],
    )
    assert [c.name for c in s.controllers] == ["a", "b"]


def test_explicit_duplicates_in_caller_list_rejected() -> None:
    with pytest.raises(ValueError) as exc:
        Settings(
            stub_mode=False,
            controllers=[
                ControllerConfig(name="dupe", host="10.0.0.1", api_key=SecretStr("k1")),
                ControllerConfig(name="dupe", host="10.0.0.2", api_key=SecretStr("k2")),
            ],
        )
    assert "Duplicate" in str(exc.value)


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


def test_safe_repr_never_leaks_api_key() -> None:
    """`safe_repr()` must include `api_key_set` but never the value, and
    the literal string 'api_key' (the value field) must not appear in the
    serialized output.
    """
    s = Settings(stub_mode=False, unifi_host="10.0.0.1", unifi_api_key="super-secret-key")
    repr_dict = s.safe_repr()
    serialized = str(repr_dict)
    # The secret value must not appear anywhere.
    assert "super-secret-key" not in serialized
    # `api_key_set` IS present per controller; bare `api_key` (the value
    # key) is NOT.
    assert "api_key_set" in serialized
    assert "'api_key'" not in serialized
    assert '"api_key"' not in serialized
    controllers = repr_dict["controllers"]
    assert isinstance(controllers, list)
    assert controllers[0]["api_key_set"] is True  # type: ignore[index]
    assert "api_key" not in controllers[0]  # type: ignore[operator]


def test_secretstr_round_trip() -> None:
    """`controllers[0].api_key.get_secret_value()` must return the original."""
    s = Settings(stub_mode=False, unifi_host="10.0.0.1", unifi_api_key="round-trip-value")
    assert s.controllers[0].api_key.get_secret_value() == "round-trip-value"


def test_secretstr_default_repr_is_redacted() -> None:
    """Pydantic's SecretStr should redact its own repr/str by default."""
    c = ControllerConfig(name="x", host="h", api_key=SecretStr("hidden"))
    assert "hidden" not in repr(c)
    assert "hidden" not in str(c.api_key)


def test_backward_compat_unifi_api_key_env_works(monkeypatch: pytest.MonkeyPatch) -> None:
    """The legacy UNIFI_API_KEY env var must still flow through to
    controllers[0].api_key, retrievable via get_secret_value().
    """
    # Clear anything that could interfere.
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "MCP_UNIFI_CONTROLLERS_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("UNIFI_HOST", "192.168.86.1")
    monkeypatch.setenv("UNIFI_API_KEY", "env-key-42")

    s = Settings()
    assert s.unifi_api_key == "env-key-42"  # legacy field still populated
    assert len(s.controllers) == 1
    assert s.controllers[0].api_key.get_secret_value() == "env-key-42"
    assert s.controllers[0].host == "192.168.86.1"
    assert s.controllers[0].name == "default"


def test_yaml_priority_over_legacy_env(tmp_path: Path) -> None:
    """If both YAML and legacy env are set, YAML wins (file is more explicit)."""
    yaml_path = tmp_path / "controllers.yml"
    yaml_path.write_text(
        "- name: yaml-wins\n  host: 1.2.3.4\n  api_key: yaml-key\n",
        encoding="utf-8",
    )
    s = Settings(
        stub_mode=False,
        controllers_file=yaml_path,
        unifi_host="9.9.9.9",
        unifi_api_key="legacy-key",
    )
    assert len(s.controllers) == 1
    assert s.controllers[0].name == "yaml-wins"
    assert s.controllers[0].host == "1.2.3.4"
