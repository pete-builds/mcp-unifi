"""File-backed secrets, the file-backed TLS default, and the legacy-shape warning.

This is the opt-in hardening shape ADR 0007 adopts from PR #154 (@Taltos-ch):
every secret gains a ``*_file`` twin for Docker and Kubernetes secret mounts,
a controller configured by ``api_key_file`` verifies TLS unless told not to,
and a controller still on the value-supplied shape is named once per boot.
Nothing here refuses a configuration that worked before this shipped; the
tests that prove that are the ones asserting the ADR 0003 default survives.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import AliasChoices, SecretStr, ValidationError

from mcp_unifi.config import ADR_0007, ControllerConfig, Settings
from mcp_unifi.logging_setup import JsonFormatter
from mcp_unifi.redaction import redact
from mcp_unifi.server import build_server

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.usefixtures("clean_unifi_env")

API_KEY = "file-api-key-9f3a7c"
ACCESS_KEY = "file-access-key-b81d"
OS_PASSWORD = "file-console-pass-4e2f"
BEARER = "d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9"


def _write(tmp_path: Path, name: str, contents: str) -> Path:
    path = tmp_path / name
    path.write_text(contents, encoding="utf-8")
    return path


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    return _write(tmp_path, "unifi_api_key", f"{API_KEY}\n")


def _legacy_env(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    """Real mode against a host, plus whatever the test sets on top."""
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("UNIFI_HOST", env.pop("UNIFI_HOST", "h"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)


# ---------------------------------------------------------------------------
# ControllerConfig: resolution, precedence, failure modes
# ---------------------------------------------------------------------------


def test_api_key_file_resolves_and_turns_tls_verification_on(key_file: Path) -> None:
    c = ControllerConfig(name="dc", host="unifi.example.com", api_key_file=key_file)
    assert c.api_key.get_secret_value() == API_KEY
    assert c.api_key_file == key_file
    assert c.verify_ssl is True


def test_trailing_newline_is_stripped(tmp_path: Path) -> None:
    path = _write(tmp_path, "k", f"  {API_KEY}\r\n\n")
    c = ControllerConfig(name="dc", host="h", api_key_file=path)
    assert c.api_key.get_secret_value() == API_KEY


def test_file_wins_when_both_forms_are_set(key_file: Path) -> None:
    c = ControllerConfig(
        name="dc", host="h", api_key=SecretStr("inline-value"), api_key_file=key_file
    )
    assert c.api_key.get_secret_value() == API_KEY


def test_inline_value_keeps_the_adr_0003_default() -> None:
    c = ControllerConfig(name="lan", host="192.168.1.1", api_key=SecretStr("inline"))
    assert c.verify_ssl is False
    assert c.api_key_file is None


def test_explicit_verify_ssl_false_survives_the_file_form(key_file: Path) -> None:
    c = ControllerConfig(name="dc", host="h", api_key_file=key_file, verify_ssl=False)
    assert c.verify_ssl is False


def test_explicit_verify_ssl_true_survives_the_value_form() -> None:
    c = ControllerConfig(name="lan", host="h", api_key=SecretStr("inline"), verify_ssl=True)
    assert c.verify_ssl is True


def test_string_path_is_accepted(key_file: Path) -> None:
    c = ControllerConfig(name="dc", host="h", api_key_file=str(key_file))  # type: ignore[arg-type]
    assert c.api_key_file == key_file
    assert c.api_key.get_secret_value() == API_KEY


def test_missing_file_fails_naming_the_controller_and_field(tmp_path: Path) -> None:
    with pytest.raises(ValidationError) as exc:
        ControllerConfig(name="home", host="h", api_key_file=tmp_path / "absent")
    msg = str(exc.value)
    assert "controller 'home' api_key_file" in msg
    assert "does not exist" in msg


def test_empty_file_fails(tmp_path: Path) -> None:
    path = _write(tmp_path, "empty", "  \n\n")
    with pytest.raises(ValidationError, match="is empty"):
        ControllerConfig(name="home", host="h", api_key_file=path)


def test_directory_is_not_a_regular_file(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="not a regular file"):
        ControllerConfig(name="home", host="h", api_key_file=tmp_path)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permission bits")
def test_unreadable_file_fails_without_leaking(tmp_path: Path) -> None:
    path = _write(tmp_path, "locked", API_KEY)
    path.chmod(0)
    try:
        with pytest.raises(ValidationError) as exc:
            ControllerConfig(name="home", host="h", api_key_file=path)
    finally:
        path.chmod(0o600)
    msg = str(exc.value)
    assert "cannot be read" in msg
    assert API_KEY not in msg


def test_neither_form_is_still_a_validation_error() -> None:
    with pytest.raises(ValidationError, match="api_key"):
        ControllerConfig(name="home", host="h")  # type: ignore[call-arg]


def test_access_and_console_password_files_resolve_and_win(tmp_path: Path) -> None:
    access = _write(tmp_path, "access", ACCESS_KEY)
    console = _write(tmp_path, "console", OS_PASSWORD)
    c = ControllerConfig(
        name="dc",
        host="h",
        api_key=SecretStr("k"),
        access_host="hub",
        access_api_key=SecretStr("inline-access"),
        access_api_key_file=access,
        os_username="admin",
        os_password=SecretStr("inline-pass"),
        os_password_file=console,
    )
    assert c.access_api_key is not None
    assert c.access_api_key.get_secret_value() == ACCESS_KEY
    assert c.os_password is not None
    assert c.os_password.get_secret_value() == OS_PASSWORD
    # The Network key came inline, so the TLS default did not move.
    assert c.verify_ssl is False


# ---------------------------------------------------------------------------
# Settings: legacy env promotion, YAML, stub mode
# ---------------------------------------------------------------------------


def test_legacy_env_api_key_file_promotes(monkeypatch: pytest.MonkeyPatch, key_file: Path) -> None:
    _legacy_env(monkeypatch, UNIFI_HOST="unifi.example.com", UNIFI_API_KEY_FILE=str(key_file))
    s = Settings()
    c = s.controllers[0]
    assert c.name == "default"
    assert c.api_key.get_secret_value() == API_KEY
    assert c.api_key_file == key_file
    assert c.verify_ssl is True


def test_legacy_env_value_keeps_the_adr_0003_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _legacy_env(monkeypatch, UNIFI_HOST="192.168.1.1", UNIFI_API_KEY="inline")
    c = Settings().controllers[0]
    assert c.api_key.get_secret_value() == "inline"
    assert c.verify_ssl is False


def test_legacy_env_file_wins_over_value(monkeypatch: pytest.MonkeyPatch, key_file: Path) -> None:
    _legacy_env(monkeypatch, UNIFI_API_KEY="inline", UNIFI_API_KEY_FILE=str(key_file))
    assert Settings().controllers[0].api_key.get_secret_value() == API_KEY


def test_legacy_env_explicit_verify_ssl_false_with_file(
    monkeypatch: pytest.MonkeyPatch, key_file: Path
) -> None:
    _legacy_env(monkeypatch, UNIFI_API_KEY_FILE=str(key_file), UNIFI_VERIFY_SSL="false")
    assert Settings().controllers[0].verify_ssl is False


def test_legacy_env_secondary_files_promote(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    access = _write(tmp_path, "access", ACCESS_KEY)
    console = _write(tmp_path, "console", OS_PASSWORD)
    _legacy_env(
        monkeypatch,
        UNIFI_API_KEY="inline",
        UNIFI_ACCESS_HOST="hub",
        UNIFI_ACCESS_API_KEY_FILE=str(access),
        UNIFI_OS_USERNAME="admin",
        UNIFI_OS_PASSWORD_FILE=str(console),
    )
    c = Settings().controllers[0]
    assert c.access_api_key is not None
    assert c.access_api_key.get_secret_value() == ACCESS_KEY
    assert c.os_password is not None
    assert c.os_password.get_secret_value() == OS_PASSWORD


def test_real_mode_error_names_the_file_variant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STUB_MODE", "false")
    with pytest.raises(ValueError, match="UNIFI_API_KEY_FILE"):
        Settings()


def test_yaml_mixes_both_shapes(tmp_path: Path, key_file: Path) -> None:
    yaml_path = _write(
        tmp_path,
        "controllers.yaml",
        f"""
- name: lan
  host: 192.168.1.1
  api_key: inline-lan-key
- name: dc
  host: unifi.example.com
  api_key_file: {key_file}
""",
    )
    s = Settings(stub_mode=False, controllers_file=yaml_path)
    lan, dc = s.controllers
    assert lan.verify_ssl is False
    assert lan.api_key.get_secret_value() == "inline-lan-key"
    assert dc.verify_ssl is True
    assert dc.api_key.get_secret_value() == API_KEY


def test_yaml_missing_secret_file_names_the_controller(tmp_path: Path) -> None:
    yaml_path = _write(
        tmp_path,
        "controllers.yaml",
        f"""
- name: dc
  host: h
  api_key_file: {tmp_path / "absent"}
""",
    )
    with pytest.raises(ValueError, match="controller 'dc' api_key_file"):
        Settings(stub_mode=False, controllers_file=yaml_path)


def test_stub_mode_is_unchanged() -> None:
    c = Settings().controllers[0]
    assert c.api_key.get_secret_value() == "stub"
    assert c.api_key_file is None
    assert c.verify_ssl is False


# ---------------------------------------------------------------------------
# HTTP bearer token file
# ---------------------------------------------------------------------------


def test_bare_token_file_named_by_client_id(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", f"{BEARER}\n")
    s = Settings(auth_token_file=token_file, client_id="taltos")
    assert s.auth_token_map == {BEARER: {"client_id": "taltos", "scopes": []}}
    assert s.auth_client_scopes == {"taltos": {"*"}}


def test_bare_token_file_without_client_id_is_auto_named(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", BEARER)
    s = Settings(auth_token_file=token_file)
    assert s.auth_token_map[BEARER]["client_id"] == "client-0"


def test_file_token_combines_with_inline_tokens(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", BEARER)
    s = Settings(auth_tokens="inline-a:tok-a,tok-b", auth_token_file=token_file, client_id="filed")
    ids = {meta["client_id"] for meta in s.auth_token_map.values()}
    assert ids == {"inline-a", "client-1", "filed"}


def test_file_may_carry_the_full_grammar(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", "ops:tok-1:network|protect,viewer:tok-2\n")
    s = Settings(auth_token_file=token_file)
    assert s.auth_client_scopes == {"ops": {"network", "protect"}, "viewer": {"*"}}


def test_grammar_file_plus_client_id_is_rejected(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", "ops:tok-1")
    with pytest.raises(ValueError, match="already carries client names"):
        _ = Settings(auth_token_file=token_file, client_id="ops").auth_token_map


def test_client_id_without_file_is_rejected() -> None:
    with pytest.raises(ValueError, match="MCP_UNIFI_AUTH_TOKEN_FILE is not"):
        _ = Settings(client_id="orphan").auth_token_map


def test_duplicate_token_across_env_and_file_is_rejected(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", BEARER)
    with pytest.raises(ValueError, match="reuses a token"):
        _ = Settings(auth_tokens=f"inline:{BEARER}", auth_token_file=token_file, client_id="dup")
        _ = _.auth_token_map


def test_reserved_delimiter_in_bare_file_token_names_the_file(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", "ab|cd")
    with pytest.raises(ValueError, match=r"MCP_UNIFI_AUTH_TOKEN_FILE.*reserved delimiter"):
        _ = Settings(auth_token_file=token_file).auth_token_map


def test_client_id_with_delimiter_is_rejected(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", BEARER)
    with pytest.raises(ValueError, match="MCP_UNIFI_CLIENT_ID must not contain"):
        _ = Settings(auth_token_file=token_file, client_id="a:b").auth_token_map


def test_missing_token_file_fails_startup(tmp_path: Path) -> None:
    s = Settings(auth_token_file=tmp_path / "absent", client_id="x")
    with pytest.raises(ValueError, match=r"MCP_UNIFI_AUTH_TOKEN_FILE.*does not exist"):
        build_server(s)


def test_empty_token_file_fails_startup(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", "\n")
    s = Settings(auth_token_file=token_file, client_id="x")
    with pytest.raises(ValueError, match=r"MCP_UNIFI_AUTH_TOKEN_FILE.*is empty"):
        build_server(s)


def test_http_boots_on_a_file_token_alone(tmp_path: Path) -> None:
    token_file = _write(tmp_path, "token", BEARER)
    s = Settings(auth_token_file=token_file, client_id="taltos")
    assert s.mcp_transport == "streamable-http"
    assert s.auth_required is True
    build_server(s)
    assert s.safe_repr()["auth_client_ids"] == ["taltos"]


# ---------------------------------------------------------------------------
# Redaction: paths may be logged, contents never
# ---------------------------------------------------------------------------


def _all_file_settings(tmp_path: Path, **overrides: object) -> Settings:
    key = _write(tmp_path, "api_key", API_KEY)
    access = _write(tmp_path, "access", ACCESS_KEY)
    console = _write(tmp_path, "console", OS_PASSWORD)
    token = _write(tmp_path, "token", BEARER)
    kwargs: dict[str, object] = {
        "stub_mode": False,
        "controllers": [
            ControllerConfig(
                name="dc",
                host="unifi.example.com",
                api_key_file=key,
                access_host="hub.example.com",
                access_api_key_file=access,
                os_username="admin",
                os_password_file=console,
            )
        ],
        "auth_token_file": token,
        "client_id": "taltos",
        "log_format": "json",
    }
    kwargs.update(overrides)
    return Settings(**kwargs)  # type: ignore[arg-type]


def test_safe_repr_reports_paths_and_never_contents(tmp_path: Path) -> None:
    s = _all_file_settings(tmp_path)
    rendered = json.dumps(s.safe_repr(), default=str)
    for secret in (API_KEY, ACCESS_KEY, OS_PASSWORD, BEARER):
        assert secret not in rendered
    for path_name in ("api_key", "access", "console", "token"):
        assert str(tmp_path / path_name) in rendered
    (controller,) = s.safe_repr()["controllers"]  # type: ignore[misc]
    assert controller["api_key_set"] is True
    assert controller["access_api_key_set"] is True
    assert controller["os_password_set"] is True


def _file_fields() -> set[str]:
    """Every ``*_file`` field the startup line can report, by its safe_repr key."""
    controller = {f for f in ControllerConfig.model_fields if f.endswith("_file")}
    settings = {
        f for f in Settings.model_fields if f.endswith("_file") and not f.startswith("unifi_")
    }
    return controller | settings


def test_every_file_field_survives_redaction() -> None:
    """A path field whose name contains ``key``, ``password`` or ``token``
    would come out of the startup line as ``[REDACTED]`` unless it is listed
    in ``NON_SECRET_KEYS``. The next ``*_file`` field must be added there
    too, and this is the test that says so."""
    fields = _file_fields()
    assert {"api_key_file", "auth_token_file"} <= fields, fields
    paths = dict.fromkeys(fields, "/run/secrets/x")
    assert redact(paths) == paths


def test_no_secret_reaches_any_log_record(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Boot exactly as ``main()`` does and read every record back rendered.

    The control is the path assertion at the end: the same records that
    must not carry a secret must carry the secret's *path*, which proves the
    capture saw the startup line rather than passing on an empty log.
    """
    caplog.set_level(logging.DEBUG)
    s = _all_file_settings(tmp_path)
    logging.getLogger("mcp_unifi.server").info(
        "MCP UniFi starting", extra={"config": s.safe_repr()}
    )
    build_server(s)
    formatter = JsonFormatter()
    rendered = [formatter.format(r) + r.getMessage() for r in caplog.records]
    assert rendered, "nothing was logged; the capture is not seeing startup"
    for secret in (API_KEY, ACCESS_KEY, OS_PASSWORD, BEARER):
        assert not any(secret in line for line in rendered), f"{secret!r} reached a log record"
    assert any(str(tmp_path / "api_key") in line for line in rendered)


# ---------------------------------------------------------------------------
# The startup warning: once per boot, names the controller, silent when hardened
# ---------------------------------------------------------------------------


def test_legacy_controller_is_named_exactly_once(
    config_warnings: Callable[[], list[str]],
) -> None:
    s = Settings(
        stub_mode=False, unifi_host="192.168.1.1", unifi_api_key="inline", mcp_transport="stdio"
    )
    build_server(s)
    (msg,) = config_warnings()
    assert "controller 'default'" in msg
    assert "API key supplied as a value" in msg
    assert "TLS verification off" in msg
    assert ADR_0007 in msg
    assert "\n" not in msg


def test_hardened_controller_is_silent(
    key_file: Path, config_warnings: Callable[[], list[str]]
) -> None:
    s = Settings(
        stub_mode=False,
        unifi_host="unifi.example.com",
        unifi_api_key_file=key_file,
        mcp_transport="stdio",
    )
    build_server(s)
    assert config_warnings() == []


def test_file_key_with_tls_off_still_warns_about_tls_only(
    key_file: Path, config_warnings: Callable[[], list[str]]
) -> None:
    s = Settings(
        stub_mode=False,
        unifi_host="h",
        unifi_api_key_file=key_file,
        unifi_verify_ssl=False,
        mcp_transport="stdio",
    )
    build_server(s)
    (msg,) = config_warnings()
    assert "TLS verification off" in msg
    assert "API key supplied as a value" not in msg


def test_mixed_controllers_warn_only_for_the_legacy_one(
    key_file: Path, config_warnings: Callable[[], list[str]]
) -> None:
    s = Settings(
        stub_mode=False,
        mcp_transport="stdio",
        controllers=[
            ControllerConfig(name="lan", host="192.168.1.1", api_key=SecretStr("inline")),
            ControllerConfig(name="dc", host="unifi.example.com", api_key_file=key_file),
        ],
    )
    build_server(s)
    (msg,) = config_warnings()
    assert "controller 'lan'" in msg
    assert "'dc'" not in msg


def test_stub_mode_never_warns(config_warnings: Callable[[], list[str]]) -> None:
    build_server(Settings(auth_required=False))
    assert config_warnings() == []


def test_env_bearer_tokens_warn_on_http_only(
    config_warnings: Callable[[], list[str]], caplog: pytest.LogCaptureFixture
) -> None:
    base = {"stub_mode": False, "unifi_host": "h", "unifi_api_key": "k", "auth_tokens": "a:tok"}
    build_server(Settings(**base, mcp_transport="streamable-http"))  # type: ignore[arg-type]
    (http,) = [m for m in config_warnings() if "MCP_UNIFI_AUTH_TOKENS" in m]
    assert "MCP_UNIFI_AUTH_TOKEN_FILE" in http
    caplog.clear()
    build_server(Settings(**base, mcp_transport="stdio"))  # type: ignore[arg-type]
    assert not [m for m in config_warnings() if "MCP_UNIFI_AUTH_TOKENS" in m]


def test_file_bearer_token_does_not_warn(
    tmp_path: Path, config_warnings: Callable[[], list[str]]
) -> None:
    build_server(_all_file_settings(tmp_path))
    assert config_warnings() == []


def test_one_line_per_legacy_controller_plus_one_for_env_tokens(
    key_file: Path, config_warnings: Callable[[], list[str]]
) -> None:
    s = Settings(
        stub_mode=False,
        auth_tokens="a:tok",
        controllers=[
            ControllerConfig(name="lan", host="192.168.1.1", api_key=SecretStr("inline")),
            ControllerConfig(name="dc", host="h", api_key_file=key_file),
            ControllerConfig(name="old", host="10.0.0.1", api_key=SecretStr("inline2")),
        ],
    )
    build_server(s)
    assert len(config_warnings()) == 3


# ---------------------------------------------------------------------------
# Docs guard: every _FILE variable the code accepts is in the two config tables
# ---------------------------------------------------------------------------

_CONFIG_DOCS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "site" / "src" / "content" / "docs" / "reference" / "configuration.md",
)


def _file_env_vars() -> set[str]:
    """Every ``*_FILE`` environment variable ``Settings`` binds, read off the model."""
    out: set[str] = set()
    for name, info in Settings.model_fields.items():
        if not name.endswith("_file"):
            continue
        alias = info.validation_alias
        if isinstance(alias, AliasChoices):
            out.update(str(c) for c in alias.choices if str(c).isupper())
        else:
            out.add(name.upper())
    return out


def test_every_file_variable_is_documented() -> None:
    """A ``_FILE`` variant that exists in code but not in the config tables is
    a feature nobody can find. The same guard keeps ``MCP_UNIFI_CLIENT_ID``
    beside its file."""
    expected = _file_env_vars() | {"MCP_UNIFI_CLIENT_ID"}
    assert {"UNIFI_API_KEY_FILE", "MCP_UNIFI_AUTH_TOKEN_FILE"} <= expected, expected
    for doc in _CONFIG_DOCS:
        text = doc.read_text(encoding="utf-8")
        missing = sorted(v for v in expected if f"`{v}`" not in text)
        assert not missing, f"{doc.relative_to(REPO_ROOT)} does not document {missing}"
