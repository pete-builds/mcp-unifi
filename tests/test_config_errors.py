"""A failed startup must not print the secrets it was configured with.

``load_settings`` used to let pydantic's ``ValidationError`` escape. That
message carries ``input_value=`` for the object under validation: for a
model-level check on ``Settings`` that is every bound environment variable,
bearer tokens and API key included, and for a check on ``ControllerConfig``
it is the controller entry with its key already read in from ``api_key_file``.
The exception leaves ``main()`` before logging is configured, so the text goes
straight to stderr and the container log, and a healthcheck restart loop
prints it again on every restart. A wrong ``MCP_UNIFI_DEFAULT_CONTROLLER``
printed a live bearer token in the reproduction that led here; a malformed
controllers YAML printed the line holding the API key through PyYAML's own
message.

Each test here checks the *whole* formatted traceback, cause chain included,
because a chained ``ValidationError`` would be printed in full even when the
outer message is clean.
"""

from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from mcp_unifi.config import ConfigurationError, load_settings

API_KEY = "api-key-value-9f3c1a7e5b2d"
TOKEN = "bearer-token-value-4d8e2c6a1f0b"
FILE_KEY = "file-backed-key-7b1e9c3d5a2f"

_ENV_VARS = (
    "STUB_MODE",
    "UNIFI_HOST",
    "UNIFI_API_KEY",
    "UNIFI_API_KEY_FILE",
    "MCP_UNIFI_AUTH_TOKENS",
    "MCP_UNIFI_AUTH_TOKEN_FILE",
    "MCP_UNIFI_CLIENT_ID",
    "MCP_UNIFI_DEFAULT_CONTROLLER",
    "MCP_UNIFI_CONTROLLERS_FILE",
    "CONTROLLERS_FILE",
)


def _rendered(exc: BaseException) -> str:
    """What the default handler prints when this exception ends the process."""
    return "".join(traceback.format_exception(exc))


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # Keep a developer's own .env out of the input pydantic-settings reads.
    monkeypatch.chdir(tmp_path)


def test_a_settings_level_error_names_the_problem_and_no_value(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.setenv("UNIFI_API_KEY", API_KEY)
    monkeypatch.setenv("MCP_UNIFI_AUTH_TOKENS", f"agent:{TOKEN}")
    monkeypatch.setenv("MCP_UNIFI_DEFAULT_CONTROLLER", "typo")

    with pytest.raises(ConfigurationError) as info:
        load_settings()

    text = _rendered(info.value)
    assert API_KEY not in text
    assert TOKEN not in text
    assert "MCP_UNIFI_DEFAULT_CONTROLLER" in text
    assert "typo" in text
    assert "ValidationError" not in text, "the pydantic cause must not be chained"


def test_a_file_backed_key_is_not_printed_either(
    clean_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The key is read from the file into the controller entry by a "before"
    # validator. pydantic reports the input as it was before that ran, so the
    # file contents were never in the printed text; this pins that boundary
    # (it passed against the old code too) rather than catching a regression.
    key_file = tmp_path / "api_key"
    key_file.write_text(FILE_KEY + "\n")
    controllers = tmp_path / "controllers.yaml"
    controllers.write_text(
        "- name: home\n"
        "  host: 192.0.2.1\n"
        "  verify_ssl: true\n"
        f"  pinned_cert: {tmp_path / 'missing.pem'}\n"
        f"  api_key_file: {key_file}\n"
    )
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("MCP_UNIFI_CONTROLLERS_FILE", str(controllers))

    with pytest.raises(ConfigurationError) as info:
        load_settings()

    text = _rendered(info.value)
    assert FILE_KEY not in text
    assert FILE_KEY[-12:] not in text, "a truncated input repr still shows the tail of the key"
    assert "pinned_cert" in text
    assert "missing.pem" in text


def test_a_controller_level_error_from_yaml_names_no_value(
    clean_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A missing pin file fails ControllerConfig's own after-validator, whose
    # input_value is the whole controller entry. The key is last in the entry
    # so it sits in the tail pydantic's truncated repr keeps.
    controllers = tmp_path / "controllers.yaml"
    controllers.write_text(
        "- name: home\n"
        "  host: 192.0.2.1\n"
        "  verify_ssl: true\n"
        f"  pinned_cert: {tmp_path / 'missing.pem'}\n"
        f"  api_key: {API_KEY}\n"
    )
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("MCP_UNIFI_CONTROLLERS_FILE", str(controllers))

    with pytest.raises(ConfigurationError) as info:
        load_settings()

    text = _rendered(info.value)
    assert API_KEY not in text
    assert API_KEY[-12:] not in text, "a truncated input repr still shows the tail of the key"
    assert "pinned_cert" in text
    assert "missing.pem" in text


def test_a_malformed_yaml_line_is_located_but_not_quoted(
    clean_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # PyYAML's own message quotes the offending line with a caret under it.
    controllers = tmp_path / "controllers.yaml"
    controllers.write_text(f"- name: home\n  api_key: abc: {API_KEY}\n")
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("MCP_UNIFI_CONTROLLERS_FILE", str(controllers))

    with pytest.raises(ConfigurationError) as info:
        load_settings()

    text = _rendered(info.value)
    assert API_KEY not in text
    assert "not valid YAML" in text
    assert "line 2" in text
