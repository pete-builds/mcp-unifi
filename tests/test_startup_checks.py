"""Checks ``server.main()`` makes before it serves a single request.

Each of these used to surface late or not at all:

* a mistyped ``MCP_UNIFI_AUDIT_SINK`` booted healthy and then failed every
  tool call, because the sink was built on the first call;
* the stdout sink on the stdio transport wrote audit lines into the
  JSON-RPC stream;
* an audit path that cannot be written (the default ``./audit.jsonl`` on the
  read-only root filesystem the shipped compose file and Helm chart use)
  dropped every record while every tool call reported success;
* bare variable names such as ``READONLY`` and ``AUTH_REQUIRED`` were read
  as settings without a word, while documented nowhere.

``main()`` runs in-process with ``FastMCP.run`` replaced by a recorder, so a
test can tell "refused to start" from "started" without binding a port.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import fastmcp
import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from mcp_unifi import audit, config, server
from mcp_unifi.config import Settings


@pytest.fixture
def run_main(
    clean_unifi_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[[], list[dict[str, Any]]]:
    """Return a callable that runs ``server.main()`` and the ``run`` calls it made.

    ``configure_logging`` is stubbed because it removes every root handler,
    caplog's included. The session-idle setting and the recorded sink status
    are process globals that ``main()`` writes; monkeypatch restores both.
    """
    for var in (audit.ENV_SINK, audit.ENV_PATH, "MCP_UNIFI_READONLY", "READONLY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MCP_UNIFI_AUTH_REQUIRED", "false")
    monkeypatch.setenv(audit.ENV_PATH, str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(server, "configure_logging", lambda **_: None)
    monkeypatch.setattr(
        fastmcp.settings,
        "http_session_idle_timeout",
        fastmcp.settings.http_session_idle_timeout,
    )
    monkeypatch.setattr(audit, "_SINK_STATUS", None, raising=False)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(FastMCP, "run", lambda self, **kwargs: calls.append(kwargs))

    def _run() -> list[dict[str, Any]]:
        server.main()
        return calls

    return _run


def _unwritable_path(tmp_path: Path) -> Path:
    """A path no user can create: its parent is a regular file.

    Permission bits would not do, since a test run as root ignores them.
    """
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    return blocker / "audit.jsonl"


# ---------------------------------------------------------------------------
# Sink configuration fails at startup, not on the first call
# ---------------------------------------------------------------------------


def test_unknown_audit_sink_fails_startup(
    run_main: Callable[[], list[dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(audit.ENV_SINK, "files")
    with pytest.raises(ValueError, match=r"MCP_UNIFI_AUDIT_SINK='files' is not one of"):
        run_main()


def test_stdout_sink_on_stdio_transport_fails_startup(
    run_main: Callable[[], list[dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(audit.ENV_SINK, "stdout")
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    with pytest.raises(ValueError, match="JSON-RPC"):
        run_main()


def test_stdout_sink_on_http_transport_still_starts(
    run_main: Callable[[], list[dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(audit.ENV_SINK, "stdout")
    assert run_main() == [
        {"transport": "streamable-http", "host": "0.0.0.0", "port": 3714},
    ]
    assert audit.sink_status() == {"sink": "stdout"}


# ---------------------------------------------------------------------------
# An unwritable file sink starts, says so once, and shows on /health
# ---------------------------------------------------------------------------


def test_unwritable_audit_path_starts_and_logs_one_error(
    run_main: Callable[[], list[dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = _unwritable_path(tmp_path)
    monkeypatch.setenv(audit.ENV_PATH, str(path))
    caplog.set_level(logging.ERROR, logger="mcp_unifi.audit")

    calls = run_main()

    assert len(calls) == 1, "an unwritable audit path must not stop the server"
    errors = [r.getMessage() for r in caplog.records if r.name == "mcp_unifi.audit"]
    assert len(errors) == 1
    assert str(path) in errors[0]
    assert "MCP_UNIFI_AUDIT_SINK=stdout" in errors[0]
    assert "MCP_UNIFI_AUDIT_PATH" in errors[0]
    assert audit.sink_status() == {"sink": "file", "writable": False}


def test_writable_audit_path_reports_writable(
    run_main: Callable[[], list[dict[str, Any]]], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="mcp_unifi.audit")
    run_main()
    assert audit.sink_status() == {"sink": "file", "writable": True}
    assert not [r for r in caplog.records if r.name == "mcp_unifi.audit"]


def test_health_reports_an_unwritable_audit_log_without_failing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The body says the audit log is dark; the status code stays 200.

    The Docker HEALTHCHECK and the Helm probes read only the status code, and
    restarting the container would not make the path writable.
    """
    monkeypatch.setattr(audit, "_SINK_STATUS", None, raising=False)
    audit.check_configured_sink(
        transport="streamable-http",
        env={audit.ENV_SINK: "file", audit.ENV_PATH: str(_unwritable_path(tmp_path))},
    )
    settings = Settings(stub_mode=True, log_format="text", auth_required=False)
    with TestClient(server.build_server(settings).http_app()) as client:
        resp = client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["audit"] == {"sink": "file", "writable": False}


# ---------------------------------------------------------------------------
# Bare variable names: still read, now announced (finding F9)
# ---------------------------------------------------------------------------


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "mcp_unifi.config" and r.levelno == logging.WARNING
    ]


def test_bare_name_warns_and_names_the_prefixed_variable(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    caplog.set_level(logging.WARNING, logger="mcp_unifi.config")
    warned = config.log_bare_name_warnings(
        env={"CLIENT_ID": "stray-tool-7f3a", "READONLY": "true"},
        env_file=tmp_path / "missing.env",
    )
    assert sorted(warned) == ["CLIENT_ID", "READONLY"]
    messages = _warnings(caplog)
    assert len(messages) == 2
    assert any("MCP_UNIFI_CLIENT_ID" in m for m in messages)
    assert any("MCP_UNIFI_READONLY" in m for m in messages)
    assert all("later release" in m for m in messages)
    assert not any("stray-tool-7f3a" in m for m in messages), "a value reached the log"


def test_bare_name_in_dotenv_warns(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("auth_required=false\n", encoding="utf-8")
    caplog.set_level(logging.WARNING, logger="mcp_unifi.config")
    assert config.log_bare_name_warnings(env={}, env_file=dotenv) == ["AUTH_REQUIRED"]
    assert "MCP_UNIFI_AUTH_REQUIRED" in _warnings(caplog)[0]


def test_no_warning_when_the_prefixed_name_is_set_or_the_name_is_documented(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    caplog.set_level(logging.WARNING, logger="mcp_unifi.config")
    warned = config.log_bare_name_warnings(
        env={
            "MCP_UNIFI_READONLY": "true",
            "READONLY": "true",
            "FORCE_FULL_TEXT_RESPONSES": "true",
            "STUB_MODE": "true",
        },
        env_file=tmp_path / "missing.env",
    )
    assert warned == []
    assert _warnings(caplog) == []


def test_bare_name_is_still_read_in_this_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Warn, do not drop: a deployment relying on READONLY must stay read-only."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MCP_UNIFI_READONLY", raising=False)
    monkeypatch.setenv("READONLY", "true")
    assert Settings().readonly is True


def test_main_logs_the_bare_name_warning_at_startup(
    run_main: Callable[[], list[dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("READONLY", "true")
    caplog.set_level(logging.WARNING, logger="mcp_unifi.config")
    run_main()
    assert any("MCP_UNIFI_READONLY" in m for m in _warnings(caplog))
