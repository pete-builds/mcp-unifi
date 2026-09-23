"""Shared fixtures for the mcp-unifi test suite."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator

import pytest

from mcp_unifi import audit, telemetry
from mcp_unifi.clients import retry as _retry
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules.network._pending import reset_pending_actions


@pytest.fixture(autouse=True)
def _no_tracing_by_default() -> Iterator[None]:
    """Clear the cached tracer around every test.

    Tracing is opt-in and off by default, so the default state under test must
    be "no tracer". Clearing afterwards too stops a test that installs a fake
    tracer from leaking spans into the next one.
    """
    telemetry.reset_tracer()
    yield
    telemetry.reset_tracer()


@pytest.fixture(autouse=True)
def _fast_retry_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the 5xx-retry backoff so read-path retry tests don't sleep.

    The retry helper waits ``BACKOFF_BASE_SECONDS`` between attempts on a 5xx
    GET. In production that is a short real delay; under test it would add up
    across the many upstream-500 cases, so we drive it to 0.
    """
    monkeypatch.setattr(_retry, "BACKOFF_BASE_SECONDS", 0.0)


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Redirect the audit-log singleton at a per-test tmp file.

    Prevents the test suite from ever writing to the repo's CWD as a side
    effect of any tool call (every tool now emits via the @audited decorator).
    Tests that need to assert on audit contents pin their own sink via
    ``audit.set_audit_log(...)``; this fixture just makes the default safe.
    """
    log_path = tmp_path / "test-audit.jsonl"  # type: ignore[operator]
    monkeypatch.setenv(audit.ENV_SINK, "file")
    monkeypatch.setenv(audit.ENV_PATH, str(log_path))
    audit.set_audit_log(None)
    # Reset the preview-then-confirm pending-actions registry so tokens
    # minted in one test never leak into another.
    reset_pending_actions()
    try:
        yield
    finally:
        audit.set_audit_log(None)
        reset_pending_actions()


#: Every environment variable that shapes ``Settings``. One list, so a test
#: file that wants a clean slate gets the same slate as every other.
UNIFI_ENV_VARS: tuple[str, ...] = (
    "STUB_MODE",
    "UNIFI_HOST",
    "UNIFI_API_KEY",
    "UNIFI_API_KEY_FILE",
    "UNIFI_PORT",
    "UNIFI_SITE",
    "UNIFI_VERIFY_SSL",
    "UNIFI_PINNED_CERT",
    "UNIFI_PROTECT_API",
    "UNIFI_ACCESS_HOST",
    "UNIFI_ACCESS_API_KEY",
    "UNIFI_ACCESS_API_KEY_FILE",
    "UNIFI_ACCESS_PORT",
    "UNIFI_OS_USERNAME",
    "UNIFI_OS_PASSWORD",
    "UNIFI_OS_PASSWORD_FILE",
    "IOT_SUBNET_TEMPLATE",
    "IOT_DHCP_START_OFFSET",
    "IOT_DHCP_STOP_OFFSET",
    "MCP_TRANSPORT",
    "MCP_HOST",
    "MCP_PORT",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "MCP_UNIFI_CONTROLLERS_FILE",
    "MCP_UNIFI_AUTH_TOKENS",
    "MCP_UNIFI_AUTH_TOKEN_FILE",
    "MCP_UNIFI_CLIENT_ID",
    "MCP_UNIFI_AUTH_REQUIRED",
)


@pytest.fixture
def clean_unifi_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing from a developer's shell or ``.env`` may shape the test."""
    for var in UNIFI_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def config_warnings(caplog: pytest.LogCaptureFixture) -> Callable[[], list[str]]:
    """The WARNING lines ``mcp_unifi.config`` has emitted so far, as messages."""
    caplog.set_level(logging.WARNING)

    def _messages() -> list[str]:
        return [
            r.getMessage()
            for r in caplog.records
            if r.name == "mcp_unifi.config" and r.levelno == logging.WARNING
        ]

    return _messages


@pytest.fixture
def stub_state() -> StubState:
    """Fresh in-memory stub state for each test."""
    return StubState()


@pytest.fixture
def stub_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Stub-mode settings with no .env interference."""
    # Make sure nothing leaks from a developer's local .env
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "IOT_SUBNET_TEMPLATE",
        "IOT_DHCP_START_OFFSET",
        "IOT_DHCP_STOP_OFFSET",
        "MCP_TRANSPORT",
        "MCP_HOST",
        "MCP_PORT",
        "LOG_LEVEL",
        "LOG_FORMAT",
        "MCP_UNIFI_CONTROLLERS_FILE",
        "MCP_UNIFI_AUTH_TOKENS",
        "MCP_UNIFI_AUTH_REQUIRED",
    ):
        monkeypatch.delenv(var, raising=False)
    # auth_required defaults to True in v0.9.0+; tests that don't exercise
    # auth want a server that boots cleanly without tokens.
    yield Settings(stub_mode=True, log_format="text", auth_required=False)


@pytest.fixture
def real_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Real-mode settings pointing at a fake gateway for httpx mocking."""
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "IOT_SUBNET_TEMPLATE",
        "IOT_DHCP_START_OFFSET",
        "IOT_DHCP_STOP_OFFSET",
        "MCP_TRANSPORT",
        "MCP_HOST",
        "MCP_PORT",
        "LOG_LEVEL",
        "LOG_FORMAT",
        "MCP_UNIFI_AUTH_TOKENS",
        "MCP_UNIFI_AUTH_REQUIRED",
    ):
        monkeypatch.delenv(var, raising=False)
    yield Settings(
        stub_mode=False,
        unifi_host="gateway.test",
        unifi_port=443,
        unifi_site="default",
        unifi_api_key="test-api-key-1234",
        log_format="text",
        auth_required=False,
    )
