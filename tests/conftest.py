"""Shared fixtures for the mcp-unifi test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from mcp_unifi import audit
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules.network._pending import reset_pending_actions


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
