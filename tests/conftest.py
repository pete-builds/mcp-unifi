"""Shared fixtures for the mcp-unifi test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings


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
        "MCP_HOST",
        "MCP_PORT",
        "LOG_LEVEL",
        "LOG_FORMAT",
    ):
        monkeypatch.delenv(var, raising=False)
    yield Settings(stub_mode=True, log_format="text")


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
        "MCP_HOST",
        "MCP_PORT",
        "LOG_LEVEL",
        "LOG_FORMAT",
    ):
        monkeypatch.delenv(var, raising=False)
    yield Settings(
        stub_mode=False,
        unifi_host="gateway.test",
        unifi_port=443,
        unifi_site="default",
        unifi_api_key="test-api-key-1234",
        log_format="text",
    )
