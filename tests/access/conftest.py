"""Access-module test fixtures.

Mirrors ``tests/protect/conftest.py``: builds a FastMCP server with the
Access module enabled, injecting a fresh :class:`AccessStubState` so each
test sees a deterministic seeded controller. The ``MCP_UNIFI_MODULES_ENABLED``
env var is flipped at fixture-setup time to ``"access"`` (Network and
Protect are not needed for these tests).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState, make_access_stub_state
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server


def _text(result: Any) -> str:
    """Extract the text payload from a FastMCP ToolResult."""
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


@pytest.fixture
def access_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Stub-mode settings with the Access module enabled."""
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "UNIFI_ACCESS_HOST",
        "UNIFI_ACCESS_API_KEY",
        "UNIFI_ACCESS_PORT",
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
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "access")
    yield Settings(stub_mode=True, log_format="text", auth_required=False)


@pytest.fixture
def stub_access_state() -> AccessStubState:
    """Fresh seeded Access stub state per test."""
    return make_access_stub_state()


@pytest.fixture
def access_registry(access_settings: Settings, stub_access_state: AccessStubState) -> FastMCP:
    """FastMCP server with the Access module wired and a fresh stub state."""
    return build_server(access_settings, access_stub=stub_access_state)
