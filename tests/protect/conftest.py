"""Protect-module test fixtures.

Mirrors ``tests/network/conftest.py``: builds a FastMCP server with the
Protect module enabled, injecting a fresh :class:`ProtectStubState` so each
test sees a deterministic seeded controller. The ``MCP_UNIFI_MODULES_ENABLED``
env var is flipped at fixture-setup time to ``"protect"`` (Network is not
needed for these tests and skipping it keeps the tool surface focused).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.protect_stubs import ProtectStubState, make_protect_stub_state
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server


def _text(result: Any) -> str:
    """Extract the text payload from a FastMCP ToolResult."""
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


@pytest.fixture
def protect_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Stub-mode settings with the Protect module enabled.

    Network tools are skipped so per-test tool surface is just Protect; this
    keeps fixture build time small and avoids accidental cross-talk with
    Network state.
    """
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
        "MCP_UNIFI_CONTROLLERS_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "protect")
    yield Settings(stub_mode=True, log_format="text")


@pytest.fixture
def stub_protect_state() -> ProtectStubState:
    """Fresh seeded Protect stub state per test."""
    return make_protect_stub_state()


@pytest.fixture
def protect_registry(protect_settings: Settings, stub_protect_state: ProtectStubState) -> FastMCP:
    """FastMCP server with the Protect module wired and a fresh stub state.

    Returns the server (not the registry directly) so test bodies use the same
    ``_call(server, tool, args)`` pattern as the Network tests.
    """
    return build_server(protect_settings, protect_stub=stub_protect_state)
