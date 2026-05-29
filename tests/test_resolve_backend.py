"""Tests for :func:`resolve_backend`, the tool-facing backend resolver.

Tool bodies catch :class:`UniFiError` and return a formatted ``err(...)``
envelope. The registry getters, however, raise dispatcher-layer errors that
are *siblings* of ``UniFiError`` (``AccessNotAvailableError``,
``ProtectNotAvailableError``, ``UnknownControllerError``), so a tool that
called a getter directly would let those escape its handler and surface as a
raw framework error. ``resolve_backend`` translates them to ``UniFiError`` so
every tool's existing ``except UniFiError`` path covers them.

These tests pin both halves: the unit translation, and the end-to-end result
that an access tool now returns an error envelope (not a raised exception)
when the module is enabled but no Access backend was wired.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.backends import AccessStubBackend, StubBackend
from mcp_unifi.clients.access_stubs import make_access_stub_state
from mcp_unifi.clients.stubs import make_stub_state
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.dispatcher import ControllerRegistry, resolve_backend
from mcp_unifi.server import build_server


def test_missing_access_backend_becomes_unifierror() -> None:
    """Access module enabled but no Access backend → UniFiError, not AccessNotAvailableError."""
    registry = ControllerRegistry({"default": StubBackend(make_stub_state())})
    with pytest.raises(UniFiError) as excinfo:
        resolve_backend(registry, "default", "access")
    # The clean operator-facing message is preserved.
    assert "Access" in str(excinfo.value)


def test_unknown_controller_becomes_unifierror() -> None:
    """A bad controller name surfaces as UniFiError so the tool handler catches it."""
    registry = ControllerRegistry(
        {"default": StubBackend(make_stub_state())},
        access_backends={"default": AccessStubBackend(make_access_stub_state())},
    )
    with pytest.raises(UniFiError):
        resolve_backend(registry, "typo", "access")
    with pytest.raises(UniFiError):
        resolve_backend(registry, "typo")  # network kind (default)


def test_happy_path_returns_backend() -> None:
    """A configured controller resolves to its backend unchanged."""
    network = StubBackend(make_stub_state())
    access = AccessStubBackend(make_access_stub_state())
    registry = ControllerRegistry({"default": network}, access_backends={"default": access})
    assert resolve_backend(registry, "default") is network
    assert resolve_backend(registry, "default", "access") is access


async def test_access_tool_returns_err_envelope_without_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: an access tool with no Access backend returns err(), never raises.

    Reproduces the v0.10 gap: the ``access`` module is enabled (so its tools are
    registered) but real mode has no ``access_*`` config, so the registry holds
    no Access backend. Before the fix, the resulting AccessNotAvailableError
    escaped the tool's ``except UniFiError`` and surfaced as a framework error.
    """
    for var in ("MCP_UNIFI_CONTROLLERS_FILE", "UNIFI_HOST", "UNIFI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "access")
    # Stub mode keeps the test offline, but we inject no access stub, so the
    # registry has Network + Access stub backends only if build wires them.
    # Force the missing-backend path by building real-mode settings with a
    # network controller but no access_* fields.
    settings = Settings(
        stub_mode=False,
        log_format="text",
        auth_required=False,
        controllers=[{"name": "default", "host": "example", "api_key": "k", "port": 443}],
    )
    server: FastMCP = build_server(settings)

    raw = await server.call_tool("list_doors", {})
    payload: dict[str, Any] = json.loads(raw.content[0].text)
    assert "error" in payload
    assert "Access" in payload["error"]
