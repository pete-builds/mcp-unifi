"""Network-module-scoped fixtures shared across split test files.

When ``tests/test_tools.py`` was split per source module (Step 5), the
``stub_server`` and ``real_server`` fixtures plus the ``BASE`` URL constant
moved here so every per-resource file can import them via pytest's standard
fixture injection. Test bodies are unchanged from the pre-split file.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState, make_stub_state
from mcp_unifi.clients.unifi import UniFiClient
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.dispatcher import build_registry, register_modules
from mcp_unifi.server import build_server

BASE = "https://gateway.test:443/proxy/network/api/s/default"


def _text(result: Any) -> str:
    """Extract the text payload from a FastMCP ToolResult."""
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


@pytest.fixture
def stub_server(stub_settings: Settings, stub_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=stub_state)


@pytest.fixture
async def real_server(real_settings: Settings) -> AsyncIterator[FastMCP]:
    # Step 3: build the client from settings.controllers["default"] (which
    # the legacy unifi_* env vars auto-promote into). The dispatcher then
    # accepts the client via the unifi= override on the "default" name.
    default_ctrl = next(c for c in real_settings.controllers if c.name == "default")
    client = UniFiClient(
        host=default_ctrl.host,
        api_key=default_ctrl.api_key.get_secret_value(),
        port=default_ctrl.port,
        site=default_ctrl.site,
        verify_ssl=default_ctrl.verify_ssl,
    )
    server = build_server(real_settings, unifi=client)
    yield server
    await client.aclose()


# ---------------------------------------------------------------------------
# Multi-site fixtures (Step 5, Part B)
# ---------------------------------------------------------------------------


def _seed_home_state() -> StubState:
    """Stub state with a recognizable 'home' marker.

    Renames the seed gateway so multi-site tests can prove tools called with
    ``controller="home"`` saw the home state and not the office state.
    """
    state = make_stub_state()
    state.devices[0]["name"] = "Home Gateway"
    state.networks[0]["name"] = "Home Default"
    return state


def _seed_office_state() -> StubState:
    """Stub state with a recognizable 'office' marker."""
    state = make_stub_state()
    state.devices[0]["name"] = "Office Gateway"
    state.networks[0]["name"] = "Office Default"
    return state


@pytest.fixture
def two_controller_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Stub-mode settings with two named controllers ('home' and 'office')."""
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
    return Settings(
        stub_mode=True,
        log_format="text",
        controllers=[
            ControllerConfig(name="home", host="stub-home", api_key="stub-home-key"),
            ControllerConfig(name="office", host="stub-office", api_key="stub-office-key"),
        ],
    )


@pytest.fixture
def two_controller_states() -> dict[str, StubState]:
    """Two distinct seeded stub states keyed by controller name."""
    return {"home": _seed_home_state(), "office": _seed_office_state()}


@pytest.fixture
def multi_site_server(
    two_controller_settings: Settings,
    two_controller_states: dict[str, StubState],
) -> FastMCP:
    """FastMCP server wired with two controllers, each with its own state."""
    from mcp_unifi.backends import StubBackend

    overrides = {
        name: StubBackend(state) for name, state in two_controller_states.items()
    }
    registry = build_registry(two_controller_settings, stub_overrides=overrides)
    mcp = FastMCP("UniFi-MultiSite-Test")
    register_modules(mcp, two_controller_settings, registry)
    return mcp
