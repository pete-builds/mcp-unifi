"""A preview token can only be confirmed by the client that asked for it.

Before this, any authenticated client holding a token could run another
client's queued delete. These tests drive the real tools through the server,
switching the authenticated identity the way FastMCP reports it, so they fail
if ``confirm_destructive_action`` goes back to an issuer-blind ``pop``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules.network._pending import get_pending_actions, reset_pending_actions
from mcp_unifi.server import build_server


class _Identity:
    """Stand-in for ``fastmcp.server.dependencies.get_access_token``."""

    def __init__(self) -> None:
        self.client_id: str | None = None

    def __call__(self) -> Any:
        if self.client_id is None:
            return None
        return AccessToken(token="t-" + self.client_id, client_id=self.client_id, scopes=[])


@pytest.fixture
def identity(monkeypatch: pytest.MonkeyPatch) -> _Identity:
    ident = _Identity()
    monkeypatch.setattr("fastmcp.server.dependencies.get_access_token", ident)
    return ident


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    reset_pending_actions()
    yield
    reset_pending_actions()


@pytest.fixture
def stub_server(stub_settings: Settings, stub_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=stub_state)


async def _call(server: FastMCP, name: str, args: dict[str, Any]) -> Any:
    raw = await server.call_tool(name, args)
    return json.loads(raw.content[0].text)


async def test_another_client_cannot_confirm_and_the_owner_still_can(
    stub_server: FastMCP, stub_state: StubState, identity: _Identity
) -> None:
    vlan_id = stub_state.networks[0]["_id"]

    identity.client_id = "alice"
    preview = await _call(stub_server, "delete_vlan", {"network_id": vlan_id})
    token = preview["token"]

    identity.client_id = "mallory"
    refused = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert "error" in refused
    assert "unknown or expired token" in refused["error"]
    assert any(n["_id"] == vlan_id for n in stub_state.networks), "wrong client deleted it"
    assert token in get_pending_actions(), "wrong client consumed the owner's token"

    identity.client_id = "alice"
    done = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert done.get("deleted") is True
    assert not any(n["_id"] == vlan_id for n in stub_state.networks)


async def test_an_unauthenticated_caller_cannot_confirm_an_authenticated_preview(
    stub_server: FastMCP, stub_state: StubState, identity: _Identity
) -> None:
    vlan_id = stub_state.networks[0]["_id"]
    identity.client_id = "alice"
    token = (await _call(stub_server, "delete_vlan", {"network_id": vlan_id}))["token"]

    identity.client_id = None
    refused = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert "error" in refused
    assert token in get_pending_actions()


async def test_stdio_with_no_identity_still_confirms(
    stub_server: FastMCP, stub_state: StubState, identity: _Identity
) -> None:
    """No auth on either call (stdio, or HTTP with auth off) keeps working."""
    vlan_id = stub_state.networks[0]["_id"]
    token = (await _call(stub_server, "delete_vlan", {"network_id": vlan_id}))["token"]
    done = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert done.get("deleted") is True


async def test_the_issuer_is_recorded_on_the_pending_action(
    stub_server: FastMCP, stub_state: StubState, identity: _Identity
) -> None:
    identity.client_id = "alice"
    vlan_id = stub_state.networks[0]["_id"]
    token = (await _call(stub_server, "delete_vlan", {"network_id": vlan_id}))["token"]
    pending = get_pending_actions().get(token)
    assert pending is not None
    assert pending.issuer == "alice"


def test_the_tool_description_states_the_rule(stub_server: FastMCP) -> None:
    """FastMCP drops everything after ``Args:``; the rule must sit above it."""
    import asyncio

    tool = asyncio.run(stub_server.get_tool("confirm_destructive_action"))
    assert tool is not None
    assert "Only the client that requested the preview can confirm it" in (tool.description or "")
