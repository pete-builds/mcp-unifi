"""Tests for ``mcp_unifi.modules.network.port_profiles``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_port_profiles_stub(stub_server: FastMCP) -> None:
    profiles = await _call(stub_server, "list_port_profiles")
    assert {p["name"] for p in profiles} == {"All", "Disabled"}


async def test_create_port_profile_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "create_port_profile",
        {"name": "PoE Cameras", "poe_mode": "auto", "forward": "native"},
    )
    assert result["name"] == "PoE Cameras"
    assert result["poe_mode"] == "auto"
    assert any(p["_id"] == result["_id"] for p in stub_state.list_port_profiles())


async def test_create_port_profile_with_tagged_vlans(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_port_profile",
        {
            "name": "Trunk",
            "native_networkconf_id": "n1",
            "tagged_networkconf_ids": ["n2", "n3"],
        },
    )
    assert result["tagged_networkconf_ids"] == ["n2", "n3"]
    assert result["native_networkconf_id"] == "n1"


async def test_update_port_profile_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    profile_id = stub_state.list_port_profiles()[0]["_id"]
    result = await _call(
        stub_server,
        "update_port_profile",
        {"profile_id": profile_id, "updates": {"poe_mode": "off"}},
    )
    assert result["poe_mode"] == "off"


async def test_update_port_profile_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_port_profile",
        {"profile_id": "ghost", "updates": {"poe_mode": "off"}},
    )
    assert "not found" in result["error"]


async def test_delete_port_profile_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    profile_id = stub_state.list_port_profiles()[0]["_id"]
    # v0.7.0: preview first, then confirm.
    preview = await _call(stub_server, "delete_port_profile", {"profile_id": profile_id})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == profile_id
    result = await _call(
        stub_server, "confirm_destructive_action", {"token": preview["token"]}
    )
    assert result["deleted"] is True


async def test_delete_port_profile_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_port_profile", {"profile_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_port_profiles(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p"}]})
    )
    result = await _call(real_server, "list_port_profiles")
    assert result[0]["_id"] == "p"


@respx.mock
async def test_list_port_profiles_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_port_profiles")
    assert "error" in result


@respx.mock
async def test_real_create_port_profile(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/portconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p1", "name": "PoE"}]})
    )
    result = await _call(real_server, "create_port_profile", {"name": "PoE"})
    assert result["_id"] == "p1"


@respx.mock
async def test_real_update_port_profile(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/portconf/p1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p1", "poe_mode": "off"}]})
    )
    result = await _call(
        real_server,
        "update_port_profile",
        {"profile_id": "p1", "updates": {"poe_mode": "off"}},
    )
    assert result["poe_mode"] == "off"


@respx.mock
async def test_real_delete_port_profile(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p1", "name": "PoE"}]})
    )
    respx.delete(f"{BASE}/rest/portconf/p1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_port_profile", {"profile_id": "p1"})
    assert preview["preview"] is True
    result = await _call(
        real_server, "confirm_destructive_action", {"token": preview["token"]}
    )
    assert result["deleted"] is True
