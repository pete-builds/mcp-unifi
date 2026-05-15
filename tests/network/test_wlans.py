"""Tests for ``mcp_unifi.modules.network.wlans``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import json

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_wlans_stub(stub_server: FastMCP) -> None:
    wlans = await _call(stub_server, "list_wlans")
    assert wlans[0]["name"] == "Home"


async def test_create_wlan_redacts_passphrase(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {
            "name": "TestSSID",
            "passphrase": "supersecret-do-not-leak",
            "network_id": net_id,
        },
    )
    assert result["x_passphrase"] == "[REDACTED]"
    assert "supersecret-do-not-leak" not in json.dumps(result)


async def test_create_wlan_open_security_omits_passphrase(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {
            "name": "OpenSSID",
            "passphrase": "ignored",
            "network_id": net_id,
            "security": "open",
        },
    )
    assert "x_passphrase" not in result


async def test_update_wlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": wlan_id, "updates": {"name": "Renamed", "hide_ssid": True}},
    )
    assert result["name"] == "Renamed"
    assert result["hide_ssid"] is True


async def test_update_wlan_redacts_passphrase(stub_server: FastMCP, stub_state: StubState) -> None:
    """Updating x_passphrase via update_wlan should redact in the response."""
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": wlan_id, "updates": {"x_passphrase": "rotated-secret-xyz"}},
    )
    assert result["x_passphrase"] == "[REDACTED]"
    assert "rotated-secret-xyz" not in json.dumps(result)


async def test_update_wlan_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": "ghost", "updates": {"name": "X"}},
    )
    assert "not found" in result["error"]


async def test_delete_wlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(stub_server, "delete_wlan", {"wlan_id": wlan_id})
    assert result["deleted"] is True
    assert result["wlan_id"] == wlan_id
    assert stub_state.list_wlans() == []


async def test_delete_wlan_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_wlan", {"wlan_id": "ghost"})
    assert result["deleted"] is False


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_wlans(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w"}]})
    )
    result = await _call(real_server, "list_wlans")
    assert result[0]["_id"] == "w"


@respx.mock
async def test_real_create_wlan(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1"}]})
    )
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert result["_id"] == "w1"


@respx.mock
async def test_real_update_wlan(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/wlanconf/w1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "Renamed"}]})
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "w1", "updates": {"name": "Renamed"}},
    )
    assert result["name"] == "Renamed"


@respx.mock
async def test_real_delete_wlan(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_wlan", {"wlan_id": "w1"})
    assert result["deleted"] is True
    assert result["wlan_id"] == "w1"


@respx.mock
async def test_real_update_wlan_handles_404(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/wlanconf/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "missing", "updates": {"name": "X"}},
    )
    assert "error" in result


@respx.mock
async def test_real_delete_wlan_handles_409(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(409, text="in use"))
    result = await _call(real_server, "delete_wlan", {"wlan_id": "w1"})
    assert "error" in result


@respx.mock
async def test_create_wlan_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert "error" in result


@respx.mock
async def test_list_wlans_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_wlans")
    assert "error" in result
