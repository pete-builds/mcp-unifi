"""Tests for ``mcp_unifi.modules.network.teleport``.

Only the two operations the local UniFi Network API supports
(``get_teleport_config``, ``set_teleport_enabled``) are exercised. The
client/invitation/revoke endpoints are not implemented because the
controller does not expose them via the local API on fw 5.1.12.33296.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_get_teleport_config_stub_defaults(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_teleport_config")
    assert result["enabled"] is False
    assert result["clients_via_local_api"] is False
    assert isinstance(result["notes"], list)
    assert any("mobile app" in n.lower() for n in result["notes"])


async def test_set_teleport_enabled_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(stub_server, "set_teleport_enabled", {"enabled": True})
    assert result["enabled"] is True
    assert stub_state.settings["teleport"]["enabled"] is True

    result = await _call(stub_server, "set_teleport_enabled", {"enabled": False})
    assert result["enabled"] is False
    assert stub_state.settings["teleport"]["enabled"] is False


async def test_set_teleport_enabled_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    before = dict(stub_state.settings["teleport"])
    result = await _call(stub_server, "set_teleport_enabled", {"enabled": True, "dry_run": True})
    assert result["dry_run"] is True
    assert result["would_patch"]["setting_key"] == "teleport"
    assert result["would_patch"]["patch"]["enabled"] is True
    assert stub_state.settings["teleport"] == before


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_teleport_config(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/setting/teleport").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "tp123", "key": "teleport", "enabled": True}]},
        )
    )
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "wg1",
                        "name": "One-Click VPN",
                        "purpose": "remote-user-vpn",
                        "vpn_type": "wireguard-server",
                        "ip_subnet": "192.168.10.1/24",
                        "local_port": 51820,
                        "external_id": "abc-123",
                        "enabled": True,
                    },
                    {"_id": "lan", "name": "Default", "purpose": "corporate"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_teleport_config")
    assert result["enabled"] is True
    assert result["clients_via_local_api"] is False
    assert len(result["vpn_networks"]) == 1
    assert result["vpn_networks"][0]["name"] == "One-Click VPN"


@respx.mock
async def test_real_set_teleport_enabled(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"data": [{"_id": "tp123", "key": "teleport", "enabled": True}]},
        )

    respx.post(f"{BASE}/set/setting/teleport").mock(side_effect=capture)
    result = await _call(real_server, "set_teleport_enabled", {"enabled": True})
    assert result["enabled"] is True
    assert captured["body"] == {"enabled": True}


@respx.mock
async def test_real_set_teleport_enabled_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/set/setting/teleport").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "set_teleport_enabled", {"enabled": True})
    assert "error" in result
