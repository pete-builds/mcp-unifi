"""Tests for ``mcp_unifi.modules.network.honeypot``.

Honeypots live as a list inside the ``ips`` per-key setting (verified
against UCG-Fiber fw 5.1.12.33296). These tests cover both the stub
in-memory list mutations and the live read-modify-write wire pattern.
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


async def test_list_honeypots_stub_empty(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_honeypots")
    assert result["enabled"] is False
    assert result["honeypots"] == []


async def test_create_honeypot_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_honeypot",
        {"network_id": net_id, "ip": "192.168.1.50"},
    )
    assert result["network_id"] == net_id
    assert result["ip"] == "192.168.1.50"
    assert result["id"] == f"{net_id}:192.168.1.50"

    listed = await _call(stub_server, "list_honeypots")
    assert listed["enabled"] is True
    assert len(listed["honeypots"]) == 1
    assert listed["honeypots"][0]["ip"] == "192.168.1.50"


async def test_create_honeypot_rejects_duplicate(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    await _call(
        stub_server,
        "create_honeypot",
        {"network_id": net_id, "ip": "192.168.1.51"},
    )
    result = await _call(
        stub_server,
        "create_honeypot",
        {"network_id": net_id, "ip": "192.168.1.51"},
    )
    assert "error" in result
    assert "already exists" in result["error"]


async def test_create_honeypot_invalid_ip(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_honeypot",
        {"network_id": net_id, "ip": "not-an-ip"},
    )
    assert "error" in result


async def test_create_honeypot_unknown_network(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_honeypot",
        {"network_id": "ghost", "ip": "10.0.0.5"},
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_delete_honeypot_preview_then_confirm(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    created = await _call(
        stub_server,
        "create_honeypot",
        {"network_id": net_id, "ip": "192.168.1.52"},
    )

    preview = await _call(stub_server, "delete_honeypot", {"id": created["id"]})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == created["id"]
    # Preview must not delete.
    assert any(
        h.get("ip_address") == "192.168.1.52" for h in stub_state.settings["ips"]["honeypot"]
    )

    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["honeypot_id"] == created["id"]
    assert stub_state.settings["ips"]["honeypot"] == []
    assert stub_state.settings["ips"]["honeypot_enabled"] is False


async def test_delete_honeypot_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_honeypot", {"id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_honeypots(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/setting/ips").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "ips123",
                        "key": "ips",
                        "honeypot_enabled": True,
                        "honeypot": [
                            {
                                "network_id": "net-iot",
                                "ip_address": "10.0.50.2",
                                "version": "v4",
                            }
                        ],
                    }
                ]
            },
        )
    )
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "net-iot", "name": "IoT"}]})
    )
    result = await _call(real_server, "list_honeypots")
    assert result["enabled"] is True
    assert len(result["honeypots"]) == 1
    assert result["honeypots"][0]["network_name"] == "IoT"
    assert result["honeypots"][0]["ip"] == "10.0.50.2"


@respx.mock
async def test_real_create_honeypot_appends_and_writes(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "net-iot", "name": "IoT"}]})
    )
    respx.get(f"{BASE}/rest/setting/ips").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "ips123",
                        "key": "ips",
                        "honeypot_enabled": False,
                        "honeypot": [],
                    }
                ]
            },
        )
    )
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "ips123", "key": "ips"}]})

    respx.post(f"{BASE}/set/setting/ips").mock(side_effect=capture)

    result = await _call(
        real_server,
        "create_honeypot",
        {"network_id": "net-iot", "ip": "10.0.50.2"},
    )
    assert result["ip"] == "10.0.50.2"
    assert captured["body"]["honeypot_enabled"] is True
    assert len(captured["body"]["honeypot"]) == 1
    assert captured["body"]["honeypot"][0]["ip_address"] == "10.0.50.2"
    assert captured["body"]["honeypot"][0]["network_id"] == "net-iot"
