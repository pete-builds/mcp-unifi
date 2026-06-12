"""Tests for the Dynamic DNS tools in
``mcp_unifi.modules.network.dynamic_dns``.

The stub seeds Dynamic DNS empty (matching the live gateway), so the stub
tests exercise the full create -> read -> update -> delete round-trip from an
empty start. Real-mode tests assert the legacy ``/rest/dynamicdns`` wiring and
that the provider password is redacted in dry-run previews.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

_CREATE_ARGS = {
    "service": "namecheap",
    "host_name": "home.example.com",
    "login": "example.com",
    "password": "dyndns-token-value",
}


# ---------------------------------------------------------------------------
# Stub mode — empty start, then round-trip
# ---------------------------------------------------------------------------


async def test_list_dynamic_dns_starts_empty(stub_server: FastMCP) -> None:
    entries = await _call(stub_server, "list_dynamic_dns")
    assert entries == []


async def test_create_dynamic_dns_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(stub_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    assert result["service"] == "namecheap"
    assert result["host_name"] == "home.example.com"
    assert result["x_password"] == "dyndns-token-value"
    assert result["interface"] == "wan"
    assert result["enabled"] is True
    assert len(stub_state.list_dynamic_dns()) == 1


async def test_create_dynamic_dns_with_custom_server(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_dynamic_dns",
        {**_CREATE_ARGS, "service": "custom", "server": "ddns.example.net"},
    )
    assert result["server"] == "ddns.example.net"


async def test_create_dynamic_dns_dry_run_redacts_password(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    result = await _call(stub_server, "create_dynamic_dns", {**_CREATE_ARGS, "dry_run": True})
    assert result["dry_run"] is True
    assert result["would_create"]["dynamic_dns"]["x_password"] == "[REDACTED]"
    assert "dyndns-token-value" not in json.dumps(result)
    assert stub_state.list_dynamic_dns() == []


async def test_get_dynamic_dns_details_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    created = await _call(stub_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    result = await _call(stub_server, "get_dynamic_dns_details", {"ddns_id": created["_id"]})
    assert result["_id"] == created["_id"]
    assert result["host_name"] == "home.example.com"


async def test_get_dynamic_dns_details_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_dynamic_dns_details", {"ddns_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_update_dynamic_dns_stub(stub_server: FastMCP) -> None:
    created = await _call(stub_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    result = await _call(
        stub_server,
        "update_dynamic_dns",
        {"ddns_id": created["_id"], "updates": {"enabled": False}},
    )
    assert result["enabled"] is False
    assert result["host_name"] == "home.example.com"


async def test_update_dynamic_dns_dry_run_redacts_password(stub_server: FastMCP) -> None:
    created = await _call(stub_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    result = await _call(
        stub_server,
        "update_dynamic_dns",
        {
            "ddns_id": created["_id"],
            "updates": {"x_password": "new-secret-token"},
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    assert result["would_update"]["patch"]["x_password"] == "[REDACTED]"
    assert "new-secret-token" not in json.dumps(result)


async def test_update_dynamic_dns_empty_updates(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "update_dynamic_dns", {"ddns_id": "x", "updates": {}})
    assert "error" in result


async def test_update_dynamic_dns_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_dynamic_dns",
        {"ddns_id": "ghost", "updates": {"enabled": False}},
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_delete_dynamic_dns_round_trip(stub_server: FastMCP, stub_state: StubState) -> None:
    created = await _call(stub_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    did = created["_id"]
    preview = await _call(stub_server, "delete_dynamic_dns", {"ddns_id": did})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == did
    assert any(d["_id"] == did for d in stub_state.list_dynamic_dns())  # not deleted yet
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["ddns_id"] == did
    assert not any(d["_id"] == did for d in stub_state.list_dynamic_dns())


async def test_delete_dynamic_dns_dry_run(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_dynamic_dns", {"ddns_id": "x", "dry_run": True})
    assert result["dry_run"] is True
    assert result["would_delete"]["ddns_id"] == "x"


async def test_delete_dynamic_dns_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_dynamic_dns", {"ddns_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_dynamic_dns(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/dynamicdns").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "dd1", "host_name": "h"}]})
    )
    result = await _call(real_server, "list_dynamic_dns")
    assert result[0]["_id"] == "dd1"


@respx.mock
async def test_real_create_dynamic_dns(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "dd2"}]})

    respx.post(f"{BASE}/rest/dynamicdns").mock(side_effect=capture)
    result = await _call(real_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    assert result["_id"] == "dd2"
    assert captured["body"]["service"] == "namecheap"
    assert captured["body"]["host_name"] == "home.example.com"
    assert captured["body"]["x_password"] == "dyndns-token-value"


@respx.mock
async def test_real_update_dynamic_dns(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/dynamicdns/dd1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "dd1", "enabled": False}]})
    )
    result = await _call(
        real_server, "update_dynamic_dns", {"ddns_id": "dd1", "updates": {"enabled": False}}
    )
    assert result["enabled"] is False


@respx.mock
async def test_real_delete_dynamic_dns(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/dynamicdns").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "dd1", "host_name": "h"}]})
    )
    respx.delete(f"{BASE}/rest/dynamicdns/dd1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_dynamic_dns", {"ddns_id": "dd1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


@respx.mock
async def test_real_list_dynamic_dns_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/dynamicdns").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_dynamic_dns")
    assert "error" in result


@respx.mock
async def test_real_create_dynamic_dns_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/dynamicdns").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "create_dynamic_dns", dict(_CREATE_ARGS))
    assert "error" in result


@respx.mock
async def test_real_update_dynamic_dns_handles_500(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/dynamicdns/dd1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server, "update_dynamic_dns", {"ddns_id": "dd1", "updates": {"enabled": False}}
    )
    assert "error" in result


@respx.mock
async def test_real_get_dynamic_dns_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/dynamicdns").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_dynamic_dns_details", {"ddns_id": "dd1"})
    assert "error" in result


@respx.mock
async def test_real_delete_dynamic_dns_handles_500_on_lookup(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/dynamicdns").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "delete_dynamic_dns", {"ddns_id": "dd1"})
    assert "error" in result
