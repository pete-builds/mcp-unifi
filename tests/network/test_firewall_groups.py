"""Tests for the firewall-group tools in ``mcp_unifi.modules.network.firewall``.

Covers read (list + details), create (with type validation), full-PUT
read-modify-write update, the preview-then-confirm delete round-trip, and the
error envelopes for each. Real-mode tests assert the legacy ``/rest/firewallgroup``
wiring and prove update sends the whole record back (read-modify-write).
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
# Stub mode — reads
# ---------------------------------------------------------------------------


async def test_list_firewall_groups_stub(stub_server: FastMCP) -> None:
    groups = await _call(stub_server, "list_firewall_groups")
    assert isinstance(groups, list)
    types = {g["group_type"] for g in groups}
    assert "address-group" in types
    assert "port-group" in types


async def test_get_firewall_group_details_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    gid = stub_state.list_firewall_groups()[0]["_id"]
    result = await _call(stub_server, "get_firewall_group_details", {"group_id": gid})
    assert result["_id"] == gid
    assert "group_members" in result


async def test_get_firewall_group_details_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_firewall_group_details", {"group_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Stub mode — create
# ---------------------------------------------------------------------------


async def test_create_firewall_group_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_firewall_group",
        {
            "name": "IoT Subnets",
            "group_type": "address-group",
            "members": ["10.50.0.0/24", "10.60.0.0/24"],
        },
    )
    assert result["name"] == "IoT Subnets"
    assert result["group_type"] == "address-group"
    assert result["group_members"] == ["10.50.0.0/24", "10.60.0.0/24"]
    assert "_id" in result


async def test_create_firewall_group_rejects_bad_type(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_firewall_group",
        {"name": "X", "group_type": "magic-group", "members": []},
    )
    assert "error" in result
    assert "group_type" in result["error"]


async def test_create_firewall_group_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    before = len(stub_state.list_firewall_groups())
    result = await _call(
        stub_server,
        "create_firewall_group",
        {
            "name": "Web",
            "group_type": "port-group",
            "members": ["80", "443"],
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    assert result["would_create"]["firewall_group"]["group_type"] == "port-group"
    assert len(stub_state.list_firewall_groups()) == before  # nothing created


# ---------------------------------------------------------------------------
# Stub mode — update (read-modify-write)
# ---------------------------------------------------------------------------


async def test_update_firewall_group_members(stub_server: FastMCP, stub_state: StubState) -> None:
    gid = stub_state.list_firewall_groups()[0]["_id"]
    result = await _call(
        stub_server,
        "update_firewall_group",
        {"group_id": gid, "members": ["10.99.0.0/24"]},
    )
    assert result["group_members"] == ["10.99.0.0/24"]
    # group_type preserved by the read-modify-write.
    assert result["group_type"] == "address-group"


async def test_update_firewall_group_dry_run_diff(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    group = stub_state.list_firewall_groups()[0]
    gid = group["_id"]
    original_members = list(group["group_members"])
    result = await _call(
        stub_server,
        "update_firewall_group",
        {"group_id": gid, "name": "Renamed", "dry_run": True},
    )
    assert result["dry_run"] is True
    assert result["would_update"]["after"]["name"] == "Renamed"
    # Unchanged on the stub.
    assert stub_state.list_firewall_groups()[0]["group_members"] == original_members


async def test_update_firewall_group_requires_a_field(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    gid = stub_state.list_firewall_groups()[0]["_id"]
    result = await _call(stub_server, "update_firewall_group", {"group_id": gid})
    assert "error" in result
    assert "at least one" in result["error"]


async def test_update_firewall_group_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "update_firewall_group", {"group_id": "ghost", "name": "X"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Stub mode — delete (preview-then-confirm)
# ---------------------------------------------------------------------------


async def test_delete_firewall_group_round_trip(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    gid = stub_state.list_firewall_groups()[0]["_id"]
    preview = await _call(stub_server, "delete_firewall_group", {"group_id": gid})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == gid
    # Preview must not delete.
    assert any(g["_id"] == gid for g in stub_state.list_firewall_groups())
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["group_id"] == gid
    assert not any(g["_id"] == gid for g in stub_state.list_firewall_groups())


async def test_delete_firewall_group_dry_run(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_firewall_group", {"group_id": "x", "dry_run": True})
    assert result["dry_run"] is True
    assert result["would_delete"]["group_id"] == "x"


async def test_delete_firewall_group_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_firewall_group", {"group_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_firewall_groups(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "g1", "name": "RFC1918"}]})
    )
    result = await _call(real_server, "list_firewall_groups")
    assert result[0]["_id"] == "g1"


@respx.mock
async def test_real_create_firewall_group(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "g2"}]})

    respx.post(f"{BASE}/rest/firewallgroup").mock(side_effect=capture)
    result = await _call(
        real_server,
        "create_firewall_group",
        {"name": "Web", "group_type": "port-group", "members": ["443"]},
    )
    assert result["_id"] == "g2"
    assert captured["body"]["group_type"] == "port-group"
    assert captured["body"]["group_members"] == ["443"]


@respx.mock
async def test_real_update_firewall_group_is_full_put(real_server: FastMCP) -> None:
    """Update must read the record then PUT the whole thing back (RMW)."""
    respx.get(f"{BASE}/rest/firewallgroup").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "g1",
                        "name": "RFC1918",
                        "group_type": "address-group",
                        "group_members": ["10.0.0.0/8"],
                        "site_id": "default",
                    }
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/firewallgroup/g1").mock(
        return_value=httpx.Response(
            200, json={"data": [{"_id": "g1", "group_members": ["10.99.0.0/24"]}]}
        )
    )
    result = await _call(
        real_server,
        "update_firewall_group",
        {"group_id": "g1", "members": ["10.99.0.0/24"]},
    )
    assert result["_id"] == "g1"
    assert put_route.called
    body = json.loads(put_route.calls[0].request.content)
    # Full record sent back: untouched keys preserved, members replaced.
    assert body["group_type"] == "address-group"
    assert body["name"] == "RFC1918"
    assert body["group_members"] == ["10.99.0.0/24"]
    assert "_id" not in body  # _id goes in the URL, not the body


@respx.mock
async def test_real_delete_firewall_group(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "g1", "name": "RFC1918"}]})
    )
    respx.delete(f"{BASE}/rest/firewallgroup/g1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_firewall_group", {"group_id": "g1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


@respx.mock
async def test_real_list_firewall_groups_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_firewall_groups")
    assert "error" in result


@respx.mock
async def test_real_create_firewall_group_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/firewallgroup").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_firewall_group",
        {"name": "X", "group_type": "address-group", "members": []},
    )
    assert "error" in result


@respx.mock
async def test_real_update_firewall_group_handles_500_on_lookup(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "update_firewall_group", {"group_id": "g1", "name": "X"})
    assert "error" in result


@respx.mock
async def test_real_update_firewall_group_handles_500_on_put(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "g1", "name": "X", "group_type": "address-group"}]},
        )
    )
    respx.put(f"{BASE}/rest/firewallgroup/g1").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "update_firewall_group", {"group_id": "g1", "name": "Y"})
    assert "error" in result


@respx.mock
async def test_real_get_firewall_group_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_firewall_group_details", {"group_id": "g1"})
    assert "error" in result


@respx.mock
async def test_real_delete_firewall_group_handles_500_on_lookup(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallgroup").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "delete_firewall_group", {"group_id": "g1"})
    assert "error" in result
