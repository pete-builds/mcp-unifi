"""Tests for the static-routing tools in ``mcp_unifi.modules.network.routing``.

Covers read (list + details), create (with distance validation + dry_run),
update, the preview-then-confirm delete round-trip, and error envelopes.
Real-mode tests assert the legacy ``/rest/routing`` wiring.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode — reads
# ---------------------------------------------------------------------------


async def test_list_routes_stub(stub_server: FastMCP) -> None:
    routes = await _call(stub_server, "list_routes")
    assert isinstance(routes, list)
    assert routes[0]["type"] == "static-route"
    assert "static-route_network" in routes[0]


async def test_get_route_details_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_routes()[0]["_id"]
    result = await _call(stub_server, "get_route_details", {"route_id": rid})
    assert result["_id"] == rid


async def test_get_route_details_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_route_details", {"route_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Stub mode — create
# ---------------------------------------------------------------------------


async def test_create_route_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_route",
        {
            "name": "Lab via firewall",
            "destination": "10.99.0.0/24",
            "next_hop": "192.168.1.254",
        },
    )
    assert result["name"] == "Lab via firewall"
    assert result["static-route_network"] == "10.99.0.0/24"
    assert result["static-route_nexthop"] == "192.168.1.254"
    assert result["static-route_distance"] == 1
    assert result["type"] == "static-route"


async def test_create_route_rejects_bad_distance(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_route",
        {
            "name": "X",
            "destination": "10.0.0.0/24",
            "next_hop": "10.0.0.1",
            "distance": 999,
        },
    )
    assert "error" in result
    assert "distance" in result["error"]


async def test_create_route_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    before = len(stub_state.list_routes())
    result = await _call(
        stub_server,
        "create_route",
        {
            "name": "Lab",
            "destination": "10.99.0.0/24",
            "next_hop": "192.168.1.254",
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    assert result["would_create"]["route"]["static-route_network"] == "10.99.0.0/24"
    assert len(stub_state.list_routes()) == before


# ---------------------------------------------------------------------------
# Stub mode — update
# ---------------------------------------------------------------------------


async def test_update_route_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_routes()[0]["_id"]
    result = await _call(
        stub_server,
        "update_route",
        {"route_id": rid, "updates": {"enabled": False}},
    )
    assert result["enabled"] is False


async def test_update_route_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_routes()[0]["_id"]
    result = await _call(
        stub_server,
        "update_route",
        {"route_id": rid, "updates": {"static-route_distance": 5}, "dry_run": True},
    )
    assert result["dry_run"] is True
    # Unchanged on the stub.
    assert stub_state.list_routes()[0]["static-route_distance"] == 1


async def test_update_route_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "update_route", {"route_id": "ghost", "updates": {"enabled": False}}
    )
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Stub mode — delete (preview-then-confirm)
# ---------------------------------------------------------------------------


async def test_delete_route_round_trip(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_routes()[0]["_id"]
    preview = await _call(stub_server, "delete_route", {"route_id": rid})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == rid
    assert any(r["_id"] == rid for r in stub_state.list_routes())  # not deleted yet
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["route_id"] == rid
    assert not any(r["_id"] == rid for r in stub_state.list_routes())


async def test_delete_route_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    # The dry run resolves the route like the preview does, so it needs a real id.
    route_id = stub_state.routes[0]["_id"]
    result = await _call(stub_server, "delete_route", {"route_id": route_id, "dry_run": True})
    assert result["dry_run"] is True
    assert result["would_delete"]["route_id"] == route_id


async def test_delete_route_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_route", {"route_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_routes(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/routing").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "rt1"}]})
    )
    result = await _call(real_server, "list_routes")
    assert result[0]["_id"] == "rt1"


@respx.mock
async def test_real_create_route(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "rt2"}]})

    respx.post(f"{BASE}/rest/routing").mock(side_effect=capture)
    result = await _call(
        real_server,
        "create_route",
        {"name": "Lab", "destination": "10.99.0.0/24", "next_hop": "192.168.1.254"},
    )
    assert result["_id"] == "rt2"
    assert captured["body"]["static-route_network"] == "10.99.0.0/24"
    assert captured["body"]["type"] == "static-route"


@respx.mock
async def test_real_update_route(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/routing/rt1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "rt1", "enabled": False}]})
    )
    result = await _call(
        real_server, "update_route", {"route_id": "rt1", "updates": {"enabled": False}}
    )
    assert result["enabled"] is False


@respx.mock
async def test_real_delete_route(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/routing").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "rt1", "name": "Lab"}]})
    )
    respx.delete(f"{BASE}/rest/routing/rt1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_route", {"route_id": "rt1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


@respx.mock
async def test_real_list_routes_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/routing").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_routes")
    assert "error" in result


@respx.mock
async def test_real_create_route_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/routing").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_route",
        {"name": "X", "destination": "10.0.0.0/24", "next_hop": "10.0.0.1"},
    )
    assert "error" in result


@respx.mock
async def test_real_update_route_handles_500(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/routing/rt1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server, "update_route", {"route_id": "rt1", "updates": {"enabled": False}}
    )
    assert "error" in result


@respx.mock
async def test_real_get_route_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/routing").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_route_details", {"route_id": "rt1"})
    assert "error" in result


@respx.mock
async def test_real_delete_route_handles_500_on_lookup(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/routing").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "delete_route", {"route_id": "rt1"})
    assert "error" in result


# ---------------------------------------------------------------------------
# Input validation (D12)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"destination": "banana"}, "not a CIDR"),
        ({"destination": "10.0.0.0/33"}, "not a CIDR"),
        ({"next_hop": "also banana"}, "not an IP address"),
        ({"distance": 0}, "out of range"),
        ({"distance": 256}, "out of range"),
    ],
)
async def test_create_route_refuses_invalid_fields(
    stub_server: FastMCP, stub_state: StubState, override: dict[str, Any], expected: str
) -> None:
    args = {"name": "r", "destination": "10.99.0.0/24", "next_hop": "192.168.1.254", **override}
    before = list(stub_state.routes)
    for dry_run in (True, False):
        result = await _call(stub_server, "create_route", {**args, "dry_run": dry_run})
        assert expected in result.get("error", ""), result
    assert stub_state.routes == before


async def test_create_route_accepts_ipv6(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_route",
        {"name": "v6", "destination": "2001:db8::/48", "next_hop": "fe80::1", "dry_run": True},
    )
    assert result.get("dry_run") is True, result


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"static-route_distance": 0}, "out of range"),
        ({"static-route_distance": "abc"}, "out of range"),
        ({"static-route_distance": True}, "out of range"),
        ({"static-route_network": "banana"}, "not a CIDR"),
        ({"static-route_nexthop": "nope"}, "not an IP address"),
    ],
)
async def test_update_route_refuses_invalid_fields(
    stub_server: FastMCP, stub_state: StubState, updates: dict[str, Any], expected: str
) -> None:
    """update_route passed any value straight to the controller (D12)."""
    stub_state.routes.append({"_id": "rt-1", "name": "Lab", "static-route_distance": 1})
    for dry_run in (True, False):
        result = await _call(
            stub_server,
            "update_route",
            {"route_id": "rt-1", "updates": updates, "dry_run": dry_run},
        )
        assert expected in result.get("error", ""), result
    assert stub_state.routes[-1]["static-route_distance"] == 1


async def test_update_route_accepts_a_digit_string_distance(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.routes.append({"_id": "rt-1", "name": "Lab"})
    result = await _call(
        stub_server,
        "update_route",
        {"route_id": "rt-1", "updates": {"static-route_distance": "5"}, "dry_run": True},
    )
    assert result.get("dry_run") is True, result
