"""Tests for the v2 traffic-policy tools in ``mcp_unifi.modules.network.traffic``.

Traffic rules and routes live on the v2 surface
(``/proxy/network/v2/api/site/<site>/...``) which returns a **bare list**, so
the real-mode tests assert that the client parses the bare-list shape and that
update/toggle do a read-modify-write full PUT.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# The v2 surface sits at a different prefix than the legacy ``/api/s`` BASE.
V2_BASE = BASE.replace("/api/s/default", "/v2/api/site/default")


# ---------------------------------------------------------------------------
# Traffic rules — stub reads
# ---------------------------------------------------------------------------


async def test_list_traffic_rules_stub(stub_server: FastMCP) -> None:
    rules = await _call(stub_server, "list_traffic_rules")
    assert isinstance(rules, list)
    assert rules[0]["action"] in {"BLOCK", "ALLOW"}


async def test_get_traffic_rule_details_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_rules()[0]["_id"]
    result = await _call(stub_server, "get_traffic_rule_details", {"rule_id": rid})
    assert result["_id"] == rid


async def test_get_traffic_rule_details_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_traffic_rule_details", {"rule_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Traffic rules — stub create / update / toggle
# ---------------------------------------------------------------------------


async def test_create_traffic_rule_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_traffic_rule",
        {"rule": {"action": "ALLOW", "matching_target": "DOMAIN", "enabled": True}},
    )
    assert result["action"] == "ALLOW"
    assert result["matching_target"] == "DOMAIN"
    assert "_id" in result


async def test_create_traffic_rule_requires_object(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "create_traffic_rule", {"rule": {}})
    assert "error" in result


async def test_create_traffic_rule_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    before = len(stub_state.list_traffic_rules())
    result = await _call(
        stub_server,
        "create_traffic_rule",
        {"rule": {"action": "BLOCK", "matching_target": "INTERNET"}, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert len(stub_state.list_traffic_rules()) == before


async def test_update_traffic_rule_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_rules()[0]["_id"]
    result = await _call(
        stub_server,
        "update_traffic_rule",
        {"rule_id": rid, "updates": {"action": "ALLOW"}},
    )
    assert result["action"] == "ALLOW"
    # Read-modify-write preserved the other fields.
    assert "matching_target" in result


async def test_update_traffic_rule_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_rules()[0]["_id"]
    result = await _call(
        stub_server,
        "update_traffic_rule",
        {"rule_id": rid, "updates": {"action": "ALLOW"}, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert stub_state.list_traffic_rules()[0]["action"] == "BLOCK"  # unchanged


async def test_update_traffic_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "update_traffic_rule", {"rule_id": "ghost", "updates": {"action": "ALLOW"}}
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_toggle_traffic_rule_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_rules()[0]["_id"]
    result = await _call(stub_server, "toggle_traffic_rule", {"rule_id": rid, "enabled": False})
    assert result["enabled"] is False


async def test_toggle_traffic_rule_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_rules()[0]["_id"]
    result = await _call(
        stub_server,
        "toggle_traffic_rule",
        {"rule_id": rid, "enabled": False, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert result["would_update"]["after"]["enabled"] is False
    assert stub_state.list_traffic_rules()[0]["enabled"] is True  # unchanged


async def test_toggle_traffic_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "toggle_traffic_rule", {"rule_id": "ghost", "enabled": False})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Traffic routes — stub reads
# ---------------------------------------------------------------------------


async def test_list_traffic_routes_stub(stub_server: FastMCP) -> None:
    routes = await _call(stub_server, "list_traffic_routes")
    assert isinstance(routes, list)
    assert "kill_switch_enabled" in routes[0]


async def test_get_traffic_route_details_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_routes()[0]["_id"]
    result = await _call(stub_server, "get_traffic_route_details", {"route_id": rid})
    assert result["_id"] == rid


async def test_get_traffic_route_details_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_traffic_route_details", {"route_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Traffic routes — stub update / toggle
# ---------------------------------------------------------------------------


async def test_update_traffic_route_kill_switch(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    rid = stub_state.list_traffic_routes()[0]["_id"]
    result = await _call(
        stub_server,
        "update_traffic_route",
        {"route_id": rid, "kill_switch_enabled": True},
    )
    assert result["kill_switch_enabled"] is True


async def test_update_traffic_route_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_routes()[0]["_id"]
    result = await _call(
        stub_server,
        "update_traffic_route",
        {"route_id": rid, "kill_switch_enabled": True, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert result["would_update"]["patch"]["kill_switch_enabled"] is True
    assert stub_state.list_traffic_routes()[0]["kill_switch_enabled"] is False


async def test_update_traffic_route_requires_a_field(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    rid = stub_state.list_traffic_routes()[0]["_id"]
    result = await _call(stub_server, "update_traffic_route", {"route_id": rid})
    assert "error" in result
    assert "at least one" in result["error"]


async def test_update_traffic_route_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "update_traffic_route", {"route_id": "ghost", "kill_switch_enabled": True}
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_toggle_traffic_route_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_routes()[0]["_id"]
    result = await _call(stub_server, "toggle_traffic_route", {"route_id": rid, "enabled": False})
    assert result["enabled"] is False


async def test_toggle_traffic_route_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    rid = stub_state.list_traffic_routes()[0]["_id"]
    result = await _call(
        stub_server,
        "toggle_traffic_route",
        {"route_id": rid, "enabled": False, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert stub_state.list_traffic_routes()[0]["enabled"] is True  # unchanged


async def test_toggle_traffic_route_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "toggle_traffic_route", {"route_id": "ghost", "enabled": False}
    )
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode — v2 bare-list parsing + read-modify-write PUT
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_traffic_rules_bare_list(real_server: FastMCP) -> None:
    # v2 returns a BARE list, not the legacy {"meta","data"} envelope.
    respx.get(f"{V2_BASE}/trafficrules").mock(
        return_value=httpx.Response(200, json=[{"_id": "tr1", "action": "BLOCK"}])
    )
    result = await _call(real_server, "list_traffic_rules")
    assert result[0]["_id"] == "tr1"
    assert result[0]["action"] == "BLOCK"


@respx.mock
async def test_real_create_traffic_rule(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"_id": "tr2", "action": "ALLOW"})

    respx.post(f"{V2_BASE}/trafficrules").mock(side_effect=capture)
    result = await _call(
        real_server,
        "create_traffic_rule",
        {"rule": {"action": "ALLOW", "matching_target": "DOMAIN"}},
    )
    assert result["_id"] == "tr2"
    assert captured["body"]["action"] == "ALLOW"


@respx.mock
async def test_real_toggle_traffic_rule_is_full_put(real_server: FastMCP) -> None:
    """Toggle must read the rule, then PUT the full object with enabled flipped."""
    respx.get(f"{V2_BASE}/trafficrules").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "_id": "tr1",
                    "action": "BLOCK",
                    "matching_target": "INTERNET",
                    "enabled": True,
                }
            ],
        )
    )
    put_route = respx.put(f"{V2_BASE}/trafficrules/tr1").mock(
        return_value=httpx.Response(200, json={"_id": "tr1", "enabled": False})
    )
    result = await _call(real_server, "toggle_traffic_rule", {"rule_id": "tr1", "enabled": False})
    assert result["enabled"] is False
    assert put_route.called
    body = json.loads(put_route.calls[0].request.content)
    # Full record sent: action + matching_target preserved, enabled flipped.
    assert body["action"] == "BLOCK"
    assert body["matching_target"] == "INTERNET"
    assert body["enabled"] is False


@respx.mock
async def test_real_list_traffic_routes_bare_list(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficroutes").mock(
        return_value=httpx.Response(200, json=[{"_id": "tro1", "kill_switch_enabled": False}])
    )
    result = await _call(real_server, "list_traffic_routes")
    assert result[0]["_id"] == "tro1"


@respx.mock
async def test_real_update_traffic_route_full_put(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficroutes").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "_id": "tro1",
                    "matching_target": "DOMAIN",
                    "kill_switch_enabled": False,
                    "enabled": True,
                }
            ],
        )
    )
    put_route = respx.put(f"{V2_BASE}/trafficroutes/tro1").mock(
        return_value=httpx.Response(200, json={"_id": "tro1", "kill_switch_enabled": True})
    )
    result = await _call(
        real_server,
        "update_traffic_route",
        {"route_id": "tro1", "kill_switch_enabled": True},
    )
    assert result["kill_switch_enabled"] is True
    body = json.loads(put_route.calls[0].request.content)
    assert body["matching_target"] == "DOMAIN"  # preserved
    assert body["kill_switch_enabled"] is True


@respx.mock
async def test_real_list_traffic_rules_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficrules").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_traffic_rules")
    assert "error" in result


@respx.mock
async def test_real_create_traffic_rule_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{V2_BASE}/trafficrules").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "create_traffic_rule", {"rule": {"action": "BLOCK"}})
    assert "error" in result


@respx.mock
async def test_real_update_traffic_rule_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficrules").mock(
        return_value=httpx.Response(200, json=[{"_id": "tr1", "action": "BLOCK"}])
    )
    respx.put(f"{V2_BASE}/trafficrules/tr1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server, "update_traffic_rule", {"rule_id": "tr1", "updates": {"action": "ALLOW"}}
    )
    assert "error" in result


@respx.mock
async def test_real_toggle_traffic_rule_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficrules").mock(
        return_value=httpx.Response(200, json=[{"_id": "tr1", "enabled": True}])
    )
    respx.put(f"{V2_BASE}/trafficrules/tr1").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "toggle_traffic_rule", {"rule_id": "tr1", "enabled": False})
    assert "error" in result


@respx.mock
async def test_real_get_traffic_rule_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficrules").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_traffic_rule_details", {"rule_id": "tr1"})
    assert "error" in result


@respx.mock
async def test_real_list_traffic_routes_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficroutes").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_traffic_routes")
    assert "error" in result


@respx.mock
async def test_real_update_traffic_route_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficroutes").mock(
        return_value=httpx.Response(200, json=[{"_id": "tro1", "enabled": True}])
    )
    respx.put(f"{V2_BASE}/trafficroutes/tro1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server, "update_traffic_route", {"route_id": "tro1", "kill_switch_enabled": True}
    )
    assert "error" in result


@respx.mock
async def test_real_toggle_traffic_route_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficroutes").mock(
        return_value=httpx.Response(200, json=[{"_id": "tro1", "enabled": True}])
    )
    respx.put(f"{V2_BASE}/trafficroutes/tro1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server, "toggle_traffic_route", {"route_id": "tro1", "enabled": False}
    )
    assert "error" in result


@respx.mock
async def test_real_get_traffic_route_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/trafficroutes").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_traffic_route_details", {"route_id": "tro1"})
    assert "error" in result
