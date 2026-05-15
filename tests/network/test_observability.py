"""Tests for ``mcp_unifi.modules.network.observability``.

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


async def test_get_site_health_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_site_health")
    subsystems = {h["subsystem"] for h in result}
    assert {"wan", "lan", "wlan"} <= subsystems


async def test_get_wan_status_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_status")
    assert result["subsystem"] == "wan"
    assert "xput_up" in result and "xput_down" in result


async def test_list_events_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_events", {"limit": 1})
    assert len(result) <= 1


async def test_list_events_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_events", {"limit": 0})
    assert "limit" in result["error"]


async def test_list_alarms_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_alarms", {"limit": 50, "archived": False})
    assert isinstance(result, list)


async def test_list_alarms_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_alarms", {"limit": 0})
    assert "limit" in result["error"]


async def test_speedtest_round_trip_stub(stub_server: FastMCP) -> None:
    triggered = await _call(stub_server, "trigger_speedtest")
    assert triggered["started"] is True
    results = await _call(stub_server, "get_speedtest_results", {"limit": 5})
    assert len(results) >= 1


async def test_get_speedtest_results_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_speedtest_results", {"limit": 0})
    assert "limit" in result["error"]


async def test_list_top_talkers_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_top_talkers", {"limit": 3})
    assert len(result) <= 3
    if result:
        assert result[0]["total_bytes"] >= result[-1]["total_bytes"]


async def test_list_top_talkers_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_top_talkers", {"limit": 0})
    assert "limit" in result["error"]


async def test_audit_open_ports_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "audit_open_ports")
    assert "port_forwards" in result
    assert "wan_accept_rules" in result
    assert "summary" in result
    # The seed has one HTTPS->NAS forward and one established/related WAN_IN
    # rule (filtered out). Audit should surface the forward, no accept rules.
    assert len(result["port_forwards"]) >= 1
    assert all(
        not (r.get("state_established") and r.get("state_related"))
        for r in result["wan_accept_rules"]
    )


async def test_audit_open_ports_flags_wan_accept_rule(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.create_firewall_rule(
        {
            "name": "Open SSH from anywhere",
            "ruleset": "WAN_IN",
            "rule_index": 2100,
            "action": "accept",
            "enabled": True,
            "protocol": "tcp",
        }
    )
    result = await _call(stub_server, "audit_open_ports")
    names = [r["name"] for r in result["wan_accept_rules"]]
    assert "Open SSH from anywhere" in names


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_site_health(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"subsystem": "wan", "status": "ok"},
                    {"subsystem": "lan", "status": "ok"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_site_health")
    assert {h["subsystem"] for h in result} == {"wan", "lan"}


@respx.mock
async def test_real_get_wan_status_extracts_wan(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"subsystem": "lan", "status": "ok"},
                    {"subsystem": "wan", "status": "ok", "wan_ip": "1.2.3.4"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_wan_status")
    assert result["subsystem"] == "wan"
    assert result["wan_ip"] == "1.2.3.4"


@respx.mock
async def test_real_get_wan_status_unknown_when_missing(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(200, json={"data": [{"subsystem": "lan", "status": "ok"}]})
    )
    result = await _call(real_server, "get_wan_status")
    assert result["status"] == "unknown"


@respx.mock
async def test_real_list_events(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/event?_limit=5").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "e1"}]})
    )
    result = await _call(real_server, "list_events", {"limit": 5})
    assert result[0]["_id"] == "e1"


@respx.mock
async def test_real_list_alarms(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/alarm?archived=false&_limit=5").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "a1"}]})
    )
    result = await _call(real_server, "list_alarms", {"limit": 5, "archived": False})
    assert result[0]["_id"] == "a1"


@respx.mock
async def test_real_trigger_speedtest(real_server: FastMCP) -> None:
    import json as _json

    captured: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = _json.loads(request.content)
        return httpx.Response(200, json={"data": [{"started": True}]})

    respx.post(f"{BASE}/cmd/devmgr").mock(side_effect=capture)
    result = await _call(real_server, "trigger_speedtest")
    assert captured["body"]["cmd"] == "speedtest"
    assert result["started"] is True


@respx.mock
async def test_real_get_speedtest_results(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/report/archive.speedtest?_limit=3").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "s1"}, {"_id": "s2"}]})
    )
    result = await _call(real_server, "get_speedtest_results", {"limit": 3})
    assert len(result) == 2


@respx.mock
async def test_real_list_top_talkers(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sitedpi").mock(
        return_value=httpx.Response(
            200, json={"data": [{"mac": "aa", "rx_bytes": 100}, {"mac": "bb", "rx_bytes": 50}]}
        )
    )
    result = await _call(real_server, "list_top_talkers", {"limit": 1})
    assert len(result) == 1


@respx.mock
async def test_real_audit_open_ports(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "r1",
                        "ruleset": "WAN_IN",
                        "action": "accept",
                        "enabled": True,
                        "name": "Boilerplate",
                        "state_established": True,
                        "state_related": True,
                    },
                    {
                        "_id": "r2",
                        "ruleset": "WAN_IN",
                        "action": "accept",
                        "enabled": True,
                        "name": "Open SSH",
                    },
                ]
            },
        )
    )
    respx.get(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "pf1", "enabled": True, "name": "HTTPS to NAS"}]},
        )
    )
    result = await _call(real_server, "audit_open_ports")
    assert len(result["port_forwards"]) == 1
    names = [r["name"] for r in result["wan_accept_rules"]]
    assert names == ["Open SSH"]


@respx.mock
async def test_real_get_site_health_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_site_health")
    assert "error" in result
