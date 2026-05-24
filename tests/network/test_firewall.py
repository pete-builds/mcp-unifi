"""Tests for ``mcp_unifi.modules.network.firewall``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
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


async def test_list_firewall_rules_stub(stub_server: FastMCP) -> None:
    rules = await _call(stub_server, "list_firewall_rules")
    assert rules[0]["ruleset"] == "WAN_IN"


async def test_create_firewall_rule_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_firewall_rule",
        {
            "name": "Block IoT",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_address": "10.0.20.0/24",
            "dst_address": "192.168.1.0/24",
        },
    )
    assert result["src_address"] == "10.0.20.0/24"
    assert result["action"] == "drop"


async def test_create_firewall_rule_stub_with_dst_port(stub_server: FastMCP) -> None:
    """Port-based rules (e.g. IoT → Plex :32400) must round-trip cleanly."""
    result = await _call(
        stub_server,
        "create_firewall_rule",
        {
            "name": "IoT to Plex",
            "ruleset": "LAN_IN",
            "action": "accept",
            "protocol": "tcp",
            "src_networkconf_id": "iot-net-id",
            "dst_networkconf_id": "mgmt-net-id",
            "dst_port": "32400",
        },
    )
    assert result["dst_port"] == "32400"
    assert result["protocol"] == "tcp"
    assert result["action"] == "accept"


async def test_create_firewall_rule_stub_omits_unset_port_fields(stub_server: FastMCP) -> None:
    """Empty src_port/dst_port must NOT appear in the controller payload."""
    result = await _call(
        stub_server,
        "create_firewall_rule",
        {
            "name": "Block IoT",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_address": "10.0.50.0/24",
            "dst_address": "192.168.86.0/24",
        },
    )
    assert "dst_port" not in result
    assert "src_port" not in result


async def test_delete_firewall_rule_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    result = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    assert result["deleted"] is True
    assert result["rule_id"] == rule_id
    assert stub_state.list_firewall_rules() == []


async def test_delete_firewall_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_firewall_rule", {"rule_id": "ghost"})
    assert result["deleted"] is False


async def test_update_firewall_rule_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    result = await _call(
        stub_server,
        "update_firewall_rule",
        {"rule_id": rule_id, "updates": {"action": "drop"}},
    )
    assert result["action"] == "drop"


async def test_update_firewall_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_firewall_rule",
        {"rule_id": "ghost", "updates": {"action": "drop"}},
    )
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_firewall_rules(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r"}]})
    )
    result = await _call(real_server, "list_firewall_rules")
    assert result[0]["_id"] == "r"


@respx.mock
async def test_real_create_firewall_rule(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "f1"}]})
    )
    result = await _call(
        real_server,
        "create_firewall_rule",
        {"name": "R", "ruleset": "LAN_IN", "action": "drop"},
    )
    assert result["_id"] == "f1"


@respx.mock
async def test_real_delete_firewall_rule(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/firewallrule/r1").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_firewall_rule", {"rule_id": "r1"})
    assert result["deleted"] is True
    assert result["rule_id"] == "r1"


@respx.mock
async def test_real_delete_firewall_rule_handles_404(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/firewallrule/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(real_server, "delete_firewall_rule", {"rule_id": "missing"})
    assert "error" in result


@respx.mock
async def test_create_firewall_rule_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_firewall_rule",
        {"name": "R", "ruleset": "LAN_IN", "action": "drop"},
    )
    assert "error" in result


@respx.mock
async def test_list_firewall_rules_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_firewall_rules")
    assert "error" in result


@respx.mock
async def test_create_firewall_rule_with_networkconf_ids(real_server: FastMCP) -> None:
    """Cover the src_networkconf_id / dst_networkconf_id payload branches."""
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "fnet"}]})

    respx.post(f"{BASE}/rest/firewallrule").mock(side_effect=capture)
    result = await _call(
        real_server,
        "create_firewall_rule",
        {
            "name": "ByNet",
            "ruleset": "LAN_IN",
            "action": "accept",
            "src_networkconf_id": "src-id",
            "dst_networkconf_id": "dst-id",
        },
    )
    assert result["_id"] == "fnet"
    assert captured["body"]["src_networkconf_id"] == "src-id"
    assert captured["body"]["dst_networkconf_id"] == "dst-id"


@respx.mock
async def test_real_update_firewall_rule(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/firewallrule/r1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r1", "action": "drop"}]})
    )
    result = await _call(
        real_server,
        "update_firewall_rule",
        {"rule_id": "r1", "updates": {"action": "drop"}},
    )
    assert result["action"] == "drop"


@respx.mock
async def test_real_update_firewall_rule_500(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/firewallrule/r1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "update_firewall_rule",
        {"rule_id": "r1", "updates": {"action": "drop"}},
    )
    assert "error" in result
