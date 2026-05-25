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
    # v0.7.0: preview first, then confirm.
    preview = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == rule_id
    assert stub_state.list_firewall_rules() != []  # preview must not delete
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["rule_id"] == rule_id
    assert stub_state.list_firewall_rules() == []


async def test_delete_firewall_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_firewall_rule", {"rule_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


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
    # v0.7.0: preview first (list lookup), then confirm (actual DELETE).
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r1", "name": "R"}]})
    )
    respx.delete(f"{BASE}/rest/firewallrule/r1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_firewall_rule", {"rule_id": "r1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["rule_id"] == "r1"


@respx.mock
async def test_real_delete_firewall_rule_handles_404(real_server: FastMCP) -> None:
    # v0.7.0: 404 surfaces during the confirm phase (the DELETE). The preview
    # phase needs the list lookup to find the rule first.
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "missing"}]})
    )
    respx.delete(f"{BASE}/rest/firewallrule/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    preview = await _call(real_server, "delete_firewall_rule", {"rule_id": "missing"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
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
    """Cover the src_networkconf_id / dst_networkconf_id payload branches.

    UniFi Network 9.x ZBF rejects rules that reference a network conf by
    ``_id`` without a matching ``*_networkconf_type`` discriminator
    (``api.err.FirewallRuleNetworkConfTypeRequired``). The tool must emit
    ``src_networkconf_type`` / ``dst_networkconf_type`` (defaulting to
    ``"NETv4"``) alongside the IDs.
    """
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
    # ZBF discriminator must accompany the network_id references.
    assert captured["body"]["src_networkconf_type"] == "NETv4"
    assert captured["body"]["dst_networkconf_type"] == "NETv4"


@respx.mock
async def test_create_firewall_rule_omits_type_without_networkconf_id(
    real_server: FastMCP,
) -> None:
    """When no networkconf_id is set, the discriminator must NOT be emitted.

    Address-only rules (``src_address`` / ``dst_address``) don't reference a
    network conf, so sending a ``*_networkconf_type`` would be meaningless
    noise that the controller might reject.
    """
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "faddr"}]})

    respx.post(f"{BASE}/rest/firewallrule").mock(side_effect=capture)
    await _call(
        real_server,
        "create_firewall_rule",
        {
            "name": "ByAddr",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_address": "10.0.50.0/24",
            "dst_address": "192.168.86.0/24",
        },
    )
    assert "src_networkconf_type" not in captured["body"]
    assert "dst_networkconf_type" not in captured["body"]


@respx.mock
async def test_create_firewall_rule_default_rule_index_is_zbf_range(
    real_server: FastMCP,
) -> None:
    """v0.6.1: default rule_index must land in the UniFi 9.x ZBF user band.

    The pre-9.x default of ``2500`` was rejected on UniFi Network 9.x with
    ``api.err.FirewallRuleIndexOutOfRange``. ``20000`` is the verified safe
    floor for user-defined LAN_IN rules on UCG-Fiber running 9.x.
    """
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "fidx"}]})

    respx.post(f"{BASE}/rest/firewallrule").mock(side_effect=capture)
    await _call(
        real_server,
        "create_firewall_rule",
        {"name": "DefaultIndex", "ruleset": "LAN_IN", "action": "accept"},
    )
    assert captured["body"]["rule_index"] >= 20000


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
