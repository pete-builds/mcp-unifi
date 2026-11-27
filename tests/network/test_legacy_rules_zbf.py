"""Legacy firewall-rule writes refuse on Zone-Based Firewall sites.

Network 11 migrated every site to zones and left ``/rest/firewallrule`` empty,
so ``create_firewall_rule``, ``update_firewall_rule`` and ``delete_firewall_rule``
have nothing to write into. Each refuses, before any write, and points at the
``*_firewall_policy`` tool. Legacy sites, and sites whose state is
``unsupported`` or ``disabled``, behave exactly as before.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.audit import AuditEvent
from mcp_unifi.backends import StubBackend
from mcp_unifi.cli import replay as replay_mod
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules.network._pending import get_pending_actions
from tests.network.conftest import _call

CREATE_ARGS: dict[str, Any] = {
    "name": "Block lab",
    "ruleset": "LAN_IN",
    "action": "drop",
    "src_address": "10.0.77.0/24",
}

TOOLS = [
    ("create_firewall_rule", "create_firewall_policy"),
    ("update_firewall_rule", "update_firewall_policy"),
    ("delete_firewall_rule", "delete_firewall_policy"),
]


def _args(state: StubState, tool: str, **extra: Any) -> dict[str, Any]:
    if tool == "create_firewall_rule":
        return {**CREATE_ARGS, **extra}
    rule_id = state.firewall_rules[0]["_id"]
    if tool == "update_firewall_rule":
        return {"rule_id": rule_id, "updates": {"enabled": False}, **extra}
    return {"rule_id": rule_id, **extra}


def _assert_refused(result: dict[str, Any], policy_tool: str) -> None:
    assert "error" in result, result
    assert "Zone-Based Firewall" in result["error"]
    assert "11.0.97" in result["error"]
    assert policy_tool in result["error"]
    assert "stub_mode" in result
    assert "preview" not in result
    assert "token" not in result


@pytest.mark.parametrize(("tool", "policy_tool"), TOOLS)
async def test_refuses_on_a_zone_based_site_and_writes_nothing(
    stub_server: FastMCP, stub_state: StubState, tool: str, policy_tool: str
) -> None:
    stub_state.zone_firewall.migrate()
    rules_before = copy.deepcopy(stub_state.firewall_rules)
    pending_before = len(get_pending_actions())

    result = await _call(stub_server, tool, _args(stub_state, tool))

    _assert_refused(result, policy_tool)
    assert stub_state.firewall_rules == rules_before
    assert len(get_pending_actions()) == pending_before


@pytest.mark.parametrize(("tool", "policy_tool"), TOOLS)
async def test_dry_run_also_refuses_on_a_zone_based_site(
    stub_server: FastMCP, stub_state: StubState, tool: str, policy_tool: str
) -> None:
    """A dry run must not promise a write the real call would refuse."""
    stub_state.zone_firewall.migrate()
    result = await _call(stub_server, tool, _args(stub_state, tool, dry_run=True))
    _assert_refused(result, policy_tool)


async def test_create_refuses_before_validating_other_arguments(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.zone_firewall.migrate()
    result = await _call(
        stub_server,
        "create_firewall_rule",
        {**CREATE_ARGS, "src_firewallgroup_ids": ["../etc"]},
    )
    _assert_refused(result, "create_firewall_policy")


@pytest.mark.parametrize("state", ["legacy", "unsupported", "disabled"])
async def test_legacy_unsupported_and_disabled_sites_behave_as_before(
    stub_server: FastMCP, stub_state: StubState, state: str
) -> None:
    stub_state.zone_firewall.state = state  # type: ignore[assignment]
    count = len(stub_state.firewall_rules)

    created = await _call(stub_server, "create_firewall_rule", CREATE_ARGS)
    assert created["src_address"] == "10.0.77.0/24"
    assert len(stub_state.firewall_rules) == count + 1

    rule_id = stub_state.firewall_rules[0]["_id"]
    updated = await _call(
        stub_server, "update_firewall_rule", {"rule_id": rule_id, "updates": {"enabled": False}}
    )
    assert "error" not in updated, updated
    assert stub_state.firewall_rules[0]["enabled"] is False

    preview = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    assert preview["preview"] is True
    done = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert done["deleted"] is True
    assert all(r["_id"] != rule_id for r in stub_state.firewall_rules)


async def test_confirm_refuses_when_the_site_became_zone_based_after_the_preview(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    rule_id = stub_state.firewall_rules[0]["_id"]
    preview = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    assert preview["preview"] is True
    rules_before = copy.deepcopy(stub_state.firewall_rules)

    stub_state.zone_firewall.migrate()
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})

    _assert_refused(result, "delete_firewall_policy")
    assert stub_state.firewall_rules == rules_before


@pytest.fixture
def unreadable_state(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(self: StubBackend) -> str:
        raise UniFiError("integration API timed out")

    monkeypatch.setattr(StubBackend, "zone_firewall_state", _boom)


@pytest.mark.parametrize(("tool", "_policy_tool"), TOOLS)
async def test_unreadable_state_refuses_the_write_and_changes_nothing(
    stub_server: FastMCP,
    stub_state: StubState,
    unreadable_state: None,
    tool: str,
    _policy_tool: str,
) -> None:
    rules_before = copy.deepcopy(stub_state.firewall_rules)
    result = await _call(stub_server, tool, _args(stub_state, tool))
    assert "timed out" in result["error"]
    assert "preview" not in result
    assert stub_state.firewall_rules == rules_before


async def test_unreadable_state_still_allows_a_dry_run_preview(
    stub_server: FastMCP, stub_state: StubState, unreadable_state: None
) -> None:
    result = await _call(stub_server, "create_firewall_rule", {**CREATE_ARGS, "dry_run": True})
    assert result["dry_run"] is True


@pytest.mark.parametrize(("tool", "policy_tool"), TOOLS)
async def test_tool_description_says_it_refuses_on_zone_based_sites(
    stub_server: FastMCP, tool: str, policy_tool: str
) -> None:
    tools = await stub_server.list_tools()
    listed = list(tools.values()) if isinstance(tools, dict) else list(tools)
    by_name = {getattr(t, "name", None) or getattr(t, "key", ""): t for t in listed}
    description = " ".join((by_name[tool].description or "").split())
    prose = description.split("Args:")[0]
    assert (
        "On Zone-Based Firewall sites (every site on UniFi Network 11) this tool refuses; "
        f"use {policy_tool}."
    ) in prose


async def test_restore_refuses_legacy_rules_when_the_site_migrated_after_the_preview(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    backup_json = json.dumps(await _call(stub_server, "backup_config", {}))
    stub_state.firewall_rules = []  # the plan will now recreate the backed-up rules
    preview = await _call(stub_server, "restore_config", {"backup_json": backup_json})
    assert preview["preview"] is True

    stub_state.zone_firewall.migrate()
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})

    assert "Zone-Based Firewall" in result["error"]
    assert "Nothing was applied" in result["error"]
    assert stub_state.firewall_rules == []


async def test_replayed_legacy_create_is_refused_on_a_zone_based_site(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.zone_firewall.migrate()
    rules_before = copy.deepcopy(stub_state.firewall_rules)
    event = AuditEvent(
        ts="2026-05-14T00:00:00.000Z",
        controller="default",
        tool="create_firewall_rule",
        args=CREATE_ARGS,
        result=None,
        success=True,
        latency_ms=1.0,
    )
    results = await replay_mod.replay_events(
        [event], stub_mode=True, target_controller=None, i_mean_it=False, server=stub_server
    )
    assert results[0].success is False
    assert "Zone-Based Firewall" in (results[0].error or "")
    assert stub_state.firewall_rules == rules_before


@pytest.mark.parametrize(
    "tool", ["create_iot_network", "create_guest_network", "provision_homelab_service"]
)
async def test_composites_write_a_policy_and_no_legacy_rule_on_a_zone_based_site(
    stub_server: FastMCP, stub_state: StubState, tool: str
) -> None:
    stub_state.zone_firewall.migrate()
    rules_before = copy.deepcopy(stub_state.firewall_rules)
    args: dict[str, Any] = {
        "create_iot_network": {"name": "iot", "vlan_id": 50, "passphrase": "hunter2hunter2"},
        "create_guest_network": {
            "name": "guest",
            "ssid": "guest-wifi",
            "passphrase": "hunter2hunter2",
            "vlan_id": 60,
        },
        "provision_homelab_service": {
            "name": "plex",
            "mac": "aa:bb:cc:00:00:99",
            "ip": "192.168.1.20",
            "network_id": str(stub_state.networks[0]["_id"]),
            "ports": [32400],
        },
    }[tool]
    result = await _call(stub_server, tool, args)
    assert result["firewall_policy"]
    assert result["firewall_rule"] is None
    assert stub_state.firewall_rules == rules_before
    assert len(stub_state.zone_firewall.policies) == 1
