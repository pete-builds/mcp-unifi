"""Tests for Zone-Based Firewall writes in stub mode (ADR 0009).

Covers the three policy tools, the composites' zone branch, and
``restore_config`` on a zone-based site. The stub starts on legacy rulesets,
like the console it models did before migration; ``_migrate`` flips it.
Every existing legacy-path test runs unchanged against the default stub,
which is the regression guard for legacy sites.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.backends import StubBackend
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiError
from tests.network.conftest import _call


def _migrate(state: StubState) -> dict[str, str]:
    state.zone_firewall.migrate()
    return dict(state.zone_firewall.zone_ids)


def _default_net_id(state: StubState) -> str:
    return str(state.networks[0]["_id"])


async def _create(server: FastMCP, **overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "name": "Block lab to LAN",
        "action": "block",
        "source_zone": "Internal",
        "destination_zone": "Internal",
        "source_addresses": ["10.0.77.0/24"],
        "destination_addresses": ["192.168.1.0/24"],
        **overrides,
    }
    return await _call(server, "create_firewall_policy", args)


# ---------------------------------------------------------------------------
# Legacy site: nothing changes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        (
            "create_firewall_policy",
            {"name": "x", "action": "block", "source_zone": "Internal", "destination_zone": "X"},
        ),
        ("update_firewall_policy", {"policy": "x", "enabled": False}),
        ("delete_firewall_policy", {"policy": "x"}),
    ],
)
async def test_policy_tools_refuse_a_legacy_site(
    tool: str, args: dict[str, Any], stub_server: FastMCP, stub_state: StubState
) -> None:
    rules_before = list(stub_state.firewall_rules)
    result = await _call(stub_server, tool, args)
    assert "legacy firewall rules" in result["error"]
    assert "create_firewall_rule" in result["error"]
    assert stub_state.firewall_rules == rules_before
    assert stub_state.zone_firewall.policies == []


# ---------------------------------------------------------------------------
# create_firewall_policy
# ---------------------------------------------------------------------------


async def test_create_policy_writes_a_user_defined_policy(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _migrate(stub_state)
    rules_before = list(stub_state.firewall_rules)
    result = await _create(stub_server)
    assert result["metadata"] == {"origin": "USER_DEFINED"}
    assert result["action"] == {"type": "BLOCK"}
    assert result["source"]["zoneId"] == zones["Internal"]
    assert stub_state.zone_firewall.policies == [result]
    assert stub_state.firewall_rules == rules_before


async def test_create_policy_translates_network_ids(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    net_id = _default_net_id(stub_state)
    stub_state.networks[0]["external_id"] = "v1-default"
    result = await _create(
        stub_server,
        action="allow",
        source_addresses=None,
        source_network_ids=[net_id],
        destination_addresses=["192.168.1.20"],
        destination_ports="32400",
        protocol="tcp",
    )
    assert result["source"]["trafficFilter"]["networkFilter"]["networkIds"] == ["v1-default"]
    assert result["action"] == {"type": "ALLOW", "allowReturnTraffic": True}


async def test_create_policy_dry_run_returns_the_body_and_writes_nothing(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    result = await _create(stub_server, dry_run=True)
    assert result["dry_run"] is True
    body = result["would_create"]["firewall_policy"]
    assert body["name"] == "Block lab to LAN"
    assert "id" not in body
    assert stub_state.zone_firewall.policies == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"destination_zone": "Nowhere"}, "zones are: Dmz, External"),
        ({"source_network_ids": ["missing"], "source_addresses": None}, "network 'missing'"),
        ({"source_network_ids": ["n"]}, "not both"),
        ({"destination_ports": "443"}, "port match"),
        ({"action": "accept"}, "action"),
    ],
)
async def test_create_policy_rejects_bad_input_before_writing(
    overrides: dict[str, Any], message: str, stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    if overrides.get("source_network_ids") == ["n"]:
        overrides["source_network_ids"] = [_default_net_id(stub_state)]
    result = await _create(stub_server, **overrides)
    assert message in result["error"]
    assert stub_state.zone_firewall.policies == []


async def test_create_policy_surfaces_a_console_refusal(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    stub_state.fail_next(
        "create_v1_firewall_policy",
        UniFiError("UniFi Integration POST returned 400: schedule must not be null"),
    )
    result = await _create(stub_server)
    assert "schedule must not be null" in result["error"]
    assert stub_state.zone_firewall.policies == []


# ---------------------------------------------------------------------------
# update_firewall_policy
# ---------------------------------------------------------------------------


async def test_update_policy_by_name_is_verified(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server)
    result = await _call(
        stub_server,
        "update_firewall_policy",
        {"policy": "block lab to lan", "enabled": False, "action": "reject"},
    )
    assert result["enabled"] is False
    assert result["action"] == {"type": "REJECT"}
    assert result["id"] == created["id"]
    assert "_id" not in result
    assert result["verification"]["verified"] is True
    assert set(result["verification"]["persisted_fields"]) == {"enabled", "action"}


async def test_update_policy_keeps_return_traffic_when_switching_to_allow(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server, action="allow", allow_return_traffic=False)
    await _call(stub_server, "update_firewall_policy", {"policy": created["id"], "action": "block"})
    result = await _call(
        stub_server, "update_firewall_policy", {"policy": created["id"], "action": "allow"}
    )
    # BLOCK has no flag to keep, so going back to ALLOW takes the default.
    assert result["action"] == {"type": "ALLOW", "allowReturnTraffic": True}


async def test_update_policy_dry_run_shows_before_and_after(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server)
    result = await _call(
        stub_server,
        "update_firewall_policy",
        {"policy": created["id"], "name": "renamed", "dry_run": True},
    )
    assert result["would_update"]["before"]["name"] == "Block lab to LAN"
    assert result["would_update"]["after"]["name"] == "renamed"
    assert stub_state.zone_firewall.policies[0]["name"] == "Block lab to LAN"


async def test_update_policy_raw_updates_replace_a_field(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _migrate(stub_state)
    created = await _create(stub_server)
    result = await _call(
        stub_server,
        "update_firewall_policy",
        {"policy": created["id"], "updates": {"destination": {"zoneId": zones["External"]}}},
    )
    assert result["destination"] == {"zoneId": zones["External"]}


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"updates": {"index": 1}}, "not a writable policy field: index"),
        ({}, "at least one change"),
        ({"policy": "nope", "enabled": True}, "not found"),
    ],
)
async def test_update_policy_rejects_bad_input(
    args: dict[str, Any], message: str, stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server)
    result = await _call(stub_server, "update_firewall_policy", {"policy": created["id"], **args})
    assert message in result["error"]


async def test_update_policy_refuses_an_ambiguous_name(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    await _create(stub_server)
    await _create(stub_server)
    result = await _call(
        stub_server, "update_firewall_policy", {"policy": "Block lab to LAN", "enabled": False}
    )
    assert "2 policies are named" in result["error"]


async def test_controller_managed_policies_are_refused(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server)
    stub_state.zone_firewall.policies[0]["metadata"] = {"origin": "SYSTEM_DEFINED"}
    before = json.dumps(stub_state.zone_firewall.policies, sort_keys=True)
    for tool, extra in (
        ("update_firewall_policy", {"enabled": False}),
        ("delete_firewall_policy", {}),
    ):
        result = await _call(stub_server, tool, {"policy": created["id"], **extra})
        assert "controller-managed" in result["error"]
    assert json.dumps(stub_state.zone_firewall.policies, sort_keys=True) == before


# ---------------------------------------------------------------------------
# delete_firewall_policy
# ---------------------------------------------------------------------------


async def test_delete_policy_needs_the_confirm_token(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server)
    preview = await _call(stub_server, "delete_firewall_policy", {"policy": created["id"]})
    assert "token" in preview
    assert len(stub_state.zone_firewall.policies) == 1
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result == {"deleted": True, "policy_id": created["id"]}
    assert stub_state.zone_firewall.policies == []


async def test_delete_policy_dry_run_has_no_token(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    created = await _create(stub_server)
    result = await _call(
        stub_server, "delete_firewall_policy", {"policy": created["name"], "dry_run": True}
    )
    assert result["would_delete"]["_id"] == created["id"]
    assert "token" not in result
    assert len(stub_state.zone_firewall.policies) == 1


# ---------------------------------------------------------------------------
# Composites on a zone-based site
# ---------------------------------------------------------------------------


async def test_iot_network_isolates_with_a_zone_policy(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _migrate(stub_state)
    rules_before = list(stub_state.firewall_rules)
    result = await _call(
        stub_server,
        "create_iot_network",
        {"name": "iot", "vlan_id": 50, "passphrase": "hunter2hunter2"},
    )
    policy = result["firewall_policy"]
    assert result["firewall_rule"] is None
    assert stub_state.firewall_rules == rules_before
    assert policy["name"] == "Block iot -> Main LAN"
    assert policy["action"] == {"type": "BLOCK"}
    assert policy["source"]["zoneId"] == zones["Internal"]
    assert policy["source"]["trafficFilter"]["ipAddressFilter"]["items"] == [
        {"type": "SUBNET", "value": "10.0.50.0/24"}
    ]
    assert policy["destination"]["trafficFilter"]["ipAddressFilter"]["items"] == [
        {"type": "SUBNET", "value": "192.168.1.0/24"}
    ]
    # Both networks were found in their zones, so no fallback was noted.
    assert policy["description"] == "created by mcp-unifi"


async def test_guest_network_isolates_from_the_hotspot_zone(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _migrate(stub_state)
    result = await _call(
        stub_server,
        "create_guest_network",
        {"name": "guest", "ssid": "guest-wifi", "passphrase": "hunter2hunter2", "vlan_id": 60},
    )
    policy = result["firewall_policy"]
    assert policy["source"]["zoneId"] == zones["Hotspot"]
    assert policy["destination"]["zoneId"] == zones["Internal"]
    assert result["firewall_rule"] is None


async def test_homelab_service_allows_with_a_zone_policy(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _migrate(stub_state)
    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "plex",
            "mac": "aa:bb:cc:00:00:99",
            "ip": "192.168.1.20",
            "network_id": _default_net_id(stub_state),
            "ports": [32400, 8080],
        },
    )
    policy = result["firewall_policy"]
    assert policy["action"] == {"type": "ALLOW", "allowReturnTraffic": True}
    assert policy["source"] == {"zoneId": zones["Internal"]}
    assert policy["destination"]["trafficFilter"]["portFilter"]["items"] == [
        {"type": "PORT_NUMBER", "value": 32400},
        {"type": "PORT_NUMBER", "value": 8080},
    ]
    assert policy["ipProtocolScope"]["protocolFilter"]["protocol"] == {"name": "TCP"}


async def test_iot_policy_failure_rolls_back_wlan_and_network(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    networks_before = len(stub_state.networks)
    wlans_before = len(stub_state.wlans)
    stub_state.fail_next("create_v1_firewall_policy", UniFiError("boom"))
    result = await _call(
        stub_server,
        "create_iot_network",
        {"name": "iot", "vlan_id": 50, "passphrase": "hunter2hunter2"},
    )
    assert "failed at firewall_policy" in result["error"]
    assert {next(iter(a)) for a in result["rolled_back"]} == {"wlan", "network"}
    assert len(stub_state.networks) == networks_before
    assert len(stub_state.wlans) == wlans_before
    assert stub_state.zone_firewall.policies == []
    assert "hunter2hunter2" not in json.dumps(result)


async def test_homelab_port_forward_failure_rolls_back_the_policy(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    stub_state.fail_next("create_port_forward", UniFiError("boom"))
    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "plex",
            "mac": "aa:bb:cc:00:00:99",
            "ip": "192.168.1.20",
            "network_id": _default_net_id(stub_state),
            "ports": [32400],
            "wan_expose": True,
        },
    )
    assert "failed at port_forward" in result["error"]
    assert any("firewall_policy" in a for a in result["rolled_back"])
    assert stub_state.zone_firewall.policies == []


async def test_isolation_falls_back_to_internal_and_says_so(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _migrate(stub_state)
    result = await _call(
        stub_server,
        "create_iot_network",
        {
            "name": "iot",
            "vlan_id": 50,
            "passphrase": "hunter2hunter2",
            "main_lan_subnet": "172.16.0.0/24",
        },
    )
    policy = result["firewall_policy"]
    assert policy["destination"]["zoneId"] == zones["Internal"]
    assert "used Internal" in policy["description"]


async def test_composite_dry_runs_preview_a_zone_policy(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _migrate(stub_state)
    iot = await _call(
        stub_server,
        "create_iot_network",
        {"name": "iot", "vlan_id": 50, "passphrase": "hunter2hunter2", "dry_run": True},
    )
    guest = await _call(
        stub_server,
        "create_guest_network",
        {
            "name": "guest",
            "ssid": "guest-wifi",
            "passphrase": "hunter2hunter2",
            "vlan_id": 60,
            "dry_run": True,
        },
    )
    homelab = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "plex",
            "mac": "aa:bb:cc:00:00:99",
            "ip": "192.168.1.20",
            "network_id": _default_net_id(stub_state),
            "ports": [32400],
            "dry_run": True,
        },
    )
    for result in (iot, guest, homelab):
        assert "firewall_rule" not in result["would_create"]
        assert result["would_create"]["firewall_policy"]["api"] == "integration/v1"
    assert stub_state.zone_firewall.policies == []


async def test_composites_detect_before_the_first_write(
    stub_server: FastMCP, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    networks_before = len(stub_state.networks)

    async def _broken(self: StubBackend) -> str:
        raise UniFiError("UniFi Integration GET returned 502")

    monkeypatch.setattr(StubBackend, "zone_firewall_state", _broken)
    result = await _call(
        stub_server,
        "create_iot_network",
        {"name": "iot", "vlan_id": 50, "passphrase": "hunter2hunter2"},
    )
    assert "502" in result["error"]
    assert len(stub_state.networks) == networks_before


# ---------------------------------------------------------------------------
# restore_config on a zone-based site
# ---------------------------------------------------------------------------


async def test_restore_skips_legacy_rules_on_a_zone_based_site(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    backup = await _call(stub_server, "backup_config", {})
    assert backup["resources"]["firewall_rules"], "seed state should carry a legacy rule"
    stub_state.firewall_rules.clear()
    _migrate(stub_state)
    result = await _call(
        stub_server, "restore_config", {"backup_json": json.dumps(backup), "dry_run": True}
    )
    fw_actions = [a for a in result["would_apply"] if a["type"] == "firewall_rules"]
    assert fw_actions and all(a["action"] == "skip" for a in fw_actions)
    assert any("Zone-Based Firewall" in w for w in result["warnings"])


async def test_restore_still_replays_legacy_rules_on_a_legacy_site(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    backup = await _call(stub_server, "backup_config", {})
    stub_state.firewall_rules.clear()
    result = await _call(
        stub_server, "restore_config", {"backup_json": json.dumps(backup), "dry_run": True}
    )
    fw_actions = [a for a in result["would_apply"] if a["type"] == "firewall_rules"]
    assert fw_actions and all(a["action"] == "create" for a in fw_actions)


# ---------------------------------------------------------------------------
# What the model sees
# ---------------------------------------------------------------------------


async def test_descriptions_keep_the_return_shape_above_args(stub_server: FastMCP) -> None:
    tools = {t.name: t for t in await stub_server.list_tools()}
    assert "Returns the created v1 policy record" in (
        tools["create_firewall_policy"].description or ""
    )
    assert "verification" in (tools["update_firewall_policy"].description or "")
    assert "confirm_destructive_action" in (tools["delete_firewall_policy"].description or "")
