"""Dry-run tests for every destructive tool.

Each destructive tool must, when invoked with ``dry_run=True``:

1. Return a JSON envelope with ``"dry_run": true`` and a ``would_*`` block.
2. Skip the backend mutation entirely, leaving the stub state untouched.
3. Honor the same shape regardless of stub vs. real (composites included).

The composites also exercise the predicted-action graph and confirm the
existing rollback path on real apply still fires post-Step-3.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server


def _text(result: Any) -> str:
    """Extract the text payload from a FastMCP ToolResult."""
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


@pytest.fixture
def stub_server(stub_settings: Settings, stub_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=stub_state)


def _state_snapshot(state: StubState) -> dict[str, Any]:
    """Deep-copy every mutable list on the stub state for diffing."""
    return {
        "devices": copy.deepcopy(state.devices),
        "networks": copy.deepcopy(state.networks),
        "wlans": copy.deepcopy(state.wlans),
        "firewall_rules": copy.deepcopy(state.firewall_rules),
        "port_profiles": copy.deepcopy(state.port_profiles),
        "clients": copy.deepcopy(state.clients),
        "dhcp_leases": copy.deepcopy(state.dhcp_leases),
        "port_forwards": copy.deepcopy(state.port_forwards),
        "audit_log": copy.deepcopy(state.audit_log),
    }


def _assert_unchanged(before: dict[str, Any], state: StubState) -> None:
    after = _state_snapshot(state)
    assert before == after, "dry_run mutated stub state"


# ---------------------------------------------------------------------------
# Per-resource destructive tools
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "expect_key"),
    [
        # vlans
        (
            "create_vlan",
            {"name": "Cameras", "vlan_id": 50, "subnet": "10.0.50.0/24"},
            "would_create",
        ),
        (
            "update_vlan",
            {"network_id": "net-x", "updates": {"name": "Renamed"}},
            "would_update",
        ),
        ("delete_vlan", {"network_id": "net-x"}, "would_delete"),
        # wlans
        (
            "create_wlan",
            {
                "name": "Cameras",
                "passphrase": "supersecret-passphrase",
                "network_id": "net-x",
            },
            "would_create",
        ),
        (
            "update_wlan",
            {"wlan_id": "wlan-x", "updates": {"enabled": False}},
            "would_update",
        ),
        ("delete_wlan", {"wlan_id": "wlan-x"}, "would_delete"),
        # firewall
        (
            "create_firewall_rule",
            {"name": "blockit", "ruleset": "LAN_IN", "action": "drop"},
            "would_create",
        ),
        (
            "update_firewall_rule",
            {"rule_id": "fw-x", "updates": {"enabled": False}},
            "would_update",
        ),
        ("delete_firewall_rule", {"rule_id": "fw-x"}, "would_delete"),
        # port profiles
        ("create_port_profile", {"name": "trunk-iot"}, "would_create"),
        (
            "update_port_profile",
            {"profile_id": "pp-x", "updates": {"poe_mode": "off"}},
            "would_update",
        ),
        ("delete_port_profile", {"profile_id": "pp-x"}, "would_delete"),
        # dhcp
        (
            "create_static_dhcp_lease",
            {
                "mac": "aa:bb:cc:11:22:33",
                "ip": "10.0.1.50",
                "network_id": "net-x",
            },
            "would_create",
        ),
        ("delete_static_dhcp_lease", {"lease_id": "lease-x"}, "would_delete"),
        # port forwards
        (
            "create_port_forward",
            {
                "name": "ssh",
                "fwd": "10.0.1.10",
                "fwd_port": "22",
                "dst_port": "2222",
            },
            "would_create",
        ),
        (
            "update_port_forward",
            {"forward_id": "pf-x", "updates": {"enabled": False}},
            "would_update",
        ),
        ("delete_port_forward", {"forward_id": "pf-x"}, "would_delete"),
        # clients
        ("block_client", {"mac": "aa:bb:cc:11:22:33"}, "would_apply"),
        ("unblock_client", {"mac": "aa:bb:cc:11:22:33"}, "would_apply"),
        ("reconnect_client", {"mac": "aa:bb:cc:11:22:33"}, "would_apply"),
        # devices
        ("restart_device", {"mac": "aa:bb:cc:11:22:33"}, "would_apply"),
        (
            "locate_device",
            {"mac": "aa:bb:cc:11:22:33", "on": True},
            "would_apply",
        ),
        (
            "set_port_state",
            {"device_mac": "aa:bb:cc:11:22:33", "port_idx": 1, "enable": False},
            "would_apply",
        ),
    ],
)
async def test_dry_run_per_resource_destructive(
    tool: str,
    args: dict[str, Any],
    expect_key: str,
    stub_server: FastMCP,
    stub_state: StubState,
) -> None:
    """Every per-resource destructive tool returns a preview and mutates nothing."""
    before = _state_snapshot(stub_state)
    payload = await _call(stub_server, tool, {**args, "dry_run": True})

    assert payload.get("dry_run") is True, f"{tool}: missing dry_run=True"
    assert payload.get("controller") == "default", (
        f"{tool}: controller missing or wrong"
    )
    assert expect_key in payload, f"{tool}: missing {expect_key} block"
    assert "summary" in payload and isinstance(payload["summary"], str)
    _assert_unchanged(before, stub_state)


# ---------------------------------------------------------------------------
# Composite dry-runs
# ---------------------------------------------------------------------------


async def test_create_iot_network_dry_run_full_change_set(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = _state_snapshot(stub_state)
    payload = await _call(
        stub_server,
        "create_iot_network",
        {
            "name": "Cameras",
            "vlan_id": 50,
            "passphrase": "verysecret-iot-passphrase",
            "isolate": True,
            "dry_run": True,
        },
    )

    assert payload["dry_run"] is True
    assert payload["controller"] == "default"
    would = payload["would_create"]
    assert set(would) == {"network", "wlan", "firewall_rule"}
    assert would["network"]["vlan"] == 50
    assert would["wlan"]["name"] == "Cameras"
    # Composite preview surfaces a placeholder ID that the real apply replaces.
    assert would["wlan"]["networkconf_id"].startswith("<dry-run")
    assert would["firewall_rule"]["ruleset"] == "LAN_IN"
    assert "Would create IoT network" in payload["summary"]
    _assert_unchanged(before, stub_state)


async def test_create_iot_network_dry_run_no_isolate_drops_firewall(
    stub_server: FastMCP,
) -> None:
    payload = await _call(
        stub_server,
        "create_iot_network",
        {
            "name": "Cameras",
            "vlan_id": 50,
            "passphrase": "verysecret-iot-passphrase",
            "isolate": False,
            "dry_run": True,
        },
    )
    assert "firewall_rule" not in payload["would_create"]


async def test_create_guest_network_dry_run_full_change_set(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = _state_snapshot(stub_state)
    payload = await _call(
        stub_server,
        "create_guest_network",
        {
            "name": "Guests",
            "ssid": "Guest-WiFi",
            "passphrase": "guestnet-passphrase-x",
            "vlan_id": 60,
            "dry_run": True,
        },
    )
    assert payload["dry_run"] is True
    would = payload["would_create"]
    assert set(would) == {"network", "wlan", "firewall_rule"}
    assert would["network"]["purpose"] == "guest"
    assert would["wlan"]["is_guest"] is True
    _assert_unchanged(before, stub_state)


async def test_provision_homelab_service_dry_run_full_change_set(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = _state_snapshot(stub_state)
    payload = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "homepage",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "10.0.10.10",
            "network_id": "net-x",
            "ports": [80, 443],
            "wan_expose": True,
            "dry_run": True,
        },
    )
    assert payload["dry_run"] is True
    would = payload["would_create"]
    assert "lease" in would
    assert "firewall_rule" in would
    assert "port_forwards" in would
    assert len(would["port_forwards"]) == 2
    _assert_unchanged(before, stub_state)


async def test_provision_homelab_service_dry_run_no_ports_lease_only(
    stub_server: FastMCP,
) -> None:
    payload = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "headless",
            "mac": "aa:bb:cc:dd:ee:00",
            "ip": "10.0.10.20",
            "network_id": "net-x",
            "ports": [],
            "dry_run": True,
        },
    )
    would = payload["would_create"]
    assert "lease" in would
    assert "firewall_rule" not in would
    assert "port_forwards" not in would


async def test_quarantine_client_dry_run(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = _state_snapshot(stub_state)
    payload = await _call(
        stub_server,
        "quarantine_client",
        {"mac": "aa:bb:cc:11:22:33", "reason": "lateral movement", "dry_run": True},
    )
    assert payload["dry_run"] is True
    assert payload["would_apply"]["action"] == "quarantine"
    assert payload["would_apply"]["reason"] == "lateral movement"
    _assert_unchanged(before, stub_state)


# ---------------------------------------------------------------------------
# Composite rollback regression
# ---------------------------------------------------------------------------


async def test_create_iot_network_real_apply_rollback(
    stub_settings: Settings, stub_state: StubState
) -> None:
    """A failure in step 3 (firewall) must roll back steps 1-2 (vlan + wlan).

    We force the firewall step to fail by monkey-patching the stub's
    ``create_firewall_rule`` to raise ``UniFiError``. The composite must then
    delete the network and the WLAN it just created, returning a
    ``rolled_back`` list.
    """
    from mcp_unifi.clients.unifi import UniFiError

    nets_before = len(stub_state.networks)
    wlans_before = len(stub_state.wlans)

    def _boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated firewall failure")

    stub_state.create_firewall_rule = _boom  # type: ignore[method-assign]

    server = build_server(stub_settings, stub=stub_state)
    payload = await _call(
        server,
        "create_iot_network",
        {
            "name": "DoomedIoT",
            "vlan_id": 80,
            "passphrase": "sometemppassphrase-x",
        },
    )

    assert "error" in payload
    assert "firewall_rule" in payload["error"]
    rolled = payload["rolled_back"]
    kinds = {next(iter(action.keys())) for action in rolled}
    assert "network" in kinds
    assert "wlan" in kinds
    # Stub state should match the pre-call counts after rollback.
    assert len(stub_state.networks) == nets_before
    assert len(stub_state.wlans) == wlans_before


async def test_provision_homelab_service_real_apply_rollback(
    stub_settings: Settings, stub_state: StubState
) -> None:
    """Failure on a port-forward step rolls back the lease and firewall rule."""
    from mcp_unifi.clients.unifi import UniFiError

    leases_before = len(stub_state.dhcp_leases)
    fw_before = len(stub_state.firewall_rules)
    pf_before = len(stub_state.port_forwards)

    def _boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated port-forward failure")

    stub_state.create_port_forward = _boom  # type: ignore[method-assign]

    server = build_server(stub_settings, stub=stub_state)
    net_id = stub_state.networks[0]["_id"]
    payload = await _call(
        server,
        "provision_homelab_service",
        {
            "name": "doomedsvc",
            "mac": "aa:bb:cc:99:99:99",
            "ip": "10.0.1.99",
            "network_id": net_id,
            "ports": [8080],
            "wan_expose": True,
        },
    )

    assert "error" in payload
    assert "port_forward" in payload["error"]
    assert len(stub_state.dhcp_leases) == leases_before
    assert len(stub_state.firewall_rules) == fw_before
    assert len(stub_state.port_forwards) == pf_before


# ---------------------------------------------------------------------------
# Read-only tools should never accept dry_run (sanity check the schema)
# ---------------------------------------------------------------------------


READ_ONLY_TOOLS = (
    "list_networks",
    "list_wlans",
    "list_firewall_rules",
    "list_port_profiles",
    "list_dhcp_leases",
    "list_port_forwards",
    "list_clients",
    "list_devices",
    "list_top_talkers",
    "get_site_health",
    "get_wan_status",
    "list_events",
    "list_alarms",
    "trigger_speedtest",
    "get_speedtest_results",
    "audit_open_ports",
)


@pytest.mark.parametrize("tool", READ_ONLY_TOOLS)
async def test_read_only_tools_have_no_dry_run_param(
    tool: str, stub_server: FastMCP
) -> None:
    """Schema introspection must not show ``dry_run`` on read-only tools."""
    tools = await stub_server.list_tools()
    by_name = {t.name: t for t in tools}
    assert tool in by_name
    schema = by_name[tool].parameters
    props = schema.get("properties", {})
    assert "dry_run" not in props, f"{tool}: read-only tool exposes dry_run"
