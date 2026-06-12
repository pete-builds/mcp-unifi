"""Sanity tests for tool descriptions (Phase 2 Part C).

These are regression nets, not content judges. They assert the structural
guarantees that LLM tool selection depends on:

* every tool has a non-empty description
* descriptions are at least 50 characters (no terse one-liners)
* every destructive tool's description mentions ``dry_run``
* every composite (rolls back on partial failure) mentions ``Rollback``

Description prose itself is reviewed by humans; this test only catches drift
when a future tool slips through without the new pattern.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

# Mirror of scripts/compare_schemas.py::DESTRUCTIVE_TOOLS. Kept in sync with
# any new mutating tool added to the network module.
DESTRUCTIVE_TOOLS: frozenset[str] = frozenset(
    {
        # vlans
        "create_vlan",
        "update_vlan",
        "delete_vlan",
        # wlans
        "create_wlan",
        "update_wlan",
        "delete_wlan",
        # firewall
        "create_firewall_rule",
        "update_firewall_rule",
        "delete_firewall_rule",
        # port profiles
        "create_port_profile",
        "update_port_profile",
        "delete_port_profile",
        # dhcp
        "create_static_dhcp_lease",
        "update_static_dhcp_lease",
        "delete_static_dhcp_lease",
        # port forwards
        "create_port_forward",
        "update_port_forward",
        "delete_port_forward",
        # clients
        "block_client",
        "unblock_client",
        "reconnect_client",
        # devices
        "restart_device",
        "locate_device",
        "set_port_state",
        "set_radio_tx_power",
        "set_radio_min_rssi",
        "set_radio_channel",
        "rename_device",
        # ipv6
        "set_wan_ipv6",
        "set_lan_ipv6",
        # composites
        "create_iot_network",
        "create_guest_network",
        "provision_homelab_service",
        "quarantine_client",
        # Phase 2 destructive
        "restore_config",
        # Phase 3 destructive (Protect)
        "set_camera_recording_mode",
        "set_camera_privacy_mode",
        "set_motion_sensitivity",
        "provision_camera",
        # Phase 4 destructive (UCG-Fiber security/VPN settings)
        "set_threat_management",
        "create_honeypot",
        "delete_honeypot",
        "set_teleport_enabled",
    }
)

#: Tools that wrap multiple sub-steps with rollback semantics. Their
#: descriptions must explain what rolls back and in what order.
COMPOSITE_TOOLS: frozenset[str] = frozenset(
    {
        "create_iot_network",
        "create_guest_network",
        "provision_homelab_service",
        "quarantine_client",
        "restore_config",
        "provision_camera",
    }
)

MIN_DESCRIPTION_LEN = 50


@pytest.fixture(scope="module")
def all_tools() -> list[dict[str, Any]]:
    """Build the server in stub mode with every module enabled, list every tool.

    Phase 3 added the Protect module; we explicitly enable it here so the
    description allowlist below sees Protect's tools alongside Network's.
    """
    import asyncio
    import os

    prior = os.environ.get("MCP_UNIFI_MODULES_ENABLED")
    os.environ["MCP_UNIFI_MODULES_ENABLED"] = "network,protect"
    try:
        settings = Settings(stub_mode=True, log_format="text", mcp_transport="stdio")
        server = build_server(settings)
    finally:
        if prior is None:
            os.environ.pop("MCP_UNIFI_MODULES_ENABLED", None)
        else:
            os.environ["MCP_UNIFI_MODULES_ENABLED"] = prior

    async def _list() -> list[Any]:
        tools_obj = await server.list_tools()
        return list(tools_obj.values()) if isinstance(tools_obj, dict) else list(tools_obj)

    tools = asyncio.run(_list())
    return [
        {
            "name": getattr(t, "name", None) or getattr(t, "key", "<unknown>"),
            "description": (getattr(t, "description", "") or "").strip(),
        }
        for t in tools
    ]


def test_every_tool_has_a_description(all_tools: list[dict[str, Any]]) -> None:
    """No tool may ship without a description (FastMCP would surface ``None``)."""
    missing = [t["name"] for t in all_tools if not t["description"]]
    assert not missing, f"Tools missing a description: {missing}"


def test_descriptions_meet_minimum_length(all_tools: list[dict[str, Any]]) -> None:
    """Catch terse one-liners that haven't been migrated to the new pattern."""
    too_short = [
        (t["name"], len(t["description"]))
        for t in all_tools
        if len(t["description"]) < MIN_DESCRIPTION_LEN
    ]
    assert not too_short, f"Descriptions shorter than {MIN_DESCRIPTION_LEN} chars: {too_short}"


def test_destructive_tools_mention_dry_run(all_tools: list[dict[str, Any]]) -> None:
    """Every mutating tool must surface the dry_run safety net in its description."""
    by_name = {t["name"]: t["description"] for t in all_tools}
    missing = []
    for name in sorted(DESTRUCTIVE_TOOLS):
        desc = by_name.get(name, "")
        if "dry_run" not in desc:
            missing.append(name)
    assert not missing, f"Destructive tools that don't mention dry_run in description: {missing}"


def test_composite_tools_mention_rollback(all_tools: list[dict[str, Any]]) -> None:
    """Every composite must explain its rollback contract."""
    by_name = {t["name"]: t["description"] for t in all_tools}
    missing = []
    for name in sorted(COMPOSITE_TOOLS):
        desc = by_name.get(name, "")
        if "Rollback" not in desc and "rollback" not in desc and "rolled back" not in desc:
            missing.append(name)
    assert not missing, f"Composite tools that don't mention rollback in description: {missing}"


def test_no_unknown_destructive_tools(all_tools: list[dict[str, Any]]) -> None:
    """If a new mutating tool ships, this test forces an update to ``DESTRUCTIVE_TOOLS``.

    Any tool whose name starts with ``create_``, ``update_``, ``delete_``,
    ``block_``, ``unblock_``, ``restart_``, ``locate_``, ``set_``,
    ``reconnect_``, ``quarantine_``, ``provision_``, or ``restore_`` is
    presumed destructive and must be allowlisted.
    """
    destructive_prefixes = (
        "create_",
        "update_",
        "delete_",
        "block_",
        "unblock_",
        "restart_",
        "locate_",
        "set_",
        "reconnect_",
        "quarantine_",
        "provision_",
        "restore_",
    )
    presumed_destructive = {
        t["name"] for t in all_tools if t["name"].startswith(destructive_prefixes)
    }
    missing = sorted(presumed_destructive - DESTRUCTIVE_TOOLS)
    assert not missing, (
        f"Tools that look destructive but aren't in DESTRUCTIVE_TOOLS: "
        f"{missing}. Add them to the allowlist (and to "
        f"scripts/compare_schemas.py::DESTRUCTIVE_TOOLS)."
    )
