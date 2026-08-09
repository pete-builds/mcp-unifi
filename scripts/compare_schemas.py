"""Compare pre.json and post.json tool schemas.

Allowed changes per tool:

1. The ``controller: str = "default"`` parameter on every tool (Step 3).
2. The ``dry_run: bool = False`` parameter on destructive tools only (Step 4).
   Read-only tools (lists, ``get_*``, observability) MUST NOT carry it.

Net-new tools introduced in Phase 2 are also allowlisted via
``PHASE2_NEW_TOOLS`` so a re-run of this comparison after Phase 2 ships does
not flag them as regressions.

Anything else is a regression. Exits non-zero on any unexpected diff.

Usage:
    python scripts/compare_schemas.py scripts/pre.json scripts/post.json
    python scripts/compare_schemas.py scripts/pre.json scripts/post.json --allow-description-changes

When ``--allow-description-changes`` is passed, per-tool ``description`` text
diffs are tolerated (the script still flags any input-schema/parameter-shape
change as a regression). This mode is for Phase 2 Part C, which rewrites
every tool's description for LLM clarity without touching signatures.
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from typing import Any

#: The shape of the ``controller`` parameter, ignoring any docstring-derived
#: ``description`` field. Phase 2 Part C added param-level descriptions via
#: docstring ``Args:`` blocks, which FastMCP surfaces in the schema. The
#: contract is the type + default; the description is prose.
CONTROLLER_PARAM = {
    "default": "default",
    "type": "string",
}

DRY_RUN_PARAM = {
    "default": False,
    "type": "boolean",
}


def _strip_param_description(param: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``param`` with any ``description`` key removed.

    Phase 2 Part C added docstring-derived parameter descriptions, which
    FastMCP propagates into the JSON schema. The shape contract for the
    controller/dry_run parameters is type + default; description text is
    documentation, not contract.
    """
    out = dict(param)
    out.pop("description", None)
    return out


#: Tools that mutate state and therefore MUST gain ``dry_run`` in Step 4.
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
        # firewall groups
        "create_firewall_group",
        "update_firewall_group",
        "delete_firewall_group",
        # static routes
        "create_route",
        "update_route",
        "delete_route",
        # traffic rules (v2)
        "create_traffic_rule",
        "update_traffic_rule",
        "toggle_traffic_rule",
        # traffic routes (v2)
        "update_traffic_route",
        "toggle_traffic_route",
        # content filtering (v2 DNS)
        "update_content_filter",
        "delete_content_filter",
        # dynamic DNS
        "create_dynamic_dns",
        "update_dynamic_dns",
        "delete_dynamic_dns",
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
        # Phase 2 destructive tool
        "restore_config",
        # Phase 3 destructive (Protect)
        "set_camera_recording_mode",
        "set_camera_privacy_mode",
        "set_motion_sensitivity",
        "provision_camera",
        # Phase 4 destructive (UCG-Fiber security/VPN settings)
        "set_guest_portal",
        "set_threat_management",
        "create_honeypot",
        "delete_honeypot",
        "set_teleport_enabled",
    }
)

#: Tools introduced in Phase 2. Net-new on top of the Phase 1 schema; the
#: comparator no longer flags them as regressions when post.json is recaptured.
PHASE2_NEW_TOOLS: frozenset[str] = frozenset(
    {
        "audit_network_drift",
        "backup_config",
        "restore_config",
    }
)


def _strip_known_additions(
    schema: dict[str, Any],
    *,
    expect_dry_run: bool,
    allow_description_changes: bool = False,
) -> dict[str, Any]:
    """Return a copy of ``schema`` with ``controller`` (and optionally
    ``dry_run``) properties removed.

    When ``allow_description_changes`` is True, also strips any
    ``description`` key from every remaining parameter so per-param
    docstring additions don't trip the schema-equality check.
    """
    out = deepcopy(schema)
    props = out.get("properties", {})
    if "controller" in props:
        del props["controller"]
    if expect_dry_run and "dry_run" in props:
        del props["dry_run"]
    if allow_description_changes:
        for pname, pval in list(props.items()):
            if isinstance(pval, dict):
                props[pname] = _strip_param_description(pval)
    return out


def _load(path: str) -> dict[str, dict[str, Any]]:
    with open(path) as f:
        items = json.load(f)
    return {item["name"]: item for item in items}


def main() -> int:
    args = sys.argv[1:]
    allow_description_changes = False
    if "--allow-description-changes" in args:
        allow_description_changes = True
        args = [a for a in args if a != "--allow-description-changes"]

    if len(args) != 2:
        sys.stderr.write(
            "Usage: compare_schemas.py <pre.json> <post.json> [--allow-description-changes]\n"
        )
        return 2

    pre = _load(args[0])
    post = _load(args[1])

    pre_names = set(pre)
    post_names = set(post)
    # Phase 2 net-new tools are expected additions, not regressions.
    added = sorted((post_names - pre_names) - PHASE2_NEW_TOOLS)
    unexpected_phase2 = sorted(PHASE2_NEW_TOOLS - post_names)
    removed = sorted(pre_names - post_names)

    failures: list[str] = []

    if added:
        failures.append(f"Tools added (regression): {added}")
    if removed:
        failures.append(f"Tools removed (regression): {removed}")
    if unexpected_phase2:
        # Informational, not a hard failure: some Phase 2 tools may not yet
        # be present in post.json if it was captured mid-phase.
        sys.stderr.write(f"NOTE: Phase 2 tools missing from post.json: {unexpected_phase2}\n")

    same_tools_with_controller = 0
    same_tools_with_dry_run = 0
    description_changes = 0
    for name in sorted(pre_names & post_names):
        pre_t = pre[name]
        post_t = post[name]

        if pre_t["description"] != post_t["description"]:
            if allow_description_changes:
                description_changes += 1
            else:
                failures.append(f"{name}: description changed")

        post_props = post_t["input_schema"].get("properties", {})
        if "controller" not in post_props:
            failures.append(f"{name}: missing new 'controller' parameter")
        else:
            ctrl = post_props["controller"]
            ctrl_cmp = _strip_param_description(ctrl) if allow_description_changes else ctrl
            if ctrl_cmp != CONTROLLER_PARAM:
                failures.append(f"{name}: controller param shape unexpected: {ctrl}")
            else:
                same_tools_with_controller += 1

        expect_dry_run = name in DESTRUCTIVE_TOOLS
        if expect_dry_run:
            if "dry_run" not in post_props:
                failures.append(f"{name}: destructive tool missing 'dry_run' parameter")
            else:
                dr = post_props["dry_run"]
                dr_cmp = _strip_param_description(dr) if allow_description_changes else dr
                if dr_cmp != DRY_RUN_PARAM:
                    failures.append(f"{name}: dry_run param shape unexpected: {dr}")
                else:
                    same_tools_with_dry_run += 1
        elif "dry_run" in post_props:
            failures.append(f"{name}: read-only tool unexpectedly has 'dry_run' parameter")

        # Compare schemas with controller (+ dry_run if destructive) stripped.
        # When description changes are allowed, also strip per-param
        # description text from the remaining params so docstring rewrites
        # don't trip the equality check; param shape (type/default/required)
        # is still enforced.
        pre_schema = pre_t["input_schema"]
        if allow_description_changes:
            pre_schema = _strip_known_additions(
                pre_schema,
                expect_dry_run=False,  # pre.json may not have controller yet
                allow_description_changes=True,
            )
            # Re-add the controller stripping: pre might or might not have it
            # depending on which baseline was captured.
            pre_props = pre_schema.get("properties", {})
            pre_props.pop("controller", None)
            if expect_dry_run:
                pre_props.pop("dry_run", None)
        post_schema = _strip_known_additions(
            post_t["input_schema"],
            expect_dry_run=expect_dry_run,
            allow_description_changes=allow_description_changes,
        )
        if pre_schema != post_schema:
            failures.append(f"{name}: input_schema changed beyond the allowed additions")

    if failures:
        sys.stderr.write("REGRESSIONS:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1

    extra = ""
    if allow_description_changes and description_changes:
        extra = f" Description rewrites accepted on {description_changes} tool(s)."
    print(
        f"PASS: {len(pre_names)} tools, all unchanged except for "
        f"'controller' (on {same_tools_with_controller}) and "
        f"'dry_run' (on {same_tools_with_dry_run} destructive tools)."
        f"{extra}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
