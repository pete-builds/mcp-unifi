"""Compare pre.json and post.json tool schemas.

Allowed changes per tool:

1. The ``controller: str = "default"`` parameter on every tool (Step 3).
2. The ``dry_run: bool = False`` parameter on destructive tools only (Step 4).
   Read-only tools (lists, ``get_*``, observability) MUST NOT carry it.

Anything else is a regression. Exits non-zero on any unexpected diff.

Usage:
    python scripts/compare_schemas.py scripts/pre.json scripts/post.json
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from typing import Any

CONTROLLER_PARAM = {
    "default": "default",
    "type": "string",
}

DRY_RUN_PARAM = {
    "default": False,
    "type": "boolean",
}

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
        # port profiles
        "create_port_profile",
        "update_port_profile",
        "delete_port_profile",
        # dhcp
        "create_static_dhcp_lease",
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
        # composites
        "create_iot_network",
        "create_guest_network",
        "provision_homelab_service",
        "quarantine_client",
    }
)


def _strip_known_additions(
    schema: dict[str, Any], *, expect_dry_run: bool
) -> dict[str, Any]:
    """Return a copy of ``schema`` with ``controller`` (and optionally
    ``dry_run``) properties removed."""
    out = deepcopy(schema)
    props = out.get("properties", {})
    if "controller" in props:
        del props["controller"]
    if expect_dry_run and "dry_run" in props:
        del props["dry_run"]
    return out


def _load(path: str) -> dict[str, dict[str, Any]]:
    with open(path) as f:
        items = json.load(f)
    return {item["name"]: item for item in items}


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: compare_schemas.py <pre.json> <post.json>\n")
        return 2

    pre = _load(sys.argv[1])
    post = _load(sys.argv[2])

    pre_names = set(pre)
    post_names = set(post)
    added = sorted(post_names - pre_names)
    removed = sorted(pre_names - post_names)

    failures: list[str] = []

    if added:
        failures.append(f"Tools added (regression): {added}")
    if removed:
        failures.append(f"Tools removed (regression): {removed}")

    same_tools_with_controller = 0
    same_tools_with_dry_run = 0
    for name in sorted(pre_names & post_names):
        pre_t = pre[name]
        post_t = post[name]

        if pre_t["description"] != post_t["description"]:
            failures.append(f"{name}: description changed")

        post_props = post_t["input_schema"].get("properties", {})
        if "controller" not in post_props:
            failures.append(f"{name}: missing new 'controller' parameter")
        else:
            ctrl = post_props["controller"]
            if ctrl != CONTROLLER_PARAM:
                failures.append(
                    f"{name}: controller param shape unexpected: {ctrl}"
                )
            else:
                same_tools_with_controller += 1

        expect_dry_run = name in DESTRUCTIVE_TOOLS
        if expect_dry_run:
            if "dry_run" not in post_props:
                failures.append(
                    f"{name}: destructive tool missing 'dry_run' parameter"
                )
            else:
                dr = post_props["dry_run"]
                if dr != DRY_RUN_PARAM:
                    failures.append(
                        f"{name}: dry_run param shape unexpected: {dr}"
                    )
                else:
                    same_tools_with_dry_run += 1
        elif "dry_run" in post_props:
            failures.append(
                f"{name}: read-only tool unexpectedly has 'dry_run' parameter"
            )

        # Compare schemas with controller (+ dry_run if destructive) stripped.
        pre_schema = pre_t["input_schema"]
        post_schema = _strip_known_additions(
            post_t["input_schema"], expect_dry_run=expect_dry_run
        )
        if pre_schema != post_schema:
            failures.append(
                f"{name}: input_schema changed beyond the allowed additions"
            )

    if failures:
        sys.stderr.write("REGRESSIONS:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1

    print(
        f"PASS: {len(pre_names)} tools, all unchanged except for "
        f"'controller' (on {same_tools_with_controller}) and "
        f"'dry_run' (on {same_tools_with_dry_run} destructive tools)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
