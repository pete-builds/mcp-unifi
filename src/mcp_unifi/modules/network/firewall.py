"""Firewall rule tools: list, create, update, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.firewall")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_firewall_rules")
    async def list_firewall_rules(controller: str = "default") -> str:
        """List every firewall rule on the controller.

        Side effects: None (read-only).

        Returns one record per rule with ``_id``, ``name``, ``ruleset``,
        ``rule_index``, ``action``, ``enabled``, ``protocol``, and
        ``src_*``/``dst_*`` fields.

        Example: list_firewall_rules(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_firewall_rules())
        except UniFiError as exc:
            logger.exception("list_firewall_rules failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_firewall_rule")
    async def create_firewall_rule(
        name: str,
        ruleset: str,
        action: str,
        rule_index: int = 2500,
        protocol: str = "all",
        src_address: str = "",
        dst_address: str = "",
        src_networkconf_id: str = "",
        dst_networkconf_id: str = "",
        enabled: bool = True,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a firewall rule on the controller.

        Side effects:
        - Adds a new rule into the named ``ruleset`` at the given
          ``rule_index``. Rules with lower indexes evaluate first.
        - Takes effect immediately on the next packet hitting the affected
          datapath.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_firewall_rule(name="Block iot to LAN", ruleset="LAN_IN", action="drop", src_address="10.50.0.0/24", dst_address="192.168.1.0/24")

        Args:
            name: Display name for the rule (e.g. ``"Block iot to LAN"``).
            ruleset: Where the rule is enforced. Common values: ``"LAN_IN"``,
                ``"LAN_OUT"``, ``"LAN_LOCAL"``, ``"WAN_IN"``, ``"WAN_OUT"``,
                ``"WAN_LOCAL"``, ``"GUEST_IN"``, ``"GUEST_OUT"``,
                ``"GUEST_LOCAL"``.
            action: ``"accept"``, ``"drop"``, or ``"reject"``.
            rule_index: Evaluation order. Lower = evaluated first. UniFi
                user-defined rules typically live in the 2000-3999 range;
                2500 is a safe default.
            protocol: ``"all"``, ``"tcp"``, ``"udp"``, ``"icmp"``, etc.
            src_address: Source CIDR (e.g. ``"10.50.0.0/24"``). Empty = any.
            dst_address: Destination CIDR. Empty = any.
            src_networkconf_id: Source network ``_id``. Use this OR
                ``src_address``.
            dst_networkconf_id: Destination network ``_id``. Use this OR
                ``dst_address``.
            enabled: ``False`` creates the rule disabled for staging.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        payload: dict[str, Any] = {
            "name": name,
            "ruleset": ruleset,
            "rule_index": rule_index,
            "action": action,
            "protocol": protocol,
            "enabled": enabled,
        }
        if src_address:
            payload["src_address"] = src_address
        if dst_address:
            payload["dst_address"] = dst_address
        if src_networkconf_id:
            payload["src_networkconf_id"] = src_networkconf_id
        if dst_networkconf_id:
            payload["dst_networkconf_id"] = dst_networkconf_id
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"firewall_rule": payload},
                    "summary": (f"Would create firewall rule '{name}' ({action} on {ruleset})"),
                }
            )
        try:
            backend = registry.get(controller)
            return format_json(await backend.create_firewall_rule(payload))
        except UniFiError as exc:
            logger.exception("create_firewall_rule failed", extra={"rule_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_firewall_rule")
    async def update_firewall_rule(
        rule_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing firewall rule.

        Side effects:
        - Modifies the named rule in place. Only fields supplied in
          ``updates`` change; everything else is preserved.
        - Takes effect immediately on the next packet hitting the affected
          datapath.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_firewall_rule(rule_id="65f...", updates={"enabled": False})

        Args:
            rule_id: The ``_id`` from ``list_firewall_rules``.
            updates: Partial firewall-rule record. Common keys: ``enabled``,
                ``action``, ``protocol``, ``rule_index``, ``src_address``,
                ``dst_address``, ``src_networkconf_id``,
                ``dst_networkconf_id``, ``name``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"rule_id": rule_id, "patch": updates},
                    "summary": (f"Would update firewall rule {rule_id} ({len(updates)} field(s))"),
                }
            )
        try:
            backend = registry.get(controller)
            updated = await backend.update_firewall_rule(rule_id, updates)
            if updated is None:
                return err(f"firewall rule {rule_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_firewall_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_firewall_rule")
    async def delete_firewall_rule(
        rule_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Delete a firewall rule from the controller.

        Side effects:
        - Removes the rule. Traffic that previously matched it falls through
          to the next rule (or the implicit default).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: delete_firewall_rule(rule_id="65f...")

        Args:
            rule_id: The ``_id`` from ``list_firewall_rules``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"rule_id": rule_id},
                    "summary": f"Would delete firewall rule {rule_id}",
                }
            )
        try:
            backend = registry.get(controller)
            ok = await backend.delete_firewall_rule(rule_id)
            return format_json({"deleted": ok, "rule_id": rule_id})
        except UniFiError as exc:
            logger.exception("delete_firewall_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))
