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
        """List all firewall rules on the gateway.

        Returns:
            JSON list with _id, name, ruleset, rule_index, action, enabled,
            protocol, src_*, dst_* per rule.
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
        """Create a firewall rule.

        Args:
            name: Display name for the rule.
            ruleset: Where the rule is enforced. Common values:
                ``"LAN_IN"``, ``"LAN_OUT"``, ``"LAN_LOCAL"``,
                ``"WAN_IN"``, ``"WAN_OUT"``, ``"WAN_LOCAL"``,
                ``"GUEST_IN"``, ``"GUEST_OUT"``, ``"GUEST_LOCAL"``.
            action: ``"accept"``, ``"drop"``, or ``"reject"``.
            rule_index: Rule order. Lower = evaluated first. UniFi
                user-defined rules typically live in the 2000-3999 range; 2500
                is a safe default.
            protocol: ``"all"``, ``"tcp"``, ``"udp"``, ``"icmp"``, etc.
            src_address: Source CIDR (e.g. ``"10.0.20.0/24"``). Empty = any.
            dst_address: Destination CIDR. Empty = any.
            src_networkconf_id: Source network ``_id``. Use this OR
                src_address.
            dst_networkconf_id: Destination network ``_id``. Use this OR
                dst_address.
            enabled: Set False to create the rule disabled for staging.

        Returns:
            JSON of the created firewall rule.
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
                    "summary": (
                        f"Would create firewall rule '{name}' "
                        f"({action} on {ruleset})"
                    ),
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
        """Update fields on an existing firewall rule.

        Only the fields you supply are changed. Common partial keys:
        ``enabled``, ``action``, ``protocol``, ``rule_index``, ``src_address``,
        ``dst_address``, ``src_networkconf_id``, ``dst_networkconf_id``,
        ``name``.

        Args:
            rule_id: The ``_id`` from ``list_firewall_rules``.
            updates: Partial firewall-rule record.

        Returns:
            JSON of the updated rule, or an error if not found.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"rule_id": rule_id, "patch": updates},
                    "summary": (
                        f"Would update firewall rule {rule_id} ({len(updates)} field(s))"
                    ),
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
        """Delete a firewall rule.

        Args:
            rule_id: The ``_id`` from list_firewall_rules.

        Returns:
            JSON ``{"deleted": true, "rule_id": "..."}`` on success, or an
            error object if the gateway rejects the request.
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
