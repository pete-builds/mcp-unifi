"""Firewall tools: rules (list/create/update/delete) and reusable groups."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import CREATE, DESTRUCTIVE, READ_ONLY, WRITE_IDEMPOTENT
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedName,
)
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.firewall")

#: Accepted ``group_type`` values for a reusable firewall group.
_FIREWALL_GROUP_TYPES: frozenset[str] = frozenset(
    {"address-group", "ipv6-address-group", "port-group"}
)


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_firewall_rules", mutates=False)
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
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_firewall_rules())
        except UniFiError as exc:
            logger.exception("list_firewall_rules failed")
            return err(str(exc))

    @mcp.tool(annotations=CREATE)
    @audited("create_firewall_rule", mutates=True)
    async def create_firewall_rule(
        name: BoundedName,
        ruleset: str,
        action: str,
        rule_index: int = 20000,
        protocol: str = "all",
        src_address: str = "",
        dst_address: str = "",
        src_networkconf_id: str = "",
        dst_networkconf_id: str = "",
        src_networkconf_type: str = "NETv4",
        dst_networkconf_type: str = "NETv4",
        src_port: str = "",
        dst_port: str = "",
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

        Example: create_firewall_rule(name="Allow IoT to Plex", ruleset="LAN_IN", action="accept", protocol="tcp", src_networkconf_id="65f...", dst_networkconf_id="65a...", dst_port="32400")

        Args:
            name: Display name for the rule (e.g. ``"Block iot to LAN"``).
            ruleset: Where the rule is enforced. Common values: ``"LAN_IN"``,
                ``"LAN_OUT"``, ``"LAN_LOCAL"``, ``"WAN_IN"``, ``"WAN_OUT"``,
                ``"WAN_LOCAL"``, ``"GUEST_IN"``, ``"GUEST_OUT"``,
                ``"GUEST_LOCAL"``.
            action: ``"accept"``, ``"drop"``, or ``"reject"``.
            rule_index: Evaluation order. Lower = evaluated first. On UniFi
                Network 9.x (Zone-Based Firewall), user-defined LAN_IN rules
                live at ``20000`` and above; lower bands are reserved by the
                controller and will fail with
                ``api.err.FirewallRuleIndexOutOfRange``. ``20000`` is the safe
                default. (Older controllers used 2000-3999.)
            protocol: ``"all"``, ``"tcp"``, ``"udp"``, ``"icmp"``, etc.
                Port matches require ``"tcp"`` or ``"udp"``.
            src_address: Source CIDR (e.g. ``"10.50.0.0/24"``). Empty = any.
            dst_address: Destination CIDR. Empty = any.
            src_networkconf_id: Source network ``_id``. Use this OR
                ``src_address``.
            dst_networkconf_id: Destination network ``_id``. Use this OR
                ``dst_address``.
            src_networkconf_type: Discriminator that pairs with
                ``src_networkconf_id``. UniFi Network 9.x ZBF requires this
                whenever a rule references a network conf by ``_id`` and
                returns ``api.err.FirewallRuleNetworkConfTypeRequired``
                otherwise. Defaults to ``"NETv4"`` (IPv4 network). Only
                emitted to the controller when ``src_networkconf_id`` is set.
            dst_networkconf_type: Discriminator that pairs with
                ``dst_networkconf_id``. Same semantics as
                ``src_networkconf_type``. Defaults to ``"NETv4"``.
            src_port: Source port match. Single port (``"443"``), CSV
                (``"80,443"``), or range (``"3000-3100"``). Empty = any.
                Requires ``protocol`` set to ``"tcp"`` or ``"udp"``.
            dst_port: Destination port match. Same syntax as ``src_port``.
                The headline use case: ``dst_port="32400"`` with
                ``protocol="tcp"`` to allow IoT→Plex without opening the
                rest of MGMT.
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
            payload["src_networkconf_type"] = src_networkconf_type
        if dst_networkconf_id:
            payload["dst_networkconf_id"] = dst_networkconf_id
            payload["dst_networkconf_type"] = dst_networkconf_type
        if src_port:
            payload["src_port"] = src_port
        if dst_port:
            payload["dst_port"] = dst_port
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
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_firewall_rule(payload))
        except UniFiError as exc:
            logger.exception("create_firewall_rule failed", extra={"rule_name": name})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_firewall_rule", mutates=True)
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
                ``dst_networkconf_id``, ``src_port``, ``dst_port``, ``name``.
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
            backend = resolve_backend(registry, controller)
            updated = await backend.update_firewall_rule(rule_id, updates)
            if updated is None:
                return err(f"firewall rule {rule_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_firewall_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))

    @mcp.tool(annotations=DESTRUCTIVE)
    @audited("delete_firewall_rule", mutates=True)
    async def delete_firewall_rule(
        rule_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a firewall rule.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the rule. Traffic that previously matched it
          falls through to the next rule (or the implicit default).
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_firewall_rule(rule_id="65f...")

        Args:
            rule_id: The ``_id`` from ``list_firewall_rules``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: ``True`` skips token generation and returns the legacy
                ``{"dry_run": true, ...}`` envelope. ``False`` (default)
                generates a preview token that must be confirmed.
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
            backend = resolve_backend(registry, controller)
            rules = await backend.list_firewall_rules()
        except UniFiError as exc:
            logger.exception(
                "delete_firewall_rule preview lookup failed", extra={"rule_id": rule_id}
            )
            return err(str(exc))

        target = next((r for r in rules if isinstance(r, dict) and r.get("_id") == rule_id), None)
        if target is None:
            return err(f"firewall rule {rule_id} not found")

        resource = {
            "_id": rule_id,
            "name": target.get("name"),
            "ruleset": target.get("ruleset"),
            "action": target.get("action"),
            "enabled": target.get("enabled"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_firewall_rule(rule_id)
                return format_json({"deleted": ok, "rule_id": rule_id})
            except UniFiError as exc:
                logger.exception("delete_firewall_rule failed", extra={"rule_id": rule_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_firewall_rule",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))

    # ------------------------------------------------------------------
    # Firewall groups (reusable address/port objects)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_firewall_groups", mutates=False)
    async def list_firewall_groups(controller: str = "default") -> str:
        """List reusable firewall groups (address, IPv6-address, and port groups).

        Side effects: None (read-only).

        Firewall groups are named, reusable sets of addresses or ports that
        firewall rules and other policies reference by ``_id`` instead of
        repeating literals. Returns one record per group with ``_id``,
        ``name``, ``group_type`` (``address-group``/``ipv6-address-group``/
        ``port-group``), and ``group_members`` (the list of CIDRs, IPs, or
        ports).

        Example: list_firewall_groups(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_firewall_groups())
        except UniFiError as exc:
            logger.exception("list_firewall_groups failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_firewall_group_details", mutates=False)
    async def get_firewall_group_details(group_id: str, controller: str = "default") -> str:
        """Show one firewall group's full record by ``_id``.

        Side effects: None (read-only). Call this before
        ``update_firewall_group`` to see the current members you are about to
        read-modify-write.

        Returns the group record with ``_id``, ``name``, ``group_type``, and
        ``group_members``, or an error envelope if no group matches.

        Example: get_firewall_group_details(group_id="65f...")

        Args:
            group_id: The ``_id`` from ``list_firewall_groups``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            groups = await backend.list_firewall_groups()
        except UniFiError as exc:
            logger.exception("get_firewall_group_details failed", extra={"group_id": group_id})
            return err(str(exc))
        target = next((g for g in groups if isinstance(g, dict) and g.get("_id") == group_id), None)
        if target is None:
            return err(f"firewall group {group_id} not found")
        return format_json(target)

    @mcp.tool(annotations=CREATE)
    @audited("create_firewall_group", mutates=True)
    async def create_firewall_group(
        name: BoundedName,
        group_type: str,
        members: list[str],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a reusable firewall group of addresses, IPv6 addresses, or ports.

        Side effects:
        - Adds a new reusable object. It does nothing on its own until a
          firewall rule or policy references it by ``_id``.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_firewall_group(name="IoT Subnets", group_type="address-group", members=["10.50.0.0/24", "10.60.0.0/24"])

        Args:
            name: Display name for the group (e.g. ``"IoT Subnets"``).
            group_type: One of ``"address-group"`` (IPv4 CIDRs/IPs),
                ``"ipv6-address-group"`` (IPv6 CIDRs/IPs), or ``"port-group"``
                (TCP/UDP port numbers and ranges).
            members: The group's members as strings. For address groups:
                CIDRs or IPs (``"10.50.0.0/24"``). For IPv6 address groups:
                IPv6 CIDRs/IPs. For port groups: ports or ranges
                (``"443"``, ``"8000-8100"``).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        gt = group_type.strip().lower()
        if gt not in _FIREWALL_GROUP_TYPES:
            return err(
                f"invalid group_type {group_type!r}: use address-group, "
                "ipv6-address-group, or port-group"
            )
        payload: dict[str, Any] = {
            "name": name,
            "group_type": gt,
            "group_members": list(members),
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"firewall_group": payload},
                    "summary": (f"Would create {gt} '{name}' with {len(members)} member(s)"),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_firewall_group(payload))
        except UniFiError as exc:
            logger.exception("create_firewall_group failed", extra={"group_name": name})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_firewall_group", mutates=True)
    async def update_firewall_group(
        group_id: str,
        name: BoundedName = "",
        members: list[str] | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Rename a firewall group or replace its members (read-modify-write).

        Side effects:
        - Replaces the group's name and/or members in place. The members list
          is **replaced wholesale**, not merged, so pass the full desired set.
          The group's ``group_type`` is preserved (it is read first and
          written back unchanged); group type cannot be changed after
          creation, only members.
        - Every rule referencing this group immediately sees the new members.
        - Mutates controller state. Use dry_run=True to preview the before/
          after diff without applying.

        Read first: call ``get_firewall_group_details`` to see the current
        members.

        Example: update_firewall_group(group_id="65f...", members=["10.50.0.0/24", "10.70.0.0/24"])

        Args:
            group_id: The ``_id`` from ``list_firewall_groups``.
            name: New display name. Empty (default) keeps the current name.
            members: New full member list (replaces the old one). ``None``
                (default) keeps the current members.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the before/after diff without applying it.
        """
        if not name and members is None:
            return err("update_firewall_group requires at least one of name, members")
        try:
            backend = resolve_backend(registry, controller)
            groups = await backend.list_firewall_groups()
        except UniFiError as exc:
            logger.exception("update_firewall_group lookup failed", extra={"group_id": group_id})
            return err(str(exc))
        existing = next(
            (g for g in groups if isinstance(g, dict) and g.get("_id") == group_id), None
        )
        if existing is None:
            return err(f"firewall group {group_id} not found")

        # Full-PUT read-modify-write: send the whole record back with the
        # requested fields changed so the controller doesn't drop untouched
        # keys (group_type, site_id, etc.).
        payload: dict[str, Any] = {k: v for k, v in existing.items() if k != "_id"}
        before = {
            "name": existing.get("name"),
            "group_type": existing.get("group_type"),
            "group_members": existing.get("group_members"),
        }
        if name:
            payload["name"] = name
        if members is not None:
            payload["group_members"] = list(members)
        after = {
            "name": payload.get("name"),
            "group_type": payload.get("group_type"),
            "group_members": payload.get("group_members"),
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {
                        "group_id": group_id,
                        "before": before,
                        "after": after,
                    },
                    "summary": f"Would update firewall group {existing.get('name')!r}",
                }
            )
        try:
            updated = await backend.update_firewall_group(group_id, payload)
            if updated is None:
                return err(f"firewall group {group_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_firewall_group failed", extra={"group_id": group_id})
            return err(str(exc))

    @mcp.tool(annotations=DESTRUCTIVE)
    @audited("delete_firewall_group", mutates=True)
    async def delete_firewall_group(
        group_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a firewall group.

        This tool no longer deletes on its own. It returns a preview envelope
        with a ``token``; call ``confirm_destructive_action(token)`` to commit
        the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the group. **The controller rejects deletion of
          a group still referenced by any firewall rule** — detach it from
          every rule first.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_firewall_group(group_id="65f...")

        Args:
            group_id: The ``_id`` from ``list_firewall_groups``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: ``True`` skips token generation and returns the legacy
                ``{"dry_run": true, ...}`` envelope. ``False`` (default)
                generates a preview token that must be confirmed.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"group_id": group_id},
                    "summary": f"Would delete firewall group {group_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            groups = await backend.list_firewall_groups()
        except UniFiError as exc:
            logger.exception(
                "delete_firewall_group preview lookup failed", extra={"group_id": group_id}
            )
            return err(str(exc))

        target = next((g for g in groups if isinstance(g, dict) and g.get("_id") == group_id), None)
        if target is None:
            return err(f"firewall group {group_id} not found")

        resource = {
            "_id": group_id,
            "name": target.get("name"),
            "group_type": target.get("group_type"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_firewall_group(group_id)
                return format_json({"deleted": ok, "group_id": group_id})
            except UniFiError as exc:
                logger.exception("delete_firewall_group failed", extra={"group_id": group_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_firewall_group",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
