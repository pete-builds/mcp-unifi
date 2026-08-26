"""Traffic-policy tools: v2 traffic rules and traffic routes.

These live on the UniFi **v2** controller surface
(``/proxy/network/v2/api/site/<site>/trafficrules`` and ``.../trafficroutes``),
which returns a bare JSON list rather than the legacy ``{"meta", "data"}``
envelope. Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
(2026-06-12): both endpoints answer HTTP 200 with an empty list on a fresh
gateway.

* **Traffic rules** are the modern app/domain/IP-based allow/block policies
  (the "Traffic Rules" page in the UniFi UI). A rule carries an ``action``
  (``BLOCK``/``ALLOW``), a ``matching_target``, target devices, and an
  ``enabled`` flag.
* **Traffic routes** are policy-based routing (the "Traffic Routes" page):
  send traffic matching a target (domain/IP/region) out a specific interface
  or VPN, with an optional ``kill_switch_enabled`` that drops the traffic if
  the route's interface is down.

The v2 PUT replaces the whole object, so ``update_*`` and ``toggle_*`` here
read the current record first, merge the change, and PUT the full result
(strict read-modify-write) to avoid dropping untouched fields.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import CREATE, READ_ONLY, WRITE_IDEMPOTENT
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry
    from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.network.traffic")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    async def _find_traffic_rule(backend: Backend, rule_id: str) -> UniFiRecord | None:
        rules = await backend.list_traffic_rules()
        return next((r for r in rules if isinstance(r, dict) and r.get("_id") == rule_id), None)

    async def _find_traffic_route(backend: Backend, route_id: str) -> UniFiRecord | None:
        routes = await backend.list_traffic_routes()
        return next((r for r in routes if isinstance(r, dict) and r.get("_id") == route_id), None)

    # ------------------------------------------------------------------
    # Traffic rules
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_traffic_rules", mutates=False)
    async def list_traffic_rules(controller: str = "default") -> str:
        """List v2 traffic rules (app/domain/IP-based allow & block policies).

        Side effects: None (read-only).

        Returns one record per rule with ``_id``, ``action``
        (``BLOCK``/``ALLOW``), ``matching_target``, ``target_devices``, and
        ``enabled``. Empty on a gateway with no traffic rules configured.

        Example: list_traffic_rules(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_traffic_rules())
        except UniFiError as exc:
            logger.exception("list_traffic_rules failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_traffic_rule_details", mutates=False)
    async def get_traffic_rule_details(rule_id: str, controller: str = "default") -> str:
        """Show one traffic rule's full record by ``_id``.

        Side effects: None (read-only). Call this before
        ``update_traffic_rule`` or ``toggle_traffic_rule`` to see the rule's
        current matching target and action.

        Returns the rule record, or an error envelope if no rule matches.

        Example: get_traffic_rule_details(rule_id="65f...")

        Args:
            rule_id: The ``_id`` from ``list_traffic_rules``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            target = await _find_traffic_rule(backend, rule_id)
        except UniFiError as exc:
            logger.exception("get_traffic_rule_details failed", extra={"rule_id": rule_id})
            return err(str(exc))
        if target is None:
            return err(f"traffic rule {rule_id} not found")
        return format_json(target)

    @mcp.tool(annotations=CREATE)
    @audited("create_traffic_rule", mutates=True)
    async def create_traffic_rule(
        rule: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a v2 traffic rule from a full rule object.

        Side effects:
        - Adds a new app/domain/IP allow-or-block policy that takes effect
          immediately on matching traffic.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        The v2 traffic-rule schema is rich and version-dependent, so this tool
        takes the full rule object as a dict rather than fixed parameters.
        Build it from a ``get_traffic_rule_details`` example on a similar rule,
        or from the UniFi UI's network inspector.

        Example: create_traffic_rule(rule={"action": "BLOCK", "matching_target": "INTERNET", "target_devices": [], "enabled": True})

        Args:
            rule: The full traffic-rule object. Common keys: ``action``
                (``"BLOCK"``/``"ALLOW"``), ``matching_target``
                (``"INTERNET"``/``"DOMAIN"``/``"IP"``/``"REGION"`` etc.),
                ``target_devices`` (list), ``enabled`` (bool), and the
                target-specific fields (``domains``, ``ip_addresses``,
                ``app_ids``, ``regions``) for the chosen ``matching_target``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not rule:
            return err("create_traffic_rule requires a non-empty rule object")
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"traffic_rule": rule},
                    "summary": (
                        f"Would create traffic rule "
                        f"({rule.get('action', '?')} {rule.get('matching_target', '?')})"
                    ),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_traffic_rule(rule))
        except UniFiError as exc:
            logger.exception("create_traffic_rule failed")
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_traffic_rule", mutates=True)
    async def update_traffic_rule(
        rule_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing traffic rule (read-modify-write).

        Side effects:
        - Modifies the named rule in place. The v2 PUT replaces the whole
          object, so this reads the current rule first and merges ``updates``
          onto it before writing — only the keys you supply change.
        - Takes effect immediately on matching traffic.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_traffic_rule(rule_id="65f...", updates={"action": "ALLOW"})

        Args:
            rule_id: The ``_id`` from ``list_traffic_rules``.
            updates: Partial traffic-rule record to merge. Common keys:
                ``action``, ``matching_target``, ``target_devices``,
                ``enabled``, plus target-specific fields.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        try:
            backend = resolve_backend(registry, controller)
            existing = await _find_traffic_rule(backend, rule_id)
        except UniFiError as exc:
            logger.exception("update_traffic_rule lookup failed", extra={"rule_id": rule_id})
            return err(str(exc))
        if existing is None:
            return err(f"traffic rule {rule_id} not found")
        merged = {**existing, **updates}
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"rule_id": rule_id, "patch": updates},
                    "summary": (f"Would update traffic rule {rule_id} ({len(updates)} field(s))"),
                }
            )
        try:
            updated = await backend.update_traffic_rule(rule_id, merged)
            if updated is None:
                return err(f"traffic rule {rule_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_traffic_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("toggle_traffic_rule", mutates=True)
    async def toggle_traffic_rule(
        rule_id: str,
        enabled: bool,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Enable or disable a traffic rule without editing its other fields.

        Side effects:
        - Flips the rule's ``enabled`` flag. Reads the current rule first and
          PUTs the full object back with only ``enabled`` changed
          (read-modify-write), so the rest of the rule is preserved.
        - Takes effect immediately: a disabled BLOCK rule stops blocking; a
          disabled ALLOW rule stops allowing.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: toggle_traffic_rule(rule_id="65f...", enabled=False)

        Args:
            rule_id: The ``_id`` from ``list_traffic_rules``.
            enabled: ``True`` to enable the rule, ``False`` to disable it.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        try:
            backend = resolve_backend(registry, controller)
            existing = await _find_traffic_rule(backend, rule_id)
        except UniFiError as exc:
            logger.exception("toggle_traffic_rule lookup failed", extra={"rule_id": rule_id})
            return err(str(exc))
        if existing is None:
            return err(f"traffic rule {rule_id} not found")
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {
                        "rule_id": rule_id,
                        "before": {"enabled": existing.get("enabled")},
                        "after": {"enabled": enabled},
                    },
                    "summary": (
                        f"Would {'enable' if enabled else 'disable'} traffic rule {rule_id}"
                    ),
                }
            )
        merged = {**existing, "enabled": enabled}
        try:
            updated = await backend.update_traffic_rule(rule_id, merged)
            if updated is None:
                return err(f"traffic rule {rule_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("toggle_traffic_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # Traffic routes (policy-based routing)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_traffic_routes", mutates=False)
    async def list_traffic_routes(controller: str = "default") -> str:
        """List v2 traffic routes (policy-based routing, e.g. VPN-client routes).

        Side effects: None (read-only).

        Returns one record per route with ``_id``, ``matching_target``,
        ``next_hop`` / ``network_id`` (the interface or VPN the matched
        traffic is sent out), ``kill_switch_enabled``, and ``enabled``. Empty
        on a gateway with no policy routes configured.

        Example: list_traffic_routes(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_traffic_routes())
        except UniFiError as exc:
            logger.exception("list_traffic_routes failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_traffic_route_details", mutates=False)
    async def get_traffic_route_details(route_id: str, controller: str = "default") -> str:
        """Show one traffic route's full record by ``_id``.

        Side effects: None (read-only). Call this before
        ``update_traffic_route`` or ``toggle_traffic_route`` to see the route's
        current matching target, next hop, and kill-switch state.

        Returns the route record, or an error envelope if no route matches.

        Example: get_traffic_route_details(route_id="65f...")

        Args:
            route_id: The ``_id`` from ``list_traffic_routes``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            target = await _find_traffic_route(backend, route_id)
        except UniFiError as exc:
            logger.exception("get_traffic_route_details failed", extra={"route_id": route_id})
            return err(str(exc))
        if target is None:
            return err(f"traffic route {route_id} not found")
        return format_json(target)

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_traffic_route", mutates=True)
    async def update_traffic_route(
        route_id: str,
        updates: dict[str, Any] | None = None,
        kill_switch_enabled: bool | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing traffic route (read-modify-write).

        Side effects:
        - Modifies the named policy route in place. The v2 PUT replaces the
          whole object, so this reads the current route first and merges your
          changes onto it before writing — only the keys you supply change.
        - Changes where matched traffic is routed (and, via
          ``kill_switch_enabled``, whether it is dropped when the route's
          interface is down). Takes effect immediately.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_traffic_route(route_id="65f...", kill_switch_enabled=True)

        Args:
            route_id: The ``_id`` from ``list_traffic_routes``.
            updates: Partial traffic-route record to merge. Common keys:
                ``matching_target``, ``domains``, ``ip_addresses``,
                ``next_hop``, ``network_id``, ``enabled``. ``None`` (default)
                applies no field changes beyond ``kill_switch_enabled``.
            kill_switch_enabled: When set, toggles the route's kill switch
                (drop matched traffic if the route's interface is down).
                ``None`` (default) leaves it unchanged. Merged into ``updates``
                if both are given.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        patch: dict[str, Any] = dict(updates) if updates else {}
        if kill_switch_enabled is not None:
            patch["kill_switch_enabled"] = kill_switch_enabled
        if not patch:
            return err("update_traffic_route requires at least one of updates, kill_switch_enabled")
        try:
            backend = resolve_backend(registry, controller)
            existing = await _find_traffic_route(backend, route_id)
        except UniFiError as exc:
            logger.exception("update_traffic_route lookup failed", extra={"route_id": route_id})
            return err(str(exc))
        if existing is None:
            return err(f"traffic route {route_id} not found")
        merged = {**existing, **patch}
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"route_id": route_id, "patch": patch},
                    "summary": (f"Would update traffic route {route_id} ({len(patch)} field(s))"),
                }
            )
        try:
            updated = await backend.update_traffic_route(route_id, merged)
            if updated is None:
                return err(f"traffic route {route_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_traffic_route failed", extra={"route_id": route_id})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("toggle_traffic_route", mutates=True)
    async def toggle_traffic_route(
        route_id: str,
        enabled: bool,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Enable or disable a traffic route without editing its other fields.

        Side effects:
        - Flips the route's ``enabled`` flag. Reads the current route first
          and PUTs the full object back with only ``enabled`` changed
          (read-modify-write), so the rest of the route is preserved.
        - Takes effect immediately: a disabled route stops steering its
          matched traffic, which then follows the default route.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: toggle_traffic_route(route_id="65f...", enabled=False)

        Args:
            route_id: The ``_id`` from ``list_traffic_routes``.
            enabled: ``True`` to enable the route, ``False`` to disable it.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        try:
            backend = resolve_backend(registry, controller)
            existing = await _find_traffic_route(backend, route_id)
        except UniFiError as exc:
            logger.exception("toggle_traffic_route lookup failed", extra={"route_id": route_id})
            return err(str(exc))
        if existing is None:
            return err(f"traffic route {route_id} not found")
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {
                        "route_id": route_id,
                        "before": {"enabled": existing.get("enabled")},
                        "after": {"enabled": enabled},
                    },
                    "summary": (
                        f"Would {'enable' if enabled else 'disable'} traffic route {route_id}"
                    ),
                }
            )
        merged = {**existing, "enabled": enabled}
        try:
            updated = await backend.update_traffic_route(route_id, merged)
            if updated is None:
                return err(f"traffic route {route_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("toggle_traffic_route failed", extra={"route_id": route_id})
            return err(str(exc))


__all__ = ["register"]
