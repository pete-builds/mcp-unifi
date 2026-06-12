"""Static routing tools: list, get, create, update, delete.

Static (next-hop) routes live in the legacy ``/rest/routing`` collection.
Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
(2026-06-12): ``GET /rest/routing`` returns the standard ``{"meta", "data"}``
envelope (empty on a fresh gateway). A static route carries:

    ``name``                     display name
    ``type``                     ``"static-route"``
    ``static-route_network``     destination CIDR (e.g. ``"10.99.0.0/24"``)
    ``static-route_nexthop``     next-hop gateway IP
    ``static-route_distance``    administrative distance (lower = preferred)
    ``static-route_type``        ``"nexthop-route"`` (vs interface-route)
    ``enabled``                  bool

These are distinct from **traffic routes** (policy-based routing on the v2
surface, see ``traffic.py``): static routes are classic destination-based
next-hop routing.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.routing")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_routes")
    async def list_routes(controller: str = "default") -> str:
        """List user-defined static (next-hop) routes on the controller.

        Side effects: None (read-only).

        Returns one record per route with ``_id``, ``name``, ``type``,
        ``static-route_network`` (destination CIDR),
        ``static-route_nexthop`` (next-hop IP), ``static-route_distance``,
        and ``enabled``. Empty on a gateway with no custom routes (the default
        route is managed by the WAN config, not listed here).

        Example: list_routes(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_routes())
        except UniFiError as exc:
            logger.exception("list_routes failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_route_details")
    async def get_route_details(route_id: str, controller: str = "default") -> str:
        """Show one static route's full record by ``_id``.

        Side effects: None (read-only). Call this before ``update_route`` to
        see the current destination, next hop, and distance.

        Returns the route record, or an error envelope if no route matches.

        Example: get_route_details(route_id="65f...")

        Args:
            route_id: The ``_id`` from ``list_routes``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            routes = await backend.list_routes()
        except UniFiError as exc:
            logger.exception("get_route_details failed", extra={"route_id": route_id})
            return err(str(exc))
        target = next(
            (r for r in routes if isinstance(r, dict) and r.get("_id") == route_id), None
        )
        if target is None:
            return err(f"route {route_id} not found")
        return format_json(target)

    @mcp.tool()
    @audited("create_route")
    async def create_route(
        name: str,
        destination: str,
        next_hop: str,
        distance: int = 1,
        enabled: bool = True,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a static next-hop route.

        Side effects:
        - Adds a destination-based route: traffic to ``destination`` is sent
          to ``next_hop`` instead of following the default route. Takes effect
          immediately on the gateway's routing table.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        BLAST RADIUS: a static route changes where traffic for the
        destination prefix is sent. A wrong next-hop can black-hole that
        prefix. It does not affect traffic outside ``destination``.

        Example: create_route(name="Lab via firewall", destination="10.99.0.0/24", next_hop="192.168.1.254")

        Args:
            name: Display name for the route (e.g. ``"Lab via firewall"``).
            destination: Destination network in CIDR form
                (``"10.99.0.0/24"``). This is the prefix the route matches.
            next_hop: Next-hop gateway IP that traffic to ``destination`` is
                forwarded to (must be reachable on a directly-connected
                network).
            distance: Administrative distance (1-255). Lower wins when two
                routes match the same destination. Defaults to ``1``.
            enabled: ``False`` creates the route disabled for staging.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not 1 <= distance <= 255:
            return err(f"distance {distance} out of range (1-255)")
        payload: dict[str, Any] = {
            "name": name,
            "type": "static-route",
            "static-route_network": destination,
            "static-route_nexthop": next_hop,
            "static-route_distance": distance,
            "static-route_type": "nexthop-route",
            "enabled": enabled,
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"route": payload},
                    "summary": (
                        f"Would create static route '{name}' "
                        f"({destination} via {next_hop})"
                    ),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_route(payload))
        except UniFiError as exc:
            logger.exception("create_route failed", extra={"route_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_route")
    async def update_route(
        route_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing static route.

        Side effects:
        - Modifies the named route in place. Only fields supplied in
          ``updates`` change; everything else is preserved.
        - Takes effect immediately on the gateway's routing table.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_route(route_id="65f...", updates={"enabled": False})

        Args:
            route_id: The ``_id`` from ``list_routes``.
            updates: Partial route record. Common keys: ``name``, ``enabled``,
                ``static-route_network`` (destination CIDR),
                ``static-route_nexthop`` (next-hop IP),
                ``static-route_distance``.
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
                    "would_update": {"route_id": route_id, "patch": updates},
                    "summary": f"Would update route {route_id} ({len(updates)} field(s))",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            updated = await backend.update_route(route_id, updates)
            if updated is None:
                return err(f"route {route_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_route failed", extra={"route_id": route_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_route")
    async def delete_route(
        route_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a static route.

        This tool no longer deletes on its own. It returns a preview envelope
        with a ``token``; call ``confirm_destructive_action(token)`` to commit
        the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the route. Traffic to the destination prefix
          falls back to the default route (or another matching route).
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_route(route_id="65f...")

        Args:
            route_id: The ``_id`` from ``list_routes``.
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
                    "would_delete": {"route_id": route_id},
                    "summary": f"Would delete route {route_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            routes = await backend.list_routes()
        except UniFiError as exc:
            logger.exception("delete_route preview lookup failed", extra={"route_id": route_id})
            return err(str(exc))

        target = next(
            (r for r in routes if isinstance(r, dict) and r.get("_id") == route_id), None
        )
        if target is None:
            return err(f"route {route_id} not found")

        resource = {
            "_id": route_id,
            "name": target.get("name"),
            "static-route_network": target.get("static-route_network"),
            "static-route_nexthop": target.get("static-route_nexthop"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_route(route_id)
                return format_json({"deleted": ok, "route_id": route_id})
            except UniFiError as exc:
                logger.exception("delete_route failed", extra={"route_id": route_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_route",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))


__all__ = ["register"]
