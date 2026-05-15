"""Static DHCP lease tools: list, create, delete."""

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

logger = logging.getLogger("mcp_unifi.network.dhcp")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_dhcp_leases")
    async def list_dhcp_leases(controller: str = "default") -> str:
        """List static DHCP reservations on the controller.

        Side effects: None (read-only).

        UniFi stores fixed leases on the user object with
        ``use_fixedip=true``. This returns just those entries with ``_id``,
        ``mac``, ``name``, ``hostname``, ``fixed_ip``, and ``network_id``.

        Example: list_dhcp_leases(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_dhcp_leases())
        except UniFiError as exc:
            logger.exception("list_dhcp_leases failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_static_dhcp_lease")
    async def create_static_dhcp_lease(
        mac: str,
        ip: str,
        network_id: str,
        name: str = "",
        hostname: str = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Reserve a fixed IP for a client by MAC.

        Side effects:
        - Adds a fixed-IP entry on the user object so ``mac`` always receives
          ``ip`` from the controller's DHCP server. The next DHCP renewal
          for that client picks up the reservation.
        - The IP must fall inside the network's subnet or the controller
          will reject the request.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_static_dhcp_lease(mac="aa:bb:cc:00:00:01", ip="10.50.0.10", network_id="65f...", name="cameras-nvr")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
            ip: IPv4 address to reserve.
            network_id: ``_id`` of the network/VLAN this client lives on.
            name: Friendly display name (optional).
            hostname: DHCP hostname (optional).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        payload: dict[str, Any] = {
            "mac": mac,
            "use_fixedip": True,
            "fixed_ip": ip,
            "network_id": network_id,
        }
        if name:
            payload["name"] = name
        if hostname:
            payload["hostname"] = hostname
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"dhcp_lease": payload},
                    "summary": f"Would reserve {ip} for {mac}",
                }
            )
        try:
            backend = registry.get(controller)
            return format_json(await backend.create_dhcp_lease(payload))
        except UniFiError as exc:
            logger.exception("create_static_dhcp_lease failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_static_dhcp_lease")
    async def delete_static_dhcp_lease(
        lease_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Delete a static DHCP reservation.

        Side effects:
        - Removes the fixed-IP entry. The client returns to dynamic DHCP on
          its next renewal and may receive a different address.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: delete_static_dhcp_lease(lease_id="65f...")

        Args:
            lease_id: The ``_id`` from ``list_dhcp_leases``.
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
                    "would_delete": {"lease_id": lease_id},
                    "summary": f"Would delete DHCP lease {lease_id}",
                }
            )
        try:
            backend = registry.get(controller)
            ok = await backend.delete_dhcp_lease(lease_id)
            return format_json({"deleted": ok, "lease_id": lease_id})
        except UniFiError as exc:
            logger.exception("delete_static_dhcp_lease failed", extra={"lease_id": lease_id})
            return err(str(exc))
