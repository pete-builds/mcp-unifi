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
        """List static DHCP reservations on the gateway.

        UniFi stores fixed leases on the user object with ``use_fixedip=true``.
        This returns just those entries.

        Returns:
            JSON list of lease records: ``_id``, ``mac``, ``name``,
            ``hostname``, ``fixed_ip``, ``network_id``.
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
        """Reserve a fixed IP for a client.

        Args:
            mac: Client MAC address.
            ip: IPv4 address to reserve. Must fall inside the network's subnet.
            network_id: ``_id`` of the network/VLAN this client lives on.
            name: Friendly display name (optional).
            hostname: DHCP hostname (optional).

        Returns:
            JSON of the created reservation.
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

        Args:
            lease_id: The ``_id`` from ``list_dhcp_leases``.

        Returns:
            JSON ``{"deleted": true, "lease_id": "..."}``.
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
