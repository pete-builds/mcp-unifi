"""Network/VLAN tools: list, create, update, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err, subnet_to_dhcp

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.vlans")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_networks")
    async def list_networks(controller: str = "default") -> str:
        """List all configured networks/VLANs on the gateway.

        Returns:
            JSON list of network records: _id, name, purpose, vlan,
            vlan_enabled, ip_subnet, dhcpd_enabled, dhcpd_start, dhcpd_stop,
            enabled.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_networks())
        except UniFiError as exc:
            logger.exception("list_networks failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_vlan")
    async def create_vlan(
        name: str,
        vlan_id: int,
        subnet: str,
        dhcp_start: str = "",
        dhcp_stop: str = "",
        purpose: str = "corporate",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a new VLAN-tagged network.

        Args:
            name: Network display name (e.g. "IoT", "Guest").
            vlan_id: 802.1Q VLAN ID, 2-4094.
            subnet: CIDR for the VLAN gateway IP, e.g. "10.0.20.0/24". The
                first usable address (.1) becomes the router/DHCP server.
            dhcp_start: First DHCP lease address. If empty, defaults to
                ``.<IOT_DHCP_START_OFFSET>`` of the subnet.
            dhcp_stop: Last DHCP lease address. If empty, defaults to
                ``.<IOT_DHCP_STOP_OFFSET>`` of the subnet.
            purpose: UniFi network purpose. "corporate" for normal LANs,
                "guest" for hotspot-style isolation.

        Returns:
            JSON of the created network record (with assigned _id).
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        if not dhcp_start or not dhcp_stop:
            _, default_start, default_stop = subnet_to_dhcp(
                subnet,
                settings.iot_dhcp_start_offset,
                settings.iot_dhcp_stop_offset,
            )
            dhcp_start = dhcp_start or default_start
            dhcp_stop = dhcp_stop or default_stop

        payload: dict[str, Any] = {
            "name": name,
            "purpose": purpose,
            "vlan_enabled": True,
            "vlan": vlan_id,
            "ip_subnet": subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": dhcp_start,
            "dhcpd_stop": dhcp_stop,
            "enabled": True,
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"network": payload},
                    "summary": (
                        f"Would create VLAN '{name}' (id={vlan_id}) on {subnet}"
                    ),
                }
            )
        try:
            backend = registry.get(controller)
            return format_json(await backend.create_network(payload))
        except UniFiError as exc:
            logger.exception("create_vlan failed", extra={"vlan_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_vlan")
    async def update_vlan(
        network_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Update fields on an existing VLAN/network.

        Only the fields you supply are changed; everything else is preserved.

        Args:
            network_id: The ``_id`` from list_networks.
            updates: Partial network record. Common keys: name, vlan,
                ip_subnet, dhcpd_start, dhcpd_stop, enabled.

        Returns:
            JSON of the updated network record, or error if not found.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"network_id": network_id, "patch": updates},
                    "summary": f"Would update VLAN {network_id} ({len(updates)} field(s))",
                }
            )
        try:
            backend = registry.get(controller)
            updated = await backend.update_network(network_id, updates)
            if updated is None:
                return err(f"network {network_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_vlan failed", extra={"network_id": network_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_vlan")
    async def delete_vlan(
        network_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Delete a VLAN/network.

        Args:
            network_id: The ``_id`` from list_networks. Be sure no SSIDs or
                firewall rules still reference it; the controller will reject
                otherwise.

        Returns:
            JSON ``{"deleted": true}`` on success.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"network_id": network_id},
                    "summary": f"Would delete VLAN {network_id}",
                }
            )
        try:
            backend = registry.get(controller)
            ok = await backend.delete_network(network_id)
            return format_json({"deleted": ok, "network_id": network_id})
        except UniFiError as exc:
            logger.exception("delete_vlan failed", extra={"network_id": network_id})
            return err(str(exc))
