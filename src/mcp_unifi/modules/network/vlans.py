"""Network/VLAN tools: list, create, update, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import (
    format_json,
    make_err,
    normalize_ip_subnet,
    subnet_to_dhcp,
)
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

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
        """List every network/VLAN configured on the controller.

        Side effects: None (read-only).

        Returns one record per network with ``_id``, ``name``, ``purpose``,
        ``vlan``, ``vlan_enabled``, ``ip_subnet``, ``dhcpd_enabled``,
        ``dhcpd_start``, ``dhcpd_stop``, and ``enabled``.

        Example: list_networks(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
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
        """Create a VLAN-tagged network on the controller.

        Side effects:
        - Adds a new network record with the given VLAN ID, IP subnet, and
          DHCP scope. The first usable address (.1) becomes the gateway.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_vlan(name="iot", vlan_id=50, subnet="10.50.0.0/24")

        Args:
            name: Network display name (e.g. ``"iot"``, ``"cameras"``).
            vlan_id: 802.1Q VLAN ID, 2-4094.
            subnet: Subnet in either gateway-IP form (``"10.50.0.1/24"``,
                what the UniFi controller stores) or network form
                (``"10.50.0.0/24"``). Network form is auto-promoted to
                gateway form before the POST so callers don't have to
                remember which one UniFi wants. /24 only.
            dhcp_start: First DHCP lease address. Empty = derived from
                ``IOT_DHCP_START_OFFSET``.
            dhcp_stop: Last DHCP lease address. Empty = derived from
                ``IOT_DHCP_STOP_OFFSET``.
            purpose: ``"corporate"`` for normal LANs, ``"guest"`` for
                hotspot-style isolation.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        normalized_subnet = normalize_ip_subnet(subnet)

        if not dhcp_start or not dhcp_stop:
            _, default_start, default_stop = subnet_to_dhcp(
                normalized_subnet,
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
            "ip_subnet": normalized_subnet,
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
                    "summary": (f"Would create VLAN '{name}' (id={vlan_id}) on {subnet}"),
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
        """Patch fields on an existing VLAN/network record.

        Side effects:
        - Modifies the named network in place. Only fields supplied in
          ``updates`` change; everything else is preserved.
        - Changes to ``vlan`` or ``ip_subnet`` may disconnect clients on the
          affected network.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_vlan(network_id="65f...", updates={"enabled": False})

        Args:
            network_id: The ``_id`` from ``list_networks``.
            updates: Partial network record. Common keys: ``name``, ``vlan``,
                ``ip_subnet``, ``dhcpd_start``, ``dhcpd_stop``, ``enabled``,
                ``mdns_enabled`` (toggle the per-VLAN mDNS reflector
                independently of network creation), ``purpose``.
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
        """Preview deletion of a VLAN/network.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the network record. Any WLANs, firewall rules,
          or DHCP reservations still referencing it must be detached first
          or the controller will reject the request. Clients on this VLAN
          lose connectivity.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_vlan(network_id="65f...")

        Args:
            network_id: The ``_id`` from ``list_networks``.
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
                    "would_delete": {"network_id": network_id},
                    "summary": f"Would delete VLAN {network_id}",
                }
            )
        try:
            backend = registry.get(controller)
            networks = await backend.list_networks()
        except UniFiError as exc:
            logger.exception("delete_vlan preview lookup failed", extra={"network_id": network_id})
            return err(str(exc))

        target = next(
            (n for n in networks if isinstance(n, dict) and n.get("_id") == network_id), None
        )
        if target is None:
            return err(f"network {network_id} not found")

        resource = {
            "_id": network_id,
            "name": target.get("name"),
            "vlan": target.get("vlan"),
            "ip_subnet": target.get("ip_subnet"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_network(network_id)
                return format_json({"deleted": ok, "network_id": network_id})
            except UniFiError as exc:
                logger.exception("delete_vlan failed", extra={"network_id": network_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_vlan",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
