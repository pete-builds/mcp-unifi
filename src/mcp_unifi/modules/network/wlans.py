"""WLAN tools: list, create, update, delete."""

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

logger = logging.getLogger("mcp_unifi.network.wlans")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_wlans")
    async def list_wlans(controller: str = "default") -> str:
        """List all WiFi SSIDs configured on the gateway.

        Returns:
            JSON list of WLAN records: _id, name, enabled, security, wpa_mode,
            networkconf_id, is_guest, hide_ssid, wlan_band.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_wlans())
        except UniFiError as exc:
            logger.exception("list_wlans failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_wlan")
    async def create_wlan(
        name: str,
        passphrase: str,
        network_id: str,
        security: str = "wpapsk",
        wpa_mode: str = "wpa2",
        is_guest: bool = False,
        hide_ssid: bool = False,
        wlan_band: str = "both",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a new WiFi SSID bound to a specific network/VLAN.

        Args:
            name: SSID broadcast name.
            passphrase: WPA pre-shared key (8-63 chars). Required unless
                ``security="open"``.
            network_id: The ``_id`` of the network/VLAN this SSID lives on.
                Get it from list_networks.
            security: ``"wpapsk"`` (default), ``"wpaeap"``, or ``"open"``.
            wpa_mode: ``"wpa2"`` (default) or ``"wpa3"`` if all clients
                support it.
            is_guest: True isolates clients from each other and the rest of
                the LAN.
            hide_ssid: True suppresses the SSID broadcast.
            wlan_band: ``"2g"``, ``"5g"``, ``"6g"``, or ``"both"`` (default).

        Returns:
            JSON of the created WLAN record.
        """
        payload: dict[str, Any] = {
            "name": name,
            "enabled": True,
            "security": security,
            "wpa_mode": wpa_mode,
            "networkconf_id": network_id,
            "is_guest": is_guest,
            "hide_ssid": hide_ssid,
            "wlan_band": wlan_band,
        }
        if security != "open":
            payload["x_passphrase"] = passphrase
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"wlan": payload},
                    "summary": f"Would create WLAN '{name}' on network {network_id}",
                }
            )
        try:
            backend = registry.get(controller)
            return format_json(await backend.create_wlan(payload))
        except UniFiError as exc:
            logger.exception("create_wlan failed", extra={"wlan_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_wlan")
    async def update_wlan(
        wlan_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Update fields on an existing WiFi SSID.

        Only the fields you supply are changed; everything else is preserved.
        Passphrases are accepted via the ``x_passphrase`` key in ``updates``
        and are redacted in the response.

        Args:
            wlan_id: The ``_id`` from list_wlans.
            updates: Partial WLAN record. Common keys: name, enabled,
                x_passphrase, wpa_mode, hide_ssid, wlan_band, is_guest.

        Returns:
            JSON of the updated WLAN record, or error if not found.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"wlan_id": wlan_id, "patch": updates},
                    "summary": f"Would update WLAN {wlan_id} ({len(updates)} field(s))",
                }
            )
        try:
            backend = registry.get(controller)
            updated = await backend.update_wlan(wlan_id, updates)
            if updated is None:
                return err(f"wlan {wlan_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_wlan failed", extra={"wlan_id": wlan_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_wlan")
    async def delete_wlan(
        wlan_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Delete a WiFi SSID.

        Args:
            wlan_id: The ``_id`` from list_wlans.

        Returns:
            JSON ``{"deleted": true, "wlan_id": "..."}`` on success, or an
            error object if the gateway rejects the request.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"wlan_id": wlan_id},
                    "summary": f"Would delete WLAN {wlan_id}",
                }
            )
        try:
            backend = registry.get(controller)
            ok = await backend.delete_wlan(wlan_id)
            return format_json({"deleted": ok, "wlan_id": wlan_id})
        except UniFiError as exc:
            logger.exception("delete_wlan failed", extra={"wlan_id": wlan_id})
            return err(str(exc))
