"""WLAN tools: list, create, update, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import (
    format_json,
    make_err,
    resolve_default_ap_group,
)
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

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
        """List every WiFi SSID configured on the controller.

        Side effects: None (read-only).

        Returns one record per WLAN with ``_id``, ``name``, ``enabled``,
        ``security``, ``wpa_mode``, ``networkconf_id``, ``is_guest``,
        ``hide_ssid``, and ``wlan_band``.

        Example: list_wlans(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_wlans())
        except UniFiError as exc:
            logger.exception("list_wlans failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_ap_groups")
    async def list_ap_groups(controller: str = "default") -> str:
        """List access-point groups configured on the controller.

        Side effects: None (read-only).

        Returns one record per AP group with ``_id``, ``name``,
        ``attr_hidden_id`` (the built-in "default" group carries
        ``"default"`` here), ``device_macs``, and ``site_id``.

        Used by ``create_wlan`` to auto-resolve the default AP group when no
        explicit ``ap_group_ids`` is supplied. Call this directly to inspect
        which groups exist before creating per-AP-group WLANs.

        Example: list_ap_groups(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_ap_groups())
        except UniFiError as exc:
            logger.exception("list_ap_groups failed")
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
        ap_group_ids: list[str] | None = None,
        ap_group_mode: str = "all",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a WiFi SSID bound to an existing network/VLAN.

        Side effects:
        - Adds a new WLAN record. Access points start broadcasting the SSID
          within seconds of the apply.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        AP-group binding:
        - UniFi controllers reject ``POST /rest/wlanconf`` with
          ``api.err.ApGroupMissing`` when ``ap_group_ids`` is absent. When
          ``ap_group_ids`` is unset, this tool calls ``list_ap_groups`` and
          uses the controller's "default" group automatically. Pass an
          explicit list to broadcast only on specific groups.

        Example: create_wlan(name="iot", passphrase="hunter2hunter2", network_id="65f...")

        Args:
            name: SSID broadcast name (e.g. ``"iot"``).
            passphrase: WPA pre-shared key (8-63 chars). Required unless
                ``security="open"``.
            network_id: ``_id`` of the network/VLAN this SSID lives on. Get
                it from ``list_networks``.
            security: ``"wpapsk"`` (default), ``"wpaeap"``, or ``"open"``.
            wpa_mode: ``"wpa2"`` (default) or ``"wpa3"`` if all clients
                support it.
            is_guest: ``True`` isolates clients from each other and the rest
                of the LAN.
            hide_ssid: ``True`` suppresses SSID broadcast.
            wlan_band: ``"2g"``, ``"5g"``, ``"6g"``, or ``"both"`` (default).
            ap_group_ids: List of AP group ``_id`` strings to broadcast on.
                Empty/None auto-resolves to the controller's "default"
                group via ``list_ap_groups``.
            ap_group_mode: ``"all"`` (default) broadcasts on every AP in the
                listed groups. Matches the controller UI default.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        try:
            backend = resolve_backend(registry, controller)
        except UniFiError as exc:
            logger.exception("create_wlan failed", extra={"wlan_name": name})
            return err(str(exc))

        resolved_groups: list[str] = list(ap_group_ids) if ap_group_ids else []
        if not resolved_groups:
            try:
                resolved_groups = await resolve_default_ap_group(backend)
            except UniFiError as exc:
                logger.exception("create_wlan failed", extra={"wlan_name": name})
                return err(f"failed to resolve default AP group: {exc}")
            if not resolved_groups:
                return err("no AP groups found on controller; pass ap_group_ids explicitly")

        payload: dict[str, Any] = {
            "name": name,
            "enabled": True,
            "security": security,
            "wpa_mode": wpa_mode,
            "networkconf_id": network_id,
            "is_guest": is_guest,
            "hide_ssid": hide_ssid,
            "wlan_band": wlan_band,
            "ap_group_ids": resolved_groups,
            "ap_group_mode": ap_group_mode,
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
        """Patch fields on an existing WiFi SSID.

        Side effects:
        - Modifies the named WLAN in place. Only fields supplied in
          ``updates`` change; everything else is preserved.
        - Changes to ``security``, ``wpa_mode``, or ``x_passphrase`` may
          disconnect connected clients until they re-authenticate.
        - Passphrases passed via ``x_passphrase`` are redacted in the
          response.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_wlan(wlan_id="65f...", updates={"enabled": False})

        Args:
            wlan_id: The ``_id`` from ``list_wlans``.
            updates: Partial WLAN record. Common keys: ``name``, ``enabled``,
                ``x_passphrase``, ``wpa_mode``, ``hide_ssid``, ``wlan_band``,
                ``is_guest``.
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
                    "would_update": {"wlan_id": wlan_id, "patch": updates},
                    "summary": f"Would update WLAN {wlan_id} ({len(updates)} field(s))",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
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
        """Preview deletion of a WiFi SSID.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the WLAN record. APs stop broadcasting the
          SSID within seconds. Connected wireless clients on this SSID are
          immediately disconnected.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_wlan(wlan_id="65f...")

        Args:
            wlan_id: The ``_id`` from ``list_wlans``.
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
                    "would_delete": {"wlan_id": wlan_id},
                    "summary": f"Would delete WLAN {wlan_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            wlans = await backend.list_wlans()
        except UniFiError as exc:
            logger.exception("delete_wlan preview lookup failed", extra={"wlan_id": wlan_id})
            return err(str(exc))

        target = next((w for w in wlans if isinstance(w, dict) and w.get("_id") == wlan_id), None)
        if target is None:
            return err(f"wlan {wlan_id} not found")

        resource = {
            "_id": wlan_id,
            "name": target.get("name"),
            "ssid": target.get("ssid") or target.get("name"),
            "enabled": target.get("enabled"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_wlan(wlan_id)
                return format_json({"deleted": ok, "wlan_id": wlan_id})
            except UniFiError as exc:
                logger.exception("delete_wlan failed", extra={"wlan_id": wlan_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_wlan",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
