"""Switch port profile tools: list, create, update, delete."""

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

logger = logging.getLogger("mcp_unifi.network.port_profiles")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_port_profiles")
    async def list_port_profiles(controller: str = "default") -> str:
        """List switch port profiles configured on the gateway.

        Port profiles control PoE, native VLAN, tagged VLANs, and STP per
        switch port. Use these IDs when assigning ports on a switch.

        Returns:
            JSON list of profiles: _id, name, native_networkconf_id, forward,
            poe_mode.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_port_profiles())
        except UniFiError as exc:
            logger.exception("list_port_profiles failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_port_profile")
    async def create_port_profile(
        name: str,
        native_networkconf_id: str = "",
        forward: str = "all",
        poe_mode: str = "auto",
        tagged_networkconf_ids: list[str] | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a new switch port profile.

        Port profiles define how a switch port behaves: which VLAN is native,
        which are tagged, whether PoE is on, and how traffic is forwarded.

        Args:
            name: Display name for the profile.
            native_networkconf_id: ``_id`` of the native (untagged) network.
                Empty for trunk ports.
            forward: ``"all"`` (default), ``"native"``, ``"customize"``, or
                ``"disabled"``.
            poe_mode: ``"auto"`` (default), ``"passive24v"``, ``"passthrough"``,
                or ``"off"``.
            tagged_networkconf_ids: Optional list of network ``_id``s carried as
                tagged VLANs.

        Returns:
            JSON of the created profile (with assigned ``_id``).
        """
        payload: dict[str, Any] = {
            "name": name,
            "forward": forward,
            "poe_mode": poe_mode,
        }
        if native_networkconf_id:
            payload["native_networkconf_id"] = native_networkconf_id
        if tagged_networkconf_ids:
            payload["tagged_networkconf_ids"] = tagged_networkconf_ids
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"port_profile": payload},
                    "summary": f"Would create port profile '{name}'",
                }
            )
        try:
            backend = registry.get(controller)
            return format_json(await backend.create_port_profile(payload))
        except UniFiError as exc:
            logger.exception("create_port_profile failed", extra={"profile_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_port_profile")
    async def update_port_profile(
        profile_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Update fields on an existing port profile.

        Args:
            profile_id: The ``_id`` from ``list_port_profiles``.
            updates: Partial profile record. Common keys: ``name``, ``forward``,
                ``poe_mode``, ``native_networkconf_id``, ``tagged_networkconf_ids``.

        Returns:
            JSON of the updated profile, or an error if not found.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"profile_id": profile_id, "patch": updates},
                    "summary": (
                        f"Would update port profile {profile_id} ({len(updates)} field(s))"
                    ),
                }
            )
        try:
            backend = registry.get(controller)
            updated = await backend.update_port_profile(profile_id, updates)
            if updated is None:
                return err(f"port profile {profile_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_port_profile failed", extra={"profile_id": profile_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_port_profile")
    async def delete_port_profile(
        profile_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Delete a switch port profile.

        Args:
            profile_id: The ``_id`` from ``list_port_profiles``. The controller
                will reject the delete if any switch port still references the
                profile.

        Returns:
            JSON ``{"deleted": true, "profile_id": "..."}`` on success.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"profile_id": profile_id},
                    "summary": f"Would delete port profile {profile_id}",
                }
            )
        try:
            backend = registry.get(controller)
            ok = await backend.delete_port_profile(profile_id)
            return format_json({"deleted": ok, "profile_id": profile_id})
        except UniFiError as exc:
            logger.exception("delete_port_profile failed", extra={"profile_id": profile_id})
            return err(str(exc))
