"""Switch port profile tools: list, create, update, delete."""

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

logger = logging.getLogger("mcp_unifi.network.port_profiles")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_port_profiles")
    async def list_port_profiles(controller: str = "default") -> str:
        """List switch port profiles configured on the controller.

        Side effects: None (read-only).

        Port profiles control PoE, native VLAN, tagged VLANs, and STP per
        switch port. Returns one record per profile with ``_id``, ``name``,
        ``native_networkconf_id``, ``forward``, and ``poe_mode``. Use these
        IDs when assigning ports on a switch.

        Example: list_port_profiles(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
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
        """Create a switch port profile.

        Side effects:
        - Adds a new profile defining native (untagged) VLAN, tagged VLANs,
          PoE behaviour, and forwarding mode. The profile is dormant until
          a switch port is assigned to it (via ``set_port_state``).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_port_profile(name="iot-trunk", native_networkconf_id="65f...", tagged_networkconf_ids=["65a...", "65b..."], poe_mode="auto")

        Args:
            name: Display name for the profile (e.g. ``"iot-trunk"``).
            native_networkconf_id: ``_id`` of the native (untagged) network.
                Empty for trunk-only ports.
            forward: ``"all"`` (default), ``"native"``, ``"customize"``, or
                ``"disabled"``.
            poe_mode: ``"auto"`` (default), ``"passive24v"``,
                ``"passthrough"``, or ``"off"``.
            tagged_networkconf_ids: Optional list of network ``_id`` strings
                carried as tagged VLANs.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
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
            backend = resolve_backend(registry, controller)
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
        """Patch fields on an existing port profile.

        Side effects:
        - Modifies the named profile in place. Every switch port currently
          using the profile picks up the new behaviour on the next
          provision (typically within seconds).
        - Changing ``native_networkconf_id`` may move powered devices to a
          different VLAN.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_port_profile(profile_id="65f...", updates={"poe_mode": "off"})

        Args:
            profile_id: The ``_id`` from ``list_port_profiles``.
            updates: Partial profile record. Common keys: ``name``,
                ``forward``, ``poe_mode``, ``native_networkconf_id``,
                ``tagged_networkconf_ids``.
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
                    "would_update": {"profile_id": profile_id, "patch": updates},
                    "summary": (
                        f"Would update port profile {profile_id} ({len(updates)} field(s))"
                    ),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
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
        """Preview deletion of a switch port profile.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the profile. The controller rejects the
          request if any switch port still references it.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_port_profile(profile_id="65f...")

        Args:
            profile_id: The ``_id`` from ``list_port_profiles``.
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
                    "would_delete": {"profile_id": profile_id},
                    "summary": f"Would delete port profile {profile_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            profiles = await backend.list_port_profiles()
        except UniFiError as exc:
            logger.exception(
                "delete_port_profile preview lookup failed", extra={"profile_id": profile_id}
            )
            return err(str(exc))

        target = next(
            (p for p in profiles if isinstance(p, dict) and p.get("_id") == profile_id), None
        )
        if target is None:
            return err(f"port profile {profile_id} not found")

        resource = {
            "_id": profile_id,
            "name": target.get("name"),
            "native_networkconf_id": target.get("native_networkconf_id"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_port_profile(profile_id)
                return format_json({"deleted": ok, "profile_id": profile_id})
            except UniFiError as exc:
                logger.exception("delete_port_profile failed", extra={"profile_id": profile_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_port_profile",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
