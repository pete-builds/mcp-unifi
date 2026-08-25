"""Teleport VPN tools.

Teleport is UniFi's wireguard-based remote-user VPN. On UCG-Fiber fw
5.1.12.33296 the controller exposes the master on/off toggle as a
per-key setting record (``teleport``), but the client roster and
invitation lifecycle live behind the Ubiquiti mobile app / cloud
pairing flow — they are **not** exposed via the local Network API.

Endpoints used (legacy controller API):

* ``GET /rest/setting/teleport`` — returns ``{enabled: bool, _id, key,
  site_id}``. That is the entire record; no per-client roster.
* ``POST /set/setting/teleport`` — partial-update; flip ``enabled`` to
  turn the VPN listener on or off.

Tool surface deliberately stops at the two operations the local API
supports:

* ``get_teleport_config`` — current state plus a stable
  ``clients_via_local_api=False`` indicator so callers know not to ask
  for a client list here.
* ``set_teleport_enabled`` — toggle the listener.

The brief asked for ``create_teleport_invitation``, ``list_teleport_clients``,
and ``revoke_teleport_client``. After exhausting the controller's REST
surface (``/api/s/.../rest/teleport*``, ``/api/s/.../list/teleport*``,
``/api/s/.../stat/teleport*``, ``/api/s/.../cmd/teleport``, the v2 and
integration APIs), none of those collections exist on this firmware.
Apoc should document those operations as UI-only until Ubiquiti publishes
a local API surface for them.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import READ_ONLY, WRITE_IDEMPOTENT
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.teleport")


def _wireguard_vpn_networks(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return wireguard-server network records (Teleport is built on these)."""
    out: list[dict[str, Any]] = []
    for n in networks:
        vpn_type = str(n.get("vpn_type", ""))
        purpose = str(n.get("purpose", ""))
        if "wireguard" in vpn_type or purpose == "remote-user-vpn":
            out.append(
                {
                    "_id": n.get("_id"),
                    "name": n.get("name"),
                    "vpn_type": vpn_type,
                    "ip_subnet": n.get("ip_subnet"),
                    "local_port": n.get("local_port"),
                    "external_id": n.get("external_id"),
                    "enabled": n.get("enabled"),
                }
            )
    return out


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_teleport_config", mutates=False)
    async def get_teleport_config(controller: str = "default") -> str:
        """Return Teleport VPN state and any wireguard-server networks.

        Side effects: None (read-only).

        Returns ``{"enabled": bool, "vpn_networks": [...],
        "clients_via_local_api": false, "notes": [...]}``. The ``enabled``
        flag is the global Teleport listener toggle; ``vpn_networks``
        lists the underlying wireguard-server network records (Teleport
        rides on these for tunnel termination); ``clients_via_local_api``
        is a hard ``false`` on UniFi Network 9.x — the client roster and
        invitation lifecycle are only reachable via the Ubiquiti mobile
        app pairing flow, not the local API.

        Example: get_teleport_config(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            record = await backend.get_setting("teleport")
            networks_raw = await backend.list_networks()
        except UniFiError as exc:
            logger.exception("get_teleport_config failed")
            return err(str(exc))

        vpn_networks = _wireguard_vpn_networks(list(networks_raw))
        # ``_wireguard_vpn_networks`` projects a fixed key list today, which is
        # what keeps ``x_private_key`` off this response. That is one edit away
        # from being false — redact enforces it regardless of the projection.
        return format_json(
            redact(
                {
                    "enabled": bool(record.get("enabled", False)),
                    "vpn_networks": vpn_networks,
                    "clients_via_local_api": False,
                    "notes": [
                        "Teleport client roster and invitation links are not exposed via "
                        "the local UniFi Network API on fw 5.1.12.33296. Use the UniFi "
                        "mobile app on the gateway owner's device to invite or revoke a "
                        "client; the toggle here only controls the listener."
                    ],
                }
            )
        )

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("set_teleport_enabled", mutates=True)
    async def set_teleport_enabled(
        enabled: bool,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Toggle the Teleport VPN listener.

        Side effects:
        - Patches the ``teleport`` setting record's ``enabled`` field.
          When ``False``, the controller tears down the listener and
          disconnects any active sessions. Registered clients (via the
          mobile app) remain registered and reconnect once the listener
          is re-enabled.
        - Mutates controller state. Use dry_run=True to preview.

        Example: set_teleport_enabled(enabled=True)

        Args:
            enabled: ``True`` activates the listener; ``False`` disables it.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it.
        """
        patch: dict[str, Any] = {"enabled": bool(enabled)}

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_patch": {"setting_key": "teleport", "patch": patch},
                    "summary": f"Would set Teleport enabled={bool(enabled)}",
                }
            )

        try:
            backend = resolve_backend(registry, controller)
            record = await backend.set_setting("teleport", patch)
        except UniFiError as exc:
            logger.exception("set_teleport_enabled failed")
            return err(str(exc))
        return format_json({"enabled": bool(record.get("enabled", False))})


__all__ = ["register"]
