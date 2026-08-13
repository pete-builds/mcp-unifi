"""Client tools: list, block, unblock, reconnect.

Quarantine is a composite (block + log) and lives in :mod:`composites`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.clients")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_clients", mutates=False)
    async def list_clients(controller: str = "default") -> str:
        """List currently active wireless and wired clients.

        Side effects: None (read-only).

        Mirrors the controller's Insights → Clients view: MAC, hostname, IP,
        network, signal/satisfaction (wireless only), AP or switch port
        (wired), uptime, and last_seen.

        Example: list_clients(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_clients())
        except UniFiError as exc:
            logger.exception("list_clients failed")
            return err(str(exc))

    @mcp.tool()
    @audited("block_client", mutates=True)
    async def block_client(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Block a client by MAC so it cannot rejoin until unblocked.

        Side effects:
        - Adds the MAC to the controller's user-block list. The client is
          immediately disconnected and prevented from re-associating on any
          SSID until ``unblock_client`` is called.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: block_client(mac="aa:bb:cc:00:00:01")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
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
                    "would_apply": {"action": "block", "mac": mac},
                    "summary": f"Would block client {mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            blocked = await backend.block_client(mac)
            if blocked is None:
                return err(f"client {mac} not found")
            return format_json(blocked)
        except UniFiError as exc:
            logger.exception("block_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("unblock_client", mutates=True)
    async def unblock_client(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Unblock a previously-blocked client by MAC.

        Side effects:
        - Removes the MAC from the controller's user-block list. The client
          can re-associate immediately.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: unblock_client(mac="aa:bb:cc:00:00:01")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
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
                    "would_apply": {"action": "unblock", "mac": mac},
                    "summary": f"Would unblock client {mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            unblocked = await backend.unblock_client(mac)
            if unblocked is None:
                return err(f"client {mac} not found")
            return format_json(unblocked)
        except UniFiError as exc:
            logger.exception("unblock_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    # Classified mutating: nothing is persisted, but it deauths a live client off
    # the network. Transient effects on someone's connectivity are still effects.
    @audited("reconnect_client", mutates=True)
    async def reconnect_client(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Force a client to reconnect (kick-sta).

        Side effects:
        - Issues a deauthentication frame for ``mac`` on its current AP. The
          client immediately disconnects and most clients re-associate
          automatically within seconds.
        - The block-list is not modified; this is a transient nudge.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: reconnect_client(mac="aa:bb:cc:00:00:01")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
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
                    "would_apply": {"action": "reconnect", "mac": mac},
                    "summary": f"Would force reconnect of client {mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            ok = await backend.reconnect_client(mac)
            return format_json({"reconnected": ok, "mac": mac})
        except UniFiError as exc:
            logger.exception("reconnect_client failed", extra={"mac": mac})
            return err(str(exc))
