"""Client tools: list, block, unblock, reconnect.

Quarantine is a composite (block + log) and lives in :mod:`composites`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.clients.unifi import UniFiError
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
    @audited("list_clients")
    async def list_clients(controller: str = "default") -> str:
        """List currently active wireless and wired clients on the gateway.

        Returns the same data the controller's Insights → Clients view shows:
        MAC, hostname, IP, network, signal/satisfaction (wireless only), AP
        or switch port (when wired), and uptime/last_seen timestamps.

        Returns:
            JSON list of client records. Empty list if no clients are
            connected.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_clients())
        except UniFiError as exc:
            logger.exception("list_clients failed")
            return err(str(exc))

    @mcp.tool()
    @audited("block_client")
    async def block_client(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Block a client by MAC. The client cannot rejoin until unblocked.

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).

        Returns:
            JSON of the blocked client record, or an error if not found.
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
            backend = registry.get(controller)
            blocked = await backend.block_client(mac)
            if blocked is None:
                return err(f"client {mac} not found")
            return format_json(blocked)
        except UniFiError as exc:
            logger.exception("block_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("unblock_client")
    async def unblock_client(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Unblock a previously-blocked client by MAC.

        Args:
            mac: Client MAC address.

        Returns:
            JSON of the unblocked client record, or an error if not found.
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
            backend = registry.get(controller)
            unblocked = await backend.unblock_client(mac)
            if unblocked is None:
                return err(f"client {mac} not found")
            return format_json(unblocked)
        except UniFiError as exc:
            logger.exception("unblock_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("reconnect_client")
    async def reconnect_client(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Force a client to reconnect (kick-sta).

        Useful for fixing a stuck client without having to power-cycle it.

        Args:
            mac: Client MAC address.

        Returns:
            JSON ``{"reconnected": true, "mac": "..."}`` on success.
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
            backend = registry.get(controller)
            ok = await backend.reconnect_client(mac)
            return format_json({"reconnected": ok, "mac": mac})
        except UniFiError as exc:
            logger.exception("reconnect_client failed", extra={"mac": mac})
            return err(str(exc))
