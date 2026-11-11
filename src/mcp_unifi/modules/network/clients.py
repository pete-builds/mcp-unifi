"""Client tools: list, block, unblock, reconnect.

Quarantine is a composite (block + log) and lives in :mod:`composites`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import DESTRUCTIVE, READ_ONLY, WRITE_IDEMPOTENT
from mcp_unifi.clients.mac import same_mac
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.clients")


async def _dry_run_lookup(backend: Backend, mac: str, connected_only: bool) -> dict[str, Any]:
    """What a dry run can honestly say about whether ``mac`` is known.

    The controller's stamgr commands take any MAC, and a real console may
    accept a block for a client it has never seen (that is how a device is
    banned before it first joins). So a dry run must not claim the call
    will fail for an unknown MAC, and must not claim it will succeed either.
    It reports what the controller knows and says when it cannot tell.
    """
    if connected_only:
        clients = await backend.list_clients()
        known = any(isinstance(c, dict) and same_mac(c.get("mac"), mac) for c in clients)
        if known:
            return {"client_known": True}
        return {
            "client_known": False,
            "note": (
                f"{mac} is not currently connected. The real call may report it not found, "
                "or the controller may accept a kick that reaches nobody; a dry run cannot "
                "tell which."
            ),
        }
    known = await backend.find_user_by_mac(mac) is not None
    if known:
        return {"client_known": True}
    return {
        "client_known": False,
        "note": (
            f"The controller has no record of {mac}. Whether the real call accepts a MAC it "
            "has never seen depends on the controller; a dry run cannot tell."
        ),
    }


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
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

    @mcp.tool(annotations=DESTRUCTIVE)
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
                predicted change set plus ``client_known``, and a ``note``
                when the controller does not know the MAC.
        """
        try:
            backend = resolve_backend(registry, controller)
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_apply": {"action": "block", "mac": mac},
                        **await _dry_run_lookup(backend, mac, connected_only=False),
                        "summary": f"Would block client {mac}",
                    }
                )
            blocked = await backend.block_client(mac)
            if blocked is None:
                return err(f"client {mac} not found")
            return format_json(blocked)
        except UniFiError as exc:
            logger.exception("block_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
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
                predicted change set plus ``client_known``, and a ``note``
                when the controller does not know the MAC.
        """
        try:
            backend = resolve_backend(registry, controller)
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_apply": {"action": "unblock", "mac": mac},
                        **await _dry_run_lookup(backend, mac, connected_only=False),
                        "summary": f"Would unblock client {mac}",
                    }
                )
            unblocked = await backend.unblock_client(mac)
            if unblocked is None:
                return err(f"client {mac} not found")
            return format_json(unblocked)
        except UniFiError as exc:
            logger.exception("unblock_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool(annotations=DESTRUCTIVE)
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
                predicted change set plus ``client_known``, and a ``note``
                when the controller does not know the MAC.
        """
        try:
            backend = resolve_backend(registry, controller)
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_apply": {"action": "reconnect", "mac": mac},
                        **await _dry_run_lookup(backend, mac, connected_only=True),
                        "summary": f"Would force reconnect of client {mac}",
                    }
                )
            ok = await backend.reconnect_client(mac)
            if not ok:
                return err(f"client {mac} not found")
            return format_json({"reconnected": True, "mac": mac})
        except UniFiError as exc:
            logger.exception("reconnect_client failed", extra={"mac": mac})
            return err(str(exc))
