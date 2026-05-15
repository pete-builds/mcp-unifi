"""Port forward (DNAT) tools: list, create, update, delete."""

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

logger = logging.getLogger("mcp_unifi.network.port_forwards")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_port_forwards")
    async def list_port_forwards(controller: str = "default") -> str:
        """List all port-forward (DNAT) rules.

        Returns:
            JSON list of records: ``_id``, ``name``, ``enabled``, ``proto``,
            ``src``, ``fwd``, ``fwd_port``, ``dst_port``.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_port_forwards())
        except UniFiError as exc:
            logger.exception("list_port_forwards failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_port_forward")
    async def create_port_forward(
        name: str,
        fwd: str,
        fwd_port: str,
        dst_port: str,
        proto: str = "tcp",
        src: str = "any",
        enabled: bool = True,
        log: bool = False,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a port-forward (DNAT) rule.

        Args:
            name: Display name.
            fwd: Internal IP to forward to.
            fwd_port: Internal port (string; UniFi accepts ranges like
                ``"8000-8010"``).
            dst_port: External / WAN port to listen on.
            proto: ``"tcp"``, ``"udp"``, or ``"tcp_udp"``.
            src: Source restriction. ``"any"`` (default) or a CIDR.
            enabled: ``True`` to enable immediately.
            log: ``True`` to log forwarded packets.

        Returns:
            JSON of the created rule.
        """
        payload: dict[str, Any] = {
            "name": name,
            "fwd": fwd,
            "fwd_port": fwd_port,
            "dst_port": dst_port,
            "proto": proto,
            "src": src,
            "enabled": enabled,
            "log": log,
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"port_forward": payload},
                    "summary": (
                        f"Would forward WAN:{dst_port} -> {fwd}:{fwd_port} ({proto})"
                    ),
                }
            )
        try:
            backend = registry.get(controller)
            return format_json(await backend.create_port_forward(payload))
        except UniFiError as exc:
            logger.exception("create_port_forward failed", extra={"forward_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_port_forward")
    async def update_port_forward(
        forward_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Update a port-forward rule.

        Args:
            forward_id: The ``_id`` from ``list_port_forwards``.
            updates: Partial record. Common keys: ``enabled``, ``fwd_port``,
                ``dst_port``, ``proto``, ``src``, ``fwd``, ``name``.

        Returns:
            JSON of the updated rule, or an error if not found.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"forward_id": forward_id, "patch": updates},
                    "summary": (
                        f"Would update port forward {forward_id} ({len(updates)} field(s))"
                    ),
                }
            )
        try:
            backend = registry.get(controller)
            updated = await backend.update_port_forward(forward_id, updates)
            if updated is None:
                return err(f"port forward {forward_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_port_forward failed", extra={"forward_id": forward_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_port_forward")
    async def delete_port_forward(
        forward_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Delete a port-forward rule.

        Args:
            forward_id: The ``_id`` from ``list_port_forwards``.

        Returns:
            JSON ``{"deleted": true, "forward_id": "..."}``.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"forward_id": forward_id},
                    "summary": f"Would delete port forward {forward_id}",
                }
            )
        try:
            backend = registry.get(controller)
            ok = await backend.delete_port_forward(forward_id)
            return format_json({"deleted": ok, "forward_id": forward_id})
        except UniFiError as exc:
            logger.exception("delete_port_forward failed", extra={"forward_id": forward_id})
            return err(str(exc))
