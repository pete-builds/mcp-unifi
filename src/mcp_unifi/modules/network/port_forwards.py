"""Port forward (DNAT) tools: list, create, update, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedName,
)
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions
from mcp_unifi.modules.network._verify import verified_update

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.port_forwards")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_port_forwards", mutates=False)
    async def list_port_forwards(controller: str = "default") -> str:
        """List every port-forward (DNAT) rule on the controller.

        Side effects: None (read-only).

        Returns one record per forward with ``_id``, ``name``, ``enabled``,
        ``proto``, ``src``, ``fwd``, ``fwd_port``, and ``dst_port``.

        Example: list_port_forwards(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_port_forwards())
        except UniFiError as exc:
            logger.exception("list_port_forwards failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_port_forward", mutates=True)
    async def create_port_forward(
        name: BoundedName,
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
        """Create a port-forward (DNAT) rule on the WAN.

        Side effects:
        - Adds a NAT rule that exposes the internal host ``fwd:fwd_port`` to
          the WAN on ``dst_port``. The service is reachable from the public
          internet (subject to ``src`` restriction).
        - Takes effect immediately on the next inbound packet.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_port_forward(name="plex", fwd="10.50.0.10", fwd_port="32400", dst_port="32400", proto="tcp")

        Args:
            name: Display name for the rule.
            fwd: Internal IP to forward to (e.g. ``"10.50.0.10"``).
            fwd_port: Internal port (string; UniFi accepts ranges like
                ``"8000-8010"``).
            dst_port: External / WAN port to listen on.
            proto: ``"tcp"``, ``"udp"``, or ``"tcp_udp"``.
            src: Source restriction. ``"any"`` (default) or a CIDR.
            enabled: ``True`` enables the rule immediately.
            log: ``True`` logs forwarded packets.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
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
                    "summary": (f"Would forward WAN:{dst_port} -> {fwd}:{fwd_port} ({proto})"),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_port_forward(payload))
        except UniFiError as exc:
            logger.exception("create_port_forward failed", extra={"forward_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_port_forward", mutates=True)
    async def update_port_forward(
        forward_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing port-forward rule.

        Side effects:
        - Modifies the named forward in place. Only fields supplied in
          ``updates`` change.
        - Takes effect immediately on the next inbound packet.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Verified write: after applying, the rule is re-read from the
        controller and the response carries a ``verification`` block listing
        ``persisted_fields``, ``unchanged_fields`` (already correct before
        the write), ``dropped_fields`` (silently discarded by the
        controller), ``coerced_fields`` (stored with a different value or
        type), and ``unverifiable_fields``. ``fwd_ip`` is a known drop site
        on some firmware. A response with ``verified: false`` and
        ``mutation_applied: true`` means the controller accepted the write
        but did not store it exactly — that is **not a rollback**, and the
        rule may be in a mixed state. Re-check before assuming a port is
        closed.

        Example: update_port_forward(forward_id="65f...", updates={"enabled": False})

        Args:
            forward_id: The ``_id`` from ``list_port_forwards``.
            updates: Partial record. Common keys: ``enabled``, ``fwd_port``,
                ``dst_port``, ``proto``, ``src``, ``fwd``, ``name``.
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
                    "would_update": {"forward_id": forward_id, "patch": updates},
                    "summary": (
                        f"Would update port forward {forward_id} ({len(updates)} field(s))"
                    ),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            outcome = await verified_update(
                lister=backend.list_port_forwards,
                updater=lambda: backend.update_port_forward(forward_id, updates),
                record_id=forward_id,
                updates=updates,
            )
            if outcome is None:
                return err(f"port forward {forward_id} not found")
            record, verification = outcome
            return format_json(
                {
                    "forward_id": forward_id,
                    "verification": verification,
                    "port_forward": record,
                }
            )
        except UniFiError as exc:
            logger.exception("update_port_forward failed", extra={"forward_id": forward_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_port_forward", mutates=True)
    async def delete_port_forward(
        forward_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a port-forward (DNAT) rule.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the NAT rule. The internal service stops
          being reachable from the WAN immediately.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_port_forward(forward_id="65f...")

        Args:
            forward_id: The ``_id`` from ``list_port_forwards``.
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
                    "would_delete": {"forward_id": forward_id},
                    "summary": f"Would delete port forward {forward_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            forwards = await backend.list_port_forwards()
        except UniFiError as exc:
            logger.exception(
                "delete_port_forward preview lookup failed", extra={"forward_id": forward_id}
            )
            return err(str(exc))

        target = next(
            (f for f in forwards if isinstance(f, dict) and f.get("_id") == forward_id), None
        )
        if target is None:
            return err(f"port forward {forward_id} not found")

        resource = {
            "_id": forward_id,
            "name": target.get("name"),
            "fwd": target.get("fwd"),
            "fwd_port": target.get("fwd_port"),
            "dst_port": target.get("dst_port"),
            "proto": target.get("proto"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_port_forward(forward_id)
                return format_json({"deleted": ok, "forward_id": forward_id})
            except UniFiError as exc:
                logger.exception("delete_port_forward failed", extra={"forward_id": forward_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_port_forward",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
