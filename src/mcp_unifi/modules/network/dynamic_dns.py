"""Dynamic DNS tools: list, get, create, update, delete.

Dynamic DNS keeps an external DNS hostname pointed at the gateway's current
WAN IP by pushing updates to a DDNS provider. These configs live in the legacy
``/rest/dynamicdns`` collection. Probed live read-only against a UCG-Fiber on
UniFi Network 10.4.57 (2026-06-12): ``GET /rest/dynamicdns`` returns the
standard ``{"meta", "data"}`` envelope (empty on this gateway).

A DDNS record carries:

    ``service``      provider keyword (e.g. ``dyndns``, ``namecheap``,
                     ``cloudflare``, ``noip``, ``custom``)
    ``host_name``    the FQDN to keep updated (e.g. ``home.example.com``)
    ``login``        provider account / username (or zone for some providers)
    ``x_password``   provider password / API token (write-only, redacted back)
    ``server``       custom update-URL host (only for ``service == "custom"``)
    ``interface``    WAN interface whose IP is tracked (e.g. ``"wan"``)
    ``enabled``      bool
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedHostname,
    BoundedSecret,
    BoundedText,
)
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry
    from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.network.dynamic_dns")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    async def _find_ddns(backend: Backend, ddns_id: str) -> UniFiRecord | None:
        entries = await backend.list_dynamic_dns()
        return next((d for d in entries if isinstance(d, dict) and d.get("_id") == ddns_id), None)

    @mcp.tool()
    @audited("list_dynamic_dns")
    async def list_dynamic_dns(controller: str = "default") -> str:
        """List Dynamic DNS update configurations on the controller.

        Side effects: None (read-only).

        Returns one record per DDNS config with ``_id``, ``service``
        (provider), ``host_name`` (the FQDN kept updated), ``login``,
        ``server`` (custom update-URL host, if any), ``interface`` (tracked
        WAN), and ``enabled``. The provider password (``x_password``) is
        write-only and comes back redacted. Empty on a gateway with no DDNS
        configured.

        Example: list_dynamic_dns(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_dynamic_dns())
        except UniFiError as exc:
            logger.exception("list_dynamic_dns failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_dynamic_dns_details")
    async def get_dynamic_dns_details(ddns_id: str, controller: str = "default") -> str:
        """Show one Dynamic DNS config's full record by ``_id``.

        Side effects: None (read-only). Call this before
        ``update_dynamic_dns`` to see the current provider, hostname, and
        tracked interface.

        Returns the DDNS record (with ``x_password`` redacted), or an error
        envelope if no config matches.

        Example: get_dynamic_dns_details(ddns_id="65f...")

        Args:
            ddns_id: The ``_id`` from ``list_dynamic_dns``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            target = await _find_ddns(backend, ddns_id)
        except UniFiError as exc:
            logger.exception("get_dynamic_dns_details failed", extra={"ddns_id": ddns_id})
            return err(str(exc))
        if target is None:
            return err(f"dynamic DNS config {ddns_id} not found")
        return format_json(target)

    @mcp.tool()
    @audited("create_dynamic_dns")
    async def create_dynamic_dns(
        service: str,
        host_name: BoundedHostname,
        login: BoundedText,
        password: BoundedSecret,
        server: BoundedHostname = "",
        interface: str = "wan",
        enabled: bool = True,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a Dynamic DNS update configuration.

        Side effects:
        - Adds a DDNS config: the gateway will push the WAN IP to ``service``
          for ``host_name`` whenever the WAN address changes. Takes effect
          immediately (the gateway sends an update on the next IP check).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_dynamic_dns(service="namecheap", host_name="home.example.com", login="example.com", password="<token>")

        Args:
            service: Provider keyword (e.g. ``"dyndns"``, ``"namecheap"``,
                ``"cloudflare"``, ``"noip"``, or ``"custom"``).
            host_name: The FQDN to keep pointed at the WAN IP
                (``"home.example.com"``).
            login: Provider account / username. For some providers (e.g.
                Namecheap) this is the zone/domain.
            password: Provider password or API token. Stored write-only and
                redacted in reads.
            server: Custom update-URL host. Only used (and required) when
                ``service == "custom"``; leave empty otherwise.
            interface: WAN interface whose IP is tracked. Defaults to
                ``"wan"`` (the primary WAN on a single-WAN gateway).
            enabled: ``False`` creates the config disabled for staging.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set (with the password redacted).
        """
        payload: dict[str, Any] = {
            "service": service,
            "host_name": host_name,
            "login": login,
            "x_password": password,
            "interface": interface,
            "enabled": enabled,
        }
        if server:
            payload["server"] = server
        if dry_run:
            redacted = {**payload, "x_password": "[REDACTED]"}
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"dynamic_dns": redacted},
                    "summary": (f"Would create dynamic DNS for {host_name!r} via {service}"),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_dynamic_dns(payload))
        except UniFiError as exc:
            logger.exception("create_dynamic_dns failed", extra={"host_name": host_name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_dynamic_dns")
    async def update_dynamic_dns(
        ddns_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing Dynamic DNS config.

        Side effects:
        - Modifies the named DDNS config in place. Only fields supplied in
          ``updates`` change; everything else is preserved.
        - Takes effect immediately: changing ``host_name`` or ``service``
          repoints the next update; toggling ``enabled`` starts or stops
          updates.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_dynamic_dns(ddns_id="65f...", updates={"enabled": False})

        Args:
            ddns_id: The ``_id`` from ``list_dynamic_dns``.
            updates: Partial DDNS record. Common keys: ``service``,
                ``host_name``, ``login``, ``x_password`` (new password/token),
                ``server``, ``interface``, ``enabled``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set (``x_password`` redacted if present).
        """
        if not updates:
            return err("update_dynamic_dns requires a non-empty updates object")
        if dry_run:
            redacted = (
                {**updates, "x_password": "[REDACTED]"} if "x_password" in updates else updates
            )
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"ddns_id": ddns_id, "patch": redacted},
                    "summary": (f"Would update dynamic DNS {ddns_id} ({len(updates)} field(s))"),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            updated = await backend.update_dynamic_dns(ddns_id, updates)
            if updated is None:
                return err(f"dynamic DNS config {ddns_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_dynamic_dns failed", extra={"ddns_id": ddns_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_dynamic_dns")
    async def delete_dynamic_dns(
        ddns_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a Dynamic DNS config.

        This tool does not delete on its own. It returns a preview envelope
        with a ``token``; call ``confirm_destructive_action(token)`` to commit
        the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the DDNS config. The provider stops receiving
          updates from the gateway; the external hostname goes stale once its
          TTL lapses.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token: purely informational, no commit step possible.

        Example: delete_dynamic_dns(ddns_id="65f...")

        Args:
            ddns_id: The ``_id`` from ``list_dynamic_dns``.
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
                    "would_delete": {"ddns_id": ddns_id},
                    "summary": f"Would delete dynamic DNS {ddns_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            target = await _find_ddns(backend, ddns_id)
        except UniFiError as exc:
            logger.exception("delete_dynamic_dns preview lookup failed", extra={"ddns_id": ddns_id})
            return err(str(exc))
        if target is None:
            return err(f"dynamic DNS config {ddns_id} not found")

        resource = {
            "_id": ddns_id,
            "host_name": target.get("host_name"),
            "service": target.get("service"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_dynamic_dns(ddns_id)
                return format_json({"deleted": ok, "ddns_id": ddns_id})
            except UniFiError as exc:
                logger.exception("delete_dynamic_dns failed", extra={"ddns_id": ddns_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_dynamic_dns",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))


__all__ = ["register"]
