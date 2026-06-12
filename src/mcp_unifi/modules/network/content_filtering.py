"""DNS content-filtering tools: list, get, update, delete.

Content-filtering profiles are the UniFi "DNS Content Filtering" feature
(category blocking, safe-search enforcement, and per-client/per-network
filtering). They live on the v2 controller surface
(``/proxy/network/v2/api/site/<site>/content-filtering``), which returns a
**bare** JSON list rather than the legacy ``{"meta", "data"}`` envelope.
Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
(2026-06-12): ``GET .../content-filtering`` answers HTTP 200 with one
populated profile.

A profile carries:

    ``name``           display name
    ``enabled``        bool
    ``categories``     blocked DNS-category enum list (e.g. ``ADVERTISEMENT``)
    ``allow_list``     per-domain allow overrides
    ``block_list``     per-domain block overrides
    ``client_macs``    client MACs the profile applies to
    ``network_ids``    networks the profile applies to
    ``safe_search``    safe-search enforcement targets
    ``schedule``       a ``{"mode": "ALWAYS"|...}`` block

The v2 PUT replaces the whole object, so ``update_content_filter`` reads the
current record first, merges the change, and PUTs the full result (strict
read-modify-write) to avoid dropping untouched fields.
"""

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

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry
    from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.network.content_filtering")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    async def _find_filter(backend: Backend, filter_id: str) -> UniFiRecord | None:
        profiles = await backend.list_content_filters()
        return next(
            (p for p in profiles if isinstance(p, dict) and p.get("_id") == filter_id), None
        )

    @mcp.tool()
    @audited("list_content_filters")
    async def list_content_filters(controller: str = "default") -> str:
        """List DNS content-filtering profiles (category blocking, safe-search).

        Side effects: None (read-only).

        Returns one record per profile with ``_id``, ``name``, ``enabled``,
        ``categories`` (blocked DNS-category enum list), ``allow_list`` /
        ``block_list`` (per-domain overrides), ``client_macs`` and
        ``network_ids`` (the scope the profile applies to), ``safe_search``,
        and ``schedule``. Empty on a gateway with no filtering profiles.

        Example: list_content_filters(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_content_filters())
        except UniFiError as exc:
            logger.exception("list_content_filters failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_content_filter_details")
    async def get_content_filter_details(filter_id: str, controller: str = "default") -> str:
        """Show one content-filtering profile's full record by ``_id``.

        Side effects: None (read-only). Call this before
        ``update_content_filter`` to see the profile's current categories,
        allow/block lists, and scope (the values you are about to
        read-modify-write).

        Returns the profile record, or an error envelope if no profile
        matches.

        Example: get_content_filter_details(filter_id="65f...")

        Args:
            filter_id: The ``_id`` from ``list_content_filters``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            target = await _find_filter(backend, filter_id)
        except UniFiError as exc:
            logger.exception("get_content_filter_details failed", extra={"filter_id": filter_id})
            return err(str(exc))
        if target is None:
            return err(f"content filter {filter_id} not found")
        return format_json(target)

    @mcp.tool()
    @audited("update_content_filter")
    async def update_content_filter(
        filter_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing content-filtering profile (read-modify-write).

        Side effects:
        - Modifies the named profile in place. The v2 PUT replaces the whole
          object, so this reads the current profile first and merges
          ``updates`` onto it before writing: only the keys you supply change,
          everything else (scope, schedule, the other lists) is preserved.
        - Takes effect immediately on DNS resolution for the in-scope clients
          and networks: enabling a category starts blocking it; adding a
          ``block_list`` domain starts NXDOMAIN-ing it.
        - List fields (``categories``, ``allow_list``, ``block_list``,
          ``client_macs``, ``network_ids``, ``safe_search``) are **replaced
          wholesale**, not appended, so pass the full desired list. Read the
          current value with ``get_content_filter_details`` first.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: update_content_filter(filter_id="65f...", updates={"enabled": False})

        Args:
            filter_id: The ``_id`` from ``list_content_filters``.
            updates: Partial profile record to merge. Common keys: ``name``,
                ``enabled``, ``categories`` (full blocked-category list),
                ``allow_list`` / ``block_list`` (full per-domain lists),
                ``client_macs`` / ``network_ids`` (full scope lists),
                ``safe_search``, ``schedule``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not updates:
            return err("update_content_filter requires a non-empty updates object")
        try:
            backend = resolve_backend(registry, controller)
            existing = await _find_filter(backend, filter_id)
        except UniFiError as exc:
            logger.exception("update_content_filter lookup failed", extra={"filter_id": filter_id})
            return err(str(exc))
        if existing is None:
            return err(f"content filter {filter_id} not found")
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"filter_id": filter_id, "patch": updates},
                    "summary": (
                        f"Would update content filter {existing.get('name')!r} "
                        f"({len(updates)} field(s))"
                    ),
                }
            )
        merged = {**existing, **updates}
        try:
            updated = await backend.update_content_filter(filter_id, merged)
            if updated is None:
                return err(f"content filter {filter_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("update_content_filter failed", extra={"filter_id": filter_id})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_content_filter")
    async def delete_content_filter(
        filter_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a content-filtering profile.

        This tool does not delete on its own. It returns a preview envelope
        with a ``token``; call ``confirm_destructive_action(token)`` to commit
        the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the profile. The clients and networks in its
          scope stop being filtered by it and fall back to whatever other
          profile (or none) applies.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token: purely informational, no commit step possible.

        Example: delete_content_filter(filter_id="65f...")

        Args:
            filter_id: The ``_id`` from ``list_content_filters``.
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
                    "would_delete": {"filter_id": filter_id},
                    "summary": f"Would delete content filter {filter_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            target = await _find_filter(backend, filter_id)
        except UniFiError as exc:
            logger.exception(
                "delete_content_filter preview lookup failed", extra={"filter_id": filter_id}
            )
            return err(str(exc))
        if target is None:
            return err(f"content filter {filter_id} not found")

        resource = {
            "_id": filter_id,
            "name": target.get("name"),
            "categories": target.get("categories"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_content_filter(filter_id)
                return format_json({"deleted": ok, "filter_id": filter_id})
            except UniFiError as exc:
                logger.exception("delete_content_filter failed", extra={"filter_id": filter_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_content_filter",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))


__all__ = ["register"]
