"""Static DHCP lease tools: list, create, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedHostname,
    BoundedName,
)
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.dhcp")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_dhcp_leases", mutates=False)
    async def list_dhcp_leases(controller: str = "default") -> str:
        """List static DHCP reservations on the controller.

        Side effects: None (read-only).

        UniFi stores fixed leases on the user object with
        ``use_fixedip=true``. This returns just those entries with ``_id``,
        ``mac``, ``name``, ``hostname``, ``fixed_ip``, and ``network_id``.

        Example: list_dhcp_leases(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_dhcp_leases())
        except UniFiError as exc:
            logger.exception("list_dhcp_leases failed")
            return err(str(exc))

    @mcp.tool()
    @audited("create_static_dhcp_lease", mutates=True)
    async def create_static_dhcp_lease(
        mac: str,
        ip: str,
        network_id: str,
        name: BoundedName = "",
        hostname: BoundedHostname = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Reserve a fixed IP for a client by MAC.

        Side effects:
        - Adds a fixed-IP entry on the user object so ``mac`` always receives
          ``ip`` from the controller's DHCP server. The next DHCP renewal
          for that client picks up the reservation.
        - The IP must fall inside the network's subnet or the controller
          will reject the request.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_static_dhcp_lease(mac="aa:bb:cc:00:00:01", ip="10.50.0.10", network_id="65f...", name="cameras-nvr")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
            ip: IPv4 address to reserve.
            network_id: ``_id`` of the network/VLAN this client lives on.
            name: Friendly display name (optional).
            hostname: DHCP hostname (optional).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        payload: dict[str, Any] = {
            "mac": mac,
            "use_fixedip": True,
            "fixed_ip": ip,
            "network_id": network_id,
        }
        if name:
            payload["name"] = name
        if hostname:
            payload["hostname"] = hostname
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"dhcp_lease": payload},
                    "summary": f"Would reserve {ip} for {mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_dhcp_lease(payload))
        except UniFiError as exc:
            logger.exception("create_static_dhcp_lease failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("update_static_dhcp_lease", mutates=True)
    async def update_static_dhcp_lease(
        mac: str,
        fixed_ip: str,
        network_id: str,
        name: BoundedName = "",
        local_dns_record: BoundedHostname = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Convert or update an existing client to a fixed-IP reservation.

        Use this instead of ``create_static_dhcp_lease`` when the MAC already
        has a user record on the controller (any client that has ever
        connected). The controller rejects POST ``/rest/user`` for known MACs
        with ``api.err.MacUsed``; this tool resolves the existing ``_id`` and
        PUTs an update to ``/rest/user/{_id}`` instead.

        Side effects:
        - Sets ``use_fixedip=true`` and pins ``fixed_ip`` on the user record.
        - If ``local_dns_record`` is supplied, also sets
          ``local_dns_record_enabled=true`` so the name resolves on the LAN
          (controller version permitting).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - If no user record exists for ``mac``, the call fails with a clear
          error. In that case use ``create_static_dhcp_lease`` instead.

        Example: update_static_dhcp_lease(mac="d0:11:e5:03:f6:3a", fixed_ip="192.168.1.50", network_id="6a0...", name="cypher")

        Args:
            mac: Client MAC address (e.g. ``"d0:11:e5:03:f6:3a"``).
            fixed_ip: IPv4 address to pin. Must be inside the network's subnet.
            network_id: ``_id`` of the network/VLAN the IP belongs to.
            name: Friendly display name / hostname alias (optional).
            local_dns_record: Local DNS name to resolve to ``fixed_ip``
                (optional). When set, ``local_dns_record_enabled=true`` is
                also sent.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        payload: dict[str, Any] = {
            "use_fixedip": True,
            "fixed_ip": fixed_ip,
            "network_id": network_id,
        }
        if name:
            payload["name"] = name
        if local_dns_record:
            payload["local_dns_record"] = local_dns_record
            payload["local_dns_record_enabled"] = True
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"mac": mac, "patch": payload},
                    "summary": f"Would pin {fixed_ip} on {mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            user = await backend.find_user_by_mac(mac)
            if not user or not user.get("_id"):
                return err(
                    f"No user record found for MAC {mac}. "
                    "Use create_static_dhcp_lease for unknown MACs."
                )
            user_id = str(user["_id"])
            result = await backend.update_dhcp_lease(user_id, payload)
            return format_json(result)
        except UniFiError as exc:
            logger.exception("update_static_dhcp_lease failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("delete_static_dhcp_lease", mutates=True)
    async def delete_static_dhcp_lease(
        lease_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a static DHCP reservation.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the fixed-IP entry. The client returns to
          dynamic DHCP on its next renewal and may receive a different
          address.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_static_dhcp_lease(lease_id="65f...")

        Args:
            lease_id: The ``_id`` from ``list_dhcp_leases``.
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
                    "would_delete": {"lease_id": lease_id},
                    "summary": f"Would delete DHCP lease {lease_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            leases = await backend.list_dhcp_leases()
        except UniFiError as exc:
            logger.exception(
                "delete_static_dhcp_lease preview lookup failed", extra={"lease_id": lease_id}
            )
            return err(str(exc))

        target = next(
            (lease for lease in leases if isinstance(lease, dict) and lease.get("_id") == lease_id),
            None,
        )
        if target is None:
            return err(f"dhcp lease {lease_id} not found")

        resource = {
            "_id": lease_id,
            "mac": target.get("mac"),
            "fixed_ip": target.get("fixed_ip"),
            "name": target.get("name") or target.get("hostname"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_dhcp_lease(lease_id)
                return format_json({"deleted": ok, "lease_id": lease_id})
            except UniFiError as exc:
                logger.exception("delete_static_dhcp_lease failed", extra={"lease_id": lease_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_static_dhcp_lease",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
