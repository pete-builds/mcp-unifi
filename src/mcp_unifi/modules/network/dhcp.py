"""Static DHCP lease tools: list, create, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import CREATE, DESTRUCTIVE, READ_ONLY, WRITE_IDEMPOTENT
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedHostname,
    BoundedName,
)
from mcp_unifi.modules.network._common import (
    NetworkRefError,
    format_json,
    make_err,
    resolve_network_ref,
    same_network,
)
from mcp_unifi.modules.network._pending import format_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.dhcp")


async def _read_back(backend: Backend, mac: str) -> tuple[dict[str, Any], str | None]:
    """The user record for ``mac`` as the controller holds it after a write.

    Issue #219: on Network 11 the ``PUT /rest/user/{id}`` answer can be an
    empty object, so the write's own response says nothing about what landed.
    The write has already been sent when this runs, so a failed read is
    reported next to the result, never as the call's error.
    """
    try:
        found = await backend.find_user_by_mac(mac)
    except UniFiError as exc:
        return {}, f"the write was sent, but reading the record back failed: {exc}"
    if found is None:
        return {}, "the write was sent, but no record for this MAC could be read back"
    return dict(found), None


def _applied(
    *,
    controller: str,
    change_key: str,
    change: dict[str, Any],
    sent: dict[str, Any],
    written: dict[str, Any],
    reread: dict[str, Any],
    read_back_error: str | None,
    summary: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A real call's answer: the dry run's summary shape plus what was applied.

    The top level still carries the written record's fields, as it did when
    the tool returned the controller's write response and nothing else
    (callers read ``result["_id"]`` and ``result["fixed_ip"]``). The write
    response wins where it has a key; the re-read fills in the rest, which is
    everything when the controller answered ``{}``.
    """
    body: dict[str, Any] = {**reread, **written}
    body.update(
        {
            "dry_run": False,
            "controller": controller,
            change_key: change,
            "sent_fields": sorted(sent),
            "record": reread or None,
            "summary": summary,
        }
    )
    if extra:
        body.update(extra)
    if read_back_error:
        body["read_back_error"] = read_back_error
    return body


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
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

    @mcp.tool(annotations=CREATE)
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

        Network reference: ``network_id`` may be the network's ``_id`` or
        its ``legacy_id`` from ``list_networks`` (UniFi Network 11 gives a
        network a UUID ``_id`` and keeps its old ObjectId as ``legacy_id``).
        It is resolved before anything is written: a reference that names no
        network, or more than one, is refused, ``dry_run`` included. The
        network's ``_id`` is what is sent. What a Network 11 controller
        stores for a new lease written with the UUID ``_id`` (kept, converted
        to the legacy id, or refused) has not been verified live.

        Returns: the dry run answers ``{"dry_run": true, "controller",
        "would_create": {"dhcp_lease": payload}, "summary"}``. The real call
        answers the same shape for what was applied: ``{"dry_run": false,
        "controller", "created": {"dhcp_lease": payload}, "sent_fields":
        [...], "record": <the user record re-read after the write>,
        "summary"}``, plus ``read_back_error`` if that read failed. The top
        level also keeps the created record's fields (``_id``, ``fixed_ip``,
        ...), as before.

        Example: create_static_dhcp_lease(mac="aa:bb:cc:00:00:01", ip="10.50.0.10", network_id="65f...", name="cameras-nvr")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
            ip: IPv4 address to reserve.
            network_id: ``_id`` or ``legacy_id`` of the network/VLAN this
                client lives on.
            name: Friendly display name (optional).
            hostname: DHCP hostname (optional).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        try:
            backend = resolve_backend(registry, controller)
            network, _ = await resolve_network_ref(backend, network_id)
        except NetworkRefError as exc:
            return err(f"{exc}; nothing was written")
        except UniFiError as exc:
            logger.exception("create_static_dhcp_lease network lookup failed")
            return err(str(exc))
        payload: dict[str, Any] = {
            "mac": mac,
            "use_fixedip": True,
            "fixed_ip": ip,
            "network_id": network["_id"],
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
            written = await backend.create_dhcp_lease(payload)
        except UniFiError as exc:
            logger.exception("create_static_dhcp_lease failed", extra={"mac": mac})
            if "api.err.MacUsed" in str(exc):
                return err(
                    f"{mac} already has a user record on the controller (api.err.MacUsed), "
                    "so a new one cannot be created. Use update_static_dhcp_lease with the "
                    "same mac to set or change its reservation instead."
                )
            return err(str(exc))
        reread, read_back_error = await _read_back(backend, mac)
        return format_json(
            _applied(
                controller=controller,
                change_key="created",
                change={"dhcp_lease": payload},
                sent=payload,
                written=written,
                reread=reread,
                read_back_error=read_back_error,
                summary=f"Reserved {ip} for {mac}",
            )
        )

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_static_dhcp_lease", mutates=True)
    async def update_static_dhcp_lease(
        mac: str,
        fixed_ip: str,
        network_id: str = "",
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

        This always reserves an IP. To rename a client or set its note with
        no reservation, use ``update_clients``.

        Side effects:
        - Sets ``use_fixedip=true`` and pins ``fixed_ip`` on the user record.
        - ``network_id`` is sent only when given and different. Left out,
          the record keeps the network it already has, as the Art-of-WiFi
          client's ``edit_client_fixedip`` treats it. Omitting it is not
          live-verified.
        - If ``local_dns_record`` is supplied, also sets
          ``local_dns_record_enabled=true`` so the name resolves on the LAN
          (controller version permitting).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - If no user record exists for ``mac``, the call fails with a clear
          error, ``dry_run`` included. In that case use
          ``create_static_dhcp_lease`` instead.

        Network reference: ``network_id`` may be the network's ``_id`` or
        its ``legacy_id`` from ``list_networks``. On UniFi Network 11 a
        network's ``_id`` is a UUID and its old ObjectId is kept as
        ``legacy_id``, and older reservations still store that legacy id as
        their ``network_id``. The reference is resolved before anything is
        written: one that names no network, or more than one, is refused. If
        the record already points at that network, in either form,
        ``network_id`` is not sent at all, so an unchanged binding is never
        rewritten. Otherwise the network's ``_id`` is sent. What a Network 11
        controller stores when a lease is written with the UUID ``_id`` (kept,
        converted to the legacy id, or refused) has not been verified live.

        Returns: the dry run answers ``{"dry_run": true, "controller",
        "would_update": {"mac", "patch"}, "summary"}``. The real call answers
        the same shape for what was applied: ``{"dry_run": false,
        "controller", "updated": {"mac", "user_id", "patch"}, "sent_fields":
        [...], "record": <the user record re-read after the write>,
        "summary"}``, plus ``read_back_error`` if that read failed. With
        ``network_id`` given, both also carry ``network_binding``: the network it
        resolved to and whether ``network_id`` was sent. The top level also
        keeps the written record's fields (``_id``, ``fixed_ip``, ...), filled
        in from the re-read when the controller answers the write with ``{}``.

        Example: update_static_dhcp_lease(mac="d0:11:e5:03:f6:3a", fixed_ip="192.168.1.50", network_id="6a0...", name="cypher")

        Args:
            mac: Client MAC address (e.g. ``"d0:11:e5:03:f6:3a"``).
            fixed_ip: IPv4 address to pin. Must be inside the network's subnet.
            network_id: ``_id`` or ``legacy_id`` of the network/VLAN the IP
                belongs to (optional). Leave it out to keep the record's
                current network.
            name: Friendly display name / hostname alias (optional).
            local_dns_record: Local DNS name to resolve to ``fixed_ip``
                (optional). When set, ``local_dns_record_enabled=true`` is
                also sent.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        try:
            backend = resolve_backend(registry, controller)
            network: dict[str, Any] | None = None
            networks: list[dict[str, Any]] = []
            if network_id:
                network, networks = await resolve_network_ref(backend, network_id)
            user = await backend.find_user_by_mac(mac)
        except NetworkRefError as exc:
            return err(f"{exc}; nothing was written")
        except UniFiError as exc:
            logger.exception("update_static_dhcp_lease lookup failed", extra={"mac": mac})
            return err(str(exc))
        if not user or not user.get("_id"):
            return err(
                f"No user record found for MAC {mac}. "
                "Use create_static_dhcp_lease for unknown MACs."
            )
        user_id = str(user["_id"])

        payload: dict[str, Any] = {
            "use_fixedip": True,
            "fixed_ip": fixed_ip,
        }
        extra: dict[str, Any] = {}
        if network is not None:
            # A reservation made before Network 11 stores its network's
            # legacy_id. The caller's reference naming that same network, in
            # either form, is no change: sending it would rewrite the binding.
            unchanged = same_network(networks, user.get("network_id"), network["_id"])
            if not unchanged:
                payload["network_id"] = network["_id"]
            extra["network_binding"] = {
                "requested": network_id,
                "_id": network["_id"],
                "name": network.get("name"),
                "network_id_sent": not unchanged,
                "reason": (
                    "the record already points at this network"
                    if unchanged
                    else "the record points at a different network, or none"
                ),
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
                    **extra,
                }
            )
        try:
            written = await backend.update_dhcp_lease(user_id, payload)
        except UniFiError as exc:
            logger.exception("update_static_dhcp_lease failed", extra={"mac": mac})
            return err(str(exc))
        reread, read_back_error = await _read_back(backend, mac)
        return format_json(
            _applied(
                controller=controller,
                change_key="updated",
                change={"mac": mac, "user_id": user_id, "patch": payload},
                sent=payload,
                written=written,
                reread=reread,
                read_back_error=read_back_error,
                summary=f"Pinned {fixed_ip} on {mac}",
                extra=extra,
            )
        )

    @mcp.tool(annotations=DESTRUCTIVE)
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
        return format_preview_envelope(pending)
