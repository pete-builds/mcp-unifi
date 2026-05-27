"""Honeypot tools.

Honeypots are NOT a dedicated REST collection on UniFi Network 9.x. They
live as a list-of-objects (``honeypot``) inside the ``ips`` per-key setting
record. Each entry is ``{"network_id": <_id>, "ip_address": <ip>,
"version": "v4"}`` (verified on UCG-Fiber fw 5.1.12.33296). The
``honeypot_enabled`` toggle in the same record is the global on/off.

We expose three operator-shaped tools (``list_honeypots``,
``create_honeypot``, ``delete_honeypot``) and synthesise a stable ``id``
for each entry (``{network_id}:{ip_address}``) since the controller does
not assign one. The ``id`` is deterministic so the same honeypot keeps
the same id across calls.

Writes go through ``POST /set/setting/ips`` with a partial body that
replaces the ``honeypot`` list wholesale and toggles ``honeypot_enabled``
to track whether the list is empty.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.honeypot")


def _honeypot_id(entry: dict[str, Any]) -> str:
    """Synthesise a stable id for a honeypot entry.

    UniFi does not assign an ``_id`` to honeypot list entries because they
    live inside a parent setting record. We compose one from the two
    fields a caller actually controls. Stable across repeated calls.
    """
    return f"{entry.get('network_id', '')}:{entry.get('ip_address', '')}"


async def _network_lookup(backend: Any) -> dict[str, dict[str, Any]]:
    """Return ``{network_id: {name, ip_subnet, ...}}`` for friendly output."""
    networks = await backend.list_networks()
    out: dict[str, dict[str, Any]] = {}
    for n in networks:
        if isinstance(n, dict):
            nid = n.get("_id")
            if isinstance(nid, str):
                out[nid] = n
    return out


def _enrich(entry: dict[str, Any], networks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Attach human-readable network_name to a honeypot entry."""
    nid = str(entry.get("network_id", ""))
    net = networks.get(nid, {})
    return {
        "id": _honeypot_id(entry),
        "network_id": nid,
        "network_name": net.get("name"),
        "ip": entry.get("ip_address"),
        "version": entry.get("version", "v4"),
    }


def _validate_ipv4(ip: str) -> str | None:
    """Return an error message if ``ip`` is not a valid bare IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return f"ip {ip!r} is not a valid IPv4 address"
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return f"ip {ip} is not a valid LAN honeypot address"
    return None


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_honeypots")
    async def list_honeypots(controller: str = "default") -> str:
        """List configured honeypots and the global honeypot toggle.

        Side effects: None (read-only).

        Returns ``{"enabled": bool, "honeypots": [...]}`` where each entry
        carries ``id`` (synthesised ``network_id:ip``), ``network_id``,
        ``network_name`` (looked up from ``list_networks``), ``ip``, and
        ``version`` (always ``v4`` on UniFi 9.x).

        Example: list_honeypots(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get(controller)
            record = await backend.get_setting("ips")
            networks = await _network_lookup(backend)
        except UniFiError as exc:
            logger.exception("list_honeypots failed")
            return err(str(exc))
        raw = record.get("honeypot", []) or []
        entries = [_enrich(e, networks) for e in raw if isinstance(e, dict)]
        return format_json(
            {
                "enabled": bool(record.get("honeypot_enabled", False)),
                "honeypots": entries,
            }
        )

    @mcp.tool()
    @audited("create_honeypot")
    async def create_honeypot(
        network_id: str,
        ip: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Add a honeypot trap to a network.

        Side effects:
        - Reads the current ``ips`` setting, appends a new entry
          ``{"network_id": ..., "ip_address": ..., "version": "v4"}``,
          and writes the updated list back via ``POST /set/setting/ips``.
        - Sets ``honeypot_enabled=true`` on the controller (the toggle
          tracks list non-emptiness).
        - Mutates controller state. Use dry_run=True to preview.

        Refuses to write if the (network_id, ip) pair is already a
        honeypot or if ``ip`` is not a valid LAN IPv4 address.

        Example: create_honeypot(network_id="65f...", ip="10.0.50.2")

        Args:
            network_id: The ``_id`` from ``list_networks`` for the VLAN the
                honeypot should live on.
            ip: Unallocated IPv4 address inside the target network.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it.
        """
        validation_err = _validate_ipv4(ip)
        if validation_err is not None:
            return err(validation_err)

        try:
            backend = registry.get(controller)
            networks = await _network_lookup(backend)
        except UniFiError as exc:
            logger.exception("create_honeypot lookup failed")
            return err(str(exc))

        if network_id not in networks:
            return err(f"network {network_id} not found")

        try:
            record = await backend.get_setting("ips")
        except UniFiError as exc:
            logger.exception("create_honeypot ips lookup failed")
            return err(str(exc))

        existing = list(record.get("honeypot", []) or [])
        for entry in existing:
            if not isinstance(entry, dict):
                continue
            if entry.get("network_id") == network_id and entry.get("ip_address") == ip:
                return err(f"honeypot already exists at {ip} on {network_id}")

        new_entry = {"network_id": network_id, "ip_address": ip, "version": "v4"}
        updated = [*existing, new_entry]
        patch: dict[str, Any] = {"honeypot": updated, "honeypot_enabled": True}

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_patch": {"setting_key": "ips", "patch": patch},
                    "summary": (
                        f"Would add honeypot {ip} on {networks[network_id].get('name', network_id)}"
                    ),
                }
            )

        try:
            await backend.set_setting("ips", patch)
        except UniFiError as exc:
            logger.exception("create_honeypot failed")
            return err(str(exc))
        return format_json(_enrich(new_entry, networks))

    @mcp.tool()
    @audited("delete_honeypot")
    async def delete_honeypot(
        id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a honeypot entry.

        v0.7.0 destructive pattern: this tool does not delete on its own.
        It returns a preview envelope with a ``token``; call
        ``confirm_destructive_action(token)`` to commit. Tokens expire
        after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: rewrites the ``ips`` setting's ``honeypot`` list with
          the entry removed and sets ``honeypot_enabled`` based on whether
          the resulting list is empty.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope
          with no token (informational only).

        Example: delete_honeypot(id="65f...:10.0.50.2")

        Args:
            id: The synthesised honeypot id from ``list_honeypots`` in
                ``{network_id}:{ip}`` form.
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
                    "would_delete": {"honeypot_id": id},
                    "summary": f"Would delete honeypot {id}",
                }
            )

        try:
            backend = registry.get(controller)
            record = await backend.get_setting("ips")
        except UniFiError as exc:
            logger.exception("delete_honeypot lookup failed")
            return err(str(exc))

        existing = list(record.get("honeypot", []) or [])
        target_entry: dict[str, Any] | None = None
        target_index = -1
        for idx, entry in enumerate(existing):
            if isinstance(entry, dict) and _honeypot_id(entry) == id:
                target_entry = entry
                target_index = idx
                break

        if target_entry is None:
            return err(f"honeypot {id} not found")

        resource = {
            "_id": id,
            "network_id": target_entry.get("network_id"),
            "ip": target_entry.get("ip_address"),
        }

        async def _execute() -> str:
            try:
                remaining = [e for i, e in enumerate(existing) if i != target_index]
                patch: dict[str, Any] = {
                    "honeypot": remaining,
                    "honeypot_enabled": bool(remaining),
                }
                await backend.set_setting("ips", patch)
                return format_json({"deleted": True, "honeypot_id": id})
            except UniFiError as exc:
                logger.exception("delete_honeypot failed", extra={"honeypot_id": id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_honeypot",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))


__all__ = ["register"]
