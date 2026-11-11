"""Client tools: list, block, unblock, reconnect, and name/note updates.

Quarantine is a composite (block + log) and lives in :mod:`composites`.
"""

from __future__ import annotations

import logging
import unicodedata
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mcp_unifi.annotations import DESTRUCTIVE, READ_ONLY, WRITE_IDEMPOTENT
from mcp_unifi.clients.mac import is_mac, normalize_mac, same_mac
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import annotate_audit, audited
from mcp_unifi.modules._params import BoundedName, BoundedNote
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.clients")

#: Most clients one ``update_clients`` call may touch. Each changed client is
#: one PUT, sent one after another.
MAX_CLIENT_UPDATES = 100

#: The fields ``update_clients`` writes, in the order a diff lists them.
_TEXT_FIELDS: tuple[str, ...] = ("name", "note")


def _clean_text(value: str | None) -> str | None:
    """Strip ``value``; ``None`` for a clear (``None`` or empty after strip)."""
    if value is None:
        return None
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise ValueError("must not contain control characters (newlines, tabs, escapes)")
    stripped = value.strip()
    return stripped or None


class ClientUpdate(BaseModel):
    """One client's name and note change. A field left out is kept; null or "" clears it."""

    # ``model_fields_set`` is what tells "left out" from "sent as null", so
    # neither text field may get a default that reads as "set". No other key
    # is accepted: an item is never passed through to the controller.
    model_config = ConfigDict(extra="forbid")

    mac: str = Field(description='Client MAC in any common form, e.g. "aa:bb:cc:00:00:01".')
    name: BoundedName | None = Field(
        default=None,
        description="New display name. Leave out to keep it; null or empty clears it.",
    )
    note: BoundedNote | None = Field(
        default=None,
        description="New note. Leave out to keep it; null or empty clears it.",
    )

    @field_validator("mac")
    @classmethod
    def _valid_mac(cls, value: str) -> str:
        if not is_mac(value):
            raise ValueError(f"{value!r} is not a MAC address")
        return normalize_mac(value)

    @field_validator("name", "note")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return _clean_text(value)

    @model_validator(mode="after")
    def _sets_something(self) -> ClientUpdate:
        if not self.model_fields_set & set(_TEXT_FIELDS):
            raise ValueError(f"{self.mac}: set at least one of name or note")
        return self

    def wanted(self) -> dict[str, str | None]:
        """``{field: new value}`` for the fields this update names; ``None`` clears."""
        return {f: getattr(self, f) for f in _TEXT_FIELDS if f in self.model_fields_set}

    def as_audit_args(self) -> dict[str, Any]:
        """The update as the caller sent it, explicit nulls kept, for the audit log."""
        return self.model_dump(exclude_unset=True)


def _stored_text(record: dict[str, Any], field: str) -> str | None:
    """A user record's ``name``/``note``, with missing and empty both ``None``."""
    value = record.get(field)
    if value is None or value == "":
        return None
    return str(value)


def _plan_client_update(
    record: dict[str, Any], update: ClientUpdate
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Return ``(patch, changes)`` for one client.

    ``patch`` is the PUT body: only the fields whose value differs, a clear
    sent as ``""``, plus ``noted`` when it has to flip. ``changes`` is the
    per-field ``{old, new}`` diff a caller sees, ``noted`` marked dependent.
    Nothing differs: both are empty and no write is sent.
    """
    patch: dict[str, Any] = {}
    changes: dict[str, dict[str, Any]] = {}
    after = {f: _stored_text(record, f) for f in _TEXT_FIELDS}
    for field, new in update.wanted().items():
        old = after[field]
        if new == old:
            continue
        after[field] = new
        patch[field] = new if new is not None else ""
        changes[field] = {"old": old, "new": new}
    if patch:
        # The controller's ``noted`` flag tracks "this record has a name or a
        # note": a UI rename on Network 11.0.99 (issue #219) flipped it from
        # false to true alongside ``name``. Sent only when it has to change.
        old_noted = bool(record.get("noted"))
        new_noted = any(after[f] for f in _TEXT_FIELDS)
        if new_noted != old_noted:
            patch["noted"] = new_noted
            changes["noted"] = {"old": old_noted, "new": new_noted, "dependent": True}
    return patch, changes


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

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_clients", mutates=True)
    async def update_clients(
        updates: Annotated[list[ClientUpdate], Field(min_length=1, max_length=MAX_CLIENT_UPDATES)],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set or clear the display name and note of one or more clients by MAC.

        Cosmetic only: no IP reservation, network, AP or group is touched.
        To pin an IP use ``update_static_dhcp_lease`` instead; that tool
        always sets ``use_fixedip``, so renaming through it reserves an IP.

        Side effects:
        - For each client whose name or note differs, sends one partial
          ``PUT /rest/user/{_id}`` carrying only the changed fields, plus
          ``noted`` when it has to flip (it is true exactly when the client
          has a name or a note, as a UI rename sets it). A client whose
          values already match gets no write.
        - A clear is sent as an empty string, which the long-standing
          Art-of-WiFi client documents as removing the name. Applying a
          clear through this REST endpoint is not live-verified.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - The same MAC twice in one call is refused before anything is
          written. One client failing does not stop the others; each MAC
          gets its own ``status``. If no client was updated or already
          matched, the response is an error envelope that still carries
          every per-MAC result.

        Example: update_clients(updates=[{"mac": "aa:bb:cc:00:00:02", "name": "Pete's iPhone"}, {"mac": "aa:bb:cc:00:00:04", "note": None}])

        Args:
            updates: 1 to 100 items, each ``{"mac": ..., "name": ...,
                "note": ...}``. ``mac`` is required. Leave a field out to
                keep it; send ``null`` or ``""`` to clear it. Each item must
                name at least one of ``name`` (max 128) or ``note``
                (max 1024). Surrounding whitespace is stripped, control
                characters are refused, other keys are refused.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns, per
                MAC, the ``{old, new}`` value of each field that would
                change (``noted`` marked ``dependent``), and flags MACs the
                controller has no record of.
        """
        # Record the updates as plain dicts with explicit nulls kept. The
        # pydantic items would otherwise reach the audit sink as their repr,
        # which neither reads back as JSON nor replays.
        annotate_audit(updates=[u.as_audit_args() for u in updates])
        for i, update in enumerate(updates):
            for earlier in updates[:i]:
                if same_mac(earlier.mac, update.mac):
                    return err(
                        f"{update.mac} appears more than once in updates; send each MAC "
                        "once. Nothing was written."
                    )
        try:
            backend = resolve_backend(registry, controller)
            records = await backend.list_user_records()
        except UniFiError as exc:
            logger.exception("update_clients lookup failed")
            return err(str(exc))

        planned: list[tuple[ClientUpdate, dict[str, Any] | None, dict[str, Any], dict[str, Any]]]
        planned = []
        for update in updates:
            record = next(
                (r for r in records if isinstance(r, dict) and same_mac(r.get("mac"), update.mac)),
                None,
            )
            if record is None:
                planned.append((update, None, {}, {}))
                continue
            patch, changes = _plan_client_update(record, update)
            planned.append((update, record, patch, changes))

        if dry_run:
            previews: list[dict[str, Any]] = []
            for update, record, patch, changes in planned:
                if record is None:
                    previews.append(
                        {
                            "mac": update.mac,
                            "client_known": False,
                            "status": "not_found",
                            "changes": {},
                            "note": (
                                f"The controller has no record of {update.mac}; the real call "
                                "reports it not_found and writes nothing for it."
                            ),
                        }
                    )
                    continue
                previews.append(
                    {
                        "mac": update.mac,
                        "client_known": True,
                        "status": "would_update" if patch else "unchanged",
                        "changes": changes,
                    }
                )
            would = sum(1 for p in previews if p["status"] == "would_update")
            unknown = sum(1 for p in previews if p["status"] == "not_found")
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": previews,
                    "summary": (
                        f"Would update {would} of {len(previews)} clients "
                        f"({len(previews) - would - unknown} unchanged, {unknown} not found)"
                    ),
                }
            )

        results: list[dict[str, Any]] = []
        for update, record, patch, changes in planned:
            if record is None:
                results.append({"mac": update.mac, "status": "not_found", "changes": {}})
                continue
            if not patch:
                results.append({"mac": update.mac, "status": "unchanged", "changes": {}})
                continue
            user_id = record.get("_id")
            if not isinstance(user_id, str) or not user_id:
                results.append(
                    {
                        "mac": update.mac,
                        "status": "failed",
                        "changes": changes,
                        "error": "the controller's user record for this MAC has no _id",
                    }
                )
                continue
            try:
                await backend.update_user(user_id, patch)
            except UniFiError as exc:
                logger.exception("update_clients write failed", extra={"mac": update.mac})
                results.append(
                    {"mac": update.mac, "status": "failed", "changes": changes, "error": str(exc)}
                )
                continue
            results.append({"mac": update.mac, "status": "updated", "changes": changes})

        counts = {
            status: sum(1 for r in results if r["status"] == status)
            for status in ("updated", "unchanged", "not_found", "failed")
        }
        summary = (
            f"Updated {counts['updated']} of {len(results)} clients "
            f"({counts['unchanged']} unchanged, {counts['not_found']} not found, "
            f"{counts['failed']} failed)"
        )
        body: dict[str, Any] = {
            "controller": controller,
            **counts,
            "results": results,
            "summary": summary,
        }
        if counts["updated"] == 0 and counts["unchanged"] == 0:
            # Nothing landed and nothing already matched: every MAC was
            # unknown or refused. That is a failed call, in the same envelope
            # every other tool fails with, so a caller (or the replay tool)
            # checking for ``error`` sees it.
            return format_json(
                {
                    "error": f"update_clients changed nothing: {summary}",
                    "stub_mode": settings.stub_mode,
                    **body,
                }
            )
        return format_json(body)
