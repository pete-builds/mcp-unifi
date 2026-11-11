"""Access module: doors, credentials, visitors, badge events, hubs and readers.

Registered when ``MCP_UNIFI_MODULES_ENABLED`` includes ``"access"``. The
module is opt-in: by default only ``"network"`` is enabled.

v0.10 ships 18 read-only tools. The UniFi Access API key only authorises
GETs; door unlocks, credential issuance, and visitor-pass creation require a
separate session-token flow (see ``docs/v0.10-access-module.md``). The write
surface is gated by a future Option B decision.

Every tool follows the same conventions as the Network and Protect modules:

* ``@audited("<tool_name>")`` so every invocation emits one audit envelope.
* Read-only tools take ``controller="default"``.
* No ``dry_run`` parameter (the surface is read-only by design).
"""

from __future__ import annotations

import logging
import math
import time
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import READ_ONLY
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json as _format_json
from mcp_unifi.modules.network._common import make_err
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.access")


def format_json(data: object) -> str:
    """Serialise a tool response with sensitive keys redacted.

    The credential and visitor tools already redact explicitly because their
    records carry ``pass_code`` and similar; routing every response through
    :func:`redact` closes the door, policy, device, and user reads too, so no
    Access record can surface a secret-shaped field unredacted. Redaction is
    idempotent, so the explicit calls that remain are harmless.
    """
    return _format_json(redact(data))


#: Valid ``result`` filter values for event queries. Empty string means "any".
EVENT_RESULTS: frozenset[str] = frozenset({"granted", "denied"})

#: Valid credential ``type`` values. Surfaced so the LLM gets a stable
#: enumeration to filter against when audits ask about specific credential
#: classes (e.g. "all NFC cards expiring soon").
CREDENTIAL_TYPES: frozenset[str] = frozenset({"nfc", "pin", "mobile"})


#: Upper bounds the read tools enforce, matching the Network module's
#: ``hours`` (720 = 30 days) and ``limit`` (1000) bounds.
MAX_HOURS_BACK = 720
MAX_LIMIT = 1000

#: Most events ``summarize_access_activity`` aggregates. The result says so
#: when the window held more.
SUMMARY_EVENT_CAP = 500

#: An ``expires_at`` below this is not a plausible epoch-millisecond value
#: (it is before 1973). It is more likely seconds, or 0 meaning "no expiry",
#: so it is reported as unparseable rather than as a credential that expired
#: in 1970.
_MIN_EXPIRES_AT_MS = 100_000_000_000


def _bounds_error(*, hours_back: int | None = None, limit: int | None = None) -> str | None:
    """Return the error message for an out-of-range ``hours_back`` or ``limit``."""
    if hours_back is not None and not 1 <= hours_back <= MAX_HOURS_BACK:
        return f"hours_back must be between 1 and {MAX_HOURS_BACK}"
    if limit is not None and not 1 <= limit <= MAX_LIMIT:
        return f"limit must be between 1 and {MAX_LIMIT}"
    return None


def _expiry_ms(value: object) -> int | None:
    """Return ``value`` as epoch milliseconds, or ``None`` when it is not one.

    Accepts ints and finite floats (not bools, which are ints in Python, and
    not strings or anything else) at or above :data:`_MIN_EXPIRES_AT_MS`.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value < _MIN_EXPIRES_AT_MS:
        return None
    return int(value)


def _hours_window(hours_back: int) -> tuple[int, int]:
    """Return ``(start_ms, end_ms)`` covering the last ``hours_back`` hours."""
    end_ms = int(time.time() * 1000)
    start_ms = end_ms - max(hours_back, 0) * 3600 * 1000
    return start_ms, end_ms


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    """Register every Access tool on ``mcp``."""
    err = make_err(settings)

    # ------------------------------------------------------------------
    # Doors (3)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_doors", mutates=False)
    async def list_doors(controller: str = "default") -> str:
        """List every door bonded to the Access controller.

        Side effects: None (read-only).

        Returns one record per door with ``id``, ``name``, ``location``,
        ``hub_id``, ``locked``, ``online``, ``door_position_status``,
        ``lock_status``, and ``last_activity`` (epoch ms).

        Example: list_doors(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(await backend.list_doors())
        except UniFiError as exc:
            logger.exception("list_doors failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_door", mutates=False)
    async def get_door(door_id: str, controller: str = "default") -> str:
        """Fetch one door's full record by ID.

        Side effects: None (read-only).

        Returns the same fields as one entry in ``list_doors`` plus the live
        lock and position status. Useful for confirming a door is online
        before reading recent events against it.

        Example: get_door(door_id="abc...", controller="default")

        Args:
            door_id: Access door ``id`` from ``list_doors``.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            door = await backend.get_door(door_id)
            if door is None:
                return err(f"door {door_id} not found")
            return format_json(door)
        except UniFiError as exc:
            logger.exception("get_door failed", extra={"door_id": door_id})
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_door_groups", mutates=False)
    async def list_door_groups(controller: str = "default") -> str:
        """List every door group defined on the controller.

        Side effects: None (read-only).

        Door groups bundle doors for access-policy assignment. Returns
        ``id``, ``name``, ``door_ids``, and ``description``.

        Example: list_door_groups(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(await backend.list_door_groups())
        except UniFiError as exc:
            logger.exception("list_door_groups failed")
            return err(str(exc))

    # ------------------------------------------------------------------
    # Access policies (2)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_access_policies", mutates=False)
    async def list_access_policies(controller: str = "default") -> str:
        """List every access policy on the controller.

        Side effects: None (read-only).

        Each policy ties a schedule (e.g. business hours), one or more door
        groups, and a set of users / credential types. Returns ``id``,
        ``name``, ``type``, ``schedule``, ``door_group_ids``, ``user_ids``,
        ``credential_types``, ``active``.

        Example: list_access_policies(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(await backend.list_access_policies())
        except UniFiError as exc:
            logger.exception("list_access_policies failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_access_policy", mutates=False)
    async def get_access_policy(policy_id: str, controller: str = "default") -> str:
        """Fetch one access policy's full record by ID.

        Side effects: None (read-only).

        Same shape as one entry from ``list_access_policies``. Useful when
        auditing why a specific user can or cannot badge into a specific door
        at a specific time.

        Example: get_access_policy(policy_id="pol...", controller="default")

        Args:
            policy_id: Access policy ``id`` from ``list_access_policies``.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            policy = await backend.get_access_policy(policy_id)
            if policy is None:
                return err(f"access policy {policy_id} not found")
            return format_json(policy)
        except UniFiError as exc:
            logger.exception("get_access_policy failed", extra={"policy_id": policy_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # Credentials (3)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_credentials", mutates=False)
    async def list_credentials(controller: str = "default") -> str:
        """List every credential enrolled in the Access controller.

        Side effects: None (read-only).

        Returns one record per credential with ``id``, ``type`` (``nfc``,
        ``pin``, or ``mobile``), ``label``, ``user_id``, ``status``,
        ``issued_at`` (ms), and ``expires_at`` (ms or null for non-expiring
        mobile credentials).

        Example: list_credentials(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            # Credential records carry enrolment material (card/mobile
            # tokens); redact strips anything matching the canonical
            # sensitive-key patterns before it reaches the transcript.
            return format_json(redact(await backend.list_credentials()))
        except UniFiError as exc:
            logger.exception("list_credentials failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_credential", mutates=False)
    async def get_credential(credential_id: str, controller: str = "default") -> str:
        """Fetch one credential's full record by ID.

        Side effects: None (read-only).

        Same shape as one entry from ``list_credentials`` plus any
        type-specific fields (``card_id`` for NFC, ``pin_length`` for PIN,
        ``device_label`` for mobile).

        Example: get_credential(credential_id="cred...", controller="default")

        Args:
            credential_id: Credential ``id`` from ``list_credentials``.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            cred = await backend.get_credential(credential_id)
            if cred is None:
                return err(f"credential {credential_id} not found")
            return format_json(redact(cred))
        except UniFiError as exc:
            logger.exception("get_credential failed", extra={"credential_id": credential_id})
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("audit_expiring_credentials", mutates=False)
    async def audit_expiring_credentials(
        days_ahead: int = 30,
        credential_type: str = "",
        controller: str = "default",
    ) -> str:
        """Return credentials expiring within ``days_ahead`` days.

        Side effects: None (read-only).

        Iterates ``list_credentials`` client-side and filters to those whose
        ``expires_at`` (epoch milliseconds) falls inside the window
        ``[now, now + days_ahead]``. Each entry includes ``days_until_expiry``
        so the LLM can sort and summarise without re-doing the math.
        Credentials with no ``expires_at`` (typical for mobile credentials)
        are left out and only counted in ``no_expiry_count``. Two more lists
        keep nothing hidden: ``already_expired`` holds credentials whose
        ``expires_at`` is already in the past (with ``days_since_expiry``),
        and ``unparseable_expiry`` holds credentials whose ``expires_at`` is
        present but is not an epoch-millisecond number (a string, seconds, 0),
        so a bad value is reported rather than skipped.

        Example: audit_expiring_credentials(days_ahead=14)

        Args:
            days_ahead: Look-ahead window in days. Defaults to 30.
            credential_type: Optional ``"nfc"``, ``"pin"``, or ``"mobile"``
                filter. Empty (default) returns every type.
            controller: Name of the UniFi controller to target.
        """
        if days_ahead < 0:
            return err(f"days_ahead {days_ahead} must be >= 0")
        if credential_type and credential_type not in CREDENTIAL_TYPES:
            return err(f"credential_type {credential_type!r} not in {sorted(CREDENTIAL_TYPES)}")
        try:
            backend = resolve_backend(registry, controller, "access")
            credentials = await backend.list_credentials()
        except UniFiError as exc:
            logger.exception("audit_expiring_credentials failed")
            return err(str(exc))

        now_ms = int(time.time() * 1000)
        horizon_ms = now_ms + days_ahead * 86_400 * 1000
        day_ms = 86_400 * 1000
        expiring: list[dict[str, Any]] = []
        already_expired: list[dict[str, Any]] = []
        unparseable: list[dict[str, Any]] = []
        no_expiry = 0
        for cred in credentials:
            if credential_type and cred.get("type") != credential_type:
                continue
            raw_expiry = cred.get("expires_at")
            if raw_expiry is None:
                no_expiry += 1
                continue
            expires_at = _expiry_ms(raw_expiry)
            if expires_at is None:
                unparseable.append(
                    {
                        "id": cred.get("id"),
                        "type": cred.get("type"),
                        "label": cred.get("label"),
                        "user_id": cred.get("user_id"),
                        "expires_at": raw_expiry,
                    }
                )
            elif expires_at < now_ms:
                annotated = dict(cred)
                annotated["days_since_expiry"] = (now_ms - expires_at) // day_ms
                already_expired.append(annotated)
            elif expires_at <= horizon_ms:
                annotated = dict(cred)
                annotated["days_until_expiry"] = (expires_at - now_ms) // day_ms
                expiring.append(annotated)
        expiring.sort(key=lambda c: c["expires_at"])
        already_expired.sort(key=lambda c: c["expires_at"], reverse=True)
        return format_json(
            {
                "horizon_days": days_ahead,
                "now_ms": now_ms,
                "count": len(expiring),
                # Same records ``list_credentials`` redacts. This tool reads
                # them through the backend directly rather than through that
                # tool, so it needs its own call — the 0.19.2 pass wired the
                # two obvious credential readers and missed this one.
                "credentials": redact(expiring),
                "already_expired_count": len(already_expired),
                "already_expired": redact(already_expired),
                "unparseable_expiry_count": len(unparseable),
                "unparseable_expiry": redact(unparseable),
                "no_expiry_count": no_expiry,
            }
        )

    # ------------------------------------------------------------------
    # Visitors (2)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_visitors", mutates=False)
    async def list_visitors(controller: str = "default") -> str:
        """List every visitor pass on the controller (active and expired).

        Side effects: None (read-only).

        Returns one record per visitor with ``id``, ``first_name``,
        ``last_name``, ``full_name``, ``email``, ``host_user_id``,
        ``valid_from`` (ms), ``valid_until`` (ms), and ``status``.

        ``pass_code`` is **redacted** to ``"[REDACTED]"``. It is the code that
        opens the door, not the record's identifier — ``id`` is, and ``id``
        still comes back, so ``get_visitor`` and every other lookup still
        work. Read the code from the Access UI if you need to reissue it.

        Example: list_visitors(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(redact(await backend.list_visitors()))
        except UniFiError as exc:
            logger.exception("list_visitors failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_visitor", mutates=False)
    async def get_visitor(visitor_id: str, controller: str = "default") -> str:
        """Fetch one visitor pass's full record by ID.

        Side effects: None (read-only).

        Same shape as one entry from ``list_visitors`` plus any per-pass
        purpose / notes, with ``pass_code`` redacted for the same reason.

        Example: get_visitor(visitor_id="vis...", controller="default")

        Args:
            visitor_id: Visitor ``id`` from ``list_visitors``.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            visitor = await backend.get_visitor(visitor_id)
            if visitor is None:
                return err(f"visitor {visitor_id} not found")
            return format_json(redact(visitor))
        except UniFiError as exc:
            logger.exception("get_visitor failed", extra={"visitor_id": visitor_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # Events (4)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_access_events", mutates=False)
    async def list_access_events(
        hours_back: int = 24,
        result: str = "",
        door_id: str = "",
        limit: int = 100,
        controller: str = "default",
    ) -> str:
        """List badge-scan / door events with filters.

        Side effects: None (read-only).

        Returns events whose timestamp falls inside the last ``hours_back``
        hours. ``result`` filters to ``"granted"`` or ``"denied"``; empty
        returns both. ``door_id`` narrows to one door.

        Example: list_access_events(hours_back=6, result="denied", limit=20)

        Args:
            hours_back: Look-back window in hours (1 to 720). Defaults to 24.
            result: Optional ``"granted"`` or ``"denied"`` filter. Empty
                (default) returns both.
            door_id: Optional door ``id`` filter. Empty returns events
                across every door.
            limit: Maximum events returned (1 to 1000). Defaults to 100.
            controller: Name of the UniFi controller to target.
        """
        if result and result not in EVENT_RESULTS:
            return err(f"result {result!r} not in {sorted(EVENT_RESULTS)}")
        if msg := _bounds_error(hours_back=hours_back, limit=limit):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "access")
            start_ms, end_ms = _hours_window(hours_back)
            events = await backend.list_events(
                start_ms, end_ms, limit, result=result, door_id=door_id
            )
            return format_json(events)
        except UniFiError as exc:
            logger.exception("list_access_events failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_recent_access_events", mutates=False)
    async def get_recent_access_events(
        limit: int = 20,
        controller: str = "default",
    ) -> str:
        """Return the most recent N events across every door.

        Side effects: None (read-only).

        Convenience wrapper around ``list_access_events`` with a 24-hour
        window and no filters. Useful for "what just happened" triage.

        Example: get_recent_access_events(limit=10)

        Args:
            limit: Maximum events returned (1 to 1000). Defaults to 20.
            controller: Name of the UniFi controller to target.
        """
        if msg := _bounds_error(limit=limit):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "access")
            start_ms, end_ms = _hours_window(24)
            events = await backend.list_events(start_ms, end_ms, limit)
            return format_json(events)
        except UniFiError as exc:
            logger.exception("get_recent_access_events failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("summarize_access_activity", mutates=False)
    async def summarize_access_activity(
        hours_back: int = 24,
        controller: str = "default",
    ) -> str:
        """Aggregate badge events by door, user, and outcome.

        Side effects: None (read-only).

        Pulls events over the last ``hours_back`` hours and rolls them up
        into counts so the LLM can answer "who used which door how often"
        without re-aggregating client-side. At most 500 events are
        aggregated, the newest ones. Returns ``total``, ``granted``,
        ``denied``, ``other`` (events whose ``result`` is neither, so
        ``granted + denied + other == total``), plus ``by_door`` and
        ``by_user`` maps. When the window held more than 500 events,
        ``truncated`` is ``true`` and every count covers only the newest 500;
        narrow ``hours_back`` for exact counts.

        Example: summarize_access_activity(hours_back=24)

        Args:
            hours_back: Look-back window in hours (1 to 720). Defaults to 24.
            controller: Name of the UniFi controller to target.
        """
        if msg := _bounds_error(hours_back=hours_back):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "access")
            start_ms, end_ms = _hours_window(hours_back)
            # Ask for one more than the cap so a window that held exactly the
            # cap is not reported as truncated.
            fetched = await backend.list_events(start_ms, end_ms, SUMMARY_EVENT_CAP + 1)
        except UniFiError as exc:
            logger.exception("summarize_access_activity failed")
            return err(str(exc))

        # Newest first in our code rather than trusting the controller's order,
        # so the cap always drops the oldest events.
        fetched = sorted(
            fetched,
            key=lambda e: e["timestamp"] if isinstance(e.get("timestamp"), (int, float)) else 0,
            reverse=True,
        )
        truncated = len(fetched) > SUMMARY_EVENT_CAP
        events = fetched[:SUMMARY_EVENT_CAP]

        total = len(events)
        granted = sum(1 for e in events if e.get("result") == "granted")
        denied = sum(1 for e in events if e.get("result") == "denied")
        by_door: dict[str, dict[str, Any]] = {}
        by_user: dict[str, dict[str, Any]] = {}
        for evt in events:
            door_id = str(evt.get("door_id") or "unknown")
            door_bucket = by_door.setdefault(
                door_id,
                {"door_id": door_id, "door_name": evt.get("door_name"), "total": 0, "denied": 0},
            )
            door_bucket["total"] += 1
            if evt.get("result") == "denied":
                door_bucket["denied"] += 1

            user_id = str(evt.get("user_id") or "unknown")
            user_bucket = by_user.setdefault(
                user_id,
                {"user_id": user_id, "user_name": evt.get("user_name"), "total": 0, "denied": 0},
            )
            user_bucket["total"] += 1
            if evt.get("result") == "denied":
                user_bucket["denied"] += 1

        summary: dict[str, Any] = {
            "hours_back": hours_back,
            "total": total,
            "granted": granted,
            "denied": denied,
            "other": total - granted - denied,
            "truncated": truncated,
            "by_door": sorted(by_door.values(), key=lambda d: d["total"], reverse=True),
            "by_user": sorted(by_user.values(), key=lambda u: u["total"], reverse=True),
        }
        if truncated:
            summary["note"] = (
                f"The window held more than {SUMMARY_EVENT_CAP} events. Counts cover "
                f"only the newest {SUMMARY_EVENT_CAP}; use a smaller hours_back for "
                "exact totals."
            )
        return format_json(summary)

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_failed_access_attempts", mutates=False)
    async def list_failed_access_attempts(
        hours_back: int = 24,
        door_id: str = "",
        limit: int = 100,
        controller: str = "default",
    ) -> str:
        """Return only ``result == "denied"`` events within the window.

        Side effects: None (read-only).

        Convenience wrapper around ``list_access_events`` for security audits.
        Each entry includes ``reason`` (e.g. ``"expired"``, ``"off-hours"``,
        ``"unknown_pin"``) so the LLM can summarise the cause distribution.

        Example: list_failed_access_attempts(hours_back=12, door_id="abc...")

        Args:
            hours_back: Look-back window in hours (1 to 720). Defaults to 24.
            door_id: Optional door ``id`` filter. Empty returns denials
                across every door.
            limit: Maximum events returned (1 to 1000). Defaults to 100.
            controller: Name of the UniFi controller to target.
        """
        if msg := _bounds_error(hours_back=hours_back, limit=limit):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "access")
            start_ms, end_ms = _hours_window(hours_back)
            events = await backend.list_events(
                start_ms, end_ms, limit, result="denied", door_id=door_id
            )
            return format_json(events)
        except UniFiError as exc:
            logger.exception("list_failed_access_attempts failed")
            return err(str(exc))

    # ------------------------------------------------------------------
    # Devices (2)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_access_devices", mutates=False)
    async def list_access_devices(controller: str = "default") -> str:
        """List hubs, readers, relays, and intercoms bonded to the controller.

        Side effects: None (read-only).

        Returns one record per device with ``id``, ``type`` (``hub`` or
        ``reader``), ``model``, ``name``, ``mac``, ``ip``, ``online``,
        ``firmware_version``, and (for readers) the ``door_id`` and
        ``hub_id`` they belong to.

        Example: list_access_devices(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(await backend.list_devices())
        except UniFiError as exc:
            logger.exception("list_access_devices failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_access_device", mutates=False)
    async def get_access_device(device_id: str, controller: str = "default") -> str:
        """Fetch one Access device's full record by ID.

        Side effects: None (read-only).

        Same shape as one entry from ``list_access_devices``. Useful for
        checking firmware version, online status, or hub assignment on a
        specific reader.

        Example: get_access_device(device_id="dev...", controller="default")

        Args:
            device_id: Device ``id`` from ``list_access_devices``.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            device = await backend.get_device(device_id)
            if device is None:
                return err(f"access device {device_id} not found")
            return format_json(device)
        except UniFiError as exc:
            logger.exception("get_access_device failed", extra={"device_id": device_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # System (2)
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_access_system_info", mutates=False)
    async def get_access_system_info(controller: str = "default") -> str:
        """Return controller version, license tier, and capacity.

        Side effects: None (read-only).

        Returns ``version``, ``release_channel``, ``license`` (with
        ``doors_used``, ``doors_max``, ``users_used``, ``users_max``),
        ``controller_id``, ``uptime_seconds``. Useful for surfacing licence
        ceilings before suggesting enrolling more doors / users.

        Example: get_access_system_info(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(await backend.get_system_info())
        except UniFiError as exc:
            logger.exception("get_access_system_info failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_access_users", mutates=False)
    async def list_access_users(controller: str = "default") -> str:
        """List every user enrolled in the Access system.

        Side effects: None (read-only).

        Returns one record per user with ``id``, ``first_name``, ``last_name``,
        ``full_name``, ``email``, ``status``, ``employee_number``, and
        ``credential_ids`` (cross-reference with ``list_credentials``).

        Example: list_access_users(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = resolve_backend(registry, controller, "access")
            return format_json(await backend.list_users())
        except UniFiError as exc:
            logger.exception("list_access_users failed")
            return err(str(exc))


__all__ = ["register"]
