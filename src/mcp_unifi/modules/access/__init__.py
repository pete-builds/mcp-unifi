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
import time
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.access")

#: Valid ``result`` filter values for event queries. Empty string means "any".
EVENT_RESULTS: frozenset[str] = frozenset({"granted", "denied"})

#: Valid credential ``type`` values. Surfaced so the LLM gets a stable
#: enumeration to filter against when audits ask about specific credential
#: classes (e.g. "all NFC cards expiring soon").
CREDENTIAL_TYPES: frozenset[str] = frozenset({"nfc", "pin", "mobile"})


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

    @mcp.tool()
    @audited("list_doors")
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
            backend = registry.get_access(controller)
            return format_json(await backend.list_doors())
        except UniFiError as exc:
            logger.exception("list_doors failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_door")
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
            backend = registry.get_access(controller)
            door = await backend.get_door(door_id)
            if door is None:
                return err(f"door {door_id} not found")
            return format_json(door)
        except UniFiError as exc:
            logger.exception("get_door failed", extra={"door_id": door_id})
            return err(str(exc))

    @mcp.tool()
    @audited("list_door_groups")
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
            backend = registry.get_access(controller)
            return format_json(await backend.list_door_groups())
        except UniFiError as exc:
            logger.exception("list_door_groups failed")
            return err(str(exc))

    # ------------------------------------------------------------------
    # Access policies (2)
    # ------------------------------------------------------------------

    @mcp.tool()
    @audited("list_access_policies")
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
            backend = registry.get_access(controller)
            return format_json(await backend.list_access_policies())
        except UniFiError as exc:
            logger.exception("list_access_policies failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_access_policy")
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
            backend = registry.get_access(controller)
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

    @mcp.tool()
    @audited("list_credentials")
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
            backend = registry.get_access(controller)
            return format_json(await backend.list_credentials())
        except UniFiError as exc:
            logger.exception("list_credentials failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_credential")
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
            backend = registry.get_access(controller)
            cred = await backend.get_credential(credential_id)
            if cred is None:
                return err(f"credential {credential_id} not found")
            return format_json(cred)
        except UniFiError as exc:
            logger.exception("get_credential failed", extra={"credential_id": credential_id})
            return err(str(exc))

    @mcp.tool()
    @audited("audit_expiring_credentials")
    async def audit_expiring_credentials(
        days_ahead: int = 30,
        credential_type: str = "",
        controller: str = "default",
    ) -> str:
        """Return credentials expiring within ``days_ahead`` days.

        Side effects: None (read-only).

        Iterates ``list_credentials`` client-side and filters to those whose
        ``expires_at`` falls inside the window ``[now, now + days_ahead]``.
        Credentials with no ``expires_at`` (typical for mobile credentials)
        are excluded. Each entry includes ``days_until_expiry`` so the LLM
        can sort and summarise without re-doing the math.

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
            backend = registry.get_access(controller)
            credentials = await backend.list_credentials()
        except UniFiError as exc:
            logger.exception("audit_expiring_credentials failed")
            return err(str(exc))

        now_ms = int(time.time() * 1000)
        horizon_ms = now_ms + days_ahead * 86_400 * 1000
        expiring: list[dict[str, Any]] = []
        for cred in credentials:
            if credential_type and cred.get("type") != credential_type:
                continue
            expires_at = cred.get("expires_at")
            if not isinstance(expires_at, int):
                continue
            if now_ms <= expires_at <= horizon_ms:
                annotated = dict(cred)
                annotated["days_until_expiry"] = max(0, (expires_at - now_ms) // (86_400 * 1000))
                expiring.append(annotated)
        expiring.sort(key=lambda c: c.get("expires_at", 0))
        return format_json(
            {
                "horizon_days": days_ahead,
                "now_ms": now_ms,
                "count": len(expiring),
                "credentials": expiring,
            }
        )

    # ------------------------------------------------------------------
    # Visitors (2)
    # ------------------------------------------------------------------

    @mcp.tool()
    @audited("list_visitors")
    async def list_visitors(controller: str = "default") -> str:
        """List every visitor pass on the controller (active and expired).

        Side effects: None (read-only).

        Returns one record per visitor with ``id``, ``first_name``,
        ``last_name``, ``full_name``, ``email``, ``host_user_id``,
        ``valid_from`` (ms), ``valid_until`` (ms), ``status``, and
        ``pass_code``.

        Example: list_visitors(controller="default")

        Args:
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = registry.get_access(controller)
            return format_json(await backend.list_visitors())
        except UniFiError as exc:
            logger.exception("list_visitors failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_visitor")
    async def get_visitor(visitor_id: str, controller: str = "default") -> str:
        """Fetch one visitor pass's full record by ID.

        Side effects: None (read-only).

        Same shape as one entry from ``list_visitors`` plus any per-pass
        purpose / notes.

        Example: get_visitor(visitor_id="vis...", controller="default")

        Args:
            visitor_id: Visitor ``id`` from ``list_visitors``.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = registry.get_access(controller)
            visitor = await backend.get_visitor(visitor_id)
            if visitor is None:
                return err(f"visitor {visitor_id} not found")
            return format_json(visitor)
        except UniFiError as exc:
            logger.exception("get_visitor failed", extra={"visitor_id": visitor_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # Events (4)
    # ------------------------------------------------------------------

    @mcp.tool()
    @audited("list_access_events")
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
            hours_back: Look-back window in hours. Defaults to 24.
            result: Optional ``"granted"`` or ``"denied"`` filter. Empty
                (default) returns both.
            door_id: Optional door ``id`` filter. Empty returns events
                across every door.
            limit: Maximum events returned. Defaults to 100.
            controller: Name of the UniFi controller to target.
        """
        if result and result not in EVENT_RESULTS:
            return err(f"result {result!r} not in {sorted(EVENT_RESULTS)}")
        try:
            backend = registry.get_access(controller)
            start_ms, end_ms = _hours_window(hours_back)
            events = await backend.list_events(
                start_ms, end_ms, limit, result=result, door_id=door_id
            )
            return format_json(events)
        except UniFiError as exc:
            logger.exception("list_access_events failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_recent_access_events")
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
            limit: Maximum events returned. Defaults to 20.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = registry.get_access(controller)
            start_ms, end_ms = _hours_window(24)
            events = await backend.list_events(start_ms, end_ms, limit)
            return format_json(events)
        except UniFiError as exc:
            logger.exception("get_recent_access_events failed")
            return err(str(exc))

    @mcp.tool()
    @audited("summarize_access_activity")
    async def summarize_access_activity(
        hours_back: int = 24,
        controller: str = "default",
    ) -> str:
        """Aggregate badge events by door, user, and outcome.

        Side effects: None (read-only).

        Pulls events over the last ``hours_back`` hours (cap 500 to keep the
        summary tractable) and rolls them up into counts so the LLM can
        answer "who used which door how often" without re-aggregating
        client-side. Returns ``total``, ``granted``, ``denied``, plus
        ``by_door`` and ``by_user`` maps.

        Example: summarize_access_activity(hours_back=24)

        Args:
            hours_back: Look-back window in hours. Defaults to 24.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = registry.get_access(controller)
            start_ms, end_ms = _hours_window(hours_back)
            events = await backend.list_events(start_ms, end_ms, 500)
        except UniFiError as exc:
            logger.exception("summarize_access_activity failed")
            return err(str(exc))

        total = len(events)
        granted = sum(1 for e in events if e.get("result") == "granted")
        denied = total - granted
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

        return format_json(
            {
                "hours_back": hours_back,
                "total": total,
                "granted": granted,
                "denied": denied,
                "by_door": sorted(by_door.values(), key=lambda d: d["total"], reverse=True),
                "by_user": sorted(by_user.values(), key=lambda u: u["total"], reverse=True),
            }
        )

    @mcp.tool()
    @audited("list_failed_access_attempts")
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
            hours_back: Look-back window in hours. Defaults to 24.
            door_id: Optional door ``id`` filter. Empty returns denials
                across every door.
            limit: Maximum events returned. Defaults to 100.
            controller: Name of the UniFi controller to target.
        """
        try:
            backend = registry.get_access(controller)
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

    @mcp.tool()
    @audited("list_access_devices")
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
            backend = registry.get_access(controller)
            return format_json(await backend.list_devices())
        except UniFiError as exc:
            logger.exception("list_access_devices failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_access_device")
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
            backend = registry.get_access(controller)
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

    @mcp.tool()
    @audited("get_access_system_info")
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
            backend = registry.get_access(controller)
            return format_json(await backend.get_system_info())
        except UniFiError as exc:
            logger.exception("get_access_system_info failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_access_users")
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
            backend = registry.get_access(controller)
            return format_json(await backend.list_users())
        except UniFiError as exc:
            logger.exception("list_access_users failed")
            return err(str(exc))


__all__ = ["register"]
