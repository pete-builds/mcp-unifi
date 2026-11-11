"""Protect module: cameras, motion events, smart detections, recordings, doorbells.

Registered when ``MCP_UNIFI_MODULES_ENABLED`` includes ``"protect"``. The
module is opt-in: by default only ``"network"`` is enabled.

Every tool here follows the same conventions as the Network module:

* ``@audited("<tool_name>")`` on the function so every invocation emits one
  audit envelope (sensitive kwargs scrubbed downstream).
* Read-only tools take ``controller="default"``. Destructive tools also take
  ``dry_run=False`` and surface a predicted-change payload on dry runs.
* Composites (``provision_camera``) capture pre-state, apply sub-steps, and
  roll back any prior steps on failure.

Phase 3 wires 11 primitives + 1 composite; the surface is intentionally narrow
(no live RTSP, no two-way audio) so the LLM has a small, safe vocabulary.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import CREATE, READ_ONLY, WRITE_IDEMPOTENT
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

logger = logging.getLogger("mcp_unifi.protect")


def format_json(data: object) -> str:
    """Serialise a tool response with sensitive keys redacted.

    Protect records are controller records like any other: camera and
    doorbell objects carry credential-shaped fields on some firmware, and the
    id validator in :mod:`mcp_unifi.clients.ids` is the only reason a response
    here cannot be a Network record. Redacting on the way out is the second
    layer, and it is the same layer the Network module already applies.
    """
    return _format_json(redact(data))


# Allowed values for the small enums tools accept. Keeping them as
# module-level constants makes the validation message stable and lets future
# Protect firmware add modes by editing one place.
RECORDING_MODES: frozenset[str] = frozenset({"always", "motion", "never"})
SMART_DETECT_TYPES: frozenset[str] = frozenset({"person", "vehicle", "animal", "package"})


#: Upper bounds the read tools enforce, matching the Network module's
#: ``hours`` (720 = 30 days) and ``limit`` (1000) bounds.
MAX_HOURS_BACK = 720
MAX_LIMIT = 1000

#: Largest image the snapshot and thumbnail tools will return. A 4K JPEG is
#: around 1 to 2 MB; the base64 payload rides inside a tool response the model
#: has to read, so anything far past that is a wrong body, not a picture.
MAX_IMAGE_BYTES = 4 * 1024 * 1024

#: Every JPEG starts with these three bytes (SOI marker plus the next marker's
#: 0xFF). A login page or JSON error body does not.
_JPEG_MAGIC = b"\xff\xd8\xff"


def _bounds_error(*, hours_back: int | None = None, limit: int | None = None) -> str | None:
    """Return the error message for an out-of-range ``hours_back`` or ``limit``."""
    if hours_back is not None and not 1 <= hours_back <= MAX_HOURS_BACK:
        return f"hours_back must be between 1 and {MAX_HOURS_BACK}"
    if limit is not None and not 1 <= limit <= MAX_LIMIT:
        return f"limit must be between 1 and {MAX_LIMIT}"
    return None


def _image_error(data: bytes, what: str) -> str | None:
    """Return an error message when ``data`` is not a JPEG of acceptable size."""
    if len(data) > MAX_IMAGE_BYTES:
        return (
            f"{what} is {len(data)} bytes, over the {MAX_IMAGE_BYTES} byte limit; not returning it"
        )
    if not data.startswith(_JPEG_MAGIC):
        return (
            f"{what} did not come back as a JPEG ({len(data)} bytes, "
            f"starting {data[:4].hex() or 'empty'}); the controller may have "
            "returned an error page"
        )
    return None


def _newest_first(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort events by ``start``, newest first. The controller's order is not relied on."""

    def start(evt: dict[str, Any]) -> float:
        value = evt.get("start")
        return float(value) if isinstance(value, (int, float)) else 0.0

    return sorted(events, key=start, reverse=True)


def _hours_window(hours_back: int) -> tuple[int, int]:
    """Return ``(start_ms, end_ms)`` covering the last ``hours_back`` hours."""
    end_ms = int(time.time() * 1000)
    start_ms = end_ms - max(hours_back, 0) * 3600 * 1000
    return start_ms, end_ms


def _filter_by_camera(events: list[dict[str, Any]], camera_id: str) -> list[dict[str, Any]]:
    if not camera_id:
        return events
    return [e for e in events if e.get("camera") == camera_id]


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    """Register every Protect tool on ``mcp``."""
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_cameras", mutates=False)
    async def list_cameras(controller: str = "default") -> str:
        """List every camera bonded to the Protect controller.

        Side effects: None (read-only).

        Returns one record per camera with ``id``, ``name``, ``model``,
        ``mac``, ``host``, ``state``, ``isConnected``, ``isDoorbell``, plus
        the nested ``recordingSettings``, ``motionSettings``, ``privacyMask``,
        and ``stats`` blocks the UniFi Protect API surfaces.

        Example: list_cameras(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller, "protect")
            return format_json(await backend.list_cameras())
        except UniFiError as exc:
            logger.exception("list_cameras failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_camera", mutates=False)
    async def get_camera(camera_id: str, controller: str = "default") -> str:
        """Fetch a single camera's full record by ID.

        Side effects: None (read-only).

        Returns the full camera record (same shape as one entry from
        ``list_cameras``) including current recording mode, motion sensitivity,
        privacy-mask state, and the most recent ``lastMotion`` timestamp.

        Example: get_camera(camera_id="65f...", controller="default")

        Args:
            camera_id: The Protect ``id`` (or ``_id``) from ``list_cameras``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller, "protect")
            cam = await backend.get_camera(camera_id)
            if cam is None:
                return err(f"camera {camera_id} not found")
            return format_json(cam)
        except UniFiError as exc:
            logger.exception("get_camera failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_motion_events", mutates=False)
    async def list_motion_events(
        camera_id: str = "",
        limit: int = 50,
        hours_back: int = 24,
        controller: str = "default",
    ) -> str:
        """List motion events in the last ``hours_back`` hours.

        Side effects: None (read-only).

        Filters Protect's event stream to entries with ``type == "motion"``
        within the requested window. ``camera_id`` narrows the result set to
        one camera; an empty string returns motion across every bonded camera.

        Example: list_motion_events(camera_id="65f...", limit=20, hours_back=6)

        Args:
            camera_id: Protect camera ``id``. Empty (default) returns motion
                across all cameras.
            limit: Maximum number of events returned, newest first (1 to
                1000). Defaults to 50.
            hours_back: Look-back window in hours from now (1 to 720).
                Defaults to 24.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if msg := _bounds_error(hours_back=hours_back, limit=limit):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "protect")
            start_ms, end_ms = _hours_window(hours_back)
            # The camera filter runs here, after the controller has applied
            # its limit. Asking for only ``limit`` rows would let other
            # cameras' newer events crowd out the ones wanted, so with a
            # camera filter ask for the widest page, filter, sort, then cut.
            fetch = MAX_LIMIT if camera_id else limit
            events = await backend.list_events(["motion"], start_ms, end_ms, fetch)
            events = _filter_by_camera(events, camera_id)
            return format_json(_newest_first(events)[:limit])
        except UniFiError as exc:
            logger.exception("list_motion_events failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_smart_detections", mutates=False)
    async def list_smart_detections(
        detection_type: str = "person",
        camera_id: str = "",
        limit: int = 20,
        hours_back: int = 24,
        controller: str = "default",
    ) -> str:
        """List smart-detection events (person, vehicle, animal, package).

        Side effects: None (read-only).

        Filters Protect's event stream to ``type == "smartDetectZone"`` and
        narrows to entries whose ``smartDetectTypes`` contain
        ``detection_type``. Empty ``camera_id`` returns detections across all
        cameras.

        Example: list_smart_detections(detection_type="person", hours_back=12)

        Args:
            detection_type: One of ``"person"``, ``"vehicle"``, ``"animal"``,
                ``"package"``. Defaults to ``"person"``.
            camera_id: Protect camera ``id``. Empty (default) returns matches
                across all cameras.
            limit: Maximum number of events returned, newest first (1 to
                1000). Defaults to 20.
            hours_back: Look-back window in hours (1 to 720). Defaults to 24.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if detection_type not in SMART_DETECT_TYPES:
            return err(f"detection_type {detection_type!r} not in {sorted(SMART_DETECT_TYPES)}")
        if msg := _bounds_error(hours_back=hours_back, limit=limit):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "protect")
            start_ms, end_ms = _hours_window(hours_back)
            # The detection type and camera filters both run here, after the
            # controller has applied its limit, so fetch the widest page,
            # filter, sort, then cut. Fetching only ``limit`` rows would let
            # other detection types crowd out the ones wanted.
            raw = await backend.list_events(["smartDetectZone"], start_ms, end_ms, MAX_LIMIT)
            filtered = [evt for evt in raw if detection_type in (evt.get("smartDetectTypes") or [])]
            filtered = _filter_by_camera(filtered, camera_id)
            return format_json(_newest_first(filtered)[:limit])
        except UniFiError as exc:
            logger.exception("list_smart_detections failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_snapshot", mutates=False)
    async def get_snapshot(camera_id: str, controller: str = "default") -> str:
        """Fetch a current JPEG snapshot from a camera, base64-encoded.

        Side effects: None (read-only).

        Returns ``{"camera_id": ..., "format": "jpeg", "data": "<base64>",
        "size_bytes": ...}``. The JPEG payload is base64-encoded so it can
        ride inside the JSON envelope all MCP tools return; decode with
        ``base64.b64decode`` to get the raw image bytes. A body that is not
        a JPEG, or is over 4 MiB, comes back as an error instead.

        Example: get_snapshot(camera_id="65f...", controller="default")

        Args:
            camera_id: Protect camera ``id``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller, "protect")
            data = await backend.get_snapshot(camera_id)
            if msg := _image_error(data, "snapshot"):
                return err(msg)
            encoded = base64.b64encode(data).decode()
            return format_json(
                {
                    "camera_id": camera_id,
                    "format": "jpeg",
                    "data": encoded,
                    "size_bytes": len(data),
                }
            )
        except UniFiError as exc:
            logger.exception("get_snapshot failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_event_thumbnail", mutates=False)
    async def get_event_thumbnail(event_id: str, controller: str = "default") -> str:
        """Fetch the JPEG thumbnail for a Protect event, base64-encoded.

        Side effects: None (read-only).

        Same response shape as ``get_snapshot``, but keyed on the event
        instead of the camera. Useful for previewing a motion or
        smart-detection trigger without pulling the full clip. A body that
        is not a JPEG, or is over 4 MiB, comes back as an error instead.

        Example: get_event_thumbnail(event_id="evt123", controller="default")

        Args:
            event_id: Protect event ``id`` from ``list_motion_events`` or
                ``list_smart_detections``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller, "protect")
            data = await backend.get_event_thumbnail(event_id)
            if msg := _image_error(data, "thumbnail"):
                return err(msg)
            encoded = base64.b64encode(data).decode()
            return format_json(
                {
                    "event_id": event_id,
                    "format": "jpeg",
                    "data": encoded,
                    "size_bytes": len(data),
                }
            )
        except UniFiError as exc:
            logger.exception("get_event_thumbnail failed", extra={"event_id": event_id})
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_recordings", mutates=False)
    async def list_recordings(
        camera_id: str,
        hours_back: int = 24,
        controller: str = "default",
    ) -> str:
        """List Protect recordings for one camera over the last ``hours_back`` hours.

        Side effects: None (read-only).

        Returns one record per stored clip segment with ``id``, ``start``,
        ``end``, ``type``, and ``size`` (bytes). Useful for finding the
        recording window around a specific motion event.

        Example: list_recordings(camera_id="65f...", hours_back=6)

        Args:
            camera_id: Protect camera ``id``.
            hours_back: Look-back window in hours (1 to 720). Defaults to 24.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if msg := _bounds_error(hours_back=hours_back):
            return err(msg)
        try:
            backend = resolve_backend(registry, controller, "protect")
            start_ms, end_ms = _hours_window(hours_back)
            return format_json(await backend.list_recordings(camera_id, start_ms, end_ms))
        except UniFiError as exc:
            logger.exception("list_recordings failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("set_camera_recording_mode", mutates=True)
    async def set_camera_recording_mode(
        camera_id: str,
        mode: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set a camera's recording mode (``always``, ``motion``, or ``never``).

        Side effects:
        - PATCHes ``recordingSettings.mode`` on the camera. Takes effect
          immediately; ``never`` halts new clip writes.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: set_camera_recording_mode(camera_id="65f...", mode="motion")

        Args:
            camera_id: Protect camera ``id``.
            mode: One of ``"always"``, ``"motion"``, ``"never"``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if mode not in RECORDING_MODES:
            return err(f"mode {mode!r} not in {sorted(RECORDING_MODES)}")
        patch = {"recordingSettings": {"mode": mode}}
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"camera_id": camera_id, "patch": patch},
                    "summary": f"Would set camera {camera_id} recording mode to {mode}",
                }
            )
        try:
            backend = resolve_backend(registry, controller, "protect")
            updated = await backend.update_camera(camera_id, patch)
            if updated is None:
                return err(f"camera {camera_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("set_camera_recording_mode failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("set_camera_privacy_mode", mutates=True)
    async def set_camera_privacy_mode(
        camera_id: str,
        enabled: bool,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Toggle a camera's privacy mask (lens cover) on or off.

        Side effects:
        - PATCHes ``privacyMask.enabled`` on the camera. When ``True``, the
          camera stops capturing video; clips are not recorded.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: set_camera_privacy_mode(camera_id="65f...", enabled=True)

        Args:
            camera_id: Protect camera ``id``.
            enabled: ``True`` to engage the privacy mask, ``False`` to release
                it.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        patch = {"privacyMask": {"enabled": enabled}}
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"camera_id": camera_id, "patch": patch},
                    "summary": (
                        f"Would {'enable' if enabled else 'disable'} privacy "
                        f"mask on camera {camera_id}"
                    ),
                }
            )
        try:
            backend = resolve_backend(registry, controller, "protect")
            updated = await backend.update_camera(camera_id, patch)
            if updated is None:
                return err(f"camera {camera_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("set_camera_privacy_mode failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("set_motion_sensitivity", mutates=True)
    async def set_motion_sensitivity(
        camera_id: str,
        sensitivity: int,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set a camera's motion sensitivity (0-100).

        Side effects:
        - PATCHes ``motionSettings.sensitivity``. Higher values trigger more
          motion events; 0 effectively disables motion-based recording even
          when ``recordingSettings.mode`` is ``"motion"``.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: set_motion_sensitivity(camera_id="65f...", sensitivity=60)

        Args:
            camera_id: Protect camera ``id``.
            sensitivity: Integer 0-100. Out-of-range values are rejected.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not 0 <= sensitivity <= 100:
            return err(f"sensitivity {sensitivity} out of range (0-100)")
        patch = {"motionSettings": {"sensitivity": sensitivity}}
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"camera_id": camera_id, "patch": patch},
                    "summary": (
                        f"Would set camera {camera_id} motion sensitivity to {sensitivity}"
                    ),
                }
            )
        try:
            backend = resolve_backend(registry, controller, "protect")
            updated = await backend.update_camera(camera_id, patch)
            if updated is None:
                return err(f"camera {camera_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("set_motion_sensitivity failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_doorbell_messages", mutates=False)
    async def list_doorbell_messages(controller: str = "default") -> str:
        """List doorbell cameras (those with ``isDoorbell=True``).

        Side effects: None (read-only).

        Returns the subset of cameras that are doorbells. Useful as a
        pre-step before configuring chime / message tools (future Phase 3.x
        work). Each entry includes the camera's ``id``, ``name``, and
        ``isConnected``.

        Example: list_doorbell_messages(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller, "protect")
            cameras = await backend.list_cameras()
            doorbells = [
                {
                    "id": c.get("id") or c.get("_id"),
                    "name": c.get("name"),
                    "isConnected": c.get("isConnected", False),
                }
                for c in cameras
                if c.get("isDoorbell")
            ]
            return format_json(doorbells)
        except UniFiError as exc:
            logger.exception("list_doorbell_messages failed")
            return err(str(exc))

    @mcp.tool(annotations=CREATE)
    @audited("provision_camera", mutates=True)
    async def provision_camera(
        camera_id: str,
        recording_mode: str | None = None,
        sensitivity: int | None = None,
        retention_days: int | None = None,
        privacy_enabled: bool | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Configure a camera end-to-end: recording mode + sensitivity + privacy.

        Only the settings you pass are changed. A setting you leave out keeps
        the camera's current value, so passing just ``sensitivity=60`` does
        not touch the recording mode, retention or privacy mask. At least one
        setting is required. ``dry_run=True`` reads the camera and returns the
        current ("before") and requested ("after") value of each setting it
        would change.

        Side effects:
        - Step 1 (when ``recording_mode`` or ``retention_days`` is given):
          PATCHes ``recordingSettings.mode`` and/or
          ``recordingSettings.retentionDurationMs`` (computed from
          ``retention_days`` * 86400000).
        - Step 2 (when ``sensitivity`` is given): PATCHes
          ``motionSettings.sensitivity``.
        - Step 3 (when ``privacy_enabled`` is given): PATCHes
          ``privacyMask.enabled``.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: a step fails when it raises an error or when the
          controller returns no camera record for it. The failing call stops
          the run, and the steps that already applied are restored from the
          pre-call snapshot (a step that returned no record is restored too,
          since it may have applied). The response then has an ``error``
          naming ``failed_step``, plus ``rolled_back`` and ``partial`` keys
          describing what was applied and what was reverted.

        Example: provision_camera(camera_id="65f...", recording_mode="motion", sensitivity=60, retention_days=14)

        Args:
            camera_id: Protect camera ``id``.
            recording_mode: One of ``"always"``, ``"motion"``, ``"never"``.
                Omit to leave the recording mode unchanged.
            sensitivity: Motion sensitivity 0-100. Omit to leave it unchanged.
            retention_days: Clip retention in days. Multiplied by 86,400,000
                to derive ``retentionDurationMs``. Omit to leave retention
                unchanged.
            privacy_enabled: ``True`` engages the privacy mask after the
                recording / sensitivity steps, ``False`` releases it. Omit to
                leave the privacy mask unchanged.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                before and after value of each setting.
        """
        if recording_mode is not None and recording_mode not in RECORDING_MODES:
            return err(f"recording_mode {recording_mode!r} not in {sorted(RECORDING_MODES)}")
        if sensitivity is not None and not 0 <= sensitivity <= 100:
            return err(f"sensitivity {sensitivity} out of range (0-100)")
        if retention_days is not None and retention_days < 0:
            return err(f"retention_days {retention_days} must be >= 0")
        if (
            recording_mode is None
            and sensitivity is None
            and retention_days is None
            and privacy_enabled is None
        ):
            return err(
                "provision_camera needs at least one of recording_mode, sensitivity, "
                "retention_days or privacy_enabled; settings you leave out are not changed"
            )

        # What the caller asked for, for the summaries.
        asked: list[str] = []
        if recording_mode is not None:
            asked.append(f"mode={recording_mode}")
        if sensitivity is not None:
            asked.append(f"sensitivity={sensitivity}")
        if retention_days is not None:
            asked.append(f"retention={retention_days}d")
        if privacy_enabled is not None:
            asked.append(f"privacy={privacy_enabled}")

        # One patch per step, built only from what the caller passed.
        recording_inner: dict[str, Any] = {}
        if recording_mode is not None:
            recording_inner["mode"] = recording_mode
        if retention_days is not None:
            recording_inner["retentionDurationMs"] = retention_days * 86_400 * 1000
        patches: dict[str, dict[str, Any]] = {}
        if recording_inner:
            patches["recording"] = {"recordingSettings": recording_inner}
        if sensitivity is not None:
            patches["sensitivity"] = {"motionSettings": {"sensitivity": sensitivity}}
        if privacy_enabled is not None:
            patches["privacy"] = {"privacyMask": {"enabled": privacy_enabled}}

        # Read the camera first, for the dry run's before values and for the
        # rollback snapshot. A read does not break the dry-run no-write rule.
        try:
            backend = resolve_backend(registry, controller, "protect")
            original = await backend.get_camera(camera_id)
            if original is None:
                return err(f"camera {camera_id} not found")
        except UniFiError as exc:
            logger.exception(
                "provision_camera: snapshot fetch failed", extra={"camera_id": camera_id}
            )
            return err(str(exc))

        if dry_run:
            changes: list[dict[str, Any]] = []
            for patch in patches.values():
                for section, inner in patch.items():
                    current = original.get(section)
                    for key, after in inner.items():
                        before = current.get(key) if isinstance(current, dict) else None
                        changes.append(
                            {
                                "setting": f"{section}.{key}",
                                "before": before,
                                "after": after,
                                "changed": before != after,
                            }
                        )
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"camera_id": camera_id, **patches},
                    "changes": changes,
                    "summary": f"Would provision camera {camera_id}: {', '.join(asked)}",
                    "note": (
                        "Composite preview. Settings not listed are left alone. "
                        "Real apply rolls back to the pre-call snapshot on "
                        "partial failure."
                    ),
                }
            )

        # Capture the original sub-settings so rollback restores byte-identical
        # nested state, not just "the keys we touched."
        originals: dict[str, dict[str, Any]] = {
            "recording": dict(original.get("recordingSettings") or {}),
            "sensitivity": dict(original.get("motionSettings") or {}),
            "privacy": dict(original.get("privacyMask") or {}),
        }
        restore_section = {
            "recording": "recordingSettings",
            "sensitivity": "motionSettings",
            "privacy": "privacyMask",
        }

        # ``applied`` holds each step's returned record (what the response
        # reports); ``landed`` is the steps the controller confirmed.
        applied: dict[str, Any] = {"recording": None, "sensitivity": None, "privacy": None}
        landed: list[str] = []

        async def _rollback(failed_step: str, unconfirmed: bool) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            # Restore in reverse order of application so the camera lands in
            # exactly the pre-call state regardless of which step blew up. A
            # step that raised is not restored (nothing is known to have
            # landed). A step that returned no record may have applied, so it
            # is restored too.
            for step in reversed(list(patches)):
                if step not in landed and not (unconfirmed and step == failed_step):
                    continue
                try:
                    restored = await backend.update_camera(
                        camera_id, {restore_section[step]: originals[step]}
                    )
                except UniFiError as restore_exc:
                    logger.error(
                        "provision_camera rollback failed",
                        extra={"step": step, "error": str(restore_exc)},
                    )
                    actions.append({step: f"restore_failed: {restore_exc}"})
                    continue
                if restored is None:
                    actions.append({step: "restore_unconfirmed: controller returned no record"})
                else:
                    actions.append({step: "restored"})
            logger.warning(
                "provision_camera rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, detail: str, *, unconfirmed: bool = False) -> str:
            rolled_back = await _rollback(step, unconfirmed)
            return format_json(
                {
                    "error": f"provision_camera failed at {step}: {detail}",
                    "failed_step": step,
                    "stub_mode": settings.stub_mode,
                    "partial": applied,
                    "rolled_back": rolled_back,
                }
            )

        for step, patch in patches.items():
            try:
                record = await backend.update_camera(camera_id, patch)
            except UniFiError as exc:
                return await _fail(step, str(exc))
            if record is None:
                # No record back means the camera was not found or the write
                # did nothing. Either way the step is not confirmed.
                return await _fail(
                    step,
                    "the controller returned no camera record "
                    "(camera not found, or the write did nothing)",
                    unconfirmed=True,
                )
            applied[step] = record
            landed.append(step)

        return format_json(
            {
                "summary": f"Provisioned camera {camera_id}: {', '.join(asked)}",
                **applied,
            }
        )


__all__ = ["register"]
