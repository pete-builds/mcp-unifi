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

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.protect")

# Allowed values for the small enums tools accept. Keeping them as
# module-level constants makes the validation message stable and lets future
# Protect firmware add modes by editing one place.
RECORDING_MODES: frozenset[str] = frozenset({"always", "motion", "never"})
SMART_DETECT_TYPES: frozenset[str] = frozenset({"person", "vehicle", "animal", "package"})


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

    @mcp.tool()
    @audited("list_cameras")
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
            backend = registry.get_protect(controller)
            return format_json(await backend.list_cameras())
        except UniFiError as exc:
            logger.exception("list_cameras failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_camera")
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
            backend = registry.get_protect(controller)
            cam = await backend.get_camera(camera_id)
            if cam is None:
                return err(f"camera {camera_id} not found")
            return format_json(cam)
        except UniFiError as exc:
            logger.exception("get_camera failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool()
    @audited("list_motion_events")
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
            limit: Maximum number of events returned. Defaults to 50.
            hours_back: Look-back window in hours from now. Defaults to 24.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get_protect(controller)
            start_ms, end_ms = _hours_window(hours_back)
            events = await backend.list_events(["motion"], start_ms, end_ms, limit)
            events = _filter_by_camera(events, camera_id)
            return format_json(events)
        except UniFiError as exc:
            logger.exception("list_motion_events failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_smart_detections")
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
            limit: Maximum number of events returned. Defaults to 20.
            hours_back: Look-back window in hours. Defaults to 24.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if detection_type not in SMART_DETECT_TYPES:
            return err(f"detection_type {detection_type!r} not in {sorted(SMART_DETECT_TYPES)}")
        try:
            backend = registry.get_protect(controller)
            start_ms, end_ms = _hours_window(hours_back)
            raw = await backend.list_events(["smartDetectZone"], start_ms, end_ms, limit)
            filtered = [evt for evt in raw if detection_type in (evt.get("smartDetectTypes") or [])]
            filtered = _filter_by_camera(filtered, camera_id)
            return format_json(filtered)
        except UniFiError as exc:
            logger.exception("list_smart_detections failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_snapshot")
    async def get_snapshot(camera_id: str, controller: str = "default") -> str:
        """Fetch a current JPEG snapshot from a camera, base64-encoded.

        Side effects: None (read-only).

        Returns ``{"camera_id": ..., "format": "jpeg", "data": "<base64>",
        "size_bytes": ...}``. The JPEG payload is base64-encoded so it can
        ride inside the JSON envelope all MCP tools return; decode with
        ``base64.b64decode`` to get the raw image bytes.

        Example: get_snapshot(camera_id="65f...", controller="default")

        Args:
            camera_id: Protect camera ``id``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get_protect(controller)
            data = await backend.get_snapshot(camera_id)
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

    @mcp.tool()
    @audited("get_event_thumbnail")
    async def get_event_thumbnail(event_id: str, controller: str = "default") -> str:
        """Fetch the JPEG thumbnail for a Protect event, base64-encoded.

        Side effects: None (read-only).

        Same response shape as ``get_snapshot``, but keyed on the event
        instead of the camera. Useful for previewing a motion or
        smart-detection trigger without pulling the full clip.

        Example: get_event_thumbnail(event_id="evt123", controller="default")

        Args:
            event_id: Protect event ``id`` from ``list_motion_events`` or
                ``list_smart_detections``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get_protect(controller)
            data = await backend.get_event_thumbnail(event_id)
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

    @mcp.tool()
    @audited("list_recordings")
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
            hours_back: Look-back window in hours. Defaults to 24.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get_protect(controller)
            start_ms, end_ms = _hours_window(hours_back)
            return format_json(await backend.list_recordings(camera_id, start_ms, end_ms))
        except UniFiError as exc:
            logger.exception("list_recordings failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool()
    @audited("set_camera_recording_mode")
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
            backend = registry.get_protect(controller)
            updated = await backend.update_camera(camera_id, patch)
            if updated is None:
                return err(f"camera {camera_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("set_camera_recording_mode failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool()
    @audited("set_camera_privacy_mode")
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
            backend = registry.get_protect(controller)
            updated = await backend.update_camera(camera_id, patch)
            if updated is None:
                return err(f"camera {camera_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("set_camera_privacy_mode failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool()
    @audited("set_motion_sensitivity")
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
            backend = registry.get_protect(controller)
            updated = await backend.update_camera(camera_id, patch)
            if updated is None:
                return err(f"camera {camera_id} not found")
            return format_json(updated)
        except UniFiError as exc:
            logger.exception("set_motion_sensitivity failed", extra={"camera_id": camera_id})
            return err(str(exc))

    @mcp.tool()
    @audited("list_doorbell_messages")
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
            backend = registry.get_protect(controller)
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

    @mcp.tool()
    @audited("provision_camera")
    async def provision_camera(
        camera_id: str,
        recording_mode: str = "motion",
        sensitivity: int = 50,
        retention_days: int = 7,
        privacy_enabled: bool = False,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Configure a camera end-to-end: recording mode + sensitivity + privacy.

        Side effects:
        - Step 1: PATCHes ``recordingSettings.mode`` and
          ``recordingSettings.retentionDurationMs`` (computed from
          ``retention_days`` * 86400000).
        - Step 2: PATCHes ``motionSettings.sensitivity``.
        - Step 3: PATCHes ``privacyMask.enabled``.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if step 2 or step 3 fails, the camera's original
          recording, sensitivity, and privacy settings are restored from the
          pre-call snapshot. The response includes ``rolled_back`` and
          ``partial`` keys describing what was applied and what was
          reverted.

        Example: provision_camera(camera_id="65f...", recording_mode="motion", sensitivity=60, retention_days=14)

        Args:
            camera_id: Protect camera ``id``.
            recording_mode: One of ``"always"``, ``"motion"``, ``"never"``.
                Defaults to ``"motion"``.
            sensitivity: Motion sensitivity 0-100. Defaults to 50.
            retention_days: Clip retention in days. Multiplied by 86,400,000
                to derive ``retentionDurationMs``. Defaults to 7.
            privacy_enabled: ``True`` engages the privacy mask after the
                recording / sensitivity steps. Defaults to ``False``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if recording_mode not in RECORDING_MODES:
            return err(f"recording_mode {recording_mode!r} not in {sorted(RECORDING_MODES)}")
        if not 0 <= sensitivity <= 100:
            return err(f"sensitivity {sensitivity} out of range (0-100)")
        if retention_days < 0:
            return err(f"retention_days {retention_days} must be >= 0")

        retention_ms = retention_days * 86_400 * 1000
        recording_patch: dict[str, Any] = {
            "recordingSettings": {
                "mode": recording_mode,
                "retentionDurationMs": retention_ms,
            }
        }
        sensitivity_patch: dict[str, Any] = {"motionSettings": {"sensitivity": sensitivity}}
        privacy_patch: dict[str, Any] = {"privacyMask": {"enabled": privacy_enabled}}

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {
                        "camera_id": camera_id,
                        "recording": recording_patch,
                        "sensitivity": sensitivity_patch,
                        "privacy": privacy_patch,
                    },
                    "summary": (
                        f"Would provision camera {camera_id}: mode={recording_mode}, "
                        f"sensitivity={sensitivity}, retention={retention_days}d, "
                        f"privacy={privacy_enabled}"
                    ),
                    "note": (
                        "Composite preview. Real apply rolls back to the "
                        "pre-call snapshot on partial failure."
                    ),
                }
            )

        try:
            backend = registry.get_protect(controller)
            original = await backend.get_camera(camera_id)
            if original is None:
                return err(f"camera {camera_id} not found")
        except UniFiError as exc:
            logger.exception(
                "provision_camera: snapshot fetch failed", extra={"camera_id": camera_id}
            )
            return err(str(exc))

        # Capture the original sub-settings so rollback restores byte-identical
        # nested state, not just "the keys we touched." (Privacy isn't
        # captured here: step 3 (privacy) is the last step, so a failure there
        # leaves the privacy block untouched — there's nothing to restore.)
        original_recording: dict[str, Any] = dict(original.get("recordingSettings") or {})
        original_motion: dict[str, Any] = dict(original.get("motionSettings") or {})

        applied: dict[str, Any] = {
            "recording": None,
            "sensitivity": None,
            "privacy": None,
        }

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            # Restore in reverse order of application so the camera lands in
            # exactly the pre-call state regardless of which step blew up.
            if applied["sensitivity"] is not None:
                try:
                    await backend.update_camera(camera_id, {"motionSettings": original_motion})
                    actions.append({"sensitivity": "restored"})
                except UniFiError as restore_exc:
                    logger.error(
                        "provision_camera rollback (sensitivity) failed",
                        extra={"error": str(restore_exc)},
                    )
                    actions.append({"sensitivity": f"restore_failed: {restore_exc}"})
            if applied["recording"] is not None:
                try:
                    await backend.update_camera(
                        camera_id, {"recordingSettings": original_recording}
                    )
                    actions.append({"recording": "restored"})
                except UniFiError as restore_exc:
                    logger.error(
                        "provision_camera rollback (recording) failed",
                        extra={"error": str(restore_exc)},
                    )
                    actions.append({"recording": f"restore_failed: {restore_exc}"})
            logger.warning(
                "provision_camera rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return format_json(
                {
                    "error": f"provision_camera failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": applied,
                    "rolled_back": rolled_back,
                }
            )

        # Step 1: recording mode + retention.
        try:
            applied["recording"] = await backend.update_camera(camera_id, recording_patch)
        except UniFiError as exc:
            return await _fail("recording", exc)

        # Step 2: motion sensitivity.
        try:
            applied["sensitivity"] = await backend.update_camera(camera_id, sensitivity_patch)
        except UniFiError as exc:
            return await _fail("sensitivity", exc)

        # Step 3: privacy mask.
        try:
            applied["privacy"] = await backend.update_camera(camera_id, privacy_patch)
        except UniFiError as exc:
            return await _fail("privacy", exc)

        return format_json(
            {
                "summary": (
                    f"Provisioned camera {camera_id}: mode={recording_mode}, "
                    f"sensitivity={sensitivity}, retention={retention_days}d, "
                    f"privacy={privacy_enabled}"
                ),
                **applied,
            }
        )


__all__ = ["register"]
