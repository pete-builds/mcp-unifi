"""Realistic stub responses for the UniFi Protect API.

Used when ``stub_mode=True``. Payload shapes mirror what UniFi Protect returns
for the ``/proxy/protect/api`` endpoints exercised by the Protect MCP tools.

Each :class:`ProtectStubState` instance is fully independent so tests and
controllers in stub mode have isolated state (the dispatcher follows the
same per-controller-state pattern used by :class:`StubState`).
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from typing import Any

from mcp_unifi.models import UniFiRecord


def _oid() -> str:
    """24-character hex string in the shape of a Mongo ObjectId."""
    return uuid.uuid4().hex[:24]


def _ts_ms() -> int:
    """Current epoch milliseconds (Protect uses ms timestamps everywhere)."""
    return int(time.time() * 1000)


# A minimal valid 1x1 JPEG. Used by both the snapshot and event-thumbnail
# stubs so callers can exercise base64 encoding without us shipping a real
# image fixture.
_TINY_JPEG = bytes(
    [
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46,
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0xFF, 0xD9,
    ]
)


def _seed_cameras() -> list[UniFiRecord]:
    now = _ts_ms()
    cam1_id = _oid()
    cam2_id = _oid()
    return [
        {
            "_id": cam1_id,
            "id": cam1_id,
            "name": "Front Door",
            "type": "camera",
            "model": "UVC-G4-DoorBell",
            "mac": "f4:e2:c6:00:00:10",
            "host": "192.168.1.10",
            "state": "CONNECTED",
            "isConnected": True,
            "isDoorbell": True,
            "recordingSettings": {
                "mode": "motion",
                "prePaddingSecs": 4,
                "postPaddingSecs": 4,
                "retentionDurationMs": 604800000,
            },
            "privacyMask": {"enabled": False},
            "motionSettings": {"sensitivity": 50},
            "stats": {"rxBytes": 12345678, "txBytes": 987654},
            "lastMotion": now,
        },
        {
            "_id": cam2_id,
            "id": cam2_id,
            "name": "Backyard",
            "type": "camera",
            "model": "UVC-G4-Pro",
            "mac": "f4:e2:c6:00:00:11",
            "host": "192.168.1.11",
            "state": "CONNECTED",
            "isConnected": True,
            "isDoorbell": False,
            "recordingSettings": {
                "mode": "always",
                "prePaddingSecs": 4,
                "postPaddingSecs": 4,
                "retentionDurationMs": 604800000,
            },
            "privacyMask": {"enabled": False},
            "motionSettings": {"sensitivity": 75},
            "stats": {"rxBytes": 98765432, "txBytes": 1234567},
            "lastMotion": now - 300_000,
        },
    ]


def _seed_motion_events(cameras: list[UniFiRecord]) -> list[UniFiRecord]:
    """5 motion events spread across both cameras."""
    cam1 = cameras[0]
    cam2 = cameras[1]
    now = _ts_ms()
    layout = [
        (cam1, now - 60_000),
        (cam2, now - 120_000),
        (cam1, now - 240_000),
        (cam2, now - 480_000),
        (cam1, now - 1_800_000),
    ]
    events: list[UniFiRecord] = []
    for cam, start in layout:
        evt_id = _oid()
        events.append(
            {
                "_id": evt_id,
                "id": evt_id,
                "type": "motion",
                "camera": cam["id"],
                "cameraName": cam["name"],
                "start": start,
                "end": start + 8000,
                "score": 85,
                "thumbnail": _oid(),
                "heatmap": _oid(),
                "metadata": {},
            }
        )
    return events


def _seed_smart_events(cameras: list[UniFiRecord]) -> list[UniFiRecord]:
    """2 smart detections (person) across both cameras."""
    cam1 = cameras[0]
    cam2 = cameras[1]
    now = _ts_ms()
    out: list[UniFiRecord] = []
    for cam, start in [(cam1, now - 30_000), (cam2, now - 600_000)]:
        evt_id = _oid()
        out.append(
            {
                "_id": evt_id,
                "id": evt_id,
                "type": "smartDetectZone",
                "smartDetectTypes": ["person"],
                "camera": cam["id"],
                "cameraName": cam["name"],
                "start": start,
                "end": start + 5000,
                "score": 92,
                "thumbnail": _oid(),
                "metadata": {"detectedAt": start},
            }
        )
    return out


class ProtectStubState:
    """In-memory mock Protect state.

    A fresh instance always starts from seeded data: 2 cameras (one doorbell,
    one outdoor), 5 motion events, and 2 smart-detection events. Per-controller
    isolation matches the Network :class:`StubState` pattern.
    """

    def __init__(self) -> None:
        self.cameras: list[UniFiRecord] = _seed_cameras()
        self.events: list[UniFiRecord] = _seed_motion_events(self.cameras) + _seed_smart_events(
            self.cameras
        )
        # Failure-injection queue: maps method name to FIFO deque of exceptions
        # to raise on subsequent calls. Same shape as StubState._failure_queue.
        self._failure_queue: dict[str, deque[BaseException]] = defaultdict(deque)

    # ----- Failure injection ---------------------------------------------
    def fail_next(self, method_name: str, exception: BaseException) -> None:
        """Queue an exception to be raised on the next call to ``method_name``.

        Mirrors :meth:`StubState.fail_next` so the same composite-rollback test
        pattern applies to Protect composites (e.g. ``provision_camera``).
        """
        self._failure_queue[method_name].append(exception)

    def _check_failure(self, method_name: str) -> None:
        queue = self._failure_queue.get(method_name)
        if queue:
            raise queue.popleft()

    # ----- Cameras --------------------------------------------------------
    def list_cameras(self) -> list[UniFiRecord]:
        return self.cameras

    def get_camera(self, camera_id: str) -> UniFiRecord | None:
        for cam in self.cameras:
            if cam.get("id") == camera_id or cam.get("_id") == camera_id:
                return cam
        return None

    def update_camera(self, camera_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        self._check_failure("update_camera")
        for cam in self.cameras:
            if cam.get("id") == camera_id or cam.get("_id") == camera_id:
                _deep_merge(cam, patch)
                return cam
        return None

    # ----- Events ---------------------------------------------------------
    def list_events(
        self, types: list[str], start_ms: int, end_ms: int, limit: int
    ) -> list[UniFiRecord]:
        type_set = set(types) if types else None
        out: list[UniFiRecord] = []
        for evt in self.events:
            if type_set is not None and evt.get("type") not in type_set:
                continue
            start = evt.get("start", 0)
            if start < start_ms or start > end_ms:
                continue
            out.append(evt)
        # Most-recent first, then cap to limit.
        out.sort(key=lambda e: e.get("start", 0), reverse=True)
        return out[:limit]

    # ----- Snapshots / thumbnails ----------------------------------------
    def get_snapshot(self, camera_id: str) -> bytes:
        # Camera lookup is performed by the caller (the backend / tool) so the
        # stub matches the wire-level Protect API which always returns bytes.
        del camera_id
        return _TINY_JPEG

    def get_event_thumbnail(self, event_id: str) -> bytes:
        del event_id
        return _TINY_JPEG

    # ----- Recordings -----------------------------------------------------
    def list_recordings(
        self, camera_id: str, start_ms: int, end_ms: int
    ) -> list[UniFiRecord]:
        """Three deterministic recordings inside the requested window."""
        if end_ms <= start_ms:
            return []
        span = end_ms - start_ms
        step = max(span // 4, 1)
        recordings: list[UniFiRecord] = []
        for i in range(3):
            seg_start = start_ms + step * (i + 1) - (step // 2)
            rec_id = _oid()
            recordings.append(
                {
                    "_id": rec_id,
                    "id": rec_id,
                    "camera": camera_id,
                    "start": seg_start,
                    "end": seg_start + min(step, 60_000),
                    "type": "rotating",
                    "size": 1024 * 1024 * (5 + i),
                }
            )
        return recordings


def _deep_merge(dest: dict[str, Any], patch: dict[str, Any]) -> None:
    """Recursively merge ``patch`` into ``dest`` so nested settings update in place.

    Protect uses nested objects for settings (``recordingSettings.mode``,
    ``motionSettings.sensitivity``, ``privacyMask.enabled``). A shallow update
    would clobber peer keys; we recurse into dicts only.
    """
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(dest.get(key), dict):
            _deep_merge(dest[key], value)
        else:
            dest[key] = value


def make_protect_stub_state() -> ProtectStubState:
    """Return a fresh seeded :class:`ProtectStubState`.

    Mirrors :func:`make_stub_state` from the Network stubs: one entrypoint so
    future seeding hooks have a single place to plug in.
    """
    return ProtectStubState()


__all__ = ["ProtectStubState", "make_protect_stub_state"]
