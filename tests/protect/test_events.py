"""Tests for the event tools: list_motion_events, list_smart_detections."""

from __future__ import annotations

import time
from typing import Any

from fastmcp import FastMCP

from mcp_unifi.clients.protect_stubs import ProtectStubState
from tests.protect.conftest import _call


async def test_list_motion_events_all_cameras(protect_registry: FastMCP) -> None:
    events = await _call(protect_registry, "list_motion_events")
    assert isinstance(events, list)
    # Seed has 5 motion events, all within the last 24h window.
    assert len(events) == 5
    for evt in events:
        assert evt["type"] == "motion"
        assert "start" in evt and "end" in evt


async def test_list_motion_events_camera_filter(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam1_id = stub_protect_state.cameras[0]["id"]
    events = await _call(
        protect_registry,
        "list_motion_events",
        {"camera_id": cam1_id, "limit": 50},
    )
    # Seed: 3 motion events on cam1 (indexes 0, 2, 4 in the layout).
    assert len(events) == 3
    for evt in events:
        assert evt["camera"] == cam1_id


async def test_list_motion_events_respects_limit(protect_registry: FastMCP) -> None:
    events = await _call(protect_registry, "list_motion_events", {"limit": 2, "hours_back": 24})
    assert len(events) == 2


async def test_list_motion_events_narrow_window(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Events older than the window are not returned."""
    for evt in stub_protect_state.events:
        evt["start"] -= 2 * 3600 * 1000
    events = await _call(protect_registry, "list_motion_events", {"hours_back": 1})
    assert events == []


async def test_list_smart_detections_person(protect_registry: FastMCP) -> None:
    events = await _call(
        protect_registry,
        "list_smart_detections",
        {"detection_type": "person"},
    )
    assert isinstance(events, list)
    assert len(events) == 2
    for evt in events:
        assert evt["type"] == "smartDetectZone"
        assert "person" in evt["smartDetectTypes"]


async def test_list_smart_detections_vehicle_empty(
    protect_registry: FastMCP,
) -> None:
    """Seed only contains person detections, so vehicle should return [] (not error)."""
    events = await _call(
        protect_registry,
        "list_smart_detections",
        {"detection_type": "vehicle"},
    )
    assert events == []


async def test_list_smart_detections_invalid_type(protect_registry: FastMCP) -> None:
    result = await _call(
        protect_registry,
        "list_smart_detections",
        {"detection_type": "bigfoot"},
    )
    assert "error" in result
    assert "detection_type" in result["error"]


async def test_list_smart_detections_camera_filter(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam1_id = stub_protect_state.cameras[0]["id"]
    events = await _call(
        protect_registry,
        "list_smart_detections",
        {"detection_type": "person", "camera_id": cam1_id},
    )
    assert len(events) == 1
    assert events[0]["camera"] == cam1_id


# ---------------------------------------------------------------------------
# The controller's limit is applied before our camera and type filters, so the
# filters have to run on a wide page and the limit has to come last.
# ---------------------------------------------------------------------------


def _newer_events(
    state: ProtectStubState, camera_id: str, count: int, **extra: Any
) -> list[dict[str, Any]]:
    """Add ``count`` events on ``camera_id`` newer than every seeded event."""
    now = int(time.time() * 1000)
    added = [
        {"id": f"{extra.get('type', 'motion')}-{i}", "camera": camera_id, "start": now - i, **extra}
        for i in range(count)
    ]
    state.events.extend(added)
    return added


async def test_motion_camera_filter_is_applied_before_limit(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam1, cam2 = (c["id"] for c in stub_protect_state.cameras)
    _newer_events(stub_protect_state, cam1, 20, type="motion")

    events = await _call(protect_registry, "list_motion_events", {"camera_id": cam2, "limit": 20})

    # Seed has 2 motion events on cam2. Twenty newer cam1 events fill the
    # controller's first 20 rows, which used to leave nothing for cam2.
    assert len(events) == 2
    assert all(e["camera"] == cam2 for e in events)


async def test_motion_limit_is_applied_after_filter_and_keeps_newest(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam1, _ = (c["id"] for c in stub_protect_state.cameras)
    _newer_events(stub_protect_state, cam1, 10, type="motion")

    events = await _call(protect_registry, "list_motion_events", {"camera_id": cam1, "limit": 4})

    assert len(events) == 4
    starts = [e["start"] for e in events]
    assert starts == sorted(starts, reverse=True)
    assert all(e["id"].startswith("motion-") for e in events)


async def test_smart_detection_type_filter_is_applied_before_limit(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam1, _ = (c["id"] for c in stub_protect_state.cameras)
    _newer_events(stub_protect_state, cam1, 20, type="smartDetectZone", smartDetectTypes=["person"])
    stub_protect_state.events.append(
        {
            "id": "veh",
            "type": "smartDetectZone",
            "smartDetectTypes": ["vehicle"],
            "camera": cam1,
            "start": int(time.time() * 1000) - 10_000,
        }
    )

    events = await _call(
        protect_registry, "list_smart_detections", {"detection_type": "vehicle", "limit": 5}
    )

    assert [e["id"] for e in events] == ["veh"]


async def test_events_are_sorted_newest_first_whatever_the_controller_returns(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    real = stub_protect_state.list_events

    def oldest_first(types: list[str], start_ms: int, end_ms: int, limit: int) -> Any:
        return list(reversed(real(types, start_ms, end_ms, limit)))

    stub_protect_state.list_events = oldest_first  # type: ignore[method-assign]

    events = await _call(protect_registry, "list_motion_events", {"limit": 3})

    assert len(events) == 3
    starts = [e["start"] for e in events]
    assert starts == sorted(starts, reverse=True)
    # The three newest of the five seeded, not the three the controller listed first.
    newest = sorted(
        (e["start"] for e in stub_protect_state.events if e["type"] == "motion"), reverse=True
    )[:3]
    assert starts == newest


async def test_event_tools_reject_out_of_range_limit_and_window(
    protect_registry: FastMCP,
) -> None:
    for tool, args in (
        ("list_motion_events", {"limit": -1}),
        ("list_motion_events", {"limit": 0}),
        ("list_motion_events", {"limit": 1001}),
        ("list_motion_events", {"hours_back": 0}),
        ("list_motion_events", {"hours_back": -5}),
        ("list_motion_events", {"hours_back": 721}),
        ("list_smart_detections", {"limit": 1001}),
        ("list_smart_detections", {"hours_back": 100_000}),
        ("list_recordings", {"camera_id": "abc", "hours_back": 0}),
        ("list_recordings", {"camera_id": "abc", "hours_back": 721}),
    ):
        result = await _call(protect_registry, tool, args)
        assert isinstance(result, dict) and "error" in result, (tool, args)
        assert "between 1 and" in result["error"]


async def test_event_tools_accept_the_documented_maximums(protect_registry: FastMCP) -> None:
    events = await _call(protect_registry, "list_motion_events", {"limit": 1000, "hours_back": 720})
    assert isinstance(events, list)
