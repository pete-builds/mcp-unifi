"""Tests for the event tools: list_motion_events, list_smart_detections."""

from __future__ import annotations

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
    events = await _call(
        protect_registry, "list_motion_events", {"limit": 2, "hours_back": 24}
    )
    assert len(events) == 2


async def test_list_motion_events_narrow_window(protect_registry: FastMCP) -> None:
    """With a 1-second window, no seeded event should match."""
    # hours_back=0 means start==end (= now). No events should land in that span.
    events = await _call(protect_registry, "list_motion_events", {"hours_back": 0})
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
