"""Tests for the camera-read tools: list_cameras, get_camera, snapshots, recordings."""

from __future__ import annotations

import base64

from fastmcp import FastMCP

from mcp_unifi.clients.protect_stubs import ProtectStubState
from tests.protect.conftest import _call


async def test_list_cameras_seed_shape(protect_registry: FastMCP) -> None:
    cams = await _call(protect_registry, "list_cameras")
    assert isinstance(cams, list)
    assert len(cams) == 2
    names = {c["name"] for c in cams}
    assert names == {"Front Door", "Backyard"}


async def test_list_cameras_includes_settings(protect_registry: FastMCP) -> None:
    cams = await _call(protect_registry, "list_cameras")
    front = next(c for c in cams if c["name"] == "Front Door")
    assert front["recordingSettings"]["mode"] == "motion"
    assert front["motionSettings"]["sensitivity"] == 50
    assert front["privacyMask"]["enabled"] is False
    assert front["isDoorbell"] is True


async def test_get_camera_by_id(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    cam = await _call(protect_registry, "get_camera", {"camera_id": cam_id})
    assert cam["id"] == cam_id
    assert cam["name"] == "Front Door"


async def test_get_camera_not_found(protect_registry: FastMCP) -> None:
    result = await _call(protect_registry, "get_camera", {"camera_id": "doesnotexist"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_get_snapshot_returns_base64_jpeg(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(protect_registry, "get_snapshot", {"camera_id": cam_id})
    assert result["camera_id"] == cam_id
    assert result["format"] == "jpeg"
    assert result["size_bytes"] > 0
    decoded = base64.b64decode(result["data"])
    assert decoded[:2] == b"\xff\xd8"  # JPEG SOI marker
    assert decoded[-2:] == b"\xff\xd9"  # JPEG EOI marker
    assert len(decoded) == result["size_bytes"]


async def test_get_event_thumbnail_returns_base64_jpeg(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    evt_id = stub_protect_state.events[0]["id"]
    result = await _call(protect_registry, "get_event_thumbnail", {"event_id": evt_id})
    assert result["event_id"] == evt_id
    assert result["format"] == "jpeg"
    decoded = base64.b64decode(result["data"])
    assert decoded[:2] == b"\xff\xd8"


async def test_list_recordings_returns_three(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    rows = await _call(
        protect_registry,
        "list_recordings",
        {"camera_id": cam_id, "hours_back": 24},
    )
    assert isinstance(rows, list)
    assert len(rows) == 3
    for r in rows:
        assert r["camera"] == cam_id
        assert "start" in r and "end" in r
        assert r["end"] >= r["start"]


async def test_list_recordings_default_window(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Default ``hours_back=24`` should still return rows (24h is non-empty span)."""
    cam_id = stub_protect_state.cameras[0]["id"]
    rows = await _call(protect_registry, "list_recordings", {"camera_id": cam_id})
    assert len(rows) == 3
