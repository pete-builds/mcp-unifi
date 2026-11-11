"""Tests for the camera-read tools: list_cameras, get_camera, snapshots, recordings."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.protect_stubs import ProtectStubState
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules.protect import MAX_IMAGE_BYTES
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


# ---------------------------------------------------------------------------
# Image bodies are checked before they are base64-encoded into a response
# ---------------------------------------------------------------------------


async def test_get_snapshot_rejects_a_body_that_is_not_a_jpeg(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    stub_protect_state.get_snapshot = lambda _cid: b"<html>login</html>"  # type: ignore[method-assign]

    result = await _call(protect_registry, "get_snapshot", {"camera_id": cam_id})

    assert "error" in result
    assert "JPEG" in result["error"]
    assert "data" not in result


async def test_get_snapshot_rejects_an_empty_body(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    stub_protect_state.get_snapshot = lambda _cid: b""  # type: ignore[method-assign]

    result = await _call(protect_registry, "get_snapshot", {"camera_id": cam_id})

    assert "JPEG" in result["error"]


async def test_get_snapshot_rejects_an_oversized_jpeg(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    big = b"\xff\xd8\xff" + bytes(MAX_IMAGE_BYTES)
    stub_protect_state.get_snapshot = lambda _cid: big  # type: ignore[method-assign]

    result = await _call(protect_registry, "get_snapshot", {"camera_id": cam_id})

    assert "error" in result
    assert "byte limit" in result["error"]
    assert "data" not in result


async def test_get_snapshot_accepts_a_jpeg_at_the_limit(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    exact = b"\xff\xd8\xff" + bytes(MAX_IMAGE_BYTES - 3)
    stub_protect_state.get_snapshot = lambda _cid: exact  # type: ignore[method-assign]

    result = await _call(protect_registry, "get_snapshot", {"camera_id": cam_id})

    assert result["size_bytes"] == MAX_IMAGE_BYTES


async def test_get_event_thumbnail_rejects_a_body_that_is_not_a_jpeg(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    evt_id = stub_protect_state.events[0]["id"]
    stub_protect_state.get_event_thumbnail = lambda _eid: b'{"error": "nope"}'  # type: ignore[method-assign]

    result = await _call(protect_registry, "get_event_thumbnail", {"event_id": evt_id})

    assert "error" in result
    assert "JPEG" in result["error"]


# ---------------------------------------------------------------------------
# The stub answers unknown and malformed ids the way a console would
# ---------------------------------------------------------------------------


async def test_unknown_ids_are_not_found_not_success(protect_registry: FastMCP) -> None:
    for tool, args in (
        ("get_snapshot", {"camera_id": "does-not-exist"}),
        ("get_event_thumbnail", {"event_id": "does-not-exist"}),
        ("list_recordings", {"camera_id": "does-not-exist"}),
        ("get_camera", {"camera_id": "does-not-exist"}),
        ("set_motion_sensitivity", {"camera_id": "does-not-exist", "sensitivity": 5}),
    ):
        result = await _call(protect_registry, tool, args)
        assert isinstance(result, dict) and "error" in result, (tool, args)


async def test_malformed_ids_are_rejected_by_the_stub(protect_registry: FastMCP) -> None:
    traversal = "../../../network/api/s/default/rest/wlanconf"
    for tool, args in (
        ("get_snapshot", {"camera_id": traversal}),
        ("get_camera", {"camera_id": traversal}),
        ("get_camera", {"camera_id": ""}),
        ("get_event_thumbnail", {"event_id": "a/b"}),
        ("list_recordings", {"camera_id": "a&b=1"}),
        ("set_camera_privacy_mode", {"camera_id": "a/b", "enabled": True}),
    ):
        result = await _call(protect_registry, tool, args)
        assert isinstance(result, dict) and "error" in result, (tool, args)


async def test_stub_reads_return_copies(stub_protect_state: ProtectStubState) -> None:
    """Editing a returned record must not edit the stub's camera."""
    cam_id = stub_protect_state.cameras[0]["id"]

    listed = stub_protect_state.list_cameras()
    listed[0]["name"] = "mutated"
    fetched = stub_protect_state.get_camera(cam_id)
    assert fetched is not None
    fetched["recordingSettings"]["mode"] = "mutated"
    updated = stub_protect_state.update_camera(cam_id, {"motionSettings": {"sensitivity": 7}})
    assert updated is not None
    updated["motionSettings"]["sensitivity"] = 99
    stub_protect_state.list_events(["motion"], 0, 2**62, 10)[0]["type"] = "mutated"

    cam = stub_protect_state.cameras[0]
    assert cam["name"] == "Front Door"
    assert cam["recordingSettings"]["mode"] == "motion"
    assert cam["motionSettings"]["sensitivity"] == 7
    assert all(e["type"] != "mutated" for e in stub_protect_state.events)


async def test_stub_update_does_not_share_the_callers_patch(
    stub_protect_state: ProtectStubState,
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    patch = {"newBlock": {"a": 1}}
    stub_protect_state.update_camera(cam_id, patch)
    patch["newBlock"]["a"] = 2
    assert stub_protect_state.cameras[0]["newBlock"] == {"a": 1}


async def test_every_protect_stub_method_honours_fail_next(
    stub_protect_state: ProtectStubState,
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    evt_id = stub_protect_state.events[0]["id"]
    calls: dict[str, Any] = {
        "list_cameras": lambda: stub_protect_state.list_cameras(),
        "get_camera": lambda: stub_protect_state.get_camera(cam_id),
        "update_camera": lambda: stub_protect_state.update_camera(cam_id, {}),
        "list_events": lambda: stub_protect_state.list_events([], 0, 1, 1),
        "get_snapshot": lambda: stub_protect_state.get_snapshot(cam_id),
        "get_event_thumbnail": lambda: stub_protect_state.get_event_thumbnail(evt_id),
        "list_recordings": lambda: stub_protect_state.list_recordings(cam_id, 0, 10),
    }
    for name, call in calls.items():
        stub_protect_state.fail_next(name, UniFiError(f"{name} injected"))
        with pytest.raises(UniFiError, match=f"{name} injected"):
            call()
        call()  # the queue held one failure; the next call succeeds
