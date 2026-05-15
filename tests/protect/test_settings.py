"""Tests for the camera-settings tools and doorbell listing."""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_unifi.clients.protect_stubs import ProtectStubState
from tests.protect.conftest import _call


async def test_set_camera_recording_mode_happy(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_camera_recording_mode",
        {"camera_id": cam_id, "mode": "always"},
    )
    assert "error" not in result
    assert result["recordingSettings"]["mode"] == "always"
    # Stub state really mutated.
    assert stub_protect_state.cameras[0]["recordingSettings"]["mode"] == "always"


async def test_set_camera_recording_mode_invalid(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_camera_recording_mode",
        {"camera_id": cam_id, "mode": "panic"},
    )
    assert "error" in result
    # Original state untouched.
    assert stub_protect_state.cameras[0]["recordingSettings"]["mode"] == "motion"


async def test_set_camera_recording_mode_not_found(
    protect_registry: FastMCP,
) -> None:
    result = await _call(
        protect_registry,
        "set_camera_recording_mode",
        {"camera_id": "ghost", "mode": "motion"},
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_set_camera_recording_mode_dry_run(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_camera_recording_mode",
        {"camera_id": cam_id, "mode": "always", "dry_run": True},
    )
    assert result["dry_run"] is True
    # State must NOT have changed.
    assert stub_protect_state.cameras[0]["recordingSettings"]["mode"] == "motion"


async def test_set_camera_privacy_mode_enables(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_camera_privacy_mode",
        {"camera_id": cam_id, "enabled": True},
    )
    assert "error" not in result
    assert result["privacyMask"]["enabled"] is True


async def test_set_camera_privacy_mode_dry_run(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_camera_privacy_mode",
        {"camera_id": cam_id, "enabled": True, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert stub_protect_state.cameras[0]["privacyMask"]["enabled"] is False


async def test_set_camera_privacy_mode_not_found(protect_registry: FastMCP) -> None:
    result = await _call(
        protect_registry,
        "set_camera_privacy_mode",
        {"camera_id": "ghost", "enabled": True},
    )
    assert "error" in result


async def test_set_motion_sensitivity_happy(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_motion_sensitivity",
        {"camera_id": cam_id, "sensitivity": 80},
    )
    assert "error" not in result
    assert result["motionSettings"]["sensitivity"] == 80


async def test_set_motion_sensitivity_out_of_range(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    for bad in (-1, 101, 200):
        result = await _call(
            protect_registry,
            "set_motion_sensitivity",
            {"camera_id": cam_id, "sensitivity": bad},
        )
        assert "error" in result
        assert "out of range" in result["error"]
    # State untouched.
    assert stub_protect_state.cameras[0]["motionSettings"]["sensitivity"] == 50


async def test_set_motion_sensitivity_dry_run(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "set_motion_sensitivity",
        {"camera_id": cam_id, "sensitivity": 99, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert stub_protect_state.cameras[0]["motionSettings"]["sensitivity"] == 50


async def test_set_motion_sensitivity_not_found(protect_registry: FastMCP) -> None:
    result = await _call(
        protect_registry,
        "set_motion_sensitivity",
        {"camera_id": "ghost", "sensitivity": 60},
    )
    assert "error" in result


async def test_list_doorbell_messages_returns_doorbells(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    rows = await _call(protect_registry, "list_doorbell_messages")
    assert isinstance(rows, list)
    assert len(rows) == 1
    assert rows[0]["name"] == "Front Door"
    assert rows[0]["id"] == stub_protect_state.cameras[0]["id"]
    assert rows[0]["isConnected"] is True
