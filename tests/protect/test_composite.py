"""Tests for the ``provision_camera`` composite, including rollback paths."""

from __future__ import annotations

import copy
from typing import Any

from fastmcp import FastMCP

from mcp_unifi.clients.protect_stubs import ProtectStubState
from mcp_unifi.clients.unifi import UniFiError
from tests.protect.conftest import _call


def _camera_snapshot(state: ProtectStubState, cam_id: str) -> dict[str, Any]:
    """Deep copy of the camera record so we can assert byte-equality after rollback."""
    cam = next(c for c in state.cameras if c.get("id") == cam_id or c.get("_id") == cam_id)
    return copy.deepcopy(cam)


async def test_provision_camera_happy_path(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 75,
            "retention_days": 14,
            "privacy_enabled": False,
        },
    )

    assert "error" not in result
    cam = stub_protect_state.cameras[0]
    assert cam["recordingSettings"]["mode"] == "always"
    assert cam["recordingSettings"]["retentionDurationMs"] == 14 * 86400 * 1000
    assert cam["motionSettings"]["sensitivity"] == 75
    assert cam["privacyMask"]["enabled"] is False
    assert "Provisioned camera" in result["summary"]


async def test_provision_camera_validates_mode(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": cam_id, "recording_mode": "bogus"},
    )
    assert "error" in result
    # Nothing touched.
    assert stub_protect_state.cameras[0] == pre


async def test_provision_camera_validates_sensitivity(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": cam_id, "sensitivity": 150},
    )
    assert "error" in result
    assert stub_protect_state.cameras[0] == pre


async def test_provision_camera_validates_retention(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": cam_id, "retention_days": -3},
    )
    assert "error" in result
    assert stub_protect_state.cameras[0] == pre


async def test_provision_camera_not_found(protect_registry: FastMCP) -> None:
    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": "ghost-camera-id"},
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_provision_camera_dry_run(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 75,
            "retention_days": 30,
            "privacy_enabled": True,
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    assert result["would_update"]["camera_id"] == cam_id
    # State must be exactly the pre snapshot.
    assert stub_protect_state.cameras[0] == pre


async def test_provision_camera_rolls_back_on_sensitivity_failure(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Inject failure at step 2: recording must be restored, sensitivity untouched."""
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    # Step 1 (recording mode/retention) succeeds.
    # Step 2 (sensitivity update) fails.
    # The stub's update_camera consumes ONE queued failure per call. The composite
    # calls update_camera multiple times — once per step plus once for rollback.
    # We queue exactly one failure to land on the second call (step 2).
    failures: list[BaseException | None] = [None, UniFiError("simulated sensitivity failure")]

    real_update = stub_protect_state.update_camera
    call_count = {"n": 0}

    def fake_update(camera_id: str, patch: dict[str, Any]) -> Any:
        i = call_count["n"]
        call_count["n"] += 1
        if i < len(failures) and failures[i] is not None:
            raise failures[i]  # type: ignore[misc]
        return real_update(camera_id, patch)

    stub_protect_state.update_camera = fake_update  # type: ignore[method-assign]

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 95,
            "retention_days": 30,
        },
    )

    assert "error" in result
    assert "sensitivity" in result["error"]
    assert result["partial"]["sensitivity"] is None  # step 2 never landed
    assert result["partial"]["recording"] is not None
    # State must be byte-identical to pre.
    post = _camera_snapshot(stub_protect_state, cam_id)
    assert post == pre, f"rollback failed; pre={pre} post={post}"


async def test_provision_camera_rolls_back_on_privacy_failure(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Inject failure at step 3: recording + sensitivity must both be restored."""
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    # Calls: step1 ok, step2 ok, step3 fails. Rollback then calls update_camera
    # twice more (restore sensitivity, restore recording) — those must succeed.
    failures: list[BaseException | None] = [
        None,
        None,
        UniFiError("simulated privacy failure"),
    ]
    real_update = stub_protect_state.update_camera
    call_count = {"n": 0}

    def fake_update(camera_id: str, patch: dict[str, Any]) -> Any:
        i = call_count["n"]
        call_count["n"] += 1
        if i < len(failures) and failures[i] is not None:
            raise failures[i]  # type: ignore[misc]
        return real_update(camera_id, patch)

    stub_protect_state.update_camera = fake_update  # type: ignore[method-assign]

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 95,
            "retention_days": 30,
            "privacy_enabled": True,
        },
    )

    assert "error" in result
    assert "privacy" in result["error"]
    # State must be byte-identical to pre.
    post = _camera_snapshot(stub_protect_state, cam_id)
    assert post == pre, f"rollback failed; pre={pre} post={post}"


async def test_provision_camera_rolls_back_on_recording_failure(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Inject failure at step 1: nothing to roll back, state unchanged."""
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)

    stub_protect_state.fail_next("update_camera", UniFiError("simulated recording failure"))

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 95,
            "retention_days": 30,
        },
    )

    assert "error" in result
    assert "recording" in result["error"]
    assert result["partial"]["recording"] is None
    # State byte-identical to pre.
    post = _camera_snapshot(stub_protect_state, cam_id)
    assert post == pre, f"rollback failed; pre={pre} post={post}"


async def test_provision_camera_snapshot_fetch_failure(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """A UniFiError on the initial get_camera surfaces cleanly."""
    cam_id = stub_protect_state.cameras[0]["id"]

    def boom(_camera_id: str) -> Any:
        raise UniFiError("simulated snapshot fetch failure")

    stub_protect_state.get_camera = boom  # type: ignore[method-assign]

    result = await _call(protect_registry, "provision_camera", {"camera_id": cam_id})
    assert "error" in result
    assert "snapshot fetch" in result["error"]


async def test_provision_camera_rollback_recording_restore_fails(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Step-3 fails AND the rollback's recording-restore also fails.

    The composite should still return an error envelope (not raise) and the
    ``rolled_back`` log should record the restore failure so an operator can
    see the camera was left mid-state.
    """
    cam_id = stub_protect_state.cameras[0]["id"]

    real_update = stub_protect_state.update_camera
    # Calls: step1 ok, step2 ok, step3 fails, rollback-sensitivity ok,
    # rollback-recording fails.
    seq: list[BaseException | None] = [
        None,
        None,
        UniFiError("step3-fail"),
        None,
        UniFiError("rollback-recording-fail"),
    ]
    n = {"i": 0}

    def fake_update(camera_id: str, patch: dict[str, Any]) -> Any:
        i = n["i"]
        n["i"] += 1
        if i < len(seq) and seq[i] is not None:
            raise seq[i]  # type: ignore[misc]
        return real_update(camera_id, patch)

    stub_protect_state.update_camera = fake_update  # type: ignore[method-assign]

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 95,
            "retention_days": 30,
            "privacy_enabled": True,
        },
    )

    assert "error" in result
    assert "privacy" in result["error"]
    # The rollback log surfaces the restore failure.
    rolled = result["rolled_back"]
    assert any("restore_failed" in str(entry) for entry in rolled)


async def test_provision_camera_rollback_sensitivity_restore_fails(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Step-3 fails AND the sensitivity-restore step also fails.

    The composite must still report failure and continue to attempt the
    recording-restore (we don't bail out of rollback on the first failure).
    """
    cam_id = stub_protect_state.cameras[0]["id"]

    real_update = stub_protect_state.update_camera
    # Calls: step1 ok, step2 ok, step3 fails, rollback-sensitivity fails,
    # rollback-recording ok.
    seq: list[BaseException | None] = [
        None,
        None,
        UniFiError("step3-fail"),
        UniFiError("rollback-sensitivity-fail"),
        None,
    ]
    n = {"i": 0}

    def fake_update(camera_id: str, patch: dict[str, Any]) -> Any:
        i = n["i"]
        n["i"] += 1
        if i < len(seq) and seq[i] is not None:
            raise seq[i]  # type: ignore[misc]
        return real_update(camera_id, patch)

    stub_protect_state.update_camera = fake_update  # type: ignore[method-assign]

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "always",
            "sensitivity": 95,
            "retention_days": 30,
            "privacy_enabled": True,
        },
    )

    assert "error" in result
    rolled = result["rolled_back"]
    # Sensitivity restore reported as failed; recording restore reported as restored.
    assert any(
        isinstance(entry, dict) and "restore_failed" in str(entry.get("sensitivity", ""))
        for entry in rolled
    )
