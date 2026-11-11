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
        {"camera_id": "ghost-camera-id", "sensitivity": 50},
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

    result = await _call(
        protect_registry, "provision_camera", {"camera_id": cam_id, "sensitivity": 50}
    )
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


# ---------------------------------------------------------------------------
# Settings the caller did not pass are left alone
# ---------------------------------------------------------------------------


def _customise_camera(state: ProtectStubState) -> dict[str, Any]:
    """Give camera 0 non-default settings and return its pre-call snapshot."""
    cam = state.cameras[0]
    cam["recordingSettings"]["mode"] = "always"
    cam["recordingSettings"]["retentionDurationMs"] = 30 * 86_400 * 1000
    cam["motionSettings"]["sensitivity"] = 85
    cam["privacyMask"]["enabled"] = True
    return _camera_snapshot(state, cam["id"])


async def test_provision_camera_leaves_unpassed_settings_alone(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Passing one setting must not overwrite the others with defaults."""
    pre = _customise_camera(stub_protect_state)

    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": pre["id"], "recording_mode": "motion"},
    )

    assert "error" not in result
    cam = stub_protect_state.cameras[0]
    assert cam["recordingSettings"]["mode"] == "motion"
    # None of these were passed, so none may change.
    assert cam["recordingSettings"]["retentionDurationMs"] == 30 * 86_400 * 1000
    assert cam["motionSettings"]["sensitivity"] == 85
    assert cam["privacyMask"]["enabled"] is True
    assert result["sensitivity"] is None
    assert result["privacy"] is None


async def test_provision_camera_sensitivity_only_touches_only_sensitivity(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    pre = _customise_camera(stub_protect_state)
    calls: list[dict[str, Any]] = []
    real_update = stub_protect_state.update_camera

    def spy(camera_id: str, patch: dict[str, Any]) -> Any:
        calls.append(patch)
        return real_update(camera_id, patch)

    stub_protect_state.update_camera = spy  # type: ignore[method-assign]

    result = await _call(
        protect_registry, "provision_camera", {"camera_id": pre["id"], "sensitivity": 20}
    )

    assert "error" not in result
    assert calls == [{"motionSettings": {"sensitivity": 20}}]
    post = _camera_snapshot(stub_protect_state, pre["id"])
    assert post["motionSettings"]["sensitivity"] == 20
    post["motionSettings"]["sensitivity"] = 85
    assert post == pre


async def test_provision_camera_requires_at_least_one_setting(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    pre = _customise_camera(stub_protect_state)

    result = await _call(protect_registry, "provision_camera", {"camera_id": pre["id"]})

    assert "error" in result
    assert "at least one" in result["error"]
    assert stub_protect_state.cameras[0] == pre


async def test_provision_camera_dry_run_shows_before_and_after(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    pre = _customise_camera(stub_protect_state)

    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": pre["id"], "recording_mode": "motion", "sensitivity": 40, "dry_run": True},
    )

    assert result["dry_run"] is True
    by_setting = {c["setting"]: c for c in result["changes"]}
    assert set(by_setting) == {"recordingSettings.mode", "motionSettings.sensitivity"}
    assert by_setting["recordingSettings.mode"]["before"] == "always"
    assert by_setting["recordingSettings.mode"]["after"] == "motion"
    assert by_setting["motionSettings.sensitivity"]["before"] == 85
    assert by_setting["motionSettings.sensitivity"]["after"] == 40
    # Nothing was passed for retention or privacy, so they are not in the preview.
    assert "privacy" not in result["would_update"]
    assert stub_protect_state.cameras[0] == pre


async def test_provision_camera_dry_run_unknown_camera(protect_registry: FastMCP) -> None:
    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": "ghost-camera-id", "sensitivity": 40, "dry_run": True},
    )
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# A step that returns no record is a failed step
# ---------------------------------------------------------------------------


def _none_on_call(state: ProtectStubState, none_call: int, *, apply: bool) -> None:
    """Make the ``none_call``-th update_camera call (1-based) return ``None``.

    ``apply=True`` still applies the patch first, as a real controller does
    when it accepts a PATCH and replies with an empty body.
    """
    real_update = state.update_camera
    n = {"i": 0}

    def fake(camera_id: str, patch: dict[str, Any]) -> Any:
        n["i"] += 1
        if n["i"] == none_call:
            if apply:
                real_update(camera_id, patch)
            return None
        return real_update(camera_id, patch)

    state.update_camera = fake  # type: ignore[method-assign]


async def test_provision_camera_none_from_a_step_fails_and_rolls_back(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """Step 2 applies but replies with no record: stop, restore, name the step."""
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)
    _none_on_call(stub_protect_state, 2, apply=True)

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "never",
            "sensitivity": 90,
            "privacy_enabled": True,
        },
    )

    assert "error" in result
    assert result["failed_step"] == "sensitivity"
    assert "sensitivity" in result["error"]
    # Step 3 never ran, and both earlier steps were put back.
    assert result["partial"]["privacy"] is None
    restored = {k for entry in result["rolled_back"] for k in entry}
    assert restored == {"recording", "sensitivity"}
    assert _camera_snapshot(stub_protect_state, cam_id) == pre


async def test_provision_camera_none_from_the_last_step_is_restored(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """The privacy step may have applied even though no record came back."""
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)
    _none_on_call(stub_protect_state, 3, apply=True)

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "never",
            "sensitivity": 90,
            "privacy_enabled": True,
        },
    )

    assert result["failed_step"] == "privacy"
    assert {k for entry in result["rolled_back"] for k in entry} == {
        "privacy",
        "sensitivity",
        "recording",
    }
    assert _camera_snapshot(stub_protect_state, cam_id) == pre


async def test_provision_camera_none_from_the_first_step_stops_the_run(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    cam_id = stub_protect_state.cameras[0]["id"]
    pre = _camera_snapshot(stub_protect_state, cam_id)
    _none_on_call(stub_protect_state, 1, apply=False)
    seen: list[dict[str, Any]] = []
    inner = stub_protect_state.update_camera

    def spy(camera_id: str, patch: dict[str, Any]) -> Any:
        seen.append(patch)
        return inner(camera_id, patch)

    stub_protect_state.update_camera = spy  # type: ignore[method-assign]

    result = await _call(
        protect_registry,
        "provision_camera",
        {"camera_id": cam_id, "recording_mode": "never", "sensitivity": 90},
    )

    assert result["failed_step"] == "recording"
    # The sensitivity step must not have been attempted after the failure.
    assert not any("motionSettings" in patch for patch in seen)
    assert _camera_snapshot(stub_protect_state, cam_id) == pre


async def test_provision_camera_partial_reports_each_step_as_applied(
    protect_registry: FastMCP, stub_protect_state: ProtectStubState
) -> None:
    """``partial`` is a copy of what each step returned, not the live camera."""
    cam_id = stub_protect_state.cameras[0]["id"]
    real_update = stub_protect_state.update_camera
    n = {"i": 0}

    def fake(camera_id: str, patch: dict[str, Any]) -> Any:
        n["i"] += 1
        if n["i"] == 3:
            raise UniFiError("privacy boom")
        return real_update(camera_id, patch)

    stub_protect_state.update_camera = fake  # type: ignore[method-assign]

    result = await _call(
        protect_registry,
        "provision_camera",
        {
            "camera_id": cam_id,
            "recording_mode": "never",
            "sensitivity": 10,
            "privacy_enabled": True,
        },
    )

    # Step 1 set "never"; the later rollback restored "motion" on the stub, but
    # the record step 1 returned must still show what it applied.
    assert result["partial"]["recording"]["recordingSettings"]["mode"] == "never"
