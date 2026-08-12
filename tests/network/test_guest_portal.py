"""Tests for ``mcp_unifi.modules.network.guest_portal``.

``set_guest_portal`` is the one preview-then-confirm tool that performs a
**full-object read-modify-write**. Every other confirmable action carries just
an id, so the gap between preview and confirm costs nothing. Here it is the
whole record, which makes the five-minute token window a place where another
admin's edits can be silently reverted.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.modules.network import guest_portal
from tests.network.conftest import _call

SETTING_KEY = "guest_access"


async def test_get_guest_portal_projects_the_operational_fields(
    stub_server: FastMCP,
) -> None:
    result = await _call(stub_server, "get_guest_portal")
    assert "portal_enabled" in result
    assert "auth" in result


async def test_set_guest_portal_applies_on_confirm(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    preview = await _call(stub_server, "set_guest_portal", {"portal_enabled": False})
    assert preview["preview"] is True

    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["applied"] == {"portal_enabled": False}
    assert stub_state.get_setting(SETTING_KEY)["portal_enabled"] is False


async def test_confirm_does_not_revert_a_concurrent_edit(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """REGRESSION: the confirm step wrote a five-minute-old snapshot.

    ``desired`` was built from the record as it read when the *preview* was
    generated, then written back in full on confirm. Anything another admin
    (or the controller) changed in between was overwritten with the stale
    value and reported as an unrelated success.

    Deleting a guest-access field is unrecoverable without a backup, which is
    precisely why this tool writes the full object rather than a minimal body
    — so the window has to be closed at the other end, by re-reading.
    """
    stub_state.set_setting(SETTING_KEY, {"redirect_url": "https://original.example"})

    preview = await _call(stub_server, "set_guest_portal", {"portal_enabled": False})

    # Someone else edits an unrelated field while the token is outstanding.
    stub_state.set_setting(SETTING_KEY, {"redirect_url": "https://changed-by-someone-else"})

    await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})

    stored = stub_state.get_setting(SETTING_KEY)
    assert stored["redirect_url"] == "https://changed-by-someone-else"
    assert stored["portal_enabled"] is False


async def test_confirm_diffs_against_the_fresh_pre_write_state(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """The returned diff must describe the write that happened, not a stale one.

    A diff computed against the preview-time snapshot would attribute another
    admin's edit to this write.
    """
    stub_state.set_setting(SETTING_KEY, {"redirect_url": "https://original.example"})
    preview = await _call(stub_server, "set_guest_portal", {"portal_enabled": False})
    stub_state.set_setting(SETTING_KEY, {"redirect_url": "https://changed-by-someone-else"})

    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})

    changed = result["diff"]["changed"]
    assert "portal_enabled" in changed
    assert "redirect_url" not in changed


async def test_dry_run_does_not_mint_a_token_or_write(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = stub_state.get_setting(SETTING_KEY)["portal_enabled"]
    result = await _call(
        stub_server, "set_guest_portal", {"portal_enabled": False, "dry_run": True}
    )
    assert result["dry_run"] is True
    assert "token" not in result
    assert stub_state.get_setting(SETTING_KEY)["portal_enabled"] == before


async def test_rejects_an_unknown_auth_mode(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_guest_portal", {"auth": "telepathy"})
    assert "error" in result
    assert "not allowed" in result["error"]


async def test_rejects_an_empty_patch(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_guest_portal", {})
    assert "error" in result
    assert "No changes requested" in result["error"]


async def test_get_guest_portal_redacts_projected_secrets(
    stub_server: FastMCP, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``guest_access`` is where portal and RADIUS credentials would live.

    No field in ``_PROJECTED`` is a secret today, so the projection is what
    keeps this response clean. That is a guarantee held by an allowlist, and
    allowlists grow: ``_PROJECTED`` is monkeypatched here to include the
    credential fields a future "surface the portal password too" edit would add.
    The tool must still redact them.
    """
    monkeypatch.setattr(
        guest_portal,
        "_PROJECTED",
        (*guest_portal._PROJECTED, "x_password", "radius_secret"),
    )
    record = stub_state.settings.setdefault(SETTING_KEY, {})
    record["x_password"] = "portal-password-do-not-leak"
    record["radius_secret"] = "radius-do-not-leak"

    result = await _call(stub_server, "get_guest_portal")

    assert result["x_password"] == "[REDACTED]"
    assert result["radius_secret"] == "[REDACTED]"
    assert "do-not-leak" not in str(result)
    # Operational fields are untouched.
    assert "portal_enabled" in result
