"""Preview-then-confirm (PtC) tests for v0.7.0 destructive Network tools.

The six ``delete_*`` tools in the Network module now return a preview
envelope with a token instead of mutating the controller directly. The
``confirm_destructive_action(token)`` tool executes the queued action and
removes the token from the in-process pending-actions registry.

These tests live alongside the per-resource files because the contract is
per-tool, but the cross-cutting concerns (token reuse, expiration, envelope
shape) collect here. The per-resource test files still own the happy-path
preview-then-confirm flow (smoked end-to-end against stub + real backends).
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules.network._pending import (
    TOKEN_TTL_SECONDS,
    get_pending_actions,
    reset_pending_actions,
)
from mcp_unifi.server import build_server


def _text(result: Any) -> str:
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


@pytest.fixture
def stub_server(stub_settings: Settings, stub_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=stub_state)


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


PREVIEW_FIELDS = (
    "preview",
    "action",
    "controller",
    "resource",
    "token",
    "expires_at",
    "confirm_with",
)


@pytest.mark.parametrize(
    ("tool", "arg_name", "arg_source", "expected_action"),
    [
        ("delete_vlan", "network_id", "networks", "delete_vlan"),
        ("delete_wlan", "wlan_id", "wlans", "delete_wlan"),
        ("delete_firewall_rule", "rule_id", "firewall_rules", "delete_firewall_rule"),
        ("delete_port_profile", "profile_id", "port_profiles", "delete_port_profile"),
        ("delete_port_forward", "forward_id", "port_forwards", "delete_port_forward"),
        ("delete_static_dhcp_lease", "lease_id", "dhcp_leases", "delete_static_dhcp_lease"),
    ],
)
async def test_each_delete_tool_returns_preview_envelope(
    stub_server: FastMCP,
    stub_state: StubState,
    tool: str,
    arg_name: str,
    arg_source: str,
    expected_action: str,
) -> None:
    """Every delete_* returns the canonical preview envelope; no mutation yet."""
    record = getattr(stub_state, arg_source)[0]
    before = list(getattr(stub_state, arg_source))

    preview = await _call(stub_server, tool, {arg_name: record["_id"]})
    after = list(getattr(stub_state, arg_source))

    # Envelope shape pins the public contract.
    for field in PREVIEW_FIELDS:
        assert field in preview, f"{tool} preview missing field: {field}"
    assert preview["preview"] is True
    assert preview["action"] == expected_action
    assert preview["controller"] == "default"
    assert preview["confirm_with"] == "confirm_destructive_action"
    # Resource snapshot must at least carry _id; tools include name where present.
    assert preview["resource"]["_id"] == record["_id"]
    # Token shape: UUID4 string, 36 chars with dashes.
    assert isinstance(preview["token"], str)
    assert len(preview["token"]) == 36
    # No mutation on preview.
    assert before == after, f"{tool} preview mutated stub state"


# ---------------------------------------------------------------------------
# Confirm executes and removes the token
# ---------------------------------------------------------------------------


async def test_confirm_executes_the_pending_action(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    preview = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    token = preview["token"]
    assert token in get_pending_actions()

    result = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert result["deleted"] is True
    assert result["rule_id"] == rule_id
    assert stub_state.list_firewall_rules() == []
    # Token is single-use: registry no longer carries it.
    assert token not in get_pending_actions()


async def test_confirm_twice_returns_error_on_second_call(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    network_id = stub_state.list_networks()[0]["_id"]
    preview = await _call(stub_server, "delete_vlan", {"network_id": network_id})
    token = preview["token"]

    first = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert first["deleted"] is True

    second = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert "error" in second
    assert "unknown or expired" in second["error"]


async def test_confirm_with_unknown_token_returns_error(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "confirm_destructive_action", {"token": "00000000-0000-0000-0000-000000000000"}
    )
    assert "error" in result
    assert "unknown or expired" in result["error"]


# ---------------------------------------------------------------------------
# Token TTL: expire the token by advancing the clock
# ---------------------------------------------------------------------------


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, float]]:
    """Monkeypatch time.time on the pending-actions module.

    The fixture exposes a mutable ``state`` dict whose ``now`` key tests can
    bump to advance the clock past TOKEN_TTL_SECONDS.
    """
    state = {"now": 1_000_000.0}

    def fake_time() -> float:
        return state["now"]

    monkeypatch.setattr(time, "time", fake_time)
    # The _pending module imports time at module level and calls time.time()
    # directly, so patching the stdlib function is enough.
    yield state


async def test_token_expires_after_ttl(
    stub_server: FastMCP, stub_state: StubState, frozen_clock: dict[str, float]
) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    preview = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    token = preview["token"]
    assert token in get_pending_actions()

    # Advance the clock just past the TTL and confirm the token is gone.
    frozen_clock["now"] += TOKEN_TTL_SECONDS + 1.0
    result = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert "error" in result
    assert "unknown or expired" in result["error"]
    # The firewall rule must still be present — confirm never ran.
    assert any(r["_id"] == rule_id for r in stub_state.list_firewall_rules())


async def test_token_still_valid_just_before_expiry(
    stub_server: FastMCP, stub_state: StubState, frozen_clock: dict[str, float]
) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    preview = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    token = preview["token"]

    # Advance to one second inside the TTL window — token must still resolve.
    frozen_clock["now"] += TOKEN_TTL_SECONDS - 1.0
    result = await _call(stub_server, "confirm_destructive_action", {"token": token})
    assert result["deleted"] is True


# ---------------------------------------------------------------------------
# Multiple pending actions coexist
# ---------------------------------------------------------------------------


async def test_multiple_pending_tokens_resolve_independently(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    # Seed two deletable rules so we can mint two distinct tokens.
    state = stub_state
    state.firewall_rules.append({"_id": "fw-extra", "name": "Extra", "ruleset": "LAN_IN"})
    rule_ids = [r["_id"] for r in state.list_firewall_rules()]
    assert len(rule_ids) >= 2

    preview_a = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_ids[0]})
    preview_b = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_ids[1]})
    assert preview_a["token"] != preview_b["token"]
    assert len(get_pending_actions()) == 2

    # Confirm the second token; the first must still be valid.
    await _call(stub_server, "confirm_destructive_action", {"token": preview_b["token"]})
    assert len(get_pending_actions()) == 1
    assert preview_a["token"] in get_pending_actions()

    # Now confirm the first.
    result = await _call(
        stub_server, "confirm_destructive_action", {"token": preview_a["token"]}
    )
    assert result["deleted"] is True
    assert len(get_pending_actions()) == 0


# ---------------------------------------------------------------------------
# Registry reset (cross-test hygiene)
# ---------------------------------------------------------------------------


async def test_reset_drops_all_pending_actions(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """``reset_pending_actions()`` is the seam tests rely on for isolation."""
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    assert len(get_pending_actions()) == 1
    reset_pending_actions()
    assert len(get_pending_actions()) == 0
