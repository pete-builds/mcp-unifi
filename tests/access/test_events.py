"""Tests for the event tools: list_access_events, get_recent_access_events,
summarize_access_activity, list_failed_access_attempts.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
from mcp_unifi.clients.unifi import UniFiError
from tests.access.conftest import _call


async def test_list_access_events_default_window(access_registry: FastMCP) -> None:
    events = await _call(access_registry, "list_access_events")
    assert isinstance(events, list)
    # 24h default window catches all 50 seeded events; default limit 100
    assert len(events) == 50
    # Newest first
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_list_access_events_limit(access_registry: FastMCP) -> None:
    events = await _call(access_registry, "list_access_events", {"limit": 5})
    assert len(events) == 5


async def test_list_access_events_result_filter(access_registry: FastMCP) -> None:
    granted = await _call(
        access_registry, "list_access_events", {"result": "granted", "limit": 100}
    )
    denied = await _call(access_registry, "list_access_events", {"result": "denied", "limit": 100})
    assert all(e["result"] == "granted" for e in granted)
    assert all(e["result"] == "denied" for e in denied)
    assert len(granted) + len(denied) == 50


async def test_list_access_events_door_filter(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    door_id = stub_access_state.doors[0]["id"]
    events = await _call(
        access_registry,
        "list_access_events",
        {"door_id": door_id, "limit": 100},
    )
    assert all(e["door_id"] == door_id for e in events)
    assert len(events) > 0


async def test_list_access_events_invalid_result(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "list_access_events", {"result": "maybe"})
    assert "error" in result
    assert "result" in result["error"]


async def test_get_recent_access_events(access_registry: FastMCP) -> None:
    events = await _call(access_registry, "get_recent_access_events", {"limit": 5})
    assert len(events) == 5
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_summarize_access_activity(access_registry: FastMCP) -> None:
    summary = await _call(access_registry, "summarize_access_activity")
    assert summary["total"] == 50
    # Seed mix: ~25% denied
    assert summary["denied"] > 0
    assert summary["granted"] > 0
    assert summary["granted"] + summary["denied"] == summary["total"]
    # Both doors should appear
    assert len(summary["by_door"]) == 2
    # All three users should appear
    assert len(summary["by_user"]) == 3
    # Buckets sorted by total desc
    door_totals = [d["total"] for d in summary["by_door"]]
    assert door_totals == sorted(door_totals, reverse=True)


async def test_list_failed_access_attempts(access_registry: FastMCP) -> None:
    failures = await _call(access_registry, "list_failed_access_attempts")
    assert all(e["result"] == "denied" for e in failures)
    assert all(e.get("reason") for e in failures)


async def test_list_failed_access_attempts_door_filter(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    door_id = stub_access_state.doors[1]["id"]
    failures = await _call(
        access_registry,
        "list_failed_access_attempts",
        {"door_id": door_id},
    )
    assert all(f["door_id"] == door_id for f in failures)
    assert all(f["result"] == "denied" for f in failures)


# ---------------------------------------------------------------------------
# summarize_access_activity: consistent counts, and a cap that says so
# ---------------------------------------------------------------------------


async def test_summarize_counts_agree_when_results_are_not_granted_or_denied(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    for evt in stub_access_state.events[:10]:
        evt["result"] = "BLOCKED"
    for evt in stub_access_state.events[10:15]:
        evt.pop("result")

    summary = await _call(access_registry, "summarize_access_activity")

    assert summary["total"] == 50
    assert summary["granted"] + summary["denied"] + summary["other"] == summary["total"]
    assert summary["other"] == 15
    # The headline count and the per-door and per-user counts now agree.
    assert summary["denied"] == sum(d["denied"] for d in summary["by_door"])
    assert summary["denied"] == sum(u["denied"] for u in summary["by_user"])
    assert summary["truncated"] is False
    assert "note" not in summary


def _pad_events(state: AccessStubState, count: int) -> None:
    """Replace the seeded events with ``count`` granted ones, ids ``e0`` newest first."""
    now = int(time.time() * 1000)
    base = state.events[0]
    state.events = [
        {**base, "id": f"e{i}", "timestamp": now - 1000 - i, "result": "granted"}
        for i in range(count)
    ]


async def test_summarize_says_when_the_cap_truncated_the_input(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    _pad_events(stub_access_state, 700)

    summary = await _call(access_registry, "summarize_access_activity")

    assert summary["total"] == 500
    assert summary["truncated"] is True
    assert "500" in summary["note"]


async def test_summarize_exactly_at_the_cap_is_not_truncated(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    _pad_events(stub_access_state, 500)

    summary = await _call(access_registry, "summarize_access_activity")

    assert summary["total"] == 500
    assert summary["truncated"] is False


async def test_summarize_cap_keeps_the_newest_events_whatever_order_they_arrive_in(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    """Ten old denied events must be the ones dropped by the cap."""
    _pad_events(stub_access_state, 500)
    old = int(time.time() * 1000) - 20 * 3600 * 1000
    stub_access_state.events.extend(
        {**stub_access_state.events[0], "id": f"old{i}", "timestamp": old - i, "result": "denied"}
        for i in range(10)
    )
    real = stub_access_state.list_events

    def oldest_first(*args: Any, **kwargs: Any) -> Any:
        return list(reversed(real(*args, **kwargs)))

    stub_access_state.list_events = oldest_first  # type: ignore[method-assign]

    summary = await _call(access_registry, "summarize_access_activity")

    assert summary["truncated"] is True
    assert summary["denied"] == 0
    assert summary["granted"] == 500


# ---------------------------------------------------------------------------
# limit and hours_back are bounded
# ---------------------------------------------------------------------------


async def test_access_event_tools_reject_out_of_range_limit_and_window(
    access_registry: FastMCP,
) -> None:
    for tool, args in (
        ("list_access_events", {"limit": -1}),
        ("list_access_events", {"limit": 0}),
        ("list_access_events", {"limit": 1001}),
        ("list_access_events", {"hours_back": 0}),
        ("list_access_events", {"hours_back": 721}),
        ("get_recent_access_events", {"limit": -5}),
        ("get_recent_access_events", {"limit": 1001}),
        ("list_failed_access_attempts", {"limit": 0}),
        ("list_failed_access_attempts", {"hours_back": -1}),
        ("summarize_access_activity", {"hours_back": 0}),
        ("summarize_access_activity", {"hours_back": 10_000}),
    ):
        result = await _call(access_registry, tool, args)
        assert isinstance(result, dict) and "error" in result, (tool, args)
        assert "between 1 and" in result["error"]


async def test_access_event_tools_accept_the_documented_maximums(
    access_registry: FastMCP,
) -> None:
    events = await _call(access_registry, "list_access_events", {"limit": 1000, "hours_back": 720})
    assert len(events) == 50


# ---------------------------------------------------------------------------
# The stub validates ids and filters the way AccessClient does
# ---------------------------------------------------------------------------


async def test_malformed_ids_and_filters_are_rejected_by_the_stub(
    access_registry: FastMCP,
) -> None:
    for tool, args in (
        ("get_door", {"door_id": "a/b"}),
        ("get_door", {"door_id": ""}),
        ("get_credential", {"credential_id": "../x"}),
        ("get_visitor", {"visitor_id": "a?b"}),
        ("get_access_policy", {"policy_id": "a#b"}),
        ("get_access_device", {"device_id": "a b"}),
        ("list_access_events", {"door_id": "a&b=1"}),
        ("list_failed_access_attempts", {"door_id": "a&b=1"}),
    ):
        result = await _call(access_registry, tool, args)
        assert isinstance(result, dict) and "error" in result, (tool, args)


async def test_unknown_ids_are_not_found(access_registry: FastMCP) -> None:
    for tool, args in (
        ("get_door", {"door_id": "does-not-exist"}),
        ("get_credential", {"credential_id": "does-not-exist"}),
        ("get_visitor", {"visitor_id": "does-not-exist"}),
        ("get_access_policy", {"policy_id": "does-not-exist"}),
        ("get_access_device", {"device_id": "does-not-exist"}),
    ):
        result = await _call(access_registry, tool, args)
        assert "not found" in result["error"], (tool, args)


async def test_stub_reads_return_copies(stub_access_state: AccessStubState) -> None:
    """Editing a returned record must not edit the stub's state."""
    door_id = stub_access_state.doors[0]["id"]
    stub_access_state.list_doors()[0]["name"] = "mutated"
    door = stub_access_state.get_door(door_id)
    assert door is not None
    door["name"] = "mutated"
    stub_access_state.list_credentials()[0]["status"] = "mutated"
    stub_access_state.list_events(0, 2**62, 5)[0]["result"] = "mutated"
    stub_access_state.get_system_info()["license"]["doors_max"] = 0

    assert stub_access_state.doors[0]["name"] == "Main Entrance"
    assert stub_access_state.credentials[0]["status"] == "active"
    assert all(e["result"] != "mutated" for e in stub_access_state.events)
    assert stub_access_state.system_info["license"]["doors_max"] == 10


async def test_every_access_stub_method_honours_fail_next(
    stub_access_state: AccessStubState,
) -> None:
    state = stub_access_state
    calls: dict[str, Any] = {
        "list_doors": lambda: state.list_doors(),
        "get_door": lambda: state.get_door("x"),
        "list_door_groups": lambda: state.list_door_groups(),
        "list_access_policies": lambda: state.list_access_policies(),
        "get_access_policy": lambda: state.get_access_policy("x"),
        "list_credentials": lambda: state.list_credentials(),
        "get_credential": lambda: state.get_credential("x"),
        "list_visitors": lambda: state.list_visitors(),
        "get_visitor": lambda: state.get_visitor("x"),
        "list_events": lambda: state.list_events(0, 1, 1),
        "list_devices": lambda: state.list_devices(),
        "get_device": lambda: state.get_device("x"),
        "get_system_info": lambda: state.get_system_info(),
        "list_users": lambda: state.list_users(),
    }
    for name, call in calls.items():
        state.fail_next(name, UniFiError(f"{name} injected"))
        with pytest.raises(UniFiError, match=f"{name} injected"):
            call()
        call()  # one failure was queued; the next call succeeds
