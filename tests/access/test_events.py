"""Tests for the event tools: list_access_events, get_recent_access_events,
summarize_access_activity, list_failed_access_attempts.
"""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
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
