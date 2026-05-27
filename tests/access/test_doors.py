"""Tests for the door-read tools: list_doors, get_door, list_door_groups, policies."""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
from tests.access.conftest import _call


async def test_list_doors_seed_shape(access_registry: FastMCP) -> None:
    doors = await _call(access_registry, "list_doors")
    assert isinstance(doors, list)
    assert len(doors) == 2
    names = {d["name"] for d in doors}
    assert names == {"Main Entrance", "Server Room"}


async def test_list_doors_includes_lock_state(access_registry: FastMCP) -> None:
    doors = await _call(access_registry, "list_doors")
    for door in doors:
        assert door["locked"] is True
        assert door["online"] is True
        assert door["lock_status"] == "locked"
        assert door["hub_id"]  # back-filled in __init__


async def test_get_door_by_id(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    door_id = stub_access_state.doors[0]["id"]
    door = await _call(access_registry, "get_door", {"door_id": door_id})
    assert door["id"] == door_id
    assert door["name"] == "Main Entrance"


async def test_get_door_not_found(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "get_door", {"door_id": "nope"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_list_door_groups(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    groups = await _call(access_registry, "list_door_groups")
    assert len(groups) == 1
    group = groups[0]
    assert group["name"] == "All Doors"
    assert len(group["door_ids"]) == 2
    door_ids = {d["id"] for d in stub_access_state.doors}
    assert set(group["door_ids"]) == door_ids


async def test_list_access_policies(access_registry: FastMCP) -> None:
    policies = await _call(access_registry, "list_access_policies")
    assert len(policies) == 1
    policy = policies[0]
    assert policy["name"] == "Business Hours — All Users"
    assert policy["active"] is True
    assert "monday" in policy["schedule"]


async def test_get_access_policy_by_id(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    policy_id = stub_access_state.access_policies[0]["id"]
    policy = await _call(access_registry, "get_access_policy", {"policy_id": policy_id})
    assert policy["id"] == policy_id
    assert len(policy["user_ids"]) == 3


async def test_get_access_policy_not_found(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "get_access_policy", {"policy_id": "nope"})
    assert "error" in result
    assert "not found" in result["error"]
