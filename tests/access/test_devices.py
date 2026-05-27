"""Tests for the device tools: list_access_devices, get_access_device,
get_access_system_info, list_access_users.
"""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
from tests.access.conftest import _call


async def test_list_access_devices_seed_shape(access_registry: FastMCP) -> None:
    devices = await _call(access_registry, "list_access_devices")
    assert isinstance(devices, list)
    assert len(devices) == 3
    types = [d["type"] for d in devices]
    assert types.count("hub") == 1
    assert types.count("reader") == 2


async def test_get_access_device_by_id(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    device_id = stub_access_state.devices[0]["id"]
    device = await _call(access_registry, "get_access_device", {"device_id": device_id})
    assert device["id"] == device_id
    assert device["type"] == "hub"
    assert device["online"] is True


async def test_get_access_device_not_found(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "get_access_device", {"device_id": "nope"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_get_access_system_info(access_registry: FastMCP) -> None:
    info = await _call(access_registry, "get_access_system_info")
    assert info["version"] == "2.6.42"
    assert info["release_channel"] == "stable"
    assert info["license"]["doors_used"] == 2
    assert info["license"]["doors_max"] == 10


async def test_list_access_users(access_registry: FastMCP) -> None:
    users = await _call(access_registry, "list_access_users")
    assert len(users) == 3
    names = {u["full_name"] for u in users}
    assert names == {"Alice Admin", "Bob Builder", "Carol Contractor"}


async def test_list_access_users_credential_cross_reference(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    """Each seeded user owns exactly one credential, wired in AccessStubState.__init__."""
    users = await _call(access_registry, "list_access_users")
    credentials = stub_access_state.credentials
    cred_ids = {c["id"] for c in credentials}
    user_cred_ids: set[str] = set()
    for user in users:
        assert len(user["credential_ids"]) == 1
        user_cred_ids.update(user["credential_ids"])
    assert user_cred_ids == cred_ids
