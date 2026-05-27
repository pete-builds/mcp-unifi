"""Tests for the visitor tools: list_visitors, get_visitor."""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
from tests.access.conftest import _call


async def test_list_visitors_seed_shape(access_registry: FastMCP) -> None:
    visitors = await _call(access_registry, "list_visitors")
    assert isinstance(visitors, list)
    assert len(visitors) == 1
    visitor = visitors[0]
    assert visitor["full_name"] == "Dave Delivery"
    assert visitor["status"] == "active"
    assert visitor["pass_code"].startswith("ACC-VISIT-")


async def test_get_visitor_by_id(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    visitor_id = stub_access_state.visitors[0]["id"]
    visitor = await _call(access_registry, "get_visitor", {"visitor_id": visitor_id})
    assert visitor["id"] == visitor_id
    assert visitor["full_name"] == "Dave Delivery"
    assert visitor["host_user_id"] == stub_access_state.users[0]["id"]


async def test_get_visitor_not_found(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "get_visitor", {"visitor_id": "nope"})
    assert "error" in result
    assert "not found" in result["error"]
