"""Tests for the visitor tools: list_visitors, get_visitor."""

from __future__ import annotations

import json

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
    # The pass code is present as a field but never as a value; see
    # test_visitor_reads_redact_the_pass_code below for why.
    assert visitor["pass_code"] == "[REDACTED]"


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


async def test_visitor_reads_redact_the_pass_code(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    """A visitor pass code opens a door, and it is not the record's identifier.

    Found sweeping for the devices.py failure mode: fields that are secrets
    but match no pattern, so redaction is a no-op wherever it is applied.
    ``pass_code`` was worse than the device keys — it matched no pattern
    *and* neither visitor tool called ``redact`` at all, while the docstring
    advertised the field as part of the return shape.

    The distinction that makes this a value and not a reference: the record
    carries a separate ``id``, which is what ``get_visitor`` and every other
    lookup take. Redacting ``pass_code`` costs a caller nothing they cannot
    get from ``id``.
    """
    visitor = stub_access_state.visitors[0]
    visitor["pass_code"] = "ACC-VISIT-do-not-leak"
    visitor_id = visitor["id"]

    listed = await _call(access_registry, "list_visitors")
    single = await _call(access_registry, "get_visitor", {"visitor_id": visitor_id})

    for payload in (next(v for v in listed if v["id"] == visitor_id), single):
        assert payload["pass_code"] == "[REDACTED]"
        # Identity, the host link, and the validity window all survive, so a
        # caller can still audit and revoke the pass.
        assert payload["id"] == visitor_id
        assert payload["full_name"] == "Dave Delivery"
        assert payload["host_user_id"] == stub_access_state.users[0]["id"]
        assert payload["status"] == "active"

    assert "do-not-leak" not in json.dumps(listed)
    assert "do-not-leak" not in json.dumps(single)
