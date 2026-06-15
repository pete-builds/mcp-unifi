"""Tests for the DNS content-filtering tools in
``mcp_unifi.modules.network.content_filtering``.

Covers read (list + details), update (read-modify-write + dry_run + missing),
the preview-then-confirm delete round-trip, and error envelopes. Real-mode
tests assert the v2 ``/content-filtering`` wiring (bare-list surface).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# The v2 surface sits at a different prefix than the legacy ``/api/s`` BASE.
V2_BASE = BASE.replace("/api/s/default", "/v2/api/site/default")


# ---------------------------------------------------------------------------
# Stub mode — reads
# ---------------------------------------------------------------------------


async def test_list_content_filters_stub(stub_server: FastMCP) -> None:
    profiles = await _call(stub_server, "list_content_filters")
    assert isinstance(profiles, list)
    assert profiles[0]["name"] == "adblock"
    assert "categories" in profiles[0]
    assert profiles[0]["schedule"]["mode"] == "ALWAYS"


async def test_get_content_filter_details_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    fid = stub_state.list_content_filters()[0]["_id"]
    result = await _call(stub_server, "get_content_filter_details", {"filter_id": fid})
    assert result["_id"] == fid
    assert result["enabled"] is True


async def test_get_content_filter_details_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_content_filter_details", {"filter_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Stub mode — update (read-modify-write)
# ---------------------------------------------------------------------------


async def test_update_content_filter_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    fid = stub_state.list_content_filters()[0]["_id"]
    result = await _call(
        stub_server,
        "update_content_filter",
        {"filter_id": fid, "updates": {"enabled": False}},
    )
    assert result["enabled"] is False
    # Untouched fields preserved (read-modify-write merge).
    assert result["name"] == "adblock"
    assert result["schedule"]["mode"] == "ALWAYS"


async def test_update_content_filter_replaces_lists(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    fid = stub_state.list_content_filters()[0]["_id"]
    result = await _call(
        stub_server,
        "update_content_filter",
        {"filter_id": fid, "updates": {"categories": ["ADVERTISEMENT", "MALWARE"]}},
    )
    assert result["categories"] == ["ADVERTISEMENT", "MALWARE"]


async def test_update_content_filter_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    fid = stub_state.list_content_filters()[0]["_id"]
    result = await _call(
        stub_server,
        "update_content_filter",
        {"filter_id": fid, "updates": {"enabled": False}, "dry_run": True},
    )
    assert result["dry_run"] is True
    assert result["would_update"]["filter_id"] == fid
    # Unchanged on the stub.
    assert stub_state.list_content_filters()[0]["enabled"] is True


async def test_update_content_filter_empty_updates(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "update_content_filter", {"filter_id": "x", "updates": {}})
    assert "error" in result


async def test_update_content_filter_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_content_filter",
        {"filter_id": "ghost", "updates": {"enabled": False}},
    )
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Stub mode — delete (preview-then-confirm)
# ---------------------------------------------------------------------------


async def test_delete_content_filter_round_trip(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    fid = stub_state.list_content_filters()[0]["_id"]
    preview = await _call(stub_server, "delete_content_filter", {"filter_id": fid})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == fid
    assert any(c["_id"] == fid for c in stub_state.list_content_filters())  # not deleted yet
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["filter_id"] == fid
    assert not any(c["_id"] == fid for c in stub_state.list_content_filters())


async def test_delete_content_filter_dry_run(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_content_filter", {"filter_id": "x", "dry_run": True})
    assert result["dry_run"] is True
    assert result["would_delete"]["filter_id"] == "x"


async def test_delete_content_filter_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_content_filter", {"filter_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------

_SAMPLE = {
    "_id": "cf1",
    "name": "adblock",
    "enabled": True,
    "categories": ["ADVERTISEMENT"],
    "allow_list": [],
    "block_list": [],
    "client_macs": [],
    "network_ids": ["net1"],
    "safe_search": [],
    "schedule": {"mode": "ALWAYS"},
}


@respx.mock
async def test_real_list_content_filters(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(200, json=[_SAMPLE]))
    result = await _call(real_server, "list_content_filters")
    assert result[0]["name"] == "adblock"


@respx.mock
async def test_real_get_content_filter_details(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(200, json=[_SAMPLE]))
    result = await _call(real_server, "get_content_filter_details", {"filter_id": "cf1"})
    assert result["_id"] == "cf1"


@respx.mock
async def test_real_update_content_filter_read_modify_write(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={**_SAMPLE, "enabled": False})

    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(200, json=[_SAMPLE]))
    respx.put(f"{V2_BASE}/content-filtering/cf1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "update_content_filter",
        {"filter_id": "cf1", "updates": {"enabled": False}},
    )
    assert result["enabled"] is False
    # The full record is PUT back (untouched fields preserved).
    assert captured["body"]["name"] == "adblock"
    assert captured["body"]["schedule"]["mode"] == "ALWAYS"
    assert captured["body"]["enabled"] is False


@respx.mock
async def test_real_delete_content_filter(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(200, json=[_SAMPLE]))
    respx.delete(f"{V2_BASE}/content-filtering/cf1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_content_filter", {"filter_id": "cf1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


@respx.mock
async def test_real_list_content_filters_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_content_filters")
    assert "error" in result


@respx.mock
async def test_real_update_content_filter_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(200, json=[_SAMPLE]))
    respx.put(f"{V2_BASE}/content-filtering/cf1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "update_content_filter",
        {"filter_id": "cf1", "updates": {"enabled": False}},
    )
    assert "error" in result


@respx.mock
async def test_real_get_content_filter_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_content_filter_details", {"filter_id": "cf1"})
    assert "error" in result


@respx.mock
async def test_real_delete_content_filter_handles_500_on_lookup(real_server: FastMCP) -> None:
    respx.get(f"{V2_BASE}/content-filtering").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "delete_content_filter", {"filter_id": "cf1"})
    assert "error" in result
