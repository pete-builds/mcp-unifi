"""Tests for ``mcp_unifi.modules.network.threat_management``.

Covers the stub-mode contract (read + write through ``StubState.settings``)
and the real-mode wire shape (``GET /rest/setting/ips`` + ``POST
/set/setting/ips``) via respx mocks against the same UCG-Fiber fw
5.1.12.33296 endpoints Forge probed live in this session.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_get_threat_management_stub_defaults(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_threat_management")
    assert result["enabled"] is False
    assert result["mode"] == "off"
    assert result["enabled_signature_categories"] == []
    assert result["honeypot_enabled"] is False


async def test_set_threat_management_stub_enables_ips(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    result = await _call(
        stub_server,
        "set_threat_management",
        {"enabled": True, "mode": "ips"},
    )
    assert result["enabled"] is True
    assert result["mode"] == "ips"
    # State should reflect the new mode.
    assert stub_state.settings["ips"]["ips_mode"] == "ips"


async def test_set_threat_management_disabled_forces_off(stub_server: FastMCP) -> None:
    """``enabled=False`` must set ``mode=off`` regardless of the ``mode`` arg."""
    result = await _call(
        stub_server,
        "set_threat_management",
        {"enabled": False, "mode": "ips"},
    )
    assert result["enabled"] is False
    assert result["mode"] == "off"


async def test_set_threat_management_replaces_categories(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    new_cats = ["emerging-malware", "tor", "dshield"]
    result = await _call(
        stub_server,
        "set_threat_management",
        {"enabled": True, "mode": "ids", "signature_categories": new_cats},
    )
    assert result["enabled_signature_categories"] == new_cats
    assert stub_state.settings["ips"]["enabled_categories"] == new_cats


async def test_set_threat_management_invalid_mode(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_threat_management",
        {"enabled": True, "mode": "blocking"},
    )
    assert "error" in result
    assert "mode" in result["error"]


async def test_set_threat_management_dry_run(stub_server: FastMCP, stub_state: StubState) -> None:
    before = dict(stub_state.settings["ips"])
    result = await _call(
        stub_server,
        "set_threat_management",
        {"enabled": True, "mode": "ips", "dry_run": True},
    )
    assert result["dry_run"] is True
    assert result["would_patch"]["setting_key"] == "ips"
    assert result["would_patch"]["patch"]["ips_mode"] == "ips"
    # Real state must not change on dry-run.
    assert stub_state.settings["ips"] == before


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_threat_management(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/setting/ips").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "ips123",
                        "key": "ips",
                        "ips_mode": "ids",
                        "enabled_categories": ["emerging-malware", "tor"],
                        "enabled_networks": ["nethome"],
                        "honeypot_enabled": True,
                        "endpoint_scanning": False,
                        "ad_blocking_enabled": False,
                        "dns_filtering": True,
                    }
                ]
            },
        )
    )
    result = await _call(real_server, "get_threat_management")
    assert result["enabled"] is True
    assert result["mode"] == "ids"
    assert "emerging-malware" in result["enabled_signature_categories"]
    assert result["honeypot_enabled"] is True
    assert result["dns_filtering"] is True


@respx.mock
async def test_real_set_threat_management_sends_partial_patch(
    real_server: FastMCP,
) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "ips123",
                        "key": "ips",
                        "ips_mode": "ips",
                        "enabled_categories": ["emerging-malware"],
                    }
                ]
            },
        )

    respx.post(f"{BASE}/set/setting/ips").mock(side_effect=capture)
    result = await _call(
        real_server,
        "set_threat_management",
        {
            "enabled": True,
            "mode": "ips",
            "signature_categories": ["emerging-malware"],
        },
    )
    assert result["mode"] == "ips"
    assert captured["body"]["ips_mode"] == "ips"
    assert captured["body"]["enabled_categories"] == ["emerging-malware"]


@respx.mock
async def test_real_set_threat_management_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/set/setting/ips").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "set_threat_management",
        {"enabled": False},
    )
    assert "error" in result


@respx.mock
async def test_real_get_threat_management_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/setting/ips").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_threat_management")
    assert "error" in result
