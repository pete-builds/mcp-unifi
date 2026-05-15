"""Tests for ``mcp_unifi.modules.network.devices``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import FastMCP

from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_devices_stub(stub_server: FastMCP) -> None:
    devices = await _call(stub_server, "list_devices")
    assert any(d["model"] == "UCGFiber" for d in devices)


async def test_restart_device_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "restart_device", {"mac": "f4:e2:c6:00:00:01"})
    assert result["restarted"] is True


async def test_restart_device_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "restart_device", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_locate_device_on_then_off(stub_server: FastMCP) -> None:
    on = await _call(stub_server, "locate_device", {"mac": "f4:e2:c6:00:00:02", "on": True})
    assert on["locating"] is True
    off = await _call(stub_server, "locate_device", {"mac": "f4:e2:c6:00:00:02", "on": False})
    assert off["locating"] is False


async def test_locate_device_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "locate_device", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_set_port_state_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5, "enable": False, "poe_mode": "off"},
    )
    assert result["enable"] is False
    assert result["poe_mode"] == "off"


async def test_set_port_state_no_args(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5},
    )
    assert "at least one of" in result["error"]


async def test_set_port_state_unknown_device(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": "00:00:00:00:00:00", "port_idx": 1, "enable": True},
    )
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_devices(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "x", "model": "UCGFiber"}]})
    )
    devices = await _call(real_server, "list_devices")
    assert devices[0]["model"] == "UCGFiber"


@respx.mock
async def test_real_list_devices_error_returns_structured_error(
    real_server: FastMCP,
) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(401, text="Unauthorized"))
    result = await _call(real_server, "list_devices")
    assert "error" in result
    assert "401" in result["error"]
    assert result["stub_mode"] is False


@respx.mock
async def test_real_restart_device(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/devmgr").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "restart_device", {"mac": "f4:e2:c6:00:00:01"})
    assert result["restarted"] is True


@respx.mock
async def test_real_locate_device(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": []})

    respx.post(f"{BASE}/cmd/devmgr").mock(side_effect=capture)
    result = await _call(real_server, "locate_device", {"mac": "f4:e2:c6:00:00:02", "on": True})
    assert result["locating"] is True
    assert captured["body"]["cmd"] == "set-locate"


@respx.mock
async def test_real_set_port_state(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "mac": "f4:e2:c6:00:00:03",
                        "port_overrides": [{"port_idx": 1, "enable": True}],
                    }
                ]
            },
        )
    )
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "port_overrides": captured["body"]["port_overrides"],
                    }
                ]
            },
        )

    respx.put(f"{BASE}/rest/device/switch-1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5, "poe_mode": "off"},
    )
    assert result["_id"] == "switch-1"
    overrides = {o["port_idx"]: o for o in captured["body"]["port_overrides"]}
    assert overrides[5]["poe_mode"] == "off"
    assert 1 in overrides  # existing override preserved


@respx.mock
async def test_real_set_port_state_unknown_device(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(
        real_server,
        "set_port_state",
        {"device_mac": "ff:ff:ff:ff:ff:ff", "port_idx": 1, "enable": True},
    )
    assert "not found" in result["error"]
