"""Tests for ``mcp_unifi.modules.network.vlans``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged;
fixtures (``stub_server``, ``real_server``) and helpers (``BASE``, ``_call``)
come from ``tests/network/conftest.py``.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_networks_stub(stub_server: FastMCP) -> None:
    nets = await _call(stub_server, "list_networks")
    assert nets[0]["name"] == "Default"


async def test_create_vlan_validates_range(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_vlan",
        {"name": "Bad", "vlan_id": 1, "subnet": "10.0.1.0/24"},
    )
    assert "out of range" in result["error"]


async def test_create_vlan_uses_default_dhcp_range(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    result = await _call(
        stub_server,
        "create_vlan",
        {"name": "Office", "vlan_id": 50, "subnet": "10.0.50.0/24"},
    )
    assert result["dhcpd_start"] == "10.0.50.100"
    assert result["dhcpd_stop"] == "10.0.50.200"
    assert result["vlan"] == 50
    assert len(stub_state.list_networks()) == 2


async def test_create_vlan_honours_custom_dhcp(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_vlan",
        {
            "name": "Custom",
            "vlan_id": 60,
            "subnet": "10.0.60.0/24",
            "dhcp_start": "10.0.60.50",
            "dhcp_stop": "10.0.60.150",
        },
    )
    assert result["dhcpd_start"] == "10.0.60.50"
    assert result["dhcpd_stop"] == "10.0.60.150"


async def test_update_vlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "update_vlan",
        {"network_id": net_id, "updates": {"name": "Renamed"}},
    )
    assert result["name"] == "Renamed"


async def test_update_vlan_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_vlan",
        {"network_id": "ghost", "updates": {"name": "X"}},
    )
    assert "not found" in result["error"]


async def test_delete_vlan_stub(stub_server: FastMCP) -> None:
    created = await _call(
        stub_server,
        "create_vlan",
        {"name": "Doomed", "vlan_id": 70, "subnet": "10.0.70.0/24"},
    )
    result = await _call(stub_server, "delete_vlan", {"network_id": created["_id"]})
    assert result["deleted"] is True


async def test_delete_vlan_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_vlan", {"network_id": "ghost"})
    assert result["deleted"] is False


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_create_vlan(real_server: FastMCP) -> None:
    route = respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n9", "name": "IoT", "vlan": 20}]})
    )
    result = await _call(
        real_server,
        "create_vlan",
        {"name": "IoT", "vlan_id": 20, "subnet": "10.0.20.0/24"},
    )
    assert result["_id"] == "n9"
    assert route.called


@respx.mock
async def test_real_list_networks(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n", "name": "X"}]})
    )
    result = await _call(real_server, "list_networks")
    assert result[0]["name"] == "X"


@respx.mock
async def test_real_update_vlan(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "Up"}]})
    )
    result = await _call(
        real_server,
        "update_vlan",
        {"network_id": "n1", "updates": {"name": "Up"}},
    )
    assert result["name"] == "Up"


@respx.mock
async def test_real_delete_vlan(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/networkconf/n1").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_vlan", {"network_id": "n1"})
    assert result["deleted"] is True


@respx.mock
async def test_create_vlan_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(
        real_server,
        "create_vlan",
        {"name": "X", "vlan_id": 5, "subnet": "10.0.5.0/24"},
    )
    assert "error" in result
    assert result["stub_mode"] is False


@respx.mock
async def test_update_vlan_real_mode_handles_404(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/networkconf/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(
        real_server,
        "update_vlan",
        {"network_id": "missing", "updates": {"name": "X"}},
    )
    assert "error" in result


@respx.mock
async def test_delete_vlan_real_mode_handles_409(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(409, text="referenced by SSID")
    )
    result = await _call(real_server, "delete_vlan", {"network_id": "n1"})
    assert "error" in result


@respx.mock
async def test_list_networks_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_networks")
    assert "error" in result
