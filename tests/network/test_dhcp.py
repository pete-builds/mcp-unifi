"""Tests for ``mcp_unifi.modules.network.dhcp``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
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


async def test_list_dhcp_leases_stub(stub_server: FastMCP) -> None:
    leases = await _call(stub_server, "list_dhcp_leases")
    assert isinstance(leases, list)
    assert all(lease.get("use_fixedip") for lease in leases)


async def test_create_static_dhcp_lease_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_static_dhcp_lease",
        {
            "mac": "11:22:33:44:55:66",
            "ip": "192.168.1.42",
            "network_id": net_id,
            "name": "Test Pi",
            "hostname": "pi-test",
        },
    )
    assert result["mac"] == "11:22:33:44:55:66"
    assert result["fixed_ip"] == "192.168.1.42"
    assert result["use_fixedip"] is True


async def test_delete_static_dhcp_lease_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    lease_id = stub_state.list_dhcp_leases()[0]["_id"]
    result = await _call(stub_server, "delete_static_dhcp_lease", {"lease_id": lease_id})
    assert result["deleted"] is True


async def test_delete_static_dhcp_lease_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_static_dhcp_lease", {"lease_id": "ghost"})
    assert result["deleted"] is False


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_dhcp_leases(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"_id": "u1", "use_fixedip": True, "fixed_ip": "192.168.1.10"},
                    {"_id": "u2", "use_fixedip": False},
                ]
            },
        )
    )
    result = await _call(real_server, "list_dhcp_leases")
    assert len(result) == 1
    assert result[0]["_id"] == "u1"


@respx.mock
async def test_real_create_static_dhcp_lease(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/user").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "u9"}]})
    )
    result = await _call(
        real_server,
        "create_static_dhcp_lease",
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.42", "network_id": "n1"},
    )
    assert result["_id"] == "u9"


@respx.mock
async def test_real_delete_static_dhcp_lease(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/user/u9").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_static_dhcp_lease", {"lease_id": "u9"})
    assert result["deleted"] is True
