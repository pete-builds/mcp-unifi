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
    # v0.7.0: preview first, then confirm.
    preview = await _call(stub_server, "delete_static_dhcp_lease", {"lease_id": lease_id})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == lease_id
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


async def test_delete_static_dhcp_lease_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_static_dhcp_lease", {"lease_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


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
    # v0.7.0 delete previews via list_dhcp_leases first.
    respx.get(f"{BASE}/list/user").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "u9", "use_fixedip": True, "fixed_ip": "1.2.3.4"}]},
        )
    )
    respx.delete(f"{BASE}/rest/user/u9").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_static_dhcp_lease", {"lease_id": "u9"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


# ---------------------------------------------------------------------------
# update_static_dhcp_lease
# ---------------------------------------------------------------------------


async def test_update_static_dhcp_lease_converts_known_client_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    # Pick a known client that's not already a fixed-IP lease.
    client = stub_state.list_clients()[0]
    mac = client["mac"]
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {
            "mac": mac,
            "fixed_ip": "192.168.1.77",
            "network_id": net_id,
            "name": "promoted",
        },
    )
    assert result["use_fixedip"] is True
    assert result["fixed_ip"] == "192.168.1.77"
    assert result["name"] == "promoted"
    # _id should match the original client record (no new user created).
    assert result["_id"] == client["_id"]


async def test_update_static_dhcp_lease_updates_existing_lease_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    lease = stub_state.list_dhcp_leases()[0]
    net_id = lease["network_id"]
    result = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {
            "mac": lease["mac"],
            "fixed_ip": "192.168.1.250",
            "network_id": net_id,
        },
    )
    assert result["_id"] == lease["_id"]
    assert result["fixed_ip"] == "192.168.1.250"


async def test_update_static_dhcp_lease_unknown_mac_returns_error_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {
            "mac": "ff:ff:ff:ff:ff:ff",
            "fixed_ip": "192.168.1.99",
            "network_id": net_id,
        },
    )
    assert "error" in result
    assert "create_static_dhcp_lease" in result["error"]


async def test_update_static_dhcp_lease_dry_run_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {
            "mac": "aa:bb:cc:00:00:01",
            "fixed_ip": "192.168.1.55",
            "network_id": net_id,
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    assert result["would_update"]["mac"] == "aa:bb:cc:00:00:01"
    assert result["would_update"]["patch"]["fixed_ip"] == "192.168.1.55"
    assert result["would_update"]["patch"]["use_fixedip"] is True


async def test_update_static_dhcp_lease_local_dns_record_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {
            "mac": "aa:bb:cc:00:00:02",
            "fixed_ip": "192.168.1.42",
            "network_id": net_id,
            "name": "iphone",
            "local_dns_record": "iphone.lan",
        },
    )
    assert result["local_dns_record"] == "iphone.lan"
    assert result["local_dns_record_enabled"] is True


@respx.mock
async def test_real_update_static_dhcp_lease(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"_id": "u42", "mac": "d0:11:e5:03:f6:3a", "name": "cypher"},
                    {"_id": "u43", "mac": "aa:bb:cc:dd:ee:ff"},
                ]
            },
        )
    )
    respx.put(f"{BASE}/rest/user/u42").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "u42",
                        "mac": "d0:11:e5:03:f6:3a",
                        "use_fixedip": True,
                        "fixed_ip": "192.168.1.50",
                        "network_id": "n1",
                        "name": "cypher",
                    }
                ]
            },
        )
    )
    result = await _call(
        real_server,
        "update_static_dhcp_lease",
        {
            "mac": "d0:11:e5:03:f6:3a",
            "fixed_ip": "192.168.1.50",
            "network_id": "n1",
            "name": "cypher",
        },
    )
    assert result["_id"] == "u42"
    assert result["fixed_ip"] == "192.168.1.50"


@respx.mock
async def test_real_update_static_dhcp_lease_unknown_mac(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(
        real_server,
        "update_static_dhcp_lease",
        {
            "mac": "ff:ff:ff:ff:ff:ff",
            "fixed_ip": "192.168.1.99",
            "network_id": "n1",
        },
    )
    assert "error" in result
    assert "create_static_dhcp_lease" in result["error"]
