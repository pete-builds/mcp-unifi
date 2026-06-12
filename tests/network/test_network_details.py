"""Tests for the ``get_network_details`` tool in
``mcp_unifi.modules.network.vlans``.

Covers resolution by id and by name, the section grouping (network / dhcp /
ipv6 / vpn / raw), the IPv6 section surfacing, ambiguous-name and not-found
errors, and the real-mode ``/rest/networkconf`` wiring.
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


async def test_get_network_details_by_id(stub_server: FastMCP, stub_state: StubState) -> None:
    nid = stub_state.list_networks()[0]["_id"]
    result = await _call(stub_server, "get_network_details", {"network_id": nid})
    assert result["controller"] == "default"
    assert result["network"]["_id"] == nid
    assert set(result) >= {"network", "dhcp", "ipv6", "vpn", "raw"}


async def test_get_network_details_by_name(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_network_details", {"name": "Default"})
    assert result["network"]["name"] == "Default"


async def test_get_network_details_name_case_insensitive(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_network_details", {"name": "default"})
    assert result["network"]["name"] == "Default"


async def test_get_network_details_ipv6_section_populated(stub_server: FastMCP) -> None:
    """The Default LAN seed carries IPv6 keys; the ipv6 section must surface them."""
    result = await _call(stub_server, "get_network_details", {"name": "Default"})
    ipv6 = result["ipv6"]
    assert "ipv6_interface_type" in ipv6
    assert "ipv6_ra_enabled" in ipv6
    assert "ipv6_client_address_assignment" in ipv6
    # Keys are the IPv6-prefixed subset only.
    assert all(k.startswith("ipv6_") for k in ipv6)


async def test_get_network_details_dhcp_section(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_network_details", {"name": "Default"})
    dhcp = result["dhcp"]
    assert "dhcpd_start" in dhcp
    assert "dhcpd_stop" in dhcp
    assert all(k.startswith(("dhcpd_", "dhcpdv6_")) for k in dhcp)


async def test_get_network_details_requires_selector(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_network_details", {})
    assert "error" in result
    assert "network_id or name" in result["error"]


async def test_get_network_details_id_not_found(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_network_details", {"network_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_get_network_details_name_not_found(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_network_details", {"name": "Nonexistent"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_get_network_details_ambiguous_name(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    # Force two networks with the same name.
    stub_state.networks.append({"_id": "dup1", "name": "Default", "purpose": "corporate"})
    result = await _call(stub_server, "get_network_details", {"name": "Default"})
    assert "error" in result
    assert "multiple networks" in result["error"]


async def test_get_network_details_id_wins_over_name(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    nid = stub_state.list_networks()[1]["_id"]  # the WAN ("Internet 1")
    result = await _call(stub_server, "get_network_details", {"network_id": nid, "name": "Default"})
    assert result["network"]["_id"] == nid


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_network_details(real_server: FastMCP) -> None:
    record = {
        "_id": "net1",
        "name": "Default",
        "purpose": "corporate",
        "ip_subnet": "192.168.1.1/24",
        "dhcpd_enabled": True,
        "dhcpd_start": "192.168.1.100",
        "ipv6_interface_type": "pd",
        "ipv6_ra_enabled": True,
        "ipv6_pd_start": "::2",
        "ipv6_pd_stop": "::7d1",
    }
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [record]})
    )
    result = await _call(real_server, "get_network_details", {"network_id": "net1"})
    assert result["network"]["name"] == "Default"
    assert result["ipv6"]["ipv6_pd_start"] == "::2"
    assert result["ipv6"]["ipv6_pd_stop"] == "::7d1"
    assert result["dhcp"]["dhcpd_start"] == "192.168.1.100"


@respx.mock
async def test_real_get_network_details_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_network_details", {"network_id": "net1"})
    assert "error" in result
