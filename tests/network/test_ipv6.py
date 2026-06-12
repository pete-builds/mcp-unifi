"""Tests for the IPv6 tools: get_wan_ipv6, set_wan_ipv6, set_lan_ipv6.

Shape, dry-run before/after, validation, and the WAN/LAN guard rails, plus a
real-mode test proving the read-modify-write PUT carries only the IPv6 keys.

The split-module fixtures (``stub_server``, ``real_server``) and helpers
(``BASE``, ``_call``) come from ``tests/network/conftest.py``.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call


def _lan_id(state: StubState) -> str:
    lan = next(n for n in state.networks if n.get("purpose") == "corporate")
    return str(lan["_id"])


def _wan_id(state: StubState) -> str:
    wan = next(n for n in state.networks if n.get("purpose") == "wan")
    return str(wan["_id"])


# ---------------------------------------------------------------------------
# get_wan_ipv6 (read-only)
# ---------------------------------------------------------------------------


async def test_get_wan_ipv6_returns_keys(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_ipv6")
    assert result["controller"] == "default"
    wans = result["wan_ipv6"]
    assert len(wans) == 1
    wan = wans[0]
    assert wan["name"] == "Internet 1"
    assert wan["wan_type_v6"] == "disabled"
    assert wan["ipv6_wan_delegation_type"] == "none"
    assert "_id" in wan


async def test_get_wan_ipv6_filter_by_name(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_ipv6", {"wan_name": "Internet 1"})
    assert len(result["wan_ipv6"]) == 1


async def test_get_wan_ipv6_unknown_name_errors(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_ipv6", {"wan_name": "Nope"})
    assert "error" in result


# ---------------------------------------------------------------------------
# set_wan_ipv6 (mutating)
# ---------------------------------------------------------------------------


async def test_set_wan_ipv6_dry_run_diff(stub_server: FastMCP, stub_state: StubState) -> None:
    before = [dict(n) for n in stub_state.networks]
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {
            "connection_type": "dhcpv6",
            "prefix_delegation": "prefix-delegation",
            "pd_size": 56,
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    upd = result["would_update"]
    assert upd["action"] == "set_wan_ipv6"
    assert upd["before"]["wan_type_v6"] == "disabled"
    assert upd["after"]["wan_type_v6"] == "dhcpv6"
    assert upd["after"]["ipv6_wan_delegation_type"] == "prefix-delegation"
    assert upd["after"]["wan_dhcpv6_pd_size"] == 56
    assert upd["after"]["wan_dhcpv6_pd_size_auto"] is False
    assert "blast_radius" in result
    # Nothing mutated.
    assert [dict(n) for n in stub_state.networks] == before


async def test_set_wan_ipv6_applies(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6"},
    )
    assert result["updated"] is True
    assert result["after"]["wan_type_v6"] == "dhcpv6"
    # State actually changed.
    wan = next(n for n in stub_state.networks if n.get("purpose") == "wan")
    assert wan["wan_type_v6"] == "dhcpv6"


async def test_set_wan_ipv6_requires_a_field(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_wan_ipv6", {})
    assert "error" in result
    assert "at least one" in result["error"]


async def test_set_wan_ipv6_rejects_bad_type(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_wan_ipv6", {"connection_type": "ipv6plus"})
    assert "error" in result


async def test_set_wan_ipv6_rejects_bad_pd_size(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_wan_ipv6", {"pd_size": 32})
    assert "error" in result


# ---------------------------------------------------------------------------
# set_lan_ipv6 (mutating)
# ---------------------------------------------------------------------------


async def test_set_lan_ipv6_dry_run_diff(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    before = [dict(n) for n in stub_state.networks]
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "ra_enabled": True, "dry_run": True},
    )
    assert result["dry_run"] is True
    upd = result["would_update"]
    assert upd["action"] == "set_lan_ipv6"
    assert upd["before"]["ipv6_interface_type"] == "none"
    assert upd["after"]["ipv6_interface_type"] == "pd"
    assert upd["after"]["ipv6_ra_enabled"] is True
    assert [dict(n) for n in stub_state.networks] == before


async def test_set_lan_ipv6_applies(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "address_assignment": "dhcpv6"},
    )
    assert result["updated"] is True
    assert result["after"]["ipv6_interface_type"] == "pd"
    assert result["after"]["ipv6_client_address_assignment"] == "dhcpv6"


async def test_set_lan_ipv6_explicit_dns(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "dns_auto": False, "dns_servers": ["2606:4700:4700::1111"]},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["dhcpdv6_dns_auto"] is False
    assert lan["dhcpdv6_dns_1"] == "2606:4700:4700::1111"
    # Unused slots blanked so a shorter list clears stale servers.
    assert lan["dhcpdv6_dns_2"] == ""


async def test_set_lan_ipv6_rejects_wan_target(stub_server: FastMCP, stub_state: StubState) -> None:
    wan_id = _wan_id(stub_state)
    result = await _call(
        stub_server, "set_lan_ipv6", {"network_id": wan_id, "interface_type": "pd"}
    )
    assert "error" in result
    assert "set_wan_ipv6" in result["error"]


async def test_set_lan_ipv6_unknown_network(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "set_lan_ipv6", {"network_id": "nope", "interface_type": "pd"}
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_set_lan_ipv6_requires_a_field(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(stub_server, "set_lan_ipv6", {"network_id": lan_id})
    assert "error" in result
    assert "at least one" in result["error"]


async def test_set_lan_ipv6_rejects_bad_interface_type(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server, "set_lan_ipv6", {"network_id": lan_id, "interface_type": "magic"}
    )
    assert "error" in result


# ---------------------------------------------------------------------------
# Real-mode: prove read-modify-write PUTs only the IPv6 keys
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_set_lan_ipv6_puts_only_ipv6_keys(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "lan1",
                        "name": "Default",
                        "purpose": "corporate",
                        "ip_subnet": "192.168.1.1/24",
                        "ipv6_interface_type": "none",
                        "ipv6_ra_enabled": False,
                    }
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/networkconf/lan1").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "lan1", "ipv6_interface_type": "pd", "ipv6_ra_enabled": True}]},
        )
    )
    result = await _call(
        real_server,
        "set_lan_ipv6",
        {"network_id": "lan1", "interface_type": "pd", "ra_enabled": True},
    )
    assert result["updated"] is True
    assert put_route.called
    sent = put_route.calls[0].request
    import json as _json

    body = _json.loads(sent.content)
    # Strict read-modify-write: only IPv6 keys in the patch, no ip_subnet etc.
    assert body == {"ipv6_interface_type": "pd", "ipv6_ra_enabled": True}


@respx.mock
async def test_real_set_wan_ipv6_handles_404(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200, json={"data": [{"_id": "wan1", "name": "Internet 1", "purpose": "wan"}]}
        )
    )
    respx.put(f"{BASE}/rest/networkconf/wan1").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(real_server, "set_wan_ipv6", {"connection_type": "dhcpv6"})
    assert "error" in result
