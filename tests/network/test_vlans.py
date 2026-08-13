"""Tests for ``mcp_unifi.modules.network.vlans``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged;
fixtures (``stub_server``, ``real_server``) and helpers (``BASE``, ``_call``)
come from ``tests/network/conftest.py``.
"""

from __future__ import annotations

import json

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
    # Seed (LAN + WAN) + the created VLAN.
    assert len(stub_state.list_networks()) == 3


async def test_create_vlan_normalizes_network_form_subnet(stub_server: FastMCP) -> None:
    """Accept network form (10.0.50.0/24) and promote to gateway form (10.0.50.1/24)."""
    result = await _call(
        stub_server,
        "create_vlan",
        {"name": "IoT", "vlan_id": 50, "subnet": "10.0.50.0/24"},
    )
    assert result["ip_subnet"] == "10.0.50.1/24"


async def test_create_vlan_accepts_gateway_form_subnet(stub_server: FastMCP) -> None:
    """Gateway form (10.0.50.1/24) passes through unchanged."""
    result = await _call(
        stub_server,
        "create_vlan",
        {"name": "IoT", "vlan_id": 51, "subnet": "10.0.51.1/24"},
    )
    assert result["ip_subnet"] == "10.0.51.1/24"


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
    assert result["network"]["name"] == "Renamed"
    assert result["verification"]["verified"] is True
    assert result["verification"]["persisted_fields"] == ["name"]


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
    # v0.7.0: delete_vlan returns a preview envelope; commit via confirm.
    preview = await _call(stub_server, "delete_vlan", {"network_id": created["_id"]})
    assert preview["preview"] is True
    assert preview["action"] == "delete_vlan"
    assert preview["resource"]["_id"] == created["_id"]
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True


async def test_delete_vlan_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_vlan", {"network_id": "ghost"})
    # No preview is minted when the lookup fails.
    assert "error" in result
    assert "not found" in result["error"]


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
    # Verification re-reads the collection before and after the write.
    respx.get(f"{BASE}/rest/networkconf").mock(
        side_effect=[
            httpx.Response(200, json={"data": [{"_id": "n1", "name": "Old"}]}),
            httpx.Response(200, json={"data": [{"_id": "n1", "name": "Up"}]}),
        ]
    )
    respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "Up"}]})
    )
    result = await _call(
        real_server,
        "update_vlan",
        {"network_id": "n1", "updates": {"name": "Up"}},
    )
    assert result["network"]["name"] == "Up"
    assert result["verification"]["verified"] is True


@respx.mock
async def test_real_delete_vlan(real_server: FastMCP) -> None:
    # v0.7.0: delete previews via list_networks first, then commits via
    # confirm_destructive_action which hits the actual DELETE endpoint.
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "X"}]})
    )
    respx.delete(f"{BASE}/rest/networkconf/n1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_vlan", {"network_id": "n1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
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
    respx.get(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(200, json={"data": []}))
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
    # v0.7.0: 409 surfaces during confirm. Preview needs a list lookup first.
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "X"}]})
    )
    respx.delete(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(409, text="referenced by SSID")
    )
    preview = await _call(real_server, "delete_vlan", {"network_id": "n1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" in result


@respx.mock
async def test_list_networks_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_networks")
    assert "error" in result


# ---------------------------------------------------------------------------
# Read-path redaction
#
# ``list_networks`` and ``get_network_details`` return ``networkconf`` records,
# which on a gateway running any VPN carry key material. Both returned it in
# cleartext until 0.19.2. ``get_network_details`` is the worse of the two: it
# emits a ``vpn`` section built by substring-matching ``"vpn"`` in the key name
# *and* a ``raw`` copy of the entire record.
# ---------------------------------------------------------------------------

VPN_NETWORK_SECRETS = {
    "x_ipsec_pre_shared_key": "ipsec-psk-do-not-leak",
    "x_preshared_key": "wireguard-psk-do-not-leak",
    "x_private_key": "wireguard-private-do-not-leak",
    "x_secret": "radius-secret-do-not-leak",
}


def _seed_vpn_network(stub_state: StubState) -> str:
    """Add a site-to-site VPN network carrying every secret field. Returns its id."""
    record = stub_state.create_network(
        {
            "name": "Site-to-Site",
            "purpose": "site-vpn",
            "vpn_type": "ipsec-vpn",
            "radiusprofile_id": "6501aaaabbbbccccdddd0001",
            **VPN_NETWORK_SECRETS,
        }
    )
    return str(record["_id"])


async def test_list_networks_redacts_vpn_key_material(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    _seed_vpn_network(stub_state)

    nets = await _call(stub_server, "list_networks")
    vpn = next(n for n in nets if n["name"] == "Site-to-Site")

    for key in VPN_NETWORK_SECRETS:
        assert vpn[key] == "[REDACTED]", f"{key} leaked from list_networks"
    assert "do-not-leak" not in json.dumps(nets)

    # The RADIUS profile reference is not a secret and callers resolve it.
    assert vpn["radiusprofile_id"] == "6501aaaabbbbccccdddd0001"


async def test_get_network_details_redacts_every_section(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = _seed_vpn_network(stub_state)

    result = await _call(stub_server, "get_network_details", {"network_id": net_id})

    # Note where the key material actually lands. The ``vpn`` section is built
    # by substring-matching ``"vpn"`` in the key name, and not one of UniFi's
    # VPN secret fields contains that substring — they reach the caller through
    # ``raw``, which is the whole record by design ("so nothing is hidden").
    for key in VPN_NETWORK_SECRETS:
        assert result["raw"][key] == "[REDACTED]", f"{key} leaked from the raw section"
    assert "do-not-leak" not in json.dumps(result)

    # ``radiusprofile_id`` lands in the vpn section by prefix match; it must
    # survive so the caller can still resolve the profile.
    assert result["vpn"]["radiusprofile_id"] == "6501aaaabbbbccccdddd0001"
    assert result["vpn"]["vpn_type"] == "ipsec-vpn"
    assert result["network"]["name"] == "Site-to-Site"
