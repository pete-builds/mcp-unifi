"""Tests for ``mcp_unifi.modules.network.composites``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
Covers create_iot_network, create_guest_network, provision_homelab_service,
quarantine_client across stub and real (respx-mocked) modes, including every
rollback path.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server
from tests.network.conftest import BASE, _call

# v2 AP-groups endpoint sits at /v2/api/site/<site>/apgroups (not under BASE,
# which targets the legacy /api/s/<site>/... prefix). create_wlan resolves the
# default group via this endpoint before POSTing /rest/wlanconf, so every
# real-mode composite that exercises WLAN creation must mock it.
APGROUPS_URL = "https://gateway.test:443/proxy/network/v2/api/site/default/apgroups"
_DEFAULT_APGROUPS_BODY = [{"_id": "apg-default", "attr_hidden_id": "default", "name": "Default"}]


def _mock_default_apgroups() -> None:
    """Register a respx mock returning a single default AP group."""
    respx.get(APGROUPS_URL).mock(return_value=httpx.Response(200, json=_DEFAULT_APGROUPS_BODY))


# ---------------------------------------------------------------------------
# create_iot_network — stub
# ---------------------------------------------------------------------------


async def test_create_iot_network_happy_path(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 20, "passphrase": "iot-pass-1234"},
    )
    assert result["network"]["name"] == "IoT"
    assert result["wlan"]["name"] == "IoT"
    assert result["wlan"]["x_passphrase"] == "[REDACTED]"
    assert result["firewall_rule"]["name"] == "Block IoT -> Main LAN"
    assert result["firewall_rule"]["src_address"] == "10.0.20.0/24"
    assert "iot-pass-1234" not in json.dumps(result)
    # State should reflect all three resources. Networks: seed LAN + seed WAN
    # + the created IoT network.
    assert len(stub_state.list_networks()) == 3
    assert len(stub_state.list_wlans()) == 2
    assert len(stub_state.list_firewall_rules()) == 2


async def test_create_iot_network_no_isolation(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "create_iot_network",
        {
            "name": "Trusted",
            "vlan_id": 25,
            "passphrase": "trust-pass-99",
            "isolate": False,
        },
    )
    assert result["firewall_rule"] is None
    assert len(stub_state.list_firewall_rules()) == 1  # only the seed rule


async def test_create_iot_network_validates_vlan_range(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_iot_network",
        {"name": "Bad", "vlan_id": 0, "passphrase": "x"},
    )
    assert "out of range" in result["error"]


async def test_create_iot_network_rollback_on_wlan_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If WLAN creation fails after VLAN, the VLAN must be rolled back."""
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated WLAN failure")

    monkeypatch.setattr(stub_state, "create_wlan", boom)

    server = build_server(stub_settings, stub=stub_state)
    result = await _call(
        server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 30, "passphrase": "iot-pass-x"},
    )
    assert "WLAN" in result["error"] or "wlan" in result["error"]
    assert result["partial"]["network"] is not None
    assert result["partial"]["wlan"] is None
    # VLAN should be cleaned up in rollback, leaving the seed (LAN + WAN).
    assert len(stub_state.list_networks()) == 2
    assert any(
        action.get("network") == result["partial"]["network"]["_id"]
        for action in result["rolled_back"]
    )


async def test_create_iot_network_rollback_on_firewall_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If firewall creation fails, both the WLAN AND VLAN must be rolled back."""
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated firewall failure")

    monkeypatch.setattr(stub_state, "create_firewall_rule", boom)

    server = build_server(stub_settings, stub=stub_state)
    result = await _call(
        server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 40, "passphrase": "iot-pass-y"},
    )
    assert "firewall" in result["error"].lower()
    assert result["partial"]["network"] is not None
    assert result["partial"]["wlan"] is not None
    # Both VLAN and WLAN should be cleaned up, leaving the seed (LAN + WAN).
    assert len(stub_state.list_networks()) == 2
    assert len(stub_state.list_wlans()) == 1
    rolled_kinds = {next(iter(action.keys() - {"deleted"})) for action in result["rolled_back"]}
    assert "wlan" in rolled_kinds
    assert "network" in rolled_kinds


async def test_create_iot_network_rollback_on_vlan_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If VLAN creation itself fails, nothing was created and rollback is empty."""
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated VLAN failure")

    monkeypatch.setattr(stub_state, "create_network", boom)

    server = build_server(stub_settings, stub=stub_state)
    result = await _call(
        server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 50, "passphrase": "iot-pass-z"},
    )
    assert "vlan" in result["error"].lower() or "VLAN" in result["error"]
    assert result["partial"]["network"] is None
    assert result["rolled_back"] == []


async def test_create_iot_network_subnet_override(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    result = await _call(
        stub_server,
        "create_iot_network",
        {
            "name": "Custom",
            "vlan_id": 80,
            "passphrase": "custom-pass",
            "subnet": "172.16.80.0/24",
            "main_lan_subnet": "172.16.0.0/24",
        },
    )
    # v0.6.0: ip_subnet normalizes to gateway form so the controller stops
    # silently rewriting (or refusing) the network-form input.
    assert result["network"]["ip_subnet"] == "172.16.80.1/24"
    # Firewall src/dst stay in network form so the rules read naturally.
    assert result["firewall_rule"]["src_address"] == "172.16.80.0/24"
    assert result["firewall_rule"]["dst_address"] == "172.16.0.0/24"


# ---------------------------------------------------------------------------
# create_iot_network — real
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_iot_network_full_flow(real_server: FastMCP) -> None:
    _mock_default_apgroups()
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "net-id"}]})
    )
    respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "wlan-id"}]})
    )
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "fw-id"}]})
    )
    result = await _call(
        real_server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 30, "passphrase": "real-pass"},
    )
    assert result["network"]["_id"] == "net-id"
    assert result["wlan"]["_id"] == "wlan-id"
    assert result["firewall_rule"]["_id"] == "fw-id"


@respx.mock
async def test_real_iot_network_rolls_back_on_wlan_failure(
    real_server: FastMCP,
) -> None:
    _mock_default_apgroups()
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "rb-net"}]})
    )
    respx.post(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500, text="boom"))
    delete_route = respx.delete(f"{BASE}/rest/networkconf/rb-net").mock(
        return_value=httpx.Response(200)
    )
    result = await _call(
        real_server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 40, "passphrase": "real-pass-2"},
    )
    assert "wlan" in result["error"].lower()
    assert delete_route.called  # rollback ran
    assert any(a.get("network") == "rb-net" for a in result["rolled_back"])


@respx.mock
async def test_real_iot_network_rolls_back_firewall_and_wlan(
    real_server: FastMCP,
) -> None:
    """Firewall rule fails after WLAN: both WLAN and VLAN must be cleaned up."""
    _mock_default_apgroups()
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "rb-net"}]})
    )
    respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "rb-wlan"}]})
    )
    respx.post(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(500, text="fw boom"))
    wlan_delete = respx.delete(f"{BASE}/rest/wlanconf/rb-wlan").mock(
        return_value=httpx.Response(200)
    )
    net_delete = respx.delete(f"{BASE}/rest/networkconf/rb-net").mock(
        return_value=httpx.Response(200)
    )
    result = await _call(
        real_server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 60, "passphrase": "rb-pass"},
    )
    assert "firewall" in result["error"].lower()
    assert wlan_delete.called
    assert net_delete.called
    rolled_kinds = {next(iter(a.keys() - {"deleted"})) for a in result["rolled_back"]}
    assert rolled_kinds == {"wlan", "network"}


@respx.mock
async def test_real_iot_network_rollback_records_delete_failure(
    real_server: FastMCP,
) -> None:
    """Rollback should be best-effort: delete failures are logged, not raised."""
    _mock_default_apgroups()
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "stuck-net"}]})
    )
    respx.post(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500, text="wlan boom"))
    # Rollback delete also fails — the response should still come back cleanly.
    respx.delete(f"{BASE}/rest/networkconf/stuck-net").mock(
        return_value=httpx.Response(409, text="cannot delete")
    )
    result = await _call(
        real_server,
        "create_iot_network",
        {"name": "IoT", "vlan_id": 70, "passphrase": "stuck-pass"},
    )
    assert "wlan" in result["error"].lower()
    # The delete attempt should be recorded with deleted=False
    network_actions = [a for a in result["rolled_back"] if "network" in a]
    assert network_actions and network_actions[0]["deleted"] is False


# ---------------------------------------------------------------------------
# provision_homelab_service — stub
# ---------------------------------------------------------------------------


async def test_provision_homelab_service_lan_only(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "Pi-hole",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.53",
            "network_id": net_id,
            "ports": [53, 80],
        },
    )
    assert result["lease"]["fixed_ip"] == "192.168.1.53"
    assert result["firewall_rule"] is not None
    assert result["firewall_rule"]["dst_address"] == "192.168.1.53/32"
    assert result["port_forwards"] == []


async def test_provision_homelab_service_with_wan_expose(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "Web",
            "mac": "aa:bb:cc:dd:ee:01",
            "ip": "192.168.1.99",
            "network_id": net_id,
            "ports": [80, 443],
            "wan_expose": True,
        },
    )
    assert len(result["port_forwards"]) == 2
    ports = {pf["fwd_port"] for pf in result["port_forwards"]}
    assert ports == {"80", "443"}


async def test_provision_homelab_service_no_ports(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "Storage",
            "mac": "aa:bb:cc:dd:ee:02",
            "ip": "192.168.1.20",
            "network_id": net_id,
        },
    )
    assert result["lease"] is not None
    assert result["firewall_rule"] is None
    assert result["port_forwards"] == []


async def test_provision_homelab_service_rollback_on_firewall_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If firewall creation fails after the lease, the lease is rolled back."""
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated firewall failure")

    monkeypatch.setattr(stub_state, "create_firewall_rule", boom)

    server = build_server(stub_settings, stub=stub_state)
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        server,
        "provision_homelab_service",
        {
            "name": "Pi",
            "mac": "aa:bb:cc:dd:ee:03",
            "ip": "192.168.1.77",
            "network_id": net_id,
            "ports": [80],
        },
    )
    assert "firewall" in result["error"].lower()
    # The lease should have been rolled back.
    assert all(lease["fixed_ip"] != "192.168.1.77" for lease in stub_state.list_dhcp_leases())
    rolled_kinds = {next(iter(a.keys() - {"deleted"})) for a in result["rolled_back"]}
    assert "dhcp_lease" in rolled_kinds


async def test_provision_homelab_service_rollback_on_port_forward_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a port-forward fails, the firewall rule and lease must both roll back."""
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated port-forward failure")

    monkeypatch.setattr(stub_state, "create_port_forward", boom)

    server = build_server(stub_settings, stub=stub_state)
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        server,
        "provision_homelab_service",
        {
            "name": "App",
            "mac": "aa:bb:cc:dd:ee:04",
            "ip": "192.168.1.88",
            "network_id": net_id,
            "ports": [80, 443],
            "wan_expose": True,
        },
    )
    assert "port_forward" in result["error"].lower() or "port-forward" in result["error"].lower()
    rolled_kinds = {next(iter(a.keys() - {"deleted"})) for a in result["rolled_back"]}
    assert "dhcp_lease" in rolled_kinds
    assert "firewall_rule" in rolled_kinds


async def test_provision_homelab_service_rollback_on_lease_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lease failure means nothing was created and rollback is empty."""
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated lease failure")

    monkeypatch.setattr(stub_state, "create_dhcp_lease", boom)

    server = build_server(stub_settings, stub=stub_state)
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        server,
        "provision_homelab_service",
        {
            "name": "X",
            "mac": "aa:bb:cc:dd:ee:05",
            "ip": "192.168.1.55",
            "network_id": net_id,
            "ports": [22],
        },
    )
    assert "lease" in result["error"].lower()
    assert result["partial"]["lease"] is None
    assert result["rolled_back"] == []


# ---------------------------------------------------------------------------
# quarantine_client — stub
# ---------------------------------------------------------------------------


async def test_quarantine_client_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "quarantine_client",
        {"mac": "aa:bb:cc:00:00:04", "reason": "suspicious DNS traffic"},
    )
    assert result["quarantined"] is True
    assert result["mac"] == "aa:bb:cc:00:00:04"


async def test_quarantine_client_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "quarantine_client",
        {"mac": "ff:ff:ff:ff:ff:ff", "reason": ""},
    )
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# create_guest_network — stub
# ---------------------------------------------------------------------------


async def test_create_guest_network_happy_path(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "create_guest_network",
        {
            "name": "Guest",
            "ssid": "Guest WiFi",
            "passphrase": "guestpass1",
            "vlan_id": 90,
            "schedule": "weekdays-9-17",
        },
    )
    assert result["network"]["purpose"] == "guest"
    assert result["wlan"]["is_guest"] is True
    assert result["wlan"]["schedule"] == "weekdays-9-17"
    assert result["firewall_rule"]["src_address"] == "10.0.90.0/24"


async def test_create_guest_network_validates_vlan(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_guest_network",
        {"name": "X", "ssid": "X", "passphrase": "p", "vlan_id": 1},
    )
    assert "out of range" in result["error"]


async def test_create_guest_network_rollback_on_wlan_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated WLAN failure")

    monkeypatch.setattr(stub_state, "create_wlan", boom)

    server = build_server(stub_settings, stub=stub_state)
    result = await _call(
        server,
        "create_guest_network",
        {
            "name": "Guest",
            "ssid": "GW",
            "passphrase": "p",
            "vlan_id": 91,
        },
    )
    assert "wlan" in result["error"].lower()
    # VLAN should be rolled back, leaving the seed (LAN + WAN).
    assert len(stub_state.list_networks()) == 2


async def test_create_guest_network_rollback_on_vlan_failure(
    stub_settings: Settings, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_unifi.clients.unifi import UniFiError

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise UniFiError("simulated VLAN failure")

    monkeypatch.setattr(stub_state, "create_network", boom)

    server = build_server(stub_settings, stub=stub_state)
    result = await _call(
        server,
        "create_guest_network",
        {"name": "Guest", "ssid": "GW", "passphrase": "p", "vlan_id": 92},
    )
    assert "vlan" in result["error"].lower()
    assert result["rolled_back"] == []


# ---------------------------------------------------------------------------
# Composites — real
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_provision_homelab_service_full_flow(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/user").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "lease1"}]})
    )
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "fw1"}]})
    )
    respx.post(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf1"}]})
    )
    result = await _call(
        real_server,
        "provision_homelab_service",
        {
            "name": "Web",
            "mac": "aa:bb:cc:dd:ee:01",
            "ip": "192.168.1.99",
            "network_id": "n1",
            "ports": [80],
            "wan_expose": True,
        },
    )
    assert result["lease"]["_id"] == "lease1"
    assert result["firewall_rule"]["_id"] == "fw1"
    assert len(result["port_forwards"]) == 1


@respx.mock
async def test_real_provision_homelab_service_rolls_back_on_pf_failure(
    real_server: FastMCP,
) -> None:
    respx.post(f"{BASE}/rest/user").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "lease-x"}]})
    )
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "fw-x"}]})
    )
    respx.post(f"{BASE}/rest/portforward").mock(return_value=httpx.Response(500, text="boom"))
    fw_delete = respx.delete(f"{BASE}/rest/firewallrule/fw-x").mock(
        return_value=httpx.Response(200)
    )
    lease_delete = respx.delete(f"{BASE}/rest/user/lease-x").mock(return_value=httpx.Response(200))
    result = await _call(
        real_server,
        "provision_homelab_service",
        {
            "name": "Web",
            "mac": "aa:bb:cc:dd:ee:02",
            "ip": "192.168.1.97",
            "network_id": "n1",
            "ports": [80],
            "wan_expose": True,
        },
    )
    assert "error" in result
    assert fw_delete.called
    assert lease_delete.called


@respx.mock
async def test_real_create_guest_network_full_flow(real_server: FastMCP) -> None:
    _mock_default_apgroups()
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "gn"}]})
    )
    respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "gw"}]})
    )
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "gfw"}]})
    )
    result = await _call(
        real_server,
        "create_guest_network",
        {
            "name": "G",
            "ssid": "GS",
            "passphrase": "guestpass1",
            "vlan_id": 95,
        },
    )
    assert result["network"]["_id"] == "gn"
    assert result["wlan"]["_id"] == "gw"
    assert result["firewall_rule"]["_id"] == "gfw"


@respx.mock
async def test_real_quarantine_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(
        return_value=httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})
    )
    result = await _call(
        real_server,
        "quarantine_client",
        {"mac": "aa:bb:cc:00:00:01", "reason": "test"},
    )
    assert result["quarantined"] is True


@respx.mock
async def test_real_quarantine_client_handles_error(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "quarantine_client",
        {"mac": "aa:bb:cc:00:00:01", "reason": "test"},
    )
    assert "error" in result
