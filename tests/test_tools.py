"""End-to-end MCP tool tests in stub mode and real mode.

These exercise the full ``build_server`` factory the same way Claude Code
would: name a tool, pass JSON args, parse the JSON response. Real-mode tests
mock the gateway HTTP layer with respx, so no network is required.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiClient
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

BASE = "https://gateway.test:443/proxy/network/api/s/default"


def _text(result: Any) -> str:
    """Extract the text payload from a FastMCP ToolResult."""
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


# ---------------------------------------------------------------------------
# Stub mode — full coverage of every tool
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_server(stub_settings: Settings, stub_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=stub_state)


async def test_list_devices_stub(stub_server: FastMCP) -> None:
    devices = await _call(stub_server, "list_devices")
    assert any(d["model"] == "UCGFiber" for d in devices)


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


async def test_list_wlans_stub(stub_server: FastMCP) -> None:
    wlans = await _call(stub_server, "list_wlans")
    assert wlans[0]["name"] == "Home"


async def test_create_wlan_redacts_passphrase(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {
            "name": "TestSSID",
            "passphrase": "supersecret-do-not-leak",
            "network_id": net_id,
        },
    )
    assert result["x_passphrase"] == "[REDACTED]"
    assert "supersecret-do-not-leak" not in json.dumps(result)


async def test_create_wlan_open_security_omits_passphrase(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {
            "name": "OpenSSID",
            "passphrase": "ignored",
            "network_id": net_id,
            "security": "open",
        },
    )
    assert "x_passphrase" not in result


async def test_list_firewall_rules_stub(stub_server: FastMCP) -> None:
    rules = await _call(stub_server, "list_firewall_rules")
    assert rules[0]["ruleset"] == "WAN_IN"


async def test_create_firewall_rule_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_firewall_rule",
        {
            "name": "Block IoT",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_address": "10.0.20.0/24",
            "dst_address": "192.168.1.0/24",
        },
    )
    assert result["src_address"] == "10.0.20.0/24"
    assert result["action"] == "drop"


async def test_list_port_profiles_stub(stub_server: FastMCP) -> None:
    profiles = await _call(stub_server, "list_port_profiles")
    assert {p["name"] for p in profiles} == {"All", "Disabled"}


# ---------------------------------------------------------------------------
# update_wlan, delete_wlan, delete_firewall_rule, list_clients (new in 0.2.0)
# ---------------------------------------------------------------------------


async def test_update_wlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": wlan_id, "updates": {"name": "Renamed", "hide_ssid": True}},
    )
    assert result["name"] == "Renamed"
    assert result["hide_ssid"] is True


async def test_update_wlan_redacts_passphrase(stub_server: FastMCP, stub_state: StubState) -> None:
    """Updating x_passphrase via update_wlan should redact in the response."""
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": wlan_id, "updates": {"x_passphrase": "rotated-secret-xyz"}},
    )
    assert result["x_passphrase"] == "[REDACTED]"
    assert "rotated-secret-xyz" not in json.dumps(result)


async def test_update_wlan_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": "ghost", "updates": {"name": "X"}},
    )
    assert "not found" in result["error"]


async def test_delete_wlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(stub_server, "delete_wlan", {"wlan_id": wlan_id})
    assert result["deleted"] is True
    assert result["wlan_id"] == wlan_id
    assert stub_state.list_wlans() == []


async def test_delete_wlan_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_wlan", {"wlan_id": "ghost"})
    assert result["deleted"] is False


async def test_delete_firewall_rule_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    result = await _call(stub_server, "delete_firewall_rule", {"rule_id": rule_id})
    assert result["deleted"] is True
    assert result["rule_id"] == rule_id
    assert stub_state.list_firewall_rules() == []


async def test_delete_firewall_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_firewall_rule", {"rule_id": "ghost"})
    assert result["deleted"] is False


async def test_list_clients_stub(stub_server: FastMCP) -> None:
    """Stub mode should return a realistic mix of wireless and wired clients."""
    clients = await _call(stub_server, "list_clients")
    assert isinstance(clients, list)
    assert 3 <= len(clients) <= 5
    by_mac = {c["mac"]: c for c in clients}
    # Required fields on every client
    for c in clients:
        assert {"_id", "mac", "hostname", "ip", "is_wired", "last_seen"}.issubset(c)
    # At least one wireless client with signal/satisfaction
    wireless = [c for c in clients if not c["is_wired"]]
    assert wireless, "stub data should include at least one wireless client"
    assert all("signal" in c and "satisfaction" in c for c in wireless)
    # At least one wired client
    wired = [c for c in clients if c["is_wired"]]
    assert wired, "stub data should include at least one wired client"
    # Sanity: known seed MACs are present
    assert "aa:bb:cc:00:00:01" in by_mac


# ---------------------------------------------------------------------------
# create_iot_network — happy path + every rollback path
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
    # State should reflect all three resources.
    assert len(stub_state.list_networks()) == 2
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
    # VLAN should be cleaned up in rollback
    assert len(stub_state.list_networks()) == 1
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
    # Both VLAN and WLAN should be cleaned up
    assert len(stub_state.list_networks()) == 1
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
    assert result["network"]["ip_subnet"] == "172.16.80.0/24"
    assert result["firewall_rule"]["src_address"] == "172.16.80.0/24"
    assert result["firewall_rule"]["dst_address"] == "172.16.0.0/24"


# ---------------------------------------------------------------------------
# Real mode — exercise the HTTP path through respx
# ---------------------------------------------------------------------------


@pytest.fixture
async def real_server(real_settings: Settings) -> FastMCP:
    client = UniFiClient(
        host=real_settings.unifi_host,
        api_key=real_settings.unifi_api_key,
        port=real_settings.unifi_port,
        site=real_settings.unifi_site,
    )
    server = build_server(real_settings, unifi=client)
    yield server
    await client.aclose()


@respx.mock
async def test_real_list_devices(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "x", "model": "UCGFiber"}]})
    )
    devices = await _call(real_server, "list_devices")
    assert devices[0]["model"] == "UCGFiber"


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
async def test_real_iot_network_full_flow(real_server: FastMCP) -> None:
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
async def test_real_list_devices_error_returns_structured_error(
    real_server: FastMCP,
) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(401, text="Unauthorized"))
    result = await _call(real_server, "list_devices")
    assert "error" in result
    assert "401" in result["error"]
    assert result["stub_mode"] is False


@respx.mock
async def test_real_list_networks(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n", "name": "X"}]})
    )
    result = await _call(real_server, "list_networks")
    assert result[0]["name"] == "X"


@respx.mock
async def test_real_list_wlans(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w"}]})
    )
    result = await _call(real_server, "list_wlans")
    assert result[0]["_id"] == "w"


@respx.mock
async def test_real_list_firewall_rules(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r"}]})
    )
    result = await _call(real_server, "list_firewall_rules")
    assert result[0]["_id"] == "r"


@respx.mock
async def test_real_list_port_profiles(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p"}]})
    )
    result = await _call(real_server, "list_port_profiles")
    assert result[0]["_id"] == "p"


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
async def test_real_create_wlan(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1"}]})
    )
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert result["_id"] == "w1"


@respx.mock
async def test_real_create_firewall_rule(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "f1"}]})
    )
    result = await _call(
        real_server,
        "create_firewall_rule",
        {"name": "R", "ruleset": "LAN_IN", "action": "drop"},
    )
    assert result["_id"] == "f1"


@respx.mock
async def test_real_update_wlan(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/wlanconf/w1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "Renamed"}]})
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "w1", "updates": {"name": "Renamed"}},
    )
    assert result["name"] == "Renamed"


@respx.mock
async def test_real_delete_wlan(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_wlan", {"wlan_id": "w1"})
    assert result["deleted"] is True
    assert result["wlan_id"] == "w1"


@respx.mock
async def test_real_delete_firewall_rule(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/firewallrule/r1").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_firewall_rule", {"rule_id": "r1"})
    assert result["deleted"] is True
    assert result["rule_id"] == "r1"


@respx.mock
async def test_real_list_clients(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "c1", "mac": "aa:bb:cc:00:00:01", "is_wired": False}]},
        )
    )
    result = await _call(real_server, "list_clients")
    assert result[0]["_id"] == "c1"


@respx.mock
async def test_real_list_clients_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_clients")
    assert "error" in result


@respx.mock
async def test_real_update_wlan_handles_404(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/wlanconf/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "missing", "updates": {"name": "X"}},
    )
    assert "error" in result


@respx.mock
async def test_real_delete_wlan_handles_409(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(409, text="in use"))
    result = await _call(real_server, "delete_wlan", {"wlan_id": "w1"})
    assert "error" in result


@respx.mock
async def test_real_delete_firewall_rule_handles_404(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/firewallrule/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(real_server, "delete_firewall_rule", {"rule_id": "missing"})
    assert "error" in result


# ---------------------------------------------------------------------------
# Error handling — make sure failures never crash the MCP loop
# ---------------------------------------------------------------------------


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
async def test_create_wlan_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert "error" in result


@respx.mock
async def test_create_firewall_rule_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_firewall_rule",
        {"name": "R", "ruleset": "LAN_IN", "action": "drop"},
    )
    assert "error" in result


@respx.mock
async def test_list_networks_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_networks")
    assert "error" in result


@respx.mock
async def test_list_wlans_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_wlans")
    assert "error" in result


@respx.mock
async def test_list_firewall_rules_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_firewall_rules")
    assert "error" in result


@respx.mock
async def test_list_port_profiles_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_port_profiles")
    assert "error" in result


@respx.mock
async def test_create_firewall_rule_with_networkconf_ids(real_server: FastMCP) -> None:
    """Cover the src_networkconf_id / dst_networkconf_id payload branches."""
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "fnet"}]})

    respx.post(f"{BASE}/rest/firewallrule").mock(side_effect=capture)
    result = await _call(
        real_server,
        "create_firewall_rule",
        {
            "name": "ByNet",
            "ruleset": "LAN_IN",
            "action": "accept",
            "src_networkconf_id": "src-id",
            "dst_networkconf_id": "dst-id",
        },
    )
    assert result["_id"] == "fnet"
    assert captured["body"]["src_networkconf_id"] == "src-id"
    assert captured["body"]["dst_networkconf_id"] == "dst-id"


@respx.mock
async def test_real_iot_network_rolls_back_firewall_and_wlan(
    real_server: FastMCP,
) -> None:
    """Firewall rule fails after WLAN: both WLAN and VLAN must be cleaned up."""
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


# ===========================================================================
# v0.3.0 tools — Tier 1 fills, Tier 2 ops, Tier 3 observability, Tier 4 composites
# ===========================================================================


# ---------------------------------------------------------------------------
# Tier 1: update_firewall_rule + port profile CRUD
# ---------------------------------------------------------------------------


async def test_update_firewall_rule_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    rule_id = stub_state.list_firewall_rules()[0]["_id"]
    result = await _call(
        stub_server,
        "update_firewall_rule",
        {"rule_id": rule_id, "updates": {"action": "drop"}},
    )
    assert result["action"] == "drop"


async def test_update_firewall_rule_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_firewall_rule",
        {"rule_id": "ghost", "updates": {"action": "drop"}},
    )
    assert "not found" in result["error"]


async def test_create_port_profile_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "create_port_profile",
        {"name": "PoE Cameras", "poe_mode": "auto", "forward": "native"},
    )
    assert result["name"] == "PoE Cameras"
    assert result["poe_mode"] == "auto"
    assert any(p["_id"] == result["_id"] for p in stub_state.list_port_profiles())


async def test_create_port_profile_with_tagged_vlans(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "create_port_profile",
        {
            "name": "Trunk",
            "native_networkconf_id": "n1",
            "tagged_networkconf_ids": ["n2", "n3"],
        },
    )
    assert result["tagged_networkconf_ids"] == ["n2", "n3"]
    assert result["native_networkconf_id"] == "n1"


async def test_update_port_profile_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    profile_id = stub_state.list_port_profiles()[0]["_id"]
    result = await _call(
        stub_server,
        "update_port_profile",
        {"profile_id": profile_id, "updates": {"poe_mode": "off"}},
    )
    assert result["poe_mode"] == "off"


async def test_update_port_profile_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_port_profile",
        {"profile_id": "ghost", "updates": {"poe_mode": "off"}},
    )
    assert "not found" in result["error"]


async def test_delete_port_profile_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    profile_id = stub_state.list_port_profiles()[0]["_id"]
    result = await _call(stub_server, "delete_port_profile", {"profile_id": profile_id})
    assert result["deleted"] is True


async def test_delete_port_profile_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_port_profile", {"profile_id": "ghost"})
    assert result["deleted"] is False


# ---------------------------------------------------------------------------
# Tier 2: client commands (block / unblock / reconnect)
# ---------------------------------------------------------------------------


async def test_block_unblock_client_stub(stub_server: FastMCP) -> None:
    blocked = await _call(stub_server, "block_client", {"mac": "aa:bb:cc:00:00:01"})
    assert blocked["blocked"] is True
    unblocked = await _call(stub_server, "unblock_client", {"mac": "aa:bb:cc:00:00:01"})
    assert unblocked["blocked"] is False


async def test_block_client_unknown(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "block_client", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_unblock_client_unknown(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "unblock_client", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_reconnect_client_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "reconnect_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["reconnected"] is True


async def test_reconnect_client_unknown(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "reconnect_client", {"mac": "00:00:00:00:00:00"})
    assert result["reconnected"] is False


# ---------------------------------------------------------------------------
# Tier 2: device commands (restart / locate / set_port_state)
# ---------------------------------------------------------------------------


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
# Tier 2: static DHCP leases
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
# Tier 2: port forward CRUD
# ---------------------------------------------------------------------------


async def test_list_port_forwards_stub(stub_server: FastMCP) -> None:
    pfs = await _call(stub_server, "list_port_forwards")
    assert isinstance(pfs, list)
    assert pfs[0]["name"] == "HTTPS to NAS"


async def test_create_update_delete_port_forward_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    created = await _call(
        stub_server,
        "create_port_forward",
        {
            "name": "SSH",
            "fwd": "192.168.1.10",
            "fwd_port": "22",
            "dst_port": "2222",
            "proto": "tcp",
        },
    )
    assert created["fwd_port"] == "22"

    updated = await _call(
        stub_server,
        "update_port_forward",
        {"forward_id": created["_id"], "updates": {"enabled": False}},
    )
    assert updated["enabled"] is False

    deleted = await _call(stub_server, "delete_port_forward", {"forward_id": created["_id"]})
    assert deleted["deleted"] is True


async def test_update_port_forward_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_port_forward",
        {"forward_id": "ghost", "updates": {"enabled": False}},
    )
    assert "not found" in result["error"]


async def test_delete_port_forward_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_port_forward", {"forward_id": "ghost"})
    assert result["deleted"] is False


# ---------------------------------------------------------------------------
# Tier 3: observability
# ---------------------------------------------------------------------------


async def test_get_site_health_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_site_health")
    subsystems = {h["subsystem"] for h in result}
    assert {"wan", "lan", "wlan"} <= subsystems


async def test_get_wan_status_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_status")
    assert result["subsystem"] == "wan"
    assert "xput_up" in result and "xput_down" in result


async def test_list_events_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_events", {"limit": 1})
    assert len(result) <= 1


async def test_list_events_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_events", {"limit": 0})
    assert "limit" in result["error"]


async def test_list_alarms_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_alarms", {"limit": 50, "archived": False})
    assert isinstance(result, list)


async def test_list_alarms_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_alarms", {"limit": 0})
    assert "limit" in result["error"]


async def test_speedtest_round_trip_stub(stub_server: FastMCP) -> None:
    triggered = await _call(stub_server, "trigger_speedtest")
    assert triggered["started"] is True
    results = await _call(stub_server, "get_speedtest_results", {"limit": 5})
    assert len(results) >= 1


async def test_get_speedtest_results_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_speedtest_results", {"limit": 0})
    assert "limit" in result["error"]


async def test_list_top_talkers_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_top_talkers", {"limit": 3})
    assert len(result) <= 3
    if result:
        assert result[0]["total_bytes"] >= result[-1]["total_bytes"]


async def test_list_top_talkers_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_top_talkers", {"limit": 0})
    assert "limit" in result["error"]


# ---------------------------------------------------------------------------
# Tier 4: composites
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
    # VLAN should be rolled back.
    assert len(stub_state.list_networks()) == 1


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


async def test_audit_open_ports_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "audit_open_ports")
    assert "port_forwards" in result
    assert "wan_accept_rules" in result
    assert "summary" in result
    # The seed has one HTTPS->NAS forward and one established/related WAN_IN
    # rule (filtered out). Audit should surface the forward, no accept rules.
    assert len(result["port_forwards"]) >= 1
    assert all(
        not (r.get("state_established") and r.get("state_related"))
        for r in result["wan_accept_rules"]
    )


async def test_audit_open_ports_flags_wan_accept_rule(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.create_firewall_rule(
        {
            "name": "Open SSH from anywhere",
            "ruleset": "WAN_IN",
            "rule_index": 2100,
            "action": "accept",
            "enabled": True,
            "protocol": "tcp",
        }
    )
    result = await _call(stub_server, "audit_open_ports")
    names = [r["name"] for r in result["wan_accept_rules"]]
    assert "Open SSH from anywhere" in names


# ---------------------------------------------------------------------------
# Real-mode HTTP coverage for v0.3.0 tools
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_update_firewall_rule(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/firewallrule/r1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r1", "action": "drop"}]})
    )
    result = await _call(
        real_server,
        "update_firewall_rule",
        {"rule_id": "r1", "updates": {"action": "drop"}},
    )
    assert result["action"] == "drop"


@respx.mock
async def test_real_update_firewall_rule_500(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/firewallrule/r1").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "update_firewall_rule",
        {"rule_id": "r1", "updates": {"action": "drop"}},
    )
    assert "error" in result


@respx.mock
async def test_real_create_port_profile(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/rest/portconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p1", "name": "PoE"}]})
    )
    result = await _call(real_server, "create_port_profile", {"name": "PoE"})
    assert result["_id"] == "p1"


@respx.mock
async def test_real_update_port_profile(real_server: FastMCP) -> None:
    respx.put(f"{BASE}/rest/portconf/p1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p1", "poe_mode": "off"}]})
    )
    result = await _call(
        real_server,
        "update_port_profile",
        {"profile_id": "p1", "updates": {"poe_mode": "off"}},
    )
    assert result["poe_mode"] == "off"


@respx.mock
async def test_real_delete_port_profile(real_server: FastMCP) -> None:
    respx.delete(f"{BASE}/rest/portconf/p1").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "delete_port_profile", {"profile_id": "p1"})
    assert result["deleted"] is True


@respx.mock
async def test_real_block_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(
        return_value=httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})
    )
    result = await _call(real_server, "block_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["mac"] == "aa:bb:cc:00:00:01"


@respx.mock
async def test_real_unblock_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(
        return_value=httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})
    )
    result = await _call(real_server, "unblock_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["mac"] == "aa:bb:cc:00:00:01"


@respx.mock
async def test_real_reconnect_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "reconnect_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["reconnected"] is True


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


@respx.mock
async def test_real_port_forward_crud(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf1"}]})
    )
    listed = await _call(real_server, "list_port_forwards")
    assert listed[0]["_id"] == "pf1"

    respx.post(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf2"}]})
    )
    created = await _call(
        real_server,
        "create_port_forward",
        {"name": "X", "fwd": "10.0.0.5", "fwd_port": "80", "dst_port": "80"},
    )
    assert created["_id"] == "pf2"

    respx.put(f"{BASE}/rest/portforward/pf2").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf2", "enabled": False}]})
    )
    updated = await _call(
        real_server, "update_port_forward", {"forward_id": "pf2", "updates": {"enabled": False}}
    )
    assert updated["enabled"] is False

    respx.delete(f"{BASE}/rest/portforward/pf2").mock(return_value=httpx.Response(200))
    deleted = await _call(real_server, "delete_port_forward", {"forward_id": "pf2"})
    assert deleted["deleted"] is True


@respx.mock
async def test_real_get_site_health(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"subsystem": "wan", "status": "ok"},
                    {"subsystem": "lan", "status": "ok"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_site_health")
    assert {h["subsystem"] for h in result} == {"wan", "lan"}


@respx.mock
async def test_real_get_wan_status_extracts_wan(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"subsystem": "lan", "status": "ok"},
                    {"subsystem": "wan", "status": "ok", "wan_ip": "1.2.3.4"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_wan_status")
    assert result["subsystem"] == "wan"
    assert result["wan_ip"] == "1.2.3.4"


@respx.mock
async def test_real_get_wan_status_unknown_when_missing(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(200, json={"data": [{"subsystem": "lan", "status": "ok"}]})
    )
    result = await _call(real_server, "get_wan_status")
    assert result["status"] == "unknown"


@respx.mock
async def test_real_list_events(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/event?_limit=5").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "e1"}]})
    )
    result = await _call(real_server, "list_events", {"limit": 5})
    assert result[0]["_id"] == "e1"


@respx.mock
async def test_real_list_alarms(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/alarm?archived=false&_limit=5").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "a1"}]})
    )
    result = await _call(real_server, "list_alarms", {"limit": 5, "archived": False})
    assert result[0]["_id"] == "a1"


@respx.mock
async def test_real_trigger_speedtest(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"started": True}]})

    respx.post(f"{BASE}/cmd/devmgr").mock(side_effect=capture)
    result = await _call(real_server, "trigger_speedtest")
    assert captured["body"]["cmd"] == "speedtest"
    assert result["started"] is True


@respx.mock
async def test_real_get_speedtest_results(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/report/archive.speedtest?_limit=3").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "s1"}, {"_id": "s2"}]})
    )
    result = await _call(real_server, "get_speedtest_results", {"limit": 3})
    assert len(result) == 2


@respx.mock
async def test_real_list_top_talkers(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sitedpi").mock(
        return_value=httpx.Response(
            200, json={"data": [{"mac": "aa", "rx_bytes": 100}, {"mac": "bb", "rx_bytes": 50}]}
        )
    )
    result = await _call(real_server, "list_top_talkers", {"limit": 1})
    assert len(result) == 1


@respx.mock
async def test_real_audit_open_ports(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "r1",
                        "ruleset": "WAN_IN",
                        "action": "accept",
                        "enabled": True,
                        "name": "Boilerplate",
                        "state_established": True,
                        "state_related": True,
                    },
                    {
                        "_id": "r2",
                        "ruleset": "WAN_IN",
                        "action": "accept",
                        "enabled": True,
                        "name": "Open SSH",
                    },
                ]
            },
        )
    )
    respx.get(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "pf1", "enabled": True, "name": "HTTPS to NAS"}]},
        )
    )
    result = await _call(real_server, "audit_open_ports")
    assert len(result["port_forwards"]) == 1
    names = [r["name"] for r in result["wan_accept_rules"]]
    assert names == ["Open SSH"]


@respx.mock
async def test_real_block_client_handles_error(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "block_client", {"mac": "aa:bb:cc:00:00:01"})
    assert "error" in result


@respx.mock
async def test_real_get_site_health_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_site_health")
    assert "error" in result


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
