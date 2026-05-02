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
