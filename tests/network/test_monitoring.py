"""Contract tests for the bounded controller/site/device monitoring slice."""

from __future__ import annotations

import httpx
import respx

from tests.network.conftest import BASE, _call


async def test_controller_info_is_compact_and_redacted(stub_server) -> None:
    result = await _call(stub_server, "get_controller_info")

    assert result["controller"] == "default"
    assert result["site"] == "default"
    assert result["stub_mode"] is True
    assert set(result) <= {
        "controller", "site", "host", "port", "version", "build", "uptime", "stub_mode"
    }


async def test_sites_are_bounded_and_paginated(stub_server) -> None:
    result = await _call(stub_server, "list_sites", {"page": 1, "limit": 1})

    assert result["page"] == 1
    assert result["limit"] == 1
    assert result["total"] == 1
    assert result["items"] == [{"id": "default", "name": "default", "controller": "default"}]


async def test_site_health_is_bounded_and_filterable(stub_server) -> None:
    result = await _call(
        stub_server,
        "get_site_health_bounded",
        {"subsystem": "wan", "page": 1, "limit": 1},
    )

    assert result["total"] == 1
    assert result["items"][0]["subsystem"] == "wan"


async def test_devices_support_filters_and_return_a_bounded_projection(stub_server) -> None:
    result = await _call(
        stub_server,
        "list_devices_bounded",
        {"device_type": "uap", "status": "online", "page": 1, "limit": 1},
    )

    assert result["total"] == 1
    assert result["items"][0]["type"] == "uap"
    assert result["items"][0]["status"] == "online"
    assert set(result["items"][0]) <= {
        "id", "mac", "name", "type", "model", "firmware", "ip", "status",
        "adopted", "uptime", "cpu_pct", "memory_pct",
    }


async def test_device_details_requires_one_unambiguous_selector(stub_server) -> None:
    result = await _call(stub_server, "get_device_details")
    assert result["error_code"] == "ambiguous_target"


async def test_device_details_unknown_device_is_distinct(stub_server) -> None:
    result = await _call(stub_server, "get_device_details", {"mac": "00:00:00:00:00:00"})
    assert result["error_code"] == "not_found"


@respx.mock
async def test_bounded_devices_map_auth_failures_without_leaking_body(real_server) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(401, json={"message": "secret-api-key rejected"})
    )

    result = await _call(real_server, "list_devices_bounded")

    assert result["error_code"] == "authorization"
    assert "secret-api-key" not in str(result)
    assert result["stub_mode"] is False


async def test_invalid_pagination_is_rejected_before_backend(stub_server) -> None:
    result = await _call(stub_server, "list_devices_bounded", {"page": 0})
    assert result["error_code"] == "invalid_input"


async def test_clients_are_bounded_filterable_and_secret_free(stub_server) -> None:
    result = await _call(stub_server, "list_clients_bounded", {"wired": False, "limit": 1})
    assert result["total"] == 3
    assert len(result["items"]) == 1
    assert all(item["is_wired"] is False for item in result["items"])
    assert all("x_passphrase" not in item for item in result["items"])


async def test_networks_are_bounded_and_projected(stub_server) -> None:
    result = await _call(stub_server, "list_networks_bounded", {"purpose": "corporate"})
    assert result["total"] == 1
    assert set(result["items"][0]) <= {
        "_id", "name", "purpose", "vlan_enabled", "vlan", "ip_subnet", "dhcpd_enabled",
        "site_id", "enabled", "wan_networkgroup", "ipv6_interface_type",
    }


async def test_wlans_include_bounded_radio_facts_without_psk(stub_server) -> None:
    result = await _call(stub_server, "list_wlans_bounded")
    wlan = result["items"][0]
    assert wlan["name"] == "Home"
    assert wlan["radios"][0]["radio"] == "ng"
    assert "x_passphrase" not in str(result)


async def test_switch_ports_are_bounded_and_filterable(stub_server) -> None:
    result = await _call(
        stub_server,
        "list_switch_ports_bounded",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5},
    )
    assert result["total"] == 1
    assert result["items"][0]["port_idx"] == 5
    assert result["items"][0]["poe_mode"] == "auto"
    assert result["items"][0]["client_mac"] == "aa:bb:cc:00:00:03"


async def test_monitoring_surface_adds_no_mutation_aliases(stub_server) -> None:
    tools = await stub_server.list_tools()
    names = {tool.name for tool in tools}
    assert {
        "list_clients_bounded",
        "list_networks_bounded",
        "list_wlans_bounded",
        "list_switch_ports_bounded",
    } <= names
    assert "cycle_port_poe" not in names


async def test_bounded_wan_events_threat_and_firmware_contracts(stub_server) -> None:
    wan = await _call(stub_server, "get_wan_status_bounded")
    assert wan["subsystem"] == "wan"
    assert "isp_name" in wan
    traffic = await _call(stub_server, "get_wan_traffic_bounded")
    assert traffic["xput_up"] == 1820.5
    assert traffic["xput_down"] == 1985.2

    events = await _call(stub_server, "list_events_bounded", {"limit": 1})
    assert events["total"] == 2
    assert len(events["items"]) == 1
    assert "x_passphrase" not in str(events)

    threats = await _call(stub_server, "list_threat_signals_bounded")
    assert threats["total"] == 1
    assert threats["items"][0]["anomaly"] == "USER_HIGH_TCP_LATENCY"

    firmware = await _call(stub_server, "get_firmware_info")
    assert firmware["version"] == "10.4.57"
    assert firmware["update_available"] is False


async def test_bounded_alarm_and_firewall_are_explicitly_labelled(stub_server) -> None:
    alarms = await _call(stub_server, "list_alarms_bounded", {"limit": 1})
    assert alarms["total"] == 1
    assert alarms["items"][0]["archived"] is False

    firewall = await _call(stub_server, "inspect_firewall_bounded", {"limit": 1})
    assert firewall["legacy"]["total"] == 1
    assert firewall["zone_based"]["policies"]["total"] == 1
    assert len(firewall["zone_based"]["zones"]) == 2


async def test_new_monitoring_surface_is_read_only(stub_server) -> None:
    tools = {tool.name: tool for tool in await stub_server.list_tools()}
    names = {
        "get_wan_status_bounded", "list_events_bounded", "list_alarms_bounded",
        "list_threat_signals_bounded", "inspect_firewall_bounded", "get_firmware_info",
    }
    assert names <= tools.keys()
    for name in names:
        assert tools[name].annotations.readOnlyHint is True
        assert tools[name].annotations.destructiveHint is False


async def test_new_monitoring_pagination_is_bounded(stub_server) -> None:
    result = await _call(stub_server, "list_events_bounded", {"limit": 101})
    assert result["error_code"] == "invalid_input"
