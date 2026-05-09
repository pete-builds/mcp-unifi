"""Tests for the in-memory stub state machine."""

from __future__ import annotations

import pytest

from mcp_unifi.clients.stubs import StubState


def test_seed_data_present(stub_state: StubState) -> None:
    # v0.3.0 added a switch (USW24PoE) so port-state tools have a target.
    assert len(stub_state.list_devices()) == 3
    assert len(stub_state.list_networks()) == 1
    assert len(stub_state.list_wlans()) == 1
    assert len(stub_state.list_firewall_rules()) == 1
    assert len(stub_state.list_port_profiles()) == 2
    assert 3 <= len(stub_state.list_clients()) <= 5
    assert len(stub_state.list_dhcp_leases()) >= 1
    assert len(stub_state.list_port_forwards()) >= 1


def test_each_instance_is_independent() -> None:
    a = StubState()
    b = StubState()
    a.create_network({"name": "T1", "vlan": 5, "ip_subnet": "10.0.5.0/24"})
    assert len(a.list_networks()) == 2
    assert len(b.list_networks()) == 1


def test_devices_have_expected_shape(stub_state: StubState) -> None:
    devices = stub_state.list_devices()
    gateway = next(d for d in devices if d["type"] == "ugw")
    assert gateway["model"] == "UCGFiber"
    assert "_id" in gateway
    assert "satisfaction" in gateway


# ---------------------------------------------------------------------------
# Network CRUD
# ---------------------------------------------------------------------------


def test_create_network_assigns_id(stub_state: StubState) -> None:
    rec = stub_state.create_network({"name": "IoT", "vlan": 20, "ip_subnet": "10.0.20.0/24"})
    assert "_id" in rec
    assert rec["name"] == "IoT"
    assert rec["enabled"] is True
    assert len(stub_state.list_networks()) == 2


def test_update_network_patches_existing(stub_state: StubState) -> None:
    rec = stub_state.create_network({"name": "Pre", "vlan": 30})
    updated = stub_state.update_network(rec["_id"], {"name": "Post", "vlan": 31})
    assert updated is not None
    assert updated["name"] == "Post"
    assert updated["vlan"] == 31


def test_update_network_returns_none_when_missing(stub_state: StubState) -> None:
    assert stub_state.update_network("nonexistent", {"name": "X"}) is None


def test_delete_network(stub_state: StubState) -> None:
    rec = stub_state.create_network({"name": "Doomed", "vlan": 99})
    assert stub_state.delete_network(rec["_id"]) is True
    assert stub_state.delete_network(rec["_id"]) is False


# ---------------------------------------------------------------------------
# WLAN CRUD
# ---------------------------------------------------------------------------


def test_create_wlan_redacts_passphrase(stub_state: StubState) -> None:
    net = stub_state.list_networks()[0]
    rec = stub_state.create_wlan(
        {
            "name": "TestSSID",
            "x_passphrase": "supersecret123",
            "networkconf_id": net["_id"],
            "security": "wpapsk",
        }
    )
    assert rec["x_passphrase"] == "[REDACTED]"
    assert rec["name"] == "TestSSID"


def test_delete_wlan(stub_state: StubState) -> None:
    net = stub_state.list_networks()[0]
    rec = stub_state.create_wlan(
        {"name": "TempSSID", "x_passphrase": "p", "networkconf_id": net["_id"]}
    )
    assert stub_state.delete_wlan(rec["_id"]) is True
    assert stub_state.delete_wlan(rec["_id"]) is False


def test_update_wlan_patches_existing(stub_state: StubState) -> None:
    net = stub_state.list_networks()[0]
    rec = stub_state.create_wlan(
        {"name": "Pre", "x_passphrase": "p1", "networkconf_id": net["_id"]}
    )
    updated = stub_state.update_wlan(rec["_id"], {"name": "Post", "hide_ssid": True})
    assert updated is not None
    assert updated["name"] == "Post"
    assert updated["hide_ssid"] is True


def test_update_wlan_returns_none_when_missing(stub_state: StubState) -> None:
    assert stub_state.update_wlan("nonexistent", {"name": "X"}) is None


def test_update_wlan_redacts_passphrase_on_change(stub_state: StubState) -> None:
    net = stub_state.list_networks()[0]
    rec = stub_state.create_wlan(
        {"name": "Pre", "x_passphrase": "old-secret", "networkconf_id": net["_id"]}
    )
    updated = stub_state.update_wlan(rec["_id"], {"x_passphrase": "rotated-secret"})
    assert updated is not None
    assert updated["x_passphrase"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Firewall CRUD
# ---------------------------------------------------------------------------


def test_create_firewall_rule(stub_state: StubState) -> None:
    rec = stub_state.create_firewall_rule(
        {
            "name": "Block X",
            "ruleset": "LAN_IN",
            "action": "drop",
            "rule_index": 2050,
        }
    )
    assert "_id" in rec
    assert rec["action"] == "drop"


def test_delete_firewall_rule(stub_state: StubState) -> None:
    rec = stub_state.create_firewall_rule({"name": "Temp", "ruleset": "LAN_IN", "action": "drop"})
    assert stub_state.delete_firewall_rule(rec["_id"]) is True
    assert stub_state.delete_firewall_rule(rec["_id"]) is False


# ---------------------------------------------------------------------------
# Read-only collections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "list_devices",
        "list_networks",
        "list_wlans",
        "list_firewall_rules",
        "list_port_profiles",
        "list_clients",
    ],
)
def test_list_methods_return_lists(stub_state: StubState, method: str) -> None:
    result = getattr(stub_state, method)()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Clients seed shape
# ---------------------------------------------------------------------------


def test_clients_seed_mix_of_wireless_and_wired(stub_state: StubState) -> None:
    clients = stub_state.list_clients()
    assert any(not c["is_wired"] for c in clients), "expected at least one wireless"
    assert any(c["is_wired"] for c in clients), "expected at least one wired"


def test_wireless_clients_have_signal_metrics(stub_state: StubState) -> None:
    for c in stub_state.list_clients():
        if not c["is_wired"]:
            assert "signal" in c
            assert "satisfaction" in c
            assert "ap_mac" in c


# ---------------------------------------------------------------------------
# v0.3.0 stub helpers
# ---------------------------------------------------------------------------


def test_block_unblock_round_trip(stub_state: StubState) -> None:
    mac = stub_state.list_clients()[0]["mac"]
    blocked = stub_state.block_client(mac)
    assert blocked is not None and blocked["blocked"] is True
    unblocked = stub_state.unblock_client(mac)
    assert unblocked is not None and unblocked["blocked"] is False


def test_block_unknown_client_returns_none(stub_state: StubState) -> None:
    assert stub_state.block_client("00:00:00:00:00:00") is None
    assert stub_state.unblock_client("00:00:00:00:00:00") is None


def test_reconnect_client(stub_state: StubState) -> None:
    mac = stub_state.list_clients()[0]["mac"]
    assert stub_state.reconnect_client(mac) is True
    assert stub_state.reconnect_client("00:00:00:00:00:00") is False


def test_top_talkers_ranks_by_total_bytes(stub_state: StubState) -> None:
    talkers = stub_state.top_talkers(2)
    assert len(talkers) == 2
    # NAS has the highest tx+rx in the seed.
    assert talkers[0]["hostname"] == "nas"
    assert talkers[0]["total_bytes"] >= talkers[1]["total_bytes"]


def test_restart_and_locate_device(stub_state: StubState) -> None:
    gateway_mac = "f4:e2:c6:00:00:01"
    assert stub_state.restart_device(gateway_mac) is True
    assert stub_state.restart_device("00:00:00:00:00:00") is False
    assert stub_state.locate_device(gateway_mac, True) is True
    assert stub_state.find_device_by_mac(gateway_mac)["locating"] is True
    assert stub_state.locate_device(gateway_mac, False) is True
    assert stub_state.find_device_by_mac(gateway_mac)["locating"] is False


def test_set_port_state_updates_port(stub_state: StubState) -> None:
    switch_mac = "f4:e2:c6:00:00:03"
    port = stub_state.set_port_state(switch_mac, 5, enable=False, poe_mode="off")
    assert port is not None
    assert port["enable"] is False
    assert port["poe_mode"] == "off"


def test_set_port_state_unknown_device(stub_state: StubState) -> None:
    assert stub_state.set_port_state("ff:ff:ff:ff:ff:ff", 1, enable=True) is None


def test_set_port_state_unknown_port(stub_state: StubState) -> None:
    switch_mac = "f4:e2:c6:00:00:03"
    assert stub_state.set_port_state(switch_mac, 999, enable=False) is None


def test_dhcp_lease_crud(stub_state: StubState) -> None:
    net = stub_state.list_networks()[0]
    lease = stub_state.create_dhcp_lease(
        {
            "mac": "11:22:33:44:55:66",
            "fixed_ip": "192.168.1.50",
            "network_id": net["_id"],
            "name": "Pi",
            "use_fixedip": True,
        }
    )
    assert "_id" in lease
    assert any(item["_id"] == lease["_id"] for item in stub_state.list_dhcp_leases())
    assert stub_state.delete_dhcp_lease(lease["_id"]) is True
    assert stub_state.delete_dhcp_lease(lease["_id"]) is False


def test_port_forward_crud(stub_state: StubState) -> None:
    pf = stub_state.create_port_forward(
        {
            "name": "X",
            "fwd": "192.168.1.99",
            "fwd_port": "8080",
            "dst_port": "8080",
            "proto": "tcp",
            "src": "any",
        }
    )
    updated = stub_state.update_port_forward(pf["_id"], {"enabled": False})
    assert updated is not None and updated["enabled"] is False
    assert stub_state.update_port_forward("ghost", {"enabled": True}) is None
    assert stub_state.delete_port_forward(pf["_id"]) is True
    assert stub_state.delete_port_forward(pf["_id"]) is False


def test_firewall_rule_update(stub_state: StubState) -> None:
    rule = stub_state.create_firewall_rule({"name": "P", "ruleset": "LAN_IN", "action": "drop"})
    updated = stub_state.update_firewall_rule(rule["_id"], {"action": "accept"})
    assert updated is not None and updated["action"] == "accept"
    assert stub_state.update_firewall_rule("ghost", {"action": "drop"}) is None


def test_port_profile_crud(stub_state: StubState) -> None:
    p = stub_state.create_port_profile({"name": "PoE Cam", "forward": "all", "poe_mode": "auto"})
    updated = stub_state.update_port_profile(p["_id"], {"poe_mode": "off"})
    assert updated is not None and updated["poe_mode"] == "off"
    assert stub_state.update_port_profile("ghost", {"name": "X"}) is None
    assert stub_state.delete_port_profile(p["_id"]) is True
    assert stub_state.delete_port_profile(p["_id"]) is False


def test_observability_endpoints(stub_state: StubState) -> None:
    assert len(stub_state.list_events(2)) <= 2
    assert isinstance(stub_state.list_alarms(10, archived=False), list)
    assert isinstance(stub_state.list_alarms(10, archived=True), list)
    health = stub_state.get_site_health()
    assert any(h["subsystem"] == "wan" for h in health)
    wan = stub_state.get_wan_status()
    assert wan["subsystem"] == "wan"


def test_speedtest_appends_result(stub_state: StubState) -> None:
    before = len(stub_state.get_speedtest_results(100))
    res = stub_state.trigger_speedtest()
    assert res["started"] is True
    after = stub_state.get_speedtest_results(100)
    assert len(after) == before + 1
