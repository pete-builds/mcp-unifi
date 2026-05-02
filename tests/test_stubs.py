"""Tests for the in-memory stub state machine."""

from __future__ import annotations

import pytest

from mcp_unifi.clients.stubs import StubState


def test_seed_data_present(stub_state: StubState) -> None:
    assert len(stub_state.list_devices()) == 2
    assert len(stub_state.list_networks()) == 1
    assert len(stub_state.list_wlans()) == 1
    assert len(stub_state.list_firewall_rules()) == 1
    assert len(stub_state.list_port_profiles()) == 2


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
    ],
)
def test_list_methods_return_lists(stub_state: StubState, method: str) -> None:
    result = getattr(stub_state, method)()
    assert isinstance(result, list)
