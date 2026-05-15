"""Tests for ``audit_network_drift`` (Phase 2, Part A).

Read-only tool. Compares the controller state against a YAML spec and returns
a structured diff. We exercise:

* in-sync case (declared resources match controller state)
* missing resource (spec declares a network the controller doesn't have)
* extra resource (controller has a network the spec didn't declare)
* field-level drift (subnet differs)
* multi-resource diff (networks + WLANs + firewall in one pass)
* malformed YAML / non-mapping spec → clear error
"""

from __future__ import annotations

import textwrap

from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import _call

# ---------------------------------------------------------------------------
# In-sync
# ---------------------------------------------------------------------------


async def test_drift_in_sync_when_spec_matches_seed(stub_server: FastMCP) -> None:
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is True
    assert result["drifts"] == []
    assert result["controller"] == "default"
    assert result["summary"] == "in sync"


async def test_drift_in_sync_with_field_match(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    # Seed network "Default" has whatever the stub picks; align the spec to
    # whatever the stub seeded so we can assert sync at the field level.
    seed = stub_state.list_networks()[0]
    spec = textwrap.dedent(
        f"""
        networks:
          - name: "{seed['name']}"
            subnet: "{seed.get('ip_subnet', '')}"
            purpose: "{seed.get('purpose', '')}"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is True


# ---------------------------------------------------------------------------
# Missing resource
# ---------------------------------------------------------------------------


async def test_drift_missing_network(stub_server: FastMCP) -> None:
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
          - name: "IoT"
            vlan: 50
            subnet: "10.50.0.0/24"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False

    missing = [
        d
        for d in result["drifts"]
        if d["name"] == "iot" and d["field"] == "_resource"
    ]
    assert len(missing) == 1
    assert missing[0]["expected"] == "present"
    assert missing[0]["actual"] is None
    assert missing[0]["resource_type"] == "vlan"


# ---------------------------------------------------------------------------
# Extra resource
# ---------------------------------------------------------------------------


async def test_drift_extra_network_on_controller(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.create_network(
        {
            "name": "Lab",
            "purpose": "corporate",
            "vlan": 99,
            "vlan_enabled": True,
            "ip_subnet": "10.99.0.0/24",
            "enabled": True,
        }
    )
    # Spec only declares "Default" — Lab is extra.
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    extras = [
        d
        for d in result["drifts"]
        if d["resource_type"] == "vlan"
        and d["field"] == "_resource"
        and d["expected"] is None
    ]
    assert any(d["name"] == "lab" for d in extras)
    assert result["in_sync"] is False


# ---------------------------------------------------------------------------
# Field-level drift
# ---------------------------------------------------------------------------


async def test_drift_field_level_subnet_mismatch(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    seed = stub_state.list_networks()[0]
    spec = textwrap.dedent(
        f"""
        networks:
          - name: "{seed['name']}"
            subnet: "10.99.99.0/24"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    field_drifts = [
        d
        for d in result["drifts"]
        if d["resource_type"] == "vlan" and d["field"] == "subnet"
    ]
    assert len(field_drifts) == 1
    assert field_drifts[0]["expected"] == "10.99.99.0/24"
    assert field_drifts[0]["actual"] == seed.get("ip_subnet")


# ---------------------------------------------------------------------------
# Multi-resource diff
# ---------------------------------------------------------------------------


async def test_drift_multi_resource(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    # Seed extras to drive both the "extra" path on WLANs and a missing
    # firewall rule via the spec.
    stub_state.create_wlan(
        {
            "name": "Cameras-IoT",
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": "supersecret",
            "networkconf_id": stub_state.list_networks()[0]["_id"],
            "is_guest": False,
            "hide_ssid": False,
            "wlan_band": "both",
        }
    )
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
        wlans:
          - name: "Cameras-IoT"
            security: "wpaeap"   # mismatch
        firewall_rules:
          - name: "Block IoT to LAN"
            action: "drop"
            src: "10.50.0.0/24"
            dst: "192.168.86.0/24"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False

    # WLAN field drift on security
    wlan_field = [
        d
        for d in result["drifts"]
        if d["resource_type"] == "wlan" and d["field"] == "security"
    ]
    assert len(wlan_field) == 1
    assert wlan_field[0]["expected"] == "wpaeap"
    assert wlan_field[0]["actual"] == "wpapsk"

    # Firewall rule missing from controller
    fw_missing = [
        d
        for d in result["drifts"]
        if d["resource_type"] == "firewall_rule"
        and d["name"] == "block iot to lan"
        and d["field"] == "_resource"
    ]
    assert len(fw_missing) == 1
    assert fw_missing[0]["actual"] is None

    # Summary mentions resource types
    assert "wlan" in result["summary"]
    assert "firewall_rule" in result["summary"]


# ---------------------------------------------------------------------------
# Empty / partial specs
# ---------------------------------------------------------------------------


async def test_drift_empty_spec_is_in_sync(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": ""})
    assert result["in_sync"] is True
    assert result["drifts"] == []


async def test_drift_section_not_declared_is_not_audited(
    stub_server: FastMCP,
) -> None:
    # Spec only audits networks; firewall rules on the controller are ignored.
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    fw_drifts = [d for d in result["drifts"] if d["resource_type"] == "firewall_rule"]
    assert fw_drifts == []


# ---------------------------------------------------------------------------
# WLAN network binding
# ---------------------------------------------------------------------------


async def test_drift_wlan_network_binding_match(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    default_net = stub_state.list_networks()[0]
    stub_state.create_wlan(
        {
            "name": "Cameras-IoT",
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": "supersecret",
            "networkconf_id": default_net["_id"],
            "is_guest": False,
            "hide_ssid": False,
            "wlan_band": "both",
        }
    )
    spec = textwrap.dedent(
        f"""
        wlans:
          - name: "Cameras-IoT"
            network: "{default_net['name']}"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    binding_drifts = [
        d
        for d in result["drifts"]
        if d["resource_type"] == "wlan" and d["field"] == "network"
    ]
    assert binding_drifts == []


async def test_drift_wlan_network_binding_unknown_name(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    default_net = stub_state.list_networks()[0]
    stub_state.create_wlan(
        {
            "name": "Cameras-IoT",
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": "supersecret",
            "networkconf_id": default_net["_id"],
            "is_guest": False,
            "hide_ssid": False,
            "wlan_band": "both",
        }
    )
    spec = textwrap.dedent(
        """
        wlans:
          - name: "Cameras-IoT"
            network: "DoesNotExist"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    binding_drifts = [
        d
        for d in result["drifts"]
        if d["resource_type"] == "wlan" and d["field"] == "network"
    ]
    assert len(binding_drifts) == 1
    assert binding_drifts[0]["expected"] == "DoesNotExist"


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


async def test_drift_malformed_yaml(stub_server: FastMCP) -> None:
    bad = "networks:\n  - name: foo\n  bad: indentation"
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": bad})
    assert "error" in result
    assert "malformed spec_yaml" in result["error"]


async def test_drift_non_mapping_top_level(stub_server: FastMCP) -> None:
    bad = "- just: a list"
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": bad})
    assert "error" in result
    assert "mapping at the top level" in result["error"]


async def test_drift_section_not_a_list(stub_server: FastMCP) -> None:
    bad = "networks: notalist"
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": bad})
    assert "error" in result
    assert "spec.networks must be a list" in result["error"]


async def test_drift_unnamed_resource_flagged(stub_server: FastMCP) -> None:
    spec = textwrap.dedent(
        """
        networks:
          - vlan: 50
            subnet: "10.50.0.0/24"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    name_drifts = [
        d
        for d in result["drifts"]
        if d["field"] == "name" and d["name"] == "<unnamed>"
    ]
    assert len(name_drifts) == 1


# ---------------------------------------------------------------------------
# Controller routing
# ---------------------------------------------------------------------------


async def test_drift_unknown_controller(stub_server: FastMCP) -> None:
    spec = "networks: []\n"
    result = await _call(
        stub_server,
        "audit_network_drift",
        {"spec_yaml": spec, "controller": "missing"},
    )
    assert "error" in result
    assert "Unknown controller" in result["error"]
