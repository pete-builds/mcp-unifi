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
    # Seed is the LAN "Default" plus the WAN "Internet 1" (v0.14.0). Drift
    # audits both directions, so the spec must name every seeded network.
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
          - name: "Internet 1"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is True
    assert result["drifts"] == []
    assert result["controller"] == "default"
    assert result["summary"] == "in sync"


async def test_drift_in_sync_with_field_match(stub_server: FastMCP, stub_state: StubState) -> None:
    # Seed network "Default" has whatever the stub picks; align the spec to
    # whatever the stub seeded so we can assert sync at the field level. The
    # WAN seed (v0.14.0) must also appear or drift flags it as extra.
    seed = stub_state.list_networks()[0]
    spec = textwrap.dedent(
        f"""
        networks:
          - name: "{seed["name"]}"
            subnet: "{seed.get("ip_subnet", "")}"
            purpose: "{seed.get("purpose", "")}"
          - name: "Internet 1"
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

    missing = [d for d in result["drifts"] if d["name"] == "iot" and d["field"] == "_resource"]
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
        if d["resource_type"] == "vlan" and d["field"] == "_resource" and d["expected"] is None
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
          - name: "{seed["name"]}"
            subnet: "10.99.99.0/24"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    field_drifts = [
        d for d in result["drifts"] if d["resource_type"] == "vlan" and d["field"] == "subnet"
    ]
    assert len(field_drifts) == 1
    assert field_drifts[0]["expected"] == "10.99.99.0/24"
    assert field_drifts[0]["actual"] == seed.get("ip_subnet")


# ---------------------------------------------------------------------------
# Multi-resource diff
# ---------------------------------------------------------------------------


async def test_drift_multi_resource(stub_server: FastMCP, stub_state: StubState) -> None:
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
        d for d in result["drifts"] if d["resource_type"] == "wlan" and d["field"] == "security"
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
            network: "{default_net["name"]}"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    binding_drifts = [
        d for d in result["drifts"] if d["resource_type"] == "wlan" and d["field"] == "network"
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
        d for d in result["drifts"] if d["resource_type"] == "wlan" and d["field"] == "network"
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
    name_drifts = [d for d in result["drifts"] if d["field"] == "name" and d["name"] == "<unnamed>"]
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


# ---------------------------------------------------------------------------
# Zone-Based Firewall policies (issue #112)
# ---------------------------------------------------------------------------


def _zone_ids(stub_state: StubState) -> dict[str, str]:
    return {z["zone_key"]: z["_id"] for z in stub_state.list_firewall_zones()}


async def test_drift_firewall_policies_section(stub_server: FastMCP, stub_state: StubState) -> None:
    zones = _zone_ids(stub_state)
    stub_state.firewall_policies.append(
        {
            "_id": "p-ssh",
            "name": "Open SSH",
            "action": "ALLOW",
            "enabled": True,
            "predefined": False,
            "index": 20000,
            "protocol": "tcp",
            "source": {"zone_id": zones["wan"]},
            "destination": {"zone_id": zones["lan"]},
        }
    )
    spec = textwrap.dedent(
        """
        firewall_policies:
          - name: "Open SSH"
            action: "block"          # mismatch, case-insensitive
            source_zone: "wan"       # matches, case-insensitive
            destination_zone: "LAN"
          - name: "Allow Return Traffic"
          - name: "Block IoT to LAN"  # missing on the controller
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False
    policy_drifts = [d for d in result["drifts"] if d["resource_type"] == "firewall_policy"]

    action = [d for d in policy_drifts if d["name"] == "open ssh" and d["field"] == "action"]
    assert len(action) == 1
    assert action[0] == {
        "resource_type": "firewall_policy",
        "name": "open ssh",
        "field": "action",
        "expected": "BLOCK",
        "actual": "ALLOW",
    }
    assert not [d for d in policy_drifts if d["field"] in ("source_zone", "destination_zone")]

    missing = [d for d in policy_drifts if d["name"] == "block iot to lan"]
    assert len(missing) == 1
    assert missing[0]["field"] == "_resource"
    assert missing[0]["actual"] is None

    assert "firewall_policy" in result["summary"]


async def test_drift_firewall_policies_not_declared_is_not_audited(
    stub_server: FastMCP,
) -> None:
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert [d for d in result["drifts"] if d["resource_type"] == "firewall_policy"] == []


async def test_drift_firewall_policies_must_be_a_list(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "audit_network_drift", {"spec_yaml": "firewall_policies: 1\n"}
    )
    assert "firewall_policies must be a list" in result["error"]


# ---------------------------------------------------------------------------
# Blind spots: duplicates, nameless extras, keys with no comparison
#
# The controller index used to be a dict keyed by name that kept the last
# duplicate and skipped nameless records, and spec keys outside a section's
# field map were skipped without a word. Each of these left the audit
# answering ``in_sync: true`` on a site that did not match the spec.
# ---------------------------------------------------------------------------


async def test_drift_duplicate_name_on_controller_is_drift(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.firewall_rules.clear()
    base = {"ruleset": "LAN_IN", "action": "accept", "protocol": "tcp"}
    stub_state.create_firewall_rule(
        {**base, "name": "Allow Plex", "dst_address": "192.168.1.20/32", "dst_port": "32400"}
    )
    # An unauthorised second rule under the same name, open on every port.
    stub_state.create_firewall_rule(
        {**base, "name": "Allow Plex", "dst_address": "192.168.1.20/32"}
    )
    spec = textwrap.dedent(
        """
        firewall_rules:
          - name: "Allow Plex"
            action: "accept"
            protocol: "tcp"
            dst: "192.168.1.20/32"
            dst_port: "32400"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False
    dup = [d for d in result["drifts"] if d["field"] == "_duplicate"]
    assert dup == [
        {
            "resource_type": "firewall_rule",
            "name": "allow plex",
            "field": "_duplicate",
            "expected": 1,
            "actual": 2,
        }
    ]
    # Both copies are compared, so the open one shows its port drift too.
    port = [d for d in result["drifts"] if d["field"] == "dst_port"]
    assert len(port) == 1
    assert port[0]["expected"] == "32400"
    assert port[0]["actual"] is None
    assert result["not_compared"] == []


async def test_drift_nameless_extra_on_controller_is_drift(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.create_network({"purpose": "corporate", "vlan": 66, "ip_subnet": "10.66.0.0/24"})
    nameless_id = stub_state.networks[-1]["_id"]
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
          - name: "Internet 1"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False
    extras = [d for d in result["drifts"] if d["name"] == "<unnamed>"]
    assert len(extras) == 1
    assert extras[0]["field"] == "_resource"
    assert extras[0]["expected"] is None
    assert extras[0]["id"] == nameless_id


async def test_drift_duplicate_extra_network_counts_both(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    for vlan in (70, 71):
        stub_state.create_network({"name": "Lab", "purpose": "corporate", "vlan": vlan})
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
          - name: "Internet 1"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    lab = {d["field"]: d for d in result["drifts"] if d["name"] == "lab"}
    assert lab["_resource"]["expected"] is None
    assert lab["_duplicate"]["actual"] == 2


async def test_drift_unmapped_spec_key_is_reported_not_dropped(stub_server: FastMCP) -> None:
    # ``subnett`` is a typo. It used to be skipped, and the audit said in sync.
    spec = textwrap.dedent(
        """
        networks:
          - name: "Default"
            subnett: "10.99.0.0/24"
          - name: "Internet 1"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["drifts"] == []
    assert result["not_compared"] == [
        {"resource_type": "vlan", "name": "default", "field": "subnett", "expected": "10.99.0.0/24"}
    ]
    assert result["in_sync"] is False
    assert "not compared" in result["summary"]
    assert "vlan.subnett" in result["summary"]


async def test_drift_unknown_section_is_reported_not_dropped(stub_server: FastMCP) -> None:
    spec = textwrap.dedent(
        """
        port_forwards:
          - name: "HTTPS to NAS"
        """
    )
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False
    assert [(n["resource_type"], n["field"]) for n in result["not_compared"]] == [
        ("port_forwards", "_section")
    ]


async def test_drift_wlan_enabled_is_compared(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan = stub_state.list_wlans()[0]
    wlan["enabled"] = True
    spec = f'wlans:\n  - name: "{wlan["name"]}"\n    enabled: false\n'
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    assert result["in_sync"] is False
    enabled = [d for d in result["drifts"] if d["field"] == "enabled"]
    assert len(enabled) == 1
    assert enabled[0]["expected"] is False
    assert enabled[0]["actual"] is True
    assert result["not_compared"] == []


async def test_drift_wlan_binding_to_a_shared_network_name_is_drift(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """A WLAN bound to one of two networks named alike cannot be confirmed."""
    stub_state.create_network({"name": "IoT", "purpose": "corporate", "vlan": 50})
    # Bound to the second: the old name index kept the last duplicate, so
    # this binding used to pass as confirmed.
    second = stub_state.create_network({"name": "IoT", "purpose": "corporate", "vlan": 51})
    stub_state.create_wlan({"name": "Cams", "security": "wpapsk", "networkconf_id": second["_id"]})
    spec = 'wlans:\n  - name: "Cams"\n    network: "IoT"\n  - name: "Home"\n'
    result = await _call(stub_server, "audit_network_drift", {"spec_yaml": spec})
    binding = [d for d in result["drifts"] if d["field"] == "network"]
    assert len(binding) == 1
    assert binding[0]["actual"] == second["_id"]
    assert result["in_sync"] is False
