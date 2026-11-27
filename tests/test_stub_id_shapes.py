"""Pin the stub id shapes to what UniFi Network 11 really sends.

Probed read-only on a UCG-Fiber running Network 11.0.99 (2026-11-27): every
``_id`` and ``site_id`` is a UUID string; networks and WLANs keep the old
24-hex ObjectId as ``legacy_id``; a static lease has no ``legacy_id`` and its
``network_id`` is the network's ``legacy_id`` (not its ``_id``), while
``last_connection_network_id`` is the network's UUID ``_id``. Stubs that return
24-hex ids let code pass here that fails on a real console (issue #219).
"""

from __future__ import annotations

import re
import uuid

from mcp_unifi.clients.stubs import StubState

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{24}$")


def _all_records(state: StubState) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for name in (
        "devices",
        "networks",
        "wlans",
        "firewall_rules",
        "firewall_groups",
        "firewall_zones",
        "firewall_policies",
        "routes",
        "traffic_rules",
        "traffic_routes",
        "content_filters",
        "port_profiles",
        "ap_groups",
        "clients",
        "dhcp_leases",
        "port_forwards",
        "events",
        "alarms",
        "sessions",
        "speedtest_results",
    ):
        out.extend((name, r) for r in getattr(state, name))
    out.extend((f"settings[{k}]", r) for k, r in state.settings.items())
    return out


def test_every_seed_id_and_site_id_is_a_uuid(stub_state: StubState) -> None:
    records = _all_records(stub_state)
    assert records
    for name, rec in records:
        assert _UUID_RE.match(str(rec["_id"])), (name, rec["_id"])
        if "site_id" in rec:
            assert _UUID_RE.match(str(rec["site_id"])), (name, rec["site_id"])


def test_created_records_get_uuid_ids_and_site_id(stub_state: StubState) -> None:
    made = [
        stub_state.create_network({"name": "N"}),
        stub_state.create_wlan({"name": "W"}),
        stub_state.create_firewall_rule({"name": "R"}),
        stub_state.create_firewall_group({"name": "G"}),
        stub_state.create_route({"name": "Rt"}),
        stub_state.create_traffic_rule({"description": "T"}),
        stub_state.create_dynamic_dns({"host_name": "h"}),
        stub_state.create_port_profile({"name": "P"}),
        stub_state.create_port_forward({"name": "F"}),
        stub_state.create_dhcp_lease({"mac": "aa:bb:cc:99:99:99", "fixed_ip": "192.168.1.99"}),
    ]
    for rec in made:
        assert _UUID_RE.match(rec["_id"]), rec
        if "site_id" in rec:
            assert _UUID_RE.match(rec["site_id"]), rec
        uuid.UUID(rec["_id"])  # parses as a real UUID


def test_networks_and_wlans_carry_legacy_id(stub_state: StubState) -> None:
    created_net = stub_state.create_network({"name": "N"})
    created_wlan = stub_state.create_wlan({"name": "W"})
    for rec in [*stub_state.networks, *stub_state.wlans, created_net, created_wlan]:
        assert _OBJECT_ID_RE.match(rec["legacy_id"]), rec
        assert rec["legacy_id"] != rec["_id"]


def test_leases_have_no_legacy_id(stub_state: StubState) -> None:
    lease = stub_state.create_dhcp_lease({"mac": "aa:bb:cc:99:99:99", "fixed_ip": "192.168.1.99"})
    for rec in [*stub_state.dhcp_leases, lease]:
        assert "legacy_id" not in rec


def test_lease_network_id_is_the_networks_legacy_id(stub_state: StubState) -> None:
    network = stub_state.networks[0]
    lease = stub_state.list_dhcp_leases()[0]
    assert lease["network_id"] == network["legacy_id"]
    assert lease["network_id"] not in {n["_id"] for n in stub_state.networks}
    assert lease["last_connection_network_id"] == network["_id"]


def test_wlan_networkconf_id_is_the_network_uuid_id(stub_state: StubState) -> None:
    network_ids = {n["_id"] for n in stub_state.networks}
    wlan = stub_state.list_wlans()[0]
    assert wlan["networkconf_id"] in network_ids
    assert _UUID_RE.match(wlan["networkconf_id"])


def test_zones_and_networks_reference_each_other_by_uuid(stub_state: StubState) -> None:
    zone_ids = {z["_id"] for z in stub_state.firewall_zones}
    network_ids = {n["_id"] for n in stub_state.networks}
    for zone in stub_state.firewall_zones:
        assert set(zone["network_ids"]) <= network_ids
    for net in stub_state.networks:
        if "firewall_zone_id" in net:
            assert net["firewall_zone_id"] in zone_ids
            zone = next(z for z in stub_state.firewall_zones if z["_id"] == net["firewall_zone_id"])
            assert net["_id"] in zone["network_ids"]
