"""Tests for ``mcp_unifi.clients.zone_policy`` (ADR 0009).

The builder is the one place an Integration API policy body is shaped, so these
tests pin it against the published UniFi Network 10.6.106 reference. The
reference's field lists below are copied from the scraped docs
(developer.ui.com/network/v10.6.106/createfirewallpolicy and
updatefirewallpolicy), not from this module, so a builder that drifts from the
documented shape fails here rather than on a console.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_unifi.clients import zone_policy as zp

#: Top-level PUT body fields in the 10.6.106 reference.
DOC_PUT_FIELDS = {
    "action",
    "connectionStateFilter",
    "description",
    "destination",
    "enabled",
    "ipProtocolScope",
    "ipsecFilter",
    "loggingEnabled",
    "name",
    "schedule",
    "source",
}
#: Fields the 10.6.106 reference marks required on POST.
DOC_REQUIRED = {
    "action",
    "destination",
    "enabled",
    "ipProtocolScope",
    "loggingEnabled",
    "name",
    "source",
}

ZONE_A = "aaaaaaaa-0000-4000-8000-000000000001"
ZONE_B = "bbbbbbbb-0000-4000-8000-000000000002"


def _plex_body() -> dict[str, Any]:
    return zp.create_body(
        name="Allow IoT to Plex",
        action="allow",
        source=zp.endpoint(ZONE_A, network_ids=["net-v1-iot"]),
        destination=zp.endpoint(ZONE_B, addresses=["192.168.86.20"], ports="32400"),
        protocol="tcp",
    )


def test_writable_keys_match_the_published_put_body() -> None:
    assert zp.WRITABLE_KEYS == DOC_PUT_FIELDS


def test_create_body_carries_every_documented_required_field() -> None:
    body = _plex_body()
    assert set(body) >= DOC_REQUIRED
    assert set(body) <= DOC_PUT_FIELDS


def test_create_body_shape_for_a_single_host_allow() -> None:
    body = _plex_body()
    assert body["action"] == {"type": "ALLOW", "allowReturnTraffic": True}
    assert body["source"] == {
        "zoneId": ZONE_A,
        "trafficFilter": {
            "type": "NETWORK",
            "networkFilter": {"matchOpposite": False, "networkIds": ["net-v1-iot"]},
        },
    }
    assert body["destination"] == {
        "zoneId": ZONE_B,
        "trafficFilter": {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": [{"type": "IP_ADDRESS", "value": "192.168.86.20"}],
            },
            "portFilter": {
                "type": "PORTS",
                "matchOpposite": False,
                "items": [{"type": "PORT_NUMBER", "value": 32400}],
            },
        },
    }
    assert body["ipProtocolScope"] == {
        "ipVersion": "IPV4",
        "protocolFilter": {
            "type": "NAMED_PROTOCOL",
            "matchOpposite": False,
            "protocol": {"name": "TCP"},
        },
    }
    assert body["enabled"] is True
    assert body["loggingEnabled"] is False
    assert "description" not in body
    assert "connectionStateFilter" not in body


def test_block_action_has_no_return_traffic_flag() -> None:
    assert zp.action_body("block") == {"type": "BLOCK"}
    assert zp.action_body("REJECT") == {"type": "REJECT"}


def test_unknown_action_is_refused() -> None:
    with pytest.raises(zp.PolicyBodyError, match="action"):
        zp.action_body("accept")


@pytest.mark.parametrize(
    ("spec", "items"),
    [
        ("443", [{"type": "PORT_NUMBER", "value": 443}]),
        (
            "80, 443",
            [{"type": "PORT_NUMBER", "value": 80}, {"type": "PORT_NUMBER", "value": 443}],
        ),
        ("8000-8100", [{"type": "PORT_NUMBER_RANGE", "start": 8000, "stop": 8100}]),
        ("", []),
    ],
)
def test_port_items(spec: str, items: list[dict[str, Any]]) -> None:
    assert zp.port_items(spec) == items


@pytest.mark.parametrize("spec", ["0", "65536", "http", "100-90", "1-x"])
def test_bad_ports_are_refused(spec: str) -> None:
    with pytest.raises(zp.PolicyBodyError):
        zp.port_items(spec)


def test_address_items_cover_ip_subnet_and_range() -> None:
    assert zp.address_items(["10.0.50.1/24", "10.0.50.7", "10.0.50.10-10.0.50.20"]) == [
        {"type": "SUBNET", "value": "10.0.50.0/24"},
        {"type": "IP_ADDRESS", "value": "10.0.50.7"},
        {"type": "IP_ADDRESS_RANGE", "start": "10.0.50.10", "stop": "10.0.50.20"},
    ]


@pytest.mark.parametrize("value", ["10.0.0", "10.0.0.9-10.0.0.1", "10.0.0.1-fd00::1", "nope/24"])
def test_bad_addresses_are_refused(value: str) -> None:
    with pytest.raises(zp.PolicyBodyError):
        zp.address_items([value])


def test_one_side_cannot_match_networks_and_addresses() -> None:
    with pytest.raises(zp.PolicyBodyError, match="not both"):
        zp.endpoint(ZONE_A, network_ids=["n"], addresses=["10.0.0.1"])


def test_endpoint_with_only_ports_uses_the_port_filter_type() -> None:
    assert zp.endpoint(ZONE_A, ports="53") == {
        "zoneId": ZONE_A,
        "trafficFilter": {
            "type": "PORT",
            "portFilter": {
                "type": "PORTS",
                "matchOpposite": False,
                "items": [{"type": "PORT_NUMBER", "value": 53}],
            },
        },
    }


def test_endpoint_with_nothing_matches_the_whole_zone() -> None:
    assert zp.endpoint(ZONE_A) == {"zoneId": ZONE_A}


def test_port_match_needs_tcp_or_udp() -> None:
    with pytest.raises(zp.PolicyBodyError, match="port match"):
        zp.create_body(
            name="x",
            action="allow",
            source=zp.endpoint(ZONE_A),
            destination=zp.endpoint(ZONE_B, ports="443"),
        )


@pytest.mark.parametrize(
    ("protocol", "version", "expected"),
    [
        ("all", "ipv4", {"ipVersion": "IPV4"}),
        (
            "tcp_udp",
            "IPV4_AND_IPV6",
            {
                "ipVersion": "IPV4_AND_IPV6",
                "protocolFilter": {"type": "PRESET", "preset": {"name": "TCP_UDP"}},
            },
        ),
        (
            "icmpv6",
            "IPV6",
            {
                "ipVersion": "IPV6",
                "protocolFilter": {
                    "type": "NAMED_PROTOCOL",
                    "matchOpposite": False,
                    "protocol": {"name": "ICMPV6"},
                },
            },
        ),
    ],
)
def test_protocol_scope(protocol: str, version: str, expected: dict[str, Any]) -> None:
    assert zp.protocol_scope(protocol, version) == expected


@pytest.mark.parametrize(
    ("protocol", "version"),
    [("icmp", "IPV6"), ("icmpv6", "IPV4"), ("gre2", "IPV4"), ("tcp", "IPV5")],
)
def test_bad_protocol_scope_is_refused(protocol: str, version: str) -> None:
    with pytest.raises(zp.PolicyBodyError):
        zp.protocol_scope(protocol, version)


def test_empty_name_is_refused() -> None:
    with pytest.raises(zp.PolicyBodyError, match="name"):
        zp.create_body(
            name="  ", action="block", source=zp.endpoint(ZONE_A), destination=zp.endpoint(ZONE_B)
        )


def test_optional_fields_appear_only_when_set() -> None:
    body = zp.create_body(
        name="x",
        action="block",
        source=zp.endpoint(ZONE_A),
        destination=zp.endpoint(ZONE_B),
        description="why",
        connection_states=["new", " "],
    )
    assert body["description"] == "why"
    assert body["connectionStateFilter"] == ["NEW"]


def test_put_body_drops_read_only_fields_and_applies_changes() -> None:
    current = {**_plex_body(), "id": "p1", "index": 10003, "metadata": {"origin": "USER_DEFINED"}}
    body = zp.put_body(current, {"enabled": False})
    assert "id" not in body and "index" not in body and "metadata" not in body
    assert body["enabled"] is False
    assert body["name"] == "Allow IoT to Plex"


def test_put_body_refuses_a_field_the_put_does_not_take() -> None:
    with pytest.raises(zp.PolicyBodyError, match="index"):
        zp.put_body(_plex_body(), {"index": 1})


def test_find_by_id_wins_over_name_and_name_ignores_case() -> None:
    records = [{"id": "Internal", "name": "x"}, {"id": "z2", "name": "Internal"}]
    assert zp.find_by_id_or_name(records, "Internal") == [records[0]]
    assert zp.find_by_id_or_name(records, "X") == [records[0]]
    assert zp.find_by_id_or_name(records, "missing") == []


def test_zone_of_network() -> None:
    zones = [{"id": "z1", "networkIds": ["a"]}, {"id": "z2", "networkIds": ["b"]}]
    assert zp.zone_of_network(zones, "b") == zones[1]
    assert zp.zone_of_network(zones, "c") is None


def test_is_user_defined() -> None:
    assert zp.is_user_defined({"metadata": {"origin": "USER_DEFINED"}})
    assert not zp.is_user_defined({"metadata": {"origin": "SYSTEM_DEFINED"}})
    assert not zp.is_user_defined({})
