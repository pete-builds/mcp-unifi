"""Tests for ``mcp_unifi.clients.integration_translate`` (ADR 0008).

The expected bodies are the shapes a UCG-Fiber on UniFi Network 10.6.106
accepted on 2026-10-17. Every ``None`` case is a payload that must stay on the
private API because the Integration API cannot express it exactly.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_unifi.clients import integration_translate as tr

V1_NET = "99999999-8888-4777-8666-555555555555"
AP_GROUP = "650000000000000000000003"


def _vlan_payload(**over: Any) -> dict[str, Any]:
    """What ``create_vlan`` sends today."""
    payload: dict[str, Any] = {
        "name": "cameras",
        "purpose": "corporate",
        "vlan_enabled": True,
        "vlan": 77,
        "ip_subnet": "10.0.77.1/24",
        "dhcpd_enabled": True,
        "dhcpd_start": "10.0.77.6",
        "dhcpd_stop": "10.0.77.254",
        "enabled": True,
    }
    payload.update(over)
    return payload


def _wlan_payload(**over: Any) -> dict[str, Any]:
    """What ``create_wlan`` sends today with its defaults."""
    payload: dict[str, Any] = {
        "name": "cams",
        "enabled": True,
        "security": "wpapsk",
        "wpa_mode": "wpa2",
        "networkconf_id": "650000000000000000000001",
        "is_guest": False,
        "hide_ssid": False,
        "wlan_band": "both",
        "ap_group_ids": [AP_GROUP],
        "ap_group_mode": "all",
        "x_passphrase": "correct-horse-battery",
    }
    payload.update(over)
    return payload


V1_NETWORK_READBACK: dict[str, Any] = {
    "management": "GATEWAY",
    "id": V1_NET,
    "name": "IoT",
    "enabled": True,
    "vlanId": 50,
    "metadata": {"origin": "USER_DEFINED"},
    "isolationEnabled": False,
    "cellularBackupEnabled": False,
    "internetAccessEnabled": True,
    "mdnsForwardingEnabled": True,
    "ipv4Configuration": {
        "autoScaleEnabled": False,
        "hostIpAddress": "10.20.30.1",
        "prefixLength": 24,
        "dhcpConfiguration": {
            "mode": "SERVER",
            "ipAddressRange": {"start": "10.20.30.100", "stop": "10.20.30.200"},
            "leaseTimeSeconds": 86400,
            "domainName": "",
            "pingConflictDetectionEnabled": True,
        },
    },
    "default": False,
}

V1_WLAN_READBACK: dict[str, Any] = {
    "type": "STANDARD",
    "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    "name": "home",
    "metadata": {"origin": "USER_DEFINED"},
    "enabled": True,
    "network": {"type": "SPECIFIC", "networkId": "12345678-1234-4234-8234-123456789abc"},
    "securityConfiguration": {
        "type": "WPA2_WPA3_PERSONAL",
        "fastRoamingEnabled": False,
        "passphrase": "old-passphrase-1",
        "pmfMode": "OPTIONAL",
    },
    "hideName": False,
    "broadcastingFrequenciesGHz": [2.4, 6, 5],
    "bssTransitionEnabled": True,
}


# ---------------------------------------------------------------------------
# network_create_body
# ---------------------------------------------------------------------------


def test_create_vlan_payload_maps_to_a_gateway_network() -> None:
    """The five defaulted fields are the ones a live create was refused without."""
    assert tr.network_create_body(_vlan_payload()) == {
        "management": "GATEWAY",
        "name": "cameras",
        "enabled": True,
        "vlanId": 77,
        "internetAccessEnabled": True,
        "isolationEnabled": False,
        "cellularBackupEnabled": False,
        "ipv4Configuration": {
            "autoScaleEnabled": False,
            "hostIpAddress": "10.0.77.1",
            "prefixLength": 24,
            "dhcpConfiguration": {
                "mode": "SERVER",
                "ipAddressRange": {"start": "10.0.77.6", "stop": "10.0.77.254"},
                "leaseTimeSeconds": 86400,
                "pingConflictDetectionEnabled": True,
            },
        },
    }


def test_caller_flags_override_the_create_defaults() -> None:
    body = tr.network_create_body(
        _vlan_payload(internet_access_enabled=False, network_isolation_enabled=True)
    )
    assert body is not None
    assert body["internetAccessEnabled"] is False
    assert body["isolationEnabled"] is True


def test_network_without_dhcp_and_with_flags() -> None:
    payload = _vlan_payload(
        dhcpd_enabled=False,
        internet_access_enabled=False,
        network_isolation_enabled=True,
        mdns_enabled=False,
    )
    del payload["dhcpd_start"], payload["dhcpd_stop"]
    body = tr.network_create_body(payload)
    assert body is not None
    assert "dhcpConfiguration" not in body["ipv4Configuration"]
    assert body["internetAccessEnabled"] is False
    assert body["isolationEnabled"] is True
    assert body["mdnsForwardingEnabled"] is False


def test_lease_time_maps() -> None:
    body = tr.network_create_body(_vlan_payload(dhcpd_leasetime=3600))
    assert body is not None
    assert body["ipv4Configuration"]["dhcpConfiguration"]["leaseTimeSeconds"] == 3600


@pytest.mark.parametrize(
    "over",
    [
        {"purpose": "guest"},  # v1 has no guest concept
        {"vlan_enabled": False},
        {"vlan": 1},
        {"vlan": 4095},
        {"vlan": True},
        {"ip_subnet": "10.0.77.0/24"},  # network form, not gateway form
        {"ip_subnet": "not-a-subnet"},
        {"dhcpd_start": "nope"},
        {"enabled": "yes"},
        {"name": ""},
        {"ipv6_interface_type": "pd"},  # unmapped key
        {"dhcpd_dns_1": "1.1.1.1"},  # unmapped key
        {"dhcpd_leasetime": 0},
    ],
)
def test_network_create_refuses_what_it_cannot_map(over: dict[str, Any]) -> None:
    assert tr.network_create_body(_vlan_payload(**over)) is None


def test_network_create_refuses_missing_required_key() -> None:
    payload = _vlan_payload()
    del payload["enabled"]
    assert tr.network_create_body(payload) is None


def test_dhcp_enabled_without_a_range_is_refused() -> None:
    payload = _vlan_payload()
    del payload["dhcpd_stop"]
    assert tr.network_create_body(payload) is None


def test_dhcp_disabled_with_a_range_is_refused() -> None:
    assert tr.network_create_body(_vlan_payload(dhcpd_enabled=False)) is None


# ---------------------------------------------------------------------------
# network_put_body
# ---------------------------------------------------------------------------


def test_rename_keeps_everything_else_and_strips_server_fields() -> None:
    body = tr.network_put_body(V1_NETWORK_READBACK, {"name": "IoT-2"})
    assert body is not None
    assert body["name"] == "IoT-2"
    for owned in ("id", "metadata", "default"):
        assert owned not in body
    assert body["ipv4Configuration"] == V1_NETWORK_READBACK["ipv4Configuration"]
    assert V1_NETWORK_READBACK["name"] == "IoT"  # readback not mutated


def test_dhcp_start_only_keeps_existing_stop() -> None:
    body = tr.network_put_body(V1_NETWORK_READBACK, {"dhcpd_start": "10.20.30.50"})
    assert body is not None
    rng = body["ipv4Configuration"]["dhcpConfiguration"]["ipAddressRange"]
    assert rng == {"start": "10.20.30.50", "stop": "10.20.30.200"}
    assert body["ipv4Configuration"]["dhcpConfiguration"]["leaseTimeSeconds"] == 86400


def test_dhcp_disable_drops_the_block() -> None:
    body = tr.network_put_body(V1_NETWORK_READBACK, {"dhcpd_enabled": False})
    assert body is not None
    assert "dhcpConfiguration" not in body["ipv4Configuration"]


def test_subnet_vlan_and_flags_update() -> None:
    body = tr.network_put_body(
        V1_NETWORK_READBACK,
        {"ip_subnet": "10.20.31.1/25", "vlan": 51, "enabled": False, "mdns_enabled": False},
    )
    assert body is not None
    assert body["ipv4Configuration"]["hostIpAddress"] == "10.20.31.1"
    assert body["ipv4Configuration"]["prefixLength"] == 25
    assert body["vlanId"] == 51
    assert body["enabled"] is False
    assert body["mdnsForwardingEnabled"] is False


@pytest.mark.parametrize(
    "patch",
    [
        {},
        {"purpose": "guest"},
        {"ipv6_interface_type": "pd"},
        {"dhcpd_enabled": False, "dhcpd_start": "10.20.30.5"},
        {"dhcpd_enabled": "no"},
        {"vlan_enabled": False},
        {"ip_subnet": "10.20.30.0/24"},
    ],
)
def test_network_put_refuses_what_it_cannot_map(patch: dict[str, Any]) -> None:
    assert tr.network_put_body(V1_NETWORK_READBACK, patch) is None


def test_network_put_refuses_non_gateway_networks() -> None:
    switch = dict(V1_NETWORK_READBACK, management="SWITCH")
    assert tr.network_put_body(switch, {"name": "x"}) is None


def test_enabling_dhcp_on_a_network_without_a_range_is_refused() -> None:
    no_dhcp = dict(V1_NETWORK_READBACK)
    no_dhcp["ipv4Configuration"] = {
        k: v
        for k, v in V1_NETWORK_READBACK["ipv4Configuration"].items()
        if k != "dhcpConfiguration"
    }
    assert tr.network_put_body(no_dhcp, {"dhcpd_enabled": True}) is None


# ---------------------------------------------------------------------------
# wlan_create_body
# ---------------------------------------------------------------------------


def test_create_wlan_payload_maps_with_the_undocumented_required_fields() -> None:
    body = tr.wlan_create_body(_wlan_payload(), v1_network_id=V1_NET, default_ap_group_id=AP_GROUP)
    assert body == {
        "type": "STANDARD",
        "name": "cams",
        "enabled": True,
        "hideName": False,
        "network": {"type": "SPECIFIC", "networkId": V1_NET},
        "securityConfiguration": {
            "type": "WPA2_PERSONAL",
            "passphrase": "correct-horse-battery",
            "fastRoamingEnabled": False,
        },
        "broadcastingFrequenciesGHz": [2.4, 5],
        "clientIsolationEnabled": False,
        "multicastToUnicastConversionEnabled": False,
        "uapsdEnabled": False,
        "channel2gLockedTo6": False,
        "dtimPeriod2gLockedTo3": False,
        "advertiseDeviceName": False,
        "arpProxyEnabled": False,
        "bssTransitionEnabled": True,
    }


def test_radio_locks_are_never_set() -> None:
    """Either lock, if true, retunes every AP that broadcasts the SSID."""
    body = tr.wlan_create_body(_wlan_payload(), v1_network_id=V1_NET, default_ap_group_id=AP_GROUP)
    assert body is not None
    assert body["channel2gLockedTo6"] is False
    assert body["dtimPeriod2gLockedTo3"] is False


@pytest.mark.parametrize(("band", "freqs"), [("2g", [2.4]), ("5g", [5]), ("both", [2.4, 5])])
def test_bands(band: str, freqs: list[float]) -> None:
    body = tr.wlan_create_body(
        _wlan_payload(wlan_band=band), v1_network_id=V1_NET, default_ap_group_id=AP_GROUP
    )
    assert body is not None
    assert body["broadcastingFrequenciesGHz"] == freqs


@pytest.mark.parametrize(
    "over",
    [
        {"security": "open"},
        {"security": "wpaeap"},
        {"wpa_mode": "wpa3"},
        {"is_guest": True},
        {"ap_group_mode": "groups"},
        {"ap_group_ids": ["some-other-group"]},
        {"ap_group_ids": [AP_GROUP, "second"]},
        {"wlan_band": "6g"},
        {"x_passphrase": "short"},
        {"hide_ssid": "no"},
        {"schedule": ["mon|0800-1700"]},  # unmapped key
    ],
)
def test_wlan_create_refuses_what_it_cannot_map(over: dict[str, Any]) -> None:
    body = tr.wlan_create_body(
        _wlan_payload(**over), v1_network_id=V1_NET, default_ap_group_id=AP_GROUP
    )
    assert body is None


def test_wlan_create_needs_the_v1_network_and_default_group() -> None:
    assert (
        tr.wlan_create_body(_wlan_payload(), v1_network_id=None, default_ap_group_id=AP_GROUP)
        is None
    )
    assert (
        tr.wlan_create_body(_wlan_payload(), v1_network_id=V1_NET, default_ap_group_id=None) is None
    )


# ---------------------------------------------------------------------------
# wlan_put_body
# ---------------------------------------------------------------------------


def test_wlan_rename_and_hide() -> None:
    body = tr.wlan_put_body(V1_WLAN_READBACK, {"name": "EIGHT", "hide_ssid": True})
    assert body is not None
    assert body["name"] == "EIGHT"
    assert body["hideName"] is True
    assert "id" not in body and "metadata" not in body
    assert body["securityConfiguration"]["passphrase"] == "old-passphrase-1"


def test_wlan_passphrase_change_on_personal_security() -> None:
    body = tr.wlan_put_body(V1_WLAN_READBACK, {"x_passphrase": "new-passphrase-2"})
    assert body is not None
    assert body["securityConfiguration"]["passphrase"] == "new-passphrase-2"
    assert V1_WLAN_READBACK["securityConfiguration"]["passphrase"] == "old-passphrase-1"


def test_wlan_passphrase_change_on_enterprise_is_refused() -> None:
    enterprise = dict(V1_WLAN_READBACK, securityConfiguration={"type": "WPA2_ENTERPRISE"})
    assert tr.wlan_put_body(enterprise, {"x_passphrase": "new-passphrase-2"}) is None


def test_wlan_network_move_needs_the_v1_id() -> None:
    assert tr.wlan_put_body(V1_WLAN_READBACK, {"networkconf_id": "abc"}) is None
    body = tr.wlan_put_body(V1_WLAN_READBACK, {"networkconf_id": "abc"}, v1_network_id=V1_NET)
    assert body is not None
    assert body["network"] == {"type": "SPECIFIC", "networkId": V1_NET}


@pytest.mark.parametrize(
    "patch",
    [{}, {"is_guest": True}, {"wlan_band": "6g"}, {"x_passphrase": "short"}, {"enabled": 1}],
)
def test_wlan_put_refuses_what_it_cannot_map(patch: dict[str, Any]) -> None:
    assert tr.wlan_put_body(V1_WLAN_READBACK, patch) is None
