"""Realistic stub responses for the UniFi controller API.

Used when ``stub_mode=True`` (the default). Payloads mirror the shape returned
by the legacy ``/api/s/<site>/...`` endpoints on a UniFi OS gateway. Field
names come from public UniFi documentation and community write-ups; no code
was copied from any reference implementation.

The state machine holds in-memory data so create/update/delete tools behave
consistently within a single container lifetime. State resets on restart. Each
``StubState`` instance is fully independent so tests can exercise it in
isolation without sharing module-level singletons.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from mcp_unifi.models import UniFiRecord


def _oid() -> str:
    """24-character hex string in the shape of a Mongo ObjectId."""
    return uuid.uuid4().hex[:24]


def _ts() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Seed state — what a freshly-unboxed UCG-Fiber + U7 Pro looks like
# ---------------------------------------------------------------------------


def _seed_devices() -> list[UniFiRecord]:
    return [
        {
            "_id": _oid(),
            "mac": "f4:e2:c6:00:00:01",
            "type": "ugw",
            "model": "UCGFiber",
            "name": "Gateway",
            "ip": "192.168.1.1",
            "version": "9.0.108",
            "adopted": True,
            "state": 1,
            "uptime": 482311,
            "num_sta": 12,
            "satisfaction": 99,
        },
        {
            "_id": _oid(),
            "mac": "f4:e2:c6:00:00:02",
            "type": "uap",
            "model": "U7Pro",
            "name": "U7 Pro - Living Room",
            "ip": "192.168.1.2",
            "version": "7.0.92",
            "adopted": True,
            "state": 1,
            "uptime": 482010,
            "num_sta": 12,
            "satisfaction": 98,
            "radio_table": [
                {"radio": "ng", "channel": 6, "ht": 20, "tx_power": 23},
                {"radio": "na", "channel": 36, "ht": 80, "tx_power": 26},
                {"radio": "6e", "channel": 37, "ht": 160, "tx_power": 24},
            ],
        },
    ]


def _seed_networks() -> list[UniFiRecord]:
    return [
        {
            "_id": _oid(),
            "name": "Default",
            "purpose": "corporate",
            "vlan_enabled": False,
            "vlan": None,
            "ip_subnet": "192.168.1.1/24",
            "dhcpd_enabled": True,
            "dhcpd_start": "192.168.1.100",
            "dhcpd_stop": "192.168.1.200",
            "domain_name": "localdomain",
            "site_id": "default",
            "enabled": True,
        },
    ]


def _seed_wlans(network_id: str) -> list[UniFiRecord]:
    return [
        {
            "_id": _oid(),
            "name": "Home",
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": "[REDACTED]",
            "networkconf_id": network_id,
            "is_guest": False,
            "hide_ssid": False,
            "wlan_band": "both",
        },
    ]


def _seed_firewall_rules() -> list[UniFiRecord]:
    return [
        {
            "_id": _oid(),
            "name": "Allow established/related",
            "ruleset": "WAN_IN",
            "rule_index": 2000,
            "action": "accept",
            "enabled": True,
            "protocol": "all",
            "state_established": True,
            "state_related": True,
        },
    ]


def _seed_port_profiles() -> list[UniFiRecord]:
    return [
        {
            "_id": _oid(),
            "name": "All",
            "site_id": "default",
            "native_networkconf_id": "",
            "forward": "all",
            "poe_mode": "auto",
        },
        {
            "_id": _oid(),
            "name": "Disabled",
            "site_id": "default",
            "forward": "disabled",
            "poe_mode": "off",
        },
    ]


# ---------------------------------------------------------------------------
# Stub state container
# ---------------------------------------------------------------------------


class StubState:
    """In-memory mock controller state.

    A fresh instance always starts from seeded data. The module-level
    :data:`STUB` singleton is what ``server.py`` uses; tests should construct
    their own ``StubState()`` to avoid cross-test pollution.
    """

    def __init__(self) -> None:
        self.devices: list[UniFiRecord] = _seed_devices()
        self.networks: list[UniFiRecord] = _seed_networks()
        default_net_id: str = self.networks[0]["_id"]
        self.wlans: list[UniFiRecord] = _seed_wlans(default_net_id)
        self.firewall_rules: list[UniFiRecord] = _seed_firewall_rules()
        self.port_profiles: list[UniFiRecord] = _seed_port_profiles()

    # ----- Devices --------------------------------------------------------
    def list_devices(self) -> list[UniFiRecord]:
        return self.devices

    # ----- Networks / VLANs -----------------------------------------------
    def list_networks(self) -> list[UniFiRecord]:
        return self.networks

    def create_network(self, payload: dict[str, Any]) -> UniFiRecord:
        record: UniFiRecord = {
            "_id": _oid(),
            "site_id": "default",
            "enabled": True,
            **payload,
        }
        self.networks.append(record)
        return record

    def update_network(self, network_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        for net in self.networks:
            if net.get("_id") == network_id:
                net.update(patch)
                return net
        return None

    def delete_network(self, network_id: str) -> bool:
        before = len(self.networks)
        self.networks = [n for n in self.networks if n.get("_id") != network_id]
        return len(self.networks) < before

    # ----- WLANs ----------------------------------------------------------
    def list_wlans(self) -> list[UniFiRecord]:
        return self.wlans

    def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        record: UniFiRecord = {"_id": _oid(), "enabled": True, **payload}
        # Don't echo the passphrase back in stub responses.
        if "x_passphrase" in record:
            record["x_passphrase"] = "[REDACTED]"  # noqa: S105 - redaction sentinel
        self.wlans.append(record)
        return record

    def delete_wlan(self, wlan_id: str) -> bool:
        before = len(self.wlans)
        self.wlans = [w for w in self.wlans if w.get("_id") != wlan_id]
        return len(self.wlans) < before

    # ----- Firewall -------------------------------------------------------
    def list_firewall_rules(self) -> list[UniFiRecord]:
        return self.firewall_rules

    def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        record: UniFiRecord = {"_id": _oid(), "enabled": True, **payload}
        self.firewall_rules.append(record)
        return record

    def delete_firewall_rule(self, rule_id: str) -> bool:
        before = len(self.firewall_rules)
        self.firewall_rules = [r for r in self.firewall_rules if r.get("_id") != rule_id]
        return len(self.firewall_rules) < before

    # ----- Port profiles --------------------------------------------------
    def list_port_profiles(self) -> list[UniFiRecord]:
        return self.port_profiles


# Module-level singleton — server.py imports this directly so create/update/
# delete calls within a session see consistent state.
STUB = StubState()
