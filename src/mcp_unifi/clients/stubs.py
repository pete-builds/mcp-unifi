"""Realistic stub responses for the UniFi controller API.

Used when ``stub_mode=True`` (the default). Payloads mirror the shape returned
by the legacy ``/api/s/<site>/...`` endpoints on a UniFi OS gateway. Field
names come from public UniFi documentation and community write-ups; no code
was copied from any reference implementation.

The state machine holds in-memory data so create/update/delete tools behave
consistently within a single container lifetime. State resets on restart. Each
``StubState`` instance is fully independent so tests can exercise it in
isolation. Multi-controller stub mode (Step 3) gives each controller its own
:class:`StubState` via :func:`make_stub_state`; there is no module-level
singleton.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
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
            "locating": False,
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
            "locating": False,
            "radio_table": [
                {"radio": "ng", "channel": 6, "ht": 20, "tx_power": 23},
                {"radio": "na", "channel": 36, "ht": 80, "tx_power": 26},
                {"radio": "6e", "channel": 37, "ht": 160, "tx_power": 24},
            ],
        },
        {
            "_id": _oid(),
            "mac": "f4:e2:c6:00:00:03",
            "type": "usw",
            "model": "USW24PoE",
            "name": "Switch - Office",
            "ip": "192.168.1.3",
            "version": "7.0.50",
            "adopted": True,
            "state": 1,
            "uptime": 481000,
            "num_sta": 6,
            "satisfaction": 97,
            "locating": False,
            "port_table": [
                {"port_idx": i, "enable": True, "poe_mode": "auto", "portconf_id": ""}
                for i in range(1, 25)
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


def _seed_clients() -> list[UniFiRecord]:
    """Realistic snapshot of clients on a small home network.

    Field names follow the legacy controller ``/stat/sta`` shape: a mix of
    wireless and wired clients, with signal/satisfaction populated only for
    wireless. Last-seen timestamps fan out across the past day so callers can
    test recency filters meaningfully.
    """
    now = _ts()
    return [
        {
            "_id": _oid(),
            "mac": "aa:bb:cc:00:00:01",
            "hostname": "petes-laptop",
            "name": "Pete's MacBook",
            "ip": "192.168.1.101",
            "is_wired": False,
            "blocked": False,
            "network": "Default",
            "essid": "Home",
            "ap_mac": "f4:e2:c6:00:00:02",
            "channel": 36,
            "radio": "na",
            "signal": -52,
            "rssi": 42,
            "satisfaction": 96,
            "tx_rate": 866000,
            "rx_rate": 866000,
            "tx_bytes": 1_200_000_000,
            "rx_bytes": 8_400_000_000,
            "uptime": 14523,
            "last_seen": now - 5,
            "first_seen": now - 14523,
        },
        {
            "_id": _oid(),
            "mac": "aa:bb:cc:00:00:02",
            "hostname": "iphone-15",
            "name": "iPhone 15",
            "ip": "192.168.1.102",
            "is_wired": False,
            "blocked": False,
            "network": "Default",
            "essid": "Home",
            "ap_mac": "f4:e2:c6:00:00:02",
            "channel": 36,
            "radio": "na",
            "signal": -64,
            "rssi": 30,
            "satisfaction": 88,
            "tx_rate": 433000,
            "rx_rate": 433000,
            "tx_bytes": 240_000_000,
            "rx_bytes": 1_900_000_000,
            "uptime": 86342,
            "last_seen": now - 12,
            "first_seen": now - 86342,
        },
        {
            "_id": _oid(),
            "mac": "aa:bb:cc:00:00:03",
            "hostname": "nas",
            "name": "Synology NAS",
            "ip": "192.168.1.10",
            "is_wired": True,
            "blocked": False,
            "network": "Default",
            "sw_mac": "f4:e2:c6:00:00:03",
            "sw_port": 5,
            "tx_bytes": 18_000_000_000,
            "rx_bytes": 4_500_000_000,
            "uptime": 2580412,
            "last_seen": now - 1,
            "first_seen": now - 2580412,
        },
        {
            "_id": _oid(),
            "mac": "aa:bb:cc:00:00:04",
            "hostname": "echo-dot",
            "name": "Echo Dot",
            "ip": "192.168.1.150",
            "is_wired": False,
            "blocked": False,
            "network": "Default",
            "essid": "Home",
            "ap_mac": "f4:e2:c6:00:00:02",
            "channel": 6,
            "radio": "ng",
            "signal": -71,
            "rssi": 23,
            "satisfaction": 72,
            "tx_rate": 144400,
            "rx_rate": 144400,
            "tx_bytes": 60_000_000,
            "rx_bytes": 220_000_000,
            "uptime": 432198,
            "last_seen": now - 30,
            "first_seen": now - 432198,
        },
    ]


def _seed_dhcp_leases(network_id: str) -> list[UniFiRecord]:
    """Static DHCP reservations.

    UniFi stores fixed leases on the ``user`` object with
    ``use_fixedip=true``. The seed list intentionally mirrors that shape so
    callers can list / create / delete reservations in stub mode.
    """
    return [
        {
            "_id": _oid(),
            "mac": "aa:bb:cc:00:00:03",
            "name": "Synology NAS",
            "hostname": "nas",
            "use_fixedip": True,
            "fixed_ip": "192.168.1.10",
            "network_id": network_id,
            "noted": True,
        },
    ]


def _seed_port_forwards() -> list[UniFiRecord]:
    return [
        {
            "_id": _oid(),
            "name": "HTTPS to NAS",
            "enabled": True,
            "src": "any",
            "proto": "tcp",
            "fwd": "192.168.1.10",
            "fwd_port": "443",
            "dst_port": "443",
            "log": False,
        },
    ]


def _seed_events() -> list[UniFiRecord]:
    now = _ts()
    return [
        {
            "_id": _oid(),
            "time": now - 60,
            "datetime": "stub",
            "key": "EVT_LU_Connected",
            "msg": "Pete's MacBook connected to Home",
            "subsystem": "wlan",
        },
        {
            "_id": _oid(),
            "time": now - 3600,
            "datetime": "stub",
            "key": "EVT_GW_WANConnected",
            "msg": "WAN link is up (2.0 Gbps)",
            "subsystem": "wan",
        },
    ]


def _seed_alarms() -> list[UniFiRecord]:
    now = _ts()
    return [
        {
            "_id": _oid(),
            "time": now - 7200,
            "datetime": "stub",
            "archived": False,
            "key": "EVT_AP_Lost_Contact",
            "msg": "AP U7 Pro - Living Room briefly lost contact",
            "subsystem": "lan",
        },
    ]


def _seed_health() -> list[UniFiRecord]:
    return [
        {
            "subsystem": "wan",
            "status": "ok",
            "gw_name": "Gateway",
            "gw_mac": "f4:e2:c6:00:00:01",
            "wan_ip": "203.0.113.42",
            "isp_name": "Empire Internet Access",
            "speedtest_status": "Idle",
            "uptime": 482311,
            "latency": 8,
            "xput_up": 1820.5,
            "xput_down": 1985.2,
        },
        {"subsystem": "lan", "status": "ok", "num_user": 12, "num_guest": 0},
        {"subsystem": "wlan", "status": "ok", "num_ap": 1, "num_user": 8},
        {"subsystem": "www", "status": "ok"},
        {"subsystem": "vpn", "status": "warning", "num_active": 0},
    ]


def _seed_speedtest_results() -> list[UniFiRecord]:
    now = _ts()
    return [
        {
            "_id": _oid(),
            "time": now - 86400,
            "xput_up": 1820.5,
            "xput_download": 1985.2,
            "latency": 8,
            "server": {"city": "New York, NY", "provider": "Ubiquiti"},
        },
    ]


# ---------------------------------------------------------------------------
# Stub state container
# ---------------------------------------------------------------------------


class StubState:
    """In-memory mock controller state.

    A fresh instance always starts from seeded data. The dispatcher gives each
    controller its own :class:`StubState` (see :func:`make_stub_state`); tests
    construct their own to avoid cross-test pollution.
    """

    def __init__(self) -> None:
        self.devices: list[UniFiRecord] = _seed_devices()
        self.networks: list[UniFiRecord] = _seed_networks()
        default_net_id: str = self.networks[0]["_id"]
        self.wlans: list[UniFiRecord] = _seed_wlans(default_net_id)
        self.firewall_rules: list[UniFiRecord] = _seed_firewall_rules()
        self.port_profiles: list[UniFiRecord] = _seed_port_profiles()
        self.clients: list[UniFiRecord] = _seed_clients()
        self.dhcp_leases: list[UniFiRecord] = _seed_dhcp_leases(default_net_id)
        self.port_forwards: list[UniFiRecord] = _seed_port_forwards()
        self.events: list[UniFiRecord] = _seed_events()
        self.alarms: list[UniFiRecord] = _seed_alarms()
        self.health: list[UniFiRecord] = _seed_health()
        self.speedtest_results: list[UniFiRecord] = _seed_speedtest_results()
        self.audit_log: list[UniFiRecord] = []  # records of block/unblock/reconnect/etc.
        # Failure-injection queue: maps method name to a FIFO deque of
        # exceptions to raise on subsequent calls. Used by property tests
        # (Hypothesis) to verify rollback correctness on the composites.
        self._failure_queue: dict[str, deque[BaseException]] = defaultdict(deque)

    # ----- Failure injection (test helper) --------------------------------
    def fail_next(self, method_name: str, exception: BaseException) -> None:
        """Queue an exception to be raised on the next call to ``method_name``.

        The first invocation of ``method_name`` after this call consumes the
        queued exception, raises it, and clears that one entry. Multiple
        queued failures for the same method are honored in FIFO order. Tests
        use this to deterministically fail one sub-step of a composite and
        then verify rollback restores the prior state.

        This helper is purely additive — it does not alter the behavior of
        any existing :class:`StubState` method outside of consuming a queued
        failure when one is present.
        """
        self._failure_queue[method_name].append(exception)

    def _check_failure(self, method_name: str) -> None:
        """Raise and consume a queued failure for ``method_name`` if any."""
        queue = self._failure_queue.get(method_name)
        if queue:
            raise queue.popleft()

    # ----- Devices --------------------------------------------------------
    def list_devices(self) -> list[UniFiRecord]:
        return self.devices

    def find_device_by_mac(self, mac: str) -> UniFiRecord | None:
        for d in self.devices:
            if d.get("mac") == mac:
                return d
        return None

    def restart_device(self, mac: str) -> bool:
        dev = self.find_device_by_mac(mac)
        if dev is None:
            return False
        dev["state"] = 5  # UniFi: 5 == "restarting"
        self.audit_log.append({"action": "restart_device", "mac": mac, "ts": _ts()})
        return True

    def locate_device(self, mac: str, on: bool) -> bool:
        dev = self.find_device_by_mac(mac)
        if dev is None:
            return False
        dev["locating"] = on
        self.audit_log.append({"action": "locate_device", "mac": mac, "on": on, "ts": _ts()})
        return True

    def set_port_state(
        self,
        device_mac: str,
        port_idx: int,
        *,
        enable: bool | None = None,
        poe_mode: str | None = None,
        portconf_id: str | None = None,
    ) -> UniFiRecord | None:
        dev = self.find_device_by_mac(device_mac)
        if dev is None:
            return None
        port_table: list[UniFiRecord] = dev.get("port_table") or []
        for port in port_table:
            if port.get("port_idx") == port_idx:
                if enable is not None:
                    port["enable"] = enable
                if poe_mode is not None:
                    port["poe_mode"] = poe_mode
                if portconf_id is not None:
                    port["portconf_id"] = portconf_id
                self.audit_log.append(
                    {
                        "action": "set_port_state",
                        "mac": device_mac,
                        "port_idx": port_idx,
                        "ts": _ts(),
                    }
                )
                return port
        return None

    # ----- Networks / VLANs -----------------------------------------------
    def list_networks(self) -> list[UniFiRecord]:
        return self.networks

    def create_network(self, payload: dict[str, Any]) -> UniFiRecord:
        self._check_failure("create_network")
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
        self._check_failure("delete_network")
        before = len(self.networks)
        self.networks = [n for n in self.networks if n.get("_id") != network_id]
        return len(self.networks) < before

    # ----- WLANs ----------------------------------------------------------
    def list_wlans(self) -> list[UniFiRecord]:
        return self.wlans

    def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        self._check_failure("create_wlan")
        record: UniFiRecord = {"_id": _oid(), "enabled": True, **payload}
        # Don't echo the passphrase back in stub responses.
        if "x_passphrase" in record:
            record["x_passphrase"] = "[REDACTED]"  # noqa: S105 - redaction sentinel
        self.wlans.append(record)
        return record

    def update_wlan(self, wlan_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        for wlan in self.wlans:
            if wlan.get("_id") == wlan_id:
                wlan.update(patch)
                if "x_passphrase" in wlan:
                    wlan["x_passphrase"] = "[REDACTED]"  # noqa: S105 - redaction sentinel
                return wlan
        return None

    def delete_wlan(self, wlan_id: str) -> bool:
        self._check_failure("delete_wlan")
        before = len(self.wlans)
        self.wlans = [w for w in self.wlans if w.get("_id") != wlan_id]
        return len(self.wlans) < before

    # ----- Firewall -------------------------------------------------------
    def list_firewall_rules(self) -> list[UniFiRecord]:
        return self.firewall_rules

    def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        self._check_failure("create_firewall_rule")
        record: UniFiRecord = {"_id": _oid(), "enabled": True, **payload}
        self.firewall_rules.append(record)
        return record

    def update_firewall_rule(self, rule_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        for rule in self.firewall_rules:
            if rule.get("_id") == rule_id:
                rule.update(patch)
                return rule
        return None

    def delete_firewall_rule(self, rule_id: str) -> bool:
        self._check_failure("delete_firewall_rule")
        before = len(self.firewall_rules)
        self.firewall_rules = [r for r in self.firewall_rules if r.get("_id") != rule_id]
        return len(self.firewall_rules) < before

    # ----- Port profiles --------------------------------------------------
    def list_port_profiles(self) -> list[UniFiRecord]:
        return self.port_profiles

    def create_port_profile(self, payload: dict[str, Any]) -> UniFiRecord:
        record: UniFiRecord = {"_id": _oid(), "site_id": "default", **payload}
        self.port_profiles.append(record)
        return record

    def update_port_profile(self, profile_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        for profile in self.port_profiles:
            if profile.get("_id") == profile_id:
                profile.update(patch)
                return profile
        return None

    def delete_port_profile(self, profile_id: str) -> bool:
        before = len(self.port_profiles)
        self.port_profiles = [p for p in self.port_profiles if p.get("_id") != profile_id]
        return len(self.port_profiles) < before

    # ----- Clients --------------------------------------------------------
    def list_clients(self) -> list[UniFiRecord]:
        return self.clients

    def block_client(self, mac: str) -> UniFiRecord | None:
        self._check_failure("block_client")
        for c in self.clients:
            if c.get("mac") == mac:
                c["blocked"] = True
                self.audit_log.append({"action": "block_client", "mac": mac, "ts": _ts()})
                return c
        return None

    def unblock_client(self, mac: str) -> UniFiRecord | None:
        for c in self.clients:
            if c.get("mac") == mac:
                c["blocked"] = False
                self.audit_log.append({"action": "unblock_client", "mac": mac, "ts": _ts()})
                return c
        return None

    def reconnect_client(self, mac: str) -> bool:
        for c in self.clients:
            if c.get("mac") == mac:
                self.audit_log.append({"action": "reconnect_client", "mac": mac, "ts": _ts()})
                return True
        return False

    def top_talkers(self, limit: int) -> list[UniFiRecord]:
        ranked = sorted(
            self.clients,
            key=lambda c: c.get("tx_bytes", 0) + c.get("rx_bytes", 0),
            reverse=True,
        )
        return [
            {
                "mac": c.get("mac"),
                "hostname": c.get("hostname"),
                "ip": c.get("ip"),
                "tx_bytes": c.get("tx_bytes", 0),
                "rx_bytes": c.get("rx_bytes", 0),
                "total_bytes": c.get("tx_bytes", 0) + c.get("rx_bytes", 0),
            }
            for c in ranked[:limit]
        ]

    # ----- DHCP leases (static) -------------------------------------------
    def list_dhcp_leases(self) -> list[UniFiRecord]:
        return [u for u in self.dhcp_leases if u.get("use_fixedip")]

    def create_dhcp_lease(self, payload: dict[str, Any]) -> UniFiRecord:
        self._check_failure("create_dhcp_lease")
        record: UniFiRecord = {"_id": _oid(), "use_fixedip": True, **payload}
        self.dhcp_leases.append(record)
        return record

    def delete_dhcp_lease(self, lease_id: str) -> bool:
        self._check_failure("delete_dhcp_lease")
        before = len(self.dhcp_leases)
        self.dhcp_leases = [u for u in self.dhcp_leases if u.get("_id") != lease_id]
        return len(self.dhcp_leases) < before

    # ----- Port forwarding ------------------------------------------------
    def list_port_forwards(self) -> list[UniFiRecord]:
        return self.port_forwards

    def create_port_forward(self, payload: dict[str, Any]) -> UniFiRecord:
        self._check_failure("create_port_forward")
        record: UniFiRecord = {"_id": _oid(), "enabled": True, **payload}
        self.port_forwards.append(record)
        return record

    def update_port_forward(self, forward_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        for pf in self.port_forwards:
            if pf.get("_id") == forward_id:
                pf.update(patch)
                return pf
        return None

    def delete_port_forward(self, forward_id: str) -> bool:
        self._check_failure("delete_port_forward")
        before = len(self.port_forwards)
        self.port_forwards = [p for p in self.port_forwards if p.get("_id") != forward_id]
        return len(self.port_forwards) < before

    # ----- Observability --------------------------------------------------
    def list_events(self, limit: int) -> list[UniFiRecord]:
        return self.events[:limit]

    def list_alarms(self, limit: int, archived: bool) -> list[UniFiRecord]:
        filtered = [a for a in self.alarms if a.get("archived", False) == archived]
        return filtered[:limit]

    def get_site_health(self) -> list[UniFiRecord]:
        return self.health

    def get_wan_status(self) -> UniFiRecord:
        for h in self.health:
            if h.get("subsystem") == "wan":
                return h
        return {"subsystem": "wan", "status": "unknown"}

    def trigger_speedtest(self) -> UniFiRecord:
        # Append a fresh result to the front of the list.
        result = {
            "_id": _oid(),
            "time": _ts(),
            "xput_up": 1820.5,
            "xput_download": 1985.2,
            "latency": 8,
            "server": {"city": "New York, NY", "provider": "Ubiquiti"},
        }
        self.speedtest_results.insert(0, result)
        # Update WAN health to mirror the new measurement.
        for h in self.health:
            if h.get("subsystem") == "wan":
                h["xput_up"] = result["xput_up"]
                h["xput_down"] = result["xput_download"]
                h["latency"] = result["latency"]
                break
        return {"started": True, "result": result}

    def get_speedtest_results(self, limit: int) -> list[UniFiRecord]:
        return self.speedtest_results[:limit]


def make_stub_state() -> StubState:
    """Return a fresh seeded :class:`StubState`.

    Step 3 removed the module-level singleton: each controller in stub mode
    now owns an isolated state instance. Use this helper instead of constructing
    ``StubState()`` directly so future seeding hooks have one entrypoint.
    """
    return StubState()
