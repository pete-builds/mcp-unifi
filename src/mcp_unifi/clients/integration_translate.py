"""Translate private-API network and WLAN payloads into Integration API bodies.

Every tool in this server builds its write payload in the private API's shape
(``rest/networkconf``, ``rest/wlanconf``). ADR 0008 routes the subset of those
writes that the official Integration API can express through
``/proxy/network/integration/v1``. This module is that subset, and nothing
more: each function returns the Integration API body, or ``None`` when the
payload carries anything without an exact equivalent there. ``None`` is not an
error; it sends the write down the private path unchanged.

The field mapping was read off a live UCG-Fiber on UniFi Network 10.6.106
(2026-10-17), by reading the same networks and WLANs through both surfaces,
not from developer.ui.com. The published schema marks fields optional that
the controller rejects a create without. For WLANs: ``advertiseDeviceName``,
``arpProxyEnabled``, ``broadcastingFrequenciesGHz``, ``bssTransitionEnabled``
and ``securityConfiguration.fastRoamingEnabled``. For networks:
``internetAccessEnabled``, ``cellularBackupEnabled``, ``isolationEnabled``, and
on a DHCP block ``leaseTimeSeconds`` and ``pingConflictDetectionEnabled``. Where
the private payload is silent, the defaults below are the values the private
API applies to a new network and that every live network read back.

What deliberately stays private, and why:

- ``purpose="guest"`` networks. The Integration API has no guest concept; a
  guest network reads back exactly like a corporate one, so a v1 create would
  silently drop the guest policy.
- WLANs that are guest, enterprise (RADIUS), open, WPA3, 6 GHz, scheduled, or
  bound to specific AP groups. None of those were exercised live, and AP-group
  targeting has no one-to-one mapping onto ``broadcastingDeviceFilter``.
- Anything touching IPv6, DHCP DNS overrides, VPN or WAN records.
"""

from __future__ import annotations

import ipaddress
from copy import deepcopy
from typing import Any

#: v1 fields the server owns. Sent back on a PUT they are either ignored or
#: rejected, so every PUT body is the readback minus these.
_SERVER_OWNED = ("id", "metadata", "default")

_NETWORK_CREATE_REQUIRED = frozenset(
    {"name", "purpose", "vlan_enabled", "vlan", "ip_subnet", "dhcpd_enabled", "enabled"}
)
_NETWORK_CREATE_OPTIONAL = frozenset(
    {
        "dhcpd_start",
        "dhcpd_stop",
        "dhcpd_leasetime",
        "internet_access_enabled",
        "network_isolation_enabled",
        "mdns_enabled",
    }
)
_NETWORK_PATCHABLE = frozenset(
    {
        "name",
        "enabled",
        "vlan",
        "vlan_enabled",
        "purpose",
        "ip_subnet",
        "dhcpd_enabled",
        "dhcpd_start",
        "dhcpd_stop",
        "dhcpd_leasetime",
        "internet_access_enabled",
        "network_isolation_enabled",
        "mdns_enabled",
    }
)
_NETWORK_BOOLS = {
    "internet_access_enabled": "internetAccessEnabled",
    "network_isolation_enabled": "isolationEnabled",
    "mdns_enabled": "mdnsForwardingEnabled",
}
#: Required by the controller on create, absent from most private payloads.
_NETWORK_CREATE_DEFAULTS: dict[str, Any] = {
    "internetAccessEnabled": True,
    "isolationEnabled": False,
    "cellularBackupEnabled": False,
}
_DHCP_LEASE_DEFAULT = 86400

_WLAN_CREATE_KEYS = frozenset(
    {
        "name",
        "enabled",
        "security",
        "wpa_mode",
        "networkconf_id",
        "is_guest",
        "hide_ssid",
        "wlan_band",
        "ap_group_ids",
        "ap_group_mode",
        "x_passphrase",
    }
)
_WLAN_PATCHABLE = frozenset(
    {"name", "enabled", "hide_ssid", "x_passphrase", "networkconf_id", "wlan_band"}
)
#: Private ``wlan_band`` to v1 ``broadcastingFrequenciesGHz``. 6 GHz is left
#: out: it requires WPA3, which this translation does not emit.
_BANDS: dict[str, list[float]] = {"both": [2.4, 5], "2g": [2.4], "5g": [5]}
_PERSONAL_SECURITY = ("WPA2_PERSONAL", "WPA2_WPA3_PERSONAL", "WPA3_PERSONAL")


def _host_and_prefix(ip_subnet: Any) -> tuple[str, int] | None:
    """Split gateway-form ``"10.0.77.1/24"`` into host and prefix length.

    Network form (``"10.0.77.0/24"``) is refused: the private API stores the
    gateway address, and guessing it here would be a translation, not a map.
    """
    if not isinstance(ip_subnet, str):
        return None
    try:
        iface = ipaddress.IPv4Interface(ip_subnet)
    except ValueError:
        return None
    if iface.ip == iface.network.network_address or iface.ip == iface.network.broadcast_address:
        return None
    return str(iface.ip), iface.network.prefixlen


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def network_create_body(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Map a private ``networkconf`` create payload to a v1 GATEWAY network body."""
    keys = set(payload)
    if not keys >= _NETWORK_CREATE_REQUIRED:
        return None
    if keys - _NETWORK_CREATE_REQUIRED - _NETWORK_CREATE_OPTIONAL:
        return None
    if payload["purpose"] != "corporate" or payload["vlan_enabled"] is not True:
        return None
    vlan = payload["vlan"]
    if not isinstance(vlan, int) or isinstance(vlan, bool) or not 2 <= vlan <= 4094:
        return None
    name = payload["name"]
    if not isinstance(name, str) or not name:
        return None
    if not _is_bool(payload["enabled"]) or not _is_bool(payload["dhcpd_enabled"]):
        return None
    host = _host_and_prefix(payload["ip_subnet"])
    if host is None:
        return None

    ipv4: dict[str, Any] = {
        "autoScaleEnabled": False,
        "hostIpAddress": host[0],
        "prefixLength": host[1],
    }
    if payload["dhcpd_enabled"]:
        dhcp = _dhcp_server(payload, None)
        if dhcp is None:
            return None
        ipv4["dhcpConfiguration"] = dhcp
    elif keys & {"dhcpd_start", "dhcpd_stop", "dhcpd_leasetime"}:
        return None

    body: dict[str, Any] = {
        "management": "GATEWAY",
        "name": name,
        "enabled": payload["enabled"],
        "vlanId": vlan,
        "ipv4Configuration": ipv4,
        **_NETWORK_CREATE_DEFAULTS,
    }
    for private_key, v1_key in _NETWORK_BOOLS.items():
        if private_key in payload:
            if not _is_bool(payload[private_key]):
                return None
            body[v1_key] = payload[private_key]
    return body


def _dhcp_server(changes: dict[str, Any], current: dict[str, Any] | None) -> dict[str, Any] | None:
    """Build a SERVER-mode DHCP block from ``changes`` layered over ``current``."""
    dhcp: dict[str, Any] = (
        deepcopy(current)
        if current
        else {
            "mode": "SERVER",
            "ipAddressRange": {},
            "leaseTimeSeconds": _DHCP_LEASE_DEFAULT,
            "pingConflictDetectionEnabled": True,
        }
    )
    if dhcp.get("mode") != "SERVER":
        return None
    rng = dict(dhcp.get("ipAddressRange") or {})
    for private_key, v1_key in (("dhcpd_start", "start"), ("dhcpd_stop", "stop")):
        if private_key in changes:
            value = changes[private_key]
            try:
                ipaddress.IPv4Address(value)
            except (ipaddress.AddressValueError, ValueError):
                return None
            rng[v1_key] = value
    if not rng.get("start") or not rng.get("stop"):
        return None
    dhcp["ipAddressRange"] = rng
    if "dhcpd_leasetime" in changes:
        lease = changes["dhcpd_leasetime"]
        if not isinstance(lease, int) or isinstance(lease, bool) or lease <= 0:
            return None
        dhcp["leaseTimeSeconds"] = lease
    return dhcp


def network_put_body(current: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any] | None:
    """Layer a private ``networkconf`` patch over a v1 readback; return the PUT body.

    ``current`` is ``GET /v1/sites/{site}/networks/{id}``. The private API
    merges a patch; the v1 PUT replaces the record, so the merge happens here.
    """
    if not patch or set(patch) - _NETWORK_PATCHABLE:
        return None
    if current.get("management") != "GATEWAY":
        return None
    if "purpose" in patch and patch["purpose"] != "corporate":
        return None
    if "vlan_enabled" in patch and patch["vlan_enabled"] is not True:
        return None

    body = {k: deepcopy(v) for k, v in current.items() if k not in _SERVER_OWNED}
    ipv4: dict[str, Any] = body.setdefault("ipv4Configuration", {})

    if "name" in patch:
        if not isinstance(patch["name"], str) or not patch["name"]:
            return None
        body["name"] = patch["name"]
    if "enabled" in patch:
        if not _is_bool(patch["enabled"]):
            return None
        body["enabled"] = patch["enabled"]
    if "vlan" in patch:
        vlan = patch["vlan"]
        if not isinstance(vlan, int) or isinstance(vlan, bool) or not 2 <= vlan <= 4094:
            return None
        body["vlanId"] = vlan
    if "ip_subnet" in patch:
        host = _host_and_prefix(patch["ip_subnet"])
        if host is None:
            return None
        ipv4["hostIpAddress"], ipv4["prefixLength"] = host

    dhcp_keys = {"dhcpd_start", "dhcpd_stop", "dhcpd_leasetime"}
    if patch.get("dhcpd_enabled") is False:
        if set(patch) & dhcp_keys:
            return None
        ipv4.pop("dhcpConfiguration", None)
    elif "dhcpd_enabled" in patch and patch["dhcpd_enabled"] is not True:
        return None
    elif patch.get("dhcpd_enabled") is True or set(patch) & dhcp_keys:
        dhcp = _dhcp_server(patch, ipv4.get("dhcpConfiguration"))
        if dhcp is None:
            return None
        ipv4["dhcpConfiguration"] = dhcp

    for private_key, v1_key in _NETWORK_BOOLS.items():
        if private_key in patch:
            if not _is_bool(patch[private_key]):
                return None
            body[v1_key] = patch[private_key]
    return body


def wlan_create_body(
    payload: dict[str, Any],
    *,
    v1_network_id: str | None,
    default_ap_group_id: str | None,
) -> dict[str, Any] | None:
    """Map a private ``wlanconf`` create payload to a v1 WiFi broadcast body.

    ``v1_network_id`` is the target network's ``external_id``. The payload must
    broadcast on exactly the controller's default AP group in ``all`` mode,
    which is what v1 expresses as no ``broadcastingDeviceFilter``.
    """
    if set(payload) - _WLAN_CREATE_KEYS:
        return None
    if not v1_network_id or not default_ap_group_id:
        return None
    if payload.get("security") != "wpapsk" or payload.get("wpa_mode") != "wpa2":
        return None
    if payload.get("is_guest") is not False:
        return None
    if payload.get("ap_group_mode") != "all":
        return None
    if payload.get("ap_group_ids") != [default_ap_group_id]:
        return None
    bands = _BANDS.get(payload.get("wlan_band", ""))
    if bands is None:
        return None
    name, passphrase = payload.get("name"), payload.get("x_passphrase")
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63:
        return None
    enabled, hidden = payload.get("enabled"), payload.get("hide_ssid")
    if not _is_bool(enabled) or not _is_bool(hidden):
        return None

    return {
        "type": "STANDARD",
        "name": name,
        "enabled": enabled,
        "hideName": hidden,
        "network": {"type": "SPECIFIC", "networkId": v1_network_id},
        "securityConfiguration": {
            "type": "WPA2_PERSONAL",
            "passphrase": passphrase,
            "fastRoamingEnabled": False,
        },
        "broadcastingFrequenciesGHz": bands,
        "clientIsolationEnabled": False,
        "multicastToUnicastConversionEnabled": False,
        "uapsdEnabled": False,
        "channel2gLockedTo6": False,
        "dtimPeriod2gLockedTo3": False,
        "advertiseDeviceName": False,
        "arpProxyEnabled": False,
        "bssTransitionEnabled": True,
    }


def wlan_put_body(
    current: dict[str, Any],
    patch: dict[str, Any],
    *,
    v1_network_id: str | None = None,
) -> dict[str, Any] | None:
    """Layer a private ``wlanconf`` patch over a v1 readback; return the PUT body.

    ``v1_network_id`` is required only when the patch moves the WLAN to another
    network (``networkconf_id``); it is that network's ``external_id``.
    """
    if not patch or set(patch) - _WLAN_PATCHABLE:
        return None
    body = {k: deepcopy(v) for k, v in current.items() if k not in _SERVER_OWNED}

    if "name" in patch:
        if not isinstance(patch["name"], str) or not patch["name"]:
            return None
        body["name"] = patch["name"]
    for private_key, v1_key in (("enabled", "enabled"), ("hide_ssid", "hideName")):
        if private_key in patch:
            if not _is_bool(patch[private_key]):
                return None
            body[v1_key] = patch[private_key]
    if "x_passphrase" in patch:
        security = body.get("securityConfiguration")
        passphrase = patch["x_passphrase"]
        if not isinstance(security, dict) or security.get("type") not in _PERSONAL_SECURITY:
            return None
        if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63:
            return None
        security["passphrase"] = passphrase
    if "networkconf_id" in patch:
        if not v1_network_id:
            return None
        body["network"] = {"type": "SPECIFIC", "networkId": v1_network_id}
    if "wlan_band" in patch:
        bands = _BANDS.get(patch["wlan_band"])
        if bands is None:
            return None
        body["broadcastingFrequenciesGHz"] = bands
    return body
