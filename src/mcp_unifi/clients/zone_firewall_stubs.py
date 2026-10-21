"""In-memory Zone-Based Firewall, in Integration API shapes (ADR 0009).

Separate from :mod:`mcp_unifi.clients.stubs`, whose v2 zone and policy seeds
back the read-only ``list_firewall_*`` tools. This one backs the v1 write
path and starts on **legacy** rulesets, like the console it models did before
migration, so every existing stub-mode test keeps seeing a legacy site. Tests
that want a zone-based site call :meth:`ZoneFirewallStubState.migrate`.

Zone membership is computed from the private network list on every read
rather than stored: a new guest network lands in ``Hotspot`` and every other
LAN in ``Internal``, which is what the zone-assignment defaults are documented
to do. Nothing here has been checked against a migrated console.
"""

from __future__ import annotations

import uuid
from typing import Any

from mcp_unifi.clients.errors import UniFiError
from mcp_unifi.clients.integration import ZBF_NOT_CONFIGURED, ZoneFirewallState
from mcp_unifi.clients.zone_policy import USER_DEFINED, WRITABLE_KEYS
from mcp_unifi.models import UniFiRecord

#: The default zones a migrated site starts with, in display order.
DEFAULT_ZONES: tuple[str, ...] = ("Internal", "External", "Gateway", "Vpn", "Hotspot", "Dmz")

#: Fields the published reference marks required on a policy POST or PUT.
_REQUIRED: tuple[str, ...] = (
    "action",
    "destination",
    "enabled",
    "ipProtocolScope",
    "loggingEnabled",
    "name",
    "source",
)


def v1_network_id(network: UniFiRecord) -> str | None:
    """A stub network's Integration API id: its ``external_id``, else its ``_id``."""
    ext = network.get("external_id")
    if isinstance(ext, str) and ext:
        return ext
    nid = network.get("_id")
    return nid if isinstance(nid, str) else None


class ZoneFirewallStubState:
    """Zones and policies for one stub controller."""

    def __init__(self) -> None:
        self.state: ZoneFirewallState = "legacy"
        self.zone_ids: dict[str, str] = {}
        self.policies: list[UniFiRecord] = []

    def migrate(self) -> None:
        """Turn this site zone-based, with the default zones and no user policies."""
        self.state = "configured"
        self.zone_ids = {name: str(uuid.uuid4()) for name in DEFAULT_ZONES}

    def _require_configured(self) -> None:
        if self.state != "configured":
            raise UniFiError(f"UniFi Integration returned 400: {{'code': '{ZBF_NOT_CONFIGURED}'}}")

    def zones(self, networks: list[UniFiRecord]) -> list[UniFiRecord]:
        self._require_configured()
        members: dict[str, list[str]] = {name: [] for name in DEFAULT_ZONES}
        for net in networks:
            purpose = net.get("purpose")
            v1_id = v1_network_id(net)
            if v1_id is None or purpose in {"wan", "remote-user-vpn", "site-vpn"}:
                continue
            members["Hotspot" if purpose == "guest" else "Internal"].append(v1_id)
        return [
            {
                "id": self.zone_ids[name],
                "name": name,
                "networkIds": members[name],
                "metadata": {"origin": "SYSTEM_DEFINED"},
            }
            for name in DEFAULT_ZONES
        ]

    def _validate(self, body: dict[str, Any]) -> None:
        missing = [k for k in _REQUIRED if k not in body]
        if missing:
            raise UniFiError(
                f"UniFi Integration returned 400: missing required field(s) {', '.join(missing)}"
            )
        unknown = sorted(set(body) - WRITABLE_KEYS)
        if unknown:
            raise UniFiError(f"UniFi Integration returned 400: unknown field(s) {unknown}")
        known_zones = set(self.zone_ids.values())
        for side in ("source", "destination"):
            zone_id = body[side].get("zoneId") if isinstance(body[side], dict) else None
            if zone_id not in known_zones:
                raise UniFiError(f"UniFi Integration returned 400: {side}.zoneId not found")

    def list_policies(self) -> list[UniFiRecord]:
        self._require_configured()
        return self.policies

    def get_policy(self, policy_id: str) -> UniFiRecord | None:
        self._require_configured()
        return next((p for p in self.policies if p.get("id") == policy_id), None)

    def create_policy(self, body: dict[str, Any]) -> UniFiRecord:
        self._require_configured()
        self._validate(body)
        record: UniFiRecord = {
            **body,
            "id": str(uuid.uuid4()),
            "index": 10000 + len(self.policies),
            "metadata": {"origin": USER_DEFINED},
        }
        self.policies.append(record)
        return record

    def update_policy(self, policy_id: str, body: dict[str, Any]) -> UniFiRecord:
        self._require_configured()
        self._validate(body)
        for i, policy in enumerate(self.policies):
            if policy.get("id") == policy_id:
                fixed = {k: policy[k] for k in ("id", "index", "metadata")}
                self.policies[i] = {**body, **fixed}
                return self.policies[i]
        raise UniFiError(f"UniFi Integration returned 404: firewall policy {policy_id} not found")

    def delete_policy(self, policy_id: str) -> bool:
        self._require_configured()
        before = len(self.policies)
        self.policies = [p for p in self.policies if p.get("id") != policy_id]
        if len(self.policies) == before:
            raise UniFiError(
                f"UniFi Integration returned 404: firewall policy {policy_id} not found"
            )
        return True
