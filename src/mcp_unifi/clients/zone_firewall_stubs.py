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


#: Index the first user-defined policy receives; later ones count up from here.
_FIRST_POLICY_INDEX = 10000


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
        # Next policy ``index``. A counter rather than ``len(self.policies)``,
        # which hands a new policy the index of one still in the list as soon
        # as an earlier policy has been deleted.
        self._next_index = _FIRST_POLICY_INDEX

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
            "index": self._next_index,
            "metadata": {"origin": USER_DEFINED},
        }
        self._next_index += 1
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


# ---------------------------------------------------------------------------
# A migrated Network 11 site, in the shapes read live on 2026-11-27
# ---------------------------------------------------------------------------

#: LANs a live-shaped site carries on top of the stub's seed networks:
#: ``(name, purpose, subnet)``. Guest lands in ``Hotspot``, the rest in
#: ``Internal``, the same zone assignment :meth:`ZoneFirewallStubState.zones`
#: computes.
LIVE_LANS: tuple[tuple[str, str, str], ...] = (
    ("TRUSTED", "corporate", "10.0.10.1/24"),
    ("MGMT", "corporate", "10.0.1.1/24"),
    ("IoT", "corporate", "10.0.50.1/24"),
    ("Guest", "guest", "10.0.60.1/24"),
)


def _v2_endpoint(
    zone_id: str,
    *,
    side: str,
    networks: list[str] | None = None,
    ips: list[str] | None = None,
    port: str = "",
) -> dict[str, Any]:
    """One v2 ``source``/``destination`` object, keyed as the live records are."""
    out: dict[str, Any] = {"match_opposite_ports": False, "zone_id": zone_id}
    if side == "source":
        out["match_mac"] = False
    if networks is not None:
        out.update(
            {
                "match_opposite_networks": False,
                "matching_target": "NETWORK",
                "matching_target_type": "SPECIFIC",
                "network_ids": list(networks),
            }
        )
    elif ips is not None:
        out.update(
            {
                "ips": list(ips),
                "match_opposite_ips": False,
                "matching_target": "IP",
                "matching_target_type": "SPECIFIC",
            }
        )
    else:
        out["matching_target"] = "ANY"
    if port:
        out["port"] = port
        out["port_matching_type"] = "SPECIFIC"
    else:
        out["port_matching_type"] = "ANY"
    return out


def _v2_policy(
    name: str,
    action: str,
    source: dict[str, Any],
    destination: dict[str, Any],
    *,
    index: int,
    predefined: bool = False,
    protocol: str = "all",
    enabled: bool = True,
    logging: bool = False,
    create_allow_respond: bool = False,
    connection_state_type: str = "ALL",
    connection_states: list[str] | None = None,
    origin_type: str | None = None,
    origin_id: str | None = None,
) -> UniFiRecord:
    """One v2 policy carrying every key the live list showed on every record."""
    return {
        "_id": str(uuid.uuid4()),
        "action": action,
        "connection_state_type": connection_state_type,
        "connection_states": list(connection_states or []),
        "create_allow_respond": create_allow_respond,
        "destination": destination,
        "enabled": enabled,
        "hits": 1526513 if not predefined else 0,
        "icmp_typename": "ANY",
        "icmp_v6_typename": "ANY",
        "index": index,
        "ip_version": "IPV4",
        "last_hit": 1795811740168 if not predefined else 0,
        "logging": logging,
        "match_ip_sec": False,
        "match_ip_sec_type": "MATCH_IP_SEC",
        "match_opposite_protocol": False,
        "name": name,
        "origin_id": origin_id,
        "origin_type": origin_type,
        "predefined": predefined,
        "protocol": protocol,
        "report_flow": True,
        "report_flow_supported": True,
        "schedule": {"mode": "ALWAYS", "repeat_on_days": [], "time_all_day": False},
        "source": source,
    }


#: Name of the policy the live site holds four times, once per zone pair.
ECOWITT = "Allow Ecowitt GW to Dewfront ingest"


def seed_live_zone_site(state: Any, *, user_policies: bool = True) -> None:
    """Turn a stub controller into a migrated Network 11 site.

    Shapes follow the read-only probe of a UCG-Fiber on Network 11.0.99
    (2026-11-27): UUID ``_id`` values with the old ObjectId kept as
    ``legacy_id``, six built-in zones whose ``external_id`` is the v1 zone
    id, and v2 policies carrying every key the live list showed. Policy
    names repeat across zone pairs, as :data:`ECOWITT` does live, and so does
    ``index``.

    ``user_policies=False`` leaves out the operator-created policies, which
    is a restore target that has the zones and the controller's own policies
    but nothing the operator made. Predefined policies are mirrored into the
    v1 list with a non-``USER_DEFINED`` origin, as a migrated console shows
    them through the Integration API. ``state`` is a
    :class:`~mcp_unifi.clients.stubs.StubState` (untyped here to keep the
    import one-way).
    """
    fw: ZoneFirewallStubState = state.zone_firewall
    fw.migrate()
    for name, purpose, subnet in LIVE_LANS:
        state.networks.append(
            {
                "_id": str(uuid.uuid4()),
                "legacy_id": uuid.uuid4().hex[:24],
                "external_id": str(uuid.uuid4()),
                "name": name,
                "purpose": purpose,
                "ip_subnet": subnet,
                "vlan_enabled": True,
                "enabled": True,
                "site_id": "default",
            }
        )
    nets = {str(n.get("name")): str(n["_id"]) for n in state.networks}

    members: dict[str, list[str]] = {name: [] for name in DEFAULT_ZONES}
    for net in state.networks:
        if net.get("purpose") in {"wan", "remote-user-vpn", "site-vpn"}:
            continue
        members["Hotspot" if net.get("purpose") == "guest" else "Internal"].append(str(net["_id"]))
    v2_zone = {name: str(uuid.uuid4()) for name in DEFAULT_ZONES}
    state.firewall_zones = [
        {
            "_id": v2_zone[name],
            "attr_no_edit": False,
            "cloud_template": None,
            "default_zone": True,
            "external_id": fw.zone_ids[name],
            "name": name,
            "network_ids": members[name],
            "zone_key": name.lower(),
        }
        for name in DEFAULT_ZONES
    ]

    z = v2_zone
    predefined = [
        _v2_policy(
            "Allow Port Forward Plex",
            "ALLOW",
            _v2_endpoint(z["External"], side="source"),
            _v2_endpoint(z["Internal"], side="destination", ips=["192.168.86.20"], port="32400"),
            index=30000,
            predefined=True,
            protocol="tcp",
            origin_type="port_forward",
            origin_id=str(uuid.uuid4()),
        ),
        _v2_policy(
            "Allow Return Traffic",
            "ALLOW",
            _v2_endpoint(z["External"], side="source"),
            _v2_endpoint(z["Internal"], side="destination"),
            index=30001,
            predefined=True,
            connection_state_type="RESPOND_ONLY",
        ),
        _v2_policy(
            "Block Invalid Traffic",
            "BLOCK",
            _v2_endpoint(z["External"], side="source"),
            _v2_endpoint(z["Internal"], side="destination"),
            index=30002,
            predefined=True,
            connection_state_type="CUSTOM",
            connection_states=["INVALID"],
        ),
        _v2_policy(
            "Allow All Traffic",
            "ALLOW",
            _v2_endpoint(z["Internal"], side="source"),
            _v2_endpoint(z["External"], side="destination"),
            index=30003,
            predefined=True,
        ),
    ]
    user: list[UniFiRecord] = []
    if user_policies:
        ecowitt = [
            _v2_policy(
                ECOWITT,
                "ALLOW",
                _v2_endpoint(z["Internal"], side="source", ips=["10.0.50.117/32"]),
                _v2_endpoint(z[dest], side="destination", ips=["192.168.86.20/32"], port="3700"),
                index=10000,
                protocol="tcp",
            )
            for dest in ("Internal", "Hotspot", "External", "Vpn")
        ]
        user = [
            *ecowitt,
            _v2_policy(
                "Allow TRUSTED to MGMT",
                "ALLOW",
                _v2_endpoint(z["Internal"], side="source", networks=[nets["TRUSTED"]]),
                _v2_endpoint(z["Internal"], side="destination", networks=[nets["MGMT"]]),
                index=10001,
            ),
            _v2_policy(
                "Block IoT to TRUSTED",
                "BLOCK",
                _v2_endpoint(z["Internal"], side="source", networks=[nets["IoT"]]),
                _v2_endpoint(z["Internal"], side="destination", networks=[nets["TRUSTED"]]),
                index=10002,
            ),
            _v2_policy(
                "Allow MGMT DNS",
                "ALLOW",
                _v2_endpoint(z["Internal"], side="source", networks=[nets["MGMT"]]),
                _v2_endpoint(z["Gateway"], side="destination", ips=["10.0.1.1"], port="53"),
                index=10000,
                protocol="tcp_udp",
            ),
            _v2_policy(
                "Block Guest to Internal",
                "BLOCK",
                _v2_endpoint(z["Hotspot"], side="source"),
                _v2_endpoint(z["Internal"], side="destination"),
                index=10000,
            ),
            _v2_policy(
                "Allow Vpn to Internal",
                "ALLOW",
                _v2_endpoint(z["Vpn"], side="source"),
                _v2_endpoint(z["Internal"], side="destination"),
                index=10000,
                create_allow_respond=True,
            ),
            _v2_policy(
                "Allow Dewfront web",
                "ALLOW",
                _v2_endpoint(z["External"], side="source"),
                _v2_endpoint(
                    z["Internal"], side="destination", ips=["192.168.86.20/32"], port="80,443"
                ),
                index=10000,
                protocol="tcp",
                enabled=False,
                logging=True,
            ),
        ]
    state.firewall_policies = [*user, *predefined]

    by_v2 = {v2_zone[name]: fw.zone_ids[name] for name in DEFAULT_ZONES}
    for policy in predefined:
        fw.policies.append(
            {
                "id": str(uuid.uuid4()),
                "name": policy["name"],
                "enabled": True,
                "action": {"type": policy["action"]},
                "source": {"zoneId": by_v2[policy["source"]["zone_id"]]},
                "destination": {"zoneId": by_v2[policy["destination"]["zone_id"]]},
                "ipProtocolScope": {"ipVersion": "IPV4"},
                "loggingEnabled": False,
                "index": policy["index"],
                "metadata": {"origin": "SYSTEM_DEFINED"},
            }
        )
