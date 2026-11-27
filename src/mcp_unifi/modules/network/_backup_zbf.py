"""Zone-Based Firewall policies and zones in ``backup_config`` / ``restore_config``.

Network 11 migrated every site to the Zone-Based Firewall, so a backup without
zone policies carries nobody's firewall. This module is the policy half of the
backup envelope.

Backup
------
Reads the private v2 lists (``list_firewall_policies`` and
``list_firewall_zones``, the shapes read live on Network 11.0.99) and keeps
only operator-created policies, ``predefined: false``. Controller-managed
policies (return traffic, port-forward mirrors, the zone-pair defaults) are
left out: the console makes those itself and restore must never write one.

Records are stored portably, like the rest of the envelope: every zone
reference becomes the zone's name (``zone_name``), every network reference the
network's name (``network_names``), and any firewall-group reference the
group's name (``ip_group_name`` for ``ip_group_id`` and so on). Runtime and
controller-assigned keys are dropped (:data:`POLICY_DROP_FIELDS`). The zones
the policies point at are stored too, by name, with ``zone_key``, whether the
zone is built in, and the names of the networks in it, so a restore can say
which zone a target lacks and whether that is a custom zone.

Restore
-------
Writes through the Integration API (ADR 0009) with the same body builders
``create_firewall_policy`` uses (:mod:`mcp_unifi.clients.zone_policy`),
resolving zones by name with :func:`pick_zone` and networks by name, then
through ``external_id`` with :func:`v1_networks`. Identity is
``(name, source zone, destination zone)``, because policy names repeat
across zone pairs, and an identity the backup holds twice is held back. A
matching operator policy whose fields differ is updated so every field is the
backup's value again (:func:`update_for`), including the ones the backup sets
by leaving them out; a missing one is created. Restore never creates, updates
or deletes a controller-managed policy, never writes a zone, never reorders,
and never deletes an operator policy the backup lacks: those are reported. A
policy whose v2 shape the v1 body cannot express exactly (a schedule, an IPsec
match, a group or region match, a negated match, an ICMP type) is blocked
with the reason rather than written as an approximation, and so is one whose
copy on the site runs on a schedule. Zones are matched by name, so a policy is
also held back when its zone would cover different networks on the target: a
zone-wide side needs the same members the backup recorded, and a side naming
networks needs each of them in that zone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients import zone_policy as zp
from mcp_unifi.modules.network.firewall_policies import (
    PolicyLookupError,
    pick_zone,
    require_zone_based,
    v1_networks,
)

if TYPE_CHECKING:
    from mcp_unifi.backends import Backend

#: Envelope section names.
POLICIES = "firewall_policies"
ZONES = "firewall_zones"

#: Top-level v2 policy keys a backup drops: state, not configuration.
#: ``_id``/``legacy_id``/``site_id`` are controller-assigned; ``hits`` and
#: ``last_hit`` are runtime counters; ``origin_id``/``origin_type`` tie a
#: controller-made policy to what made it; ``predefined`` is always false for
#: what a backup keeps; ``report_flow_supported`` is a capability flag.
POLICY_DROP_FIELDS: frozenset[str] = frozenset(
    {
        "_id",
        "legacy_id",
        "site_id",
        "hits",
        "last_hit",
        "origin_id",
        "origin_type",
        "predefined",
        "report_flow_supported",
    }
)

#: ``zone_key`` of the zones a migrated console creates on its own.
BUILT_IN_ZONE_KEYS: frozenset[str] = frozenset(
    {"internal", "external", "gateway", "vpn", "hotspot", "dmz"}
)

#: v2 keys that are configuration but have no Integration API field. They are
#: kept in the backup and named in a restore warning; the console keeps its
#: own value for them.
NOT_CARRIED_FIELDS: tuple[str, ...] = ("report_flow",)

_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "action",
        "connection_state_type",
        "connection_states",
        "create_allow_respond",
        "description",
        "destination",
        "enabled",
        "icmp_typename",
        "icmp_v6_typename",
        "index",
        "ip_version",
        "logging",
        "match_ip_sec",
        "match_ip_sec_type",
        "match_opposite_protocol",
        "name",
        "protocol",
        "schedule",
        "source",
        *NOT_CARRIED_FIELDS,
        *POLICY_DROP_FIELDS,
    }
)

_ENDPOINT_KEYS: frozenset[str] = frozenset(
    {
        "zone_name",
        "matching_target",
        "matching_target_type",
        "network_names",
        "ips",
        "port",
        "port_matching_type",
        "match_opposite_networks",
        "match_opposite_ips",
        "match_opposite_ports",
        "match_mac",
    }
)

#: v2 ``ip_version`` to v1 ``ipProtocolScope.ipVersion``.
_IP_VERSIONS: dict[str, str] = {
    "IPV4": "IPV4",
    "IPV6": "IPV6",
    "BOTH": "IPV4_AND_IPV6",
    "IPV4_AND_IPV6": "IPV4_AND_IPV6",
}

#: Optional v1 filters an update removes when the backup's policy does not
#: set them. The v1 PUT replaces the whole policy (see
#: ``update_firewall_policy``), so a PUT without one is the same "every
#: connection state" / "no IPsec match" a create without it gets. The apply
#: step re-reads the policy and fails (rolling back) if the console kept one.
RESET_BY_OMISSION: tuple[str, ...] = ("connectionStateFilter", "ipsecFilter")


def schedule_is_always(value: Any) -> bool:
    """True when a v1 ``schedule`` readback means "always".

    Absent, the plain string ``"ALWAYS"`` or an object whose ``mode`` is
    ``"ALWAYS"``, in any case. Anything else is not known to mean always.
    """
    if value in (None, {}):
        return True
    if isinstance(value, str):
        return value.strip().upper() == "ALWAYS"
    mode = value.get("mode") if isinstance(value, dict) else None
    return isinstance(mode, str) and mode.strip().upper() == "ALWAYS"


def update_for(
    current: dict[str, Any], body: dict[str, Any], description: str
) -> tuple[list[str], dict[str, Any]]:
    """The fields that differ and the PUT body that sets the backup's whole policy.

    Every writable field the backup describes is put back to the backup's
    value, including the ones it describes by leaving them out: an empty
    description is cleared, an all-states policy loses a connection-state
    filter, a policy without an IPsec match loses an IPsec filter. A
    schedule is the one field this server cannot write (its v1 shape is not
    known), so a site's policy on any schedule other than always raises
    :class:`Blocked` rather than being reported as a match. An ALWAYS
    schedule the site reports is sent back as the site has it.
    """
    before = zp.put_body(current, {})
    schedule = before.get("schedule")
    if not schedule_is_always(schedule):
        raise Blocked(
            f"the site's policy has the schedule {schedule!r}, which is not known to mean "
            "always, and the backup's runs "
            "always; this server cannot write a v1 schedule, so the policy is held back: "
            "clear the schedule on the console, then run restore_config again"
        )
    payload: dict[str, Any] = {k: v for k, v in before.items() if k == "schedule"}
    payload.update(body)
    if description or before.get("description"):
        payload["description"] = description
    else:
        payload.pop("description", None)

    changes: list[str] = []
    for key in sorted({*body, "description", *RESET_BY_OMISSION}):
        have = before.get(key)
        if key == "description":
            differs = (have or "") != description
        elif key in RESET_BY_OMISSION and key not in body:
            differs = _is_set(have)
        else:
            differs = have != body.get(key)
        if differs:
            changes.append(key)
    return changes, payload


def reset_kept(readback: dict[str, Any] | None, action: dict[str, Any]) -> list[str]:
    """Fields an applied update meant to reset that the console still holds."""
    if readback is None:
        return ["the whole policy (it is gone)"]
    payload = action.get("payload") or {}
    kept = [
        key
        for key in RESET_BY_OMISSION
        if key in action.get("changes", []) and key not in payload and _is_set(readback.get(key))
    ]
    if "description" in action.get("changes", []) and (readback.get("description") or "") != (
        payload.get("description") or ""
    ):
        kept.append("description")
    return kept


def norm(value: object) -> str:
    """Trim + lowercase a value for case-insensitive matching."""
    if value is None:
        return ""
    return str(value).strip().lower()


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def _names_by_id(records: list[dict[str, Any]]) -> dict[str, str]:
    """Map every id a record is known by (``_id``, ``legacy_id``) to its name."""
    out: dict[str, str] = {}
    for rec in records:
        name = rec.get("name") if isinstance(rec, dict) else None
        if not isinstance(name, str) or not name:
            continue
        for key in ("_id", "legacy_id"):
            rid = rec.get(key)
            if isinstance(rid, str) and rid:
                out[rid] = name
    return out


def _portable_endpoint(
    side: str,
    endpoint: dict[str, Any],
    *,
    zone_names: dict[str, str],
    network_names: dict[str, str],
    group_names: dict[str, str],
    problems: list[str],
) -> dict[str, Any]:
    """One ``source``/``destination`` with every id swapped for a name."""
    out: dict[str, Any] = {}
    for key, value in endpoint.items():
        if key == "zone_id":
            name = zone_names.get(value) if isinstance(value, str) else None
            if name is None:
                problems.append(f"{side} zone {value!r} is not in the site's zone list")
            out["zone_name"] = name
        elif key == "network_ids":
            names: list[str] = []
            for nid in value if isinstance(value, list) else [value]:
                found = network_names.get(nid) if isinstance(nid, str) else None
                if found is None:
                    problems.append(f"{side} network {nid!r} is not a named network on the site")
                else:
                    names.append(found)
            out["network_names"] = names
        elif key.endswith(("_group_id", "_group_ids")):
            plural = key.endswith("_ids")
            stem = key[: -len("_ids")] if plural else key[: -len("_id")]
            refs = value if isinstance(value, list) else [value]
            group_refs: list[str | None] = []
            for gid in refs:
                if gid in ("", None):
                    continue
                found = group_names.get(gid) if isinstance(gid, str) else None
                if found is None:
                    problems.append(f"{side} {key} {gid!r} is not a named firewall group")
                group_refs.append(found)
            out[f"{stem}_names" if plural else f"{stem}_name"] = (
                group_refs if plural else (group_refs[0] if group_refs else None)
            )
        else:
            out[key] = value
    return out


def backup_sections(
    *,
    policies: list[dict[str, Any]],
    zones: list[dict[str, Any]],
    networks: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Build the envelope's ``firewall_policies`` and ``firewall_zones`` sections.

    ``policies`` and ``zones`` are the private v2 lists; ``networks`` and
    ``groups`` are the private lists WITH their ``_id``, for name lookups.
    Only ``predefined: false`` policies are kept: a record without the flag
    is not known to be the operator's, and restore must never write a
    controller-managed one. A reference that does not resolve to a name is
    listed under the policy's ``unresolved`` key, and restore blocks it.
    """
    zone_by_id = {
        str(z["_id"]): z for z in zones if isinstance(z, dict) and isinstance(z.get("_id"), str)
    }
    zone_names = {zid: str(z.get("name")) for zid, z in zone_by_id.items() if z.get("name")}
    network_names = _names_by_id(networks)
    group_names = _names_by_id(groups)

    kept: list[dict[str, Any]] = []
    used_zones: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict) or policy.get("predefined") is not False:
            continue
        problems: list[str] = []
        record: dict[str, Any] = {}
        for key, value in policy.items():
            if key in POLICY_DROP_FIELDS:
                continue
            if key in ("source", "destination") and isinstance(value, dict):
                zid = value.get("zone_id")
                if isinstance(zid, str):
                    used_zones.add(zid)
                record[key] = _portable_endpoint(
                    key,
                    value,
                    zone_names=zone_names,
                    network_names=network_names,
                    group_names=group_names,
                    problems=problems,
                )
            else:
                record[key] = value
        if problems:
            record["unresolved"] = problems
        kept.append(record)

    zone_records: list[dict[str, Any]] = []
    for zid, zone in zone_by_id.items():
        if zid not in used_zones:
            continue
        zone_key = zone.get("zone_key")
        member_ids = zone.get("network_ids")
        zone_records.append(
            {
                "name": zone.get("name"),
                "zone_key": zone_key,
                "built_in": zone.get("default_zone") is True
                or (isinstance(zone_key, str) and zone_key.lower() in BUILT_IN_ZONE_KEYS),
                "network_names": [
                    network_names[nid]
                    for nid in (member_ids if isinstance(member_ids, list) else [])
                    if isinstance(nid, str) and nid in network_names
                ],
            }
        )
    return {POLICIES: kept, ZONES: zone_records}


# ---------------------------------------------------------------------------
# Restore: v2 portable record -> create_body arguments
# ---------------------------------------------------------------------------


class Untranslatable(ValueError):
    """The backed-up policy cannot be expressed exactly as a v1 body."""


class Blocked(ValueError):
    """A reference in the policy does not resolve on the target."""


@dataclass(frozen=True)
class _Side:
    zone: str
    network_names: tuple[str, ...]
    addresses: tuple[str, ...]
    ports: str


@dataclass(frozen=True)
class _Intent:
    name: str
    action: str
    source: _Side
    destination: _Side
    protocol: str
    ip_version: str
    allow_return_traffic: bool
    enabled: bool
    logging: bool
    description: str
    connection_states: tuple[str, ...]


def _is_set(value: Any) -> bool:
    return value not in (None, False, "", [], {})


def _bool(spec: dict[str, Any], key: str, default: bool) -> bool:
    value = spec.get(key, default)
    if not isinstance(value, bool):
        raise Untranslatable(f"{key} is {value!r}, not true or false")
    return value


def _side(label: str, endpoint: Any) -> _Side:
    if not isinstance(endpoint, dict):
        raise Untranslatable(f"{label} is missing")
    unknown = sorted(k for k, v in endpoint.items() if k not in _ENDPOINT_KEYS and _is_set(v))
    if unknown:
        raise Untranslatable(
            f"{label} sets {', '.join(unknown)}, which the Integration API body does not carry"
        )
    zone = endpoint.get("zone_name")
    if not isinstance(zone, str) or not zone:
        raise Untranslatable(f"{label} has no zone name")
    for flag in ("match_opposite_networks", "match_opposite_ips", "match_opposite_ports"):
        if _is_set(endpoint.get(flag)):
            raise Untranslatable(f"{label} sets {flag} (a negated match)")
    if _is_set(endpoint.get("match_mac")):
        raise Untranslatable(f"{label} sets match_mac")

    target = endpoint.get("matching_target") or "ANY"
    target_type = endpoint.get("matching_target_type")
    networks = endpoint.get("network_names") or []
    ips = endpoint.get("ips") or []
    if target != "ANY" and target_type not in (None, "SPECIFIC"):
        raise Untranslatable(f"{label} matches by matching_target_type {target_type}")
    net_names: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    if target == "ANY":
        if networks or ips:
            raise Untranslatable(f"{label} matches ANY but also lists networks or addresses")
    elif target == "NETWORK":
        if not isinstance(networks, list) or not networks or ips:
            raise Untranslatable(f"{label} matches NETWORK without a plain network list")
        net_names = tuple(str(n) for n in networks)
    elif target == "IP":
        if not isinstance(ips, list) or not ips or networks:
            raise Untranslatable(f"{label} matches IP without a plain address list")
        addresses = tuple(str(a) for a in ips)
    else:
        raise Untranslatable(f"{label} matches by {target}")

    port_type = endpoint.get("port_matching_type") or "ANY"
    port = endpoint.get("port")
    if port_type == "ANY":
        ports = ""
    elif port_type == "SPECIFIC" and isinstance(port, str | int) and str(port).strip():
        ports = str(port).strip()
    else:
        raise Untranslatable(f"{label} matches ports by {port_type}")
    return _Side(zone=zone, network_names=net_names, addresses=addresses, ports=ports)


def translate(spec: dict[str, Any]) -> _Intent:
    """Read a backed-up v2 policy as ``create_firewall_policy`` arguments.

    Every v2 key is either mapped exactly, required to hold its "off" value,
    or named in :data:`NOT_CARRIED_FIELDS`. Anything else raises
    :class:`Untranslatable` with the key, so a restore never writes a policy
    that matches more, or less, than the one in the backup.
    """
    unknown = sorted(k for k, v in spec.items() if k not in _TOP_LEVEL_KEYS and _is_set(v))
    if unknown:
        raise Untranslatable(f"sets {', '.join(unknown)}, which the Integration API body lacks")
    name = spec.get("name")
    if not isinstance(name, str) or not name.strip():
        raise Untranslatable("has no name")
    action = str(spec.get("action", "")).upper()
    if action not in zp.ACTIONS:
        raise Untranslatable(f"action {spec.get('action')!r} is not ALLOW, BLOCK or REJECT")

    protocol = str(spec.get("protocol") or "all").lower()
    if protocol not in zp.PROTOCOLS:
        raise Untranslatable(f"protocol {spec.get('protocol')!r}")
    if _is_set(spec.get("match_opposite_protocol")):
        raise Untranslatable("sets match_opposite_protocol (a negated protocol match)")
    ip_version = _IP_VERSIONS.get(str(spec.get("ip_version") or "IPV4").upper())
    if ip_version is None:
        raise Untranslatable(f"ip_version {spec.get('ip_version')!r}")
    for key in ("icmp_typename", "icmp_v6_typename"):
        if spec.get(key) not in (None, "", "ANY"):
            raise Untranslatable(f"{key} is {spec.get(key)!r}; only ANY can be written")
    if _is_set(spec.get("match_ip_sec")):
        raise Untranslatable("sets match_ip_sec (an IPsec match)")
    schedule = spec.get("schedule")
    if schedule is not None and (
        not isinstance(schedule, dict) or schedule.get("mode", "ALWAYS") != "ALWAYS"
    ):
        mode = schedule.get("mode") if isinstance(schedule, dict) else schedule
        raise Untranslatable(f"schedule mode is {mode!r}; only ALWAYS can be written")

    state_type = spec.get("connection_state_type") or "ALL"
    raw_states = spec.get("connection_states") or []
    if state_type == "ALL":
        states: tuple[str, ...] = ()
    elif state_type == "CUSTOM" and isinstance(raw_states, list) and raw_states:
        states = tuple(str(s) for s in raw_states)
    else:
        raise Untranslatable(f"connection_state_type is {state_type!r}")

    description = spec.get("description") or ""
    if not isinstance(description, str):
        raise Untranslatable("description is not text")
    return _Intent(
        name=name,
        action=action,
        source=_side("source", spec.get("source")),
        destination=_side("destination", spec.get("destination")),
        protocol=protocol,
        ip_version=ip_version,
        allow_return_traffic=_bool(spec, "create_allow_respond", False)
        if action == "ALLOW"
        else True,
        enabled=_bool(spec, "enabled", True),
        logging=_bool(spec, "logging", False),
        description=description,
        connection_states=states,
    )


# ---------------------------------------------------------------------------
# Restore: plan
# ---------------------------------------------------------------------------


def _part(record: dict[str, Any], key: str) -> dict[str, Any]:
    """``record[key]`` when it is an object, else an empty one."""
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _label(spec: dict[str, Any]) -> dict[str, Any]:
    src, dst = _part(spec, "source"), _part(spec, "destination")
    return {
        "type": POLICIES,
        "name": spec.get("name"),
        "source_zone": src.get("zone_name"),
        "destination_zone": dst.get("zone_name"),
    }


def _identity(name: object, source_zone: object, destination_zone: object) -> tuple[str, str, str]:
    return (norm(name), norm(source_zone), norm(destination_zone))


def _pair_key(pair: tuple[Any, Any]) -> tuple[str, str]:
    return (norm(pair[0]), norm(pair[1]))


def _index(spec: dict[str, Any]) -> int:
    value = spec.get("index")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


async def plan_policies(
    backend: Backend,
    specs: list[dict[str, Any]],
    zones: list[dict[str, Any]],
    *,
    networks_created: set[str],
    networks_deleted: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Plan the policy section of a restore. Returns ``(actions, warnings)``.

    ``networks_created`` / ``networks_deleted`` are the normalised names of
    networks the rest of the plan creates or deletes. A policy is resolved
    against the networks on the site NOW, so one pointing at a network this
    restore creates is blocked with a note to run the restore again; the
    body every action carries is then exactly what the confirm token sends.
    """
    try:
        await require_zone_based(backend)
    except PolicyLookupError as exc:
        skipped = [
            {**_label(spec), "action": "skip", "reason": f"not restored: {exc}"} for spec in specs
        ]
        notes = (
            [f"{len(specs)} zone policy(ies) in the backup were not restored: {exc}."]
            if specs
            else []
        )
        return skipped, notes

    zones_v1 = [z for z in await backend.list_v1_firewall_zones() if isinstance(z, dict)]
    live = [p for p in await backend.list_v1_firewall_policies() if isinstance(p, dict)]
    networks = [n for n in await backend.list_networks() if isinstance(n, dict)]
    zone_name_by_v1 = {str(z.get("id")): str(z.get("name")) for z in zones_v1}
    backup_zones = {norm(z.get("name")): z for z in zones if isinstance(z, dict)}
    nets_by_name: dict[str, list[dict[str, Any]]] = {}
    for net in networks:
        if norm(net.get("name")):
            nets_by_name.setdefault(norm(net.get("name")), []).append(net)

    # Which networks each target zone holds, by name. A v1 network id the
    # site cannot name stays in as a marker, so it can only ever differ.
    name_by_v1: dict[str, str] = {}
    for net in networks:
        private_id = net.get("_id")
        if not isinstance(private_id, str) or not norm(net.get("name")):
            continue
        v1_id = await backend.v1_network_id(private_id)
        if v1_id:
            name_by_v1[v1_id] = str(net.get("name"))

    def _members(zone_v1_id: str) -> dict[str, str]:
        """``{normalised name: display name}`` of the networks in a target zone."""
        zone = next((z for z in zones_v1 if str(z.get("id")) == zone_v1_id), {})
        raw_ids = zone.get("networkIds")
        ids: list[Any] = raw_ids if isinstance(raw_ids, list) else []
        out: dict[str, str] = {}
        for nid in ids:
            name = name_by_v1.get(str(nid), f"<unnamed network {nid}>")
            out[norm(name)] = name
        return out

    def _check_membership(side: _Side, zone_v1_id: str, label: str) -> None:
        """Hold back a side whose zone would cover different networks here.

        A zone-wide side (no networks, no addresses) needs the target zone to
        hold exactly the networks the backup's zone held, with none of them
        deleted by this restore. A side naming networks needs each to sit in
        the target zone. An address side is not affected.
        """
        members = _members(zone_v1_id)
        if side.network_names:
            outside = [n for n in side.network_names if norm(n) not in members]
            if outside:
                raise Blocked(
                    f"{label} network(s) {', '.join(repr(n) for n in outside)} are not in "
                    f"zone {side.zone!r} on this site, so the policy would not apply to them"
                )
            return
        if side.addresses:
            return
        held = backup_zones.get(norm(side.zone))
        recorded = held.get("network_names") if isinstance(held, dict) else None
        if not isinstance(recorded, list):
            raise Blocked(
                f"{label} matches all of zone {side.zone!r}, and the backup does not record "
                "which networks sat in it, so restore cannot tell what it would cover here"
            )
        wanted = {norm(n): str(n) for n in recorded}
        only_backup = sorted(wanted[k] for k in wanted.keys() - members.keys())
        only_site = sorted(members[k] for k in members.keys() - wanted.keys())
        deleted = sorted(members[k] for k in members.keys() & networks_deleted)
        if only_backup or only_site or deleted:
            parts = []
            if only_backup:
                parts.append(f"only in the backup: {', '.join(only_backup)}")
            if only_site:
                parts.append(f"only on this site: {', '.join(only_site)}")
            if deleted:
                parts.append(f"deleted by this restore: {', '.join(deleted)}")
            raise Blocked(
                f"{label} matches all of zone {side.zone!r}, which holds different networks "
                f"here than in the backup ({'; '.join(parts)}), so the policy would cover "
                "different networks"
            )

    def _zone(name: str, label: str) -> str:
        try:
            return pick_zone(zones_v1, name, label)
        except PolicyLookupError as exc:
            held = backup_zones.get(norm(name))
            if isinstance(held, dict) and held.get("built_in") is False:
                raise Blocked(
                    f"{label} {name!r} is a custom zone this site does not have; restore "
                    "does not create zones: create it on the console, then run again"
                ) from exc
            raise Blocked(f"{label} {name!r} is not a zone on this site") from exc

    async def _networks(names: tuple[str, ...], label: str) -> list[str]:
        private: list[str] = []
        for name in names:
            key = norm(name)
            held = nets_by_name.get(key, [])
            if key in networks_deleted:
                raise Blocked(f"{label} network {name!r} is deleted by this restore")
            if not held:
                later = (
                    "; this restore creates it, so run restore_config again afterwards"
                    if key in networks_created
                    else ""
                )
                raise Blocked(f"{label} network {name!r} is not on the site{later}")
            if len(held) > 1:
                raise Blocked(f"{label}: {len(held)} networks on the site are named {name!r}")
            private.append(str(held[0].get("_id")))
        try:
            return await v1_networks(backend, private, label)
        except PolicyLookupError as exc:
            raise Blocked(str(exc)) from exc

    async def _body(intent: _Intent) -> dict[str, Any]:
        source_zone = _zone(intent.source.zone, "source zone")
        destination_zone = _zone(intent.destination.zone, "destination zone")
        source_networks = await _networks(intent.source.network_names, "source")
        destination_networks = await _networks(intent.destination.network_names, "destination")
        _check_membership(intent.source, source_zone, "source")
        _check_membership(intent.destination, destination_zone, "destination")
        try:
            return zp.create_body(
                name=intent.name,
                action=intent.action,
                source=zp.endpoint(
                    source_zone,
                    network_ids=source_networks,
                    addresses=intent.source.addresses,
                    ports=intent.source.ports,
                ),
                destination=zp.endpoint(
                    destination_zone,
                    network_ids=destination_networks,
                    addresses=intent.destination.addresses,
                    ports=intent.destination.ports,
                ),
                protocol=intent.protocol,
                ip_version=intent.ip_version,
                allow_return_traffic=intent.allow_return_traffic,
                enabled=intent.enabled,
                logging=intent.logging,
                description=intent.description,
                connection_states=intent.connection_states,
            )
        except zp.PolicyBodyError as exc:
            raise Blocked(str(exc)) from exc

    user_live: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    managed_live: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for policy in live:
        src, dst = _part(policy, "source"), _part(policy, "destination")
        ident = _identity(
            policy.get("name"),
            zone_name_by_v1.get(str(src.get("zoneId")), ""),
            zone_name_by_v1.get(str(dst.get("zoneId")), ""),
        )
        (user_live if zp.is_user_defined(policy) else managed_live).setdefault(ident, []).append(
            policy
        )

    ordered = sorted(enumerate(specs), key=lambda pair: (_index(pair[1]), pair[0]))
    backup_counts: dict[tuple[str, str, str], int] = {}
    for spec in specs:
        lab = _label(spec)
        ident = _identity(lab["name"], lab["source_zone"], lab["destination_zone"])
        backup_counts[ident] = backup_counts.get(ident, 0) + 1

    actions: list[dict[str, Any]] = []
    reported: set[tuple[str, str, str]] = set()
    # Zone pairs this restore creates or updates in, with the ids it updates;
    # and, per pair, (backup index, backup position, site index) of every
    # matched policy, to spot an evaluation order that differs.
    touched_pairs: dict[tuple[str, str], tuple[tuple[Any, Any], set[str]]] = {}
    matched_order: dict[tuple[str, str], tuple[tuple[Any, Any], list[tuple[int, int, int]]]] = {}
    for position, spec in ordered:
        lab = _label(spec)
        ident = _identity(lab["name"], lab["source_zone"], lab["destination_zone"])

        def _blocked(reason: str, _lab: dict[str, Any] = lab, _spec: Any = spec) -> None:
            actions.append({**_lab, "action": "blocked", "reason": reason, "record": _spec})

        if spec.get("predefined") is True:
            _blocked("a predefined policy; restore never writes controller-managed policies")
            continue
        if spec.get("unresolved"):
            _blocked(f"the backup could not name what it points at: {spec['unresolved']}")
            continue
        if ident in managed_live:
            _blocked(
                "the site holds a controller-managed policy with this name in this zone "
                "pair; restore never touches controller-managed policies"
            )
            continue
        held = user_live.get(ident, [])
        if backup_counts[ident] > 1 or len(held) > 1:
            if ident not in reported:
                reported.add(ident)
                _blocked(
                    f"duplicate identity: {backup_counts[ident]} in the backup, {len(held)} "
                    "on the site with this name and zone pair; restore cannot tell which "
                    "is which, so it creates and updates none of them"
                )
            continue
        try:
            intent = translate(spec)
            body = await _body(intent)
        except Untranslatable as exc:
            _blocked(f"cannot be written exactly through the Integration API: {exc}")
            continue
        except Blocked as exc:
            _blocked(str(exc))
            continue

        pair = (lab["source_zone"], lab["destination_zone"])
        if not held:
            actions.append({**lab, "action": "create", "payload": body})
            touched_pairs.setdefault(_pair_key(pair), (pair, set()))
            continue
        current = held[0]
        if isinstance(current.get("index"), int):
            matched_order.setdefault(_pair_key(pair), (pair, []))[1].append(
                (_index(spec), position, current["index"])
            )
        try:
            changes, payload = update_for(current, body, intent.description)
        except Blocked as exc:
            _blocked(str(exc))
            continue
        if changes:
            actions.append(
                {
                    **lab,
                    "action": "update",
                    "id": current.get("id"),
                    "changes": changes,
                    "payload": payload,
                    "before": zp.put_body(current, {}),
                }
            )
            touched_pairs.setdefault(_pair_key(pair), (pair, set()))[1].add(str(current.get("id")))

    for ident, held in user_live.items():
        if ident in backup_counts:
            continue
        for policy in held:
            src, dst = _part(policy, "source"), _part(policy, "destination")
            actions.append(
                {
                    "type": POLICIES,
                    "name": policy.get("name"),
                    "source_zone": zone_name_by_v1.get(str(src.get("zoneId"))),
                    "destination_zone": zone_name_by_v1.get(str(dst.get("zoneId"))),
                    "action": "skip",
                    "id": policy.get("id"),
                    "reason": (
                        "not in the backup; restore never deletes zone policies, so it stays"
                    ),
                }
            )

    warnings: list[str] = []
    crowded = []
    for key, (pair, updated_ids) in touched_pairs.items():
        others = [
            p
            for ident, held in user_live.items()
            if (ident[1], ident[2]) == key
            for p in held
            if str(p.get("id")) not in updated_ids
        ]
        if others:
            crowded.append(f"{pair[0]} -> {pair[1]}")
    if crowded:
        warnings.append(
            f"Evaluation order: zone pair(s) {', '.join(sorted(crowded))} already hold other "
            "user policies. The console checks a pair's policies in order and the first "
            "match wins; a created policy lands after the ones already there, and restore "
            "does not reorder. Check the order of those pairs on the console."
        )
    reordered = []
    for pair, rows in matched_order.values():
        site_indexes = [site for _, _, site in sorted(rows)]
        if site_indexes != sorted(site_indexes):
            reordered.append(f"{pair[0]} -> {pair[1]}")
    if reordered:
        warnings.append(
            f"Evaluation order differs from the backup in zone pair(s) "
            f"{', '.join(sorted(reordered))}: the matched policies sit in a different order "
            "on the site. Restore does not reorder, and the first match wins, so check "
            "them on the console."
        )
    carried = sorted(
        {key for spec in specs for key in NOT_CARRIED_FIELDS if spec.get(key) is not None}
    )
    if any(a["action"] in ("create", "update") for a in actions) and carried:
        warnings.append(
            f"The zone policy field(s) {', '.join(carried)} have no Integration API "
            "equivalent, so restored and updated policies keep the console's own value."
        )
    missing_custom = sorted(
        str(z.get("name"))
        for z in zones
        if isinstance(z, dict)
        and z.get("built_in") is False
        and not zp.find_by_id_or_name(zones_v1, str(z.get("name")))
    )
    if missing_custom:
        warnings.append(
            f"Custom zone(s) {', '.join(missing_custom)} are not on this site, and restore "
            "does not create zones. Create them on the console and run restore_config again."
        )
    return actions, warnings
