"""Network drift auditing.

``audit_network_drift`` compares the current controller state to a declared
YAML spec and returns a structured diff. Read-only — never mutates.

Spec format
-----------
The spec is a small YAML document. Each top-level key is optional; resources
not declared in the spec are simply not audited.

.. code-block:: yaml

    networks:
      - name: "IoT"
        vlan: 50
        subnet: "10.50.0.0/24"
    wlans:
      - name: "Cameras-IoT"
        network: "IoT"        # references networks[].name (case-insensitive)
        security: "wpapsk"
    firewall_rules:
      - name: "Block IoT to LAN"
        action: "drop"
        src: "10.50.0.0/24"   # matches src_address
        dst: "192.168.86.0/24" # matches dst_address
    firewall_policies:        # Zone-Based Firewall (Network 9.x+), v2 API
      - name: "Allow LAN to IoT"
        action: "allow"
        source_zone: "LAN"    # resolved from source.zone_id
        destination_zone: "IoT"

Matching rules
--------------
* Resources are matched by ``name`` (case-insensitive, leading/trailing
  whitespace stripped).
* Spec resources missing from the controller surface a drift entry with
  ``actual: null``.
* Controller resources missing from the spec surface a drift entry with
  ``expected: null`` (extra resources that the spec did not authorize).
* Field-level drift surfaces one entry per mismatched field.
* A name the controller holds more than once surfaces a ``_duplicate`` entry,
  and a controller record with no name surfaces as an extra named
  ``<unnamed>``. Neither can be matched to a spec item, so neither is in sync.
* A spec key with no comparison behind it (an unknown section, or an item key
  outside the section's field map) is listed under ``not_compared``. It is
  never dropped, and it holds ``in_sync`` false.

Return shape
------------
.. code-block:: json

    {
      "in_sync": false,
      "controller": "default",
      "summary": "3 drift(s) across 2 resource type(s)",
      "drifts": [
        {"resource_type": "vlan", "name": "iot",
         "field": "subnet", "expected": "10.50.0.0/24", "actual": "10.50.0.0/16"}
      ],
      "not_compared": []
    }
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import yaml

from mcp_unifi.annotations import READ_ONLY
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedYaml,
)
from mcp_unifi.modules.network._common import format_json, make_err, zone_names_by_id

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.drift")


# Field mappings from spec keys to controller record keys. Kept explicit so the
# spec stays human-readable while the controller's underlying schema (which uses
# UniFi's wire field names) can be matched cleanly.
NETWORK_FIELDS: dict[str, str] = {
    "vlan": "vlan",
    "subnet": "ip_subnet",
    "purpose": "purpose",
}

WLAN_FIELDS: dict[str, str] = {
    "enabled": "enabled",
    "security": "security",
    "wpa_mode": "wpa_mode",
    "is_guest": "is_guest",
    "hide_ssid": "hide_ssid",
    "wlan_band": "wlan_band",
}

# Firewall spec fields are aliased to the wire fields used by the controller.
FIREWALL_FIELDS: dict[str, str] = {
    "action": "action",
    "ruleset": "ruleset",
    "protocol": "protocol",
    "src": "src_address",
    "dst": "dst_address",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "enabled": "enabled",
}

# Zone-Based Firewall policy spec fields. ``source_zone`` / ``destination_zone``
# are resolved from ``source.zone_id`` / ``destination.zone_id`` via the zone
# list before the diff runs; the wire record itself carries only ids.
FIREWALL_POLICY_FIELDS: dict[str, str] = {
    "action": "action",
    "enabled": "enabled",
    "protocol": "protocol",
    "index": "index",
    "source_zone": "source_zone",
    "destination_zone": "destination_zone",
}


def _norm_name(value: object) -> str:
    """Normalise a resource name for matching: trim + lowercase."""
    if value is None:
        return ""
    return str(value).strip().lower()


#: Spec keys each section understands, beyond its field map. Anything else a
#: spec item carries is reported under ``not_compared`` rather than dropped.
_SECTION_KEYS: dict[str, tuple[str, frozenset[str]]] = {
    "networks": ("vlan", frozenset({"name", *NETWORK_FIELDS})),
    "wlans": ("wlan", frozenset({"name", "network", *WLAN_FIELDS})),
    "firewall_rules": ("firewall_rule", frozenset({"name", *FIREWALL_FIELDS})),
    "firewall_policies": ("firewall_policy", frozenset({"name", *FIREWALL_POLICY_FIELDS})),
}


def _group_by_name(
    records: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """Group controller records by lowercase ``name``.

    Returns ``(groups, nameless)``. Every record lands somewhere: a name the
    controller holds twice keeps both records, and a record with no name is
    returned separately so the caller can report it. This used to be a dict
    keyed by name that kept the last duplicate and skipped nameless records,
    so an unauthorised second rule sharing a declared rule's name, or a rule
    with no name at all, left the audit reporting ``in_sync: true``.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    nameless: list[dict[str, Any]] = []
    for rec in records:
        key = _norm_name(rec.get("name"))
        if not key:
            nameless.append(rec)
            continue
        groups.setdefault(key, []).append(rec)
    return groups, nameless


def _presence_drifts(
    *,
    resource_type: str,
    groups: dict[str, list[dict[str, Any]]],
    nameless: list[dict[str, Any]],
    spec_names: set[str],
) -> list[dict[str, Any]]:
    """Report controller records the spec did not authorise.

    Three shapes count: a name the spec does not declare (``_resource`` with
    ``expected: null``), a name the controller holds more than once
    (``_duplicate``, expected 1, actual the count, whether or not the spec
    declares it), and a record with no name at all (``_resource`` under the
    name ``<unnamed>``, with its ``id`` so it can be found). Only called for
    a section the spec includes.
    """
    drifts: list[dict[str, Any]] = []
    for actual_name, matches in groups.items():
        if actual_name not in spec_names:
            drifts.append(
                {
                    "resource_type": resource_type,
                    "name": actual_name,
                    "field": "_resource",
                    "expected": None,
                    "actual": "present",
                }
            )
        if len(matches) > 1:
            drifts.append(
                {
                    "resource_type": resource_type,
                    "name": actual_name,
                    "field": "_duplicate",
                    "expected": 1,
                    "actual": len(matches),
                }
            )
    for rec in nameless:
        drifts.append(
            {
                "resource_type": resource_type,
                "name": "<unnamed>",
                "field": "_resource",
                "expected": None,
                "actual": "present",
                "id": rec.get("_id"),
            }
        )
    return drifts


def _not_compared(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """List every spec section and item key the audit has no comparison for.

    A key with no mapping used to be skipped without a word, so a spec that
    pinned ``dst_port`` or a misspelt ``subnett`` came back ``in_sync: true``
    having checked nothing. Each one is now named here instead.
    """
    out: list[dict[str, Any]] = []
    for section, items in spec.items():
        known = _SECTION_KEYS.get(str(section))
        if known is None:
            out.append(
                {
                    "resource_type": str(section),
                    "name": None,
                    "field": "_section",
                    "expected": items,
                }
            )
            continue
        resource_type, keys = known
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = _norm_name(item.get("name")) or "<unnamed>"
            for key, value in item.items():
                if key not in keys:
                    out.append(
                        {
                            "resource_type": resource_type,
                            "name": name,
                            "field": str(key),
                            "expected": value,
                        }
                    )
    return out


def _diff_fields(
    *,
    resource_type: str,
    name: str,
    spec_item: dict[str, Any],
    actual: dict[str, Any],
    field_map: dict[str, str],
) -> list[dict[str, Any]]:
    """Compare each spec field against the actual record's mapped wire field."""
    drifts: list[dict[str, Any]] = []
    for spec_key, wire_key in field_map.items():
        if spec_key not in spec_item:
            continue
        expected = spec_item[spec_key]
        actual_value = actual.get(wire_key)
        if expected != actual_value:
            drifts.append(
                {
                    "resource_type": resource_type,
                    "name": name,
                    "field": spec_key,
                    "expected": expected,
                    "actual": actual_value,
                }
            )
    return drifts


def _diff_networks(
    spec_networks: list[Any],
    actual_networks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    drifts: list[dict[str, Any]] = []
    actual_groups, nameless = _group_by_name(actual_networks)
    spec_names: set[str] = set()

    for spec_item in spec_networks:
        if not isinstance(spec_item, dict):
            drifts.append(
                {
                    "resource_type": "vlan",
                    "name": "<malformed>",
                    "field": "_spec",
                    "expected": "mapping",
                    "actual": type(spec_item).__name__,
                }
            )
            continue
        name = _norm_name(spec_item.get("name"))
        if not name:
            drifts.append(
                {
                    "resource_type": "vlan",
                    "name": "<unnamed>",
                    "field": "name",
                    "expected": "non-empty string",
                    "actual": spec_item.get("name"),
                }
            )
            continue
        spec_names.add(name)

        matches = actual_groups.get(name)
        if not matches:
            drifts.append(
                {
                    "resource_type": "vlan",
                    "name": name,
                    "field": "_resource",
                    "expected": "present",
                    "actual": None,
                }
            )
            continue

        for actual in matches:
            drifts.extend(
                _diff_fields(
                    resource_type="vlan",
                    name=name,
                    spec_item=spec_item,
                    actual=actual,
                    field_map=NETWORK_FIELDS,
                )
            )

    # Extra controller-side resources that the spec did not authorize. Only
    # flagged when the spec includes the section at all (an empty/missing
    # section means "I'm not auditing networks").
    drifts.extend(
        _presence_drifts(
            resource_type="vlan", groups=actual_groups, nameless=nameless, spec_names=spec_names
        )
    )
    return drifts


def _diff_wlans(
    spec_wlans: list[Any],
    actual_wlans: list[dict[str, Any]],
    actual_networks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    drifts: list[dict[str, Any]] = []
    actual_groups, nameless = _group_by_name(actual_wlans)

    # ``wlan.network`` in the spec is a network *name*; the controller stores
    # the network ``_id`` on the WLAN record as ``networkconf_id``. Build a
    # name -> ids index so we can resolve spec.network to the expected id. A
    # name two networks share resolves to no single id, so the binding cannot
    # be confirmed and is reported.
    network_name_to_ids: dict[str, list[str]] = {}
    for net in actual_networks:
        n = _norm_name(net.get("name"))
        nid = net.get("_id")
        if n and isinstance(nid, str):
            network_name_to_ids.setdefault(n, []).append(nid)

    spec_names: set[str] = set()

    for spec_item in spec_wlans:
        if not isinstance(spec_item, dict):
            drifts.append(
                {
                    "resource_type": "wlan",
                    "name": "<malformed>",
                    "field": "_spec",
                    "expected": "mapping",
                    "actual": type(spec_item).__name__,
                }
            )
            continue
        name = _norm_name(spec_item.get("name"))
        if not name:
            drifts.append(
                {
                    "resource_type": "wlan",
                    "name": "<unnamed>",
                    "field": "name",
                    "expected": "non-empty string",
                    "actual": spec_item.get("name"),
                }
            )
            continue
        spec_names.add(name)

        matches = actual_groups.get(name)
        if not matches:
            drifts.append(
                {
                    "resource_type": "wlan",
                    "name": name,
                    "field": "_resource",
                    "expected": "present",
                    "actual": None,
                }
            )
            continue

        for actual in matches:
            drifts.extend(
                _diff_fields(
                    resource_type="wlan",
                    name=name,
                    spec_item=spec_item,
                    actual=actual,
                    field_map=WLAN_FIELDS,
                )
            )

            # Network binding check (resolve name -> id).
            if "network" in spec_item:
                spec_network_name = _norm_name(spec_item["network"])
                expected_ids = network_name_to_ids.get(spec_network_name, [])
                actual_id = actual.get("networkconf_id")
                if len(expected_ids) != 1 or expected_ids[0] != actual_id:
                    drifts.append(
                        {
                            "resource_type": "wlan",
                            "name": name,
                            "field": "network",
                            "expected": spec_item["network"],
                            "actual": actual_id,
                        }
                    )

    drifts.extend(
        _presence_drifts(
            resource_type="wlan", groups=actual_groups, nameless=nameless, spec_names=spec_names
        )
    )
    return drifts


def _diff_named_resources(
    *,
    resource_type: str,
    spec_items: list[Any],
    actual_items: list[dict[str, Any]],
    field_map: dict[str, str],
) -> list[dict[str, Any]]:
    """Diff a name-keyed resource list both ways (missing, extra, field drift)."""
    drifts: list[dict[str, Any]] = []
    actual_groups, nameless = _group_by_name(actual_items)
    spec_names: set[str] = set()

    for spec_item in spec_items:
        if not isinstance(spec_item, dict):
            drifts.append(
                {
                    "resource_type": resource_type,
                    "name": "<malformed>",
                    "field": "_spec",
                    "expected": "mapping",
                    "actual": type(spec_item).__name__,
                }
            )
            continue
        name = _norm_name(spec_item.get("name"))
        if not name:
            drifts.append(
                {
                    "resource_type": resource_type,
                    "name": "<unnamed>",
                    "field": "name",
                    "expected": "non-empty string",
                    "actual": spec_item.get("name"),
                }
            )
            continue
        spec_names.add(name)

        matches = actual_groups.get(name)
        if not matches:
            drifts.append(
                {
                    "resource_type": resource_type,
                    "name": name,
                    "field": "_resource",
                    "expected": "present",
                    "actual": None,
                }
            )
            continue

        for actual in matches:
            drifts.extend(
                _diff_fields(
                    resource_type=resource_type,
                    name=name,
                    spec_item=spec_item,
                    actual=actual,
                    field_map=field_map,
                )
            )

    drifts.extend(
        _presence_drifts(
            resource_type=resource_type,
            groups=actual_groups,
            nameless=nameless,
            spec_names=spec_names,
        )
    )
    return drifts


def _diff_firewall_rules(
    spec_rules: list[Any],
    actual_rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return _diff_named_resources(
        resource_type="firewall_rule",
        spec_items=spec_rules,
        actual_items=actual_rules,
        field_map=FIREWALL_FIELDS,
    )


def _diff_firewall_policies(
    spec_policies: list[Any],
    actual_policies: list[dict[str, Any]],
    zones: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Diff Zone-Based Firewall policies against a spec.

    Policies name their zones only by id, so each record is annotated with
    ``source_zone`` / ``destination_zone`` display names first. ``action`` is
    compared case-insensitively (the wire value is ``ALLOW``, a spec author
    writes ``allow``) and zone names the same way, matching how resources
    themselves are matched by name.
    """
    names = zone_names_by_id(zones)
    annotated: list[dict[str, Any]] = []
    for policy in actual_policies:
        source = policy.get("source")
        source = source if isinstance(source, dict) else {}
        destination = policy.get("destination")
        destination = destination if isinstance(destination, dict) else {}
        record = dict(policy)
        if isinstance(record.get("action"), str):
            record["action"] = record["action"].upper()
        record["source_zone"] = _norm_name(names.get(str(source.get("zone_id")), ""))
        record["destination_zone"] = _norm_name(names.get(str(destination.get("zone_id")), ""))
        annotated.append(record)

    normalised_spec: list[Any] = []
    for item in spec_policies:
        if isinstance(item, dict):
            item = dict(item)
            if isinstance(item.get("action"), str):
                item["action"] = item["action"].upper()
            for key in ("source_zone", "destination_zone"):
                if key in item:
                    item[key] = _norm_name(item[key])
        normalised_spec.append(item)

    return _diff_named_resources(
        resource_type="firewall_policy",
        spec_items=normalised_spec,
        actual_items=annotated,
        field_map=FIREWALL_POLICY_FIELDS,
    )


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("audit_network_drift", mutates=False)
    async def audit_network_drift(
        spec_yaml: BoundedYaml,
        controller: str = "default",
    ) -> str:
        """Compare current controller state to a declared YAML spec.

        Read-only — never mutates the controller. Returns a structured diff
        showing fields that drifted, resources missing from the controller, and
        resources present on the controller that the spec did not declare.

        Side effects:
        - None (read-only). Lists networks, WLANs, legacy firewall rules,
          and Zone-Based Firewall policies and zones.

        Spec format (YAML, all sections optional):

            networks:
              - name: "IoT"
                vlan: 50
                subnet: "10.50.0.0/24"
            wlans:
              - name: "Cameras-IoT"
                network: "IoT"        # references a network by name
                security: "wpapsk"
            firewall_rules:
              - name: "Block IoT to LAN"
                action: "drop"
                src: "10.50.0.0/24"
                dst: "192.168.86.0/24"
            firewall_policies:          # Zone-Based Firewall sites
              - name: "Allow LAN to IoT"
                action: "allow"
                source_zone: "LAN"
                destination_zone: "IoT"

        ``firewall_rules`` audits the legacy rulesets and ``firewall_policies``
        the Zone-Based Firewall; a site uses one or the other, so declare the
        section that matches it. Resources are matched by ``name`` (case-insensitive). Sections you omit
        are not audited; sections you include audit BOTH directions (missing
        and extra). To audit a section as "exactly these resources", include it
        explicitly. To audit as "at least these resources", omit the section
        and use ``audit_open_ports`` or other read-only tools instead.

        Returns ``{"in_sync": bool, "controller": str, "summary": str,
        "drifts": [...], "not_compared": [...]}``. Each drift is
        ``{"resource_type", "name", "field", "expected", "actual"}``. The
        synthetic field ``_resource`` flags presence/absence of an entire
        resource (``expected=null`` = extra; ``actual=null`` = missing); a
        controller record with no name is an extra named ``<unnamed>``.
        ``_duplicate`` flags a name the controller holds more than once.
        ``not_compared`` lists every spec section or key this tool has no
        comparison for (compared keys: networks ``vlan``/``subnet``/
        ``purpose``; wlans ``network``/``enabled``/``security``/
        ``wpa_mode``/``is_guest``/``hide_ssid``/``wlan_band``;
        firewall_rules ``action``/``ruleset``/``protocol``/``src``/``dst``/
        ``src_port``/``dst_port``/``enabled``; firewall_policies ``action``/
        ``enabled``/``protocol``/``index``/``source_zone``/
        ``destination_zone``). ``in_sync`` is true only when there are no
        drifts AND nothing went uncompared.

        Example: audit_network_drift(spec_yaml="networks:\\n  - name: iot\\n    vlan: 50\\n")

        Args:
            spec_yaml: The spec document, as a YAML string.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            spec = yaml.safe_load(spec_yaml)
        except yaml.YAMLError as exc:
            return err(f"malformed spec_yaml: {exc}")

        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            return err(
                f"spec_yaml must be a YAML mapping at the top level, got {type(spec).__name__}"
            )

        try:
            backend = resolve_backend(registry, controller)
        except UniFiError as exc:
            return err(str(exc))

        drifts: list[dict[str, Any]] = []
        # Always pull networks because WLANs reference them.
        try:
            actual_networks = list(await backend.list_networks())
        except UniFiError as exc:
            logger.exception("audit_network_drift: list_networks failed")
            return err(str(exc))

        if "networks" in spec:
            spec_networks = spec.get("networks") or []
            if not isinstance(spec_networks, list):
                return err("spec.networks must be a list")
            drifts.extend(_diff_networks(spec_networks, actual_networks))

        if "wlans" in spec:
            spec_wlans = spec.get("wlans") or []
            if not isinstance(spec_wlans, list):
                return err("spec.wlans must be a list")
            try:
                actual_wlans = list(await backend.list_wlans())
            except UniFiError as exc:
                logger.exception("audit_network_drift: list_wlans failed")
                return err(str(exc))
            drifts.extend(_diff_wlans(spec_wlans, actual_wlans, actual_networks))

        if "firewall_rules" in spec:
            spec_rules = spec.get("firewall_rules") or []
            if not isinstance(spec_rules, list):
                return err("spec.firewall_rules must be a list")
            try:
                actual_rules = list(await backend.list_firewall_rules())
            except UniFiError as exc:
                logger.exception("audit_network_drift: list_firewall_rules failed")
                return err(str(exc))
            drifts.extend(_diff_firewall_rules(spec_rules, actual_rules))

        if "firewall_policies" in spec:
            spec_policies = spec.get("firewall_policies") or []
            if not isinstance(spec_policies, list):
                return err("spec.firewall_policies must be a list")
            try:
                actual_policies = list(await backend.list_firewall_policies())
                zones = list(await backend.list_firewall_zones())
            except UniFiError as exc:
                logger.exception("audit_network_drift: list_firewall_policies failed")
                return err(str(exc))
            drifts.extend(_diff_firewall_policies(spec_policies, actual_policies, zones))

        not_compared = _not_compared(spec)
        # A key the audit could not compare is not evidence of sync, so it
        # holds ``in_sync`` false just as a drift does.
        in_sync = not drifts and not not_compared
        resource_types = sorted({d["resource_type"] for d in drifts})
        parts: list[str] = []
        if drifts:
            parts.append(
                f"{len(drifts)} drift(s) across {len(resource_types)} "
                f"resource type(s): {', '.join(resource_types)}"
            )
        if not_compared:
            fields = ", ".join(f"{n['resource_type']}.{n['field']}" for n in not_compared)
            parts.append(f"{len(not_compared)} spec key(s) not compared: {fields}")
        summary = "in sync" if in_sync else "; ".join(parts)
        return format_json(
            {
                "in_sync": in_sync,
                "controller": controller,
                "summary": summary,
                "drifts": drifts,
                "not_compared": not_compared,
            }
        )


__all__ = ["register"]
