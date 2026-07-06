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

Matching rules
--------------
* Resources are matched by ``name`` (case-insensitive, leading/trailing
  whitespace stripped).
* Spec resources missing from the controller surface a drift entry with
  ``actual: null``.
* Controller resources missing from the spec surface a drift entry with
  ``expected: null`` (extra resources that the spec did not authorize).
* Field-level drift surfaces one entry per mismatched field.

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
      ]
    }
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import yaml

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedYaml,
)
from mcp_unifi.modules.network._common import format_json, make_err

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
    "enabled": "enabled",
}


def _norm_name(value: object) -> str:
    """Normalise a resource name for matching: trim + lowercase."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _index_by_name(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index a list of controller records by lowercase ``name``.

    Records without a ``name`` are skipped (controller boilerplate sometimes
    surfaces nameless rules; they aren't matchable by spec anyway).
    """
    out: dict[str, dict[str, Any]] = {}
    for rec in records:
        key = _norm_name(rec.get("name"))
        if not key:
            continue
        # Last-write wins for duplicate names; in practice the controller
        # rejects duplicate network/WLAN names, so this only matters in
        # malformed test data.
        out[key] = rec
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
    actual_index = _index_by_name(actual_networks)
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

        actual = actual_index.get(name)
        if actual is None:
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
    for actual_name, _ in actual_index.items():
        if actual_name not in spec_names:
            drifts.append(
                {
                    "resource_type": "vlan",
                    "name": actual_name,
                    "field": "_resource",
                    "expected": None,
                    "actual": "present",
                }
            )

    return drifts


def _diff_wlans(
    spec_wlans: list[Any],
    actual_wlans: list[dict[str, Any]],
    actual_networks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    drifts: list[dict[str, Any]] = []
    actual_index = _index_by_name(actual_wlans)

    # ``wlan.network`` in the spec is a network *name*; the controller stores
    # the network ``_id`` on the WLAN record as ``networkconf_id``. Build a
    # name -> _id index so we can resolve spec.network to the expected id.
    network_name_to_id: dict[str, str] = {}
    for net in actual_networks:
        n = _norm_name(net.get("name"))
        nid = net.get("_id")
        if n and isinstance(nid, str):
            network_name_to_id[n] = nid

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

        actual = actual_index.get(name)
        if actual is None:
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
            expected_id = network_name_to_id.get(spec_network_name)
            actual_id = actual.get("networkconf_id")
            if expected_id is None or expected_id != actual_id:
                drifts.append(
                    {
                        "resource_type": "wlan",
                        "name": name,
                        "field": "network",
                        "expected": spec_item["network"],
                        "actual": actual_id,
                    }
                )

    for actual_name in actual_index:
        if actual_name not in spec_names:
            drifts.append(
                {
                    "resource_type": "wlan",
                    "name": actual_name,
                    "field": "_resource",
                    "expected": None,
                    "actual": "present",
                }
            )

    return drifts


def _diff_firewall_rules(
    spec_rules: list[Any],
    actual_rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    drifts: list[dict[str, Any]] = []
    actual_index = _index_by_name(actual_rules)
    spec_names: set[str] = set()

    for spec_item in spec_rules:
        if not isinstance(spec_item, dict):
            drifts.append(
                {
                    "resource_type": "firewall_rule",
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
                    "resource_type": "firewall_rule",
                    "name": "<unnamed>",
                    "field": "name",
                    "expected": "non-empty string",
                    "actual": spec_item.get("name"),
                }
            )
            continue
        spec_names.add(name)

        actual = actual_index.get(name)
        if actual is None:
            drifts.append(
                {
                    "resource_type": "firewall_rule",
                    "name": name,
                    "field": "_resource",
                    "expected": "present",
                    "actual": None,
                }
            )
            continue

        drifts.extend(
            _diff_fields(
                resource_type="firewall_rule",
                name=name,
                spec_item=spec_item,
                actual=actual,
                field_map=FIREWALL_FIELDS,
            )
        )

    for actual_name in actual_index:
        if actual_name not in spec_names:
            drifts.append(
                {
                    "resource_type": "firewall_rule",
                    "name": actual_name,
                    "field": "_resource",
                    "expected": None,
                    "actual": "present",
                }
            )

    return drifts


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("audit_network_drift")
    async def audit_network_drift(
        spec_yaml: BoundedYaml,
        controller: str = "default",
    ) -> str:
        """Compare current controller state to a declared YAML spec.

        Read-only — never mutates the controller. Returns a structured diff
        showing fields that drifted, resources missing from the controller, and
        resources present on the controller that the spec did not declare.

        Side effects:
        - None (read-only). Lists networks, WLANs, and firewall rules.

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

        Resources are matched by ``name`` (case-insensitive). Sections you omit
        are not audited; sections you include audit BOTH directions (missing
        and extra). To audit a section as "exactly these resources", include it
        explicitly. To audit as "at least these resources", omit the section
        and use ``audit_open_ports`` or other read-only tools instead.

        Returns ``{"in_sync": bool, "controller": str, "summary": str,
        "drifts": [...]}``. Each drift is ``{"resource_type", "name",
        "field", "expected", "actual"}``. The synthetic field ``_resource``
        flags presence/absence of an entire resource (``expected=null`` =
        extra; ``actual=null`` = missing).

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

        in_sync = len(drifts) == 0
        resource_types = sorted({d["resource_type"] for d in drifts})
        summary = (
            "in sync"
            if in_sync
            else f"{len(drifts)} drift(s) across {len(resource_types)} "
            f"resource type(s): {', '.join(resource_types)}"
        )
        return format_json(
            {
                "in_sync": in_sync,
                "controller": controller,
                "summary": summary,
                "drifts": drifts,
            }
        )


__all__ = ["register"]
