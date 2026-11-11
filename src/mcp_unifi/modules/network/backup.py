"""Backup and restore tools for controller configuration.

Two tools:

* ``backup_config`` (read-only): snapshot every persistent resource on a
  controller into a single versioned JSON envelope. Secrets are stripped.
* ``restore_config`` (destructive): diff the envelope against the live
  controller, build an action plan, and apply it with rollback on partial
  failure. Honors ``dry_run``.

Envelope shape (``schema = "1"``):

.. code-block:: json

    {
      "schema": "1",
      "controller": "default",
      "ts": "2026-05-15T12:34:56+00:00",
      "secrets_stripped": true,
      "not_included": {"firewall_policies": "...", ...},
      "resources": {
        "networks": [...],
        "firewall_groups": [...],
        "wlans": [...],
        "firewall_rules": [...],
        "port_profiles": [...],
        "dhcp_leases": [...],
        "port_forwards": [...]
      }
    }

``not_included`` names every kind of persistent configuration the envelope
does NOT carry (see :data:`NOT_INCLUDED`), Zone-Based Firewall policies
first among them. ``restore_config`` repeats the same list as
``not_restored`` in its plan, so a backup is never mistaken for a whole-site
snapshot.

Secret handling
---------------
On backup, every sensitive field on a WLAN or network record is replaced with
the sentinel ``<redacted-on-backup>`` and the envelope-level
``secrets_stripped: true`` flag is set. Sensitivity is decided by
:func:`mcp_unifi.redaction.is_sensitive`, the same predicate the read path and
the audit log use, so this covers WLAN ``x_passphrase`` *and* the network VPN
keys (``x_ipsec_pre_shared_key``, WireGuard ``x_private_key`` /
``x_preshared_key``, RADIUS ``x_secret``). It previously matched the literal
key ``x_passphrase`` and nothing else, which meant a backup envelope — a tool
response, returned to the caller in full — carried every VPN pre-shared key on
the controller in cleartext.

The audit log captures resource counts and the envelope schema/version only —
never the full backup blob (too large; secrets are sentineled but the flag
still warrants treating the blob as operator-handled output).

On restore, any restored WLAN or network still carrying the sentinel is
forced ``enabled=False`` so a sentinel-passphrase SSID is never broadcast and
a VPN tunnel is never stood up on a pre-shared key that is a published
constant. The values themselves are checked, whatever the envelope's
``secrets_stripped`` flag says: an envelope trimmed or rebuilt by hand can
carry the sentinel under ``secrets_stripped: false``. The operator must reset
each secret and re-enable manually. A warning is included in the response.

Identity & ordering
-------------------
Resources are matched by ``name`` (case-insensitive, trim) for everything
except DHCP leases (matched by ``mac``) and port forwards (matched by
``name``, falling back to ``(fwd, fwd_port)``).

An identity held by more than one record, on the site or in the backup, while
the other side also holds it, cannot be matched record to record. Restore
does not pick one: the plan carries a ``blocked`` action for that identity
and nothing under it is created or deleted. (An identity only one side holds
is unambiguous however many records share it: all are created, or all are
deleted.)

Apply plan order avoids the controller's referential constraints:

* **Deletes** (extras the backup didn't authorize) execute first, in the
  order: firewall_rules -> port_forwards -> wlans -> dhcp_leases ->
  port_profiles -> networks.
  Firewall groups are never deleted as extras: zone policies and other
  objects this backup does not cover can reference them, so an extra group
  is reported as a ``skip``.
* **Creates** (in the backup but not on the controller) execute next, in the
  reverse order: networks -> firewall_groups -> port_profiles ->
  dhcp_leases -> wlans -> port_forwards -> firewall_rules.
* **References.** A recreated network or group gets a new ``_id``, so every
  field in a restored record that points at one by id (``networkconf_id``,
  any ``*_networkconf_id`` / ``*_networkconf_ids``, a lease's
  ``network_id``, any ``*firewallgroup_id(s)``) is remapped to the id the
  target has after the restore: the id of the matching record already on
  the site, or the id the restore just created. Networks and groups keep
  their source ``_id`` in the envelope for exactly this. A reference the plan
  cannot resolve (the target is not in the backup, has no name, or shares
  its name) turns that record's create into a ``blocked`` action in the
  preview, so it is never written with a dangling id.
* **Updates** are deliberately not generated in this version. A field that
  drifted on the controller remains; we surface it in dry-run output as
  ``would_apply`` *create* / *delete* / both, never as patch. (The composite
  reapply-by-recreate path keeps the restore idempotent and avoids an
  N-field-deep partial-update rollback story.)

Rollback semantics
------------------
Every create the restore performs is recorded. On any failure mid-plan, the
recorded creates are deleted in reverse order before the error envelope is
returned. Deletes that already executed are NOT undone (no copy was kept):
we surface them in the failure response so the operator can re-run with
``dry_run`` to inspect the residual gap. This matches the
``create_iot_network`` rollback contract Phase 1 established.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import DESTRUCTIVE, READ_ONLY
from mcp_unifi.backends import Backend
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedJson,
)
from mcp_unifi.modules.network._common import format_json, make_err, upsert_dhcp_lease
from mcp_unifi.modules.network._pending import format_preview_envelope, get_pending_actions
from mcp_unifi.modules.network._zone_policy import site_is_zone_based
from mcp_unifi.redaction import REDACTED, REDACTED_OUTPUT, is_sensitive

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.backup")

#: Schema version this module reads and writes. Bump only on a breaking change
#: to the envelope shape; the restore tool refuses any other value.
BACKUP_SCHEMA: str = "1"

#: Sentinel substituted for every WLAN ``x_passphrase`` in a backup. Restore
#: passes this sentinel through to the controller verbatim and forces the
#: restored WLAN to ``enabled=False`` so a sentinel-passphrase SSID is never
#: broadcast.
REDACTED_PASSPHRASE: str = "<redacted-on-backup>"  # noqa: S105 - sentinel literal

#: Resource types in the order they are created on apply (parents first).
CREATE_ORDER: tuple[str, ...] = (
    "networks",
    "firewall_groups",
    "port_profiles",
    "dhcp_leases",
    "wlans",
    "port_forwards",
    "firewall_rules",
)

#: Resource types in the order they are deleted on apply (children first).
DELETE_ORDER: tuple[str, ...] = tuple(reversed(CREATE_ORDER))

#: Types other records point at by ``_id``. Their records keep the source
#: ``_id`` in the envelope so restore can remap those pointers.
_REFERENCED_TYPES: frozenset[str] = frozenset({"networks", "firewall_groups"})

#: Types restore creates when missing but never deletes as extras. A firewall
#: group can be referenced by Zone-Based Firewall policies and other objects
#: outside this backup; deleting one the backup does not know would break them.
_NEVER_DELETED: frozenset[str] = frozenset({"firewall_groups"})

#: Persistent configuration a backup does NOT carry, keyed by what it is, with
#: what that means for a restore. Written into every envelope as
#: ``not_included`` and repeated by ``restore_config`` as ``not_restored``.
NOT_INCLUDED: dict[str, str] = {
    "firewall_policies": (
        "Zone-Based Firewall policies. Not backed up and not restored; "
        "recreate them with create_firewall_policy."
    ),
    "firewall_zones": "Zone-Based Firewall zones and which networks sit in each.",
    "static_routes": "Static routes.",
    "traffic_rules": "Traffic rules.",
    "traffic_routes": "Traffic routes (policy-based routing).",
    "content_filters": "Content filtering profiles.",
    "dynamic_dns": "Dynamic DNS entries.",
    "ap_groups": "AP groups.",
    "site_settings": "Site settings sections, such as threat management (ips) and Teleport.",
    "devices_and_clients": "Adopted devices and client state (transient, by design).",
}

#: Fields stripped from every resource record before it lands in the backup
#: envelope. ``_id`` and ``site_id`` are controller-assigned and would only
#: confuse a cross-controller restore; we re-derive the network binding by
#: name during restore. Networks and firewall groups keep their ``_id`` (see
#: ``_strip_for_backup``) so references to them can be remapped on restore.
_DROP_FIELDS: frozenset[str] = frozenset({"_id", "site_id"})


# ---------------------------------------------------------------------------
# Identity / matching helpers
# ---------------------------------------------------------------------------


def _norm(value: object) -> str:
    """Trim + lowercase a value for case-insensitive matching."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _identity(resource_type: str, record: dict[str, Any]) -> str:
    """Return the stable identity key used to match records across snapshots.

    Most resources match by name. DHCP leases match by MAC (a name is
    optional and not unique). Port forwards prefer name and fall back to
    ``fwd:fwd_port`` so legacy unnamed forwards still match.
    """
    if resource_type == "dhcp_leases":
        return _norm(record.get("mac"))
    if resource_type == "port_forwards":
        name = _norm(record.get("name"))
        if name:
            return name
        return f"{_norm(record.get('fwd'))}:{_norm(record.get('fwd_port'))}"
    return _norm(record.get("name"))


# ---------------------------------------------------------------------------
# Backup helpers
# ---------------------------------------------------------------------------


def _strip(record: dict[str, Any]) -> dict[str, Any]:
    """Drop controller-assigned fields from a resource record."""
    return {k: v for k, v in record.items() if k not in _DROP_FIELDS}


def _strip_for_backup(rtype: str, record: dict[str, Any]) -> dict[str, Any]:
    """Like :func:`_strip`, but preserves ``_id`` on referenced types.

    Networks and firewall groups keep their original controller-assigned
    ``_id`` in the envelope so that references to them (a WLAN's
    ``networkconf_id``, a rule's ``src_firewallgroup_ids``) can be remapped
    during restore. ``site_id`` is still dropped (it doesn't survive
    cross-controller restore either).
    """
    if rtype in _REFERENCED_TYPES:
        return {k: v for k, v in record.items() if k != "site_id"}
    return _strip(record)


def _reference_target(rtype: str, key: str) -> str | None:
    """Name the resource type a record field points at by ``_id``, if any.

    Matched on the controller's own naming: ``networkconf_id`` and every
    ``*_networkconf_id`` / ``*_networkconf_ids`` field point at networks (a
    WLAN's binding, a rule's source and destination, a port profile's native
    and tagged networks), a DHCP lease's ``network_id`` does too, and every
    ``*firewallgroup_id`` / ``*firewallgroup_ids`` field points at a firewall
    group. Matching the suffix rather than a fixed list covers sibling fields
    a newer controller adds under the same convention.
    """
    if key == "networkconf_id" or key.endswith(("_networkconf_id", "_networkconf_ids")):
        return "networks"
    if rtype == "dhcp_leases" and key == "network_id":
        return "networks"
    if key.endswith(("firewallgroup_id", "firewallgroup_ids")):
        return "firewall_groups"
    return None


def _reference_values(value: Any) -> list[Any]:
    """The ids a reference field holds: one string, or a list. Empty means unset."""
    items = value if isinstance(value, list) else [value]
    return [v for v in items if v not in ("", None)]


def _redact_secrets(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Replace every sensitive value with the sentinel.

    Returns ``(redacted_records, secrets_were_present)``. The flag drives the
    envelope's ``secrets_stripped`` field — set ``True`` whenever ANY record
    carried a secret (even the stub's ``[REDACTED]`` placeholder counts;
    callers can't tell the source of the placeholder and should be warned to
    rotate keys regardless).

    This used to test for the literal key ``x_passphrase``, which covered WLANs
    and nothing else. The backup envelope is a tool response, so it lands in
    the caller's transcript in full — and it carries network records, whose
    VPN key material (``x_ipsec_pre_shared_key``, ``x_private_key``,
    ``x_preshared_key``) went out in cleartext. Matching on
    :func:`~mcp_unifi.redaction.is_sensitive` instead ties this path to the one
    canonical pattern list, so a pattern added there covers backups too.

    Note the sentinel: this path writes ``<redacted-on-backup>``, and the
    response serialiser then rewrites every sensitive key to ``[REDACTED]``
    on the way out (at any depth, where this pass is top-level only). Both
    spellings are recognised by ``restore_config``, which force-disables any
    resource still carrying either.
    """
    out: list[dict[str, Any]] = []
    seen_secret = False
    for rec in records:
        clean = dict(rec)
        for key in clean:
            if is_sensitive(str(key)):
                seen_secret = True
                clean[key] = REDACTED_PASSPHRASE
        out.append(clean)
    return out, seen_secret


async def _snapshot(backend: Backend) -> dict[str, list[dict[str, Any]]]:
    """Pull every persistent resource list off the backend."""
    networks_raw = list(await backend.list_networks())
    wlans_raw = list(await backend.list_wlans())
    fw_raw = list(await backend.list_firewall_rules())
    profiles_raw = list(await backend.list_port_profiles())
    leases_raw = list(await backend.list_dhcp_leases())
    forwards_raw = list(await backend.list_port_forwards())
    groups_raw = list(await backend.list_firewall_groups())
    return {
        "networks": [_strip_for_backup("networks", r) for r in networks_raw],
        "firewall_groups": [_strip_for_backup("firewall_groups", r) for r in groups_raw],
        "wlans": [_strip(r) for r in wlans_raw],
        "firewall_rules": [_strip(r) for r in fw_raw],
        "port_profiles": [_strip(r) for r in profiles_raw],
        "dhcp_leases": [_strip(r) for r in leases_raw],
        "port_forwards": [_strip(r) for r in forwards_raw],
    }


# ---------------------------------------------------------------------------
# Restore plan
# ---------------------------------------------------------------------------


def _group_by_identity(
    rtype: str, records: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Group records by identity key, keeping every record. Nameless ones are left out."""
    out: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        ident = _identity(rtype, rec)
        if ident:
            out.setdefault(ident, []).append(rec)
    return out


def _plan(
    *,
    backup_resources: dict[str, list[dict[str, Any]]],
    current_with_ids: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """Build an ordered action plan to bring the controller to ``backup_resources``.

    ``current_with_ids`` holds the controller records WITH their ``_id``
    fields preserved so deletes can target them.

    Returns ``(actions, live_ids)``. ``live_ids`` maps, per referenced type,
    a source ``_id`` from the backup to the id of the matching record already
    on the site; references to records the plan creates are resolved at
    apply time from the create response.

    Matching used to index each side by identity in a dict, which kept one
    record per name: a backup holding two rules called "Block RFC1918"
    against a site holding one restored neither and said nothing. Every
    record is now kept, and an identity both sides hold with a duplicate on
    either becomes a ``blocked`` action instead of a silent pick.
    """
    actions: list[dict[str, Any]] = []
    backup_groups = {
        rtype: _group_by_identity(rtype, backup_resources.get(rtype, [])) for rtype in CREATE_ORDER
    }
    live_groups = {
        rtype: _group_by_identity(rtype, current_with_ids.get(rtype, [])) for rtype in CREATE_ORDER
    }
    ambiguous: dict[str, set[str]] = {
        rtype: {
            ident
            for ident, held in backup_groups[rtype].items()
            if ident in live_groups[rtype] and (len(held) > 1 or len(live_groups[rtype][ident]) > 1)
        }
        for rtype in CREATE_ORDER
    }

    # Deletes first — children before parents.
    for rtype in DELETE_ORDER:
        for live in current_with_ids.get(rtype, []):
            ident = _identity(rtype, live)
            if not ident:
                # Records without an identity key (e.g. a nameless port
                # forward) cannot be matched. We do NOT delete them; the
                # operator can clean those up by hand. Surface a note in the
                # plan so dry-run is honest about the gap.
                actions.append(
                    {
                        "action": "skip",
                        "type": rtype,
                        "reason": "no identity key",
                        "record": live,
                    }
                )
                continue
            if ident in backup_groups[rtype]:
                continue
            if rtype in _NEVER_DELETED:
                if rtype not in backup_resources:
                    # The backup predates this type; it has no opinion on it.
                    continue
                actions.append(
                    {
                        "action": "skip",
                        "type": rtype,
                        "name": live.get("name") or ident,
                        "reason": (
                            "not in the backup, but firewall groups are never deleted by "
                            "restore: zone policies and other objects outside the backup "
                            "can reference them"
                        ),
                    }
                )
                continue
            actions.append(
                {
                    "action": "delete",
                    "type": rtype,
                    "id": live.get("_id"),
                    "name": live.get("name") or ident,
                }
            )

    # Where every source ``_id`` of a referenced type will point after the
    # restore. ``None`` means "the record this plan creates"; a source id
    # missing from ``targets`` cannot be resolved, for the reason in
    # ``problems`` (or because no record in the backup carries it at all).
    targets: dict[str, dict[str, str | None]] = {t: {} for t in _REFERENCED_TYPES}
    problems: dict[str, dict[str, str]] = {t: {} for t in _REFERENCED_TYPES}
    for rtype in _REFERENCED_TYPES:
        for spec in backup_resources.get(rtype, []):
            old_id = spec.get("_id")
            if not isinstance(old_id, str) or not old_id:
                continue
            ident = _identity(rtype, spec)
            reason: str | None = None
            target: str | None = None
            if old_id in targets[rtype] or old_id in problems[rtype]:
                reason = "more than one record in the backup carries this _id"
            elif not ident:
                reason = "the record it points at has no name in the backup"
            elif ident in ambiguous[rtype]:
                reason = f"the record it points at shares the name {ident!r} with another"
            elif ident in live_groups[rtype]:
                live_id = live_groups[rtype][ident][0].get("_id")
                if isinstance(live_id, str) and live_id:
                    target = live_id
                else:
                    reason = f"the site's record named {ident!r} has no _id"
            if reason is not None:
                targets[rtype].pop(old_id, None)
                problems[rtype][old_id] = reason
            else:
                targets[rtype][old_id] = target

    def _unresolved(rtype: str, spec: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key, value in spec.items():
            target_type = _reference_target(rtype, key)
            if target_type is None:
                continue
            for ref in _reference_values(value):
                if isinstance(ref, str) and ref in targets[target_type]:
                    continue
                out.append(
                    {
                        "field": key,
                        "id": ref,
                        "reason": problems[target_type].get(str(ref))
                        or f"no record in the backup's {target_type} carries this _id",
                    }
                )
        return out

    # Creates next — parents before children.
    for rtype in CREATE_ORDER:
        reported: set[str] = set()
        for spec in backup_resources.get(rtype, []):
            ident = _identity(rtype, spec)
            if not ident:
                actions.append(
                    {
                        "action": "skip",
                        "type": rtype,
                        "reason": "no identity key in backup record",
                        "record": spec,
                    }
                )
                continue
            if ident in ambiguous[rtype]:
                if ident not in reported:
                    reported.add(ident)
                    actions.append(
                        {
                            "action": "blocked",
                            "type": rtype,
                            "name": spec.get("name") or ident,
                            "reason": (
                                f"duplicate identity: {len(backup_groups[rtype][ident])} "
                                f"in the backup, {len(live_groups[rtype][ident])} on the "
                                "site; restore cannot tell which is which, so it creates "
                                "and deletes none of them"
                            ),
                        }
                    )
                continue
            if ident in live_groups[rtype]:
                continue
            unresolved = [] if rtype in _REFERENCED_TYPES else _unresolved(rtype, spec)
            if unresolved:
                actions.append(
                    {
                        "action": "blocked",
                        "type": rtype,
                        "name": spec.get("name") or ident,
                        "reason": (
                            "points at a record restore cannot resolve; writing it would "
                            "leave a dangling id"
                        ),
                        "unresolved": unresolved,
                        "record": spec,
                    }
                )
                continue
            actions.append(
                {
                    "action": "create",
                    "type": rtype,
                    "name": spec.get("name") or ident,
                    "payload": spec,
                }
            )

    live_ids = {
        rtype: {old: new for old, new in mapping.items() if new is not None}
        for rtype, mapping in targets.items()
    }
    return actions, live_ids


def _remap_references(
    rtype: str, payload: dict[str, Any], id_maps: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """Rewrite every reference field in ``payload`` to the target's id after restore.

    The plan has already blocked any record with a reference it could not
    resolve, so a miss here means the target's create returned no ``_id``.
    That raises, which rolls the restore back, rather than writing the
    source controller's id.
    """
    out = dict(payload)
    for key, value in payload.items():
        target_type = _reference_target(rtype, key)
        if target_type is None:
            continue
        mapping = id_maps.get(target_type, {})

        def _one(ref: Any, _key: str = key, _mapping: dict[str, str] = mapping) -> Any:
            if ref in ("", None):
                return ref
            new = _mapping.get(ref) if isinstance(ref, str) else None
            if new is None:
                raise UniFiError(
                    f"restore_config: {rtype} field {_key}={ref!r} has no restored "
                    "record to point at"
                )
            return new

        out[key] = [_one(r) for r in value] if isinstance(value, list) else _one(value)
    return out


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


async def _delete_by_type(backend: Backend, rtype: str, resource_id: str) -> bool:
    """Dispatch a delete call to the right backend method for ``rtype``."""
    if rtype == "networks":
        return await backend.delete_network(resource_id)
    if rtype == "wlans":
        return await backend.delete_wlan(resource_id)
    if rtype == "firewall_rules":
        return await backend.delete_firewall_rule(resource_id)
    if rtype == "port_profiles":
        return await backend.delete_port_profile(resource_id)
    if rtype == "dhcp_leases":
        return await backend.delete_dhcp_lease(resource_id)
    if rtype == "port_forwards":
        return await backend.delete_port_forward(resource_id)
    if rtype == "firewall_groups":
        # Reached only by rollback of a group this restore created.
        return await backend.delete_firewall_group(resource_id)
    raise ValueError(f"unknown resource type for delete: {rtype}")


async def _create_by_type(backend: Backend, rtype: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a create call to the right backend method for ``rtype``."""
    if rtype == "networks":
        return await backend.create_network(payload)
    if rtype == "wlans":
        return await backend.create_wlan(payload)
    if rtype == "firewall_rules":
        return await backend.create_firewall_rule(payload)
    if rtype == "port_profiles":
        return await backend.create_port_profile(payload)
    if rtype == "dhcp_leases":
        # A lease removed earlier in this plan (or ever) leaves its user
        # record behind with use_fixedip off, so a plain create would answer
        # api.err.MacUsed on a real controller. Upsert instead.
        return await upsert_dhcp_lease(backend, payload)
    if rtype == "port_forwards":
        return await backend.create_port_forward(payload)
    if rtype == "firewall_groups":
        return await backend.create_firewall_group(payload)
    raise ValueError(f"unknown resource type for create: {rtype}")


#: Every string a redacted secret can arrive as. ``<redacted-on-backup>`` is
#: what :func:`_redact_secrets` writes; ``[REDACTED]`` is what the response
#: serialiser writes over it (and over any nested secret the shallow backup
#: pass did not reach), so it is the spelling a caller actually sees in a
#: ``backup_config`` result and pastes back; ``***`` is the audit-log sentinel,
#: for a backup recovered from ``audit.jsonl``.
_REDACTION_SENTINELS: frozenset[str] = frozenset({REDACTED_PASSPHRASE, REDACTED_OUTPUT, REDACTED})


def _carries_sentinel(value: Any) -> bool:
    """True if any string at any depth of ``value`` is a redaction sentinel."""
    if isinstance(value, str):
        return value in _REDACTION_SENTINELS
    if isinstance(value, dict):
        return any(_carries_sentinel(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_carries_sentinel(v) for v in value)
    return False


def _force_disable_if_redacted(payload: dict[str, Any]) -> dict[str, Any]:
    """If the payload still carries a redaction sentinel, force disable.

    Protects against broadcasting a sentinel-passphrase SSID on the wire, and
    against standing up a VPN network whose pre-shared key is a known public
    string. The operator must reset the secret and re-enable manually.

    Scoped to WLANs and networks by the caller — those are the two resource
    types that hold secrets. Any value equal to a sentinel triggers it, not
    just ``x_passphrase``, so a newly-covered secret field disables its
    resource on restore instead of restoring a broken credential silently.
    All three sentinel spellings count (see :data:`_REDACTION_SENTINELS`),
    and nested values are walked: the response serialiser redacts at every
    depth, so a peer list inside a network record can carry one too.

    The envelope's ``secrets_stripped`` flag is deliberately not consulted.
    It used to gate this check, so an envelope saying ``false`` (trimmed or
    rebuilt by hand) had its sentinel written to the controller as a real
    passphrase on an enabled SSID. The values are the evidence; the flag is
    only a claim about them.
    """
    if not _carries_sentinel(payload):
        return payload
    out = dict(payload)
    out["enabled"] = False
    return out


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    # Classified read despite producing an artifact: every call is a fan-out of
    # GETs, the envelope is returned to the caller, and nothing is written to
    # the controller (this is NOT the UniFi OS ".unf backup file" endpoint,
    # which would create a file on the console). Taking a backup is exactly
    # what an operator wants to still be able to do in read-only mode.
    @audited("backup_config", mutates=False)
    async def backup_config(controller: str = "default") -> str:
        """Snapshot every persistent resource on the controller into one envelope.

        Side effects: None (read-only).

        Captures networks/VLANs, firewall groups, WLANs, legacy firewall
        rules, port profiles, static DHCP reservations, and port forwards
        into one versioned JSON envelope. It does NOT capture Zone-Based
        Firewall policies or zones, static routes, traffic rules and
        routes, content filters, dynamic DNS, AP groups, or site settings;
        the envelope's ``not_included`` field lists each, so a backup is
        never mistaken for a whole-site snapshot. Transient state (clients,
        devices, observability) is excluded by design.

        Secret handling: every sensitive field on a WLAN or network record
        is replaced with the sentinel ``<redacted-on-backup>`` — WLAN
        ``x_passphrase`` and the network VPN keys
        (``x_ipsec_pre_shared_key``, ``x_private_key``, ``x_preshared_key``,
        RADIUS ``x_secret``). The envelope flag ``secrets_stripped: true``
        warns ``restore_config`` to force any restored WLAN or network still
        carrying the sentinel to ``enabled=False``.

        Returns the JSON envelope ``{"schema": "1", "controller": str,
        "ts": iso8601, "secrets_stripped": bool, "not_included": {...},
        "resources": {...}}``.

        Example: backup_config(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
        except UniFiError as exc:
            return err(str(exc))

        try:
            resources = await _snapshot(backend)
        except UniFiError as exc:
            logger.exception("backup_config: snapshot failed")
            return err(str(exc))

        # WLANs hold ``x_passphrase``; networks hold VPN key material. Both
        # go through the same sentinel pass, and either one setting the flag
        # arms restore's force-disable.
        secrets_stripped = False
        for rtype in ("wlans", "networks"):
            redacted, found = _redact_secrets(resources[rtype])
            resources[rtype] = redacted
            secrets_stripped = secrets_stripped or found

        envelope: dict[str, Any] = {
            "schema": BACKUP_SCHEMA,
            "controller": controller,
            "ts": datetime.now(tz=UTC).isoformat(),
            "secrets_stripped": secrets_stripped,
            "not_included": dict(NOT_INCLUDED),
            "resources": resources,
        }
        # Audit emits the wrapped result, which is the envelope. To avoid
        # blowing up the audit log with the full backup, log a summary line
        # at WARNING (operator-visible) and trust the envelope to be the
        # operator-handled output. Audit decorator still records the call;
        # its scrubbed view is acceptable since the only secrets are already
        # sentineled here.
        counts = {k: len(v) for k, v in resources.items()}
        logger.info(
            "backup_config snapshot",
            extra={
                "controller": controller,
                "schema": BACKUP_SCHEMA,
                "counts": counts,
                "secrets_stripped": secrets_stripped,
            },
        )
        return format_json(envelope)

    @mcp.tool(annotations=DESTRUCTIVE)
    @audited("restore_config", mutates=True)
    async def restore_config(
        backup_json: BoundedJson,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Restore controller state from a ``backup_config`` envelope.

        Side effects:
        - Diffs the envelope against current controller state and applies
          an ordered create/delete plan. Deletes run first (firewall_rules,
          port_forwards, wlans, dhcp_leases, port_profiles, networks);
          creates run second in the reverse order, with firewall groups
          after networks. No update path in this version: drifted fields
          show up as a delete + create pair (or stay put when names match).
          Extra firewall groups are never deleted.
        - References: a recreated network or group gets a new id, and every
          restored record pointing at one (WLAN, lease, port profile,
          firewall rule) is remapped to it. A record whose reference cannot
          be resolved, and any name both sides hold with a duplicate on
          either, appears as a ``blocked`` action and is not written.
        - Not covered: Zone-Based Firewall policies and zones, routes,
          traffic rules, content filters, dynamic DNS, AP groups and site
          settings are not in a backup and are left as they are; the plan
          lists them under ``not_restored``.
        - Cross-controller restore: if the envelope's ``controller``
          differs from the target, the restore proceeds and the response
          includes a warning.
        - Stripped secrets: every restored WLAN or network still carrying
          a redaction sentinel in any field is forced to ``enabled=False``,
          whatever the envelope's ``secrets_stripped`` flag says, so a
          known-string SSID is never broadcast and a VPN tunnel is never
          stood up on a public pre-shared key. The operator must reset each
          secret and re-enable manually.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior creates are reverted
          in reverse order and the response includes ``partial`` and
          ``rolled_back`` keys. Deletes that already ran are NOT undone
          (no copy was kept); the response reports them so the operator
          can re-run with ``dry_run`` to inspect the residual gap.

        Zone-based sites: legacy ``firewall_rules`` in the backup are not
        replayed onto a site running the Zone-Based Firewall. They appear in
        the plan as ``skip`` actions with a warning.

        Schema validation: ``schema != "1"`` returns an error envelope and
        no action is taken.

        Example: restore_config(backup_json=snapshot, dry_run=True)

        Args:
            backup_json: The envelope JSON string from ``backup_config``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        # Parse envelope
        try:
            envelope = json.loads(backup_json)
        except (json.JSONDecodeError, ValueError) as exc:
            return err(f"malformed backup_json: {exc}")

        if not isinstance(envelope, dict):
            return err(f"backup_json must be a JSON object, got {type(envelope).__name__}")

        schema = envelope.get("schema")
        if schema != BACKUP_SCHEMA:
            return err(
                f"unsupported backup schema {schema!r}; this version reads "
                f"only schema {BACKUP_SCHEMA!r}"
            )

        backup_resources_raw = envelope.get("resources")
        if not isinstance(backup_resources_raw, dict):
            return err("backup envelope is missing the 'resources' object")

        # Coerce each section to a list of dicts; missing sections become [].
        # The one exception is firewall_groups: envelopes taken before groups
        # were backed up have no such key, and that means "not in this
        # backup", not "the site should have none". The plan leaves the type
        # out entirely.
        backup_resources: dict[str, list[dict[str, Any]]] = {}
        for rtype in CREATE_ORDER:
            if rtype in _NEVER_DELETED and rtype not in backup_resources_raw:
                continue
            section = backup_resources_raw.get(rtype, [])
            if not isinstance(section, list):
                return err(f"backup resources.{rtype} must be a list")
            cleaned: list[dict[str, Any]] = []
            for item in section:
                if not isinstance(item, dict):
                    return err(f"backup resources.{rtype} contains a non-object entry")
                cleaned.append(item)
            backup_resources[rtype] = cleaned

        warnings: list[str] = []
        envelope_controller = envelope.get("controller")
        if envelope_controller and envelope_controller != controller:
            warnings.append(
                f"envelope controller={envelope_controller!r} differs from "
                f"target={controller!r}; restoring across controllers"
            )

        secrets_stripped = bool(envelope.get("secrets_stripped"))
        carries_sentinel = any(
            _carries_sentinel(rec)
            for rtype in ("wlans", "networks")
            for rec in backup_resources[rtype]
        )
        if secrets_stripped or carries_sentinel:
            if not secrets_stripped:
                warnings.append(
                    "The envelope says secrets_stripped is false, but records in it "
                    "carry a redaction placeholder in place of a secret."
                )
            warnings.append(
                "Secrets were stripped from this backup. Any restored WLAN or "
                "network carrying a stripped secret will be force-disabled — "
                "that includes VPN networks, whose pre-shared key is not in "
                "the envelope. Reset each secret and re-enable manually."
            )

        warnings.append(
            "A backup does not contain Zone-Based Firewall policies or zones, "
            "routes, traffic rules, content filters, dynamic DNS, AP groups or "
            "site settings; restore leaves those as they are (see not_restored)."
        )
        if "firewall_groups" not in backup_resources_raw:
            warnings.append(
                "This backup has no firewall_groups section (taken before groups "
                "were backed up). Groups on the site are left as they are, and any "
                "rule that references a group is blocked."
            )

        try:
            backend = resolve_backend(registry, controller)
        except UniFiError as exc:
            return err(str(exc))

        # Snapshot the live controller (with _id preserved for delete dispatch).
        try:
            current_with_ids: dict[str, list[dict[str, Any]]] = {
                "networks": list(await backend.list_networks()),
                "wlans": list(await backend.list_wlans()),
                "firewall_rules": list(await backend.list_firewall_rules()),
                "port_profiles": list(await backend.list_port_profiles()),
                "dhcp_leases": list(await backend.list_dhcp_leases()),
                "port_forwards": list(await backend.list_port_forwards()),
                "firewall_groups": list(await backend.list_firewall_groups()),
            }
        except UniFiError as exc:
            logger.exception("restore_config: live snapshot failed")
            return err(str(exc))

        plan, live_ids = _plan(
            backup_resources=backup_resources,
            current_with_ids=current_with_ids,
        )

        # A zone-based site has no legacy rulesets to restore into. Replaying
        # the backup's firewall_rules there would at best be refused and at
        # worst land rules the console ignores, so they are skipped and named.
        try:
            zone_based = await site_is_zone_based(backend)
        except UniFiError as exc:
            logger.exception("restore_config: firewall model detection failed")
            return err(str(exc))
        if zone_based:
            skipped_rules = 0
            for i, action in enumerate(plan):
                if action["type"] == "firewall_rules" and action["action"] in (
                    "create",
                    "blocked",
                ):
                    plan[i] = {
                        "action": "skip",
                        "type": "firewall_rules",
                        "reason": "legacy firewall rule; this site uses zone policies",
                        "record": action.get("payload", action.get("record")),
                    }
                    skipped_rules += 1
            if skipped_rules:
                warnings.append(
                    f"This site runs the Zone-Based Firewall. {skipped_rules} legacy "
                    "firewall rule(s) in the backup were skipped; recreate any you "
                    "still need with create_firewall_policy."
                )

        blocked = [a for a in plan if a["action"] == "blocked"]
        if blocked:
            listed = "; ".join(f"{a['type']} {a['name']!r}: {a['reason']}" for a in blocked)
            warnings.append(
                f"{len(blocked)} record(s) are blocked and will not be written. "
                f"Fix them in the envelope or on the site and run again. {listed}"
            )

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "warnings": warnings,
                    "not_restored": dict(NOT_INCLUDED),
                    "would_apply": plan,
                    "summary": (
                        f"{sum(1 for a in plan if a['action'] == 'create')} "
                        "create(s), "
                        f"{sum(1 for a in plan if a['action'] == 'delete')} "
                        f"delete(s), {len(blocked)} blocked"
                    ),
                }
            )

        # Everything below applies the plan. It used to run on the first call.
        # restore_config is the most destructive tool in this server -- it deletes
        # across firewall_rules, port_forwards, wlans, dhcp_leases, port_profiles
        # and networks before creating anything, and its own docstring notes that
        # deletes already run are NOT undone on rollback -- yet it was one of the
        # fifty mutating tools that did NOT go through the preview-then-confirm
        # registry. The eleven delete_* tools will not remove a single rule without
        # a token; this would flatten the whole config without one.
        #
        # dry_run stays as it was, for inspecting the plan without registering
        # anything. A non-dry run now returns a preview envelope plus a one-time
        # token, and the plan captured HERE is the plan the token commits -- so a
        # preview cannot be swapped for a different change between the two calls.
        async def _execute() -> str:
            # Source id -> id after restore, per referenced type. Seeded with
            # the records the plan matched on the site; each network or group
            # this restore creates adds its own entry as it lands.
            id_maps: dict[str, dict[str, str]] = {t: dict(m) for t, m in live_ids.items()}

            # The plan was captured at preview time. A matched network or
            # group deleted since then would leave every remapped reference
            # to it dangling, so check before changing anything.
            try:
                still_there = {
                    "networks": {n.get("_id") for n in await backend.list_networks()},
                    "firewall_groups": {g.get("_id") for g in await backend.list_firewall_groups()},
                }
            except UniFiError as exc:
                logger.exception("restore_config: pre-apply check failed")
                return err(str(exc))
            gone = sorted(
                f"{rtype} {live_id}"
                for rtype, mapping in id_maps.items()
                for live_id in mapping.values()
                if live_id not in still_there[rtype]
            )
            if gone:
                return err(
                    "the site changed since the preview: "
                    + ", ".join(gone)
                    + " no longer exist. Nothing was applied; run restore_config again."
                )

            # Apply. Track creates so rollback can undo them. Track executed
            # deletes for honest reporting (no undo path — no copy was kept).
            created_for_rollback: list[tuple[str, dict[str, Any]]] = []
            applied: list[dict[str, Any]] = []

            async def _rollback() -> list[dict[str, Any]]:
                actions: list[dict[str, Any]] = []
                for rtype, record in reversed(created_for_rollback):
                    resource_id = record.get("_id")
                    if not resource_id:
                        actions.append(
                            {
                                "type": rtype,
                                "deleted": False,
                                "reason": "no _id on created record",
                            }
                        )
                        continue
                    try:
                        ok = await _delete_by_type(backend, rtype, resource_id)
                    except UniFiError as exc:
                        logger.error(
                            "restore rollback delete failed",
                            extra={
                                "type": rtype,
                                "id": resource_id,
                                "error": str(exc),
                            },
                        )
                        actions.append({"type": rtype, "id": resource_id, "deleted": False})
                        continue
                    actions.append({"type": rtype, "id": resource_id, "deleted": ok})
                logger.warning(
                    "restore_config rolled back",
                    extra={"rolled_back": actions, "controller": controller},
                )
                return actions

            try:
                for action in plan:
                    if action["action"] in ("skip", "blocked"):
                        applied.append(action)
                        continue

                    if action["action"] == "delete":
                        rid = action["id"]
                        rtype = action["type"]
                        if not rid:
                            applied.append({**action, "result": "skipped", "reason": "no _id"})
                            continue
                        ok = await _delete_by_type(backend, rtype, rid)
                        applied.append({**action, "result": "deleted" if ok else "missing"})
                        continue

                    if action["action"] == "create":
                        rtype = action["type"]
                        payload = dict(action["payload"])

                        # Networks and groups kept their source ``_id`` in the
                        # envelope so references to them can be remapped. Drop
                        # it before sending the payload so we don't try to
                        # dictate the new id; keep it to record the mapping.
                        source_id: Any = None
                        if rtype in _REFERENCED_TYPES:
                            source_id = payload.pop("_id", None)
                        else:
                            # Every network or group reference is rewritten to
                            # the id its target has now. This used to cover a
                            # WLAN's networkconf_id and a lease's network_id
                            # only, so a restored firewall rule or port profile
                            # kept the source network's id: a rule that matched
                            # nothing and a profile pointing at no VLAN.
                            payload = _remap_references(rtype, payload, id_maps)

                        if rtype in ("wlans", "networks"):
                            payload = _force_disable_if_redacted(payload)

                        record = await _create_by_type(backend, rtype, payload)
                        created_for_rollback.append((rtype, record))
                        new_id = record.get("_id")
                        if isinstance(source_id, str) and isinstance(new_id, str):
                            id_maps.setdefault(rtype, {})[source_id] = new_id
                        applied.append({**action, "result": "created", "id": record.get("_id")})
                        continue

                    # Unknown action — surface but don't fail the apply.
                    applied.append({**action, "result": "unknown_action"})

            except UniFiError as exc:
                logger.exception("restore_config: apply failed")
                rolled_back = await _rollback()
                return format_json(
                    {
                        "error": f"restore_config failed: {exc}",
                        "stub_mode": settings.stub_mode,
                        "controller": controller,
                        "warnings": warnings,
                        "partial": applied,
                        "rolled_back": rolled_back,
                    }
                )

            return format_json(
                {
                    "controller": controller,
                    "warnings": warnings,
                    "applied": applied,
                    "summary": (
                        f"applied {len(applied)} action(s) "
                        f"({sum(1 for a in applied if a.get('result') == 'created')} "
                        "created, "
                        f"{sum(1 for a in applied if a.get('result') == 'deleted')} "
                        "deleted)"
                    ),
                }
            )

        pending = get_pending_actions().put(
            action="restore_config",
            controller=controller,
            resource={
                "creates": sum(1 for a in plan if a["action"] == "create"),
                "deletes": sum(1 for a in plan if a["action"] == "delete"),
                "blocked": len(blocked),
                "warnings": warnings,
                "not_restored": dict(NOT_INCLUDED),
                "plan": plan,
            },
            executor=_execute,
        )
        return format_preview_envelope(pending)


__all__ = ["BACKUP_SCHEMA", "NOT_INCLUDED", "REDACTED_PASSPHRASE", "register"]
