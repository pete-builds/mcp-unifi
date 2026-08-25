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
      "resources": {
        "networks": [...],
        "wlans": [...],
        "firewall_rules": [...],
        "port_profiles": [...],
        "dhcp_leases": [...],
        "port_forwards": [...]
      }
    }

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

On restore, if ``secrets_stripped: true``, any restored WLAN or network still
carrying the sentinel is forced ``enabled=False`` so a sentinel-passphrase SSID
is never broadcast and a VPN tunnel is never stood up on a pre-shared key that
is a published constant. The operator must reset each secret and re-enable
manually. A warning is included in the response.

Identity & ordering
-------------------
Resources are matched by ``name`` (case-insensitive, trim) for everything
except DHCP leases (matched by ``mac``) and port forwards (matched by
``name``, falling back to ``(fwd, fwd_port)``).

Apply plan order avoids the controller's referential constraints:

* **Deletes** (extras the backup didn't authorize) execute first, in the
  order: firewall_rules -> port_forwards -> wlans -> dhcp_leases ->
  port_profiles -> networks.
* **Creates** (in the backup but not on the controller) execute next, in the
  reverse order: networks -> port_profiles -> dhcp_leases -> wlans ->
  port_forwards -> firewall_rules. WLANs and DHCP leases that reference a
  network ID are rebound to the matching network on the live controller via
  the ``name`` index — the saved ``_id`` from the source controller does not
  survive cross-controller restore.
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
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.redaction import is_sensitive

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
    "port_profiles",
    "dhcp_leases",
    "wlans",
    "port_forwards",
    "firewall_rules",
)

#: Resource types in the order they are deleted on apply (children first).
DELETE_ORDER: tuple[str, ...] = tuple(reversed(CREATE_ORDER))

#: Fields stripped from every resource record before it lands in the backup
#: envelope. ``_id`` and ``site_id`` are controller-assigned and would only
#: confuse a cross-controller restore; we re-derive the network binding by
#: name during restore. Networks themselves keep their ``_id`` (see
#: ``_strip_for_backup``) so wlan/lease references can be resolved back to a
#: name during restore.
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
    """Like :func:`_strip`, but preserves ``_id`` on networks.

    Networks keep their original controller-assigned ``_id`` in the envelope
    so that WLAN ``networkconf_id`` and DHCP ``network_id`` references can be
    resolved back to a network name during restore. ``site_id`` is still
    dropped (it doesn't survive cross-controller restore either).
    """
    if rtype == "networks":
        return {k: v for k, v in record.items() if k != "site_id"}
    return _strip(record)


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

    Note the sentinel: this path writes ``<redacted-on-backup>`` rather than
    ``redact``'s ``[REDACTED]``, because ``restore_config`` recognises it and
    force-disables any resource still carrying it.
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
    return {
        "networks": [_strip_for_backup("networks", r) for r in networks_raw],
        "wlans": [_strip(r) for r in wlans_raw],
        "firewall_rules": [_strip(r) for r in fw_raw],
        "port_profiles": [_strip(r) for r in profiles_raw],
        "dhcp_leases": [_strip(r) for r in leases_raw],
        "port_forwards": [_strip(r) for r in forwards_raw],
    }


# ---------------------------------------------------------------------------
# Restore plan
# ---------------------------------------------------------------------------


def _plan(
    *,
    backup_resources: dict[str, list[dict[str, Any]]],
    current: dict[str, list[dict[str, Any]]],
    current_with_ids: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Build an ordered action plan to bring ``current`` to ``backup_resources``.

    ``current_with_ids`` holds the controller records WITH their ``_id``
    fields preserved so deletes can target them. ``current`` is the
    name-indexed view used for matching.
    """
    actions: list[dict[str, Any]] = []

    # Deletes first — children before parents.
    for rtype in DELETE_ORDER:
        backup_index = {_identity(rtype, r): r for r in backup_resources.get(rtype, [])}
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
            if ident not in backup_index:
                actions.append(
                    {
                        "action": "delete",
                        "type": rtype,
                        "id": live.get("_id"),
                        "name": live.get("name") or ident,
                    }
                )

    # Creates next — parents before children.
    for rtype in CREATE_ORDER:
        live_index = {_identity(rtype, r): r for r in current.get(rtype, [])}
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
            if ident not in live_index:
                actions.append(
                    {
                        "action": "create",
                        "type": rtype,
                        "name": spec.get("name") or ident,
                        "payload": spec,
                    }
                )

    return actions


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
        return await backend.create_dhcp_lease(payload)
    if rtype == "port_forwards":
        return await backend.create_port_forward(payload)
    raise ValueError(f"unknown resource type for create: {rtype}")


def _force_disable_if_redacted(payload: dict[str, Any], secrets_stripped: bool) -> dict[str, Any]:
    """If the payload still carries a redaction sentinel, force disable.

    Protects against broadcasting a sentinel-passphrase SSID on the wire, and
    against standing up a VPN network whose pre-shared key is a known public
    string. The operator must reset the secret and re-enable manually.

    Scoped to WLANs and networks by the caller — those are the two resource
    types that hold secrets. Any value equal to the sentinel triggers it, not
    just ``x_passphrase``, so a newly-covered secret field disables its
    resource on restore instead of restoring a broken credential silently.
    """
    if not secrets_stripped:
        return payload
    if not any(v == REDACTED_PASSPHRASE for v in payload.values()):
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

        Captures networks/VLANs, WLANs, firewall rules, port profiles,
        static DHCP reservations, and port forwards into one versioned JSON
        envelope. Transient state (clients, devices, observability) is
        excluded.

        Secret handling: every sensitive field on a WLAN or network record
        is replaced with the sentinel ``<redacted-on-backup>`` — WLAN
        ``x_passphrase`` and the network VPN keys
        (``x_ipsec_pre_shared_key``, ``x_private_key``, ``x_preshared_key``,
        RADIUS ``x_secret``). The envelope flag ``secrets_stripped: true``
        warns ``restore_config`` to force any restored WLAN or network still
        carrying the sentinel to ``enabled=False``.

        Returns the JSON envelope ``{"schema": "1", "controller": str,
        "ts": iso8601, "secrets_stripped": bool, "resources": {...}}``.

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
          creates run second in the reverse order. No update path in this
          version: drifted fields show up as a delete + create pair (or
          stay put when names match).
        - Cross-controller restore: if the envelope's ``controller``
          differs from the target, the restore proceeds and the response
          includes a warning.
        - Stripped secrets: if ``secrets_stripped: true``, every restored
          WLAN or network still carrying the sentinel in any field is forced
          to ``enabled=False`` so a known-string SSID is never broadcast and
          a VPN tunnel is never stood up on a public pre-shared key. The
          operator must reset each secret and re-enable manually.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior creates are reverted
          in reverse order and the response includes ``partial`` and
          ``rolled_back`` keys. Deletes that already ran are NOT undone
          (no copy was kept); the response reports them so the operator
          can re-run with ``dry_run`` to inspect the residual gap.

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
        backup_resources: dict[str, list[dict[str, Any]]] = {}
        for rtype in CREATE_ORDER:
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
        if secrets_stripped:
            warnings.append(
                "Secrets were stripped from this backup. Any restored WLAN or "
                "network carrying a stripped secret will be force-disabled — "
                "that includes VPN networks, whose pre-shared key is not in "
                "the envelope. Reset each secret and re-enable manually."
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
            }
        except UniFiError as exc:
            logger.exception("restore_config: live snapshot failed")
            return err(str(exc))

        # Strip ids for matching.
        current = {k: [_strip(r) for r in v] for k, v in current_with_ids.items()}

        plan = _plan(
            backup_resources=backup_resources,
            current=current,
            current_with_ids=current_with_ids,
        )

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "warnings": warnings,
                    "would_apply": plan,
                    "summary": (
                        f"{sum(1 for a in plan if a['action'] == 'create')} "
                        "create(s), "
                        f"{sum(1 for a in plan if a['action'] == 'delete')} "
                        "delete(s)"
                    ),
                }
            )

        # Build the old-id -> network-name map from the backup. Networks in
        # the envelope keep their original ``_id`` so wlan/lease references
        # can be resolved back to a name and then to a live id at apply time.
        backup_netid_to_name: dict[str, str] = {}
        for net in backup_resources["networks"]:
            old_id = net.get("_id")
            name = _norm(net.get("name"))
            if isinstance(old_id, str) and name:
                backup_netid_to_name[old_id] = name

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

        # Build the post-delete network-name-to-id index lazily; we refresh
        # it after creates so WLAN/lease bindings resolve correctly.
        async def _network_name_to_id() -> dict[str, str]:
            nets = list(await backend.list_networks())
            return {_norm(n.get("name")): n["_id"] for n in nets if isinstance(n.get("_id"), str)}

        try:
            for action in plan:
                if action["action"] == "skip":
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

                    # Networks kept their source ``_id`` in the envelope so
                    # we could rebuild the old-id -> name map. Drop ``_id``
                    # before sending the payload to the controller so we
                    # don't try to dictate the new id.
                    if rtype == "networks":
                        payload.pop("_id", None)

                    # Resolve wlan -> network and lease -> network refs from
                    # the saved old id back to a name, then to the live id.
                    # Falls back to leaving the field alone if the linked
                    # network isn't in the backup (operator-edited envelope
                    # or referential drift); the controller will surface
                    # the broken link via its own error path.
                    if rtype == "wlans" and "networkconf_id" in payload:
                        old_id = str(payload["networkconf_id"])
                        net_name = backup_netid_to_name.get(old_id)
                        if net_name:
                            live = await _network_name_to_id()
                            target = live.get(net_name)
                            if target:
                                payload["networkconf_id"] = target
                    elif rtype == "dhcp_leases" and "network_id" in payload:
                        old_id = str(payload["network_id"])
                        net_name = backup_netid_to_name.get(old_id)
                        if net_name:
                            live = await _network_name_to_id()
                            target = live.get(net_name)
                            if target:
                                payload["network_id"] = target

                    if rtype in ("wlans", "networks"):
                        payload = _force_disable_if_redacted(payload, secrets_stripped)

                    record = await _create_by_type(backend, rtype, payload)
                    created_for_rollback.append((rtype, record))
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


__all__ = ["BACKUP_SCHEMA", "REDACTED_PASSPHRASE", "register"]
