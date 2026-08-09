"""Read-back verification for controller writes.

THE DEFECT CLASS THIS EXISTS FOR
--------------------------------
UniFi controllers accept a write, answer ``{"rc": "ok"}``, and then store
something other than what you asked for. Observed shapes:

* A field is **silently dropped** — it never appears on the stored record.
* A field is **coerced** — ``purpose="guest"`` lands as ``"corporate"``,
  a string ``"1"`` lands as an integer, a bool lands as ``0``/``1``.
* A multi-field patch **partially applies** — two of three fields commit and
  the controller still reports failure, or reports success.

None of that is visible to a caller who trusts the PUT response, because the
PUT response is the controller's *echo of its own intent*, not a read of what
it persisted. The only honest answer comes from an independent GET after the
write.

That distinction is the whole point of this module. :func:`classify_write`
never looks at the write response; it compares what the caller **requested**
against what a **fresh read** actually returned.

FIELD CLASSIFICATION
--------------------
Every key in the requested patch lands in exactly one bucket:

``persisted``
    The stored value now equals the requested value, and it differs from what
    was there before. The write did what it said.
``unchanged``
    The stored value equals the requested value and *already did* before the
    write. A no-op, not a failure — asking for ``enabled=True`` on something
    already enabled is a satisfied request, not a broken one.
``dropped``
    The key is absent from the record after the write. The controller threw
    it away without saying so. This is data loss.
``coerced``
    The key is present but holds something other than what was requested,
    **including a value that compares equal but changed type** (``True`` →
    ``1``). Type drift is reported rather than forgiven: a caller round-
    tripping a record needs to know the controller rewrote it.
``unverifiable``
    The field cannot be read back and compared. Secrets are the main case —
    ``x_passphrase`` comes back redacted by design (see
    :mod:`mcp_unifi.redaction`), so this module cannot and will not assert
    that a PSK write landed. Absence of proof is reported as absence of
    proof.

WHY THE VERDICT IS NOT JUST A BOOLEAN
-------------------------------------
``mutation_applied`` and ``verified`` answer different questions, and a
caller compensating for a bad write needs both:

* ``mutation_applied=False`` — the controller rejected the write. Nothing
  changed. Safe to retry.
* ``mutation_applied=True, verified=False`` — the controller *accepted* the
  write and did not persist it exactly. Some fields may have committed. This
  is **not a rollback**; the record is in a mixed state. Read
  ``dropped_fields`` and ``coerced_fields`` before retrying, or a blind retry
  will re-send fields that already applied.
* ``verified=True`` — every requested field is confirmed persisted or was
  already satisfied.

AUDIT
-----
The verification block is returned inside the tool's normal response
envelope, which means :func:`mcp_unifi.modules._audit.audited` records it to
the JSONL audit log with no extra wiring. ``mcp-unifi-replay`` therefore
replays against *what the controller actually stored*, not what the caller
intended to store. That is the difference between an audit log and a wish
list.
"""

from __future__ import annotations

from typing import Any

from mcp_unifi.models import UniFiRecord
from mcp_unifi.redaction import is_sensitive

#: Keys that are never part of a caller's intent — the controller owns them,
#: and comparing them would report spurious coercion on every write.
SERVER_OWNED_KEYS: frozenset[str] = frozenset({"_id", "site_id", "attr_no_delete"})


def _values_match(requested: Any, actual: Any) -> bool:
    """True when ``actual`` is the requested value at the requested type.

    Equality alone is not enough. Python treats ``True == 1`` and
    ``1 == 1.0`` as true, but a controller that stored ``1`` where the caller
    sent ``True`` rewrote the record, and a caller that reads it back and
    re-submits it will send something different the second time. Type drift
    is a coercion, so both the value and its type have to match.
    """
    if type(requested) is not type(actual):
        return False
    return bool(requested == actual)


def classify_write(
    requested: dict[str, Any],
    before: UniFiRecord | None,
    after: UniFiRecord | None,
    *,
    mutation_applied: bool = True,
) -> dict[str, Any]:
    """Compare a requested patch against an independent post-write read.

    Args:
        requested: The patch the caller asked for. Server-owned keys
            (:data:`SERVER_OWNED_KEYS`) are ignored.
        before: The record as it read *before* the write, or ``None`` if it
            could not be read. Used only to separate a real write
            (``persisted``) from an already-satisfied no-op (``unchanged``).
            Without it every match is reported as ``persisted``.
        after: The record as it reads *now*, from a fresh GET — never the
            write response. ``None`` means the read-back failed, in which
            case every requested field is ``unverifiable``.
        mutation_applied: Whether the controller accepted the write. ``False``
            means the write itself errored.

    Returns:
        A verification block with the five field buckets, the
        ``mutation_applied`` / ``verified`` / ``partial_success`` verdict,
        and a human-readable ``verification_summary``.
    """
    fields = {k: v for k, v in requested.items() if k not in SERVER_OWNED_KEYS}

    persisted: list[str] = []
    unchanged: list[str] = []
    dropped: list[str] = []
    coerced: dict[str, dict[str, Any]] = {}
    unverifiable: list[str] = []

    for key, want in sorted(fields.items()):
        # Secrets come back redacted, so a comparison here would be comparing
        # against "[REDACTED]" and reporting a coercion that did not happen.
        if is_sensitive(key):
            unverifiable.append(key)
            continue
        if after is None:
            unverifiable.append(key)
            continue
        if key not in after:
            dropped.append(key)
            continue
        got = after[key]
        if _values_match(want, got):
            if before is not None and key in before and _values_match(want, before[key]):
                unchanged.append(key)
            else:
                persisted.append(key)
            continue
        coerced[key] = {"requested": want, "actual": got}

    verified = mutation_applied and not dropped and not coerced and not unverifiable
    committed = bool(persisted)
    partial_success = mutation_applied and not verified and committed

    return {
        "mutation_applied": mutation_applied,
        "verified": verified,
        "partial_success": partial_success,
        "persisted_fields": persisted,
        "unchanged_fields": unchanged,
        "dropped_fields": dropped,
        "coerced_fields": coerced,
        "unverifiable_fields": unverifiable,
        "verification_summary": _summarize(
            mutation_applied=mutation_applied,
            verified=verified,
            partial_success=partial_success,
            persisted=persisted,
            unchanged=unchanged,
            dropped=dropped,
            coerced=coerced,
            unverifiable=unverifiable,
            read_back_failed=after is None,
        ),
    }


def _summarize(
    *,
    mutation_applied: bool,
    verified: bool,
    partial_success: bool,
    persisted: list[str],
    unchanged: list[str],
    dropped: list[str],
    coerced: dict[str, dict[str, Any]],
    unverifiable: list[str],
    read_back_failed: bool,
) -> str:
    """One sentence a caller can act on without parsing the buckets."""
    if not mutation_applied:
        return "The controller rejected the write; nothing changed."
    if read_back_failed:
        return (
            "The controller accepted the write but it could not be read back, "
            "so nothing about the stored state is confirmed. Re-read the "
            "record before assuming this applied."
        )
    if verified:
        applied = len(persisted)
        noop = len(unchanged)
        if applied and noop:
            return f"Verified: {applied} field(s) written, {noop} already matched."
        if applied:
            return f"Verified: {applied} field(s) written and confirmed by read-back."
        return f"Verified: all {noop} requested field(s) already held the requested values."

    problems: list[str] = []
    if dropped:
        problems.append(f"{len(dropped)} dropped by the controller")
    if coerced:
        problems.append(f"{len(coerced)} stored with a different value or type")
    if unverifiable:
        problems.append(f"{len(unverifiable)} not verifiable")
    detail = "; ".join(problems)
    lead = (
        f"Partially applied: {len(persisted)} field(s) persisted, {detail}."
        if partial_success
        else f"Not applied as requested: {detail}."
    )
    return (
        f"{lead} The controller accepted the mutation, so this is NOT a "
        f"rollback and the record may be in a mixed state. Inspect the field "
        f"buckets before retrying or compensating."
    )


def verification_failed(block: dict[str, Any]) -> bool:
    """True when a verification block describes a write worth complaining about."""
    return not bool(block.get("verified"))


__all__ = [
    "SERVER_OWNED_KEYS",
    "classify_write",
    "verification_failed",
]
