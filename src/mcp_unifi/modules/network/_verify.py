"""Shared read-modify-verify plumbing for the network module's update tools.

Wraps the three-step sequence every verified write needs — read before, write,
read again — around :func:`mcp_unifi.verification.classify_write`.

The read-back is deliberately a **separate list call**, not the update
response. UniFi's ``PUT`` reply is the controller echoing its own intent; it
reports the value the controller meant to store, which is exactly the value
that turns out to be wrong when a field is silently dropped or coerced. Only
an independent GET can contradict it.

A failed read-back is not a failed write. The mutation already happened by
that point, so this module reports ``after=None`` (every field
``unverifiable``) rather than raising — losing the connection after a
successful write must not be reported to the caller as a write that did not
happen.
"""

from __future__ import annotations

import copy
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.models import UniFiRecord
from mcp_unifi.verification import classify_write

logger = logging.getLogger("mcp_unifi.network.verify")

#: Signature of a backend list method (``list_networks``, ``list_wlans``, ...).
Lister = Callable[[], Awaitable[list[UniFiRecord]]]

#: Signature of the update call, already bound to its id and patch.
Updater = Callable[[], Awaitable[UniFiRecord | None]]


async def _find(lister: Lister, record_id: str) -> UniFiRecord | None:
    """Return the record with ``_id == record_id``, or ``None``.

    Never raises: callers use this on both the pre-read (where failure only
    costs the persisted/unchanged distinction) and the post-read (where
    failure means unverifiable, not error).
    """
    try:
        records = await lister()
    except UniFiError:
        logger.exception("verification read failed", extra={"record_id": record_id})
        return None
    for record in records:
        if isinstance(record, dict) and record.get("_id") == record_id:
            return record
    return None


async def verified_update(
    *,
    lister: Lister,
    updater: Updater,
    record_id: str,
    updates: dict[str, Any],
) -> tuple[UniFiRecord | None, dict[str, Any]] | None:
    """Apply an update and verify it against an independent re-read.

    Args:
        lister: Backend list method for the resource type.
        updater: Zero-arg callable that performs the write.
        record_id: ``_id`` of the record being updated.
        updates: The patch the caller requested.

    Returns:
        ``(record_after, verification_block)`` where ``record_after`` is the
        freshly-read record (falling back to the write response if the
        read-back failed). Returns ``None`` when the record does not exist,
        so the caller can emit its own not-found error.

    Raises:
        UniFiError: only from the write itself. Read failures degrade to
            ``unverifiable`` rather than propagating.
    """
    # Snapshot, don't alias. A backend that mutates its records in place
    # (the stub does; a caching client could) would otherwise hand back a
    # reference that the write then edits underneath us, making every field
    # look like it was already correct and reporting a real write as a no-op.
    before_ref = await _find(lister, record_id)
    before = copy.deepcopy(before_ref) if before_ref is not None else None

    written = await updater()
    if written is None:
        return None

    after = await _find(lister, record_id)
    block = classify_write(updates, before, after, mutation_applied=True)
    if after is None:
        logger.warning(
            "write could not be verified by read-back",
            extra={"record_id": record_id},
        )
    return (after if after is not None else written), block


__all__ = ["verified_update"]
