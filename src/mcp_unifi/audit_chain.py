"""Hash chain over audit records: sealing, resuming after a restart, verifying.

Every record written from schema ``"2"`` on carries two extra fields:

* ``prev_hash``: the ``hash`` of the record written before it by the same
  process, or :data:`GENESIS_HASH` for the first record of a chain segment.
* ``hash``: SHA-256, as 64 lowercase hex characters, over
  :func:`canonical_bytes` of the record with its ``hash`` key removed. The
  material therefore includes ``prev_hash``, which is what binds each record to
  the one before it: changing, removing or reordering a record breaks the link
  from the record after it, and repairing that link means rewriting the next
  record's ``prev_hash``, which changes the next record's own hash in turn.

The canonical form is the JSON encoding with keys sorted at every level,
``separators=(",", ":")`` and ``ensure_ascii=True``, encoded as UTF-8. It is
computed from the record exactly as it reads back out of the file (see
:func:`normalize`), so the hash covers the redacted values that were written,
never a secret that was scrubbed before the write.

What this proves, and what it does not, is set out in
``docs/decisions/audit-records-are-correlated-and-hash-chained.md``. In
short: it detects an edit, a deletion or a reordering inside the file by
someone who does not recompute the chain. It does not stop someone with write
access from rewriting the whole file, and it cannot detect records cut off the
end of the file without a copy of a later hash kept somewhere else.

This module is deliberately free of any import from :mod:`mcp_unifi.audit` so
the verifier CLI can load it without building a sink.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: ``prev_hash`` of the first record of every chain segment.
GENESIS_HASH = "0" * 64

#: Schema version that introduced ``event_id``, ``operation_id`` and the chain.
CHAINED_SCHEMA = "2"

#: Schema versions written before the chain existed. A record of one of these
#: versions with no ``hash`` is an unchained (legacy) record, not a break.
UNCHAINED_SCHEMAS: frozenset[str] = frozenset({"1"})

# ``chain_start`` values: why a record begins a new segment at the genesis hash.
#: The file was missing or held no records when this process first wrote.
CHAIN_START_NEW_LOG = "new_log"
#: The last record in the file predates the chain (schema 1, no ``hash``).
CHAIN_START_AFTER_UNCHAINED = "after_unchained"
#: The last line in the file could not be read as a chained record.
CHAIN_START_AFTER_UNREADABLE = "after_unreadable"
#: The sink is not a file this process can read back (stdout, syslog), so
#: every process start begins a new segment.
CHAIN_START_PROCESS_START = "process_start"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: Bytes read per step when looking for the last line of an existing file.
_TAIL_STEP = 64 * 1024


def is_hash(value: object) -> bool:
    """True when ``value`` has the shape of a record hash."""
    return isinstance(value, str) and bool(_HEX64.match(value))


def normalize(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``record`` as it will read back from the file.

    Serialises with the same ``default=str`` the sinks use, then parses the
    result. Anything that is not plain JSON (a tuple, a datetime, an integer
    dict key) comes back in the form the file holds, so the hash is computed
    over the written values rather than the in-memory ones.
    """
    loaded: dict[str, Any] = json.loads(json.dumps(dict(record), default=str))
    return loaded


def canonical_bytes(record: Mapping[str, Any]) -> bytes:
    """Canonical encoding of ``record`` without its ``hash`` key."""
    material = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def record_hash(record: Mapping[str, Any]) -> str:
    """SHA-256 hex digest over :func:`canonical_bytes` of ``record``."""
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


# ---------------------------------------------------------------------------
# Resuming a chain from an existing file
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChainResume:
    """Where a writer's chain starts when it first writes to a sink.

    ``chain_start`` is ``None`` when the writer continues an existing chain,
    and otherwise names why it starts a new segment at :data:`GENESIS_HASH`.
    """

    prev_hash: str
    chain_start: str | None


def _last_nonblank_line(path: Path) -> bytes | None:
    """Return the last non-blank line of ``path`` without reading the whole file."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        buf = b""
        while pos > 0:
            step = min(_TAIL_STEP, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            stripped = buf.rstrip()
            if not stripped:
                # Only whitespace so far. Drop it so a long run of blank
                # lines cannot grow the buffer.
                buf = b""
                continue
            cut = stripped.rfind(b"\n")
            if cut != -1:
                return stripped[cut + 1 :].strip()
        stripped = buf.strip()
        return stripped or None


def resume_from_file(path: Path) -> ChainResume:
    """Decide where a writer appending to ``path`` continues the chain.

    Reads only the last line. Never raises and never rewrites anything: a file
    that cannot be read, or whose last line is not a chained record, starts a
    new segment, and ``chain_start`` on the next record says which case it was.
    """
    try:
        last = _last_nonblank_line(path)
    except FileNotFoundError:
        return ChainResume(GENESIS_HASH, CHAIN_START_NEW_LOG)
    except OSError:
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNREADABLE)
    if last is None:
        return ChainResume(GENESIS_HASH, CHAIN_START_NEW_LOG)
    try:
        payload = json.loads(last)
    except ValueError:
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNREADABLE)
    if not isinstance(payload, dict):
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNREADABLE)
    if "hash" not in payload:
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNCHAINED)
    stored = payload["hash"]
    if not is_hash(stored):
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNREADABLE)
    assert isinstance(stored, str)
    return ChainResume(stored, None)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Line:
    """One physical line of input, with where it came from."""

    source: str
    lineno: int
    text: str

    @property
    def where(self) -> str:
        return f"{self.source}:{self.lineno}"


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """The first place the chain does not hold."""

    where: str
    reason: str


@dataclass(slots=True)
class VerifyReport:
    """What :func:`verify_lines` found."""

    chained: int = 0
    unchained: int = 0
    #: ``(first, last)`` locations of each run of records that carry no hash.
    unchained_runs: list[tuple[str, str]] = field(default_factory=list)
    #: ``(location, chain_start)`` for every record that begins a segment.
    segment_starts: list[tuple[str, str | None]] = field(default_factory=list)
    #: ``hash`` of the last chained record that verified, and where it is.
    head_hash: str | None = None
    head_where: str | None = None
    #: The last location that verified, so a break can say "fine up to here".
    verified_through: str | None = None
    broken: ChainBreak | None = None
    #: True when unchained records follow chained ones: a downgrade to a
    #: version that predates the chain, or hash fields stripped from records.
    unchained_after_chained: bool = False

    @property
    def ok(self) -> bool:
        return self.broken is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "chained_records": self.chained,
            "unchained_records": self.unchained,
            "unchained_runs": [{"first": a, "last": b} for a, b in self.unchained_runs],
            "unchained_after_chained": self.unchained_after_chained,
            "segments": [{"starts_at": w, "chain_start": why} for w, why in self.segment_starts],
            "head_hash": self.head_hash,
            "head_at": self.head_where,
            "verified_through": self.verified_through,
            "break": (
                None
                if self.broken is None
                else {"at": self.broken.where, "reason": self.broken.reason}
            ),
        }


def _is_unchained(payload: Mapping[str, Any]) -> bool:
    """A record written before the chain existed: old schema, and no chain fields."""
    schema = str(payload.get("schema", "1"))
    return "hash" not in payload and "prev_hash" not in payload and schema in UNCHAINED_SCHEMAS


# Kinds of input line, decided in one pass so a large log is never held whole.
_UNREADABLE = "unreadable"
_UNCHAINED = "unchained"
_MALFORMED = "malformed"
_EDITED = "edited"
_CHAINED = "chained"


@dataclass(frozen=True, slots=True)
class _Entry:
    """What verification needs from one record, without the record itself."""

    where: str
    kind: str
    stored: str | None = None
    linked: str | None = None
    chain_start: str | None = None
    schema: str | None = None


def _classify(line: Line) -> _Entry:
    try:
        payload = json.loads(line.text)
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        return _Entry(line.where, _UNREADABLE)
    if _is_unchained(payload):
        return _Entry(line.where, _UNCHAINED)
    stored = payload.get("hash")
    linked = payload.get("prev_hash")
    schema = str(payload.get("schema"))
    if not is_hash(stored) or not is_hash(linked):
        return _Entry(line.where, _MALFORMED, schema=schema)
    chain_start = payload.get("chain_start")
    return _Entry(
        line.where,
        _CHAINED if record_hash(payload) == stored else _EDITED,
        stored=str(stored),
        linked=str(linked),
        chain_start=chain_start if isinstance(chain_start, str) else None,
        schema=schema,
    )


def verify_lines(lines: Iterable[Line]) -> VerifyReport:
    """Walk ``lines`` in order and report the first place the chain breaks.

    Blank lines are ignored. Records with no chain fields and an old schema
    are counted as unchained and are not a break. Everything else must be a
    chained record whose own hash matches its contents and whose ``prev_hash``
    names the record immediately before it, or :data:`GENESIS_HASH` where a
    segment starts. A segment starts at the beginning of the input, after an
    unchained record, or where a process writing to a non-file sink restarted.
    """
    report = VerifyReport()
    entries = [_classify(line) for line in lines if line.text.strip()]

    # Every stored hash and where it sits, so a mismatched ``prev_hash`` can be
    # explained as "missing", "earlier" or "later" rather than just "wrong".
    position: dict[str, int] = {}
    for idx, entry in enumerate(entries):
        if entry.stored is not None:
            position.setdefault(entry.stored, idx)

    prev: _Entry | None = None  # the previous record, when it was chained
    after_unchained = False
    seen_chained = False
    run_start: str | None = None
    run_end: str | None = None

    def close_run() -> None:
        nonlocal run_start, run_end
        if run_start is not None and run_end is not None:
            report.unchained_runs.append((run_start, run_end))
        run_start = run_end = None

    for idx, entry in enumerate(entries):
        if entry.kind == _UNREADABLE:
            report.broken = ChainBreak(
                entry.where,
                "unreadable line: not a JSON object (edited, or a write was cut off mid-line)",
            )
            break
        if entry.kind == _UNCHAINED:
            report.unchained += 1
            if seen_chained and run_start is None:
                report.unchained_after_chained = True
            if run_start is None:
                run_start = entry.where
            run_end = entry.where
            prev = None
            after_unchained = True
            report.verified_through = entry.where
            continue
        close_run()
        if entry.kind == _MALFORMED:
            report.broken = ChainBreak(
                entry.where,
                f"record of schema {entry.schema!r} is missing a valid hash or prev_hash "
                f"(the chain fields were removed or altered)",
            )
            break
        if entry.kind == _EDITED:
            report.broken = ChainBreak(
                entry.where, "edited record: its stored hash does not match its contents"
            )
            break

        if prev is not None and entry.linked == prev.stored:
            pass  # the ordinary case: continues the record before it
        elif entry.linked == GENESIS_HASH and (
            prev is None or entry.chain_start == CHAIN_START_PROCESS_START
        ):
            report.segment_starts.append((entry.where, entry.chain_start))
        else:
            report.broken = ChainBreak(
                entry.where, _explain_link(idx, entry, prev, after_unchained, entries, position)
            )
            break

        report.chained += 1
        seen_chained = True
        after_unchained = False
        prev = entry
        report.head_hash = entry.stored
        report.head_where = entry.where
        report.verified_through = entry.where

    close_run()
    return report


def _explain_link(
    idx: int,
    entry: _Entry,
    prev: _Entry | None,
    after_unchained: bool,
    entries: list[_Entry],
    position: Mapping[str, int],
) -> str:
    """Say why ``entry.prev_hash`` does not continue the chain."""
    if entry.linked == GENESIS_HASH:
        return (
            "the chain restarts here although the record before it is chained: records "
            "were removed before this line, or two logs were spliced together"
        )
    at = position.get(entry.linked or "")
    if at is not None and at > idx:
        return (
            f"reordered: this record follows the record at {entries[at].where}, "
            f"which appears after it"
        )
    if at is not None:
        return (
            f"out of order: this record follows the record at {entries[at].where}, not "
            f"the one immediately before it (lines reordered or duplicated, a record "
            f"inserted, or two processes writing one file)"
        )
    if after_unchained:
        return (
            "this record continues a chain, but the record before it carries no hash: a "
            "chained record was removed here, or had its hash fields stripped"
        )
    if prev is None:
        return (
            "the record this one follows is not in the input: records were removed from "
            "before this line. If this file is a later part of a rotated log, verify the "
            "earlier file first by passing both, oldest first"
        )
    return (
        "a record is missing: the record this one follows is not in the input "
        "(deleted, or a write was lost)"
    )


def read_lines(paths: Iterable[Path]) -> Iterable[Line]:
    """Yield every line of each file in ``paths``, in order, as one stream."""
    for p in paths:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for lineno, text in enumerate(fh, start=1):
                yield Line(source=str(p), lineno=lineno, text=text)


__all__ = [
    "CHAINED_SCHEMA",
    "CHAIN_START_AFTER_UNCHAINED",
    "CHAIN_START_AFTER_UNREADABLE",
    "CHAIN_START_NEW_LOG",
    "CHAIN_START_PROCESS_START",
    "GENESIS_HASH",
    "UNCHAINED_SCHEMAS",
    "ChainBreak",
    "ChainResume",
    "Line",
    "VerifyReport",
    "canonical_bytes",
    "is_hash",
    "normalize",
    "read_lines",
    "record_hash",
    "resume_from_file",
    "verify_lines",
]
