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

Canonical form, precisely enough to re-implement: the record without its
``hash`` key, encoded as JSON with

* object keys sorted by code point at every level, no duplicate keys;
* ``separators=(",", ":")``: no whitespace anywhere;
* ``ensure_ascii=True``: every non-ASCII character as a lowercase ``\\uXXXX``
  escape (surrogate pairs above U+FFFF), and Python's escapes for control
  characters, ``"`` and ``\\``;
* integers in decimal, floats as Python's ``repr`` (shortest round-trip form:
  ``12.345``, ``-0.0``, ``1e+16``), and the bare tokens ``NaN``, ``Infinity``
  and ``-Infinity`` for the non-finite floats;
* ``true``, ``false`` and ``null`` for booleans and ``None``;

then encoded as UTF-8 (which, after ``ensure_ascii``, is ASCII). It is
computed from the record exactly as it reads back out of the file (see
:func:`normalize`), so the hash covers the redacted values that were written,
never a secret that was scrubbed before the write. ``tests/test_audit_chain.py``
pins two fixed vectors.

What this proves, and what it does not, is set out in
``docs/decisions/audit-records-are-correlated-and-hash-chained.md``. In
short: it detects an edit, a deletion or a reordering inside a chain segment by
someone who does not recompute the chain. It does not stop someone with write
access from rewriting the whole file, and it cannot detect records cut off the
end of a segment without a copy of a later hash kept somewhere else.

This module is deliberately free of any import from :mod:`mcp_unifi.audit` so
the verifier CLI can load it without building a sink.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: ``prev_hash`` of the first record of every chain segment.
GENESIS_HASH = "0" * 64

#: Schema version that introduced ``event_id``, ``operation_id`` and the chain.
CHAINED_SCHEMA = "2"

#: Schema versions written before the chain existed. A record of one of these
#: versions with no chain fields is an unchained (legacy) record. It is
#: accepted only before the first chained record of its file: that is the
#: upgrade case, and nothing else writes one.
UNCHAINED_SCHEMAS: frozenset[str] = frozenset({"1"})

# ``chain_start`` values: why a record begins a new segment at the genesis hash.
#: The file was missing or held no records when this process first wrote.
#: Valid only on the first record of a file.
CHAIN_START_NEW_LOG = "new_log"
#: The last record in the file predates the chain (schema 1, no ``hash``).
#: Valid only right after an unchained record.
CHAIN_START_AFTER_UNCHAINED = "after_unchained"
#: The last line in the file could not be read as a chained record. Valid only
#: right after a line that is not JSON at all (crash damage), or as the first
#: record of a file.
CHAIN_START_AFTER_UNREADABLE = "after_unreadable"
#: The sink is not a file this process can read back (stdout, syslog), so
#: every process start begins a new segment. Valid anywhere: nothing in the
#: log can say whether a process really restarted there.
CHAIN_START_PROCESS_START = "process_start"

CHAIN_START_LABELS: frozenset[str] = frozenset(
    {
        CHAIN_START_NEW_LOG,
        CHAIN_START_AFTER_UNCHAINED,
        CHAIN_START_AFTER_UNREADABLE,
        CHAIN_START_PROCESS_START,
    }
)

_HEX64 = re.compile(r"[0-9a-f]{64}")

#: Bytes read per step when looking for the last line of an existing file.
_TAIL_STEP = 64 * 1024


def is_hash(value: object) -> bool:
    """True when ``value`` is exactly 64 lowercase hex characters."""
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


class DuplicateKeyError(ValueError):
    """A JSON object in an audit line repeats a key."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        out[key] = value
    return out


def loads_record(text: str | bytes) -> Any:
    """Parse one audit line, refusing a repeated key at any depth.

    A standard JSON parser keeps the last of two equal keys. The writer never
    repeats one, so a repeat means the line was edited, and it must not be
    read: a duplicate ``hash`` key placed first would be invisible to the hash
    check while still putting that hash's text into the file.
    """
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


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

    Reads only the last line, whether or not it ends in a newline (the file
    sink starts its own first line on a fresh line either way). Never raises
    and never rewrites anything: a file that cannot be read, or whose last line
    is not a chained record, starts a new segment, and ``chain_start`` on the
    next record says which case it was.
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
        payload = loads_record(last.decode("utf-8-sig"))
    except ValueError:  # bad JSON, bad UTF-8, or a duplicate key
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNREADABLE)
    if not isinstance(payload, dict):
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNREADABLE)
    if _is_unchained(payload):
        return ChainResume(GENESIS_HASH, CHAIN_START_AFTER_UNCHAINED)
    stored = payload.get("hash")
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
    #: Records lost immediately before any segment start after the first are
    #: not detectable, and the CLI says so for each one.
    segment_starts: list[tuple[str, str | None]] = field(default_factory=list)
    #: Locations of lines that are not JSON at all and are followed by a
    #: writer restart (``after_unreadable``): a crash mid-write. One record
    #: may have been lost at each.
    damaged: list[str] = field(default_factory=list)
    #: ``hash`` of the last chained record that verified, and where it is.
    head_hash: str | None = None
    head_where: str | None = None
    #: The last location that verified, so a break can say "fine up to here".
    verified_through: str | None = None
    #: Where the ``anchor`` hash was found among verified records, and how many
    #: chained records follow it. ``None`` when not asked for, or not found.
    anchor_where: str | None = None
    records_after_anchor: int = 0
    broken: ChainBreak | None = None

    @property
    def ok(self) -> bool:
        return self.broken is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "chained_records": self.chained,
            "unchained_records": self.unchained,
            "unchained_runs": [{"first": a, "last": b} for a, b in self.unchained_runs],
            "segments": [{"starts_at": w, "chain_start": why} for w, why in self.segment_starts],
            "damaged_lines": list(self.damaged),
            "head_hash": self.head_hash,
            "head_at": self.head_where,
            "verified_through": self.verified_through,
            "anchor_at": self.anchor_where,
            "records_after_anchor": self.records_after_anchor,
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
_NOT_JSON = "not_json"  # not JSON at all: crash damage if a restart follows it
_DUPLICATE = "duplicate"  # valid JSON with a repeated key: always a break
_NOT_OBJECT = "not_object"
_UNCHAINED = "unchained"
_MALFORMED = "malformed"
_EDITED = "edited"
_CHAINED = "chained"


@dataclass(frozen=True, slots=True)
class _Entry:
    """What verification needs from one record, without the record itself."""

    where: str
    source: str
    first_in_file: bool
    kind: str
    stored: str | None = None
    linked: str | None = None
    chain_start: str | None = None
    schema: str | None = None
    detail: str | None = None


def _classify(line: Line, first_in_file: bool) -> _Entry:
    where, source = line.where, line.source
    try:
        payload = loads_record(line.text)
    except DuplicateKeyError as exc:
        return _Entry(where, source, first_in_file, _DUPLICATE, detail=str(exc))
    except ValueError:
        return _Entry(where, source, first_in_file, _NOT_JSON)
    if not isinstance(payload, dict):
        return _Entry(where, source, first_in_file, _NOT_OBJECT)
    if _is_unchained(payload):
        return _Entry(where, source, first_in_file, _UNCHAINED)
    stored = payload.get("hash")
    linked = payload.get("prev_hash")
    schema = str(payload.get("schema"))
    if not is_hash(stored) or not is_hash(linked):
        return _Entry(where, source, first_in_file, _MALFORMED, schema=schema)
    chain_start = payload.get("chain_start")
    return _Entry(
        where,
        source,
        first_in_file,
        _CHAINED if record_hash(payload) == stored else _EDITED,
        stored=str(stored),
        linked=str(linked),
        chain_start=chain_start if isinstance(chain_start, str) else None,
        schema=schema,
        detail=None if chain_start is None or isinstance(chain_start, str) else "bad label",
    )


def _entries(lines: Iterable[Line]) -> Iterator[_Entry]:
    source: str | None = None
    for line in lines:
        if not line.text.strip():
            continue
        first = line.source != source
        source = line.source
        yield _classify(line, first)


def _segment_start_problem(entry: _Entry, before: _Entry | None) -> str | None:
    """Why a genesis record cannot begin a segment here, or ``None`` if it can.

    ``before`` is the previous non-blank line of the same file, or ``None``
    when ``entry`` is the first record of its file.
    """
    label = entry.chain_start
    if label not in CHAIN_START_LABELS:
        return f"a segment start with an unknown or missing chain_start {label!r}"
    if label == CHAIN_START_PROCESS_START:
        return None
    if label == CHAIN_START_NEW_LOG:
        if before is None:
            return None
        if before.kind == _CHAINED:
            return (
                "the chain restarts here (new_log) although the record before it is chained: "
                "records were removed before this line, or two logs were spliced together"
            )
        return "a new_log segment start that is not the first record of its file"
    if label == CHAIN_START_AFTER_UNCHAINED:
        if before is not None and before.kind == _UNCHAINED:
            return None
        return "a segment start that says it follows an unchained record, but none is before it"
    # after_unreadable
    if before is None or before.kind == _NOT_JSON:
        return None
    return "a segment start that says it follows an unreadable line, but none is before it"


def verify_lines(lines: Iterable[Line], *, anchor: str | None = None) -> VerifyReport:
    """Walk ``lines`` in order and report the first place the chain breaks.

    Blank lines are ignored, and so is a byte-order mark at the start of a
    file (:func:`read_lines` strips it). The rules:

    * Unchained (schema 1) records are accepted only before the first chained
      record of their file.
    * A chained record's own hash must match its contents, it must name the
      chained record immediately before it as ``prev_hash``, and it must not
      carry a ``chain_start`` label.
    * A genesis record (``prev_hash`` all zeros) begins a segment, and its
      ``chain_start`` label must fit where it is (see the constants above).
    * A line that is not JSON at all is crash damage when the next record is
      an ``after_unreadable`` segment start: it is listed in ``damaged`` and
      verification continues. Any other unreadable line is a break.

    With ``anchor``, also records where that hash sits among the verified
    records and how many chained records follow it.
    """
    report = VerifyReport()
    entries = list(_entries(lines))

    # Every stored hash and where it sits, so a mismatched ``prev_hash`` can be
    # explained as "missing", "earlier" or "later" rather than just "wrong".
    position: dict[str, int] = {}
    for idx, entry in enumerate(entries):
        if entry.stored is not None:
            position.setdefault(entry.stored, idx)

    prev: _Entry | None = None  # the previous record, when it was chained
    before: _Entry | None = None  # the previous line of the same file
    chained_in_file = False
    run_start: str | None = None
    run_end: str | None = None

    def close_run() -> None:
        nonlocal run_start, run_end
        if run_start is not None and run_end is not None:
            report.unchained_runs.append((run_start, run_end))
        run_start = run_end = None

    for idx, entry in enumerate(entries):
        if entry.first_in_file:
            before = None
            chained_in_file = False

        if entry.kind == _NOT_JSON:
            nxt = entries[idx + 1] if idx + 1 < len(entries) else None
            if (
                nxt is not None
                and nxt.source == entry.source
                and nxt.kind == _CHAINED
                and nxt.linked == GENESIS_HASH
                and nxt.chain_start == CHAIN_START_AFTER_UNREADABLE
            ):
                close_run()
                report.damaged.append(entry.where)
                prev = None
                before = entry
                continue
            report.broken = ChainBreak(
                entry.where,
                "unreadable line: not JSON (edited, or a write cut off mid-line; if the "
                "server crashed while writing it, its next record will mark this line as "
                "damaged)",
            )
            break
        if entry.kind == _DUPLICATE:
            report.broken = ChainBreak(
                entry.where,
                f"edited record: {entry.detail} (the writer never repeats a key, and a "
                f"repeated key hides one value from the hash check)",
            )
            break
        if entry.kind == _NOT_OBJECT:
            report.broken = ChainBreak(entry.where, "not a record: the line is not a JSON object")
            break

        if entry.kind == _UNCHAINED:
            if chained_in_file:
                report.broken = ChainBreak(
                    entry.where,
                    "unchained record after chained records: hash fields stripped from a "
                    "record, or a downgrade to a version without the chain",
                )
                break
            report.unchained += 1
            if run_start is None:
                run_start = entry.where
            run_end = entry.where
            prev = None
            before = entry
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

        if entry.linked == GENESIS_HASH:
            problem = _segment_start_problem(entry, before)
            if problem is not None:
                report.broken = ChainBreak(entry.where, problem)
                break
            report.segment_starts.append((entry.where, entry.chain_start))
        elif entry.chain_start is not None or entry.detail is not None:
            report.broken = ChainBreak(
                entry.where,
                "a record that continues the chain carries a segment-start label",
            )
            break
        elif prev is None or entry.linked != prev.stored:
            after_unchained = before is not None and before.kind == _UNCHAINED
            report.broken = ChainBreak(
                entry.where, _explain_link(idx, entry, prev, after_unchained, entries, position)
            )
            break

        report.chained += 1
        chained_in_file = True
        prev = entry
        before = entry
        report.head_hash = entry.stored
        report.head_where = entry.where
        report.verified_through = entry.where
        if anchor is not None:
            if entry.stored == anchor:
                report.anchor_where = entry.where
                report.records_after_anchor = 0
            elif report.anchor_where is not None:
                report.records_after_anchor += 1

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


def read_lines(paths: Iterable[Path]) -> Iterator[Line]:
    """Yield every line of each file in ``paths``, in order, as one stream.

    A UTF-8 byte-order mark at the start of a file is not part of any record
    (an editor may add one) and is dropped.
    """
    for p in paths:
        with p.open("r", encoding="utf-8-sig", errors="replace") as fh:
            for lineno, text in enumerate(fh, start=1):
                yield Line(source=str(p), lineno=lineno, text=text)


__all__ = [
    "CHAINED_SCHEMA",
    "CHAIN_START_AFTER_UNCHAINED",
    "CHAIN_START_AFTER_UNREADABLE",
    "CHAIN_START_LABELS",
    "CHAIN_START_NEW_LOG",
    "CHAIN_START_PROCESS_START",
    "GENESIS_HASH",
    "UNCHAINED_SCHEMAS",
    "ChainBreak",
    "ChainResume",
    "DuplicateKeyError",
    "Line",
    "VerifyReport",
    "canonical_bytes",
    "is_hash",
    "loads_record",
    "normalize",
    "read_lines",
    "record_hash",
    "resume_from_file",
    "verify_lines",
]
