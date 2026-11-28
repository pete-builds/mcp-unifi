"""Check an audit log's hash chain and report the first broken link.

Usage::

    mcp-unifi-audit-verify audit.jsonl
    mcp-unifi-audit-verify audit.jsonl.1 audit.jsonl     # a rotated log, oldest first
    mcp-unifi-audit-verify audit.jsonl --json            # machine-readable summary
    mcp-unifi-audit-verify audit.jsonl --anchor <hash>   # a head you copied elsewhere earlier
    mcp-unifi-audit-verify audit.jsonl.1 --expect-head <hash>  # a file no longer written

Exit status: ``0`` when every chained record verifies (and the anchor or
expected head checks out, when given), ``1`` at the first broken link or a
failed anchor or head check, ``2`` when a file cannot be read.

What a pass means, and what it cannot mean, is in
``docs/decisions/audit-records-are-correlated-and-hash-chained.md`` and
the audit guide. The short form: a pass says no record inside a chain segment
was edited, removed or reordered by someone who did not recompute the chain.
On its own it says nothing about records cut off the end of a segment: the end
of the file, and the point just before every later segment start, which the
output lists one by one. Copying the ``head`` hash somewhere the server cannot
write, then checking it with ``--anchor`` or ``--expect-head``, covers the end
of the file up to that copy.

Records written before the chain existed (schema ``"1"``, no ``hash``) are
reported as unchained, not as a break, when they come before the first chained
record of their file.

This is a read-only command. It never builds a server or touches a controller.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_unifi.audit_chain import VerifyReport, is_hash, read_lines, verify_lines

#: Said once per segment start after the first, so "OK" is never read as
#: covering the boundary.
BOUNDARY_NOTE = "records lost immediately before this point are not detectable"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-unifi-audit-verify",
        description=(
            "Verify the hash chain of an mcp-unifi audit log (JSONL). Reports the first "
            "edited, removed or reordered record, and prints the head hash so it can be "
            "kept somewhere else. Records cut off the end of a segment are not detectable "
            "unless you check a head you kept with --anchor or --expect-head."
        ),
    )
    parser.add_argument(
        "log_paths",
        type=Path,
        nargs="+",
        metavar="LOG",
        help=(
            "Audit log file(s). Several files are checked as one chain, in the order "
            "given, so pass a rotated log oldest first."
        ),
    )
    parser.add_argument(
        "--anchor",
        metavar="HASH",
        default=None,
        help=(
            "A head hash you copied elsewhere earlier. Fails unless a verified record "
            "carries it; records written after it are allowed. This is the check for "
            "records cut off the end of a live log, up to the moment you took the copy."
        ),
    )
    parser.add_argument(
        "--expect-head",
        metavar="HASH",
        default=None,
        help=(
            "Fails unless the verified head (the last chained record of the input) is "
            "exactly this hash. For a file that is no longer written, such as a rotated "
            "one, or a copy taken when you recorded the head."
        ),
    )
    parser.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Print one JSON object with the full result instead of the text summary.",
    )
    return parser


def _print_text(report: VerifyReport, label: str, failures: Sequence[str]) -> None:
    if report.ok and not failures:
        print(f"audit-verify: OK {label}")
    elif report.ok:
        print(f"audit-verify: FAILED {label} (the chain itself is intact; see below)")
    else:
        assert report.broken is not None
        print(f"audit-verify: BROKEN at {report.broken.where}")
        print(f"  reason: {report.broken.reason}")
        print(f"  verified through: {report.verified_through or 'nothing (first record)'}")
    for where in report.damaged:
        print(
            f"  WARNING: damaged line at {where} (crash mid-write?): not a record; one record "
            "may have been lost here, and the chain restarts after it"
        )
    if report.chained + report.unchained == 0:
        print("  WARNING: no records found")
    print(f"  records: {report.chained + report.unchained}")
    print(f"  chained records: {report.chained}")
    if report.unchained:
        runs = ", ".join(a if a == b else f"{a} to {b}" for a, b in report.unchained_runs)
        print(
            f"  unchained records (written before the chain existed): {report.unchained} ({runs})"
        )
    if report.damaged:
        print(f"  damaged lines: {len(report.damaged)}")
    print(f"  segments: {len(report.segment_starts)}")
    for n, (where, why) in enumerate(report.segment_starts, start=1):
        suffix = "" if n == 1 else f": {BOUNDARY_NOTE}"
        print(f"    {n}. starts at {where} ({why or 'start of input'}){suffix}")
    if report.head_hash is not None:
        # Only a clean chain has a head worth copying elsewhere.
        label = "head" if report.ok else "last verified hash"
        print(f"  {label}: {report.head_hash} ({report.head_where})")
        if report.ok:
            print(
                "  not covered: records cut off after the head; check a head kept elsewhere "
                "with --anchor"
            )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    for flag, value in (("--anchor", args.anchor), ("--expect-head", args.expect_head)):
        if value is not None and not is_hash(value):
            parser.error(f"{flag} takes a hash: 64 lowercase hex characters")
    paths: list[Path] = list(args.log_paths)
    for p in paths:
        if not p.is_file():
            print(f"audit-verify: not a readable file: {p}", file=sys.stderr)
            return 2
    try:
        report = verify_lines(read_lines(paths), anchor=args.anchor)
    except OSError as exc:
        print(f"audit-verify: {exc}", file=sys.stderr)
        return 2

    failures: list[str] = []
    if args.anchor is not None and (not report.ok or report.anchor_where is None):
        failures.append(
            f"ANCHOR NOT FOUND: no verified record carries {args.anchor}. Records were cut "
            "off the end, or the anchor is from another log."
        )
    if args.expect_head is not None and (not report.ok or report.head_hash != args.expect_head):
        failures.append(
            f"HEAD MISMATCH: expected head {args.expect_head}, verified head is "
            f"{report.head_hash if report.ok else 'unavailable (chain broken)'}"
        )

    if args.emit_json:
        out = report.as_dict()
        out["failures"] = failures
        print(json.dumps(out, sort_keys=True))
    else:
        _print_text(report, " ".join(str(p) for p in paths), failures)
        if args.anchor is not None and report.anchor_where is not None and report.ok:
            print(
                f"  anchor {args.anchor} found at {report.anchor_where}, "
                f"{report.records_after_anchor} records after it"
            )
        for failure in failures:
            print(f"audit-verify: {failure}")
    return 0 if report.ok and not failures else 1


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
