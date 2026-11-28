"""Check an audit log's hash chain and report the first broken link.

Usage::

    mcp-unifi-audit-verify audit.jsonl
    mcp-unifi-audit-verify audit.jsonl.1 audit.jsonl     # a rotated log, oldest first
    mcp-unifi-audit-verify audit.jsonl --json            # machine-readable summary

Exit status:

* ``0``: verified.
* ``1``: a break; the output names the first one.
* ``2``: usage error, or a file cannot be read.
* ``3``: verified, but damaged lines are present (a crash mid-write). An
  unknown number of records may be missing at each.

What a pass means: within one segment, an edited, removed, reordered or
inserted record is detected, unless whoever changed the file also recomputed
the hashes. What is not detected: records removed from the end of a segment or
the end of the file; a removed whole segment or whole rotated file; a full
rewrite. ``docs/decisions/0011-audit-records-are-correlated-and-hash-chained.md``
has the reasoning.

The output lists where every segment starts and prints the last record's
hash, as information only.

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

from mcp_unifi.audit_chain import VerifyReport, read_lines, verify_lines

EXIT_OK = 0
EXIT_BROKEN = 1
EXIT_USAGE = 2
EXIT_DAMAGED = 3

#: The closing line of every text report, so an "OK" is never read as
#: covering what the chain cannot see.
NOT_COVERED = (
    "  not covered: records before a segment start or after the last record, a removed "
    "whole segment or rotated file, and a full rewrite of the file"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-unifi-audit-verify",
        description=(
            "Verify the hash chain of an mcp-unifi audit log (JSONL). Within one segment, "
            "an edited, removed, reordered or inserted record is detected, unless whoever "
            "changed the file also recomputed the hashes. Not detected: records removed "
            "from the end of a segment or of the file, a removed whole segment or rotated "
            "file, a full rewrite. Exit 0 verified, 1 break, 2 usage, 3 verified with "
            "damaged lines."
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
        "--json",
        dest="emit_json",
        action="store_true",
        help="Print one JSON object with the full result instead of the text summary.",
    )
    return parser


def _print_text(report: VerifyReport, label: str) -> None:
    if not report.ok:
        assert report.broken is not None
        print(f"audit-verify: BROKEN at {report.broken.where}")
        print(f"  reason: {report.broken.reason}")
        print(f"  verified through: {report.verified_through or 'nothing (first record)'}")
    elif report.damaged:
        print(f"audit-verify: DAMAGED {label} (verified, with damaged lines; see below)")
    else:
        print(f"audit-verify: OK {label}")
    for where in report.damaged:
        print(
            f"  WARNING: damaged line at {where} (crash mid-write?): not a record; an unknown "
            "number of records at this point may be missing"
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
        print(f"    {n}. starts at {where} ({why})")
    if report.head_hash is not None:
        label = "last record hash" if report.ok else "last verified hash"
        print(f"  {label}: {report.head_hash} ({report.head_where})")
    print(NOT_COVERED)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = _build_parser().parse_args(argv)
    paths: list[Path] = list(args.log_paths)
    for p in paths:
        if not p.is_file():
            print(f"audit-verify: not a readable file: {p}", file=sys.stderr)
            return EXIT_USAGE
    try:
        report = verify_lines(read_lines(paths))
    except OSError as exc:
        print(f"audit-verify: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.emit_json:
        print(json.dumps(report.as_dict(), sort_keys=True))
    else:
        _print_text(report, " ".join(str(p) for p in paths))
    if not report.ok:
        return EXIT_BROKEN
    return EXIT_DAMAGED if report.damaged else EXIT_OK


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
