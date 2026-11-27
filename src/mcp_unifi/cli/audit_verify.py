"""Check an audit log's hash chain and report the first broken link.

Usage::

    mcp-unifi-audit-verify audit.jsonl
    mcp-unifi-audit-verify audit.jsonl.1 audit.jsonl     # a rotated log, oldest first
    mcp-unifi-audit-verify audit.jsonl --json            # machine-readable summary

Exit status: ``0`` when every chained record verifies, ``1`` at the first
broken link, ``2`` when a file cannot be read.

What a pass means, and what it cannot mean, is in
``docs/decisions/audit-records-are-correlated-and-hash-chained.md`` and
the audit guide. The short form: a pass says no record inside the file was
edited, removed or reordered by someone who did not recompute the chain. It
says nothing about records cut off the end of the file. To catch that, copy the
``head`` hash this command prints somewhere the server cannot write, and check
later that the record carrying it is still in the file.

Records written before the chain existed (schema ``"1"``, no ``hash``) are
reported as unchained, not as a break.

This is a read-only command. It never builds a server or touches a controller.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_unifi.audit_chain import VerifyReport, read_lines, verify_lines


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-unifi-audit-verify",
        description=(
            "Verify the hash chain of an mcp-unifi audit log (JSONL). Reports the first "
            "edited, removed or reordered record, and prints the head hash so it can be "
            "kept somewhere else. Cannot detect records cut off the end of the file."
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
    if report.ok:
        print(f"audit-verify: OK {label}")
    else:
        assert report.broken is not None
        print(f"audit-verify: BROKEN at {report.broken.where}")
        print(f"  reason: {report.broken.reason}")
        print(f"  verified through: {report.verified_through or 'nothing (first record)'}")
    print(f"  chained records: {report.chained}")
    if report.unchained:
        runs = ", ".join(a if a == b else f"{a} to {b}" for a, b in report.unchained_runs)
        print(
            f"  unchained records (written before the chain existed): {report.unchained} ({runs})"
        )
    if report.unchained_after_chained:
        print(
            "  note: unchained records follow chained ones. That is a downgrade to a version "
            "without the chain, or hash fields stripped from records; neither is verified."
        )
    for where, why in report.segment_starts:
        print(f"  segment starts at {where} ({why or 'start of input'})")
    if report.head_hash is not None:
        # Only a clean chain has a head worth copying elsewhere.
        label = "head" if report.ok else "last verified hash"
        print(f"  {label}: {report.head_hash} ({report.head_where})")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = _build_parser().parse_args(argv)
    paths: list[Path] = list(args.log_paths)
    for p in paths:
        if not p.is_file():
            print(f"audit-verify: not a readable file: {p}", file=sys.stderr)
            return 2
    try:
        report = verify_lines(read_lines(paths))
    except OSError as exc:
        print(f"audit-verify: {exc}", file=sys.stderr)
        return 2

    if args.emit_json:
        print(json.dumps(report.as_dict(), sort_keys=True))
    else:
        _print_text(report, " ".join(str(p) for p in paths))
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
