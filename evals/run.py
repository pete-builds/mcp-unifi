"""Command-line entry point for the agent-quality evals.

    python -m evals.run                       # deterministic classes only
    python -m evals.run --all                 # add the model-dependent classes
    python -m evals.run --classes refusal     # one class
    python -m evals.run --all --out evals/results/scoreboard-<label>.json
    python -m evals.run --all --baseline evals/results/baseline-<label>.json

Exit codes:

``0``  everything that ran, passed (or was cleanly skipped)
``1``  a deterministic class failed, or a baseline comparison found a regression
``2``  the run could not be set up (bad arguments, unreadable baseline)

A missing model is never an error. With no credentials configured the
model-dependent classes are marked skipped with a printed reason and the exit
code still reflects only the deterministic classes.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from evals.catalog import TIER_ORDER
from evals.classes.audit_fidelity import run_audit_fidelity
from evals.classes.jailbreak import run_jailbreak
from evals.classes.refusal import run_refusal
from evals.classes.tool_selection import run_tool_selection
from evals.harness import eval_server
from evals.model import ModelTarget, discover_target
from evals.scoring import ClassResult, Scoreboard, compare_to_baseline

DETERMINISTIC_CLASSES = ("refusal", "audit_fidelity")
MODEL_CLASSES = ("tool_selection", "jailbreak")
ALL_CLASSES = DETERMINISTIC_CLASSES + MODEL_CLASSES


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="evals.run", description=__doc__)
    parser.add_argument(
        "--classes",
        nargs="+",
        choices=ALL_CLASSES,
        help=f"classes to run (default: {' '.join(DETERMINISTIC_CLASSES)})",
    )
    parser.add_argument(
        "--all", action="store_true", help="run every class, including the model-dependent ones"
    )
    parser.add_argument("--model", help="model id, overriding MCP_UNIFI_EVAL_MODEL")
    parser.add_argument(
        "--tiers",
        nargs="+",
        choices=TIER_ORDER,
        help=(
            "surface tiers for tool_selection (default: all three). Narrowing this "
            "produces a scoreboard that is not comparable to a full baseline."
        ),
    )
    parser.add_argument("--out", type=Path, help="write the scoreboard JSON here")
    parser.add_argument("--baseline", type=Path, help="compare the scoreboard against this file")
    return parser.parse_args(argv)


async def _surface_facts() -> tuple[int, int]:
    """Return ``(total_tools, mutating_tools)`` from a live registration."""
    async with eval_server(readonly=False) as session:
        tools = await session.server.list_tools()
        return len(tools), sum(1 for t in tools if "mutating" in t.tags)


async def _run(args: argparse.Namespace) -> int:
    selected = (
        tuple(args.classes)
        if args.classes
        else ALL_CLASSES
        if args.all
        else (DETERMINISTIC_CLASSES)
    )
    tiers = tuple(args.tiers) if args.tiers else TIER_ORDER
    needs_model = any(name in MODEL_CLASSES for name in selected)
    target, reason = discover_target(args.model) if needs_model else (None, "not requested")
    if needs_model:
        print(f"model: {reason}")

    total, mutating = await _surface_facts()
    board = Scoreboard(
        model_label=target.label if target else "none",
        model_reachable=target is not None,
        tool_total=total,
        mutating_total=mutating,
        server_version=_server_version(),
    )

    for name in selected:
        print(f"running {name} ...", flush=True)
        board.classes.append(await _run_class(name, target, reason, tiers))

    _print_report(board)

    exit_code = 0
    failures = board.deterministic_failures()
    if failures:
        print("\nDETERMINISTIC FAILURES (these gate CI):")
        for line in failures:
            print(f"  {line}")
        exit_code = 1

    if args.out:
        board.write(args.out)
        print(f"\nscoreboard written to {args.out}")

    if args.baseline:
        problems = _compare(board, args.baseline)
        if problems is None:
            return 2
        if problems:
            print("\nREGRESSIONS AGAINST BASELINE:")
            for line in problems:
                print(f"  {line}")
            exit_code = 1
        else:
            print(f"\nno regression against {args.baseline}")
    return exit_code


async def _run_class(
    name: str, target: ModelTarget | None, reason: str, tiers: tuple[str, ...]
) -> ClassResult:
    if name == "refusal":
        return await run_refusal()
    if name == "audit_fidelity":
        return await run_audit_fidelity()
    if name == "tool_selection":
        return await run_tool_selection(target, skip_reason=reason, tiers=tiers)
    if name == "jailbreak":
        return await run_jailbreak(target, skip_reason=reason)
    raise ValueError(f"unknown class {name!r}")


def _compare(board: Scoreboard, baseline_path: Path) -> list[str] | None:
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read baseline {baseline_path}: {exc}", file=sys.stderr)
        return None
    return compare_to_baseline(board.to_dict(), baseline)


def _print_report(board: Scoreboard) -> None:
    print(f"\n{'=' * 68}")
    print(f"mcp-unifi agent evals | server {board.server_version} | model {board.model_label}")
    print(f"tool surface: {board.tool_total} tools, {board.mutating_total} mutating")
    print("=" * 68)
    for cls in board.classes:
        if cls.skipped:
            print(f"{cls.name:<16} SKIPPED  {cls.skip_reason}")
            continue
        kind = "gate" if cls.deterministic else "record"
        if cls.tiers:
            print(f"{cls.name:<16} ({kind})")
            for tier, results in cls.tiers.items():
                passed = sum(1 for c in results if c.passed)
                share = passed / len(results) if results else 0.0
                print(f"  {tier:<14} {passed:>3}/{len(results):<3} {share:6.1%}")
        else:
            passed = sum(1 for c in cls.cases if c.passed)
            share = passed / len(cls.cases) if cls.cases else 0.0
            print(f"{cls.name:<16} ({kind}) {passed:>3}/{len(cls.cases):<3} {share:6.1%}")
        for case in cls.cases:
            if not case.passed:
                print(f"    FAIL {case.case_id}: {case.outcome}: {case.detail}")
        for tier, results in cls.tiers.items():
            for case in results:
                if not case.passed:
                    print(f"    miss [{tier}] {case.case_id}: {case.outcome}: {case.detail}")
    print("=" * 68)


def _server_version() -> str:
    from mcp_unifi import __version__

    return str(__version__)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
