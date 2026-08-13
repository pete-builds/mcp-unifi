"""Replay an audit log against an in-process mcp-unifi server.

Usage::

    mcp-unifi-replay path/to/audit.jsonl                       # stub mode (default)
    mcp-unifi-replay path/to/audit.jsonl --target-controller home --i-mean-it

Stub mode is the default. Real-mode replay (talking to a live UniFi
controller) is gated on **two** explicit flags so it cannot be triggered by
a typo or a stray shell expansion:

* ``--target-controller <name>`` — names the controller the replay is
  authorised to touch. The replayer will only re-issue events whose
  ``controller`` field matches this name.
* ``--i-mean-it`` — second confirmation. Without it, the CLI exits before
  any network call is made.

**Scope note.** Replay builds a fresh, in-process FastMCP instance and
invokes tools via ``server.call_tool``. It does NOT go through the HTTP
transport, which means the per-client bearer-token scope from
``MCP_UNIFI_AUTH_TOKENS`` is bypassed by design — replay runs with full
tool access regardless of how narrow any client's scope is. This CLI is
an operator/admin tool; only run it on systems where you already trust
the operator's shell access.

The CLI is intentionally minimal in this step. Step 3 (dispatcher refactor)
will wire per-tool ``controller`` arg handling; until then real-mode replay
shells out to the existing single-controller wiring and uses the matching
event filter as a soft safety belt.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mcp_unifi.audit import AuditEvent, parse_jsonl
from mcp_unifi.config import Settings
from mcp_unifi.logging_setup import configure_logging

logger = logging.getLogger("mcp_unifi.cli.replay")


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ReplayResult:
    """Outcome of a single replayed call."""

    tool: str
    controller: str
    success: bool
    error: str | None
    skipped: bool = False
    skip_reason: str | None = None


# ---------------------------------------------------------------------------
# Server construction (lazy import so --help is fast and side-effect free)
# ---------------------------------------------------------------------------


def _build_server(*, stub_mode: bool) -> Any:
    """Build a FastMCP server. Imported lazily to keep ``--help`` cheap."""
    from mcp_unifi.server import build_server  # local import on purpose

    settings = Settings(stub_mode=stub_mode, log_format="text")
    return build_server(settings)


async def _call_tool(server: Any, name: str, args: dict[str, Any]) -> Any:
    return await server.call_tool(name, args)


# ---------------------------------------------------------------------------
# Replay loop
# ---------------------------------------------------------------------------


async def replay_events(
    events: Sequence[AuditEvent],
    *,
    stub_mode: bool,
    target_controller: str | None,
    i_mean_it: bool,
    server: Any | None = None,
) -> list[ReplayResult]:
    """Replay each event against the in-process server.

    In stub mode every event runs. In real mode, ``target_controller`` and
    ``i_mean_it`` must both be set; events whose ``controller`` field does
    not match ``target_controller`` are skipped (not failed).
    """
    if not stub_mode and (not target_controller or not i_mean_it):
        raise RuntimeError("Real-mode replay requires --target-controller <name> AND --i-mean-it.")

    srv = server if server is not None else _build_server(stub_mode=stub_mode)
    results: list[ReplayResult] = []
    for event in events:
        if event.denied_by:
            # A refused call was never made. The write gate and the scope
            # gate both write their refusals into this log, and re-issuing
            # one here would take the exact action the operator's own policy
            # denied — the log would become a way to launder a denial.
            results.append(
                ReplayResult(
                    tool=event.tool,
                    controller=event.controller,
                    success=False,
                    error=None,
                    skipped=True,
                    skip_reason=f"refused at capture time by {event.denied_by}; never dispatched",
                )
            )
            continue
        if (
            not stub_mode
            and target_controller is not None
            and event.controller != target_controller
        ):
            results.append(
                ReplayResult(
                    tool=event.tool,
                    controller=event.controller,
                    success=False,
                    error=None,
                    skipped=True,
                    skip_reason=(
                        f"event.controller={event.controller!r} != "
                        f"target_controller={target_controller!r}"
                    ),
                )
            )
            continue
        try:
            await _call_tool(srv, event.tool, dict(event.args))
            results.append(
                ReplayResult(
                    tool=event.tool,
                    controller=event.controller,
                    success=True,
                    error=None,
                )
            )
        except Exception as exc:  # we want every failure surfaced, not just UniFiError
            results.append(
                ReplayResult(
                    tool=event.tool,
                    controller=event.controller,
                    success=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    return results


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-unifi-replay",
        description=(
            "Replay an mcp-unifi audit log (JSONL) against an in-process MCP "
            "server. Stub mode by default; real-mode replay requires two "
            "explicit safety flags."
        ),
    )
    parser.add_argument(
        "log_path",
        type=Path,
        help="Path to an audit log file (JSONL, one event per line).",
    )
    parser.add_argument(
        "--target-controller",
        type=str,
        default=None,
        help="Real-mode only: name of the controller authorised to receive replayed calls.",
    )
    parser.add_argument(
        "--i-mean-it",
        action="store_true",
        help="Real-mode only: second confirmation flag. Required to talk to a live controller.",
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help=(
            "Replay against a real controller instead of stub mode. Requires "
            "--target-controller AND --i-mean-it."
        ),
    )
    parser.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Emit per-event results as JSON to stdout (one object per line).",
    )
    return parser


def _read_events(log_path: Path) -> list[AuditEvent]:
    if not log_path.exists():
        raise FileNotFoundError(f"audit log not found: {log_path}")
    with log_path.open("r", encoding="utf-8") as fh:
        return parse_jsonl(fh)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    configure_logging(level="INFO", fmt="text")

    try:
        events = _read_events(args.log_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"replay: {exc}", file=sys.stderr)
        return 2

    stub_mode = not args.real
    if not stub_mode and (not args.target_controller or not args.i_mean_it):
        print(
            "replay: --real requires both --target-controller <name> and --i-mean-it",
            file=sys.stderr,
        )
        return 2

    try:
        results = asyncio.run(
            replay_events(
                events,
                stub_mode=stub_mode,
                target_controller=args.target_controller,
                i_mean_it=args.i_mean_it,
            )
        )
    except RuntimeError as exc:
        print(f"replay: {exc}", file=sys.stderr)
        return 2

    succeeded = sum(1 for r in results if r.success)
    skipped = sum(1 for r in results if r.skipped)
    failed = sum(1 for r in results if not r.success and not r.skipped)

    if args.emit_json:
        for r in results:
            print(json.dumps(asdict(r), default=str))
    else:
        print(
            f"replay complete: {len(results)} events "
            f"(succeeded={succeeded}, failed={failed}, skipped={skipped})"
        )

    return 0 if failed == 0 else 1


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
