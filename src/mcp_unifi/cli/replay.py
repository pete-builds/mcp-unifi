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
transport, so it needs no bearer token, and the per-client scope from
``MCP_UNIFI_AUTH_TOKENS`` is bypassed by design: replay runs with full tool
access regardless of how narrow any client's scope is. Read-only mode
(``MCP_UNIFI_READONLY``) still applies, because it is a posture of the
whole server rather than of one client. This CLI is an operator/admin tool;
only run it on systems where you already trust the operator's shell access.

**What replay records.** A stub replay is a rehearsal and writes nothing to
the configured audit sink, so it can never be mistaken for a real event. A
real-mode replay IS a real mutation and is audited in the configured sink
like any other call, with ``client_id`` set to ``mcp-unifi-replay`` so it
can be told apart. Real mode refuses to run when the log being replayed is
the file that sink appends to.

**What replay skips.** Calls refused at capture time (``denied_by``), calls
for another controller in real mode, and calls whose recorded arguments
carry the audit log's redaction sentinel. The log never holds a secret, so
a recorded ``update_wlan`` carries ``***`` where the passphrase was;
re-issuing it would set the passphrase to ``***`` and report success.

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
import os
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from mcp_unifi import audit
from mcp_unifi.audit import AuditEvent, AuditLog, FileSink, parse_jsonl
from mcp_unifi.config import Settings, describe_validation_error
from mcp_unifi.logging_setup import configure_logging
from mcp_unifi.redaction import REDACTED

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


#: ``client_id`` on every audit record a real-mode replay writes. The field
#: already exists on the envelope, so marking a replayed call needs no schema
#: change, and ``jq 'select(.client_id == "mcp-unifi-replay")'`` finds them.
REPLAY_CLIENT_ID = "mcp-unifi-replay"


class _DiscardSink:
    """Audit sink for a stub replay: rehearsed calls are not events."""

    async def write(self, event: AuditEvent) -> None:
        return None

    async def aclose(self) -> None:
        return None


class _ReplayMarkedSink:
    """Write to the configured sink, marking each record as a replayed call."""

    def __init__(self, inner: audit.Sink) -> None:
        self._inner = inner

    async def write(self, event: AuditEvent) -> None:
        event.client_id = REPLAY_CLIENT_ID
        await self._inner.write(event)

    async def aclose(self) -> None:
        await self._inner.aclose()


def _build_server(*, stub_mode: bool) -> Any:
    """Build the in-process server replay calls, and point the audit log at the right sink.

    The server is built for the stdio transport whatever the environment
    says. Nothing reaches it over a network, so it needs no bearer token
    (the default HTTP transport refused to build without one) and applies no
    per-client scoping (with scoped tokens configured, every replayed call
    was refused, because an in-process call carries no identity). Read-only
    mode is not transport-bound and still applies.

    Imported lazily to keep ``--help`` cheap.
    """
    from mcp_unifi.server import build_server  # local import on purpose

    settings = Settings(stub_mode=stub_mode, log_format="text", mcp_transport="stdio")
    sink: audit.Sink = (
        _DiscardSink() if stub_mode else _ReplayMarkedSink(audit.get_audit_log().sink)
    )
    audit.set_audit_log(AuditLog(sink=sink))
    return build_server(settings)


def _redacted_arguments(value: Any) -> bool:
    """True when ``value`` holds the audit redaction sentinel anywhere."""
    if isinstance(value, str):
        return value == REDACTED
    if isinstance(value, dict):
        return any(_redacted_arguments(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_redacted_arguments(v) for v in value)
    return False


async def _call_tool(server: Any, name: str, args: dict[str, Any]) -> Any:
    return await server.call_tool(name, args)


def _error_envelope(result: Any) -> str | None:
    """Return the tool's error message when it answered with an error envelope.

    Tools do not raise on a bad request; they return ``{"error": ...}`` as a
    JSON string. A replay that only catches exceptions counts every such
    answer as success, which is how a replayed ``confirm_destructive_action``
    with a scrubbed token reported success while nothing was deleted.
    """
    payload: Any = result
    content = getattr(result, "content", None)
    if content:
        text = getattr(content[0], "text", None)
        if isinstance(text, str):
            try:
                payload = json.loads(text)
            except ValueError:
                return None
    if isinstance(payload, dict) and payload.get("error"):
        return str(payload["error"])
    return None


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
    not match ``target_controller`` are skipped (not failed). Events refused
    at capture time, and events whose arguments hold a redacted secret, are
    skipped in both modes.
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
        if _redacted_arguments(event.args):
            # The audit log scrubs secrets before it writes, so what it holds
            # is the sentinel, not the value. Sending it would overwrite the
            # real secret with the literal sentinel and count as a success.
            results.append(
                ReplayResult(
                    tool=event.tool,
                    controller=event.controller,
                    success=False,
                    error=None,
                    skipped=True,
                    skip_reason=(
                        f"arguments carry secrets the audit log redacted ({REDACTED!r}); "
                        "the original values are not in the log, so this call cannot be "
                        "replayed faithfully"
                    ),
                )
            )
            continue
        try:
            outcome = await _call_tool(srv, event.tool, dict(event.args))
            envelope_error = _error_envelope(outcome)
            results.append(
                ReplayResult(
                    tool=event.tool,
                    controller=event.controller,
                    success=envelope_error is None,
                    error=(
                        None
                        if envelope_error is None
                        else f"tool returned an error envelope: {envelope_error}"
                    ),
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


def _same_file(a: Path, b: Path) -> bool:
    """True when ``a`` and ``b`` name one file, through symlinks and relative paths."""
    try:
        if b.exists():
            return os.path.samefile(a, b)
        return a.resolve() == b.resolve()
    except OSError:
        return False


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
        if not stub_mode:
            # A real replay is audited in the configured sink. Appending to
            # the very log being replayed would mix the replay into the
            # evidence it was read from.
            sink = audit.get_audit_log().sink
            if isinstance(sink, FileSink) and _same_file(args.log_path, sink.path):
                print(
                    f"replay: refusing to replay {args.log_path} with --real: it is the file "
                    f"the audit sink appends to ({audit.ENV_PATH}). Copy the log elsewhere "
                    "and replay the copy.",
                    file=sys.stderr,
                )
                return 2
        server = _build_server(stub_mode=stub_mode)
    except ValidationError as exc:
        print(f"replay: {describe_validation_error(exc)}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"replay: {exc}", file=sys.stderr)
        return 2

    try:
        results = asyncio.run(
            replay_events(
                events,
                stub_mode=stub_mode,
                target_controller=args.target_controller,
                i_mean_it=args.i_mean_it,
                server=server,
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
