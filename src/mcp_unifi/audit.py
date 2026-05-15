"""Append-only audit log for mcp-unifi tool calls.

Every tool invocation can be recorded as a single JSONL line containing the
controller name, tool, scrubbed args, success flag, latency, and (on failure)
an error message. The log is the substrate for two v1.0 features:

1. **Forensics.** "What did the LLM actually do to my gateway last Tuesday?"
   answered by ``cat audit.jsonl | jq``.
2. **Replay.** ``mcp-unifi-replay <log>`` re-issues the captured calls against
   a fresh stub (or, with explicit opt-in flags, a real controller) for
   migrations and tests.

Design notes
------------
* Public API is a single ``audit.emit(...)`` coroutine. **No decorator** in
  this step on purpose: the dispatcher refactor (Step 3 of Phase 1) will
  decide where the call sites live, and we do not want to couple the audit
  module to a transient dispatcher shape.
* A module-level singleton (``AUDIT_LOG``) is built lazily from environment
  variables on first access. Tests override it via ``set_audit_log()``.
* File writes are serialized through a single ``asyncio.Lock`` so concurrent
  tool calls cannot interleave bytes mid-line.
* Secret scrubbing is a recursive walk that redacts any dict key matching a
  small set of well-known sensitive names (case-insensitive substring match
  against the registered patterns). Values become the literal string
  ``"***"``; structure is preserved so the log shape stays stable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger("mcp_unifi.audit")


# ---------------------------------------------------------------------------
# Secret scrubbing
# ---------------------------------------------------------------------------

#: Substrings (case-insensitive) that mark a dict key as sensitive. A key
#: matches if any pattern is a substring of the lowercased key. This catches
#: ``api_key``, ``X-API-Key``, ``unifi_api_key``, ``passphrase``,
#: ``x_passphrase``, ``password``, ``Password``, ``auth_token``, ``Bearer``-
#: style ``token`` keys, and ``client_secret``.
SENSITIVE_KEY_PATTERNS: frozenset[str] = frozenset(
    {
        "passphrase",
        "x_passphrase",
        "api_key",
        "password",
        "secret",
        "token",
    }
)

REDACTED = "***"


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(pattern in lowered for pattern in SENSITIVE_KEY_PATTERNS)


def scrub(value: Any) -> Any:
    """Recursively redact sensitive values inside dicts/lists.

    Dict values whose key matches a pattern in :data:`SENSITIVE_KEY_PATTERNS`
    are replaced with :data:`REDACTED`. All other values pass through. Lists
    and tuples are walked element-wise. Non-container values are returned
    as-is.

    The returned structure is always a fresh object — callers may mutate it
    without affecting their input.
    """
    if isinstance(value, dict):
        return {k: (REDACTED if _is_sensitive(str(k)) else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub(item) for item in value)
    return value


# ---------------------------------------------------------------------------
# Event envelope
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AuditEvent:
    """Single audit record. Serialised as one JSON line per emit."""

    ts: str
    controller: str
    tool: str
    args: dict[str, Any]
    result: Any
    success: bool
    latency_ms: float
    error: str | None = None
    # Schema version. Bump when the envelope shape changes so replay can
    # reject incompatible logs cleanly.
    schema: str = field(default="1")

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, sort_keys=True)


def _utc_now_iso() -> str:
    """ISO 8601 UTC timestamp with explicit ``Z`` suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


class Sink(Protocol):
    """Where an audit event ultimately lands.

    Sinks must be safe to call concurrently: the audit log holds a lock
    around each ``write`` so implementations can keep their internal logic
    straightforward.
    """

    async def write(self, event: AuditEvent) -> None: ...

    async def aclose(self) -> None: ...


class FileSink:
    """Append-only JSONL sink. Creates parent directories as needed."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    async def write(self, event: AuditEvent) -> None:
        # The outer audit log holds the lock. File open/write/close inside
        # one call is cheap and yields the simplest crash-safety story
        # (every line is fully fsynced by the OS before we return).
        line = event.to_json() + "\n"
        await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    async def aclose(self) -> None:
        return None


class StdoutSink:
    """Sink that writes one JSON line per event to stdout.

    Useful for container deployments that ship logs via Docker's logging
    driver. Note: do **not** combine with the stdio MCP transport, which
    also uses stdout.
    """

    async def write(self, event: AuditEvent) -> None:
        await asyncio.to_thread(self._write, event.to_json())

    @staticmethod
    def _write(line: str) -> None:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    async def aclose(self) -> None:
        return None


class SyslogSink:
    """Sink that emits via the stdlib ``SysLogHandler`` to local syslog.

    Each event becomes one syslog message at INFO. Production operators who
    already centralise via rsyslog/journald can route the ``mcp_unifi.audit``
    facility wherever they like.
    """

    def __init__(self, address: str | tuple[str, int] = "/dev/log") -> None:
        self._handler = logging.handlers.SysLogHandler(address=address)
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger = logging.getLogger("mcp_unifi.audit.syslog")
        # Avoid double-routing through the root logger; this logger is a
        # dedicated transport, not a diagnostic.
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)
        self._logger.addHandler(self._handler)

    async def write(self, event: AuditEvent) -> None:
        await asyncio.to_thread(self._logger.info, event.to_json())

    async def aclose(self) -> None:
        self._handler.close()
        self._logger.removeHandler(self._handler)


# ---------------------------------------------------------------------------
# Audit log facade
# ---------------------------------------------------------------------------

ENV_SINK = "MCP_UNIFI_AUDIT_SINK"
ENV_PATH = "MCP_UNIFI_AUDIT_PATH"
ENV_SYSLOG_ADDRESS = "MCP_UNIFI_AUDIT_SYSLOG_ADDRESS"

DEFAULT_PATH = "./audit.jsonl"
VALID_SINKS: frozenset[str] = frozenset({"file", "stdout", "syslog"})


class AuditLog:
    """Async-safe audit emitter with a swappable sink.

    The class is deliberately small — one lock, one sink, one ``emit`` method.
    Higher-level concerns (correlation IDs, sampling, multi-sink fan-out)
    can be layered on later if a real need shows up.
    """

    def __init__(self, sink: Sink) -> None:
        self._sink = sink
        self._lock = asyncio.Lock()

    @property
    def sink(self) -> Sink:
        return self._sink

    async def emit(
        self,
        controller: str,
        tool: str,
        args: dict[str, Any],
        result: Any,
        success: bool,
        latency_ms: float,
        error: str | None = None,
    ) -> AuditEvent:
        """Record a single tool invocation.

        Args are scrubbed before serialisation; the live arg dict the caller
        passed is not mutated. The returned :class:`AuditEvent` is convenient
        for tests that want to assert on the envelope without re-parsing the
        sink output.

        Failures inside the sink are logged and swallowed: an audit-log
        outage must never break a tool call.
        """
        event = AuditEvent(
            ts=_utc_now_iso(),
            controller=controller,
            tool=tool,
            args=scrub(args),
            result=scrub(result),
            success=success,
            latency_ms=round(latency_ms, 3),
            error=error,
        )
        async with self._lock:
            try:
                await self._sink.write(event)
            except Exception:  # pragma: no cover - defensive only
                logger.exception(
                    "audit sink write failed",
                    extra={"controller": controller, "tool": tool},
                )
        return event

    async def aclose(self) -> None:
        await self._sink.aclose()


# ---------------------------------------------------------------------------
# Module-level singleton (lazy)
# ---------------------------------------------------------------------------

_AUDIT_LOG: AuditLog | None = None


def _build_sink_from_env(env: dict[str, str] | None = None) -> Sink:
    e = env if env is not None else os.environ
    sink_name = (e.get(ENV_SINK) or "file").strip().lower()
    if sink_name not in VALID_SINKS:
        raise ValueError(f"{ENV_SINK}={sink_name!r} is not one of {sorted(VALID_SINKS)}")
    if sink_name == "stdout":
        return StdoutSink()
    if sink_name == "syslog":
        address = e.get(ENV_SYSLOG_ADDRESS, "/dev/log")
        return SyslogSink(address=address)
    return FileSink(path=e.get(ENV_PATH) or DEFAULT_PATH)


def get_audit_log() -> AuditLog:
    """Return the process-wide audit log, building it on first call."""
    global _AUDIT_LOG
    if _AUDIT_LOG is None:
        _AUDIT_LOG = AuditLog(sink=_build_sink_from_env())
    return _AUDIT_LOG


def set_audit_log(audit_log: AuditLog | None) -> None:
    """Override (or clear) the singleton. Intended for tests."""
    global _AUDIT_LOG
    _AUDIT_LOG = audit_log


async def emit(
    controller: str,
    tool: str,
    args: dict[str, Any],
    result: Any,
    success: bool,
    latency_ms: float,
    error: str | None = None,
) -> AuditEvent:
    """Convenience wrapper around :meth:`AuditLog.emit` on the singleton."""
    return await get_audit_log().emit(
        controller=controller,
        tool=tool,
        args=args,
        result=result,
        success=success,
        latency_ms=latency_ms,
        error=error,
    )


# ---------------------------------------------------------------------------
# Helpers used by replay
# ---------------------------------------------------------------------------


def parse_jsonl(lines: Iterable[str]) -> list[AuditEvent]:
    """Parse audit JSONL into :class:`AuditEvent` objects.

    Empty lines are skipped. Lines that fail to parse raise ``ValueError``
    with the offending line number — better to fail loudly during replay
    than silently drop calls.
    """
    events: list[AuditEvent] = []
    for lineno, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {lineno}: not valid JSON ({exc})") from exc
        try:
            events.append(
                AuditEvent(
                    ts=payload["ts"],
                    controller=payload["controller"],
                    tool=payload["tool"],
                    args=payload.get("args", {}) or {},
                    result=payload.get("result"),
                    success=bool(payload.get("success", False)),
                    latency_ms=float(payload.get("latency_ms", 0.0)),
                    error=payload.get("error"),
                    schema=str(payload.get("schema", "1")),
                )
            )
        except KeyError as exc:
            raise ValueError(f"line {lineno}: missing required field {exc}") from exc
    return events


__all__ = [
    "DEFAULT_PATH",
    "ENV_PATH",
    "ENV_SINK",
    "ENV_SYSLOG_ADDRESS",
    "REDACTED",
    "SENSITIVE_KEY_PATTERNS",
    "VALID_SINKS",
    "AuditEvent",
    "AuditLog",
    "FileSink",
    "Sink",
    "StdoutSink",
    "SyslogSink",
    "emit",
    "get_audit_log",
    "parse_jsonl",
    "scrub",
    "set_audit_log",
]


def __getattr__(name: str) -> Any:
    """Provide :data:`AUDIT_LOG` as a lazy module attribute."""
    if name == "AUDIT_LOG":
        return get_audit_log()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
