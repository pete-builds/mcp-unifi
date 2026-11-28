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

Correlation and tamper evidence (schema ``"2"``)
------------------------------------------------
* Every record carries a unique ``event_id`` and an ``operation_id``. A plain
  call's ``operation_id`` is its own ``event_id``. A destructive preview
  stores its ``event_id`` on the pending action, and the later
  ``confirm_destructive_action`` record carries that same value as its
  ``operation_id``, so ``jq 'select(.operation_id == "...")'`` returns the
  preview and the executed change together, in order.
* Every record carries ``prev_hash`` and ``hash`` (see
  :mod:`mcp_unifi.audit_chain`). Sealing happens inside the same lock as the
  sink write, after redaction, so the hash covers exactly what is written and
  two concurrent calls cannot fork the chain. The head hash is kept in memory;
  the file sink's last line is read once, on the first write after start.
* ``mcp-unifi-audit-verify`` walks a file and reports the first broken link.
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import stat
import sys
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from mcp_unifi import audit_chain

logger = logging.getLogger("mcp_unifi.audit")


# ---------------------------------------------------------------------------
# Secret scrubbing
# ---------------------------------------------------------------------------

# The redaction rules now live in mcp_unifi.redaction, which is shared with
# the tool **output** path. They used to live here, which is precisely why the
# read path leaked: redaction was scoped to auditing instead of to every
# emitter. Re-exported so existing importers of `audit.scrub` keep working.
from mcp_unifi.redaction import (  # noqa: E402
    REDACTED,
    SENSITIVE_KEY_PATTERNS,
    scrub,
)

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
    #: The authenticated client_id that issued this call, when HTTP transport
    #: auth is enabled (v0.9.0+). ``None`` on stdio or when auth is disabled.
    #: Replay tools tolerate older logs missing this field via the dataclass
    #: default, so schema stays at "1".
    client_id: str | None = None
    #: Which control refused this call before it ever reached the tool body
    #: (v0.21.0+): ``"readonly"`` for the write gate, ``"scope"`` for
    #: per-client module scoping. ``None`` on every call that was actually
    #: dispatched, so ``jq 'select(.denied_by)'`` isolates exactly the
    #: attempts that were blocked.
    #:
    #: This is a separate field rather than a convention on ``error``
    #: because ``success: false`` already means three different things in
    #: this log — the tool raised, the controller returned an error, or the
    #: call was never made. Only the third is a security event, and only
    #: this field distinguishes it without parsing prose. Replay reads it
    #: to skip refused calls instead of re-issuing them.
    denied_by: str | None = None
    #: Unique id of this record (schema 2+). ``None`` only on records parsed
    #: from a log written before schema 2.
    event_id: str | None = None
    #: Groups the records that make up one change (schema 2+). Equal to
    #: ``event_id`` for a plain call. A ``confirm_destructive_action`` record
    #: carries the ``event_id`` of the preview it executed.
    operation_id: str | None = None
    #: Set only on a record that begins a new hash-chain segment, naming why
    #: (``audit_chain.CHAIN_START_*``). ``None`` on a record that continues one.
    chain_start: str | None = None
    #: ``hash`` of the record before this one, or the genesis value.
    prev_hash: str | None = None
    #: SHA-256 over this record without ``hash``. See :mod:`mcp_unifi.audit_chain`.
    hash: str | None = None
    # Schema version. Bump when the envelope shape changes so replay can
    # reject incompatible logs cleanly. "2" added the ids and the hash chain;
    # every field it added has a default, so schema-1 lines still parse.
    schema: str = field(default=audit_chain.CHAINED_SCHEMA)

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
    """Append-only JSONL sink. Creates parent directories as needed.

    It is the one sink that can read back what it wrote, so it is the one that
    continues the hash chain across restarts (:meth:`resume_chain`). It never
    rewrites an existing line.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        #: True once this sink has written a complete line itself, so the
        #: file is known to end in a newline.
        self._tail_ok = False

    @property
    def path(self) -> Path:
        return self._path

    async def write(self, event: AuditEvent) -> None:
        # The outer audit log holds the lock. File open/write/fsync/close
        # inside one call is cheap and yields a simple crash-safety story:
        # once ``emit`` returns, the line is durable on the underlying
        # storage (subject to disk-level write barriers).
        line = event.to_json() + "\n"
        await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:
        # Runs under the audit lock. On this sink's first write, a file that
        # does not end in a newline (a crash cut the last write off mid-line,
        # or an editor dropped the final newline) gets one first. Otherwise the
        # new record would be fused onto that last line and lost to every
        # reader. resume_from_file reads the same last line either way, so the
        # chain decision and the write agree.
        prefix = "" if self._tail_ok else self._newline_if_unterminated()
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(prefix + line)
            fh.flush()
            os.fsync(fh.fileno())
        self._tail_ok = True

    def _newline_if_unterminated(self) -> str:
        """``"\\n"`` when the file's last byte is not a newline, else ``""``.

        Never raises: a read this sink cannot do must never stop a record
        being written. A path that is not a regular file (a pipe such as a
        piped ``/dev/stdout``, a character device) is a stream with no last
        line to repair and is never opened for reading, because opening a pipe
        to read can block. A regular file that cannot be read (mode 0200)
        gets a newline: at worst one blank line, which every reader skips.
        """
        try:
            mode = self._path.stat().st_mode
        except FileNotFoundError:
            return ""
        except OSError:
            return "\n"
        if not stat.S_ISREG(mode):
            return ""
        try:
            with self._path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                if fh.tell() == 0:
                    return ""
                fh.seek(-1, os.SEEK_END)
                return "" if fh.read(1) == b"\n" else "\n"
        except FileNotFoundError:
            return ""
        except OSError:
            return "\n"

    async def resume_chain(self) -> audit_chain.ChainResume:
        """Where the chain continues: the ``hash`` on the file's last line.

        Reads only the tail of the file, once, before this process's first
        write. Never raises; see :func:`mcp_unifi.audit_chain.resume_from_file`.
        """
        return await asyncio.to_thread(audit_chain.resume_from_file, self._path)

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


def _new_event_id() -> str:
    """A fresh record id: 32 lowercase hex characters of a UUID4."""
    return uuid.uuid4().hex


class AuditLog:
    """Async-safe audit emitter with a swappable sink.

    The class is deliberately small — one lock, one sink, one ``emit`` method.
    It also owns the head of the hash chain, because only code inside the
    lock may read and advance it.

    Args:
        sink: Where records go.
        id_factory: Makes ``event_id`` values. Tests inject a deterministic
            one; the default is a UUID4 in hex.
        client_id_override: When set, every record carries this ``client_id``
            whatever the caller passed. ``mcp-unifi-replay`` marks its records
            this way. It has to happen here, before the record is hashed: a
            sink that changed a field after sealing would break the chain.
    """

    def __init__(
        self,
        sink: Sink,
        *,
        id_factory: Callable[[], str] | None = None,
        client_id_override: str | None = None,
    ) -> None:
        self._sink = sink
        self._lock = asyncio.Lock()
        self._new_id = id_factory or _new_event_id
        self._client_id_override = client_id_override
        #: ``hash`` of the last record this process sealed. ``None`` until the
        #: first write, which resumes it from the sink.
        self._head: str | None = None

    @property
    def sink(self) -> Sink:
        return self._sink

    def new_event_id(self) -> str:
        """Allocate an ``event_id`` before the record exists.

        The audit decorator does this when a tool call starts, so a preview
        can store its own id on the pending action before its record is
        written. Pass the value back to :meth:`emit` as ``event_id``.
        """
        return self._new_id()

    async def _resume(self) -> audit_chain.ChainResume:
        resume = getattr(self._sink, "resume_chain", None)
        if resume is None:
            # stdout and syslog cannot be read back, so each process start
            # begins a segment of its own.
            return audit_chain.ChainResume(
                audit_chain.GENESIS_HASH, audit_chain.CHAIN_START_PROCESS_START
            )
        result: audit_chain.ChainResume = await resume()
        return result

    async def _seal(self, event: AuditEvent) -> None:
        """Link ``event`` to the chain and hash it. Caller holds the lock."""
        if self._head is None:
            try:
                start = await self._resume()
            except Exception:
                logger.exception("audit chain could not be resumed; starting a new segment")
                start = audit_chain.ChainResume(
                    audit_chain.GENESIS_HASH, audit_chain.CHAIN_START_UNREADABLE_LOG
                )
            self._head = start.prev_hash
            event.chain_start = start.chain_start
        event.prev_hash = self._head
        # Hash the record as it will read back from the file, and keep those
        # values on the event, so the line the sink writes is exactly the
        # material that was hashed (plus ``hash`` itself).
        material = audit_chain.normalize({k: v for k, v in asdict(event).items() if k != "hash"})
        event.args = material["args"]
        event.result = material["result"]
        event.hash = audit_chain.record_hash(material)
        # Advanced whether or not the sink write then succeeds: a record that
        # was sealed but never landed shows up to the verifier as a missing
        # record, instead of vanishing without a trace.
        self._head = event.hash

    async def emit(
        self,
        controller: str,
        tool: str,
        args: dict[str, Any],
        result: Any,
        success: bool,
        latency_ms: float,
        error: str | None = None,
        client_id: str | None = None,
        denied_by: str | None = None,
        event_id: str | None = None,
        operation_id: str | None = None,
    ) -> AuditEvent:
        """Record a single tool invocation, or a refusal to make one.

        Args are scrubbed before serialisation; the live arg dict the caller
        passed is not mutated. The returned :class:`AuditEvent` is convenient
        for tests that want to assert on the envelope without re-parsing the
        sink output.

        ``event_id`` defaults to a fresh id (see :meth:`new_event_id`) and
        ``operation_id`` defaults to the ``event_id``, so a caller that knows
        nothing about correlation, such as the scope and write gates in
        :mod:`mcp_unifi.scoping`, still writes a complete record.

        Failures inside the sink are logged and swallowed: an audit-log
        outage must never break a tool call.
        """
        eid = event_id or self._new_id()
        event = AuditEvent(
            ts=_utc_now_iso(),
            controller=controller,
            tool=tool,
            args=scrub(args),
            result=scrub(result),
            success=success,
            latency_ms=round(latency_ms, 3),
            error=error,
            client_id=self._client_id_override or client_id,
            denied_by=denied_by,
            event_id=eid,
            operation_id=operation_id or eid,
        )
        async with self._lock:
            try:
                await self._seal(event)
            except Exception:  # pragma: no cover - defensive only
                logger.exception(
                    "audit record could not be sealed into the hash chain",
                    extra={"controller": controller, "tool": tool},
                )
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

#: What :func:`check_configured_sink` found at startup, served on ``/health``.
_SINK_STATUS: dict[str, Any] | None = None


def _configured_sink_name(e: Mapping[str, str]) -> str:
    sink_name = (e.get(ENV_SINK) or "file").strip().lower()
    if sink_name not in VALID_SINKS:
        raise ValueError(f"{ENV_SINK}={sink_name!r} is not one of {sorted(VALID_SINKS)}")
    return sink_name


def _build_sink_from_env(env: dict[str, str] | None = None) -> Sink:
    e = env if env is not None else os.environ
    sink_name = _configured_sink_name(e)
    if sink_name == "stdout":
        return StdoutSink()
    if sink_name == "syslog":
        address = e.get(ENV_SYSLOG_ADDRESS, "/dev/log")
        return SyslogSink(address=address)
    return FileSink(path=e.get(ENV_PATH) or DEFAULT_PATH)


def _file_is_appendable(path: Path) -> bool:
    """Whether the file sink could append to ``path``, found by doing what it does.

    Opens the file for append (creating it, and its parent directories, just
    as :class:`FileSink` would on the first call) and writes nothing. A
    permission check alone would miss a read-only filesystem.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
    except OSError:
        return False
    return True


def check_configured_sink(
    *, transport: str, env: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Check the configured audit sink at startup and record its state for ``/health``.

    The sink used to be built on the first tool call, so a configuration
    error surfaced there instead of at boot. Two cases now fail startup, and
    both already broke every call or the transport:

    * an unknown ``MCP_UNIFI_AUDIT_SINK`` (a typo such as ``files``), with
      the same message every tool call used to fail with;
    * the stdout sink combined with the stdio transport, which would write
      audit lines into the JSON-RPC stream.

    A file sink that cannot be written does NOT fail startup. That is the
    default ``./audit.jsonl`` on a read-only root filesystem, which is what
    the shipped compose file and Helm chart run, so refusing would take down
    deployments that boot today. Instead one ERROR names the path and the
    fix, and ``/health`` reports ``writable: false``. Tool calls keep working
    and each failed write is still logged by :meth:`AuditLog.emit`.

    Returns the summary ``/health`` serves: the sink name, and for the file
    sink whether it could be written at startup. Never the path, since
    ``/health`` answers unauthenticated.
    """
    global _SINK_STATUS
    e = env if env is not None else os.environ
    sink_name = _configured_sink_name(e)
    if sink_name == "stdout" and transport == "stdio":
        raise ValueError(
            f"{ENV_SINK}=stdout cannot be used with MCP_TRANSPORT=stdio: the stdio "
            f"transport owns stdout for its JSON-RPC stream, and audit lines written "
            f"there would corrupt it. Use {ENV_SINK}=file (with {ENV_PATH}) or "
            f"{ENV_SINK}=syslog."
        )
    status: dict[str, Any] = {"sink": sink_name}
    if sink_name == "file":
        path = Path(e.get(ENV_PATH) or DEFAULT_PATH)
        writable = _file_is_appendable(path)
        status["writable"] = writable
        if not writable:
            logger.error(
                "audit log cannot be written at %s: tool calls will run, but none will be "
                "recorded. Set %s=stdout to ship audit lines with the container log, or "
                "point %s at a writable path such as a mounted volume.",
                path,
                ENV_SINK,
                ENV_PATH,
            )
    _SINK_STATUS = status
    return dict(status)


def sink_status() -> dict[str, Any] | None:
    """What :func:`check_configured_sink` found, or ``None`` if it has not run."""
    return None if _SINK_STATUS is None else dict(_SINK_STATUS)


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
                    client_id=payload.get("client_id"),
                    # Absent in logs written before v0.21.0; a missing field
                    # correctly reads as "this call was dispatched".
                    denied_by=payload.get("denied_by"),
                    # Absent from schema-1 logs, which predate correlation
                    # and the hash chain. Each reads as None.
                    event_id=payload.get("event_id"),
                    operation_id=payload.get("operation_id"),
                    chain_start=payload.get("chain_start"),
                    prev_hash=payload.get("prev_hash"),
                    hash=payload.get("hash"),
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
    "check_configured_sink",
    "emit",
    "get_audit_log",
    "parse_jsonl",
    "scrub",
    "set_audit_log",
    "sink_status",
]


def __getattr__(name: str) -> Any:
    """Provide :data:`AUDIT_LOG` as a lazy module attribute."""
    if name == "AUDIT_LOG":
        return get_audit_log()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
