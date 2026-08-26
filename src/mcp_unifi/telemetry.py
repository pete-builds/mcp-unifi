"""Optional OpenTelemetry tracing for mcp-unifi tool calls.

One span per tool call, carrying the four facts an operator needs to answer
"what did the agent try, and what happened": the tool name, whether it
mutates, whether it was a dry run, and which control refused it. Those are the
same facts :mod:`mcp_unifi.audit` already writes to JSONL. The audit log is the
forensic record of one server; a trace backend is where you ask questions
across time and across callers ("how many write attempts did client
``ci-bot`` make last week, and how many did the write gate refuse?").

Strictly optional, and that is the whole design constraint
----------------------------------------------------------
This server ships to other people. Most of them will never run a collector.
So:

* The OpenTelemetry **SDK** and the OTLP **exporter** are not dependencies at
  all. They are not in ``requirements.in``, not in ``requirements.lock``, and
  not in the ``[project] dependencies`` table. They live in the ``otel``
  extra (``pip install mcp-unifi[otel]``), which nothing installs by default.
  Stated precisely, because it matters: ``opentelemetry-api`` **is** already
  present transitively (``fastmcp-slim`` depends on it, and it is pinned at
  1.44.0 in ``requirements.lock``). The API on its own is inert. Without an
  SDK-installed tracer provider it returns a no-op tracer, so a default
  deployment creates no real spans and exports nothing even if the flag were
  flipped on.
* Tracing is **off unless asked for**. ``MCP_UNIFI_OTEL_ENABLED`` defaults to
  false, so even a deployment that happens to have the packages present
  (pulled in by some unrelated library) emits nothing.
* Every import of the OpenTelemetry API happens lazily, inside a
  ``try``/``except ImportError``, at first use. A missing package downgrades
  to "tracing disabled" plus one warning line. It is never fatal, and it never
  happens at server start.
* Every span operation is wrapped. A misconfigured exporter, a collector that
  went away, an API shape that moved between OpenTelemetry versions: all of
  them degrade to no span. **An observability failure must not become a tool
  failure.** That is the same rule :meth:`mcp_unifi.audit.AuditLog.emit`
  follows for sink errors.

With the flag unset, a server behaves exactly as it did before this module
existed: :func:`get_tracer` short-circuits before any import, returns ``None``
on the first call, caches that, and every span becomes :data:`NULL_SPAN`,
whose methods do nothing.

What is deliberately *not* recorded
-----------------------------------
Tool arguments and tool results never reach a span. Not scrubbed, not
truncated: never.

Span attributes are an emission path exactly like a ``dry_run`` preview or a
list response, and the lesson of GHSA-m3mv-27vr-gh2w is that redaction has to
be scoped to *every* emitter or it covers nothing. A trace backend is a
persistent, usually third-party, usually broadly-readable store. Getting a WPA
passphrase into one would be the same class of bug, with a worse blast radius.

So this module inverts the audit log's posture. The audit log takes arbitrary
args and scrubs them on the way out. Spans take a **fixed allowlist of
scalars** and nothing else, because an allowlist cannot be defeated by a
controller field nobody has seen yet. :meth:`SpanRecorder.set` enforces it twice
over: a key matching :data:`~mcp_unifi.redaction.SENSITIVE_KEY_PATTERNS` is
dropped, and so is any value that is not a ``str``, ``bool``, ``int``, or
``float``.

Exception **messages** are dropped for the same reason: they are free-form and
routinely echo caller input (a bad payload, a rejected SSID). The span records
the exception *type* only. The message stays in the audit log, which is local
to the operator by default.

Environment variables
---------------------
``MCP_UNIFI_OTEL_ENABLED``
    ``true``/``1``/``yes``/``on`` to enable. Default off.
``MCP_UNIFI_OTEL_SERVICE_NAME``
    Service name for the tracer. Default ``mcp-unifi``.

Endpoint, headers, sampling, and protocol are configured with the standard
``OTEL_EXPORTER_OTLP_*`` variables read by the OpenTelemetry SDK itself. This
module deliberately does not re-invent them, and it does **not** install a
tracer provider: if the process has no provider configured, the OpenTelemetry
API hands back a no-op tracer and nothing is exported. See
``docs/operations.md`` for a worked example using the
``opentelemetry-instrument`` bootstrap.
"""

from __future__ import annotations

import importlib
import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

from mcp_unifi.redaction import is_sensitive

logger = logging.getLogger("mcp_unifi.telemetry")

ENV_ENABLED: Final = "MCP_UNIFI_OTEL_ENABLED"
ENV_SERVICE_NAME: Final = "MCP_UNIFI_OTEL_SERVICE_NAME"

DEFAULT_SERVICE_NAME: Final = "mcp-unifi"

#: Prefix for every span this server emits, so a trace backend can select
#: mcp-unifi work with one ``name =~ "mcp.tool/*"`` filter.
SPAN_NAME_PREFIX: Final = "mcp.tool/"

# --- Attribute names -------------------------------------------------------
#
# Namespaced under ``mcp.`` because OpenTelemetry semantic conventions have no
# vocabulary for MCP tool calls, and squatting on ``rpc.*`` would misreport
# this as a standard RPC span in any backend that special-cases those.

#: The MCP tool name as the caller invoked it.
ATTR_TOOL: Final = "mcp.tool.name"
#: The tool's declared write classification (``mutates=`` on ``@audited``).
#: This is the attribute that makes "show me every write attempt" one query.
ATTR_MUTATES: Final = "mcp.tool.mutates"
#: True when the caller passed ``dry_run=True``, i.e. the tool previewed a
#: change instead of applying it. Absent on tools with no ``dry_run`` param,
#: which is itself the signal that the tool has no preview mode.
ATTR_DRY_RUN: Final = "mcp.tool.dry_run"
#: Which control refused the call before it reached the tool body:
#: ``"readonly"`` or ``"scope"``. Present only on refusals, so
#: ``mcp.tool.denied_by != ""`` isolates exactly the blocked attempts, the
#: same way ``jq 'select(.denied_by)'`` does over the audit log (ADR 0006).
ATTR_DENIED_BY: Final = "mcp.tool.denied_by"
#: Which named controller the call was routed to.
ATTR_CONTROLLER: Final = "mcp.tool.controller"
#: Authenticated client_id, when HTTP transport auth is on. Absent otherwise.
ATTR_CLIENT_ID: Final = "mcp.tool.client_id"
#: ``"ok"``, ``"error"``, or ``"refused"``. Three outcomes, not two, because
#: a refusal is not a failure: the server worked correctly and declined. The
#: audit log conflates the two under ``success: false`` for backward
#: compatibility; a span has no such history to preserve, so it splits them.
ATTR_OUTCOME: Final = "mcp.tool.outcome"
#: Exception class name on the error path. The message is deliberately
#: omitted; see the module docstring.
ATTR_ERROR_TYPE: Final = "mcp.tool.error_type"
#: Whether this server is answering from the built-in stub backend rather than
#: a real controller. Without it, latency numbers from a demo deployment are
#: indistinguishable from production ones in the same backend.
ATTR_STUB_MODE: Final = "mcp.server.stub_mode"

OUTCOME_OK: Final = "ok"
OUTCOME_ERROR: Final = "error"
OUTCOME_REFUSED: Final = "refused"

#: Values OpenTelemetry accepts as scalar attribute values. Anything else
#: (a dict, a list, a controller record, a Pydantic model) is dropped rather
#: than stringified, because stringifying is how an argument payload sneaks
#: onto a span.
_ALLOWED_VALUE_TYPES: Final = (str, bool, int, float)

_TRUTHY: Final = frozenset({"1", "true", "yes", "on"})


def _env_flag(name: str, env: dict[str, str] | None = None) -> bool:
    source = env if env is not None else os.environ
    return (source.get(name) or "").strip().lower() in _TRUTHY


def is_enabled(env: dict[str, str] | None = None) -> bool:
    """True when the operator asked for tracing. Default False."""
    return _env_flag(ENV_ENABLED, env)


# ---------------------------------------------------------------------------
# Span recorder
# ---------------------------------------------------------------------------


class SpanRecorder:
    """Thin, fail-safe wrapper over an OpenTelemetry span.

    Two jobs. First, enforce the attribute allowlist described in the module
    docstring, so no caller of this class can put a payload on a span even by
    accident. Second, swallow every exception the underlying span raises: an
    exporter problem must never surface as a tool error.
    """

    __slots__ = ("_span",)

    def __init__(self, span: Any) -> None:
        self._span = span

    @property
    def enabled(self) -> bool:
        """True when this recorder is attached to a real span."""
        return self._span is not None

    def set(self, key: str, value: object) -> bool:
        """Set one attribute. Returns True when it was actually recorded.

        Dropped, silently and by design, when:

        * the span is a no-op (tracing disabled),
        * ``value`` is ``None`` (an absent fact is recorded by absence, not by
          a ``"None"`` string that a backend cannot filter on),
        * ``key`` names something sensitive per
          :func:`mcp_unifi.redaction.is_sensitive`,
        * ``value`` is not a permitted scalar type.
        """
        if self._span is None or value is None:
            return False
        if is_sensitive(key):
            # Defensive: no current call site passes a sensitive key. This is
            # here so that a future one fails closed instead of exporting.
            logger.warning("refusing to set a sensitive span attribute: %s", key)
            return False
        if not isinstance(value, _ALLOWED_VALUE_TYPES):
            logger.debug("dropping non-scalar span attribute: %s (%s)", key, type(value).__name__)
            return False
        try:
            self._span.set_attribute(key, value)
        except Exception:  # pragma: no cover - defensive only
            logger.debug("span.set_attribute failed for %s", key, exc_info=True)
            return False
        return True

    def set_many(self, attributes: dict[str, object]) -> None:
        for key, value in attributes.items():
            self.set(key, value)

    def record_error(self, exc: BaseException) -> None:
        """Record that the tool body raised, by exception type only."""
        self.set(ATTR_OUTCOME, OUTCOME_ERROR)
        self.set(ATTR_ERROR_TYPE, type(exc).__name__)
        try:
            self._span.set_status(_error_status())
        except Exception:  # pragma: no cover - defensive only
            logger.debug("span.set_status failed", exc_info=True)


#: Recorder handed out when tracing is off. Every method is a no-op, so call
#: sites never branch on whether tracing is enabled.
NULL_SPAN: Final = SpanRecorder(None)


def _error_status() -> Any:
    """Build an OpenTelemetry ERROR status without a static import.

    Returns ``None`` if the API is unavailable, in which case
    :meth:`SpanRecorder.record_error` just sets no status. The description is
    omitted on purpose: it would be the exception message.
    """
    try:
        trace = importlib.import_module("opentelemetry.trace")
        return trace.Status(trace.StatusCode.ERROR)
    except Exception:  # pragma: no cover - defensive only
        return None


# ---------------------------------------------------------------------------
# Tracer acquisition
# ---------------------------------------------------------------------------

_TRACER: Any = None
_TRACER_RESOLVED = False


def get_tracer() -> Any:
    """Return the process tracer, or ``None`` when tracing is unavailable.

    Resolved once and cached, including the ``None`` result, so a server
    running without OpenTelemetry pays one failed import for its whole life
    rather than one per tool call.
    """
    global _TRACER, _TRACER_RESOLVED
    if _TRACER_RESOLVED:
        return _TRACER
    _TRACER_RESOLVED = True
    if not is_enabled():
        _TRACER = None
        return None
    try:
        trace = importlib.import_module("opentelemetry.trace")
    except ImportError:
        logger.warning(
            "%s is set but the opentelemetry packages are not installed, so tracing "
            "stays off. Install them with: pip install 'mcp-unifi[otel]'. The server "
            "is otherwise unaffected.",
            ENV_ENABLED,
        )
        _TRACER = None
        return None
    except Exception:  # pragma: no cover - defensive only
        logger.warning("could not load opentelemetry; tracing stays off", exc_info=True)
        _TRACER = None
        return None
    try:
        service_name = (os.environ.get(ENV_SERVICE_NAME) or DEFAULT_SERVICE_NAME).strip()
        _TRACER = trace.get_tracer(service_name)
        logger.info("OpenTelemetry tracing enabled (service.name=%s)", service_name)
    except Exception:  # pragma: no cover - defensive only
        logger.warning("opentelemetry tracer could not be created; tracing stays off")
        _TRACER = None
    return _TRACER


def set_tracer(tracer: Any) -> None:
    """Install a tracer directly, bypassing env lookup and the lazy import.

    Exists for tests, which use a recording fake so the span contract can be
    asserted without adding an OpenTelemetry dependency to the test
    environment. Pass ``None`` to disable; call :func:`reset_tracer` to go back
    to env-driven resolution.
    """
    global _TRACER, _TRACER_RESOLVED
    _TRACER = tracer
    _TRACER_RESOLVED = True


def reset_tracer() -> None:
    """Forget the cached tracer so the next call re-reads the environment."""
    global _TRACER, _TRACER_RESOLVED
    _TRACER = None
    _TRACER_RESOLVED = False


# ---------------------------------------------------------------------------
# Server-level facts
# ---------------------------------------------------------------------------

_STUB_MODE: bool | None = None


def configure(*, stub_mode: bool | None) -> None:
    """Record server-level facts that every span should carry.

    Called once from :func:`mcp_unifi.server.build_server`. Kept out of the
    per-call path because :func:`mcp_unifi.modules._audit.audited` has no
    access to :class:`~mcp_unifi.config.Settings`, and re-reading the
    environment there would duplicate config parsing that pydantic already
    owns.
    """
    global _STUB_MODE
    _STUB_MODE = stub_mode


def stub_mode() -> bool | None:
    """The configured stub-mode flag, or ``None`` if never configured."""
    return _STUB_MODE


# ---------------------------------------------------------------------------
# Span helpers
# ---------------------------------------------------------------------------


@contextmanager
def tool_span(
    tool_name: str,
    *,
    mutates: bool | None = None,
    controller: str | None = None,
    client_id: str | None = None,
    dry_run: bool | None = None,
    denied_by: str | None = None,
) -> Iterator[SpanRecorder]:
    """Open a span for one tool call, yielding a :class:`SpanRecorder`.

    Yields :data:`NULL_SPAN` when tracing is off or when span creation fails
    for any reason, so the caller's body is identical either way.

    ``record_exception=False`` is deliberate: the OpenTelemetry default
    attaches the full exception message and traceback as a span event, and a
    UniFi error message can carry the payload the caller just submitted. The
    caller records the exception type via :meth:`SpanRecorder.record_error`
    instead, and the message stays in the audit log.
    """
    tracer = get_tracer()
    if tracer is None:
        yield NULL_SPAN
        return
    try:
        cm = tracer.start_as_current_span(
            SPAN_NAME_PREFIX + tool_name,
            record_exception=False,
            set_status_on_exception=False,
        )
    except Exception:  # pragma: no cover - defensive only
        logger.debug("could not start a span for %s", tool_name, exc_info=True)
        yield NULL_SPAN
        return
    with cm as span:
        recorder = SpanRecorder(span)
        recorder.set_many(
            {
                ATTR_TOOL: tool_name,
                ATTR_MUTATES: mutates,
                ATTR_DRY_RUN: dry_run,
                ATTR_DENIED_BY: denied_by,
                ATTR_CONTROLLER: controller,
                ATTR_CLIENT_ID: client_id,
                ATTR_STUB_MODE: _STUB_MODE,
            }
        )
        yield recorder


def coerce_dry_run(value: object) -> bool | None:
    """Normalise a ``dry_run`` kwarg to a bool, or ``None`` when absent.

    Tools declare ``dry_run: bool`` so the value arrives as a bool in practice,
    but FastMCP dispatches from JSON and a caller can send anything. Anything
    that is not already a bool is reported as ``None`` (unknown) rather than
    guessed, because a wrong ``dry_run=false`` on a span would misreport a
    preview as an applied change.
    """
    return value if isinstance(value, bool) else None


__all__ = [
    "ATTR_CLIENT_ID",
    "ATTR_CONTROLLER",
    "ATTR_DENIED_BY",
    "ATTR_DRY_RUN",
    "ATTR_ERROR_TYPE",
    "ATTR_MUTATES",
    "ATTR_OUTCOME",
    "ATTR_STUB_MODE",
    "ATTR_TOOL",
    "DEFAULT_SERVICE_NAME",
    "ENV_ENABLED",
    "ENV_SERVICE_NAME",
    "NULL_SPAN",
    "OUTCOME_ERROR",
    "OUTCOME_OK",
    "OUTCOME_REFUSED",
    "SPAN_NAME_PREFIX",
    "SpanRecorder",
    "coerce_dry_run",
    "configure",
    "get_tracer",
    "is_enabled",
    "reset_tracer",
    "set_tracer",
    "stub_mode",
    "tool_span",
]
