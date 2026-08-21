"""Audit decorator and write-classification for MCP tool functions.

Step 4 wires every tool through a small ``@audited("<tool_name>", mutates=...)``
wrapper so every invocation emits one :class:`mcp_unifi.audit.AuditEvent` to the
configured sink. The decorator deliberately lives at the **tool layer** (not the
backend method layer) so the captured envelope reflects user-facing tool intent:
the original kwargs, the original tool name, the controller the caller asked for.

Read/write classification (v0.21)
---------------------------------
``mutates`` is a **required** keyword argument. It declares whether the tool
changes state anywhere outside this process — controller configuration, device
state, or controller-side work. :class:`mcp_unifi.scoping.WriteGateMiddleware`
uses it to enforce ``MCP_UNIFI_READONLY``.

Why here, and why required:

* It is declared at the registration site, next to the tool body and its
  ``Side effects:`` docstring, so a reviewer classifies and implements in the
  same diff.
* Being required makes the gate fail closed at *import* time. Adding a tool
  without classifying it raises ``TypeError`` and the server refuses to boot —
  there is no default that silently leaves a new mutating tool callable while
  ``MCP_UNIFI_READONLY=true``.
* It reuses the decorator every tool already carries rather than adding a
  parallel mechanism.

Classification is recorded in a process-level registry keyed by tool name
(:func:`tool_mutates`) rather than as an attribute on the wrapped function:
FastMCP re-wraps tool callables during registration, so an attribute set here
is not guaranteed to survive onto ``Tool.fn``. The registry is the value the
dispatcher reads when it tags tools, and it is what the completeness test in
``tests/test_write_gate.py`` enumerates.

Design notes
------------
* Tool bodies are ``async def`` and return JSON strings (the payload Claude
  sees). For audit we parse that string back into a structured object so the
  audit log carries dicts, not stringified JSON. If parsing fails (a tool
  returned a non-JSON sentinel for some reason) we fall back to the raw string.
* Args are scrubbed by :func:`mcp_unifi.audit.AuditLog.emit` before they hit
  the sink — sensitive keys (``passphrase``, ``api_key``, ``password``,
  ``secret``, ``token``, etc.) become ``"***"``. We do not pre-scrub here; one
  redaction pass keeps the contract in one place.
* On exception the decorator records ``success=False`` with ``error=str(exc)``
  and re-raises. The audit emit itself never blocks the exception path —
  sink errors are caught and logged inside :class:`AuditLog.emit`.
* Latency is wall-clock milliseconds measured around the wrapped coroutine.

Tracing (optional, v0.22)
-------------------------
The same wrapper opens one OpenTelemetry span per call via
:func:`mcp_unifi.telemetry.tool_span`. This is the right seam for it: it
already knows the tool name, the declared ``mutates`` flag, the resolved
controller, and the caller's kwargs (so it can read ``dry_run``), and it
already sits on both the success and the exception path.

Tracing is off by default and OpenTelemetry is not a runtime dependency; when
it is absent the span object is a no-op and this wrapper behaves exactly as it
did before. Arguments and results are **not** put on the span. See
:mod:`mcp_unifi.telemetry` for why.

The span's ``mcp.tool.outcome`` attribute uses the same semantics as the audit
log's ``success`` field: ``"ok"`` means the tool body returned, which includes
returning a formatted error envelope because the controller rejected the
request. That asymmetry is deliberate in the audit log and is preserved here so
the two records agree line for line. A trace that shows ``outcome=ok`` is
saying "the server did its job", not "the change was applied".
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from mcp_unifi import audit, telemetry

P = ParamSpec("P")
R = TypeVar("R")

#: ``{tool_name: mutates}`` for every tool decorated with :func:`audited`.
#: Populated at decoration time (i.e. when a module's ``register()`` runs).
_CLASSIFICATION: dict[str, bool] = {}


class ToolClassificationConflictError(ValueError):
    """Raised when one tool name is declared with two different ``mutates`` values.

    Tool names are globally unique across modules, so two conflicting
    declarations mean either a copy-paste error or a genuine name collision.
    Either way the write gate could not answer "is this tool mutating?"
    deterministically, so we refuse at registration rather than pick one.
    """


def tool_mutates(tool_name: str) -> bool | None:
    """Return the declared ``mutates`` flag for ``tool_name``, or ``None``.

    ``None`` means "never classified" and is treated as a hard error by
    :func:`mcp_unifi.dispatcher.register_modules` — never as "read-only".
    """
    return _CLASSIFICATION.get(tool_name)


def classified_tools() -> dict[str, bool]:
    """Return a copy of the whole ``{tool_name: mutates}`` registry."""
    return dict(_CLASSIFICATION)


def _current_client_id() -> str | None:
    """Return the authenticated client_id for the current request, or None.

    Falls back to None on stdio, in tests without an MCP context, or when
    auth is disabled. Never raises — audit must work even if the FastMCP
    dependency surface changes shape across versions.
    """
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
    except Exception:
        return None
    return token.client_id if token is not None else None


def _coerce_result(value: Any) -> Any:
    """Best-effort decode of a tool's return value into a structured object.

    Tools return JSON strings (via :func:`format_json`). We parse them back so
    the audit log holds dicts/lists, not stringified payloads. Anything we
    cannot parse is recorded as-is.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def audited(
    tool_name: str,
    *,
    mutates: bool,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Wrap an async tool function so every call emits an audit event.

    Args:
        tool_name: The MCP tool name as registered with FastMCP. Must match
            the function name (or ``@mcp.tool(name=...)`` override) so audit
            log lines line up with what a caller actually invoked.
        mutates: Required. ``True`` when calling the tool changes state outside
            this process — controller configuration, device state (an LED, a
            reboot, a deauth), or controller-side work (a speed test). ``False``
            only when the tool is a pure read: it may call the controller, but
            leaves it exactly as it found it. Read the tool's ``Side effects:``
            docstring section and make them agree. Tools declared ``True`` are
            hidden and refused when ``MCP_UNIFI_READONLY=true``.

    The wrapped function preserves its original signature, so FastMCP's schema
    introspection sees the same parameters it would for the bare function.
    """
    previous = _CLASSIFICATION.get(tool_name)
    if previous is not None and previous != mutates:
        raise ToolClassificationConflictError(
            f"tool {tool_name!r} was declared with mutates={previous} and again "
            f"with mutates={mutates}. Tool names must be globally unique and "
            f"carry one classification."
        )
    _CLASSIFICATION[tool_name] = mutates

    def decorator(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Tools are always invoked with kwargs from FastMCP's JSON
            # dispatch. Defensive: if any positional args slip through, capture
            # them under a synthetic key so they aren't silently dropped from
            # the audit envelope.
            audit_args: dict[str, Any] = dict(kwargs)
            if args:
                audit_args["_positional"] = list(args)

            controller = str(kwargs.get("controller", "default"))
            client_id = _current_client_id()
            log = audit.get_audit_log()

            # The span wraps the audit emit as well as the tool body, so its
            # duration is the full cost of serving the call rather than just
            # the controller round trip. That is the number an SLO is written
            # against: a caller waits for both.
            with telemetry.tool_span(
                tool_name,
                mutates=mutates,
                controller=controller,
                client_id=client_id,
                dry_run=telemetry.coerce_dry_run(kwargs.get("dry_run")),
            ) as span:
                start = time.perf_counter()
                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:
                    latency_ms = (time.perf_counter() - start) * 1000.0
                    span.record_error(exc)
                    await log.emit(
                        controller=controller,
                        tool=tool_name,
                        args=audit_args,
                        result=None,
                        success=False,
                        latency_ms=latency_ms,
                        error=str(exc),
                        client_id=client_id,
                    )
                    raise

                latency_ms = (time.perf_counter() - start) * 1000.0
                span.set(telemetry.ATTR_OUTCOME, telemetry.OUTCOME_OK)
                await log.emit(
                    controller=controller,
                    tool=tool_name,
                    args=audit_args,
                    result=_coerce_result(result),
                    success=True,
                    latency_ms=latency_ms,
                    client_id=client_id,
                )
                return result

        return wrapper

    return decorator


__all__ = [
    "ToolClassificationConflictError",
    "audited",
    "classified_tools",
    "tool_mutates",
]
