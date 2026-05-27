"""Audit decorator for MCP tool functions.

Step 4 wires every tool through a small ``@audited("<tool_name>")`` wrapper so
every invocation emits one :class:`mcp_unifi.audit.AuditEvent` to the configured
sink. The decorator deliberately lives at the **tool layer** (not the backend
method layer) so the captured envelope reflects user-facing tool intent: the
original kwargs, the original tool name, the controller the caller asked for.

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
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from mcp_unifi import audit

P = ParamSpec("P")
R = TypeVar("R")


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
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Wrap an async tool function so every call emits an audit event.

    Args:
        tool_name: The MCP tool name as registered with FastMCP. Must match
            the function name (or ``@mcp.tool(name=...)`` override) so audit
            log lines line up with what a caller actually invoked.

    The wrapped function preserves its original signature, so FastMCP's schema
    introspection sees the same parameters it would for the bare function.
    """

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

            start = time.perf_counter()
            try:
                result = await fn(*args, **kwargs)
            except Exception as exc:
                latency_ms = (time.perf_counter() - start) * 1000.0
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


__all__ = ["audited"]
