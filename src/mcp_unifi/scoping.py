"""Tool-visibility middleware: per-client module scoping and the read-only write gate.

Two filters live here because they are the same shape — decide from a tag the
dispatcher already applied whether this caller may see and call this tool — and
differ only in what they key on. :class:`ScopeMiddleware` keys on the caller's
module allowlist. :class:`WriteGateMiddleware` keys on whether the tool mutates.

Per-client tool scoping (HTTP transport)
----------------------------------------
Every tool registered on the FastMCP instance carries a module tag added
by :func:`mcp_unifi.dispatcher.register_modules` (``"network"``,
``"protect"``, or ``"access"``). Every bearer token in
``MCP_UNIFI_AUTH_TOKENS`` carries an ``allowed_modules`` set parsed by
:meth:`mcp_unifi.config.Settings.auth_client_scopes` — either ``{"*"}``
(full access, the default) or an explicit subset like
``{"network", "protect"}``.

:class:`ScopeMiddleware` bridges the two. On ``tools/list`` it filters
the response so a scoped client sees only tools tagged with a module in
its allowlist. On ``tools/call`` it rejects invocations of any tool the
caller's scope does not cover, so a client can't bypass the filter by
guessing tool names.

Why middleware and not per-tool ``auth=`` checks: adding an ``auth=``
argument to every ``@mcp.tool()`` call site would touch every module.
The middleware pattern keeps the concern in one file, keyed off tags the
dispatcher already applies uniformly.

Read-only write gate (both transports)
--------------------------------------
:class:`WriteGateMiddleware` is installed only when ``MCP_UNIFI_READONLY``
is on. It hides and refuses every tool tagged :data:`MUTATING_TAG`, which
the dispatcher applies from each tool's required
``@audited(..., mutates=...)`` declaration.

Where scoping asks "may *this caller* use this tool", the write gate asks
"is *this server* willing to change anything at all". The second question
has no per-client answer, which is why it keys on a tool property rather
than on the caller's identity and applies on stdio as well as HTTP.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware.middleware import (
    CallNext,
    Middleware,
    MiddlewareContext,
)
from fastmcp.tools.tool import Tool, ToolResult
from mcp import types as mt

from mcp_unifi import audit, telemetry
from mcp_unifi.modules._audit import tool_mutates

logger = logging.getLogger("mcp_unifi.scoping")

WILDCARD = "*"

#: Tag added by :func:`mcp_unifi.dispatcher.register_modules` to every tool
#: declared ``@audited(..., mutates=True)``. Lives in the same ``tool.tags``
#: set as the module tags, so :func:`_tool_modules` filters it back out before
#: any module-scope comparison.
MUTATING_TAG = "mutating"

#: Values written to :attr:`mcp_unifi.audit.AuditEvent.denied_by` so an
#: operator can tell the two controls apart in one ``jq`` pass. Read-only mode
#: is a property of the server; scope is a property of the caller, and the
#: response to each is different — one is "turn the posture off", the other is
#: "widen this client's token".
DENIED_BY_READONLY = "readonly"
DENIED_BY_SCOPE = "scope"


class ScopeMiddleware(Middleware):
    """Filter tool visibility and invocation by the caller's module scope.

    Args:
        client_scopes: ``{client_id: {module_name, ...}}``. A scope
            containing :data:`WILDCARD` (``"*"``) permits every tool.
            Unknown client_ids fall through to :data:`WILDCARD` behavior,
            because the auth provider validated the token upstream and a
            token with no scope entry means the operator omitted a scope
            (backward compat with the pre-scoping token format).
    """

    def __init__(self, client_scopes: dict[str, set[str]]) -> None:
        self._client_scopes = client_scopes
        self._unresolved_logged: set[str] = set()

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        allowed = self._allowed_modules_for_current_request()
        if WILDCARD in allowed:
            return tools
        return [t for t in tools if _tool_modules(t) & allowed]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, Any],
    ) -> Any:
        allowed = self._allowed_modules_for_current_request()
        if WILDCARD not in allowed:
            tool_name = context.message.name
            tool_modules = await _resolve_tool_modules(context, tool_name)
            if not tool_modules & allowed:
                # Never disclose which modules exist — a scoped client
                # shouldn't be able to enumerate tools it can't see by
                # brute-forcing names and reading the denial message. The
                # audit record is the opposite side of that wall: the
                # operator reading the log is entitled to the detail the
                # caller is not.
                message = f"Tool {tool_name!r} is not available to this client."
                await _record_refusal(
                    context,
                    tool_name=tool_name,
                    denied_by=DENIED_BY_SCOPE,
                    error=(
                        f"{message} Refused by per-client module scoping "
                        f"(MCP_UNIFI_AUTH_TOKENS). No call was made to the controller."
                    ),
                )
                raise ToolError(message)
        return await call_next(context)

    def _allowed_modules_for_current_request(self) -> set[str]:
        """Look up the current caller's allowed module set.

        Fails CLOSED when identity is unresolvable. This middleware is only
        installed when scoping is active (see
        ``server._install_scope_middleware``), so an unresolved caller —
        ``get_access_token()`` raised, no token in context, or a
        ``client_id`` not in ``_client_scopes`` — is an anomaly, and a
        wildcard fallback here would silently defeat the boundary. Stdio
        and every-client-wildcard modes short-circuit before this
        middleware is ever added.
        """
        client_id = _current_client_id()
        if client_id is None:
            self._log_unresolved("<no-token>")
            return set()
        allowed = self._client_scopes.get(client_id)
        if allowed is None:
            self._log_unresolved(client_id)
            return set()
        return allowed

    def _log_unresolved(self, key: str) -> None:
        # Once per distinct key so a hostile client cannot spam logs.
        if key in self._unresolved_logged:
            return
        self._unresolved_logged.add(key)
        logger.warning(
            "scope middleware denying request with unresolved client identity",
            extra={"client_id": key},
        )


def _current_client_id() -> str | None:
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
    except Exception:
        return None
    return token.client_id if token is not None else None


def _tool_modules(tool: Tool) -> set[str]:
    """Return a tool's module tags, excluding the non-module write tag."""
    return set(getattr(tool, "tags", None) or set()) - {MUTATING_TAG}


def _tool_is_mutating(tool: Tool) -> bool:
    return MUTATING_TAG in (getattr(tool, "tags", None) or set())


async def _lookup_tool(
    context: MiddlewareContext[mt.CallToolRequestParams], tool_name: str
) -> Tool | None:
    """Return the registered :class:`Tool` for ``tool_name``, or ``None``.

    Uses the request's FastMCP context to look up the registered tool
    without touching internal FastMCP state. ``None`` means "could not be
    resolved" — an unknown name, or a context this middleware cannot read.
    Both callers treat that as a denial, never as a permit.
    """
    fastmcp_ctx = context.fastmcp_context
    if fastmcp_ctx is None:
        return None
    try:
        return await fastmcp_ctx.fastmcp.get_tool(tool_name)
    except Exception:
        return None


async def _resolve_tool_modules(
    context: MiddlewareContext[mt.CallToolRequestParams], tool_name: str
) -> set[str]:
    """Return the module tag set for ``tool_name``, or empty set if unknown."""
    tool = await _lookup_tool(context, tool_name)
    return set() if tool is None else _tool_modules(tool)


def _attempted_args(context: MiddlewareContext[mt.CallToolRequestParams]) -> dict[str, Any]:
    """Return the arguments the caller tried to use, as an audit-shaped dict.

    A non-dict ``arguments`` payload is wrapped rather than dropped: the point
    of a refusal record is what was attempted, and "the caller sent something
    malformed" is itself worth keeping. Never returns the caller's object by
    reference, so scrubbing downstream cannot mutate live request state.
    """
    arguments = getattr(context.message, "arguments", None)
    if isinstance(arguments, dict):
        return dict(arguments)
    if arguments is None:
        return {}
    return {"_arguments": arguments}


async def _record_refusal(
    context: MiddlewareContext[mt.CallToolRequestParams],
    *,
    tool_name: str,
    denied_by: str,
    error: str,
) -> None:
    """Write a refused call into the audit log.

    The refusal happens above the ``@audited`` decorator, so nothing else in
    the stack will record it — and a denied mutation attempt is exactly the
    line an operator reviewing an agent wants to find. The record reuses
    :meth:`mcp_unifi.audit.AuditLog.emit`, which means the attempted arguments
    run through the same scrubber as a dispatched call: a refused
    ``create_wlan`` still arrives carrying the caller's passphrase, and the
    audit log is a persistent sink like any other.

    ``latency_ms`` is 0.0 rather than a measured value, because no work was
    done; the gate decided from a tag it already had.

    Failures are swallowed. An audit outage must not convert a clean refusal
    envelope into a transport-level error — the caller would learn less, not
    more, and the control itself would appear to have failed open.
    """
    try:
        args = _attempted_args(context)
        client_id = _current_client_id()
        # A refused call never reaches ``@audited``, so it would otherwise be
        # invisible in a trace backend while being one of the most interesting
        # things to query there. The span carries ``denied_by`` for the same
        # reason the audit record does (ADR 0006): it is the one field that
        # separates "the server declined" from "something broke". Attempted
        # arguments go to the audit log only, never onto the span.
        with telemetry.tool_span(
            tool_name,
            mutates=tool_mutates(tool_name),
            controller=str(args.get("controller", "default")),
            client_id=client_id,
            denied_by=denied_by,
        ) as span:
            span.set(telemetry.ATTR_OUTCOME, telemetry.OUTCOME_REFUSED)
        await audit.get_audit_log().emit(
            controller=str(args.get("controller", "default")),
            tool=tool_name,
            args=args,
            result=None,
            success=False,
            latency_ms=0.0,
            error=error,
            client_id=client_id,
            denied_by=denied_by,
        )
    except Exception:  # pragma: no cover - defensive only
        logger.exception(
            "failed to record a refused tool call in the audit log",
            extra={"tool": tool_name, "denied_by": denied_by},
        )


class WriteGateMiddleware(Middleware):
    """Hide and refuse every mutating tool while ``MCP_UNIFI_READONLY`` is on.

    Installed only when :attr:`mcp_unifi.config.Settings.readonly` is True, so
    a default deployment pays nothing. When it is installed:

    * ``tools/list`` omits every tool tagged :data:`MUTATING_TAG`, so a model
      is never shown a capability it cannot use.
    * ``tools/call`` refuses those same tools before the call reaches the tool
      body, so a caller that hard-codes a tool name, replays an old manifest,
      or guesses gets nowhere. Hiding alone would be advisory; the call gate is
      the control.

    The refusal is the server's normal error envelope
    (``{"error": ..., "stub_mode": ...}``), not a raised
    :class:`~fastmcp.exceptions.ToolError`. Every tool in this server reports
    failure that way — see the ``resolve_backend`` docstring for the same
    reasoning applied to dispatcher errors — and a caller that already handles
    tool errors should not need a second code path to handle this one.

    Fail-closed by construction: a tool whose tags cannot be resolved is
    refused. The classification itself is enforced upstream at registration
    (:func:`mcp_unifi.dispatcher.register_modules` raises on any unclassified
    tool), so an unresolvable tool here is an anomaly, and the safe reading of
    an anomaly in a write gate is "assume it writes".

    Args:
        stub_mode: Value echoed as ``stub_mode`` in the refusal envelope, so
            the envelope matches what a real tool would have returned.
    """

    def __init__(self, *, stub_mode: bool) -> None:
        self._stub_mode = stub_mode

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        return [t for t in tools if not _tool_is_mutating(t)]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, Any],
    ) -> Any:
        tool_name = context.message.name
        tool = await _lookup_tool(context, tool_name)
        if tool is None or _tool_is_mutating(tool):
            logger.warning(
                "read-only mode refused a tool call",
                extra={
                    "tool": tool_name,
                    "client_id": _current_client_id(),
                    "resolved": tool is not None,
                },
            )
            message = self._refusal_message(tool_name)
            # The warning above is diagnostic and rotates away with the
            # container logs. The audit record is the evidence surface, and
            # "the agent tried to delete a VLAN and was refused" belongs
            # there — a control that keeps no record of what it denied is
            # only half a control.
            await _record_refusal(
                context,
                tool_name=tool_name,
                denied_by=DENIED_BY_READONLY,
                error=message,
            )
            return self._refusal(message)
        return await call_next(context)

    @staticmethod
    def _refusal_message(tool_name: str) -> str:
        return (
            f"{tool_name} changes state and this server is running in "
            f"read-only mode (MCP_UNIFI_READONLY=true). No call was made "
            f"to the controller. Read tools are unaffected."
        )

    def _refusal(self, message: str) -> ToolResult:
        payload = json.dumps(
            {"error": message, "stub_mode": self._stub_mode},
            indent=2,
            default=str,
        )
        return ToolResult(content=[mt.TextContent(type="text", text=payload)])


__all__ = [
    "DENIED_BY_READONLY",
    "DENIED_BY_SCOPE",
    "MUTATING_TAG",
    "WILDCARD",
    "ScopeMiddleware",
    "WriteGateMiddleware",
]
