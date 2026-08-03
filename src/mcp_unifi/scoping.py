"""Per-client tool scoping for the HTTP transport.

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
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware.middleware import (
    CallNext,
    Middleware,
    MiddlewareContext,
)
from fastmcp.tools.tool import Tool
from mcp import types as mt

logger = logging.getLogger("mcp_unifi.scoping")

WILDCARD = "*"


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
                # brute-forcing names and reading the denial message.
                raise ToolError(f"Tool {tool_name!r} is not available to this client.")
        return await call_next(context)

    def _allowed_modules_for_current_request(self) -> set[str]:
        """Look up the current caller's allowed module set.

        Falls back to :data:`WILDCARD` on stdio (no auth), on tokens without
        a scope entry, and on any FastMCP dependency surface change — the
        middleware must fail open on infrastructure hiccups, not lock the
        server. The upstream auth provider is what gates access; scoping is
        a layer on top and must not become the single point of failure.
        """
        client_id = _current_client_id()
        if client_id is None:
            return {WILDCARD}
        return self._client_scopes.get(client_id, {WILDCARD})


def _current_client_id() -> str | None:
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
    except Exception:
        return None
    return token.client_id if token is not None else None


def _tool_modules(tool: Tool) -> set[str]:
    return set(getattr(tool, "tags", None) or set())


async def _resolve_tool_modules(
    context: MiddlewareContext[mt.CallToolRequestParams], tool_name: str
) -> set[str]:
    """Return the module tag set for ``tool_name``, or empty set if unknown.

    Uses the request's FastMCP context to look up the registered tool
    without touching internal FastMCP state.
    """
    fastmcp_ctx = context.fastmcp_context
    if fastmcp_ctx is None:
        return set()
    try:
        tool = await fastmcp_ctx.fastmcp.get_tool(tool_name)
    except Exception:
        return set()
    return _tool_modules(tool)


__all__ = ["WILDCARD", "ScopeMiddleware"]
