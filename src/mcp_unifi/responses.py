"""Adaptive tool responses: the data always in the text block, parsed alongside it.

WHAT A CLIENT GETS
------------------
Every tool in this server returns an indented JSON string. MCP revision
``2025-06-18`` added ``structuredContent`` to ``CallToolResult``: a place to
put the same data as a parsed object. For a client that negotiated that
revision this middleware sends:

* ``content``: the full JSON text, exactly as the tool returned it.
* ``structuredContent``: the same payload, parsed, so a host that renders or
  queries structured data does not have to re-parse a string.

That is the shape the MCP specification asks for: a tool that returns
structured content should also return the serialized JSON in a text block,
because a host is free to hand the model only the text. Claude Desktop and
most bridged or proxied setups do exactly that.

Clients that negotiated an older revision, or that cannot be identified, get
the tool's result untouched.

COMPACT MODE (OPT-IN)
---------------------
A list tool's JSON can run to thousands of tokens. A host that feeds
``structuredContent`` to the model pays for the payload twice when the text
block carries it too. For those deployments ``MCP_UNIFI_COMPACT_RESPONSES=true``
replaces the text block with a bounded summary (capped hard at
:data:`MAX_COMPACT_TEXT_CHARS`) and leaves the data in ``structuredContent``
only.

Compact mode was the default from 0.19.0 until issue #226: on a host that
shows the model only the text block, every read tool answered "returned 10
record(s). Full result is in structuredContent." and nothing else. The
negotiated revision says what the client *library* can parse; it says nothing
about what the *host* shows the model, and no handshake field does. Guessing
wrong in one direction costs tokens, in the other it loses the data, so the
default is the one that cannot lose data and the saving is the operator's
choice.

WHY MIDDLEWARE AND NOT A RETURN-TYPE CHANGE
-------------------------------------------
Changing every tool signature from ``-> str`` to a result type would rewrite
every module, every test that reads a tool's return value, and the generated
tool manifest, to express one transport concern. The same reasoning that put
per-client scoping in :mod:`mcp_unifi.scoping` applies here: the tools keep
returning JSON strings, and the boundary decides how to frame them.

WHAT THE COMPACT SUMMARY DELIBERATELY DOES NOT SAY
--------------------------------------------------
The summary never invents facts. It reports the envelope's own shape (did it
error, does it need confirmation, how many records, what did verification
say) and nothing that requires interpreting domain data. If the envelope
carries a ``verification`` block that failed, that goes in the summary
verbatim, because a silently-failed write is exactly the thing a caller must
not miss while skimming.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from fastmcp.server.middleware.middleware import (
    CallNext,
    Middleware,
    MiddlewareContext,
)
from fastmcp.tools import Tool, ToolResult
from mcp import types as mt

logger = logging.getLogger("mcp_unifi.responses")

#: MCP revision that introduced ``structuredContent`` on tool results.
#: Revisions are date strings and sort lexicographically, so a plain string
#: comparison is a correct "at least this revision" test.
STRUCTURED_CONTENT_REVISION = "2025-06-18"

#: Hard ceiling on the compact summary. A summary that grows without bound is
#: just the original payload with extra steps.
MAX_COMPACT_TEXT_CHARS = 2000

#: Envelope keys holding a record count, in the order they are preferred.
_COUNT_KEYS = ("count", "returned_count", "total_count")


def supports_structured_content(protocol_version: str | None) -> bool:
    """True when a client negotiated MCP ``2025-06-18`` or later.

    ``None`` (client revision unknown) is treated as unsupported. Guessing
    high would silently truncate the payload for a client that cannot read
    ``structuredContent``, which is data loss; guessing low only costs tokens.
    """
    if not protocol_version:
        return False
    return protocol_version >= STRUCTURED_CONTENT_REVISION


def compact_content_text(payload: Any, *, tool_name: str) -> str:
    """Build the bounded summary that replaces the full JSON text block.

    Reports the envelope's shape only — never an interpretation of the
    domain data. See the module docstring for why.
    """
    parts: list[str] = []

    if isinstance(payload, list):
        parts.append(f"{tool_name} returned {len(payload)} record(s).")
    elif isinstance(payload, dict):
        parts.append(_describe_dict(payload, tool_name))
        for key in _COUNT_KEYS:
            value = payload.get(key)
            if isinstance(value, int):
                parts.append(f"{key}={value}.")
                break
        verification = payload.get("verification")
        if isinstance(verification, dict):
            summary = verification.get("verification_summary")
            if isinstance(summary, str) and summary.strip():
                parts.append(summary.strip())
    else:
        parts.append(f"{tool_name} completed.")

    parts.append("Full result is in structuredContent.")
    return " ".join(parts)[:MAX_COMPACT_TEXT_CHARS]


def _describe_dict(payload: dict[str, Any], tool_name: str) -> str:
    """One clause describing what kind of envelope this is."""
    error = payload.get("error")
    if error:
        text = str(error).strip()
        # Controller errors arrive with and without terminal punctuation;
        # the summary reads as one sentence either way.
        if text and text[-1] not in ".!?":
            text += "."
        return f"{tool_name} failed: {text}"
    if payload.get("preview") is True:
        return f"{tool_name} returned a preview; confirm the token to apply it."
    if payload.get("dry_run") is True:
        return f"{tool_name} previewed the change; nothing was applied."
    if payload.get("deleted") is True:
        return f"{tool_name} deleted the resource."
    return f"{tool_name} completed."


def _is_autowrapped_schema(schema: Any) -> bool:
    """True for the output schema FastMCP synthesises from ``-> str``.

    Shape: ``{"type": "object", "properties": {"result": {"type": "string"}},
    "required": ["result"], "x-fastmcp-wrap-result": True}``. Matched on the
    marker plus the single string property so a hand-written schema that
    happens to have one ``result`` field is not mistaken for it.
    """
    if not isinstance(schema, dict):
        return False
    if not schema.get("x-fastmcp-wrap-result"):
        return False
    properties = schema.get("properties")
    return (
        isinstance(properties, dict)
        and set(properties) == {"result"}
        and properties["result"].get("type") == "string"
    )


def _is_autowrapped_string(structured: Any) -> bool:
    """True for FastMCP's auto-derived ``structuredContent`` on a ``str`` tool.

    Every tool here is annotated ``-> str``, so FastMCP synthesises an output
    schema of ``{"result": "string"}`` and fills it with the raw JSON text.
    The result is the payload *double-encoded*: the same bytes in the text
    block and again as a JSON string inside ``structuredContent``, costing
    roughly twice the tokens instead of saving any.

    That is not structured data a client can use, so this middleware treats
    it as absent and replaces it with the parsed object. Real
    ``structuredContent`` set deliberately by a tool is left alone.
    """
    return (
        isinstance(structured, dict)
        and set(structured) == {"result"}
        and isinstance(structured["result"], str)
    )


def _structured_payload(result: ToolResult) -> Any | None:
    """Parse a tool's JSON text block back into an object, or ``None``.

    Returns ``None`` for anything this middleware should not touch: a result
    carrying genuine ``structured_content``, a multi-block result, a non-text
    block, or text that is not JSON. In every one of those cases the original
    result passes through untouched.
    """
    structured = result.structured_content
    if structured is not None and not _is_autowrapped_string(structured):
        return None
    blocks = result.content
    if not isinstance(blocks, list) or len(blocks) != 1:
        return None
    block = blocks[0]
    if not isinstance(block, mt.TextContent):
        return None
    try:
        return json.loads(block.text)
    except (json.JSONDecodeError, ValueError):
        return None


class AdaptiveResponseMiddleware(Middleware):
    """Add parsed ``structuredContent`` to the full JSON text for new clients.

    Args:
        compact: When ``True``, a client that negotiated ``2025-06-18`` or
            later gets a bounded summary as the text block and the data in
            ``structuredContent`` only. Off by default: a host that shows the
            model only the text block would see a record count and no
            records (issue #226).
        force_full_text: When ``True``, every client gets the tool's result
            exactly as the tool returned it, with no ``structuredContent``
            substitution and the synthesised output schema left in place.
            Wins over ``compact``.
    """

    def __init__(self, *, compact: bool = False, force_full_text: bool = False) -> None:
        self._compact = compact
        self._force_full_text = force_full_text

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        """Drop the synthesised ``{"result": "string"}`` output schema.

        That schema is an artifact of the ``-> str`` annotation, not a
        contract: it says every tool returns "a string", which tells a client
        nothing and is false about the shape of the data. Worse, a client that
        receives it validates ``structuredContent`` against it and rejects the
        parsed object this middleware substitutes.

        Advertising no output schema is both more accurate and what lets the
        substitution through. Tools that declare a real schema keep it.
        """
        tools = await call_next(context)
        if self._force_full_text:
            return tools
        return [
            tool.model_copy(update={"output_schema": None})
            if _is_autowrapped_schema(tool.output_schema)
            else tool
            for tool in tools
        ]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        result = await call_next(context)
        if self._force_full_text:
            return result
        if not supports_structured_content(_negotiated_revision(context)):
            return result

        payload = _structured_payload(result)
        if payload is None:
            return result

        # structuredContent must be a JSON object per the MCP schema, so a
        # list payload is wrapped rather than sent bare.
        structured = payload if isinstance(payload, dict) else {"result": payload}
        # The text block is the only channel every host is guaranteed to show
        # the model, so by default it keeps the tool's own JSON, byte for byte.
        content: list[mt.ContentBlock] = result.content
        if self._compact:
            summary = compact_content_text(payload, tool_name=context.message.name)
            content = [mt.TextContent(type="text", text=summary)]
        return ToolResult(
            content=content,
            structured_content=structured,
            meta=result.meta,
            is_error=result.is_error,
        )


def _negotiated_revision(context: MiddlewareContext[Any]) -> str | None:
    """Return the MCP revision this client negotiated, or ``None``.

    Never raises. An unreadable session means an unknown client, and an
    unknown client is treated as an old one by
    :func:`supports_structured_content`.
    """
    try:
        fastmcp_context = context.fastmcp_context
        if fastmcp_context is None:
            return None
        params = fastmcp_context.session.client_params
        if params is None:
            return None
        version = getattr(params, "protocol_version", None) or getattr(
            params, "protocolVersion", None
        )
    except Exception:
        return None
    return version if isinstance(version, str) else None


__all__ = [
    "MAX_COMPACT_TEXT_CHARS",
    "STRUCTURED_CONTENT_REVISION",
    "AdaptiveResponseMiddleware",
    "compact_content_text",
    "supports_structured_content",
]
