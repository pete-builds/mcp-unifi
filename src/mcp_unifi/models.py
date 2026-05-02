"""Shared types for mcp-unifi.

These are runtime-friendly aliases used across the server and clients.
"""

from __future__ import annotations

from typing import Any, TypedDict

# UniFi controller payloads are loosely-typed dicts. We keep a single alias so
# the intent is explicit at call sites without inventing a heavyweight schema.
UniFiRecord = dict[str, Any]


class ToolError(TypedDict):
    """Shape of the structured error returned by every MCP tool on failure.

    Returned as a JSON string by the server tools so Claude Code can render the
    error rather than triggering an MCP transport-level fault.
    """

    error: str
    stub_mode: bool
