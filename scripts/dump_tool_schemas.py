"""Dump every MCP tool's name + description + input schema to JSON.

Used by the Step 3 schema-diff verification: snapshot the tool surface
pre-refactor and post-refactor, then diff. The only allowed change per tool
is the addition of the new ``controller`` parameter (default ``"default"``).

Usage:
    python scripts/dump_tool_schemas.py > scripts/post.json
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

# Stub mode for a deterministic registry.
os.environ.setdefault("STUB_MODE", "true")

from mcp_unifi.config import Settings
from mcp_unifi.server import build_server


def _serialise_tool(tool: Any) -> dict[str, Any]:
    """Coerce a FastMCP Tool into a stable JSON-friendly shape."""
    schema: Any
    raw_schema = getattr(tool, "parameters", None) or getattr(tool, "input_schema", None)
    if raw_schema is None:
        schema = None
    elif hasattr(raw_schema, "model_dump"):
        schema = raw_schema.model_dump()
    elif isinstance(raw_schema, dict):
        schema = raw_schema
    else:
        schema = json.loads(json.dumps(raw_schema, default=str))
    return {
        "name": getattr(tool, "name", None) or getattr(tool, "key", "<unknown>"),
        "description": (getattr(tool, "description", "") or "").strip(),
        "input_schema": schema,
    }


async def _collect() -> list[dict[str, Any]]:
    settings = Settings(stub_mode=True, log_format="text")
    server = build_server(settings)
    tools_obj = await server.list_tools()
    tools_iter = tools_obj.values() if isinstance(tools_obj, dict) else tools_obj
    out = [_serialise_tool(t) for t in tools_iter]
    out.sort(key=lambda t: t["name"])
    return out


def main() -> None:
    out = asyncio.run(_collect())
    json.dump(out, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
