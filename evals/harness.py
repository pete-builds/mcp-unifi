"""Stub-backed server harness shared by every eval class.

One context manager builds a fully-registered server (network + protect +
access), pins the audit log at a temporary JSONL file so records can be read
back and asserted on, and hands out an in-process MCP client.

Why an in-process ``fastmcp.Client`` rather than calling ``server.call_tool``
directly: the two controls these evals grade both live in **middleware**
(:class:`mcp_unifi.scoping.WriteGateMiddleware` and ``ScopeMiddleware``). A
direct call path that skipped the middleware would grade a stack the real
caller never uses, and would report a passing refusal score for a gate that
was never invoked.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastmcp import Client, FastMCP

from mcp_unifi import audit
from mcp_unifi.audit import AuditLog, FileSink
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules.network._pending import reset_pending_actions
from mcp_unifi.server import build_server

#: Every module registered, so the tool-selection class sees the whole surface
#: and the refusal class covers mutating tools outside Network.
ALL_MODULES = "network,protect,access"

MODULES_ENV = "MCP_UNIFI_MODULES_ENABLED"


class LiveControllerRefusedError(RuntimeError):
    """Raised if the harness is ever asked to build a non-stub server.

    Defensive only. The harness never passes ``stub_mode=False``; this exists
    so a future edit that tries to point the evals at a real controller fails
    loudly at the one place that could have allowed it.
    """


@dataclass(slots=True)
class HarnessSession:
    """A live in-process MCP session plus the state and audit log behind it."""

    client: Client[Any]
    server: FastMCP
    stub: StubState
    audit_path: Path
    readonly: bool

    def audit_records(self) -> list[dict[str, Any]]:
        """Return every audit record written so far, oldest first."""
        if not self.audit_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def records_for(self, tool: str) -> list[dict[str, Any]]:
        """Return the audit records whose ``tool`` field matches ``tool``."""
        return [r for r in self.audit_records() if r.get("tool") == tool]

    def network_names(self) -> set[str]:
        """Names currently present in the stub controller's network list.

        Used as the ground truth for "did the refusal actually prevent the
        change", which is the half of a write gate that a response-body
        assertion alone cannot prove.
        """
        return {str(n.get("name")) for n in self.stub.networks}


@asynccontextmanager
async def eval_server(
    *,
    readonly: bool,
    modules: str = ALL_MODULES,
) -> AsyncIterator[HarnessSession]:
    """Yield a :class:`HarnessSession` against a fresh stub controller.

    Args:
        readonly: Sets ``MCP_UNIFI_READONLY``. True installs
            :class:`~mcp_unifi.scoping.WriteGateMiddleware`.
        modules: CSV module list, defaulting to all three.
    """
    previous_modules = os.environ.get(MODULES_ENV)
    os.environ[MODULES_ENV] = modules
    tmpdir = tempfile.TemporaryDirectory(prefix="mcp-unifi-evals-")
    audit_path = Path(tmpdir.name) / "audit.jsonl"
    audit.set_audit_log(AuditLog(FileSink(audit_path)))
    reset_pending_actions()

    settings = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
        readonly=readonly,
    )
    if not settings.stub_mode:
        raise LiveControllerRefusedError(
            "evals refuse to run against a non-stub controller; stub_mode resolved False"
        )

    stub = StubState()
    server = build_server(settings, stub=stub)
    try:
        async with Client(server) as client:
            yield HarnessSession(
                client=client,
                server=server,
                stub=stub,
                audit_path=audit_path,
                readonly=readonly,
            )
    finally:
        audit.set_audit_log(None)
        reset_pending_actions()
        if previous_modules is None:
            os.environ.pop(MODULES_ENV, None)
        else:
            os.environ[MODULES_ENV] = previous_modules
        tmpdir.cleanup()


def payload_of(result: Any) -> Any:
    """Decode an MCP tool result into the JSON payload the tool returned.

    Tools in this server return JSON strings. ``structured_content`` carries
    the parsed form when the adaptive-response middleware provides it; the
    text block is the fallback.
    """
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        # FastMCP wraps a non-object top-level payload under "result".
        return structured.get("result", structured)
    content = getattr(result, "content", None) or []
    if content:
        text = getattr(content[0], "text", None)
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return None


__all__ = [
    "ALL_MODULES",
    "HarnessSession",
    "LiveControllerRefusedError",
    "eval_server",
    "payload_of",
]
