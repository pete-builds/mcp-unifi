"""HTTP transport authentication (v0.9.0+).

Covers:

* Settings parses ``MCP_UNIFI_AUTH_TOKENS`` into the StaticTokenVerifier-shape
  dict for both bare and named (``client_id:token``) entries.
* ``build_server`` refuses to construct an HTTP transport without tokens when
  ``auth_required=True``.
* ``build_server`` issues a warning (but boots) when ``auth_required=False``.
* Stdio transport is exempt — no tokens needed, no auth provider wired.
* When tokens are present, FastMCP receives a ``StaticTokenVerifier`` with
  matching client_ids.
* The ``@audited`` decorator carries through ``client_id=None`` when no auth
  context is active (the default for direct ``call_tool`` invocations).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from mcp_unifi.audit import AuditLog, FileSink, set_audit_log
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.server import _build_auth_provider, build_server

# ---------------------------------------------------------------------------
# Settings: token parsing
# ---------------------------------------------------------------------------


def test_auth_token_map_empty_when_unset() -> None:
    s = Settings(stub_mode=True, auth_required=False)
    assert s.auth_token_map == {}


def test_auth_token_map_parses_bare_tokens() -> None:
    s = Settings(stub_mode=True, auth_required=False, auth_tokens="tok-aaa,tok-bbb")
    tm = s.auth_token_map
    assert tm == {
        "tok-aaa": {"client_id": "client-0", "scopes": []},
        "tok-bbb": {"client_id": "client-1", "scopes": []},
    }


def test_auth_token_map_parses_named_tokens() -> None:
    s = Settings(
        stub_mode=True,
        auth_required=False,
        auth_tokens="claude:tok-aaa,n8n:tok-bbb",
    )
    tm = s.auth_token_map
    assert tm["tok-aaa"]["client_id"] == "claude"
    assert tm["tok-bbb"]["client_id"] == "n8n"


def test_auth_token_map_tolerates_whitespace_and_blank_entries() -> None:
    s = Settings(
        stub_mode=True,
        auth_required=False,
        auth_tokens="  claude : tok-aaa , , n8n:tok-bbb  ",
    )
    tm = s.auth_token_map
    assert {meta["client_id"] for meta in tm.values()} == {"claude", "n8n"}


def test_auth_token_map_rejects_duplicate_tokens() -> None:
    s = Settings(
        stub_mode=True,
        auth_required=False,
        auth_tokens="claude:dup,n8n:dup",
    )
    with pytest.raises(ValueError, match="reuses a token"):
        _ = s.auth_token_map


def test_auth_token_map_rejects_empty_token_value() -> None:
    s = Settings(stub_mode=True, auth_required=False, auth_tokens="claude:")
    with pytest.raises(ValueError, match="missing a token value"):
        _ = s.auth_token_map


# ---------------------------------------------------------------------------
# build_server: secure-by-default gate
# ---------------------------------------------------------------------------


def test_http_transport_refuses_to_start_without_tokens(stub_state: StubState) -> None:
    s = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="streamable-http",
        auth_required=True,
        auth_tokens="",
    )
    with pytest.raises(ValueError, match="MCP_UNIFI_AUTH_TOKENS"):
        build_server(s, stub=stub_state)


def test_http_transport_opt_out_warns_but_boots(
    stub_state: StubState, caplog: pytest.LogCaptureFixture
) -> None:
    s = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="streamable-http",
        auth_required=False,
        auth_tokens="",
    )
    with caplog.at_level(logging.WARNING, logger="mcp_unifi.server"):
        server = build_server(s, stub=stub_state)
    assert isinstance(server, FastMCP)
    assert any("WITHOUT authentication" in rec.message for rec in caplog.records)


def test_http_transport_with_tokens_wires_static_verifier(stub_state: StubState) -> None:
    s = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="streamable-http",
        auth_required=True,
        auth_tokens="claude:tok-aaa",
    )
    provider = _build_auth_provider(s)
    assert isinstance(provider, StaticTokenVerifier)
    assert "tok-aaa" in provider.tokens
    assert provider.tokens["tok-aaa"]["client_id"] == "claude"


def test_stdio_transport_skips_auth_even_without_tokens(stub_state: StubState) -> None:
    s = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=True,  # ignored on stdio
        auth_tokens="",
    )
    assert _build_auth_provider(s) is None
    server = build_server(s, stub=stub_state)
    assert isinstance(server, FastMCP)


# ---------------------------------------------------------------------------
# Audit log carries client_id (or None when no auth context)
# ---------------------------------------------------------------------------


def _text(result: Any) -> str:
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


async def test_audit_records_none_client_id_outside_auth_context(
    stub_state: StubState, tmp_path: Path
) -> None:
    """Direct ``call_tool`` bypasses HTTP/auth; client_id should be None.

    This also confirms the field is present in the envelope (default None on
    the dataclass), so older replay tools that don't know about ``client_id``
    keep parsing the JSON cleanly.
    """
    log_path = tmp_path / "audit.jsonl"
    sink = FileSink(log_path)
    set_audit_log(AuditLog(sink=sink))

    s = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
    )
    server = build_server(s, stub=stub_state)

    await _call(server, "list_networks")

    events = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    assert len(events) == 1
    assert "client_id" in events[0]
    assert events[0]["client_id"] is None
