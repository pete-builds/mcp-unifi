"""Tests for adaptive tool responses.

Two properties matter and are asserted separately:

* **No data loss.** Whatever a client can read out of the response must equal
  what the tool returned. A summary that drops a field is worse than a
  verbose response.
* **No regression for old clients.** A client that did not negotiate MCP
  ``2025-06-18`` must receive exactly the payload it received before, because
  it has nowhere else to read it from.

The end-to-end cases go through a real in-memory MCP client rather than
``server.call_tool`` so the protocol handshake actually happens — the
middleware keys off the negotiated revision, and a test that never negotiates
would pass while proving nothing.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp import Client, FastMCP

from mcp_unifi.config import Settings
from mcp_unifi.responses import (
    MAX_COMPACT_TEXT_CHARS,
    AdaptiveResponseMiddleware,
    compact_content_text,
    supports_structured_content,
)
from mcp_unifi.server import build_server

# ---------------------------------------------------------------------------
# Revision negotiation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("revision", "expected"),
    [
        ("2025-06-18", True),  # the revision that introduced structuredContent
        ("2025-11-25", True),
        ("2026-01-01", True),
        ("2025-03-26", False),
        ("2024-11-05", False),
        (None, False),  # unknown client
        ("", False),
    ],
)
def test_structured_content_support_is_a_revision_floor(
    revision: str | None, expected: bool
) -> None:
    assert supports_structured_content(revision) is expected


def test_unknown_client_is_treated_as_old_not_new() -> None:
    """Guessing high truncates for a client that cannot read the structure.

    Guessing low only costs tokens. The asymmetry is the whole argument for
    defaulting to the legacy shape.
    """
    assert supports_structured_content(None) is False


# ---------------------------------------------------------------------------
# Summary construction
# ---------------------------------------------------------------------------


def test_summary_reports_record_count_for_a_list() -> None:
    text = compact_content_text([{"a": 1}, {"a": 2}], tool_name="list_wlans")
    assert "2 record(s)" in text


def test_summary_reports_an_error() -> None:
    text = compact_content_text({"error": "network ghost not found"}, tool_name="update_vlan")
    assert "update_vlan failed: network ghost not found." in text


def test_summary_does_not_double_punctuate_an_error() -> None:
    text = compact_content_text({"error": "boom!"}, tool_name="t")
    assert "boom!." not in text


def test_summary_flags_a_pending_preview() -> None:
    text = compact_content_text({"preview": True, "token": "abc"}, tool_name="delete_vlan")
    assert "confirm the token" in text


def test_summary_flags_a_dry_run() -> None:
    text = compact_content_text({"dry_run": True}, tool_name="update_vlan")
    assert "nothing was applied" in text


def test_summary_surfaces_a_failed_verification() -> None:
    """A silently-failed write is exactly what must not be missed in a skim."""
    payload = {
        "verification": {
            "verified": False,
            "verification_summary": "Partially applied: 1 field(s) persisted, 1 dropped.",
        }
    }
    text = compact_content_text(payload, tool_name="update_vlan")
    assert "Partially applied" in text


def test_summary_is_hard_capped() -> None:
    payload = {"error": "x" * 10_000}
    text = compact_content_text(payload, tool_name="t")
    assert len(text) <= MAX_COMPACT_TEXT_CHARS


def test_summary_never_invents_domain_facts() -> None:
    """The summary describes the envelope, never the data inside it."""
    payload = [{"name": "Home", "x_passphrase": "[REDACTED]"}]
    text = compact_content_text(payload, tool_name="list_wlans")
    assert "Home" not in text


# ---------------------------------------------------------------------------
# Middleware behaviour
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, revision: str | None) -> None:
        self.client_params = (
            None if revision is None else type("P", (), {"protocolVersion": revision})()
        )


class _FakeFastMCPContext:
    def __init__(self, revision: str | None) -> None:
        self.session = _FakeSession(revision)


class _FakeContext:
    def __init__(self, revision: str | None, tool_name: str = "list_wlans") -> None:
        self.fastmcp_context = _FakeFastMCPContext(revision)
        self.message = type("M", (), {"name": tool_name})()


def _tool_result(payload: Any) -> Any:
    from fastmcp.tools.tool import ToolResult
    from mcp import types as mt

    return ToolResult(
        content=[mt.TextContent(type="text", text=json.dumps(payload, indent=2))],
        structured_content={"result": json.dumps(payload, indent=2)},
    )


async def _run(middleware: AdaptiveResponseMiddleware, revision: str | None, payload: Any) -> Any:
    async def call_next(_ctx: Any) -> Any:
        return _tool_result(payload)

    return await middleware.on_call_tool(_FakeContext(revision), call_next)


async def test_new_client_gets_summary_plus_full_structured_content() -> None:
    payload = [{"_id": "w1", "name": "Home"}]
    result = await _run(AdaptiveResponseMiddleware(), "2025-06-18", payload)
    assert result.content[0].text.startswith("list_wlans returned 1 record(s).")
    assert result.structured_content == {"result": payload}


async def test_old_client_gets_the_original_payload_untouched() -> None:
    payload = [{"_id": "w1", "name": "Home"}]
    result = await _run(AdaptiveResponseMiddleware(), "2025-03-26", payload)
    assert json.loads(result.content[0].text) == payload


async def test_force_full_text_overrides_a_capable_client() -> None:
    payload = [{"_id": "w1", "name": "Home"}]
    result = await _run(AdaptiveResponseMiddleware(force_full_text=True), "2025-11-25", payload)
    assert json.loads(result.content[0].text) == payload


async def test_non_json_text_passes_through() -> None:
    from fastmcp.tools.tool import ToolResult
    from mcp import types as mt

    async def call_next(_ctx: Any) -> Any:
        return ToolResult(content=[mt.TextContent(type="text", text="not json at all")])

    result = await AdaptiveResponseMiddleware().on_call_tool(_FakeContext("2025-11-25"), call_next)
    assert result.content[0].text == "not json at all"


async def test_genuine_structured_content_is_left_alone() -> None:
    from fastmcp.tools.tool import ToolResult
    from mcp import types as mt

    async def call_next(_ctx: Any) -> Any:
        return ToolResult(
            content=[mt.TextContent(type="text", text='{"a": 1}')],
            structured_content={"a": 1, "b": 2},
        )

    result = await AdaptiveResponseMiddleware().on_call_tool(_FakeContext("2025-11-25"), call_next)
    assert result.structured_content == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# End-to-end over a negotiated MCP session
# ---------------------------------------------------------------------------


@pytest.fixture
def stdio_server(stub_settings: Settings) -> FastMCP:
    return build_server(stub_settings.model_copy(update={"mcp_transport": "stdio"}))


async def test_end_to_end_client_reads_full_data_from_structured_content(
    stdio_server: FastMCP,
) -> None:
    """The compact text must never be the only copy of the data."""
    async with Client(stdio_server) as client:
        assert supports_structured_content(client.initialize_result.protocolVersion)
        result = await client.call_tool("list_wlans", {})

        assert "structuredContent" in result.content[0].text
        records = result.structured_content["result"]
        assert records[0]["name"] == "Home"
        # Every field the legacy response carried is still reachable.
        assert {"_id", "enabled", "security", "wlan_band"} <= set(records[0])


async def test_end_to_end_compact_text_is_much_smaller_than_the_payload(
    stdio_server: FastMCP,
) -> None:
    async with Client(stdio_server) as client:
        result = await client.call_tool("list_clients", {})
        text_chars = len(result.content[0].text)
        payload_chars = len(json.dumps(result.structured_content))
        assert text_chars < payload_chars / 4


async def test_end_to_end_verification_summary_reaches_the_text_block(
    stdio_server: FastMCP,
) -> None:
    async with Client(stdio_server) as client:
        networks = (await client.call_tool("list_networks", {})).structured_content["result"]
        result = await client.call_tool(
            "update_vlan",
            {"network_id": networks[0]["_id"], "updates": {"name": "Adaptive"}},
        )
        assert "Verified" in result.content[0].text
        assert result.structured_content["verification"]["verified"] is True


async def test_end_to_end_secrets_stay_redacted_in_both_channels(
    stdio_server: FastMCP,
) -> None:
    """Adding a second channel must not open a second leak path."""
    async with Client(stdio_server) as client:
        result = await client.call_tool("list_wlans", {})
        blob = result.content[0].text + json.dumps(result.structured_content)
        assert "[REDACTED]" in json.dumps(result.structured_content)
        assert result.structured_content["result"][0]["x_passphrase"] == "[REDACTED]"
        assert "correct-horse" not in blob


async def test_end_to_end_listed_tools_drop_the_synthetic_output_schema(
    stdio_server: FastMCP,
) -> None:
    """``{"result": "string"}`` is an artifact of ``-> str``, not a contract."""
    async with Client(stdio_server) as client:
        tools = await client.list_tools()
        listed = {t.name: t for t in tools}
        assert listed["list_wlans"].outputSchema is None
