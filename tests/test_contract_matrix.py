"""Live-registry contract checks for discovery and monitor-mode denial."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, cast

import pytest

from mcp_unifi.config import Settings
from mcp_unifi.scoping import MUTATING_TAG
from mcp_unifi.server import build_server

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_tool_manifest.py"

_spec = importlib.util.spec_from_file_location("_gen_tool_manifest_contract", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
generate_tool_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_tool_manifest)


def _settings(*, readonly: bool) -> Settings:
    return Settings(
        stub_mode=True,
        operation_mode="legacy",
        readonly=readonly,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
    )


def _payload(result: Any) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(result.content[0].text))


@pytest.mark.asyncio
async def test_discovery_snapshot_equals_canonical_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The checked-in manifest exactly describes the live registered surface."""
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")
    server = build_server(_settings(readonly=False))
    discovered = {tool.name: tool for tool in await server.list_tools()}
    manifest = json.loads(
        (REPO_ROOT / "docs/site/src/data/tool-manifest.json").read_text(encoding="utf-8")
    )
    entries = {tool["name"]: tool for tool in manifest["tools"]}
    assert set(discovered) == set(entries)
    assert manifest["tool_count"] == len(discovered)

    # Keep this projection in one place with the manifest generator so drift
    # in schemas, descriptions, module attribution, runtime support, or
    # sensitive-field policy cannot pass as a name-only discovery match.
    expected = {
        name: generate_tool_manifest._serialise_tool(tool) for name, tool in discovered.items()
    }
    assert entries == expected


@pytest.mark.asyncio
async def test_monitor_mode_direct_mutation_matrix_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every classified mutation is hidden and refused before its body runs."""
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")
    open_server = build_server(_settings(readonly=False))
    readonly_server = build_server(_settings(readonly=True))
    open_tools = await open_server.list_tools()
    mutations = {tool.name for tool in open_tools if MUTATING_TAG in tool.tags}
    open_names = {tool.name for tool in open_tools}
    readonly_names = {tool.name for tool in await readonly_server.list_tools()}
    assert mutations <= open_names
    assert mutations.isdisjoint(readonly_names)
    for name in sorted(mutations):
        payload = _payload(await readonly_server.call_tool(name, {}))
        assert "read-only mode" in payload["error"]
        assert payload["stub_mode"] is True
