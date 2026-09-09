"""Tool-level audit emission tests.

These exercise the ``@audited`` decorator wired into every Network tool. The
unit tests in :mod:`tests.test_audit` cover the audit module in isolation;
this file verifies the integration:

* Read-only and destructive tools both emit an audit event per call.
* Dry-run calls emit an event whose ``result`` carries ``dry_run: true``.
* Sensitive arg keys (``passphrase``, ``api_key``, etc.) are scrubbed.
* When a tool body raises, the decorator records ``success=false`` with the
  error string and re-raises.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.audit import REDACTED, AuditLog, FileSink, set_audit_log
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules._audit import audited
from mcp_unifi.server import build_server


def _text(result: Any) -> str:
    return result.content[0].text


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw = await server.call_tool(name, args or {})
    return json.loads(_text(raw))


@pytest.fixture
def file_sink_audit_log(tmp_path: Path) -> tuple[Path, AuditLog]:
    """Pin the singleton at a per-test FileSink and yield (path, log)."""
    log_path = tmp_path / "tool-audit.jsonl"
    sink = FileSink(log_path)
    log = AuditLog(sink=sink)
    set_audit_log(log)
    return log_path, log


@pytest.fixture
def stub_server(stub_settings: Settings, stub_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=stub_state)


def _read_events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Every tool emits one event per call
# ---------------------------------------------------------------------------


async def test_read_only_tool_emits_one_audit_event(
    stub_server: FastMCP,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    log_path, _ = file_sink_audit_log
    await _call(stub_server, "list_networks")

    events = _read_events(log_path)
    assert len(events) == 1
    ev = events[0]
    assert ev["tool"] == "list_networks"
    assert ev["controller"] == "default"
    assert ev["success"] is True
    assert isinstance(ev["latency_ms"], float | int)
    assert ev["error"] is None


async def test_destructive_tool_real_apply_emits_event(
    stub_server: FastMCP,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    log_path, _ = file_sink_audit_log
    await _call(
        stub_server,
        "create_vlan",
        {"name": "Office", "vlan_id": 51, "subnet": "10.0.51.0/24"},
    )

    events = _read_events(log_path)
    assert len(events) == 1
    ev = events[0]
    assert ev["tool"] == "create_vlan"
    assert ev["success"] is True
    # Real apply: result should NOT be flagged as dry_run.
    result = ev["result"]
    assert isinstance(result, dict)
    assert result.get("dry_run") is not True


async def test_destructive_tool_dry_run_emits_event_marked_dry_run(
    stub_server: FastMCP,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    log_path, _ = file_sink_audit_log
    await _call(
        stub_server,
        "create_vlan",
        {
            "name": "Office",
            "vlan_id": 51,
            "subnet": "10.0.51.0/24",
            "dry_run": True,
        },
    )

    events = _read_events(log_path)
    assert len(events) == 1
    ev = events[0]
    assert ev["tool"] == "create_vlan"
    assert ev["success"] is True
    assert ev["args"]["dry_run"] is True
    # Result envelope is the dry-run preview itself.
    assert ev["result"]["dry_run"] is True
    assert "would_create" in ev["result"]


# ---------------------------------------------------------------------------
# Secret scrubbing
# ---------------------------------------------------------------------------


async def test_create_wlan_passphrase_redacted_in_audit(
    stub_server: FastMCP,
    stub_state: StubState,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    log_path, _ = file_sink_audit_log
    net_id = stub_state.list_networks()[0]["_id"]
    secret = "ohno-do-not-leak-this-passphrase"
    await _call(
        stub_server,
        "create_wlan",
        {"name": "WhisperNet", "passphrase": secret, "network_id": net_id},
    )

    raw = log_path.read_text()
    assert secret not in raw, "raw passphrase leaked into audit log"
    events = _read_events(log_path)
    ev = events[0]
    assert ev["args"]["passphrase"] == REDACTED


async def test_create_wlan_dry_run_passphrase_redacted_in_audit(
    stub_server: FastMCP,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    """Even on dry-run the passphrase must be redacted in the audit envelope.

    The result block carries ``would_create.wlan.x_passphrase`` which the
    scrubber's substring match catches via the ``passphrase`` pattern.
    """
    log_path, _ = file_sink_audit_log
    secret = "another-secret-that-must-not-leak"
    await _call(
        stub_server,
        "create_wlan",
        {
            "name": "WhisperNet",
            "passphrase": secret,
            "network_id": "net-x",
            "dry_run": True,
        },
    )

    raw = log_path.read_text()
    assert secret not in raw


# ---------------------------------------------------------------------------
# Failure path
# ---------------------------------------------------------------------------


async def test_audit_records_failure_and_reraises(
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    """A tool that raises must produce a success=false audit entry and re-raise."""
    log_path, _ = file_sink_audit_log

    # ``mutates`` is required (v0.21.0 write gate); this synthetic tool is
    # never registered with FastMCP, so the value only has to be declared.
    @audited("synthetic_tool", mutates=True)
    async def boom(controller: str = "default", thing: str = "x") -> str:
        raise RuntimeError("explosive disassembly")

    with pytest.raises(RuntimeError, match="explosive disassembly"):
        await boom(thing="y")

    events = _read_events(log_path)
    assert len(events) == 1
    ev = events[0]
    assert ev["tool"] == "synthetic_tool"
    assert ev["success"] is False
    assert ev["error"] == "explosive disassembly"
    assert ev["result"] is None
    assert ev["args"]["thing"] == "y"


# ---------------------------------------------------------------------------
# Many tools => many events, in order
# ---------------------------------------------------------------------------


async def test_sequence_of_tool_calls_produces_one_event_per_call(
    stub_server: FastMCP,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    log_path, _ = file_sink_audit_log
    await _call(stub_server, "list_networks")
    await _call(stub_server, "list_wlans")
    await _call(
        stub_server,
        "create_vlan",
        {"name": "Office", "vlan_id": 52, "subnet": "10.0.52.0/24"},
    )
    await _call(
        stub_server,
        "delete_vlan",
        {"network_id": "ghost", "dry_run": True},
    )

    events = _read_events(log_path)
    tools = [e["tool"] for e in events]
    assert tools == ["list_networks", "list_wlans", "create_vlan", "delete_vlan"]
    # The dry-run call must be flagged distinctly.
    assert events[3]["args"]["dry_run"] is True
    assert events[3]["result"]["dry_run"] is True


# ---------------------------------------------------------------------------
# Confirm events name their controller and link to their preview
# (review 2026-09-08, finding 5)
# ---------------------------------------------------------------------------


async def test_annotate_audit_overrides_controller_and_adds_args(
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    from mcp_unifi.modules._audit import annotate_audit

    log_path, _ = file_sink_audit_log

    @audited("synthetic_annotated_tool", mutates=True)
    async def synthetic_annotated_tool(token: str) -> str:
        annotate_audit(controller="office", preview_id="3f1a2b4c", action="delete_vlan")
        return json.dumps({"deleted": True})

    await synthetic_annotated_tool(token="3f1a2b4c-secret-rest")

    ev = _read_events(log_path)[0]
    assert ev["controller"] == "office"
    assert ev["args"]["preview_id"] == "3f1a2b4c"
    assert ev["args"]["action"] == "delete_vlan"
    assert ev["args"]["token"] == REDACTED


async def test_annotate_audit_survives_a_raising_tool(
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    from mcp_unifi.modules._audit import annotate_audit

    log_path, _ = file_sink_audit_log

    @audited("synthetic_annotated_raiser", mutates=True)
    async def synthetic_annotated_raiser() -> str:
        annotate_audit(controller="office")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await synthetic_annotated_raiser()

    ev = _read_events(log_path)[0]
    assert ev["success"] is False
    assert ev["controller"] == "office"


async def test_confirm_event_links_to_preview_without_the_token(
    stub_server: FastMCP,
    file_sink_audit_log: tuple[Path, AuditLog],
) -> None:
    log_path, _ = file_sink_audit_log
    created = await _call(
        stub_server, "create_vlan", {"name": "Doomed", "vlan_id": 72, "subnet": "10.0.72.0/24"}
    )
    preview = await _call(stub_server, "delete_vlan", {"network_id": created["_id"]})
    assert preview["preview_id"] == preview["token"][:8]
    await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})

    events = {ev["tool"]: ev for ev in _read_events(log_path)}
    preview_ev = events["delete_vlan"]
    confirm_ev = events["confirm_destructive_action"]
    # The token stays a secret in both halves...
    assert preview_ev["result"]["token"] == REDACTED
    assert confirm_ev["args"]["token"] == REDACTED
    # ...and preview_id is the link between them.
    assert preview_ev["result"]["preview_id"] == preview["preview_id"]
    assert confirm_ev["args"]["preview_id"] == preview["preview_id"]
    assert confirm_ev["args"]["action"] == "delete_vlan"
    assert confirm_ev["controller"] == preview_ev["controller"]
    assert confirm_ev["result"]["deleted"] is True
