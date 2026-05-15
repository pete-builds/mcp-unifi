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

    @audited("synthetic_tool")
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
