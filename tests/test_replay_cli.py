"""Tests for ``mcp_unifi.cli.replay``.

Smoke-level coverage: the CLI parses args, refuses real-mode without the
two safety flags, replays stub events end-to-end against an in-process
FastMCP server, and surfaces failures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_unifi.audit import AuditEvent
from mcp_unifi.cli import replay as replay_mod


class _StubServer:
    def __init__(self, *, fail_on: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._fail_on = fail_on or set()

    async def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        self.calls.append((name, args))
        if name in self._fail_on:
            raise RuntimeError(f"boom on {name}")
        return {"ok": True, "tool": name}


def _event(tool: str, controller: str = "default", **args: Any) -> AuditEvent:
    return AuditEvent(
        ts="2026-05-14T00:00:00.000Z",
        controller=controller,
        tool=tool,
        args=args,
        result=None,
        success=True,
        latency_ms=1.0,
    )


async def test_replay_stub_runs_every_event() -> None:
    server = _StubServer()
    events = [_event("list_devices"), _event("list_networks")]
    results = await replay_mod.replay_events(
        events,
        stub_mode=True,
        target_controller=None,
        i_mean_it=False,
        server=server,
    )
    assert [r.tool for r in results] == ["list_devices", "list_networks"]
    assert all(r.success for r in results)
    assert [c[0] for c in server.calls] == ["list_devices", "list_networks"]


async def test_replay_real_mode_requires_both_flags() -> None:
    server = _StubServer()
    with pytest.raises(RuntimeError, match="--target-controller"):
        await replay_mod.replay_events(
            [_event("list_devices")],
            stub_mode=False,
            target_controller=None,
            i_mean_it=False,
            server=server,
        )


async def test_replay_real_mode_filters_by_controller() -> None:
    server = _StubServer()
    events = [
        _event("list_devices", controller="home"),
        _event("list_networks", controller="office"),
    ]
    results = await replay_mod.replay_events(
        events,
        stub_mode=False,
        target_controller="home",
        i_mean_it=True,
        server=server,
    )
    assert results[0].success and not results[0].skipped
    assert results[1].skipped is True
    assert "office" in (results[1].skip_reason or "")
    # Only the home event was actually invoked.
    assert [c[0] for c in server.calls] == ["list_devices"]


async def test_replay_skips_refused_events() -> None:
    """A refused call was never made; replaying it would make it for real.

    The write gate and the scope gate now write their refusals into the same
    log replay consumes. Re-issuing one against a live controller would take
    an action the operator's own policy denied, so denied events are skipped
    the same way an off-target controller is.
    """
    server = _StubServer()
    denied = _event("delete_vlan", network_id="x")
    denied.success = False
    denied.denied_by = "readonly"
    results = await replay_mod.replay_events(
        [_event("list_devices"), denied],
        stub_mode=True,
        target_controller=None,
        i_mean_it=False,
        server=server,
    )
    assert results[1].skipped is True
    assert "readonly" in (results[1].skip_reason or "")
    assert [c[0] for c in server.calls] == ["list_devices"]


def test_parse_jsonl_round_trips_denied_by(tmp_path: Path) -> None:
    """Replay must read the new field, and tolerate logs written without it."""
    from mcp_unifi.audit import parse_jsonl

    log = tmp_path / "audit.jsonl"
    old = {
        "ts": "2026-05-14T00:00:00.000Z",
        "controller": "default",
        "tool": "list_devices",
        "args": {},
        "result": None,
        "success": True,
        "latency_ms": 1.0,
    }
    new = dict(old, tool="delete_vlan", success=False, denied_by="scope")
    log.write_text(json.dumps(old) + "\n" + json.dumps(new) + "\n")

    events = parse_jsonl(log.read_text().splitlines())
    assert events[0].denied_by is None
    assert events[1].denied_by == "scope"


async def test_replay_captures_per_event_failures() -> None:
    server = _StubServer(fail_on={"delete_vlan"})
    events = [_event("list_devices"), _event("delete_vlan", network_id="x")]
    results = await replay_mod.replay_events(
        events,
        stub_mode=True,
        target_controller=None,
        i_mean_it=False,
        server=server,
    )
    assert results[0].success is True
    assert results[1].success is False
    assert results[1].error and "boom on delete_vlan" in results[1].error


def test_main_missing_log_file_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = replay_mod.main([str(tmp_path / "does-not-exist.jsonl")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "audit log not found" in err


def test_main_real_without_flags_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        json.dumps(
            {
                "ts": "2026-05-14T00:00:00Z",
                "controller": "default",
                "tool": "list_devices",
                "args": {},
                "result": None,
                "success": True,
                "latency_ms": 1.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    rc = replay_mod.main([str(log), "--real"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--target-controller" in err and "--i-mean-it" in err


def test_main_stub_replay_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "audit.jsonl"
    events = [
        {
            "ts": "2026-05-14T00:00:00Z",
            "controller": "default",
            "tool": "list_devices",
            "args": {},
            "result": None,
            "success": True,
            "latency_ms": 1.0,
        },
        {
            "ts": "2026-05-14T00:00:01Z",
            "controller": "default",
            "tool": "list_networks",
            "args": {},
            "result": None,
            "success": True,
            "latency_ms": 1.0,
        },
    ]
    log.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    server = _StubServer()
    monkeypatch.setattr(replay_mod, "_build_server", lambda *, stub_mode: server)

    rc = replay_mod.main([str(log)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "succeeded=2" in out
    assert "failed=0" in out
    assert [c[0] for c in server.calls] == ["list_devices", "list_networks"]


def test_main_emits_json_per_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        json.dumps(
            {
                "ts": "2026-05-14T00:00:00Z",
                "controller": "default",
                "tool": "list_devices",
                "args": {},
                "result": None,
                "success": True,
                "latency_ms": 1.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    server = _StubServer()
    monkeypatch.setattr(replay_mod, "_build_server", lambda *, stub_mode: server)

    rc = replay_mod.main([str(log), "--json"])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    payload = json.loads(out[0])
    assert payload["tool"] == "list_devices"
    assert payload["success"] is True


def test_main_returns_1_when_any_event_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        json.dumps(
            {
                "ts": "2026-05-14T00:00:00Z",
                "controller": "default",
                "tool": "delete_vlan",
                "args": {"network_id": "x"},
                "result": None,
                "success": True,
                "latency_ms": 1.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    server = _StubServer(fail_on={"delete_vlan"})
    monkeypatch.setattr(replay_mod, "_build_server", lambda *, stub_mode: server)

    rc = replay_mod.main([str(log)])
    assert rc == 1


def test_main_invalid_jsonl_returns_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text("{not json\n", encoding="utf-8")
    rc = replay_mod.main([str(log)])
    assert rc == 2
