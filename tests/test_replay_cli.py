"""Tests for ``mcp_unifi.cli.replay``.

Smoke-level coverage: the CLI parses args, refuses real-mode without the
two safety flags, replays stub events end-to-end against an in-process
FastMCP server, and surfaces failures.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

from mcp_unifi import audit
from mcp_unifi.audit import AuditEvent
from mcp_unifi.cli import replay as replay_mod
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.redaction import REDACTED
from mcp_unifi.server import build_server


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


# ---------------------------------------------------------------------------
# An error envelope is a failure, not a success (review 2026-09-08, finding 5)
# ---------------------------------------------------------------------------


class _EnvelopeServer:
    """Answers like a real tool: no exception, an ``{"error": ...}`` envelope."""

    def __init__(self, *, as_text: bool) -> None:
        self._as_text = as_text

    async def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        payload = {"error": "unknown or expired token", "stub_mode": True}
        if not self._as_text:
            return payload
        # Shaped like FastMCP's ToolResult: .content[0].text holds the JSON.
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(payload))])


@pytest.mark.parametrize("as_text", [False, True])
async def test_replay_treats_error_envelope_as_failure(as_text: bool) -> None:
    # The token is a stale value rather than the audit sentinel: an event
    # carrying ``***`` is now skipped before it reaches the server (finding
    # A2), and this test is about what happens once a call is made.
    results = await replay_mod.replay_events(
        [_event("confirm_destructive_action", token="0b7c2e1a-expired")],
        stub_mode=True,
        target_controller=None,
        i_mean_it=False,
        server=_EnvelopeServer(as_text=as_text),
    )
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error is not None
    assert "unknown or expired token" in results[0].error


# ---------------------------------------------------------------------------
# Redacted secrets are never replayed (review 2026-11, finding A2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        {"wlan_id": "w1", "updates": {"x_passphrase": REDACTED}},
        {"wlan_id": "w1", "updates": {"radius": [{"x_secret": REDACTED}]}},
        {"token": REDACTED},
    ],
    ids=["nested-dict", "nested-list", "top-level"],
)
async def test_replay_skips_an_event_whose_arguments_were_redacted(args: dict[str, Any]) -> None:
    server = _StubServer()
    results = await replay_mod.replay_events(
        [_event("update_wlan", **args)],
        stub_mode=True,
        target_controller=None,
        i_mean_it=False,
        server=server,
    )
    assert server.calls == []
    assert results[0].skipped is True
    assert results[0].success is False
    assert "redacted" in (results[0].skip_reason or "")
    assert "cannot be replayed faithfully" in (results[0].skip_reason or "")


async def test_replayed_wlan_update_never_writes_the_sentinel_passphrase(
    stub_settings: Settings, tmp_path: Path
) -> None:
    """The replay_secret shape, end to end against a spied stub.

    A real ``update_wlan`` is captured to a file sink, which scrubs the
    passphrase to ``***``. Replaying that capture used to send ``***`` as the
    new passphrase and count it a success.
    """
    state = StubState()
    patches: list[dict[str, Any]] = []
    original = state.update_wlan

    def spy(wlan_id: str, patch: dict[str, Any]) -> Any:
        patches.append(dict(patch))
        return original(wlan_id, patch)

    state.update_wlan = spy  # type: ignore[method-assign]
    capture = tmp_path / "capture.jsonl"
    audit.set_audit_log(audit.AuditLog(audit.FileSink(capture)))
    server = build_server(stub_settings, stub=state)
    wlan = state.wlans[0]
    await server.call_tool(
        "update_wlan", {"wlan_id": wlan["_id"], "updates": {"x_passphrase": "CorrectHorse9"}}
    )
    assert patches == [{"x_passphrase": "CorrectHorse9"}]

    events = audit.parse_jsonl(capture.read_text().splitlines())
    results = await replay_mod.replay_events(
        events, stub_mode=True, target_controller=None, i_mean_it=False, server=server
    )

    assert patches == [{"x_passphrase": "CorrectHorse9"}], "the backend saw a replayed write"
    assert [(r.tool, r.skipped) for r in results] == [("update_wlan", True)]


# ---------------------------------------------------------------------------
# The CLI builds its own server from a clean environment (finding A3)
# ---------------------------------------------------------------------------


def _write_log(path: Path, events: list[dict[str, Any]]) -> bytes:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path.read_bytes()


def _logged(tool: str, controller: str = "default", **args: Any) -> dict[str, Any]:
    return {
        "ts": "2026-05-14T00:00:00Z",
        "controller": controller,
        "tool": tool,
        "args": args,
        "result": None,
        "success": True,
        "latency_ms": 1.0,
    }


@pytest.fixture
def clean_replay_env(
    clean_unifi_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """No auth, sink or deployment variables, and a cwd with no ``.env``.

    The cwd matters twice: Settings reads ``.env`` from it, and the default
    audit sink is ``./audit.jsonl`` in it.
    """
    for var in (audit.ENV_SINK, audit.ENV_PATH, audit.ENV_SYSLOG_ADDRESS, "MCP_UNIFI_READONLY"):
        monkeypatch.delenv(var, raising=False)
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    audit.set_audit_log(None)
    return workdir


def test_main_stub_replay_runs_in_a_clean_environment(
    clean_replay_env: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No ``_build_server`` patch: the server is the one the CLI really builds.

    Before the fix the settings defaulted to the HTTP transport, which
    refuses to build without a bearer token, so the CLI died with a raw
    ``ValueError`` traceback in exactly the environment an operator runs it.
    """
    log = tmp_path / "input.jsonl"
    before = _write_log(
        log,
        [
            _logged("list_networks"),
            _logged("create_vlan", name="Office", vlan_id=51, subnet="10.0.51.0/24"),
        ],
    )

    rc = replay_mod.main([str(log)])

    assert rc == 0, capsys.readouterr()
    assert "succeeded=2" in capsys.readouterr().out
    assert log.read_bytes() == before
    # A stub replay is a rehearsal: nothing reaches the configured sink.
    assert not (clean_replay_env / "audit.jsonl").exists()


def test_main_stub_replay_is_not_refused_by_client_scoping(
    clean_replay_env: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With scoped tokens configured, every in-process call was refused.

    The scope middleware found no identity on an in-process call and failed
    closed, so a replay inside a scoped deployment reported every event failed.
    """
    monkeypatch.setenv("MCP_UNIFI_AUTH_TOKENS", "ops:0123abcd:protect")
    log = tmp_path / "input.jsonl"
    _write_log(log, [_logged("list_networks")])

    rc = replay_mod.main([str(log)])

    assert rc == 0, capsys.readouterr()
    assert "succeeded=1" in capsys.readouterr().out


def test_main_stub_replay_still_honours_read_only_mode(
    clean_replay_env: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("MCP_UNIFI_READONLY", "true")
    log = tmp_path / "input.jsonl"
    _write_log(
        log,
        [
            _logged("list_networks"),
            _logged("create_vlan", name="Office", vlan_id=51, subnet="10.0.51.0/24"),
        ],
    )

    rc = replay_mod.main([str(log), "--json"])

    assert rc == 1
    lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert lines[0]["success"] is True
    assert lines[1]["success"] is False
    assert "read-only mode" in lines[1]["error"]


@pytest.fixture
def real_replay_env(clean_replay_env: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("UNIFI_HOST", "gateway.test")
    monkeypatch.setenv("UNIFI_API_KEY", "test-api-key-1234")
    sink_path = clean_replay_env / "configured-audit.jsonl"
    monkeypatch.setenv(audit.ENV_SINK, "file")
    monkeypatch.setenv(audit.ENV_PATH, str(sink_path))
    return sink_path


@respx.mock
def test_main_real_replay_is_audited_and_marked_as_a_replay(
    real_replay_env: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real replay is a real call: it lands in the configured sink, marked."""
    respx.get("https://gateway.test:443/proxy/network/api/s/default/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    log = tmp_path / "input.jsonl"
    before = _write_log(log, [_logged("list_networks")])

    rc = replay_mod.main([str(log), "--real", "--target-controller", "default", "--i-mean-it"])

    assert rc == 0, capsys.readouterr()
    assert log.read_bytes() == before
    records = audit.parse_jsonl(real_replay_env.read_text().splitlines())
    assert [(r.tool, r.client_id) for r in records] == [
        ("list_networks", replay_mod.REPLAY_CLIENT_ID)
    ]


def test_main_real_replay_refuses_to_replay_the_sink_it_appends_to(
    real_replay_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _write_log(real_replay_env, [_logged("list_networks")])

    rc = replay_mod.main(
        [str(real_replay_env), "--real", "--target-controller", "default", "--i-mean-it"]
    )

    assert rc == 2
    assert "audit sink appends to" in capsys.readouterr().err
    assert real_replay_env.read_bytes() == before


def test_main_reports_bad_configuration_without_a_traceback(
    clean_replay_env: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Real mode with no controller configured is an operator error, not a crash."""
    log = tmp_path / "input.jsonl"
    _write_log(log, [_logged("list_networks")])

    rc = replay_mod.main([str(log), "--real", "--target-controller", "default", "--i-mean-it"])

    assert rc == 2
    assert "Real mode requires controller config" in capsys.readouterr().err
