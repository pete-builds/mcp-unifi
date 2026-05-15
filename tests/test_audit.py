"""Tests for ``mcp_unifi.audit``.

Covers:
* envelope shape — emit one event, parse from disk, assert all fields
* secret scrubber — nested dicts with sensitive keys, plain keys preserved
* sink dispatch — env-driven selection of file / stdout / syslog
* async safety — many concurrent emits produce well-formed lines, no
  interleaving, no dropped writes
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from mcp_unifi import audit
from mcp_unifi.audit import (
    REDACTED,
    AuditEvent,
    AuditLog,
    FileSink,
    StdoutSink,
    SyslogSink,
    _build_sink_from_env,
    get_audit_log,
    parse_jsonl,
    scrub,
    set_audit_log,
)

# ---------------------------------------------------------------------------
# Test sink — captures events in memory for assertions
# ---------------------------------------------------------------------------


class MemorySink:
    """Minimal in-memory Sink. Used to test the AuditLog facade itself."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.closed = False

    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    """Make sure no test leaks the module-level audit log into the next."""
    set_audit_log(None)
    yield
    set_audit_log(None)


@pytest.fixture
def env_clean(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for var in (audit.ENV_SINK, audit.ENV_PATH, audit.ENV_SYSLOG_ADDRESS):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


# ---------------------------------------------------------------------------
# Scrubber
# ---------------------------------------------------------------------------


def test_scrub_redacts_known_sensitive_keys_case_insensitive() -> None:
    payload = {
        "name": "guest-wifi",
        "ssid": "Brooks",
        "api_key": "abc123",
        "Password": "hunter2",
        "auth_token": "Bearer xyz",
        "X-Passphrase": "WiFiP@ss",
        "client_secret": "shhh",
    }
    cleaned = scrub(payload)
    assert cleaned["name"] == "guest-wifi"
    assert cleaned["ssid"] == "Brooks"
    assert cleaned["api_key"] == REDACTED
    assert cleaned["Password"] == REDACTED
    assert cleaned["auth_token"] == REDACTED
    assert cleaned["X-Passphrase"] == REDACTED
    assert cleaned["client_secret"] == REDACTED


def test_scrub_walks_nested_structures() -> None:
    payload = {
        "outer": {
            "inner": {
                "api_key": "leak",
                "harmless": [
                    {"name": "ok", "token": "leak2"},
                    {"name": "also-ok"},
                ],
            },
            # Keys themselves containing a sensitive substring are redacted
            # whole — the substring match errs on the side of caution. If a
            # caller really needs to surface a list named "secrets" they can
            # rename the key.
            "credentials": [{"password": "x"}, {"password": "y"}],
        },
        "tuple_field": ({"secret": "leak3"}, "ok"),
        "primitive": 42,
    }
    cleaned = scrub(payload)
    assert cleaned["outer"]["inner"]["api_key"] == REDACTED
    assert cleaned["outer"]["inner"]["harmless"][0]["name"] == "ok"
    assert cleaned["outer"]["inner"]["harmless"][0]["token"] == REDACTED
    assert cleaned["outer"]["inner"]["harmless"][1]["name"] == "also-ok"
    assert cleaned["outer"]["credentials"][0]["password"] == REDACTED
    assert cleaned["outer"]["credentials"][1]["password"] == REDACTED
    assert cleaned["tuple_field"][0]["secret"] == REDACTED
    assert cleaned["tuple_field"][1] == "ok"
    assert cleaned["primitive"] == 42


def test_scrub_redacts_keys_whose_name_contains_a_sensitive_substring() -> None:
    """Substring matching is intentional: better one false-positive than a leak."""
    payload = {
        "list_of_secrets": ["should not appear"],
        "auth_token_set": True,
    }
    cleaned = scrub(payload)
    assert cleaned["list_of_secrets"] == REDACTED
    assert cleaned["auth_token_set"] == REDACTED


def test_scrub_returns_copy_does_not_mutate_input() -> None:
    payload = {"api_key": "real", "name": "ok"}
    cleaned = scrub(payload)
    assert cleaned is not payload
    assert payload["api_key"] == "real"  # input untouched
    assert cleaned["api_key"] == REDACTED


def test_scrub_passes_through_primitives() -> None:
    assert scrub("hello") == "hello"
    assert scrub(7) == 7
    assert scrub(None) is None
    assert scrub(True) is True


# ---------------------------------------------------------------------------
# Envelope: emit one, parse it from disk
# ---------------------------------------------------------------------------


async def test_emit_writes_jsonl_with_full_envelope(tmp_path: Path) -> None:
    sink = FileSink(tmp_path / "audit.jsonl")
    log = AuditLog(sink=sink)
    event = await log.emit(
        controller="default",
        tool="create_vlan",
        args={"name": "iot", "vlan_id": 50, "api_key": "secret-do-not-log"},
        result={"_id": "abc", "vlan_id": 50},
        success=True,
        latency_ms=12.345,
    )

    # Returned envelope is sane.
    assert event.tool == "create_vlan"
    assert event.controller == "default"
    assert event.success is True
    assert event.latency_ms == 12.345
    assert event.args["api_key"] == REDACTED
    assert event.args["vlan_id"] == 50
    assert event.error is None
    assert event.schema == "1"
    assert event.ts.endswith("Z")

    # File contains exactly one well-formed line with the same data.
    lines = sink.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "create_vlan"
    assert record["controller"] == "default"
    assert record["success"] is True
    assert record["args"]["api_key"] == REDACTED
    assert record["args"]["vlan_id"] == 50
    assert record["result"] == {"_id": "abc", "vlan_id": 50}
    assert record["error"] is None
    assert record["schema"] == "1"


async def test_emit_failure_carries_error_string(tmp_path: Path) -> None:
    sink = FileSink(tmp_path / "audit.jsonl")
    log = AuditLog(sink=sink)
    event = await log.emit(
        controller="home",
        tool="delete_vlan",
        args={"network_id": "ghost"},
        result=None,
        success=False,
        latency_ms=4.2,
        error="UniFiError: 404 not found",
    )
    assert event.success is False
    assert event.error == "UniFiError: 404 not found"
    record = json.loads(sink.path.read_text(encoding="utf-8").splitlines()[0])
    assert record["error"] == "UniFiError: 404 not found"


async def test_emit_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dirs" / "audit.jsonl"
    sink = FileSink(target)
    log = AuditLog(sink=sink)
    await log.emit(
        controller="default",
        tool="list_devices",
        args={},
        result=[],
        success=True,
        latency_ms=1.0,
    )
    assert target.exists()


async def test_emit_does_not_mutate_caller_args(tmp_path: Path) -> None:
    sink = FileSink(tmp_path / "a.jsonl")
    log = AuditLog(sink=sink)
    args = {"api_key": "real", "vlan_id": 99}
    await log.emit(
        controller="default",
        tool="create_vlan",
        args=args,
        result={"ok": True},
        success=True,
        latency_ms=1.0,
    )
    # Caller's dict is untouched.
    assert args["api_key"] == "real"


# ---------------------------------------------------------------------------
# Sink dispatch from env
# ---------------------------------------------------------------------------


def test_default_sink_is_file_at_default_path(env_clean: pytest.MonkeyPatch) -> None:
    sink = _build_sink_from_env()
    assert isinstance(sink, FileSink)
    assert sink.path == Path(audit.DEFAULT_PATH)


def test_env_sink_file_with_custom_path(
    env_clean: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    custom = tmp_path / "custom.jsonl"
    env_clean.setenv(audit.ENV_SINK, "file")
    env_clean.setenv(audit.ENV_PATH, str(custom))
    sink = _build_sink_from_env()
    assert isinstance(sink, FileSink)
    assert sink.path == custom


def test_env_sink_stdout(env_clean: pytest.MonkeyPatch) -> None:
    env_clean.setenv(audit.ENV_SINK, "stdout")
    sink = _build_sink_from_env()
    assert isinstance(sink, StdoutSink)


def test_env_sink_syslog_uses_default_address(
    env_clean: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Build a SyslogSink without actually opening /dev/log on macOS dev boxes."""
    captured: dict[str, Any] = {}

    class _FakeHandler(logging.Handler):
        def __init__(self, address: str | tuple[str, int] = "/dev/log") -> None:
            super().__init__()
            captured["address"] = address

        def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover
            pass

    monkeypatch.setattr(audit.logging.handlers, "SysLogHandler", _FakeHandler)
    env_clean.setenv(audit.ENV_SINK, "syslog")
    sink = _build_sink_from_env()
    assert isinstance(sink, SyslogSink)
    assert captured["address"] == "/dev/log"


def test_env_sink_syslog_honours_address_override(
    env_clean: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class _FakeHandler(logging.Handler):
        def __init__(self, address: str | tuple[str, int] = "/dev/log") -> None:
            super().__init__()
            captured["address"] = address

    monkeypatch.setattr(audit.logging.handlers, "SysLogHandler", _FakeHandler)
    env_clean.setenv(audit.ENV_SINK, "syslog")
    env_clean.setenv(audit.ENV_SYSLOG_ADDRESS, "/var/run/syslog")
    sink = _build_sink_from_env()
    assert isinstance(sink, SyslogSink)
    assert captured["address"] == "/var/run/syslog"


def test_env_sink_unknown_value_raises(env_clean: pytest.MonkeyPatch) -> None:
    env_clean.setenv(audit.ENV_SINK, "kafka")
    with pytest.raises(ValueError, match="MCP_UNIFI_AUDIT_SINK"):
        _build_sink_from_env()


def test_env_sink_case_insensitive(env_clean: pytest.MonkeyPatch) -> None:
    env_clean.setenv(audit.ENV_SINK, "STDOUT")
    sink = _build_sink_from_env()
    assert isinstance(sink, StdoutSink)


# ---------------------------------------------------------------------------
# StdoutSink actually writes to stdout
# ---------------------------------------------------------------------------


async def test_stdout_sink_writes_one_line_per_event(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sink = StdoutSink()
    log = AuditLog(sink=sink)
    await log.emit(
        controller="home",
        tool="list_devices",
        args={},
        result=[{"mac": "aa:bb"}],
        success=True,
        latency_ms=2.0,
    )
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    record = json.loads(out[0])
    assert record["tool"] == "list_devices"
    assert record["controller"] == "home"


# ---------------------------------------------------------------------------
# Singleton lazy init from env
# ---------------------------------------------------------------------------


def test_get_audit_log_builds_lazy_singleton(
    env_clean: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "lazy.jsonl"
    env_clean.setenv(audit.ENV_SINK, "file")
    env_clean.setenv(audit.ENV_PATH, str(target))
    log = get_audit_log()
    assert isinstance(log, AuditLog)
    again = get_audit_log()
    assert again is log  # truly a singleton


async def test_module_level_emit_uses_singleton(
    env_clean: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "singleton.jsonl"
    env_clean.setenv(audit.ENV_SINK, "file")
    env_clean.setenv(audit.ENV_PATH, str(target))
    await audit.emit(
        controller="default",
        tool="get_site_health",
        args={},
        result={"status": "ok"},
        success=True,
        latency_ms=3.0,
    )
    record = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
    assert record["tool"] == "get_site_health"


def test_audit_log_attribute_resolves_to_singleton(
    env_clean: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "attr.jsonl"
    env_clean.setenv(audit.ENV_SINK, "file")
    env_clean.setenv(audit.ENV_PATH, str(target))
    # Access via the lazy module-level attribute described in __all__
    log = audit.AUDIT_LOG  # type: ignore[attr-defined]
    assert isinstance(log, AuditLog)


def test_module_getattr_unknown_raises() -> None:
    with pytest.raises(AttributeError):
        _ = audit.NOT_A_THING  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Async safety: 100 concurrent emits produce 100 well-formed lines
# ---------------------------------------------------------------------------


async def test_concurrent_emits_no_corruption(tmp_path: Path) -> None:
    target = tmp_path / "concurrent.jsonl"
    log = AuditLog(sink=FileSink(target))

    async def one(i: int) -> None:
        await log.emit(
            controller="default",
            tool="list_devices",
            args={"i": i, "api_key": f"secret-{i}"},
            result={"i": i},
            success=True,
            latency_ms=float(i),
        )

    await asyncio.gather(*(one(i) for i in range(100)))

    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 100
    seen_indices: set[int] = set()
    for raw in lines:
        record = json.loads(raw)  # every line must be valid JSON
        assert record["tool"] == "list_devices"
        assert record["args"]["api_key"] == REDACTED
        seen_indices.add(record["args"]["i"])
    # Every index 0..99 made it through exactly once.
    assert seen_indices == set(range(100))


# ---------------------------------------------------------------------------
# AuditEvent / parse_jsonl round trip — needed by replay
# ---------------------------------------------------------------------------


async def test_parse_jsonl_round_trips_emitted_events(tmp_path: Path) -> None:
    target = tmp_path / "trip.jsonl"
    log = AuditLog(sink=FileSink(target))
    await log.emit("home", "list_devices", {}, [{"mac": "a"}], True, 1.0)
    await log.emit(
        "home",
        "delete_vlan",
        {"network_id": "x"},
        None,
        False,
        2.0,
        error="not found",
    )

    events = parse_jsonl(target.read_text(encoding="utf-8").splitlines())
    assert len(events) == 2
    assert events[0].tool == "list_devices"
    assert events[1].error == "not found"
    assert events[1].success is False


def test_parse_jsonl_skips_blank_lines() -> None:
    line = json.dumps(
        {
            "ts": "2026-05-14T00:00:00Z",
            "controller": "a",
            "tool": "t",
            "args": {},
            "result": None,
            "success": True,
            "latency_ms": 1.0,
        }
    )
    raw = [line, "", "  ", ""]
    events = parse_jsonl(raw)
    assert len(events) == 1


def test_parse_jsonl_rejects_invalid_json() -> None:
    with pytest.raises(ValueError, match="line 1"):
        parse_jsonl(["{not json"])


def test_parse_jsonl_rejects_missing_fields() -> None:
    raw = ['{"ts":"2026-05-14T00:00:00Z","tool":"t"}']  # no controller, no args
    with pytest.raises(ValueError, match="missing required field"):
        parse_jsonl(raw)


# ---------------------------------------------------------------------------
# AuditLog.aclose passes through to the sink
# ---------------------------------------------------------------------------


async def test_aclose_propagates_to_sink() -> None:
    sink = MemorySink()
    log = AuditLog(sink=sink)
    await log.aclose()
    assert sink.closed is True


async def test_filesink_aclose_is_noop(tmp_path: Path) -> None:
    sink = FileSink(tmp_path / "x.jsonl")
    # Should not raise.
    await sink.aclose()


async def test_stdoutsink_aclose_is_noop() -> None:
    sink = StdoutSink()
    await sink.aclose()


# ---------------------------------------------------------------------------
# Latency precision
# ---------------------------------------------------------------------------


async def test_latency_rounded_to_three_decimals(tmp_path: Path) -> None:
    sink = FileSink(tmp_path / "lat.jsonl")
    log = AuditLog(sink=sink)
    event = await log.emit(
        "default", "list_devices", {}, [], True, latency_ms=12.3456789
    )
    assert event.latency_ms == 12.346
