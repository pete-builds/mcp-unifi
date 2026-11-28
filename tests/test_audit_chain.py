"""Correlation ids and the hash chain on audit records (schema 2).

Three things are proven here:

* **Correlation.** Every record has a unique ``event_id``. A destructive
  preview and the ``confirm_destructive_action`` that executes it share one
  ``operation_id``; an unrelated call does not.
* **The chain holds.** Records written by one process, across a restart, after
  a legacy (schema 1) log, by concurrent callers, and with redacted or
  non-JSON values all verify.
* **The verifier can fail.** Each kind of tampering it claims to detect has a
  test of its own that edits a real log and requires the verifier to name the
  right line. The limits are pinned too: records cut off the end of a segment
  are not detected, and the tests say so rather than imply otherwise.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi import audit_chain
from mcp_unifi.audit import (
    REDACTED,
    AuditEvent,
    AuditLog,
    FileSink,
    StdoutSink,
    parse_jsonl,
    set_audit_log,
)
from mcp_unifi.audit_chain import (
    CHAIN_START_AFTER_UNCHAINED,
    CHAIN_START_AFTER_UNREADABLE,
    CHAIN_START_NEW_LOG,
    CHAIN_START_PROCESS_START,
    GENESIS_HASH,
    Line,
    VerifyReport,
    read_lines,
    record_hash,
    resume_from_file,
    verify_lines,
)
from mcp_unifi.cli import audit_verify
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules._audit import audited, continue_operation
from mcp_unifi.modules.network._pending import get_pending_actions
from mcp_unifi.server import build_server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _emit(log: AuditLog, i: int, **extra: Any) -> None:
    await log.emit(
        controller="default",
        tool=extra.pop("tool", "list_devices"),
        args=extra.pop("args", {"i": i}),
        result=extra.pop("result", {"i": i}),
        success=True,
        latency_ms=float(i),
        **extra,
    )


async def _write_log(path: Path, n: int) -> list[str]:
    log = AuditLog(sink=FileSink(path))
    for i in range(n):
        await _emit(log, i)
    return path.read_text(encoding="utf-8").splitlines()


def _verify(path: Path | list[Path]) -> VerifyReport:
    paths = path if isinstance(path, list) else [path]
    return verify_lines(read_lines(paths))


def _put_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def _legacy_line(tool: str = "list_devices") -> str:
    """A record exactly as schema 1 wrote it: no ids, no chain fields."""
    return json.dumps(
        {
            "args": {},
            "client_id": None,
            "controller": "default",
            "denied_by": None,
            "error": None,
            "latency_ms": 1.0,
            "result": None,
            "schema": "1",
            "success": True,
            "tool": tool,
            "ts": "2026-08-03T00:00:00.000Z",
        },
        sort_keys=True,
    )


# ---------------------------------------------------------------------------
# Event ids
# ---------------------------------------------------------------------------


async def test_every_record_gets_a_unique_event_id(tmp_path: Path) -> None:
    lines = await _write_log(tmp_path / "a.jsonl", 50)
    records = [json.loads(line) for line in lines]
    ids = [r["event_id"] for r in records]
    assert len(set(ids)) == 50
    assert all(isinstance(i, str) and len(i) == 32 for i in ids)
    # A plain call is an operation of its own: operation_id is its event_id.
    assert all(r["operation_id"] == r["event_id"] for r in records)
    assert {r["schema"] for r in records} == {"2"}


async def test_event_id_factory_is_injectable(tmp_path: Path) -> None:
    counter = itertools.count(1)
    log = AuditLog(sink=FileSink(tmp_path / "a.jsonl"), id_factory=lambda: f"ev-{next(counter)}")
    await _emit(log, 0)
    await _emit(log, 1, operation_id="op-from-elsewhere")
    first, second = (json.loads(x) for x in (tmp_path / "a.jsonl").read_text().splitlines())
    assert (first["event_id"], first["operation_id"]) == ("ev-1", "ev-1")
    assert (second["event_id"], second["operation_id"]) == ("ev-2", "op-from-elsewhere")


# ---------------------------------------------------------------------------
# Preview and confirm share one operation
# ---------------------------------------------------------------------------


@pytest.fixture
def chained_server(
    stub_settings: Settings, stub_state: StubState, tmp_path: Path
) -> tuple[FastMCP, Path]:
    log_path = tmp_path / "tool-audit.jsonl"
    set_audit_log(AuditLog(sink=FileSink(log_path)))
    return build_server(stub_settings, stub=stub_state), log_path


async def _call(server: FastMCP, name: str, args: dict[str, Any] | None = None) -> Any:
    raw: Any = await server.call_tool(name, args or {})
    return json.loads(raw.content[0].text)


async def test_preview_and_confirm_share_an_operation_id(
    chained_server: tuple[FastMCP, Path],
) -> None:
    server, log_path = chained_server
    created = await _call(
        server, "create_vlan", {"name": "Doomed", "vlan_id": 72, "subnet": "10.0.72.0/24"}
    )
    preview = await _call(server, "delete_vlan", {"network_id": created["_id"]})
    await _call(server, "list_networks")  # unrelated, between the two halves
    await _call(server, "confirm_destructive_action", {"token": preview["token"]})

    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    by_tool = {r["tool"]: r for r in records}
    preview_ev = by_tool["delete_vlan"]
    confirm_ev = by_tool["confirm_destructive_action"]

    # The operation is named after the record that started it: the preview.
    assert preview_ev["operation_id"] == preview_ev["event_id"]
    assert confirm_ev["operation_id"] == preview_ev["event_id"]
    assert confirm_ev["event_id"] != preview_ev["event_id"]
    assert confirm_ev["result"]["deleted"] is True
    # Unrelated calls are operations of their own.
    for tool in ("create_vlan", "list_networks"):
        assert by_tool[tool]["operation_id"] == by_tool[tool]["event_id"]
        assert by_tool[tool]["operation_id"] != preview_ev["operation_id"]
    # jq 'select(.operation_id == "...")' returns the whole change, in order.
    story = [r["tool"] for r in records if r["operation_id"] == preview_ev["operation_id"]]
    assert story == ["delete_vlan", "confirm_destructive_action"]
    # The ids do not leak into tool output: the preview envelope is unchanged.
    assert set(preview) == {
        "preview_id",
        "preview",
        "action",
        "controller",
        "resource",
        "token",
        "expires_at",
        "confirm_with",
    }
    assert _verify(log_path).ok


async def test_operation_id_is_kept_server_side_not_in_the_token(
    chained_server: tuple[FastMCP, Path],
) -> None:
    server, log_path = chained_server
    created = await _call(
        server, "create_vlan", {"name": "Doomed", "vlan_id": 73, "subnet": "10.0.73.0/24"}
    )
    preview = await _call(server, "delete_vlan", {"network_id": created["_id"]})
    pending = get_pending_actions().get(preview["token"])
    assert pending is not None
    preview_ev = json.loads(log_path.read_text().splitlines()[-1])
    assert pending.operation_id == preview_ev["event_id"]
    assert pending.operation_id not in preview["token"].replace("-", "")


async def test_a_confirm_that_executes_nothing_is_its_own_operation(
    chained_server: tuple[FastMCP, Path],
) -> None:
    server, log_path = chained_server
    out = await _call(server, "confirm_destructive_action", {"token": "not-a-real-token"})
    assert "error" in out
    (record,) = (json.loads(line) for line in log_path.read_text().splitlines())
    assert record["operation_id"] == record["event_id"]


async def test_failed_confirm_still_files_under_the_preview_operation(
    chained_server: tuple[FastMCP, Path],
) -> None:
    """The executor ran and failed: that is still part of the previewed change."""
    server, log_path = chained_server
    created = await _call(
        server, "create_vlan", {"name": "Doomed", "vlan_id": 74, "subnet": "10.0.74.0/24"}
    )
    preview = await _call(server, "delete_vlan", {"network_id": created["_id"]})
    pending = get_pending_actions().get(preview["token"])
    assert pending is not None

    async def _explode() -> str:
        raise RuntimeError("controller went away")

    pending.executor = _explode
    with pytest.raises(Exception, match="controller went away"):
        await server.call_tool("confirm_destructive_action", {"token": preview["token"]})
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    preview_ev, confirm_ev = records[-2], records[-1]
    assert confirm_ev["success"] is False
    assert confirm_ev["operation_id"] == preview_ev["event_id"]


# ---------------------------------------------------------------------------
# The chain holds
# ---------------------------------------------------------------------------


async def test_chain_is_valid_after_many_writes(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 25)
    records = [json.loads(line) for line in lines]
    assert records[0]["prev_hash"] == GENESIS_HASH
    assert records[0]["chain_start"] == CHAIN_START_NEW_LOG
    for before, after in itertools.pairwise(records):
        assert after["prev_hash"] == before["hash"]
        assert after["chain_start"] is None
    for r in records:
        assert record_hash(r) == r["hash"]

    report = _verify(path)
    assert report.ok, report.broken
    assert report.chained == 25
    assert report.head_hash == records[-1]["hash"]
    assert report.head_where == f"{path}:25"


def test_hash_is_sha256_over_the_canonical_record_including_prev_hash() -> None:
    """A fixed vector, so the format can be re-implemented outside this package.

    If this changes, every log already written stops verifying.
    """
    record = {
        "args": {"b": 1, "a": "x"},
        "prev_hash": GENESIS_HASH,
        "tool": "list_devices",
        "hash": "ignored: never part of its own material",
    }
    assert audit_chain.canonical_bytes(record) == (
        b'{"args":{"a":"x","b":1},"prev_hash":"' + GENESIS_HASH.encode() + b'",'
        b'"tool":"list_devices"}'
    )
    assert record_hash(record) == "088a3ee6f7c756a8cc79b0ff2937271a5f8ba3d825779036a6ef16fc473045aa"


async def test_restart_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    await _write_log(path, 3)
    before = path.read_bytes()
    # A second process (a fresh AuditLog) appends to the same file.
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 3)
    await _emit(log, 4)

    assert path.read_bytes().startswith(before), "an existing line was rewritten"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[3]["prev_hash"] == records[2]["hash"]
    assert records[3]["chain_start"] is None
    report = _verify(path)
    assert report.ok, report.broken
    assert report.chained == 5
    assert [w for w, _ in report.segment_starts] == [f"{path}:1"]


async def test_legacy_log_continues_as_a_new_segment(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _put_lines(path, [_legacy_line(), _legacy_line("list_networks")])
    before = path.read_bytes()

    log = AuditLog(sink=FileSink(path))
    await _emit(log, 0)
    await _emit(log, 1)

    assert path.read_bytes().startswith(before), "a legacy line was rewritten"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[2]["prev_hash"] == GENESIS_HASH
    assert records[2]["chain_start"] == CHAIN_START_AFTER_UNCHAINED
    report = _verify(path)
    assert report.ok, report.broken
    assert (report.unchained, report.chained) == (2, 2)
    assert report.unchained_runs == [(f"{path}:1", f"{path}:2")]
    assert report.segment_starts == [(f"{path}:3", CHAIN_START_AFTER_UNCHAINED)]
    # Old and new records both still parse.
    events = parse_jsonl(path.read_text().splitlines())
    assert [e.event_id is None for e in events] == [True, True, False, False]
    assert [e.schema for e in events] == ["1", "1", "2", "2"]


@pytest.mark.parametrize("content", [b"", b"\n\n  \n"])
def test_resume_from_an_empty_file_starts_a_new_log(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "a.jsonl"
    path.write_bytes(content)
    assert resume_from_file(path) == audit_chain.ChainResume(GENESIS_HASH, CHAIN_START_NEW_LOG)
    assert resume_from_file(tmp_path / "missing.jsonl").chain_start == CHAIN_START_NEW_LOG


def test_resume_reads_only_the_last_line_of_a_long_file(tmp_path: Path) -> None:
    """The tail read crosses its step boundary and still finds the last line."""
    path = tmp_path / "a.jsonl"
    big = json.dumps({"hash": "a" * 64, "pad": "x" * 200_000})
    last = json.dumps({"hash": "b" * 64, "pad": "y" * 150_000})
    _put_lines(path, [big, last, "", ""])
    assert resume_from_file(path) == audit_chain.ChainResume("b" * 64, None)


@pytest.mark.parametrize(
    "tail",
    [
        '["not", "an", "object"]',
        '{"hash": "not-a-hash", "schema": "2"}',
        # A duplicate key: the line parses leniently, but not as a record.
        '{"hash": "' + "a" * 64 + '", "hash": "' + "b" * 64 + '", "schema": "2"}',
    ],
)
async def test_resume_after_an_unreadable_last_line_never_crashes(
    tmp_path: Path, tail: str
) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 2)
    path.write_text("\n".join([*lines, tail]) + "\n", encoding="utf-8")
    before = path.read_bytes()

    log = AuditLog(sink=FileSink(path))
    await _emit(log, 9)

    assert path.read_bytes().startswith(before)
    new = json.loads(path.read_text().splitlines()[-1])
    assert new["chain_start"] == CHAIN_START_AFTER_UNREADABLE
    assert new["prev_hash"] == GENESIS_HASH
    # A line that parses but is not a valid record is not crash damage: it
    # stays a break, and the verifier names it.
    report = _verify(path)
    assert not report.ok
    assert report.broken is not None and report.broken.where == f"{path}:3"


async def test_a_crash_mid_write_then_restart_leaves_a_damaged_line_not_a_break(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A torn last line (no newline) followed by a restart.

    The restarted writer must start its record on a line of its own, or the
    record is fused onto the fragment and lost to every reader. The verifier
    then reports the fragment as damage, where an unknown number of records may
    be missing, verifies everything after it, and exits 3, not 0.
    """
    path = tmp_path / "a.jsonl"
    await _write_log(path, 2)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-11-27T00:00:00.000Z", "tool": "list_dev')  # torn, no newline

    log = AuditLog(sink=FileSink(path))
    await _emit(log, 9)
    await _emit(log, 10)

    lines = path.read_text().splitlines()
    assert len(lines) == 5, "the new record was written onto the torn fragment"
    assert json.loads(lines[3])["chain_start"] == CHAIN_START_AFTER_UNREADABLE
    report = _verify(path)
    assert report.ok, report.broken
    assert report.damaged == [f"{path}:3"]
    assert report.chained == 4

    assert audit_verify.main([str(path)]) == audit_verify.EXIT_DAMAGED == 3
    out = capsys.readouterr().out
    assert out.startswith(f"audit-verify: DAMAGED {path}")
    assert (
        f"WARNING: damaged line at {path}:3 (crash mid-write?): not a record; an unknown "
        "number of records at this point may be missing" in out
    )
    assert "damaged lines: 1" in out
    assert "one record" not in out
    assert json.loads(_json_out(path, capsys))["damaged_lines"] == [f"{path}:3"]


async def test_a_damaged_line_without_a_restart_after_it_is_a_break(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    lines[1] = lines[1][: len(lines[1]) // 2]

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert report.broken.reason.startswith("unreadable line")


async def test_restart_continues_when_the_file_lacks_a_trailing_newline(tmp_path: Path) -> None:
    """A complete last record with no newline: continue its chain on a new line."""
    path = tmp_path / "a.jsonl"
    await _write_log(path, 2)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))

    log = AuditLog(sink=FileSink(path))
    await _emit(log, 2)

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 3
    assert records[2]["prev_hash"] == records[1]["hash"]
    assert records[2]["chain_start"] is None
    report = _verify(path)
    assert report.ok, report.broken
    assert report.chained == 3


async def test_concurrent_writers_produce_one_valid_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(sink=FileSink(path))

    async def one(i: int) -> None:
        # Yield a varying number of times first, so the callers reach the
        # lock in an order unrelated to the order they were created in.
        for _ in range(i % 7):
            await asyncio.sleep(0)
        await _emit(log, i)

    await asyncio.gather(*(one(i) for i in range(200)))

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 200
    prevs = [r["prev_hash"] for r in records]
    assert len(set(prevs)) == 200, "two records claim the same predecessor: the chain forked"
    report = _verify(path)
    assert report.ok, report.broken
    assert report.chained == 200


async def test_redacted_records_verify(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(sink=FileSink(path))
    await log.emit(
        controller="default",
        tool="create_wlan",
        args={"name": "iot", "passphrase": "hunter2hunter2", "nested": {"api_key": "k-123"}},
        result={"x_passphrase": "hunter2hunter2"},
        success=True,
        latency_ms=1.0,
    )
    text = path.read_text()
    assert "hunter2hunter2" not in text and "k-123" not in text
    record = json.loads(text)
    assert record["args"]["passphrase"] == REDACTED
    assert record["result"]["x_passphrase"] == REDACTED
    # The hash covers the redacted bytes that were written.
    assert record_hash(record) == record["hash"]
    assert _verify(path).ok


async def test_values_that_are_not_plain_json_hash_as_written(tmp_path: Path) -> None:
    """A tuple, a datetime and integer keys are written as JSON reads them back.

    The hash has to be over those written forms. Hashing the in-memory values
    would sort ``{10: .., 9: ..}`` numerically while the file sorts them as
    strings, and every such record would read as tampered.
    """
    path = tmp_path / "a.jsonl"
    log = AuditLog(sink=FileSink(path))
    when = dt.datetime(2026, 11, 27, 12, 0, tzinfo=dt.UTC)
    event = await log.emit(
        controller="default",
        tool="list_devices",
        args={"ids": (1, 2)},
        result={10: "ten", 9: "nine", "when": when},
        success=True,
        latency_ms=1.0,
    )
    assert event.result == {"10": "ten", "9": "nine", "when": str(when)}
    assert _verify(path).ok


async def test_stdout_sink_chains_per_process(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without a file to read back, every process start begins a segment."""
    for _process in range(2):
        log = AuditLog(sink=StdoutSink())
        await _emit(log, 0)
        await _emit(log, 1)
    out = capsys.readouterr().out.splitlines()
    first = json.loads(out[0])
    assert (first["prev_hash"], first["chain_start"]) == (GENESIS_HASH, CHAIN_START_PROCESS_START)

    collected = tmp_path / "collected.jsonl"
    _put_lines(collected, out)
    report = _verify(collected)
    assert report.ok, report.broken
    assert report.chained == 4
    assert [why for _, why in report.segment_starts] == [CHAIN_START_PROCESS_START] * 2


async def test_a_record_the_sink_failed_to_write_reads_as_missing(tmp_path: Path) -> None:
    """The head advances even when the write fails, so the loss is visible."""
    path = tmp_path / "a.jsonl"

    class FlakySink(FileSink):
        def __init__(self, target: Path) -> None:
            super().__init__(target)
            self.writes = 0

        async def write(self, event: Any) -> None:
            self.writes += 1
            if self.writes == 2:
                raise OSError("No space left on device")
            await super().write(event)

    log = AuditLog(sink=FlakySink(path))
    for i in range(3):
        await _emit(log, i)  # the failed write is swallowed, as before

    assert len(path.read_text().splitlines()) == 2
    report = _verify(path)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert report.broken.reason.startswith("a record is missing")


async def test_parse_jsonl_reads_the_new_fields(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 1)
    (event,) = parse_jsonl(lines)
    record = json.loads(lines[0])
    assert event.event_id == record["event_id"]
    assert event.operation_id == record["operation_id"]
    assert (event.prev_hash, event.hash) == (record["prev_hash"], record["hash"])
    assert event.chain_start == CHAIN_START_NEW_LOG


# ---------------------------------------------------------------------------
# The verifier catches tampering (each check has its own failing case)
# ---------------------------------------------------------------------------


def _report_for(path: Path, lines: list[str]) -> VerifyReport:
    _put_lines(path, lines)
    return _verify(path)


async def test_verifier_catches_an_edited_field(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 5)
    record = json.loads(lines[2])
    record["tool"] = "delete_vlan"
    lines[2] = json.dumps(record, sort_keys=True)

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert report.broken.reason.startswith("edited record")
    assert report.verified_through == f"{path}:2"


async def test_verifier_catches_a_deleted_middle_line(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 5)
    del lines[2]

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert report.broken.reason.startswith("a record is missing")


async def test_verifier_catches_two_swapped_lines(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 5)
    lines[1], lines[2] = lines[2], lines[1]

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert report.broken.reason.startswith("reordered")


async def test_verifier_catches_a_deletion_repaired_by_relinking(tmp_path: Path) -> None:
    """Delete a record and point the next one at its predecessor.

    This is the attack ``prev_hash`` being inside the hashed material exists
    for: the relinked record's own hash no longer matches.
    """
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 5)
    survivor = json.loads(lines[3])
    survivor["prev_hash"] = json.loads(lines[1])["hash"]
    lines[3] = json.dumps(survivor, sort_keys=True)
    del lines[2]

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert report.broken.reason.startswith("edited record")


async def test_verifier_catches_records_removed_from_the_head(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 4)

    report = _report_for(path, lines[1:])
    assert report.broken is not None
    assert report.broken.where == f"{path}:1"
    assert "removed from before this line" in report.broken.reason


async def test_verifier_catches_a_duplicated_line(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 4)

    report = _report_for(path, [*lines[:3], lines[1], lines[3]])
    assert report.broken is not None
    assert report.broken.where == f"{path}:4"
    assert report.broken.reason.startswith("out of order")


async def test_verifier_catches_a_mid_chain_restart(tmp_path: Path) -> None:
    """A record claiming to start a new file in the middle of a chain."""
    path = tmp_path / "a.jsonl"
    first = await _write_log(tmp_path / "one.jsonl", 2)
    second = await _write_log(tmp_path / "two.jsonl", 2)

    report = _report_for(path, [*first, *second])
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert "chain restarts here" in report.broken.reason


async def test_verifier_catches_stripped_chain_fields(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    record = json.loads(lines[1])
    del record["hash"]
    lines[1] = json.dumps(record, sort_keys=True)

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert "missing a valid hash" in report.broken.reason


async def test_verifier_catches_a_record_disguised_as_legacy(tmp_path: Path) -> None:
    """Strip the chain fields mid-chain and claim schema 1: a break, at that line."""
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    record = json.loads(lines[1])
    for key in ("hash", "prev_hash"):
        del record[key]
    record["schema"] = "1"
    lines[1] = json.dumps(record, sort_keys=True)

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert report.broken.reason.startswith("unchained record after chained records")


async def test_unchained_records_after_chained_ones_are_a_break(tmp_path: Path) -> None:
    """Legacy-shaped records are accepted only before a file's first chained record.

    Otherwise stripping the chain fields from the newest records (and claiming
    schema 1) would hide that they were edited.
    """
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 2)

    report = _report_for(path, [*lines, _legacy_line()])
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert report.broken.reason.startswith("unchained record after chained records")


async def test_records_cut_off_the_end_are_not_detected(tmp_path: Path) -> None:
    """Pinned limitation: a shorter chain is still a valid chain."""
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 4)
    head = json.loads(lines[-1])["hash"]

    report = _report_for(path, lines[:-1])
    assert report.ok
    assert report.head_hash != head


async def test_a_rotated_log_verifies_when_both_parts_are_given(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 4)
    older, newer = tmp_path / "a.jsonl.1", tmp_path / "a.jsonl.2"
    _put_lines(older, lines[:2])
    _put_lines(newer, lines[2:])

    alone = _verify(newer)
    assert alone.broken is not None and "rotated log" in alone.broken.reason
    together = _verify([older, newer])
    assert together.ok, together.broken
    assert together.head_where == f"{newer}:2"


async def test_rotation_then_restart_is_a_segment_start_not_a_break(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The server restarted after rotation, so the new file starts at new_log."""
    older, newer = tmp_path / "a.jsonl.1", tmp_path / "a.jsonl"
    await _write_log(older, 3)
    await _write_log(newer, 2)

    report = _verify([older, newer])
    assert report.ok, report.broken
    assert report.chained == 5
    assert report.segment_starts == [
        (f"{older}:1", CHAIN_START_NEW_LOG),
        (f"{newer}:1", CHAIN_START_NEW_LOG),
    ]
    # A new_log anywhere but the start of a file is still a break.
    spliced = tmp_path / "spliced.jsonl"
    _put_lines(spliced, older.read_text().splitlines() + newer.read_text().splitlines())
    assert not _verify(spliced).ok

    assert audit_verify.main([str(older), str(newer)]) == 0
    out = capsys.readouterr().out
    assert "segments: 2" in out
    assert f"    1. starts at {older}:1 (new_log)\n" in out
    assert f"    2. starts at {newer}:1 (new_log)\n" in out
    assert out.rstrip().endswith(NOT_COVERED)


def test_blank_lines_are_ignored() -> None:
    assert verify_lines([Line("x", 1, "\n"), Line("x", 2, "   ")]).ok


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------


async def test_cli_reports_ok_and_prints_the_head_hash(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.jsonl"
    _put_lines(path, [_legacy_line()])
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 0)
    lines = path.read_text().splitlines()
    head = json.loads(lines[-1])["hash"]

    assert audit_verify.main([str(path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"audit-verify: OK {path}")
    assert f"last record hash: {head} ({path}:2)" in out
    assert "unchained records (written before the chain existed): 1" in out
    assert f"    1. starts at {path}:2 (after_unchained)\n" in out
    assert out.rstrip().endswith(NOT_COVERED)
    for overclaim in ("anchor", "expect-head", "covers"):
        assert overclaim not in out

    assert audit_verify.main([str(path), "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is True
    assert summary["head_hash"] == head
    assert summary["break"] is None


async def test_cli_exits_1_and_names_the_line_on_a_break(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    del lines[1]
    _put_lines(path, lines)

    assert audit_verify.main([str(path)]) == 1
    out = capsys.readouterr().out
    assert out.startswith(f"audit-verify: BROKEN at {path}:2")
    assert "reason: a record is missing" in out
    assert "last verified hash: " in out and "  head: " not in out

    assert audit_verify.main([str(path), "--json"]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["break"]["at"] == f"{path}:2"


def test_cli_exits_2_on_a_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert audit_verify.main([str(tmp_path / "nope.jsonl")]) == 2
    assert "not a readable file" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Review round 1
# ---------------------------------------------------------------------------


def _forge(record: dict[str, Any]) -> str:
    """Re-seal a record the way only someone recomputing the chain could."""
    record = {k: v for k, v in record.items() if k != "hash"}
    record["hash"] = record_hash(record)
    return json.dumps(record, sort_keys=True)


async def test_a_duplicate_hash_key_is_a_break(tmp_path: Path) -> None:
    """Cut the last two records and graft the old last hash onto the new last line.

    A JSON parser keeps the last of two equal keys, so a duplicate ``hash`` key
    added at the front of a line is invisible to the hash check while putting
    another record's hash text into the file.
    """
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 5)
    old_last = json.loads(lines[-1])["hash"]
    kept = lines[:-2]
    kept[-1] = '{"hash": "' + old_last + '", ' + kept[-1][1:]
    _put_lines(path, kept)

    report = _verify(path)
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert "duplicate key" in report.broken.reason


async def test_a_duplicate_key_at_any_depth_is_a_break(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    lines[1] = lines[1].replace('"args": {"i": 1}', '"args": {"i": 1, "i": 1}')
    assert '"i": 1, "i": 1' in lines[1]

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert "duplicate key" in report.broken.reason


@pytest.mark.parametrize("field_name", [f.name for f in dataclasses.fields(AuditEvent)])
async def test_editing_any_field_breaks_verification(tmp_path: Path, field_name: str) -> None:
    """Every field is in the hashed material, so editing any one of them is caught."""
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    record = json.loads(lines[1])
    assert field_name in record
    if field_name in ("hash", "prev_hash"):
        record[field_name] = "f" * 64
    else:
        record[field_name] = "tampered" if record[field_name] != "tampered" else "x"
    lines[1] = json.dumps(record, sort_keys=True)

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"
    assert report.broken.reason.startswith("edited record")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a" * 64, True),
        ("0123456789abcdef" * 4, True),
        ("a" * 63, False),
        ("a" * 65, False),
        ("A" * 64, False),
        ("g" * 64, False),
        ("a" * 64 + "\n", False),
        (None, False),
        (1, False),
    ],
)
def test_is_hash_accepts_only_64_lowercase_hex(value: object, expected: bool) -> None:
    assert audit_chain.is_hash(value) is expected


async def test_a_cancelled_call_keeps_its_operation_id() -> None:
    sink_events: list[Any] = []

    class _Sink:
        async def write(self, event: Any) -> None:
            await asyncio.sleep(0.01)
            sink_events.append(event)

        async def aclose(self) -> None:
            return None

    set_audit_log(AuditLog(sink=_Sink()))
    started = asyncio.Event()

    @audited("synthetic_cancelled_confirm", mutates=True)
    async def synthetic_cancelled_confirm() -> str:
        continue_operation("op-from-the-preview")
        started.set()
        await asyncio.sleep(2)
        return "{}"

    task = asyncio.create_task(synthetic_cancelled_confirm())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    set_audit_log(None)

    (event,) = sink_events
    assert event.success is False
    assert event.operation_id == "op-from-the-preview"
    assert event.event_id and event.event_id != event.operation_id


def _genesis(line: str, chain_start: str | None) -> str:
    record = json.loads(line)
    record["prev_hash"] = GENESIS_HASH
    record["chain_start"] = chain_start
    return _forge(record)


@pytest.mark.parametrize(
    ("chain_start", "ok"),
    [
        ("bogus", False),
        (None, False),
        (CHAIN_START_NEW_LOG, False),
        (CHAIN_START_AFTER_UNCHAINED, False),
        (CHAIN_START_AFTER_UNREADABLE, False),
        (CHAIN_START_PROCESS_START, True),
    ],
)
async def test_a_segment_start_mid_chain_must_carry_a_label_that_fits(
    tmp_path: Path, chain_start: str | None, ok: bool
) -> None:
    """Only process_start can begin a segment right after a chained record.

    The labels are inside the hash, so only someone recomputing the chain can
    write one; these checks keep a forged restart from being waved through as
    an ordinary one.
    """
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    lines[2] = _genesis(lines[2], chain_start)

    report = _report_for(path, lines)
    assert report.ok is ok, report.broken
    if not ok:
        assert report.broken is not None and report.broken.where == f"{path}:3"


@pytest.mark.parametrize("chain_start", ["bogus", None, CHAIN_START_AFTER_UNREADABLE])
async def test_the_first_record_must_carry_a_known_label(
    tmp_path: Path, chain_start: str | None
) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 2)
    lines[0] = _genesis(lines[0], chain_start)
    second = json.loads(lines[1])
    second["prev_hash"] = json.loads(lines[0])["hash"]
    lines[1] = _forge(second)

    report = _report_for(path, lines)
    assert report.broken is not None and report.broken.where == f"{path}:1"


async def test_after_unchained_must_follow_an_unchained_record(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 1)
    # A file whose first record claims to follow an unchained one, with none there.
    lines[0] = _genesis(lines[0], CHAIN_START_AFTER_UNCHAINED)
    assert not _report_for(path, lines).ok
    # Preceded by a real unchained record it is fine.
    assert _report_for(path, [_legacy_line(), lines[0]]).ok


async def test_a_continuing_record_must_not_carry_a_segment_label(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    record = json.loads(lines[2])
    record["chain_start"] = CHAIN_START_NEW_LOG
    lines[2] = _forge(record)

    report = _report_for(path, lines)
    assert report.broken is not None and report.broken.where == f"{path}:3"


async def test_a_leading_byte_order_mark_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    await _write_log(path, 2)
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())

    report = _verify(path)
    assert report.ok, report.broken
    assert report.chained == 2


def test_an_empty_file_warns_but_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text("")
    assert audit_verify.main([str(path)]) == 0
    out = capsys.readouterr().out
    assert "WARNING: no records found" in out
    assert "records: 0" in out


def test_canonical_form_of_floats_is_pinned() -> None:
    """Python's float repr, with NaN and Infinity as bare tokens, is part of the format.

    The expected bytes are written out by hand, so this pins the format rather
    than whatever the implementation happens to produce.
    """
    record = {
        "latency_ms": 12.345,
        "result": {"big": 1e16, "inf": float("inf"), "nan": float("nan"), "neg_zero": -0.0},
        "prev_hash": GENESIS_HASH,
        "tool": "café",
    }
    expected = (
        b'{"latency_ms":12.345,'
        b'"prev_hash":"' + GENESIS_HASH.encode() + b'",'
        b'"result":{"big":1e+16,"inf":Infinity,"nan":NaN,"neg_zero":-0.0},'
        b'"tool":"caf\\u00e9"}'
    )
    assert audit_chain.canonical_bytes(record) == expected
    assert record_hash(record) == hashlib.sha256(expected).hexdigest()
    # And the values survive the trip through the file unchanged.
    assert audit_chain.canonical_bytes(audit_chain.normalize(record)) == expected


# ---------------------------------------------------------------------------
# Review round 2
# ---------------------------------------------------------------------------

NOT_COVERED = audit_verify.NOT_COVERED


def _json_out(path: Path, capsys: pytest.CaptureFixture[str]) -> str:
    audit_verify.main([str(path), "--json"])
    return capsys.readouterr().out


async def test_garbage_then_restart_then_deleting_everything_above_is_a_break(
    tmp_path: Path,
) -> None:
    """The second review's repro, with genuine writer output throughout.

    Append any non-JSON line to a live log, wait for a restart (the server
    writes a real after_unreadable record), then delete everything above that
    record. after_unreadable as the first line of a file must not pass.
    """
    path = tmp_path / "a.jsonl"
    await _write_log(path, 3)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("garbage\n")
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 3)
    await _emit(log, 4)
    lines = path.read_text().splitlines()
    assert json.loads(lines[4])["chain_start"] == CHAIN_START_AFTER_UNREADABLE

    report = _report_for(path, lines[4:])
    assert report.broken is not None
    assert report.broken.where == f"{path}:1"
    assert "after_unreadable" in report.broken.reason


async def test_after_unreadable_after_a_parseable_line_is_a_break(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 1)
    restart = _genesis(lines[0], CHAIN_START_AFTER_UNREADABLE)
    report = _report_for(path, [_legacy_line(), restart])
    assert report.broken is not None and report.broken.where == f"{path}:2"


@pytest.mark.parametrize("content", ["garbage\n", "garbage\nmore garbage", '{"ts": "x'])
async def test_a_file_holding_only_non_json_gets_after_unreadable_and_verifies(
    tmp_path: Path, content: str
) -> None:
    """The writer's honest label, and the verifier agrees: damage, not a break."""
    path = tmp_path / "a.jsonl"
    path.write_text(content)
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 0)

    lines = path.read_text().splitlines()
    assert json.loads(lines[-1])["chain_start"] == CHAIN_START_AFTER_UNREADABLE
    report = _verify(path)
    assert report.ok, report.broken
    assert len(report.damaged) == len(lines) - 1


@pytest.mark.parametrize("content", [b"\xef\xbb\xbf", b"\xef\xbb\xbf\n\n"])
async def test_a_file_holding_only_a_byte_order_mark_is_a_new_log(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "a.jsonl"
    path.write_bytes(content)
    assert resume_from_file(path).chain_start == CHAIN_START_NEW_LOG
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 0)
    report = _verify(path)
    assert report.ok, report.broken
    assert report.segment_starts[0][1] == CHAIN_START_NEW_LOG


async def test_two_crashes_in_a_row_leave_two_damaged_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A second crash while writing the first record after a crash."""
    path = tmp_path / "a.jsonl"
    await _write_log(path, 2)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-11-27T00:00:00.000Z", "tool": "list_dev')  # crash 1
    with path.open("a", encoding="utf-8") as fh:
        # What the restarted writer gets out before crash 2: its newline, then
        # part of its first record.
        fh.write('\n{"args": {}, "chain_start": "after_unrea')
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 9)

    report = _verify(path)
    assert report.ok, report.broken
    assert report.damaged == [f"{path}:3", f"{path}:4"]
    assert audit_verify.main([str(path)]) == 3
    assert "damaged lines: 2" in capsys.readouterr().out


async def test_replacing_the_last_record_with_garbage_is_not_a_clean_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    _put_lines(path, [*lines[:-1], "garbage"])
    log = AuditLog(sink=FileSink(path))
    await _emit(log, 9)

    assert audit_verify.main([str(path)]) == 3
    assert "an unknown number of records" in capsys.readouterr().out


async def test_damage_needs_a_restart_in_the_same_file(tmp_path: Path) -> None:
    """A fragment at the end of one file is not excused by the next file's start."""
    older, newer = tmp_path / "a.jsonl.1", tmp_path / "a.jsonl"
    lines = await _write_log(older, 2)
    _put_lines(older, [*lines, "garbage"])
    restart = _genesis((await _write_log(tmp_path / "x.jsonl", 1))[0], CHAIN_START_AFTER_UNREADABLE)
    _put_lines(newer, [restart])

    report = _verify([older, newer])
    assert report.broken is not None
    assert report.broken.where == f"{older}:3"


async def test_damage_needs_a_genesis_restart_after_it(tmp_path: Path) -> None:
    """A fragment followed by a record labelled after_unreadable that continues the chain."""
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    relabelled = json.loads(lines[2])
    relabelled["chain_start"] = CHAIN_START_AFTER_UNREADABLE
    report = _report_for(path, [lines[0], lines[1], "garbage", _forge(relabelled)])
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert report.broken.reason.startswith("unreadable line")


@pytest.mark.parametrize("label", [CHAIN_START_PROCESS_START, CHAIN_START_NEW_LOG, None])
async def test_damage_needs_the_after_unreadable_label(tmp_path: Path, label: str | None) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    report = _report_for(path, [lines[0], "garbage", _genesis(lines[1], label)])
    assert report.broken is not None
    assert report.broken.where == f"{path}:2"


@pytest.mark.parametrize("before", ["unchained", "damaged"])
async def test_new_log_is_valid_only_as_the_first_record_of_a_file(
    tmp_path: Path, before: str
) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 1)
    first = _legacy_line() if before == "unchained" else "garbage"
    report = _report_for(path, [first, lines[0]])
    assert report.broken is not None
    assert report.broken.where == f"{path}:{1 if before == 'damaged' else 2}"
    # The same record as the first line of its file is fine.
    assert _report_for(path, [lines[0]]).ok


def test_a_server_that_cannot_read_its_own_log_starts_a_segment_the_verifier_rejects(
    tmp_path: Path,
) -> None:
    """Pinned: an unreadable file cannot be vouched for, so the restart is a break.

    resume_from_file never raises. A directory stands in for a file the
    server cannot read.
    """
    assert resume_from_file(tmp_path).chain_start == CHAIN_START_AFTER_UNREADABLE


async def test_damage_then_an_edited_restart_is_reported_as_the_edit(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    restart = json.loads(_genesis(lines[1], CHAIN_START_AFTER_UNREADABLE))
    restart["tool"] = "delete_vlan"  # edited after sealing
    report = _report_for(path, [lines[0], "garbage", json.dumps(restart, sort_keys=True)])
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert report.broken.reason.startswith("edited record")
