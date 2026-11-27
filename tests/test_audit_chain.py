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
  right line. The limits are pinned too: a truncated tail verifies, because the
  chain alone cannot see it.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi import audit_chain
from mcp_unifi.audit import REDACTED, AuditLog, FileSink, StdoutSink, parse_jsonl, set_audit_log
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
    assert not report.unchained_after_chained
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
        '{"ts": "2026-11-27T00:00:00.000Z", "tool": "list_dev',  # torn write
        '["not", "an", "object"]',
        '{"hash": "not-a-hash", "schema": "2"}',
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
    # The damaged line itself is a break, and the verifier names it.
    report = _verify(path)
    assert not report.ok
    assert report.broken is not None and report.broken.where == f"{path}:3"


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
    """Strip the chain fields and claim schema 1: the next record notices."""
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 3)
    record = json.loads(lines[1])
    for key in ("hash", "prev_hash"):
        del record[key]
    record["schema"] = "1"
    lines[1] = json.dumps(record, sort_keys=True)

    report = _report_for(path, lines)
    assert report.broken is not None
    assert report.broken.where == f"{path}:3"
    assert "carries no hash" in report.broken.reason


async def test_unchained_records_after_chained_ones_are_flagged_not_broken(
    tmp_path: Path,
) -> None:
    path = tmp_path / "a.jsonl"
    lines = await _write_log(path, 2)

    report = _report_for(path, [*lines, _legacy_line()])
    assert report.ok
    assert report.unchained_after_chained


async def test_a_truncated_tail_is_not_detectable(tmp_path: Path) -> None:
    """Pinned limitation: the chain alone cannot see records cut off the end.

    The verifier's head hash is the defence: an operator who copied it
    elsewhere finds that it no longer appears in the file.
    """
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
    assert f"head: {head} ({path}:2)" in out
    assert "unchained records (written before the chain existed): 1" in out

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
