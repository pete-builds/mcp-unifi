# 0011. Audit records carry an operation id and form a hash chain

**Status:** Accepted (audit schema `"2"`)

## Context

The audit log (`src/mcp_unifi/audit.py`) is the only evidence a tool call leaves
behind. Two gaps made it hard to rely on:

1. **Nothing tied the halves of a change together.** A destructive tool previews
   and returns a token; `confirm_destructive_action` executes it later. The token
   is redacted from both records, and the only link was an 8-character
   `preview_id` (the token's first eight characters) inside `result` on one record
   and `args` on the other. No record had an id of its own, so "every record
   about this change" had no exact query.
2. **Nothing noticed an edited or deleted line.** The file is plain JSONL. A line
   could be changed or removed and every reader, including `mcp-unifi-replay`,
   would accept the result.

Constraints: no new runtime dependency, no change to tool output, old logs must
keep parsing everywhere, replay must keep skipping refused calls, and the scope
and write gates in `src/mcp_unifi/scoping.py` write their own records without
knowing anything about correlation.

## Decision

**Correlation.** Every record carries `event_id` (a UUID4 in hex, allocated by
`AuditLog.new_event_id`, injectable through `AuditLog(id_factory=...)`) and
`operation_id`.

- A plain call's `operation_id` is its own `event_id`. The `@audited` wrapper
  (`src/mcp_unifi/modules/_audit.py`) allocates the id before the tool body runs
  and exposes it through `current_operation_id()`.
- `PendingActionsRegistry.put` (`src/mcp_unifi/modules/network/_pending.py`)
  stores that id on the pending action as `operation_id`. It is held server side
  and never placed in the token.
- `confirm_destructive_action` calls `continue_operation(pending.operation_id)`
  once it has claimed the action, so its record carries the preview's id. A
  confirm that claims nothing gets an operation of its own.
- `AuditLog.emit` defaults both ids, so records from `scoping.py` are complete
  with no change to that file.

**Hash chain.** The guarantee, stated once and nowhere stronger: within one
segment, an edited, removed, reordered or inserted record is detected, unless
whoever changed the file also recomputed the hashes. What is not detected:
records removed from the end of a segment or the end of the file; a removed,
duplicated or reordered whole segment or whole rotated file; a full rewrite.

Every record carries `prev_hash` and `hash`.
`hash = SHA-256(canonical JSON of the record without hash)`, as 64 lowercase hex
characters. Canonical means: object keys sorted by code point at every level and
never repeated; `separators=(",", ":")`, so no whitespace; `ensure_ascii=True`, so
every non-ASCII character is a lowercase `\uXXXX` escape; integers in decimal;
floats as Python's `repr` (the shortest form that round-trips: `12.345`, `-0.0`,
`1e+16`); the bare tokens `NaN`, `Infinity` and `-Infinity` for non-finite floats;
`true`, `false`, `null`; then UTF-8. The material includes `prev_hash`. The first
record of a segment uses 64 zeros as `prev_hash` and names why it starts in
`chain_start`. The code is in `src/mcp_unifi/audit_chain.py`; two fixed vectors in
`tests/test_audit_chain.py`, one of them floats written out by hand, pin the format
so it can be re-implemented elsewhere.

- Sealing happens in `AuditLog._seal`, inside the existing lock, after redaction
  and immediately before the sink write. The record is normalised to the values
  JSON reads back (tuples become lists, integer keys become strings), and those
  values are kept on the event, so the line written is exactly the hashed
  material plus `hash`.
- The newest hash is kept in memory. The file sink reads its own last line once,
  on the first write after start (`FileSink.resume_chain`), and continues from
  it. A missing or empty file, a last line with no hash (schema 1), or a last
  line that cannot be read each start a new segment, recorded as `new_log`,
  `after_unchained` or `after_unreadable`. Nothing is ever rewritten. If the file
  does not end in a newline (a crash cut the last write off), the sink writes one
  before its first record, so the new record never fuses onto the fragment.
- Sinks that cannot be read back (stdout, syslog) start a segment at every
  process start, recorded as `process_start`.
- The head advances once a record is hashed, even if the sink write then fails,
  so a record lost to a failed write shows up as a gap. A record that cannot be
  serialised at all is never hashed: nothing is written, the head does not move,
  and the loss leaves no gap; the only trace is the ERROR the server logs.
- `mcp-unifi-audit-verify` (`src/mcp_unifi/cli/audit_verify.py`) walks one or
  more files as one chain and reports the first break by file and line: an
  edited record, a line with a repeated JSON key (at any depth: a parser keeps
  the last copy, so a repeat hides one value from the hash check), a missing
  record, a reordered or duplicated one, a stripped hash, a segment start whose
  label does not fit where it sits, or an unreadable line. As information only,
  it prints where every segment starts and the last record's hash, and closes
  with a line naming what is not covered. Exit codes: `0` verified, `1` break,
  `2` usage, `3` verified with warnings (damaged lines, or an `unreadable_log`
  segment start); from cron, `3` needs a look and is neither a pass nor proof of
  tampering.
- Segment-start labels are checked where the log can check them: `new_log` only as
  the first record of a file (so a rotated log whose server then restarted
  verifies as two segments), `after_unchained` only directly after an unchained
  record, `after_unreadable` only directly after one or more non-JSON lines of the
  same file, and nothing else. `process_start` is accepted anywhere, because
  nothing in a stdout or syslog log can show that a process really restarted
  there. `unreadable_log` is accepted anywhere and always reported (exit `3`).
  A record that continues the chain must carry no label. The writer uses
  `new_log` for a missing or empty file (or one holding only a byte-order mark),
  `after_unreadable` after a non-JSON last line, and `unreadable_log` when it can
  append to the file but not read it. It also uses `after_unreadable` when the last
  line is JSON but not a valid record; the verifier has already reported that line
  as a break. A path that is not a regular file (a pipe) is never read back and
  gets `process_start`. No read on the write path can stop a record being
  written: every one degrades to a segment start with one of these labels.
- Records with no chain fields and schema `"1"` are counted as unchained, not as a
  break, but only before the first chained record of their file (the upgrade).
  After one, they are a break: otherwise stripping the hash fields would hide an
  edit.
- A run of one or more non-JSON lines that reaches the end of its file, or is
  directly followed by an `after_unreadable` (or `unreadable_log`) segment start in
  the same file, is crash damage (two lines when the server crashed
  again while writing its first record after a crash). Each is reported and
  counted, verification continues, and the exit code is `3`, not `0`, because an
  unknown number of records may be missing there.
- Replay's real mode used to mark its records by rewriting `client_id` in a sink
  wrapper after the fact. That would now break the chain, so the mark moved into
  `AuditLog(client_id_override=...)`, applied before sealing.

The schema version moved from `"1"` to `"2"`. Every added field has a default, so
`parse_jsonl` and the evals read old and new records alike.

## Alternatives considered

- **Sign each record (HMAC or Ed25519).** Stops someone without the key from
  recomputing the chain. Lost because the key would live on the same host, under
  the same account, as the file: whoever can rewrite the file can read the key, so
  it adds key handling and rotation without changing who can forge. Worth revisiting
  if the key can live somewhere the server process cannot read back, such as a
  hardware token or a remote signer.
- **External copies of the chain built in** (periodically shipping the latest hash
  to another host, a transparency log, or object storage with retention locks).
  That is what it would take to notice records removed from the end of the file,
  or a full rewrite. Lost for this change on scope: it needs a destination,
  credentials and a schedule, and every homelab deployment would configure it
  differently.
- **A verifier flag that checks a hash kept elsewhere is still in the file.** Built
  during review and removed: a legitimate segment start (the server restarting
  after a line of garbage) let a file whose earlier records had been cut pass it.
  Making that check sound needs more than the file can provide, so this record
  makes no claim about the end of the file at all.
- **A database (SQLite with triggers, or an append-only table).** Gives queries and
  can refuse updates at the engine level, but only against a writer who goes through
  the engine; the file underneath is as editable as JSONL. It would also replace the
  JSONL format every existing consumer (`jq`, replay, the evals, log shippers) reads.
- **Correlation id carried in the token.** Lost because the token is the caller's
  bearer secret and must stay opaque; anything derived from it in the log would also
  be a partial token. The `preview_id` prefix already shows how little of a token
  can safely appear.
- **A correlation id passed down from the MCP client.** No client sends one, and a
  value the caller chooses is not evidence of anything.
- **Re-reading the file's tail on every write** so that two writers could share a
  file. Lost because it hides tampering: a line deleted from the end while the
  server runs would be silently adopted as the new head. Keeping the head in memory
  means such a deletion is caught at the next record.

## Consequences and accepted costs

- **It is tamper evidence, not tamper resistance.** Anyone who can write the file
  can recompute the chain. The chain catches edits by people or tools that do not
  recompute it, and partial or careless edits by those who try.
- **Records removed from the end of a segment or the end of the file are not
  detected.** Segment ends sit before every later segment start: a crash, an
  upgrade, a restart after rotation, and every process start on stdout or syslog.
  The verifier lists every segment start and ends each report with what is not
  covered, rather than let an `OK` imply those points were checked.
- **A removed, duplicated or reordered whole segment, or whole rotated file, is not
  detected.** Dropping a rotated file from the middle of a set goes unnoticed
  whenever the next file starts a new segment, and the same file passed twice
  verifies.
- **Downgrading breaks verification.** An older version appends unchained records
  after chained ones, which is a break from that point on. Rotate the file before
  downgrading.
- **A server that can append to its log but not read it** writes every record, but
  each restart is an `unreadable_log` segment start: exit `3`, never a clean pass.
- **A damaged line may hide an unknown number of lost records**, not only the one
  being written at the crash: replacing the end of a file with garbage and letting
  the server restart looks the same. Hence exit `3` rather than `0`.
- **One writer per file.** Two processes appending to one file fork the chain. That
  includes `mcp-unifi-replay --real` against the running server's file sink. The
  verifier reports the fork; it does not tolerate it.
- **For stdout and syslog** the guarantee applies within each process's run as the
  collector stored it. Records lost at the end of a run, and a whole missing run,
  are not detected, and a lossy transport reads as missing records.
- **A failed write reads as a missing record**, so a full disk produces a break. The
  server log has the matching ERROR. A record that could not be serialised leaves no
  gap at all, only that ERROR.
- **Disk:** about 280 bytes more per record (measured on stub records of 350 to
  1,300 bytes), roughly a 25% increase for a typical record.
- **CPU:** each record is serialised three times instead of once (normalise, hash,
  write) and hashed once. Not measured separately; the audit write already holds
  an `fsync`, which dominates.
- **A confirm refused by the scope or write gate is not linked to its preview.**
  Those gates refuse before the tool body runs, so the token is never looked up.
  Linking it needs a change in `src/mcp_unifi/scoping.py` and is a follow-up.

## Reversal condition

Revisit when either of these is true: the audit file is shipped off the host as it
is written (a remote sink with retention), at which point the remote copy is the
evidence and the in-file chain matters less; or the server gains a key it cannot
read back from the same filesystem as the log, at which point signing records
beats chaining them.
