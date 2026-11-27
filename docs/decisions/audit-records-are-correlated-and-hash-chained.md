# Audit records carry an operation id and form a hash chain

**Status:** Accepted (audit schema `"2"`). Number to be assigned at merge: ADR 0010 is taken by an open pull request (#270), so this record is named by topic until then.

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

**Hash chain.** Every record carries `prev_hash` and `hash`.
`hash = SHA-256(canonical JSON of the record without hash)`, where canonical means
keys sorted at every level, `separators=(",", ":")`, `ensure_ascii=True`, UTF-8.
The material includes `prev_hash`. The first record of a segment uses 64 zeros
as `prev_hash` and names why it starts in `chain_start`. The code is in
`src/mcp_unifi/audit_chain.py`; a fixed test vector in `tests/test_audit_chain.py`
pins the format so it can be re-implemented elsewhere.

- Sealing happens in `AuditLog._seal`, inside the existing lock, after redaction
  and immediately before the sink write. The record is normalised to the values
  JSON reads back (tuples become lists, integer keys become strings), and those
  values are kept on the event, so the line written is exactly the hashed
  material plus `hash`.
- The newest hash is kept in memory. The file sink reads its own last line once,
  on the first write after start (`FileSink.resume_chain`), and continues from
  it. A missing or empty file, a last line with no hash (schema 1), or a last
  line that cannot be read each start a new segment, recorded as `new_log`,
  `after_unchained` or `after_unreadable`. Nothing is ever rewritten.
- Sinks that cannot be read back (stdout, syslog) start a segment at every
  process start, recorded as `process_start`.
- The head advances even if the sink write then fails, so a lost record shows up
  as a gap rather than vanishing.
- `mcp-unifi-audit-verify` (`src/mcp_unifi/cli/audit_verify.py`) walks one or
  more files as one chain and reports the first break by file and line: an
  edited record, a missing record, a reordered or duplicated one, a stripped
  hash, a mid-chain restart, or an unreadable line. Records with no chain fields
  and schema `"1"` are counted as unchained, not as a break. It prints the head
  hash.
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
- **External anchoring built in** (periodically shipping the head hash to another
  host, a transparency log, or object storage with retention locks). It is the only
  thing that detects a truncated tail or a full rewrite. Lost for this change on
  scope: it needs a destination, credentials and a schedule, and every homelab
  deployment would configure it differently. The verifier prints the head hash so an
  operator can ship it with whatever they already run.
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
- **A truncated tail is undetectable** from the file alone. Only a copy of a later
  head hash, kept elsewhere, catches it.
- **One writer per file.** Two processes appending to one file fork the chain. That
  includes `mcp-unifi-replay --real` against the running server's file sink. The
  verifier reports the fork; it does not tolerate it.
- **For stdout and syslog** a pass covers each process's run as the collector stored
  it. A whole missing run is invisible, and a lossy transport reads as missing
  records.
- **A failed write reads as a missing record**, so a full disk produces a break. The
  server log has the matching ERROR.
- **Disk:** about 280 bytes more per record (measured on stub records of 350 to
  1,300 bytes), roughly a 25% increase for a typical record.
- **CPU:** each record is serialised three times instead of once (normalise, hash,
  write) and hashed once. Not measured separately; the audit write already holds
  an `fsync`, which dominates.
- **A confirm refused by the scope or write gate is not linked to its preview.**
  Those gates refuse before the tool body runs, so the token is never looked up.

## Reversal condition

Revisit when either of these is true: the audit file is shipped off the host as it
is written (a remote sink with retention), at which point the remote copy is the
anchor and the in-file chain matters less; or the server gains a key it cannot
read back from the same filesystem as the log, at which point signing records
beats chaining them.
